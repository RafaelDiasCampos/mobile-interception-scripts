'use strict';

const P = '[Facebook/Android] ';
const seen = new Set();
const counts = Object.create(null);

function log(s) { console.log(P + s); }
function hit(s) {
  const n = counts[s] = (counts[s] || 0) + 1;
  if (n <= 5 || n % 100 === 0) log(s + ' #' + n);
}

const acceptCustom = new NativeCallback(function () {
  hit('native custom verifier accepted');
  return 0; // BoringSSL ssl_verify_ok
}, 'int', ['pointer', 'pointer']);

const acceptLegacy = new NativeCallback(function () {
  hit('native X509 verifier accepted');
  return 1; // SSL_CTX_set_cert_verify_callback success
}, 'int', ['pointer', 'pointer']);

const nativeTargets = [
  ['SSL_set_custom_verify', 2, acceptCustom],
  ['SSL_CTX_set_custom_verify', 2, acceptCustom],
  ['SSL_CTX_set_cert_verify_callback', 1, acceptLegacy]
];

const exportCache = new Map();

function getExport(module, name) {
  const key = module.path + '@' + module.base.toString();
  let exports = exportCache.get(key);

  if (!exports) {
    exports = new Map(module.enumerateExports()
      .filter(item => item.type === 'function')
      .map(item => [item.name, item.address]));
    exportCache.set(key, exports);
  }

  return exports.get(name) || null;
}

function instrument(module) {
  if (!/^lib(?:javacrypto|mainlinecronet.*|coldstart)\.so$/.test(module.name))
    return;

  for (const [name, argIndex, callback] of nativeTargets) {
    const address = getExport(module, name);
    if (address === null || seen.has(address.toString())) continue;
    seen.add(address.toString());

    try {
      Interceptor.attach(address, {
        onEnter(args) {
          args[argIndex] = callback;
          hit(module.name + '!' + name + ' replaced');
        }
      });
      log('hooked ' + module.name + '!' + name);
    } catch (e) {
      log('native hook failed: ' + e);
    }
  }

  const make = getExport(module, 'SSL_new');
  const set = getExport(module, 'SSL_set_custom_verify');

  if (make !== null && set !== null && !seen.has(make.toString())) {
    seen.add(make.toString());

    const setVerify = new NativeFunction(
      set, 'void', ['pointer', 'int', 'pointer']
    );

    Interceptor.attach(make, {
      onLeave(ssl) {
        if (ssl.isNull()) return;
        try {
          setVerify(ssl, 1, acceptCustom);
          hit(module.name + '!SSL_new verifier installed');
        } catch (e) {
          log('SSL_new verifier failed: ' + e);
        }
      }
    });

    log('hooked ' + module.name + '!SSL_new');
  }

}

if (typeof Process.attachModuleObserver === 'function') {
  Process.attachModuleObserver({ onAdded: instrument });
} else {
  Process.enumerateModules().forEach(instrument);
  log('Module observer unavailable; late TLS libraries may be missed');
}

if (!Java.available) {
  log('Java VM unavailable');
} else {
  Java.perform(function () {
    log('Java.perform reached');

    function use(name, fn) {
      log('trying Java.use(' + name + ')');
      try {
        const c = Java.use(name);
        if (fn) fn(c);
        log('installed ' + name);
        return c;
      } catch (e) {
        log('unavailable ' + name + ': ' + (e.stack || e));
        return null;
      }
    }

    if (use('java.lang.String') === null) return;
    const ArrayList = use('java.util.ArrayList');
    if (ArrayList === null) return;

    function trust(name, hasPins) {
      use(name, function (c) {
        if (hasPins) {
          try {
            c.checkPins.overload('java.util.List').implementation = function () {
              hit('Android XML pins');
            };
          } catch (e) {
            log('checkPins unavailable: ' + e);
          }
        }

        let installed = 0;
        c.checkServerTrusted.overloads.forEach(function (ov) {
          const type = ov.returnType.className;
          if (type !== 'void' && type !== 'java.util.List') return;

          ov.implementation = function () {
            hit(name + '.checkServerTrusted');
            if (type === 'void') return;

            const chain = arguments[0];
            const result = ArrayList.$new();
            if (chain) {
              for (let i = 0; i < chain.length; i++)
                result.add(chain[i]);
            }
            return result;
          };
          installed++;
        });
        log(name + ': ' + installed + ' trust overloads');
      });
    }

    trust('android.security.net.config.NetworkSecurityTrustManager', true);
    trust('com.android.org.conscrypt.TrustManagerImpl', false);

    use('X.0yS', function (c) {
      const ov = c.A02.overload('java.util.List');
      if (ov.returnType.className !== 'void')
        throw Error('unexpected return type');
      ov.implementation = function () { hit('Meta public-key pins'); };
    });

    use('X.0CC', function (c) {
      let installed = 0;
      for (const name of ['AMh', 'AMi']) {
        for (const ov of c[name].overloads) {
          if (ov.returnType.className !== 'void') continue;
          ov.implementation = function () { hit('Meta ' + name); };
          installed++;
        }
      }
      log('Meta host-aware trust: ' + installed + ' void overloads');
    });

    use(
      'com.facebook.mobilenetwork.internal.certificateverifier.CertificateVerifier',
      function (c) {
        let installed = 0;
        for (const name of ['verify', 'verifyWithProofOfPossession']) {
          if (!c[name]) continue;
          for (const ov of c[name].overloads) {
            if (ov.returnType.className !== 'void') continue;
            ov.implementation = function () {
              hit('Meta CertificateVerifier.' + name +
                ' host=' + String(arguments[1]));
            };
            installed++;
          }
        }
        log('Meta CertificateVerifier: ' + installed + ' void overloads');
      }
    );

    use('X.7HO', function (c) {
      const ov = c.A02.overload(
        'java.lang.String', 'kotlin.jvm.functions.Function0'
      );
      if (ov.returnType.className !== 'void')
        throw Error('unexpected return type');
      ov.implementation = function (host) {
        hit('OkHttp pin ' + host);
      };
    });
  });
}


(() => {
  'use strict';

  // const TARGET = 'b-graph.facebook.com';
  const TARGET = 'facebook.com';
  let installed = false;

  function hostname(p) {
    try {
      // Short std::__ndk2::string values are stored inside the object.
      const bytes = new Uint8Array(p.readByteArray(24));
      const inline = Array.from(bytes, b => String.fromCharCode(b)).join('');
      const match = inline.match(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/i);
      if (match) return match[0];

      // Try the pointer layouts used for longer strings.
      for (const offset of [0, 16]) {
        const q = p.add(offset).readPointer();
        if (q.isNull() || !Process.findRangeByAddress(q)) continue;
        const s = q.readUtf8String(128);
        const candidate = s && s.match(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/i);
        if (candidate) return candidate[0];
      }
    } catch (_) { }
    return '?';
  }

  function hookVerification(e, label, hostArg) {
    let calls = 0;

    Interceptor.attach(e.address, {
      onEnter(args) {
        this.host = hostname(args[hostArg]);
      },
      onLeave(result) {
        const value = result.toInt32();
        console.log(`[Facebook/Android] ${label} host=${this.host} result=${value}`);

        if (value === 0) {
        // if (this.host.includes(TARGET) && value === 0) {
          result.replace(ptr(1));
          console.log(`[Facebook/Android] accepted ${this.host} at ${label}`);
        }
      }
    });

    console.log(`[Facebook/Android] hooked ${label} @ ${e.address}`);
  }

  function tracePinning(m, offset, label) {
    let calls = 0;

    Interceptor.attach(m.base.add(offset), {
      onEnter(args) {
        if (++calls <= 20) {
          console.log(
            `[Facebook/Android] ${label} hostCandidate=${hostname(args[1])}` +
            ` caller=${this.returnAddress}`
          );
        }
      }
    });

    console.log(`[Facebook/Android] tracing ${label} @ ${m.base.add(offset)}`);
  }

  function scan() {
    if (installed) return;

    const m = Process.enumerateModules()
      .find(x => x.name === 'libcoldstart.so');
    if (!m) return;

    let exports;
    try {
      exports = m.enumerateExports();
    } catch (e) {
      console.log(`[Facebook/Android] export scan failed: ${e}`);
      return;
    }

    installed = true;

    for (const e of exports) {
      if (e.type !== 'function') continue;

      try {
        if (e.name.startsWith(
          '_ZN8proxygen15SSLVerification17verifyWithMetricsE'
        )) {
          hookVerification(e, 'verifyWithMetrics', 2);
        }

        if (e.name.startsWith(
          '_ZN8proxygen15SSLVerification24SSLVerificationCallbacks20verifySSLCertificateE'
        )) {
          hookVerification(e, 'verifySSLCertificate', 1);
        }
      } catch (error) {
        console.log(`[Facebook/Android] hook failed: ${error}`);
      }
    }

    for (const [offset, label] of [
      [0xea5430, 'PinningSSLCallbacks slot 5'],
      [0xea52f8, 'PinningSSLCallbacks slot 6']
    ]) {
      try {
        tracePinning(m, offset, label);
      } catch (error) {
        console.log(`[Facebook/Android] pinning trace failed: ${error}`);
      }
    }
  }

  setTimeout(() => {
    scan();
    setInterval(scan, 2000);
  }, 1500);
})();