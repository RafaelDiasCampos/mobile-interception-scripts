'use strict';

const PREFIX = '[Facebook/Android] ';
const hooked = new Set();
const counts = Object.create(null);
const exportCache = new Map();

function log(message) {
  console.log(PREFIX + message);
}

function hit(label) {
  const count = counts[label] = (counts[label] || 0) + 1;
  if (count <= 5 || count % 100 === 0) log(label + ' #' + count);
}

const acceptCustom = new NativeCallback(function () {
  hit('native custom verifier accepted');
  return 0; // ssl_verify_ok
}, 'int', ['pointer', 'pointer']);

const acceptLegacy = new NativeCallback(function () {
  hit('native X509 verifier accepted');
  return 1;
}, 'int', ['pointer', 'pointer']);

const nativeTargets = [
  ['SSL_set_custom_verify', 2, acceptCustom],
  ['SSL_CTX_set_custom_verify', 2, acceptCustom],
  ['SSL_CTX_set_cert_verify_callback', 1, acceptLegacy]
];

function exportsOf(module) {
  const key = module.path + '@' + module.base.toString();
  if (!exportCache.has(key)) {
    exportCache.set(key, module.enumerateExports()
      .filter(item => item.type === 'function'));
  }
  return exportCache.get(key);
}

function attachOnce(address, label, callbacks) {
  const key = address.toString();
  if (hooked.has(key)) return;
  try {
    Interceptor.attach(address, callbacks);
    hooked.add(key);
    log('hooked ' + label + ' @ ' + address);
  } catch (error) {
    log('could not hook ' + label + ': ' + error);
  }
}

function hostname(value) {
  try {
    if (!value || value.isNull() || !Process.findRangeByAddress(value)) return '?';
    const bytes = new Uint8Array(value.readByteArray(24));
    const inline = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    const match = inline.match(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/i);
    if (match) return match[0];

    for (const offset of [0, 16]) {
      const pointer = value.add(offset).readPointer();
      if (pointer.isNull() || !Process.findRangeByAddress(pointer)) continue;
      const text = pointer.readUtf8String(128);
      const candidate = text && text.match(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/i);
      if (candidate) return candidate[0];
    }
  } catch (_) {
  }
  return '?';
}

function hookProxygen(module, exports) {
  for (const item of exports) {
    if (item.name.startsWith('_ZN8proxygen15SSLVerification17verifyWithMetricsE')) {
      attachOnce(item.address, module.name + '!verifyWithMetrics', {
        onEnter(args) {
          this.host = hostname(args[2]);
        },
        onLeave(result) {
          const value = result.toInt32();
          hit('verifyWithMetrics host=' + this.host + ' result=' + value);
          if (value === 0) {
            result.replace(ptr(1));
            hit('accepted ' + this.host + ' at verifyWithMetrics');
          }
        }
      });
    } else if (item.name.startsWith(
      '_ZN8proxygen15SSLVerification24SSLVerificationCallbacks20verifySSLCertificateE'
    )) {
      attachOnce(item.address, module.name + '!verifySSLCertificate', {
        onEnter(args) {
          this.host = hostname(args[1]);
        },
        onLeave(result) {
          hit('verifySSLCertificate host=' + this.host + ' result=' + result);
        }
      });
    }
  }
}

function instrument(module) {
  if (!/^lib(?:javacrypto|mainlinecronet.*|coldstart)\.so$/.test(module.name))
    return;

  let exports;
  try {
    exports = exportsOf(module);
  } catch (error) {
    log('export scan failed for ' + module.name + ': ' + error);
    return;
  }

  const byName = new Map(exports.map(item => [item.name, item.address]));
  for (const [name, index, callback] of nativeTargets) {
    const address = byName.get(name);
    if (!address) continue;
    attachOnce(address, module.name + '!' + name, {
      onEnter(args) {
        args[index] = callback;
        hit(module.name + '!' + name + ' replaced');
      }
    });
  }

  const make = byName.get('SSL_new');
  const set = byName.get('SSL_set_custom_verify');
  if (make && set) {
    const setVerify = new NativeFunction(set, 'void', ['pointer', 'int', 'pointer']);
    attachOnce(make, module.name + '!SSL_new', {
      onLeave(ssl) {
        if (ssl.isNull()) return;
        try {
          setVerify(ssl, 1, acceptCustom);
          hit(module.name + '!SSL_new verifier installed');
        } catch (error) {
          log('SSL_new verifier failed: ' + error);
        }
      }
    });
  }

  if (module.name === 'libcoldstart.so') hookProxygen(module, exports);
}

if (typeof Process.attachModuleObserver === 'function') {
  Process.attachModuleObserver({ onAdded: instrument });
} else {
  Process.enumerateModules().forEach(instrument);
  log('module observer unavailable; late TLS libraries may be missed');
}

if (typeof Java === 'undefined' || !Java.available) {
  log('Java VM unavailable');
} else {
  Java.perform(function () {
    function use(name, install) {
      try {
        const klass = Java.use(name);
        install(klass);
        log('installed ' + name);
      } catch (error) {
        log('could not install ' + name + ': ' + error);
      }
    }

    const ArrayList = Java.use('java.util.ArrayList');

    function trust(name, hasPins) {
      use(name, function (klass) {
        if (hasPins && klass.checkPins) {
          try {
            klass.checkPins.overload('java.util.List').implementation = function () {
              hit(name + '.checkPins');
            };
          } catch (error) {
            log(name + '.checkPins unavailable: ' + error);
          }
        }

        let installed = 0;
        for (const overload of klass.checkServerTrusted.overloads) {
          const type = overload.returnType.className;
          if (type !== 'void' && type !== 'java.util.List') continue;
          overload.implementation = function () {
            hit(name + '.checkServerTrusted');
            if (type === 'void') return;
            const result = ArrayList.$new();
            const chain = arguments[0];
            if (chain) {
              for (let i = 0; i < chain.length; i++) result.add(chain[i]);
            }
            return result;
          };
          installed++;
        }
        log(name + ': ' + installed + ' trust overloads');
      });
    }

    trust('android.security.net.config.NetworkSecurityTrustManager', true);
    trust('com.android.org.conscrypt.TrustManagerImpl', false);

    use('X.0OX', function (klass) {
      for (const [method, signature] of [
        ['A02', 'java.util.List'],
        ['A03', '[Ljava.security.cert.X509Certificate;']
      ]) {
        const overload = klass[method].overload(signature);
        if (overload.returnType.className !== 'void')
          throw new Error('unexpected return type for X.0OX.' + method);
        overload.implementation = function () {
          hit('Meta X.0OX.' + method + ' accepted');
        };
      }
    });

    use('com.facebook.mobilenetwork.internal.certificateverifier.CertificateVerifier',
      function (klass) {
        let installed = 0;
        for (const method of ['verify', 'verifyWithProofOfPossession']) {
          if (!klass[method]) continue;
          for (const overload of klass[method].overloads) {
            if (overload.returnType.className !== 'void') continue;
            overload.implementation = function () {
              hit('Meta CertificateVerifier.' + method +
                ' host=' + String(arguments[1]));
            };
            installed++;
          }
        }
        log('Meta CertificateVerifier: ' + installed + ' void overloads');
      });
  });
}
