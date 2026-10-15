'use strict';

const CONFIG = {
  autoStart: false,
  enableSecurityHooks: true,
  enableNativeTlsHooks: true,
  enableUrlSessionHooks: true,
  enabledAppHooks: [
    // 'metrics', 'verification', 'pinning', 
    'defaultPinner', 'mnsSync', 'mnsRevocation', 
    // 'mnsTrustAndPin', 'fizzObserver', 'objcPinningCheck', 
    // 'objcPinningHostCheck', 'urlSessionChallenge'
  ],
  tlsDiagnostics: true,
  traceFirstTrustFailure: false,
  maxPendingBlocks: 128,
  logFirstCalls: 3
};

const nullptr = ptr(0);
const SESSION_SELECTOR = 'URLSession:didReceiveChallenge:completionHandler:';
const TASK_SELECTOR = 'URLSession:task:didReceiveChallenge:completionHandler:';
const APP_PROFILE = {
  module: 'FBSharedFramework', uuid: '4c4c448255553144a1de6dd899bc7e05',
  version: '448.0.0', build: '1072661960',
  entries: {
    metrics: { rva: 0x73d084, prefix: 'ff8302d1fa6705a9f85f06a9f65707a9' },
    verification: { rva: 0x73edf0, prefix: 'e3031eaade1ae397fe0303aafd7b06a9' },
    pinning: { rva: 0x73ef14, prefix: 'ffc301d1f65704a9f44f05a9fd7b06a9' },
    defaultPinner: { rva: 0x73f1ec, prefix: 'e3031eaa0c2de397fe0303aafd7b15a9' },
    mnsSync: { rva: 0x4a1e98, prefix: 'f85fbca9f65701a9f44f02a9fd7b03a9' },
    mnsRevocation: { rva: 0x4a1fb0, prefix: 'ff0301d1f65701a9f44f02a9fd7b03a9' },
    mnsTrustAndPin: { rva: 0x4a215c, prefix: 'e923b96dfc6f01a9fa6702a9f85f03a9' },
    fizzObserver: { rva: 0x135c364, prefix: 'fd7bbfa977fed597ff8302d1f50302aa' }
  }
};
const state = {
  hooks: new Map(), counts: new Map(), warnings: new Set(),
  modules: new Map(), callbacks: [], pending: new Map(),
  tlsEvents: [], application: null, nextBlock: 1, observer: null,
  objcScanQueued: false, bridgeReady: false, blockCopy: null, blockRelease: null,
  cfRelease: null, traces: new Set(), enabledGroups: new Set(),
  phase: 'loaded', lastOperation: null
};
state.appProfiles = new Map();
state.appObjC = new Map();
const APP_NATIVE_HOOK_IDS = [
  'metrics', 'verification', 'pinning', 'defaultPinner', 'mnsSync',
  'mnsRevocation', 'mnsTrustAndPin', 'fizzObserver'
];
const APP_OBJC_HOOK_IDS = [
  'objcPinningCheck', 'objcPinningHostCheck', 'urlSessionChallenge'
];
const APP_HOOK_IDS = APP_NATIVE_HOOK_IDS.concat(APP_OBJC_HOOK_IDS);

function validateAppHookSelection(names = CONFIG.enabledAppHooks) {
  if (!Array.isArray(names)) throw new Error('enabledAppHooks must be an array of hook IDs.');
  const selected = Array.from(new Set(names));
  const unknown = selected.filter(name => !APP_HOOK_IDS.includes(name));
  if (unknown.length)
    throw new Error('Unknown app hook ID(s): ' + unknown.join(', ') + '. Valid IDs: ' + APP_HOOK_IDS.join(', '));
  return selected;
}
function appHookEnabled(name) {
  return Array.isArray(CONFIG.enabledAppHooks) && CONFIG.enabledAppHooks.includes(name);
}
function appObjcHooksSelected() {
  return APP_OBJC_HOOK_IDS.some(appHookEnabled) &&
    (!appHookEnabled('urlSessionChallenge') || CONFIG.enableUrlSessionHooks);
}
function configureAppHooks(names) {
  if (state.enabledGroups.size || state.hooks.size)
    throw new Error('Configure app hooks before start(); relaunch Frida to change an active selection.');
  const selected = validateAppHookSelection(names);
  CONFIG.enabledAppHooks = selected;
  log('selected app-specific hooks: ' + (selected.length ? selected.join(', ') : '(none)'));
  return selected;
}

function log(message) { console.log('[Instagram/iOS] ' + message); }
function warn(message) {
  if (state.warnings.has(message)) return;
  state.warnings.add(message);
  log('warning: ' + message);
}
function hit(label) {
  const n = (state.counts.get(label) || 0) + 1;
  state.counts.set(label, n);
  if (n <= CONFIG.logFirstCalls) log('call ' + label);
}
function nonnull(value) { return value !== null && value !== undefined && !value.isNull(); }
function pointerOf(value) { return value && value.handle ? value.handle : value; }
function bind(module, name, retType, argTypes) {
  try {
    const address = module.findExportByName(name);
    return address ? new NativeFunction(address, retType, argTypes) : null;
  } catch (_) { return null; }
}
function globalBind(name, retType, argTypes) {
  try {
    let address = null;
    if (typeof Module.findGlobalExportByName === 'function')
      address = Module.findGlobalExportByName(name);
    else if (typeof Module.findExportByName === 'function')
      address = Module.findExportByName(null, name);
    return address ? new NativeFunction(address, retType, argTypes) : null;
  } catch (_) { return null; }
}
function attach(address, label, callbacks, kind) {
  if (!address) return;
  const key = (kind || label) + '@' + address;
  if (state.hooks.has(key)) return;
  try {
    state.lastOperation = 'attach ' + label;
    log('attaching ' + label);
    const listener = Interceptor.attach(address, callbacks);
    state.hooks.set(key, { label, address: address.toString(), listener });
    log('hooked ' + label);
  } catch (e) { warn('Cannot hook ' + label + ': ' + e); }
}
function exportHook(module, name, callbacks) {
  let address = null;
  try { address = module.findExportByName(name); } catch (_) {}
  attach(address, module.name + '!' + name, callbacks, name);
}
function traceFailure(label, context) {
  if (!CONFIG.traceFirstTrustFailure || state.traces.has(label)) return;
  state.traces.add(label);
  try {
    const frames = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 12).map(p => DebugSymbol.fromAddress(p).toString());
    log('original trust failure at ' + label + '\n' + frames.join('\n'));
  } catch (e) { warn('Backtrace unavailable: ' + e); }
}
function bridgeAvailable() {
  try { return typeof ObjC !== 'undefined' && ObjC.available; }
  catch (_) { return false; }
}
function refreshNativeRuntime() {
  state.cfRelease = state.cfRelease || globalBind('CFRelease', 'void', ['pointer']);
}
function refreshObjCRuntime() {
  state.bridgeReady = bridgeAvailable();
  if (!state.bridgeReady) return;
  state.blockCopy = state.blockCopy || globalBind('_Block_copy', 'pointer', ['pointer']);
  state.blockRelease = state.blockRelease || globalBind('_Block_release', 'void', ['pointer']);
}
function readApplicationMetadata() {
  if (!state.application) {
    try {
      const bundle = ObjC.classes.NSBundle.mainBundle();
      const info = bundle.infoDictionary();
      const get = name => {
        const value = info.objectForKey_(name);
        return value && nonnull(pointerOf(value)) ? value.toString() : null;
      };
      state.application = {
        bundleId: bundle.bundleIdentifier().toString(),
        version: get('CFBundleShortVersionString'), build: get('CFBundleVersion')
      };
      log('application ' + JSON.stringify(state.application));
    } catch (_) { }
  }
}

function wrapBlock(address, argTypes, invoke, cleanup) {
  if (!state.bridgeReady || !state.blockCopy || !state.blockRelease || !nonnull(address))
    return null;
  if (state.pending.size >= CONFIG.maxPendingBlocks) {
    warn('Pending block limit reached; additional callbacks are left unchanged.');
    return null;
  }
  const copied = state.blockCopy(address);
  if (!nonnull(copied)) return null;
  let released = false;
  const id = state.nextBlock++;
  const finish = () => {
    if (released) return;
    released = true;
    setImmediate(() => {
      state.pending.delete(id);
      state.blockRelease(copied);
      if (cleanup) cleanup();
    });
  };
  try {
    const original = new ObjC.Block(copied);
    if (!original.types) original.declare({ retType: 'void', argTypes });
    const callOriginal = original.implementation;
    let called = false;
    const replacement = new ObjC.Block({
      retType: 'void', argTypes,
      implementation(...args) {
        if (called) return;
        called = true;
        try { invoke(callOriginal, args); }
        finally { finish(); }
      }
    });
    const entry = { id, original, replacement, finish };
    state.pending.set(id, entry);
    return entry;
  } catch (e) {
    state.blockRelease(copied);
    warn('Cannot wrap callback: ' + e);
    return null;
  }
}

function installSecurity(module) {
  if (!CONFIG.enableSecurityHooks) return;
  exportHook(module, 'SecTrustEvaluateWithError', {
    onEnter(args) { this.validTrust = nonnull(args[0]); this.errorOut = args[1]; },
    onLeave(retval) {
      if (!this.validTrust) return;
      const failed = retval.toInt32() === 0;
      if (nonnull(this.errorOut)) {
        try {
          const error = this.errorOut.readPointer();
          if (failed && nonnull(error)) {
            if (!state.cfRelease) { warn('CFRelease unavailable; trust error left unchanged.'); return; }
            state.cfRelease(error);
          }
          this.errorOut.writePointer(nullptr);
        } catch (e) { warn('Cannot clear trust error: ' + e); return; }
      }
      if (failed) traceFailure('SecTrustEvaluateWithError', this.context);
      retval.replace(1);
      hit('SecTrustEvaluateWithError');
    }
  });
  for (const name of ['SecTrustEvaluate', 'SecTrustGetTrustResult']) {
    exportHook(module, name, {
      onEnter(args) { this.valid = nonnull(args[0]) && nonnull(args[1]); this.resultOut = args[1]; },
      onLeave(retval) {
        if (!this.valid) return;
        try { this.resultOut.writeU32(1); } // kSecTrustResultProceed
        catch (e) { warn('Cannot write ' + name + ' result: ' + e); return; }
        retval.replace(0); // errSecSuccess
        hit(name);
      }
    });
  }
  for (const modern of [true, false]) {
    const name = modern ? 'SecTrustEvaluateAsyncWithError' : 'SecTrustEvaluateAsync';
    exportHook(module, name, {
      onEnter(args) {
        if (!nonnull(args[0])) return;
        const types = modern ? ['pointer', 'bool', 'pointer'] : ['pointer', 'uint'];
        this.entry = wrapBlock(args[2], types, (original, values) => {
          hit(name + '.callback');
          if (modern) original(values[0], true, nullptr);
          else original(values[0], 1);
        });
        if (this.entry) args[2] = this.entry.replacement.handle;
        else warn(name + ' callback not wrapped; Objective-C bridge/block APIs may be unavailable.');
      },
      onLeave(retval) {
        if (this.entry && retval.toInt32() !== 0) this.entry.finish();
      }
    });
  }
}

function installNativeTls(module) {
  if (!CONFIG.enableNativeTlsHooks) return;
  const names = ['SSL_new', 'SSL_CTX_new', 'SSL_set_custom_verify',
    'SSL_CTX_set_custom_verify', 'SSL_set_verify', 'SSL_CTX_set_verify',
    'SSL_CTX_set_cert_verify_callback', 'SSL_get_verify_result',
    'X509_verify_cert', 'X509_check_host', 'SSL_do_handshake', 'SSL_connect', 'SSL_get_error'];
  let provider = false;
  for (const name of names) {
    try { if (module.findExportByName(name)) { provider = true; break; } } catch (_) {}
  }
  if (!provider) return;
  const clearError = bind(module, 'X509_STORE_CTX_set_error', 'void', ['pointer', 'int']);
  const x509Verify = bind(module, 'X509_verify_cert', 'int', ['pointer']);
  const setCustom = bind(module, 'SSL_set_custom_verify', 'void', ['pointer', 'int', 'pointer']);
  const ctxCustom = bind(module, 'SSL_CTX_set_custom_verify', 'void', ['pointer', 'int', 'pointer']);
  const setVerify = bind(module, 'SSL_set_verify', 'void', ['pointer', 'int', 'pointer']);
  const ctxVerify = bind(module, 'SSL_CTX_set_verify', 'void', ['pointer', 'int', 'pointer']);
  const clear = ctx => { if (clearError && nonnull(ctx)) clearError(ctx, 0); };
  // BoringSSL ssl_verify_ok = 0
  const acceptCustom = new NativeCallback((_ssl, _alert) => {
    hit(module.name + '!custom_verify.callback');
    return 0;
  }, 'int', ['pointer', 'pointer']);
  const acceptCert = new NativeCallback((ctx, _opaque) => {
    if (x509Verify && nonnull(ctx)) x509Verify(ctx);
    clear(ctx);
    hit(module.name + '!cert_verify.callback');
    return 1;
  }, 'int', ['pointer', 'pointer']);
  state.callbacks.push(acceptCustom, acceptCert);
  for (const name of ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify']) {
    exportHook(module, name, {
      onEnter(args) { args[1] = nullptr; args[2] = acceptCustom; hit(module.name + '!' + name); }
    });
  }
  for (const name of ['SSL_set_verify', 'SSL_CTX_set_verify']) {
    exportHook(module, name, {
      onEnter(args) { args[1] = nullptr; args[2] = nullptr; hit(module.name + '!' + name); }
    });
  }
  exportHook(module, 'SSL_CTX_set_cert_verify_callback', {
    onEnter(args) { args[1] = acceptCert; hit(module.name + '!SSL_CTX_set_cert_verify_callback'); }
  });
  for (const isContext of [false, true]) {
    const name = isContext ? 'SSL_CTX_new' : 'SSL_new';
    const custom = isContext ? ctxCustom : setCustom;
    const legacy = isContext ? ctxVerify : setVerify;
    exportHook(module, name, {
      onLeave(retval) {
        if (!nonnull(retval)) return;
        if (custom) custom(retval, 0, acceptCustom);
        else if (legacy) legacy(retval, 0, nullptr);
        hit(module.name + '!' + name);
      }
    });
  }
  exportHook(module, 'SSL_get_verify_result', {
    onLeave(retval) { retval.replace(0); hit(module.name + '!SSL_get_verify_result'); }
  });
  exportHook(module, 'X509_verify_cert', {
    onEnter(args) { this.ctx = args[0]; },
    onLeave(retval) {
      if (!nonnull(this.ctx)) return;
      if (retval.toInt32() !== 1) traceFailure(module.name + '!X509_verify_cert', this.context);
      clear(this.ctx);
      retval.replace(1);
      hit(module.name + '!X509_verify_cert');
    }
  });
  exportHook(module, 'X509_check_host', {
    onEnter(args) { this.valid = nonnull(args[0]) && nonnull(args[1]); },
    onLeave(retval) {
      if (!this.valid) return;
      retval.replace(1);
      hit(module.name + '!X509_check_host');
    }
  });
  if (CONFIG.tlsDiagnostics) installTlsDiagnostics(module);
}

function tlsEvent(event) {
  state.tlsEvents.push(event);
  if (state.tlsEvents.length > 40) state.tlsEvents.shift();
  log('TLS ' + JSON.stringify(event));
}
function installTlsDiagnostics(module) {
  const getServername = bind(module, 'SSL_get_servername', 'pointer', ['pointer', 'int']);
  const getVersion = bind(module, 'SSL_get_version', 'pointer', ['pointer']);
  const getText = (fn, ssl, extra) => {
    try {
      if (!fn || !nonnull(ssl)) return null;
      const value = extra ? fn(ssl, 0) : fn(ssl);
      return nonnull(value) ? value.readUtf8String() : null;
    } catch (_) { return null; }
  };
  for (const name of ['SSL_do_handshake', 'SSL_connect']) {
    exportHook(module, name, {
      onEnter(args) { this.ssl = args[0]; },
      onLeave(retval) {
        if (retval.toInt32() !== 1 || !nonnull(this.ssl)) return;
        hit(module.name + '!' + name + '.complete');
        tlsEvent({ event: 'handshake-complete', module: module.name,
          sni: getText(getServername, this.ssl, true), version: getText(getVersion, this.ssl, false) });
      }
    });
  }
  exportHook(module, 'SSL_get_error', {
    onEnter(args) { this.ssl = args[0]; this.tlsResult = args[1].toInt32(); },
    onLeave(retval) {
      const code = retval.toInt32();
      hit(module.name + '!SSL_get_error.' + code);
      if (code === 0 || code === 2 || code === 3) return;
      tlsEvent({ event: 'tls-status', module: module.name, errorCode: code,
        returnValue: this.tlsResult, sni: getText(getServername, this.ssl, true) });
    }
  });
}

function installChallengeMethod(address, label) {
  attach(address, label, {
    onEnter(args) {
      let credential = null;
      try {
        const selector = ObjC.selectorAsString(args[1]);
        if (selector !== SESSION_SELECTOR && selector !== TASK_SELECTOR) return;
        const challengeIndex = selector === SESSION_SELECTOR ? 3 : 4;
        const completionIndex = challengeIndex + 1;
        if (!nonnull(args[challengeIndex]) || !nonnull(args[completionIndex])) return;
        const challenge = new ObjC.Object(args[challengeIndex]);
        const space = challenge.protectionSpace();
        if (space.authenticationMethod().toString() !== 'NSURLAuthenticationMethodServerTrust') return;
        const trust = pointerOf(space.serverTrust());
        if (!nonnull(trust)) return;
        const host = space.host().toString();
        credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
        if (!credential || !nonnull(pointerOf(credential))) return;
        credential.retain();
        const retained = credential;
        const entry = wrapBlock(args[completionIndex], ['long', 'pointer'], original => {
          hit('URLSession.serverTrust.completion');
          log('accepted URLSession server trust for ' + host);
          original(0, retained.handle); // NSURLSessionAuthChallengeUseCredential
        }, () => retained.release());
        if (!entry) { retained.release(); credential = null; return; }
        credential = null; // Entry now owns the retained credential.
        args[completionIndex] = entry.replacement.handle;
        hit('URLSession.serverTrust.challenge');
      } catch (e) {
        if (credential) { try { credential.release(); } catch (_) {} }
        warn('Cannot wrap URLSession challenge: ' + e);
      }
    }
  }, 'URLSession.challenge');
}
function bytesHex(address, length) {
  return Array.from(new Uint8Array(address.readByteArray(length)), b => b.toString(16).padStart(2, '0')).join('');
}
function machoUuid(module) {
  try {
    if (module.base.readU32() !== 0xfeedfacf) return null;
    const count = module.base.add(16).readU32();
    const bytes = module.base.add(20).readU32();
    if (count > 1024 || bytes > 1024 * 1024) return null;
    let offset = 32;
    for (let index = 0; index < count; index++) {
      const command = module.base.add(offset);
      const kind = command.readU32(), size = command.add(4).readU32();
      if (size < 8 || offset + size > 32 + bytes) return null;
      if (kind === 0x1b && size >= 24) return bytesHex(command.add(8), 16);
      offset += size;
    }
  } catch (_) {}
  return null;
}
function acceptOwnedResult(out, label) {
  try {
    if (!nonnull(out)) { warn(label + ': indirect return slot unavailable.'); return; }
    const result = out.readPointer();
    if (!nonnull(result)) { warn(label + ': original result object is null.'); return; }
    const range = Process.findRangeByAddress(result);
    if (!range || !range.protection.includes('w')) { warn(label + ': result is not writable.'); return; }
    const old = result.readU8();
    if (old !== 0 && old !== 1) { warn(label + ': unexpected success flag; result left unchanged.'); return; }
    result.writeU8(1);
    hit(label);
  } catch (e) { warn(label + ': cannot update original result: ' + e); }
}
function installAppNative(module) {
  if (!APP_NATIVE_HOOK_IDS.some(appHookEnabled) || module.name !== APP_PROFILE.module) return;
  const key = module.path + '@' + module.base;
  if (state.appProfiles.has(key)) return;
  const observedUuid = machoUuid(module);
  const profile = { module: module.name, uuid: observedUuid,
    matched: Process.arch === 'arm64', entries: {} };
  state.appProfiles.set(key, profile);
  if (!profile.matched) {
    warn(module.name + ': native app hooks require arm64.');
    return;
  }
  log('installing ' + module.name + ' native hooks; UUID ' + observedUuid);
  const clearError = bind(module, 'X509_STORE_CTX_set_error', 'void', ['pointer', 'int']);
  const mcfRelease = bind(module, 'MCFRelease', 'void', ['pointer']);
  const nativeHook = (name, label, handlers) => {
    if (!appHookEnabled(name)) {
      profile.entries[name] = 'disabled by config';
      return;
    }
    const entry = APP_PROFILE.entries[name];
    const address = module.base.add(entry.rva);
    try {
      const range = Process.findRangeByAddress(address);
      if (!range || !range.protection.includes('x')) {
        profile.entries[name] = 'address not executable';
        warn(label + ': target address is not executable; hook skipped.');
        return;
      }
      const id = 'app.' + name;
      attach(address, label, handlers, id);
      profile.entries[name] = state.hooks.has(id + '@' + address) ? 'installed' : 'installation failed';
    } catch (e) { profile.entries[name] = 'unavailable'; warn(label + ': ' + e); }
  };
  nativeHook('metrics', module.name + '!proxygen.verifyWithMetrics', {
    onEnter(args) {
      args[0] = ptr(1);
      if (clearError && nonnull(args[1])) clearError(args[1], 0);
    },
    onLeave(retval) { retval.replace(1); hit(module.name + '!proxygen.verifyWithMetrics'); }
  });
  for (const [name, label] of [
    ['verification', 'proxygen.SSLVerificationCallbacks.verifySSLCertificate'],
    ['pinning', 'proxygen.PinningSSLCallbacks.verifySSLCertificateImpl'],
    ['defaultPinner', 'proxygen.DefaultCertificatePinner.pin-check']
  ]) {
    const full = module.name + '!' + label;
    nativeHook(name, full, {
      onEnter() { this.resultOut = this.context.x8 || nullptr; },
      onLeave() {
        acceptOwnedResult(this.resultOut, full);
      }
    });
  }
  for (const [name, label] of [
    ['mnsSync', 'MNSApple.synchronous-verifier'],
    ['mnsRevocation', 'MNSApple.revocation-check'],
    ['mnsTrustAndPin', 'MNSApple.trust-and-pin-check']
  ]) {
    const full = module.name + '!' + label;
    if (!appHookEnabled(name)) {
      profile.entries[name] = 'disabled by config';
      continue;
    }
    if (!mcfRelease) {
      profile.entries[name] = 'MCFRelease unavailable';
      warn(full + ': MCFRelease unavailable; owned error results left unchanged.');
      continue;
    }
    nativeHook(name, full, {
      onLeave(retval) {
        if (nonnull(retval)) {
          traceFailure(full, this.context);
          mcfRelease(retval);
          retval.replace(0);
        }
        hit(full);
      }
    });
  }
  nativeHook('fizzObserver', module.name + '!fizz.OpenSSLCertificateVerifier.verify.observe', {
    onEnter(args) { this.peerOut = args[1]; },
    onLeave(retval) {
      const label = module.name + '!fizz.OpenSSLCertificateVerifier.verify.observe';
      hit(label);
      try {
        const peer = nonnull(this.peerOut) && nonnull(this.peerOut.readPointer());
        const n = state.counts.get(label) || 0;
        if (n <= CONFIG.logFirstCalls) log('Fizz verifier result=' + retval.toInt32() + ' peerCertificate=' + peer);
      } catch (_) {}
    }
  });
}
function installAppObjC() {
  if (!state.enabledGroups.has('objc') || !state.bridgeReady) return;
  for (const [hookId, selector, expectedTypes] of [
    ['objcPinningCheck', 'checkPinning:', 'B24@0:8@16'],
    ['objcPinningHostCheck', 'checkPinning:host:', 'B32@0:8^{__SecTrust}16@24']
  ]) {
    const label = 'FBSSLPinningVerifier ' + selector;
    if (state.appObjC.get(label) === 'installed') continue;
    if (!appHookEnabled(hookId)) {
      state.appObjC.set(label, 'disabled by config');
      continue;
    }
    try {
      const cls = ObjC.classes.FBSSLPinningVerifier;
      if (!cls) { state.appObjC.set(label, 'class unavailable'); continue; }
      const method = cls['- ' + selector];
      if (!method) { state.appObjC.set(label, 'method unavailable'); continue; }
      const nativeMethod = ObjC.api.class_getInstanceMethod(cls.handle, ObjC.selector(selector));
      const encoding = ObjC.api.method_getTypeEncoding(nativeMethod).readUtf8String();
      if (encoding !== expectedTypes) {
        state.appObjC.set(label, 'type encoding mismatch: ' + encoding);
        warn(label + ': type encoding differs from the analyzed IPA; hook skipped.');
        continue;
      }
      const kind = 'app.objc.' + selector;
      attach(method.implementation, label, {
        onEnter(args) {
          this.target = ObjC.selectorAsString(args[1]) === selector && nonnull(args[2]);
        },
        onLeave(retval) {
          if (!this.target) return;
          retval.replace(1);
          hit(label);
        }
      }, kind);
      state.appObjC.set(label, state.hooks.has(kind + '@' + method.implementation) ? 'installed' : 'installation failed');
    } catch (e) { state.appObjC.set(label, 'unavailable'); warn(label + ': ' + e); }
  }
}
function scanObjC() {
  if (!state.enabledGroups.has('objc') || !appObjcHooksSelected()) return;
  state.lastOperation = 'targeted Objective-C pinning scan';
  refreshObjCRuntime();
  if (!state.bridgeReady) return;
  readApplicationMetadata();
  installAppObjC();
  if (!appHookEnabled('urlSessionChallenge') || !CONFIG.enableUrlSessionHooks || !state.bridgeReady) return;
  try {
    const cls = ObjC.classes.FBSSLPinningProtocol;
    const method = cls && cls['- ' + TASK_SELECTOR];
    if (!method) {
      warn('FBSSLPinningProtocol task challenge method unavailable; URLSession hook skipped.');
      return;
    }
    installChallengeMethod(method.implementation,
      '-[FBSSLPinningProtocol ' + TASK_SELECTOR + ']');
  } catch (e) { warn('Targeted Objective-C scan failed: ' + e); }
}
function queueObjCScan() {
  if (!state.enabledGroups.has('objc') || !appObjcHooksSelected() || state.objcScanQueued) return;
  state.objcScanQueued = true;
  setImmediate(() => {
    if (!bridgeAvailable()) {
      state.objcScanQueued = false;
      warn('Objective-C bridge unavailable; URLSession and asynchronous blocks remain unchanged.');
      return;
    }
    try {
      if (typeof ObjC.schedule !== 'function' || !ObjC.mainQueue) {
        state.objcScanQueued = false;
        warn('Objective-C main-queue scheduling unavailable; method scans skipped.');
        return;
      }
      ObjC.schedule(ObjC.mainQueue, () => {
        state.objcScanQueued = false;
        try { scanObjC(); }
        catch (e) { warn('Objective-C startup failed: ' + e); }
      });
    } catch (e) { state.objcScanQueued = false; warn('Cannot schedule Objective-C scan: ' + e); }
  });
}
function installModule(module) {
  const needsBroadScan = state.enabledGroups.has('security') || state.enabledGroups.has('native');
  if (!needsBroadScan && (!state.enabledGroups.has('app') ||
      !APP_NATIVE_HOOK_IDS.some(appHookEnabled) || module.name !== APP_PROFILE.module)) return;
  const key = module.path + '@' + module.base;
  let entry = state.modules.get(key);
  if (!entry) { entry = { module, groups: new Set() }; state.modules.set(key, entry); }
  for (const [group, installer] of [
    ['security', installSecurity], ['native', installNativeTls], ['app', installAppNative]
  ]) {
    if (!state.enabledGroups.has(group) || entry.groups.has(group)) continue;
    if (group === 'app' && module.name !== APP_PROFILE.module) continue;
    state.lastOperation = group + ' scan: ' + module.name;
    try { installer(module); entry.groups.add(group); }
    catch (e) { warn('Cannot initialize ' + group + ' hooks for ' + module.name + ': ' + e); }
  }
}
function status() {
  return {
    platform: Process.platform, architecture: Process.arch,
    fridaVersion: typeof Frida !== 'undefined' ? Frida.version : null,
    codeSigningPolicy: Process.codeSigningPolicy || null,
    startup: { phase: state.phase, enabledGroups: Array.from(state.enabledGroups),
      lastOperation: state.lastOperation, automaticStart: CONFIG.autoStart,
      objectiveCScanQueued: state.objcScanQueued },
    application: state.application, objectiveCBridgeAvailable: state.bridgeReady,
    ipaAnalyzed: true,
    analyzedApplication: { version: APP_PROFILE.version, build: APP_PROFILE.build,
      frameworkUuid: APP_PROFILE.uuid },
    appNativeProfiles: Array.from(state.appProfiles.values()),
    appObjectiveCHooks: Object.fromEntries(state.appObjC),
    config: { ...CONFIG },
    moduleObserverActive: state.observer !== null,
    hooks: Array.from(state.hooks.values(), h => ({ label: h.label, address: h.address })),
    calls: Object.fromEntries(state.counts), pendingBlocks: state.pending.size,
    tlsEvents: state.tlsEvents.slice(), warnings: Array.from(state.warnings)
  };
}
function modulesForScan() {
  if (state.enabledGroups.has('security') || state.enabledGroups.has('native'))
    return Process.enumerateModules();
  if (!state.enabledGroups.has('app') || !APP_NATIVE_HOOK_IDS.some(appHookEnabled)) return [];
  const app = Process.findModuleByName(APP_PROFILE.module);
  return app ? [app] : [];
}
function rescan() {
  if (Process.platform !== 'darwin' || Process.codeSigningPolicy === 'required' || !state.enabledGroups.size)
    return status();
  if (state.enabledGroups.has('security')) refreshNativeRuntime();
  for (const module of modulesForScan()) installModule(module);
  queueObjCScan();
  return status();
}
function start(group = 'targeted') {
  const groupSets = {
    targeted: ['app', 'objc'],
    all: ['security', 'native', 'app', 'objc']
  };
  const groups = groupSets[group] || [group];
  if (!['targeted', 'all', 'security', 'native', 'app', 'objc'].includes(group))
    throw new Error('Use start() for targeted hooks, start("app"), start("objc"), start("security"), start("native"), or start("all").');
  CONFIG.enabledAppHooks = validateAppHookSelection();
  if (groups.some(name => name === 'app' || name === 'objc') && !CONFIG.enabledAppHooks.length)
    warn('No app-specific hooks selected; call configureAppHooks([...]) before start() in a fresh process.');
  if (Process.platform !== 'darwin') {
    state.phase = 'blocked';
    warn('This script targets iOS/Darwin; no hooks installed on ' + Process.platform + '.');
    return status();
  }
  if (Process.codeSigningPolicy === 'required') {
    state.phase = 'blocked';
    warn('Code-signing policy is required; Interceptor and native callback hooks cannot be installed in this session.');
    return status();
  }
  state.phase = 'installing';
  log('starting groups: ' + groups.join(', '));
  for (const name of groups) state.enabledGroups.add(name);
  if (state.enabledGroups.has('security')) refreshNativeRuntime();
  if (state.observer === null && typeof Process.attachModuleObserver === 'function') {
    try { state.observer = Process.attachModuleObserver({
      onAdded(module) {
        installModule(module);
        if (module.name === APP_PROFILE.module) queueObjCScan();
      },
      onRemoved(module) {
        state.modules.delete(module.path + '@' + module.base);
        state.appProfiles.delete(module.path + '@' + module.base);
        for (const [key, hook] of state.hooks) {
          if (!hook.label.startsWith(module.name + '!')) continue;
          try { hook.listener.detach(); } catch (_) {}
          state.hooks.delete(key);
        }
      }
    }); } catch (e) { warn('Module observer unavailable: ' + e); }
  }
  for (const module of modulesForScan()) installModule(module);
  if (state.observer === null)
    warn('Module observer unavailable; call rescan() after loading additional TLS providers.');
  queueObjCScan();
  state.phase = 'active';
  log('selected hook groups installed or queued. Use status() for coverage.');
  return status();
}
rpc.exports = { status, rescan, start, configureapphooks: configureAppHooks };

log('agent loaded: ' + JSON.stringify({ pid: Process.id, platform: Process.platform,
  architecture: Process.arch, fridaVersion: typeof Frida !== 'undefined' ? Frida.version : null,
  codeSigningPolicy: Process.codeSigningPolicy || null, automaticStart: CONFIG.autoStart }));
if (CONFIG.autoStart) start();
else log('No hooks installed yet. After the app resumes, run start() in the REPL.');
