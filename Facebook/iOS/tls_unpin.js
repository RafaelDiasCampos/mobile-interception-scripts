var PREFIX = '[Facebook/iOS] ';

var FORCE_ACCEPT_INVALID_CERTIFICATES = true;
var nativeAcceptCallbacks = [];

var installed = Object.create(null);
var pendingByInvoke = Object.create(null);
var trustStates = Object.create(null);
var asyncTrusts = Object.create(null);
var pinVtableRanges = [];
var pinCallbackTargets = Object.create(null);
var blockInvokeHooked = Object.create(null);
var objcScanRunning = false;
var objcScannedClasses = Object.create(null);

function emit(event, data) {
  var out = {event: event, time: new Date().toISOString()};
  if (data) Object.keys(data).forEach(function (k) { out[k] = data[k]; });
  try { console.log(PREFIX + JSON.stringify(out)); }
  catch (e) { console.log(PREFIX + event + ' ' + String(e)); }
}

function pstr(p) { try { return p ? p.toString() : 'null'; } catch (_) { return 'unknown'; } }
function safeInt(p) { try { return p.toInt32(); } catch (_) { return 0; } }
function isNull(p) { try { return !p || p.isNull(); } catch (_) { return true; } }
function stripPtr(p) { try { return p && p.strip ? p.strip() : p; } catch (_) { return p; } }
function normSymbol(s) { return String(s || '').replace(/^_+/, ''); }

function modules() {
  try { return Process.enumerateModules(); } catch (_) { return []; }
}

function findModule(hint) {
  var list = modules();
  for (var i = 0; i < list.length; i++) {
    if (list[i].name === hint || list[i].path.indexOf('/' + hint + '.framework/') >= 0 ||
        list[i].name.indexOf(hint) >= 0) return list[i];
  }
  try { return Process.findModuleByName(hint); } catch (_) { return null; }
}

function findAddress(name, moduleHints) {
  var hints = moduleHints || [];
  for (var i = 0; i < hints.length; i++) {
    var mod = findModule(hints[i]);
    if (!mod) continue;
    try {
      if (mod.findExportByName) {
        var a = mod.findExportByName(name) || mod.findExportByName('_' + name);
        if (a) return {address: a, module: mod.name, symbol: name};
      }
    } catch (_) {}
    try {
      if (mod.enumerateSymbols) {
        var syms = mod.enumerateSymbols();
        for (var j = 0; j < syms.length; j++) {
          if (normSymbol(syms[j].name) === normSymbol(name))
            return {address: syms[j].address, module: mod.name, symbol: syms[j].name};
        }
      }
    } catch (_) {}
  }
  try {
    if (Module.findGlobalExportByName) {
      var g = Module.findGlobalExportByName(name);
      if (g) return {address: g, module: 'global', symbol: name};
    }
  } catch (_) {}
  try {
    if (Module.findExportByName) {
      var old = Module.findExportByName(null, name);
      if (old) return {address: old, module: 'global', symbol: name};
    }
  } catch (_) {}
  return null;
}

function findSymbolFragment(moduleHint, fragment) {
  var mod = findModule(moduleHint);
  if (!mod) return null;
  try {
    if (mod.enumerateSymbols) {
      var syms = mod.enumerateSymbols();
      for (var i = 0; i < syms.length; i++) {
        if (String(syms[i].name).indexOf(fragment) >= 0)
          return {address: syms[i].address, module: mod.name, symbol: syms[i].name};
      }
    }
  } catch (_) {}
  return null;
}

function attachOnce(address, key, callbacks) {
  var id = pstr(address) + '|' + key;
  if (installed[id]) return false;
  try {
    Interceptor.attach(address, callbacks);
    installed[id] = true;
    return true;
  } catch (e) {
    emit('HOOK_ERROR', {hook: key, address: pstr(address), error: String(e)});
    return false;
  }
}

function callerName(retAddr) {
  try { return DebugSymbol.fromAddress(retAddr).toString(); }
  catch (_) { return pstr(retAddr); }
}

function execRange(p) {
  try {
    var r = Process.findRangeByAddress(stripPtr(p));
    return !!(r && r.protection && r.protection.indexOf('x') >= 0);
  } catch (_) { return false; }
}

function cfErrorText(errorPtr) {
  if (isNull(errorPtr)) return null;
  try {
    var copy = findAddress('CFErrorCopyDescription', ['CoreFoundation']);
    var release = findAddress('CFRelease', ['CoreFoundation']);
    if (!copy) return pstr(errorPtr);
    var fn = new NativeFunction(copy.address, 'pointer', ['pointer']);
    var desc = fn(errorPtr);
    if (isNull(desc)) return pstr(errorPtr);
    var text = ObjC.available ? new ObjC.Object(desc).toString() : pstr(desc);
    if (release) new NativeFunction(release.address, 'void', ['pointer'])(desc);
    return text;
  } catch (_) { return pstr(errorPtr); }
}

function trustState(trust) {
  var key = pstr(trust);
  if (!trustStates[key]) trustStates[key] = {
    anchorsSet: false, anchorCount: null, anchorsOnly: null
  };
  return trustStates[key];
}

function trustProtection(trust) {
  var s = trustStates[pstr(trust)];
  if (!s || !s.anchorsSet) return 'Apple trust evaluation (no custom anchors observed)';
  if (s.anchorsOnly === true) return 'custom anchor-only pinning path (MBI/custom)';
  return 'custom-anchor trust path (pinning possible)';
}

function trustResultName(n) {
  var names = {
    0: 'invalid', 1: 'proceed', 2: 'confirm', 3: 'deny', 4: 'unspecified',
    5: 'recoverableTrustFailure', 6: 'fatalTrustFailure', 7: 'otherError'
  };
  return names[n] || 'unknown(' + n + ')';
}

function trustResultPass(n) { return n === 1 || n === 4; }

function addPendingBlock(blockPtr, ctx) {
  try {
    if (isNull(blockPtr)) return false;
    var invoke = stripPtr(blockPtr.add(Process.pointerSize * 2).readPointer());
    if (!execRange(invoke)) return false;
    var invokeKey = pstr(invoke);
    ctx.blockKey = pstr(blockPtr);
    ctx.invokeKey = invokeKey;
    ctx.active = true;
    if (!pendingByInvoke[invokeKey]) pendingByInvoke[invokeKey] = [];
    pendingByInvoke[invokeKey].push(ctx);
    if (!blockInvokeHooked[invokeKey]) {
      var added = attachOnce(invoke, 'block-invoke:' + invokeKey, {
        onEnter: function (args) {
          var selfKey = pstr(args[0]);
          var trustKey = null;
          if (ctxKindMayHaveTrust(invokeKey)) {
            try { trustKey = pstr(args[1]); } catch (_) {}
          }
          var pending = pendingByInvoke[invokeKey] || [];
          var match = null;
          for (var k = 0; k < pending.length; k++) {
            if (!pending[k].active) continue;
            if (pending[k].blockKey === selfKey ||
                (trustKey && pending[k].trustKey && pending[k].trustKey === trustKey)) {
              match = pending[k]; break;
            }
          }
          if (!match) {
            for (var n = 0; n < pending.length; n++) {
              if (pending[n].active) { match = pending[n]; break; }
            }
          }
          if (!match) return;
          this.observedCtx = match;
          forceBlockCallback(match, args);
          reportBlockResult(match, args);
        },
        onLeave: function () {
          if (this.observedCtx && this.observedCtx.kind === 'auth-challenge')
            releaseChallengeCredential(this.observedCtx);
        }
      });
      if (!added) return false;
      blockInvokeHooked[invokeKey] = true;
    }
    return true;
  } catch (_) { return false; }
}

function ctxKindMayHaveTrust(invokeKey) {
  var list = pendingByInvoke[invokeKey] || [];
  for (var i = 0; i < list.length; i++)
    if (list[i].kind === 'trust-async' || list[i].kind === 'trust-async-error') return true;
  return false;
}

function finishCtx(ctx) {
  if (!ctx) return;
  ctx.active = false;
  if (ctx.trustKey && asyncTrusts[ctx.trustKey] === ctx) delete asyncTrusts[ctx.trustKey];
}

function reportBlockResult(ctx, args) {
  if (ctx.kind === 'trust-async-error') {
    var ok = safeInt(args[2]) !== 0;
    emit('VALIDATION', {
      protection: trustProtection(ctx.trust), source: 'SecTrustEvaluateAsyncWithError callback',
      verdict: ctx.forced ? 'FORCED_PASS' : (ok ? 'PASS' : 'FAIL'), forced: !!ctx.forced,
      trust: pstr(ctx.trust), error: cfErrorText(args[3])
    });
    finishCtx(ctx);
  } else if (ctx.kind === 'trust-async') {
    var result = safeInt(args[2]);
    emit('VALIDATION', {
      protection: trustProtection(ctx.trust), source: 'SecTrustEvaluateAsync callback',
      verdict: ctx.forced ? 'FORCED_PASS' : (trustResultPass(result) ? 'PASS' : 'FAIL'),
      forced: !!ctx.forced, trustResult: trustResultName(result), trust: pstr(ctx.trust)
    });
    finishCtx(ctx);
  } else if (ctx.kind === 'auth-challenge') {
    var d = safeInt(args[1]);
    var names = {0: 'useCredential', 1: 'performDefaultHandling', 2: 'cancelAuthenticationChallenge', 3: 'rejectProtectionSpace'};
    var verdict = d === 0 ? 'PASS' : (d === 2 || d === 3 ? 'FAIL' : 'DEFERRED_TO_SYSTEM');
    emit('VALIDATION', {
      protection: ctx.protection, source: ctx.source,
      verdict: ctx.forced ? 'FORCED_PASS' : verdict, forced: !!ctx.forced,
      authenticationMethod: ctx.authMethod, host: ctx.host,
      disposition: names[d] || 'unknown(' + d + ')',
      credential: isNull(args[2]) ? null : pstr(args[2])
    });
    finishCtx(ctx);
  }
}

function releaseChallengeCredential(ctx) {
  if (!ctx || !ctx.credentialRetained || !ctx.credential || !ObjC.available) return;
  try { ObjC.release(ctx.credential); } catch (_) {}
  ctx.credentialRetained = false;
  ctx.credential = null;
}

function forceBlockCallback(ctx, args) {
  if (!FORCE_ACCEPT_INVALID_CERTIFICATES || !ctx) return;
  try {
    if (ctx.kind === 'trust-async-error') {
      args[2] = ptr(1);
      args[3] = ptr(0);
      ctx.forced = true;
    } else if (ctx.kind === 'trust-async') {
      args[2] = ptr(1);
      ctx.forced = true;
    } else if (ctx.kind === 'auth-challenge' && ctx.credential && ctx.credential.handle) {
      args[1] = ptr(0);
      args[2] = ctx.credential.handle;
      ctx.forced = true;
    }
  } catch (e) {
    emit('BYPASS_ERROR', {source: ctx.source || ctx.kind, error: String(e)});
  }
}

function makeNativeAcceptCallback(returnType, argumentTypes, result) {
  var callback = new NativeCallback(function () { return result; }, returnType, argumentTypes);
  nativeAcceptCallbacks.push(callback);
  return callback;
}

function hookTlsCallbackRegistration(name, callbackIndex, returnType, argumentTypes, successValue) {
  var address = findAddress(name, ['FBSharedFramework']);
  if (!address) return;
  var hookKey = pstr(address.address) + '|replace-tls-callback:' + name;
  if (installed[hookKey]) return;
  var accept = makeNativeAcceptCallback(returnType, argumentTypes, successValue);
  attachOnce(address.address, 'replace-tls-callback:' + name, {
    onEnter: function (args) {
      if (isNull(args[callbackIndex])) return;
      this.originalCallback = pstr(args[callbackIndex]);
      args[callbackIndex] = accept;
      emit('BYPASS_INSTALLED', {
        source: name, originalCallback: this.originalCallback,
        replacement: 'always-success callback'
      });
    }
  });
}

function hookTlsCallbackRegistrations() {
  hookTlsCallbackRegistration('SSL_CTX_set_custom_verify', 2, 'int', ['pointer', 'pointer'], 0);
  hookTlsCallbackRegistration('SSL_CTX_set_cert_verify_callback', 1, 'int', ['pointer', 'pointer'], 1);
  hookTlsCallbackRegistration('SSL_CTX_set_verify', 2, 'int', ['int', 'pointer'], 1);
  hookTlsCallbackRegistration('SSL_set_verify', 2, 'int', ['int', 'pointer'], 1);
}

function clearTrustError(errorOut) {
  try {
    if (isNull(errorOut)) return;
    var oldError = errorOut.readPointer();
    if (!isNull(oldError)) {
      var release = findAddress('CFRelease', ['CoreFoundation']);
      if (release) new NativeFunction(release.address, 'void', ['pointer'])(oldError);
    }
    errorOut.writePointer(ptr(0));
  } catch (_) {}
}

function hookTrustApis() {
  var addr = findAddress('SecTrustSetAnchorCertificates', ['Security']);
  if (addr) attachOnce(addr.address, 'SecTrustSetAnchorCertificates', {
    onEnter: function (args) {
      this.trust = args[0]; this.array = args[1]; this.count = null;
      try {
        var c = findAddress('CFArrayGetCount', ['CoreFoundation']);
        if (c && !isNull(this.array))
          this.count = new NativeFunction(c.address, 'long', ['pointer'])(this.array).toNumber();
      } catch (_) {}
    },
    onLeave: function (retval) {
      var status = safeInt(retval), s = trustState(this.trust);
      if (status === 0) { s.anchorsSet = true; s.anchorCount = this.count; }
      emit('PIN_CONFIG', {
        protection: 'MBI/custom anchor pinning', source: 'SecTrustSetAnchorCertificates',
        result: status === 0 ? 'OK' : 'ERROR', status: status,
        trust: pstr(this.trust), anchorCount: this.count
      });
    }
  });

  addr = findAddress('SecTrustSetAnchorCertificatesOnly', ['Security']);
  if (addr) attachOnce(addr.address, 'SecTrustSetAnchorCertificatesOnly', {
    onEnter: function (args) { this.trust = args[0]; this.only = safeInt(args[1]) !== 0; },
    onLeave: function (retval) {
      var status = safeInt(retval), s = trustState(this.trust);
      if (status === 0) s.anchorsOnly = this.only;
      emit('PIN_CONFIG', {
        protection: 'MBI/custom anchor pinning', source: 'SecTrustSetAnchorCertificatesOnly',
        result: status === 0 ? 'OK' : 'ERROR', status: status,
        anchorsOnly: this.only, trust: pstr(this.trust)
      });
    }
  });

  addr = findAddress('SecTrustEvaluateWithError', ['Security']);
  if (addr) attachOnce(addr.address, 'SecTrustEvaluateWithError', {
    onEnter: function (args) {
      this.trust = args[0]; this.errorOut = args[1]; this.caller = callerName(this.returnAddress);
    },
    onLeave: function (retval) {
      var originalOk = safeInt(retval) !== 0, err = null;
      try { if (!isNull(this.errorOut)) err = cfErrorText(this.errorOut.readPointer()); } catch (_) {}
      if (FORCE_ACCEPT_INVALID_CERTIFICATES) {
        clearTrustError(this.errorOut);
        retval.replace(ptr(1));
      }
      emit('VALIDATION', {
        protection: trustProtection(this.trust), source: 'SecTrustEvaluateWithError',
        verdict: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'FORCED_PASS' : (originalOk ? 'PASS' : 'FAIL'),
        originalVerdict: originalOk ? 'PASS' : 'FAIL',
        trust: pstr(this.trust), error: err, caller: this.caller
      });
    }
  });

  addr = findAddress('SecTrustEvaluate', ['Security']);
  if (addr) attachOnce(addr.address, 'SecTrustEvaluate', {
    onEnter: function (args) {
      this.trust = args[0]; this.resultOut = args[1]; this.caller = callerName(this.returnAddress);
    },
    onLeave: function (retval) {
      var originalStatus = safeInt(retval), result = -1;
      try { if (!isNull(this.resultOut)) result = this.resultOut.readS32(); } catch (_) {}
      var originalPass = originalStatus === 0 && trustResultPass(result);
      if (FORCE_ACCEPT_INVALID_CERTIFICATES) {
        try { if (!isNull(this.resultOut)) this.resultOut.writeS32(1); } catch (_) {}
        retval.replace(ptr(0));
      }
      emit('VALIDATION', {
        protection: trustProtection(this.trust), source: 'SecTrustEvaluate',
        verdict: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'FORCED_PASS' : (originalPass ? 'PASS' : 'FAIL'),
        originalVerdict: originalPass ? 'PASS' : 'FAIL', osStatus: originalStatus,
        trustResult: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'proceed' : trustResultName(result),
        trust: pstr(this.trust), caller: this.caller
      });
    }
  });

  addr = findAddress('SecTrustGetTrustResult', ['Security']);
  if (addr) attachOnce(addr.address, 'SecTrustGetTrustResult', {
    onEnter: function (args) { this.trust = args[0]; this.resultOut = args[1]; },
    onLeave: function (retval) {
      var status = safeInt(retval), result = -1;
      try { if (status === 0 && !isNull(this.resultOut)) result = this.resultOut.readS32(); } catch (_) {}
      if (FORCE_ACCEPT_INVALID_CERTIFICATES) {
        try { if (!isNull(this.resultOut)) this.resultOut.writeS32(1); } catch (_) {}
        retval.replace(ptr(0));
      }
      emit('TRUST_RESULT', {
        protection: trustProtection(this.trust), source: 'SecTrustGetTrustResult',
        verdict: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'FORCED_PASS' :
          (status === 0 && trustResultPass(result) ? 'PASS' : (status === 0 ? 'FAIL' : 'UNKNOWN')),
        originalTrustResult: trustResultName(result), osStatus: status,
        trustResult: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'proceed' : trustResultName(result),
        trust: pstr(this.trust)
      });
    }
  });

  ['SecTrustEvaluateAsyncWithError', 'SecTrustEvaluateAsync'].forEach(function (name) {
    var a = findAddress(name, ['Security']);
    if (!a) return;
    var kind = name === 'SecTrustEvaluateAsyncWithError' ? 'trust-async-error' : 'trust-async';
    attachOnce(a.address, name, {
      onEnter: function (args) {
        this.trust = args[0]; this.callback = args[2];
        this.ctx = {kind: kind, trust: args[0], trustKey: pstr(args[0]), source: name};
        this.watchOk = addPendingBlock(this.callback, this.ctx);
        if (this.ctx.trustKey) asyncTrusts[this.ctx.trustKey] = this.ctx;
      },
      onLeave: function (retval) {
        var status = safeInt(retval);
        if (status !== 0) {
          emit('VALIDATION', {
            protection: trustProtection(this.trust), source: name,
            verdict: 'FAIL', stage: 'evaluation could not start',
            osStatus: status, trust: pstr(this.trust)
          });
          finishCtx(this.ctx);
        } else {
          emit('VALIDATION_PENDING', {
            protection: trustProtection(this.trust), source: name,
            callbackObserved: !!this.watchOk, trust: pstr(this.trust)
          });
        }
      }
    });
  });
}

function authInfo(challengePtr) {
  var out = {authMethod: null, host: null, serverTrust: null, credential: null, credentialRetained: false};
  try {
    if (isNull(challengePtr) || !ObjC.available) return out;
    var ch = new ObjC.Object(challengePtr), space = ch.protectionSpace();
    if (space) {
      try { out.authMethod = space.authenticationMethod().toString(); } catch (_) {}
      try { out.host = space.host().toString(); } catch (_) {}
      if (isServerTrust(out.authMethod)) {
        try {
          var trust = space.serverTrust();
          var trustPtr = trust && trust.handle ? trust.handle : trust;
          if (!isNull(trustPtr)) {
            out.serverTrust = trust;
            var credentialClass = ObjC.classes.NSURLCredential;
            if (credentialClass) {
              var credential = credentialClass.credentialForTrust_(trust);
              if (credential) {
                out.credential = ObjC.retain(credential);
                out.credentialRetained = true;
              }
            }
          }
        } catch (_) {}
      }
    }
  } catch (_) {}
  return out;
}

function isServerTrust(method) {
  return method === 'NSURLAuthenticationMethodServerTrust' ||
    String(method || '').indexOf('ServerTrust') >= 0;
}

function challengeIndexes(selector) {
  if (selector.indexOf('URLSession:task:didReceiveChallenge:completionHandler:') >= 0)
    return {challenge: 4, block: 5, source: 'NSURLSessionTaskDelegate'};
  if (selector.indexOf('URLSession:didReceiveChallenge:completionHandler:') >= 0)
    return {challenge: 3, block: 4, source: 'NSURLSessionDelegate'};
  if (selector.indexOf('webView:didReceiveAuthenticationChallenge:completionHandler:') >= 0)
    return {challenge: 3, block: 4, source: 'WKNavigationDelegate/METASecureWebView'};
  if (selector.indexOf('connection:willSendRequestForAuthenticationChallenge:') >= 0)
    return {challenge: 3, block: null, source: 'NSURLConnectionDelegate'};
  return null;
}

function hookChallengeMethod(className, methodName, methodObj) {
  var sel = methodName.replace(/^[+-]\s\*/, ''), idx = challengeIndexes(sel);
  if (!idx) return;
  var imp;
  try { imp = methodObj.implementation; } catch (_) { return; }
  if (!imp || isNull(imp)) return;

  attachOnce(imp, 'challenge:' + className + ':' + sel, {
    onEnter: function (args) {
      var info = authInfo(args[idx.challenge]);
      if (!isServerTrust(info.authMethod)) return;
      this.serverTrustChallenge = true;
      this.challengeCtx = {
        kind: 'auth-challenge',
        protection: /WK|SecureWebView/.test(idx.source + className) ?
          'METASecureWebView provider / WebKit challenge' :
          'NSURLSession/NSURLConnection pinning challenge',
        source: idx.source + ' ' + className + ' - ' + sel,
        authMethod: info.authMethod, host: info.host, serverTrust: info.serverTrust,
        credential: info.credential, credentialRetained: info.credentialRetained
      };
      emit('CHALLENGE', {
        protection: this.challengeCtx.protection, source: this.challengeCtx.source,
        stage: 'server-trust challenge', host: info.host,
        authenticationMethod: info.authMethod
      });
      if (idx.block !== null)
        this.callbackObserved = addPendingBlock(args[idx.block], this.challengeCtx);
    },
    onLeave: function () {
      if (this.serverTrustChallenge && challengeIndexes(sel).block !== null && !this.callbackObserved)
        emit('CHALLENGE', {
          source: className + ' - ' + sel,
          stage: 'completion block not observed; verdict unavailable'
        });
      if (this.serverTrustChallenge &&
          (!this.callbackObserved || challengeIndexes(sel).block === null))
        releaseChallengeCredential(this.challengeCtx);
    }
  });
}

function hookChallengeSenderMethod(className, methodName, methodObj) {
  var sel = methodName.replace(/^[+-]\s\*/, ''), challengeIndex = null, decision = null;
  if (sel.indexOf('useCredential:forAuthenticationChallenge:') >= 0) {
    challengeIndex = 3; decision = 'PASS';
  } else if (sel.indexOf('cancelAuthenticationChallenge:') >= 0) {
    challengeIndex = 2; decision = 'FAIL';
  } else if (sel.indexOf('continueWithoutCredentialForAuthenticationChallenge:') >= 0) {
    challengeIndex = 2; decision = 'DEFERRED_TO_SYSTEM';
  } else if (sel.indexOf('rejectProtectionSpaceAndContinueWithChallenge:') >= 0) {
    challengeIndex = 2; decision = 'FAIL';
  }
  if (challengeIndex === null) return;
  var imp;
  try { imp = methodObj.implementation; } catch (_) { return; }
  if (!imp || isNull(imp)) return;
  attachOnce(imp, 'challenge-sender:' + className + ':' + sel, {
    onEnter: function (args) {
      var info = authInfo(args[challengeIndex]);
      if (!isServerTrust(info.authMethod)) return;
      emit('VALIDATION', {
        protection: 'NSURLAuthenticationChallenge sender',
        source: className + ' - ' + sel, verdict: decision,
        authenticationMethod: info.authMethod, host: info.host
      });
    }
  });
}

function boolReturnType(types) {
  var s = String(types || '').trim();
  while (s.length && 'rnNoORV'.indexOf(s.charAt(0)) >= 0) s = s.substring(1);
  return s.charAt(0) === 'B' || s.charAt(0) === 'c' || s.charAt(0) === 'C';
}

function hookPinningObjCMethod(className, methodName, methodObj) {
  var sel = methodName.replace(/^[+-]\s\*/, ''), imp, types;
  try { imp = methodObj.implementation; types = methodObj.types; } catch (_) { return; }
  if (!imp || isNull(imp)) return;
  attachOnce(imp, 'pin-method:' + className + ':' + sel, {
    onEnter: function () { this.started = Date.now(); },
    onLeave: function (retval) {
      var hasBool = boolReturnType(types), originalValue = safeInt(retval);
      var data = {
        protection: className.indexOf('METASecureWebView') >= 0 ||
          className.indexOf('SecureSSLHandler') >= 0 ? 'METASecureWebView' : 'FBSSLPinningVerifier',
        source: className + ' - ' + sel,
        verdict: hasBool ? (originalValue !== 0 ? 'PASS' : 'FAIL') : 'NO_BOOLEAN_RETURN',
        returnType: String(types || 'unknown')
      };
      if (hasBool && FORCE_ACCEPT_INVALID_CERTIFICATES) {
        retval.replace(ptr(1));
        data.verdict = 'FORCED_PASS';
        data.originalReturnValue = originalValue;
        data.returnValue = 1;
      } else if (hasBool) {
        data.returnValue = originalValue;
      }
      emit('VALIDATION', data);
    }
  });
}

function scanObjCClass(className) {
  var cls;
  try { cls = ObjC.classes[className]; } catch (_) { return; }
  var methods = [];
  try { methods = cls.$ownMethods || []; } catch (_) {}

  for (var j = 0; j < methods.length; j++) {
    var methodName = String(methods[j]);
    var normalized = methodName.replace(/^[+-]\s\*/, '');
    var methodObj;
    try {
      methodObj = cls[methodName] ||
        cls['- ' + normalized] ||
        cls['+ ' + normalized];
    } catch (_) { continue; }
    if (!methodObj) continue;
    if (challengeIndexes(normalized))
      hookChallengeMethod(className, methodName, methodObj);
    hookChallengeSenderMethod(className, methodName, methodObj);

    var sslClass =
      /FBSSLPinningVerifier|METASecureWebView|SecureSSLHandler|WeakSSLPinningProvider/
        .test(className);
    var socketRocket =
      /SRWebSocket/.test(className) &&
      /pinnningPolicyWithCertificates|SSL|Trust/i.test(normalized);

    if ((sslClass &&
         /checkPinning|pinning|challenge|trust|verify|certificate|ssl/i.test(normalized)) ||
        socketRocket) {
      hookPinningObjCMethod(className, methodName, methodObj);
    }
  }
}

function scanObjC() {
  if (!ObjC.available || objcScanRunning) return;
  var names;
  try { names = Object.keys(ObjC.classes); }
  catch (_) { return; }

  objcScanRunning = true;
  var cursor = 0;
  function scanBatch() {
    var start = cursor;
    var end = Math.min(cursor + 100, names.length);
    for (; cursor < end; cursor++) {
      var className = names[cursor];
      if (objcScannedClasses[className]) continue;
      objcScannedClasses[className] = true;
      try { scanObjCClass(className); }
      catch (e) { emit('SCAN_ERROR', {className: className, error: String(e)}); }
    }
    emit('SCAN_PROGRESS', {from: start, to: end, total: names.length});
    if (cursor < names.length) {
      setTimeout(scanBatch, 0);
      return;
    }
    objcScanRunning = false;
    emit('INSTALL_STAGE', {stage: 'objc_scan_complete', classes: names.length});
  }
  setTimeout(scanBatch, 0);
}

function hookProxygen() {
  var mod = findModule('FBSharedFramework');
  if (!mod) return;

  hookTlsCallbackRegistrations();

  var ctor = findSymbolFragment('FBSharedFramework', 'DefaultCertificatePinnerC1');
  if (ctor) attachOnce(ctor.address, 'proxygen-pinner-constructor', {
    onEnter: function (args) {
      emit('PINNING_ACTIVE', {
        protection: 'Proxygen DefaultCertificatePinner',
        source: ctor.symbol, object: pstr(args[0])
      });
    }
  });

  var pinData = findSymbolFragment('FBSharedFramework', 'PinningData15getKeySHA256Set');
  if (pinData) attachOnce(pinData.address, 'proxygen-pinset-derived', {
    onEnter: function () {
      emit('PINNING_ACTIVE', {
        protection: 'Proxygen SHA-256 key pin set', source: pinData.symbol
      });
    }
  });

  var verify = findAddress('X509_verify_cert', ['FBSharedFramework']);
  if (verify) {
    var getErr = findAddress('X509_STORE_CTX_get_error', ['FBSharedFramework']);
    var setErr = findAddress('X509_STORE_CTX_set_error', ['FBSharedFramework']);
    var errText = findAddress('X509_verify_cert_error_string', ['FBSharedFramework']);
    var getErrFn = getErr ? new NativeFunction(getErr.address, 'int', ['pointer']) : null;
    var setErrFn = setErr ? new NativeFunction(setErr.address, 'void', ['pointer', 'int']) : null;
    var errTextFn = errText ? new NativeFunction(errText.address, 'pointer', ['long']) : null;
    attachOnce(verify.address, 'proxygen-X509-verify-cert', {
      onEnter: function (args) {
        this.ctx = args[0]; this.caller = callerName(this.returnAddress);
      },
      onLeave: function (retval) {
        var originalResult = safeInt(retval), ec = null, text = null;
        try { if (getErrFn) ec = getErrFn(this.ctx); } catch (_) {}
        try {
          if (ec !== null && ec !== 0 && errTextFn) {
            var p = errTextFn(ec);
            if (!isNull(p)) text = p.readCString();
          }
        } catch (_) {}
        if (FORCE_ACCEPT_INVALID_CERTIFICATES) {
          try { if (setErrFn) setErrFn(this.ctx, 0); } catch (_) {}
          retval.replace(ptr(1));
        }
        emit('VALIDATION', {
          protection: 'Proxygen/Fizz TLS certificate chain', source: 'X509_verify_cert',
          verdict: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'FORCED_PASS' :
            (originalResult === 1 ? 'PASS' :
              (originalResult === 0 || originalResult === -1 ? 'FAIL' : 'UNKNOWN')),
          originalChainResult: originalResult, x509Error: ec, error: text,
          caller: this.caller
        });
      }
    });
  }

  var getVerify = findAddress('SSL_get_verify_result', ['FBSharedFramework']);
  if (getVerify) attachOnce(getVerify.address, 'proxygen-SSL_get_verify_result', {
    onEnter: function (args) { this.ssl = args[0]; },
    onLeave: function (retval) {
      var originalCode = safeInt(retval);
      if (FORCE_ACCEPT_INVALID_CERTIFICATES) retval.replace(ptr(0));
      emit('VALIDATION', {
        protection: 'Proxygen/Fizz TLS certificate chain', source: 'SSL_get_verify_result',
        verdict: FORCE_ACCEPT_INVALID_CERTIFICATES ? 'FORCED_PASS' :
          (originalCode === 0 ? 'PASS' : 'FAIL'),
        originalX509Error: originalCode, ssl: pstr(this.ssl)
      });
    }
  });

  var vtable = findSymbolFragment('FBSharedFramework', '__ZTVN8proxygen10httpclient19PinningSSLCallbacksE');
  if (vtable) {
    var vt = stripPtr(vtable.address), modStart = stripPtr(mod.base), modEnd = modStart.add(mod.size);
    pinVtableRanges.push({start: vt, end: vt.add(0x100)});
    for (var slot = 2; slot < 18; slot++) {
      var target;
      try { target = stripPtr(vt.add(slot * Process.pointerSize).readPointer()); } catch (_) { continue; }
      if (!execRange(target)) continue;
      var targetKey = pstr(target);
      if (pinCallbackTargets[targetKey]) continue;
      pinCallbackTargets[targetKey] = true;
      (function (slotNo, targetPtr) {
        attachOnce(targetPtr, 'proxygen-pinning-callback-slot-' + slotNo, {
          onEnter: function (args) {
            var selfVt;
            try { selfVt = stripPtr(args[0].readPointer()); } catch (_) { return; }
            var isPinObject = false;
            for (var q = 0; q < pinVtableRanges.length; q++) {
              if (selfVt.compare(pinVtableRanges[q].start) >= 0 &&
                  selfVt.compare(pinVtableRanges[q].end) < 0) {
                isPinObject = true; break;
              }
            }
            if (!isPinObject) return;
            var sym = '';
            try { sym = DebugSymbol.fromAddress(targetPtr).name || ''; } catch (_) {}
            var verdict = /success|verified|accepted/i.test(sym) ? 'PASS' :
              (/failure|failed|reject|error/i.test(sym) ? 'FAIL' : 'CALLBACK_ONLY');
            emit('PROXYGEN_PIN_CALLBACK', {
              protection: 'Proxygen PinningSSLCallbacks', slot: slotNo,
              callback: sym || targetKey, verdict: verdict,
              note: verdict === 'CALLBACK_ONLY' ?
                'Callback reached; this stripped slot has no reliable pass/fail name.' : null
            });
          }
        });
      })(slot, target);
    }
  }
}

function installAll() {
  emit('INSTALL_STAGE', {stage: 'trust_hooks'});
  try { hookTrustApis(); }
  catch (e) { emit('INSTALL_ERROR', {area: 'Security trust hooks', error: String(e)}); }

  emit('INSTALL_STAGE', {stage: 'proxygen_hooks'});
  try { hookProxygen(); }
  catch (e) { emit('INSTALL_ERROR', {area: 'Proxygen hooks', error: String(e)}); }

  emit('INSTALL_STAGE', {stage: 'objc_scan_scheduled'});
}

emit('START', {
  app: 'iOS app (instrumented)',
  mode: 'certificate acceptance override for mitmproxy analysis',
  changesTrustDecisions: true
});

setTimeout(installAll, 0);
setTimeout(installAll, 1500);
setTimeout(installAll, 5000);

try {
  if (Process.attachModuleObserver) {
    Process.attachModuleObserver({
      onAdded: function (module) {
        if (/Security|CoreFoundation|FBSharedFramework|FBReactNativeProductsFramework/.test(module.name))
          setTimeout(installAll, 100);
      }
    });
  }
} catch (_) {}
