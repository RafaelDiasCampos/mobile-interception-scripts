'use strict';

const APP_BUNDLE_MARKER = 'iAliexpress.app/';
const hookedAddresses = new Set();
const hookedObjCMethods = new Set();
const scannedObjCMethods = new Set();
const hookedBlockInvokes = new Set();
const hookedBooleanBlockInvokes = new Set();
const trustHosts = new Map();
const blockHosts = new Map();
const booleanBlockContexts = new Map();

const TRUST_RESULT_NAMES = {
  0: 'INVALID',
  1: 'PROCEED',
  2: 'CONFIRM',
  3: 'DENY',
  4: 'UNSPECIFIED',
  5: 'RECOVERABLE_TRUST_FAILURE',
  6: 'FATAL_TRUST_FAILURE',
  7: 'OTHER_ERROR'
};

const CERTIFICATE_URL_ERROR_CODES = new Set([
  -1201, // server certificate has bad date
  -1202, // server certificate is untrusted
  -1203, // server certificate has unknown root
  -1204, // server certificate has been revoked
  -1205, // server certificate is required
  -1206, // client certificate was rejected
  -1207  // server certificate is not yet valid
]);

const TLS_URL_ERROR_CODES = {
  '-1200': 'secure connection failed',
  '-1201': 'server certificate has bad date',
  '-1202': 'server certificate is untrusted',
  '-1203': 'server certificate has unknown root',
  '-1204': 'server certificate has been revoked',
  '-1205': 'server certificate is required',
  '-1206': 'client certificate was rejected',
  '-1207': 'server certificate is not yet valid'
};

function callerModule(address) {
  try {
    return Process.findModuleByAddress(address);
  } catch (_) {
    return null;
  }
}

function isAppBundleAddress(address) {
  const module = callerModule(address);
  if (!module) return false;
  return module.name === 'iAliexpress' ||
    (module.path && module.path.indexOf(APP_BUNDLE_MARKER) !== -1);
}

function moduleNameAt(address) {
  const module = callerModule(address);
  return module ? module.name : '<unknown>';
}

function findGlobalExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      const address = Module.findGlobalExportByName(name);
      if (address) return address;
    }
  } catch (_) {}

  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      const address = Module.getGlobalExportByName(name);
      if (address) return address;
    }
  } catch (_) {}

  try {
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      const address = modules[i].findExportByName(name);
      if (address) return address;
    }
  } catch (_) {}
  return null;
}

function pointerKey(pointer) {
  try {
    if (pointer && pointer.handle) pointer = pointer.handle;
    return pointer && !pointer.isNull() ? pointer.toString() : '';
  } catch (_) {
    return '';
  }
}

function objectString(object, selector) {
  try {
    if (!object) return '';
    const value = selector ? object[selector]() : object;
    return value ? value.toString() : '';
  } catch (_) {
    return '';
  }
}

function errorDescription(errorPointer) {
  try {
    if (!ObjC.available || !errorPointer || errorPointer.isNull()) return '';
    const error = new ObjC.Object(errorPointer);
    return objectString(error, 'localizedDescription');
  } catch (_) {
    return '';
  }
}

function trustHost(trustPointer) {
  return trustHosts.get(pointerKey(trustPointer)) || '<host unavailable>';
}

function rememberTrustHost(trustPointer, host) {
  const key = pointerKey(trustPointer);
  if (!key || !host) return;
  if (trustHosts.size > 512) trustHosts.clear();
  trustHosts.set(key, host);
}

function installExportWatch(name, kind) {
  const address = findGlobalExport(name);
  if (!address) return false;

  const key = kind + ':' + address.toString();
  if (hookedAddresses.has(key)) return true;
  hookedAddresses.add(key);

  try {
    Interceptor.attach(address, {
      onEnter(args) {
        this.shouldLog = isAppBundleAddress(this.returnAddress);
        if (!this.shouldLog) return;
        this.caller = moduleNameAt(this.returnAddress);

        if (kind === 'trustWithError') {
          this.trust = args[0];
          this.errorOut = args[1];
          this.host = trustHost(this.trust);
        } else if (kind === 'trustLegacy') {
          this.trust = args[0];
          this.resultOut = args[1];
          this.host = trustHost(this.trust);
        }
      },

      onLeave(retval) {
        if (!this.shouldLog) return;

        if (kind === 'trustWithError') {
          const originallyPassed = retval.toInt32() !== 0;
          let detail = '';
          if (!originallyPassed && this.errorOut && !this.errorOut.isNull()) {
            try {
              const errorPointer = this.errorOut.readPointer();
              const description = errorDescription(errorPointer);
              if (description) detail = ' error="' + description + '"';
            } catch (_) {}
          }
          retval.replace(ptr(1));
          console.log('[AliExpress/iOS] [pinning bypass] SecTrustEvaluateWithError caller=' +
            this.caller + ' host=' + this.host + ' original=' +
            (originallyPassed ? 'PASS' : 'FAIL') + ' forced=PASS' + detail);
        } else if (kind === 'trustLegacy') {
          const originalStatus = retval.toInt32();
          let trustResult = -1;
          try {
            if (this.resultOut && !this.resultOut.isNull()) {
              trustResult = this.resultOut.readU32();
              this.resultOut.writeU32(1); // kSecTrustResultProceed
            }
          } catch (_) {}
          retval.replace(ptr(0)); // errSecSuccess
          console.log('[AliExpress/iOS] [pinning bypass] SecTrustEvaluate caller=' +
            this.caller + ' host=' + this.host +
            ' originalStatus=' + originalStatus +
            ' originalTrustResult=' +
            (TRUST_RESULT_NAMES[trustResult] || 'UNKNOWN') +
            '(' + trustResult + ') forced=PROCEED');
        } else if (kind === 'sslVerifyResult') {
          const code = retval.toInt32();
          retval.replace(ptr(0));
          console.log('[AliExpress/iOS] [pinning bypass] SSL_get_verify_result caller=' +
            this.caller + ' originalVerifyCode=' + code + ' forced=OK');
        } else if (kind === 'x509VerifyCert') {
          const code = retval.toInt32();
          retval.replace(ptr(1));
          console.log('[AliExpress/iOS] [pinning bypass] X509_verify_cert caller=' +
            this.caller + ' originalReturn=' + code + ' forced=PASS');
        }
      }
    });
    console.log('[AliExpress/iOS] [hook] ' + name + ' @ ' + address);
    return true;
  } catch (e) {
    console.log('[AliExpress/iOS] [hook error] ' + name + ': ' + e);
    return false;
  }
}

function installTrustApiHooks() {
  installExportWatch('SecTrustEvaluateWithError', 'trustWithError');
  installExportWatch('SecTrustEvaluate', 'trustLegacy');
  installExportWatch('SSL_get_verify_result', 'sslVerifyResult');
  installExportWatch('X509_verify_cert', 'x509VerifyCert');

  [
    'SSL_CTX_set_verify',
    'SSL_set_verify',
    'SSL_CTX_set_custom_verify',
    'SSL_set_custom_verify'
  ].forEach(installTlsVerifyConfigHook);
}

function installTlsVerifyConfigHook(name) {
  const address = findGlobalExport(name);
  if (!address) return false;

  const key = 'tlsVerifyConfig:' + address.toString();
  if (hookedAddresses.has(key)) return true;
  hookedAddresses.add(key);

  try {
    Interceptor.attach(address, {
      onEnter(args) {
        if (!isAppBundleAddress(this.returnAddress)) return;
        let originalMode = -1;
        try { originalMode = args[1].toInt32(); } catch (_) {}
        args[1] = ptr(0); // SSL_VERIFY_NONE
        args[2] = ptr(0); // no custom verification callback
        console.log('[AliExpress/iOS] [pinning bypass] ' + name + ' caller=' +
          moduleNameAt(this.returnAddress) + ' originalMode=' +
          originalMode + ' forced=VERIFY_NONE');
      }
    });
    console.log('[AliExpress/iOS] [hook] ' + name + ' @ ' + address);
    return true;
  } catch (e) {
    console.log('[AliExpress/iOS] [hook error] ' + name + ': ' + e);
    return false;
  }
}

function challengeInfo(challengePointer) {
  const result = {
    host: '<host unavailable>',
    authMethod: '<unavailable>',
    trust: null
  };
  try {
    if (!ObjC.available || !challengePointer || challengePointer.isNull()) return result;
    const challenge = new ObjC.Object(challengePointer);
    const protectionSpace = challenge.protectionSpace();
    if (!protectionSpace) return result;

    result.host = objectString(protectionSpace, 'host') || result.host;
    result.authMethod = objectString(protectionSpace, 'authenticationMethod') || result.authMethod;
    if (result.authMethod.indexOf('ServerTrust') !== -1) {
      result.trust = protectionSpace.serverTrust();
      if (result.trust && result.trust.handle) result.trust = result.trust.handle;
      rememberTrustHost(result.trust, result.host);
    }
  } catch (_) {}
  return result;
}

function dispositionName(value) {
  const names = {
    0: 'USE_CREDENTIAL',
    1: 'DEFAULT_HANDLING',
    2: 'CANCEL',
    3: 'REJECT_PROTECTION_SPACE'
  };
  return names[value] || 'UNKNOWN(' + value + ')';
}

function installChallengeBlock(blockPointer, host, owner, trustPointer) {
  try {
    if (!blockPointer || blockPointer.isNull()) return;
    const blockKey = pointerKey(blockPointer);
    if (blockKey) {
      if (blockHosts.size > 512) blockHosts.clear();
      blockHosts.set(blockKey, { host: host, trust: trustPointer });
    }

    // A block literal stores isa, flags, reserved, invoke, then descriptor.
    const invokeOffset = Process.pointerSize + 8;
    const invoke = blockPointer.add(invokeOffset).readPointer();
    if (invoke.isNull()) return;

    const invokeKey = invoke.toString();
    if (hookedBlockInvokes.has(invokeKey)) return;
    hookedBlockInvokes.add(invokeKey);

    Interceptor.attach(invoke, {
      onEnter(args) {
        let disposition = -1;
        try {
          disposition = args[1].toInt32();
        } catch (_) {}
        const originalDisposition = disposition;
        const callbackBlockKey = pointerKey(args[0]);
        const callbackContext = blockHosts.get(callbackBlockKey);
        const callbackHost = callbackContext ? callbackContext.host : '<host unavailable>';
        if (callbackBlockKey) blockHosts.delete(callbackBlockKey);
        let credentialProvided = args[2] && !args[2].isNull();

        if (callbackContext && callbackContext.trust &&
            !callbackContext.trust.isNull()) {
          try {
            const trust = new ObjC.Object(callbackContext.trust);
            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
            if (credential && credential.handle && !credential.handle.isNull()) {
              args[1] = ptr(0); // NSURLSessionAuthChallengeUseCredential
              args[2] = credential.handle;
              disposition = 0;
              credentialProvided = true;
              console.log('[AliExpress/iOS] [pinning bypass] owner=' + owner +
                ' host=' + callbackHost +
                ' challenge=SERVER_TRUST action=USE_TRUST_CREDENTIAL');
            }
          } catch (e) {
            console.log('[AliExpress/iOS] [bypass error] server-trust credential: ' + e);
          }
        }

        let outcome = 'INDETERMINATE';
        if (disposition === 0) outcome = originalDisposition === 0 ? 'ACCEPTED_BY_APP' : 'FORCED_ACCEPT';
        else if (disposition === 2 || disposition === 3) outcome = 'REJECTED_BY_APP';
        else if (disposition === 1) outcome = 'DEFERRED_TO_SYSTEM';

        console.log('[AliExpress/iOS] [server trust] owner=' + owner +
          ' host=' + callbackHost +
          ' outcome=' + outcome +
          ' disposition=' + dispositionName(disposition) +
          ' originalDisposition=' + dispositionName(originalDisposition) +
          ' credential=' + (credentialProvided ? 'present' : 'none'));
      }
    });
    console.log('[AliExpress/iOS] [hook] server-trust completion block @ ' + invoke);
  } catch (e) {
    console.log('[AliExpress/iOS] [hook error] server-trust completion block: ' + e);
  }
}

function installBooleanTrustBlock(blockPointer, host, owner) {
  try {
    if (!blockPointer || blockPointer.isNull()) return;
    const blockKey = pointerKey(blockPointer);
    if (!blockKey) return;
    if (booleanBlockContexts.size > 512) booleanBlockContexts.clear();
    booleanBlockContexts.set(blockKey, { host: host, owner: owner });

    const invokeOffset = Process.pointerSize + 8;
    const invoke = blockPointer.add(invokeOffset).readPointer();
    if (invoke.isNull()) return;
    const invokeKey = invoke.toString();
    if (hookedBooleanBlockInvokes.has(invokeKey)) return;
    hookedBooleanBlockInvokes.add(invokeKey);

    Interceptor.attach(invoke, {
      onEnter(args) {
        const callbackBlockKey = pointerKey(args[0]);
        const context = booleanBlockContexts.get(callbackBlockKey) ||
          { host: '<host unavailable>', owner: owner };
        if (callbackBlockKey) booleanBlockContexts.delete(callbackBlockKey);
        try {
          args[1] = ptr(1); // first completion value is the trust result
          console.log('[AliExpress/iOS] [pinning bypass] owner=' + context.owner +
            ' host=' + context.host +
            ' challenge=CUSTOM_SERVER_TRUST action=ACCEPT');
        } catch (e) {
          console.log('[AliExpress/iOS] [bypass error] custom server-trust completion: ' + e);
        }
      }
    });
    console.log('[AliExpress/iOS] [hook] custom server-trust completion block @ ' + invoke);
  } catch (e) {
    console.log('[AliExpress/iOS] [hook error] custom server-trust completion block: ' + e);
  }
}

function requestInfo(requestPointer) {
  const result = { scheme: '', host: '' };
  try {
    if (!ObjC.available || !requestPointer || requestPointer.isNull()) return result;
    const request = new ObjC.Object(requestPointer);
    let url = null;
    try { url = request.URL(); } catch (_) {}
    if (!url) return result;
    result.scheme = objectString(url, 'scheme');
    result.host = objectString(url, 'host');
  } catch (_) {}
  return result;
}

function taskInfo(taskPointer) {
  const result = { scheme: '', host: '' };
  try {
    if (!ObjC.available || !taskPointer || taskPointer.isNull()) return result;
    const task = new ObjC.Object(taskPointer);
    let request = null;
    try { request = task.currentRequest(); } catch (_) {}
    if (!request) {
      try { request = task.originalRequest(); } catch (_) {}
    }
    return requestInfo(request);
  } catch (_) {}
  return result;
}

function logTaskCompletion(taskPointer, errorPointer, owner) {
  const request = taskInfo(taskPointer);
  if (!errorPointer || errorPointer.isNull()) {
    if (request.scheme.toLowerCase() === 'https') {
      console.log('[AliExpress/iOS] [HTTPS task] owner=' + owner + ' host=' + request.host +
        ' result=COMPLETED certificateValidation=NO_FAILURE_REPORTED');
    }
    return;
  }

  let domain = '<unknown>';
  let code = 0;
  let description = '';
  try {
    const error = new ObjC.Object(errorPointer);
    domain = objectString(error, 'domain') || domain;
    code = Number(error.code());
    description = objectString(error, 'localizedDescription');
  } catch (_) {}

  const isUrlError = domain === 'NSURLErrorDomain';
  if (isUrlError && CERTIFICATE_URL_ERROR_CODES.has(code)) {
    console.log('[AliExpress/iOS] [certificate validation] owner=' + owner + ' host=' + request.host +
      ' result=FAIL errorCode=' + code +
      ' reason="' + (TLS_URL_ERROR_CODES[String(code)] || description) + '"');
  } else if (isUrlError && code === -1200) {
    console.log('[AliExpress/iOS] [TLS connection] owner=' + owner + ' host=' + request.host +
      ' result=FAILED certificateValidation=POSSIBLE errorCode=-1200' +
      ' reason="' + (TLS_URL_ERROR_CODES['-1200'] || description) + '"');
  } else if (/cert|trust|pin|ssl/i.test(domain + ' ' + description)) {
    console.log('[AliExpress/iOS] [candidate] owner=' + owner +
      ' host=' + request.host + ' result=ERROR domain=' + domain +
      ' code=' + code + ' description="' + description + '"');
  } else {
    console.log('[AliExpress/iOS] [HTTPS task] owner=' + owner + ' host=' + request.host +
      ' result=ERROR certificateValidation=INDETERMINATE domain=' + domain +
      ' code=' + code + ' description="' + description + '"');
  }
}

function installObjCNetworkHooks() {
  if (!ObjC.available) return;

  const selectors = [
    {
      selector: '- URLSession:didReceiveChallenge:completionHandler:',
      kind: 'challenge',
      challengeIndex: 3,
      blockIndex: 4
    },
    {
      selector: '- URLSession:task:didReceiveChallenge:completionHandler:',
      kind: 'challenge',
      challengeIndex: 4,
      blockIndex: 5
    },
    {
      selector: '- URLSession:task:didCompleteWithError:',
      kind: 'taskComplete',
      taskIndex: 3,
      errorIndex: 4
    },
    {
      selector: '- evaluateServerTrust:forRequest:completionHandler:',
      kind: 'customTrust',
      trustIndex: 2,
      requestIndex: 3,
      blockIndex: 4
    },
    {
      selector: '+ evaluateServerTrust:forRequest:completionHandler:',
      kind: 'customTrust',
      trustIndex: 2,
      requestIndex: 3,
      blockIndex: 4
    }
  ];

  let classes = [];
  try {
    classes = Object.keys(ObjC.classes);
  } catch (_) {
    return;
  }

  selectors.forEach(function (spec) {
    classes.forEach(function (className) {
      try {
        const scanKey = className + ':' + spec.selector;
        if (scannedObjCMethods.has(scanKey)) return;
        scannedObjCMethods.add(scanKey);

        const cls = ObjC.classes[className];
        const method = cls && cls[spec.selector];
        if (!method) return;

        const implementation = method.implementation;
        const module = callerModule(implementation);
        if (!module || !isAppBundleAddress(implementation)) return;

        const key = spec.selector + ':' + implementation.toString();
        if (hookedObjCMethods.has(key)) return;
        hookedObjCMethods.add(key);

        Interceptor.attach(implementation, {
          onEnter(args) {
            if (spec.kind === 'challenge') {
              const info = challengeInfo(args[spec.challengeIndex]);
              if (info.authMethod.indexOf('ServerTrust') === -1) return;

              this.isServerTrustChallenge = true;
              this.host = info.host;
              this.owner = className + ' ' + spec.selector;
              console.log('[AliExpress/iOS] [server trust challenge] owner=' + this.owner +
                ' host=' + info.host +
                ' authMethod=' + info.authMethod +
                ' trust=' + pointerKey(info.trust));
              installChallengeBlock(args[spec.blockIndex], info.host, this.owner, info.trust);
            } else if (spec.kind === 'taskComplete') {
              logTaskCompletion(args[spec.taskIndex], args[spec.errorIndex], className);
            } else if (spec.kind === 'customTrust') {
              const request = requestInfo(args[spec.requestIndex]);
              const trustKey = pointerKey(args[spec.trustIndex]);
              rememberTrustHost(args[spec.trustIndex], request.host);
              console.log('[AliExpress/iOS] [app server trust] owner=' + className +
                ' host=' + (request.host || '<host unavailable>') +
                ' trust=' + trustKey);
              installBooleanTrustBlock(args[spec.blockIndex], request.host, className);
            }
          }
        });
        console.log('[AliExpress/iOS] [hook] ' + className + ' ' + spec.selector);
      } catch (_) {}
    });
  });
}

function installAllHooks() {
  installTrustApiHooks();
}

installAllHooks();
console.log('[AliExpress/iOS] [ready] Native TLS bypass hooks installed; NSURLSession Objective-C scanning disabled.');
