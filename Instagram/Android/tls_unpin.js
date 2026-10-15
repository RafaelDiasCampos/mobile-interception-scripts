'use strict';

const OPTIONS = {
    enabled: true,
    logFirstHits: 2,
    appHookDelayMs: 200,
    hookApplicationAttach: false,
    earlyAppHooks: false,
    hooks: {
        platformPins: true,
        platformTrust: true,
        conscryptTrust: true,
        javaTlsDiagnostics: true,

        mnsJavaVerifier: true,
        facebookPinningTrust: true,
        trustManagerWrapper: true,
        hucPinner: true,
        okhttpPinner: true,
        hostnameVerifiers: true,
        mnsConfigAccessors: true,
        mnsConfigConstructors: true,
        webviewSslErrors: true,
        chromiumCertificates: true,
        chromiumSslErrors: true,
        nativeOpenSsl: false,
        nativeTlsChain: true,
        nativeFizzVerifier: true,
        nativeMbedTlsVerifier: true,
        nativeMbedTlsHandshake: true,
        nativeMnsPins: true,
        nativeHostnameVerifier: true,
        nativeTlsDiagnostics: true,
        nativePinner: true,
        nativeVerificationCallbacks: true,
        nativeVerifyWithMetrics: true
    }
};

const PLATFORM_GROUPS = ['platformPins', 'platformTrust', 'conscryptTrust',
    'javaTlsDiagnostics'];
const APP_GROUPS = ['mnsJavaVerifier', 'facebookPinningTrust',
    'trustManagerWrapper', 'hucPinner', 'okhttpPinner', 'hostnameVerifiers',
    'mnsConfigAccessors', 'mnsConfigConstructors', 'webviewSslErrors',
    'chromiumCertificates', 'chromiumSslErrors'];
const NATIVE_GROUPS = ['nativeTlsChain', 'nativeFizzVerifier',
    'nativeMbedTlsVerifier', 'nativeMbedTlsHandshake', 'nativeMnsPins', 'nativeHostnameVerifier',
    'nativeTlsDiagnostics', 'nativePinner',
    'nativeVerificationCallbacks', 'nativeVerifyWithMetrics'];

function enabled(name) {
    return OPTIONS.enabled && name !== 'nativeOpenSsl' && OPTIONS.hooks[name] === true;
}
function anyEnabled(names) { return names.some(enabled); }
function enabledGroups() { return Object.keys(OPTIONS.hooks).filter(enabled); }

const PREFIX = '[Instagram/Android]';
const INSTALLED = new Set();
const HITS = Object.create(null);
const ERRORS = Object.create(null);
const PENDING = new Set();
const LISTENERS = [];
const NATIVE_ADDRESSES = new Set();
const NATIVE_VERIFICATION = Object.create(null);
const NATIVE_PATHS = Object.create(null);
const JAVA_VERIFICATION_PATHS = Object.create(null);
const JAVA_TLS_EXCEPTIONS = Object.create(null);
const TLS_OUTCOMES = { calls: 0, errorCounts: Object.create(null), lastTerminal: null };
let moduleObserver = null;
let applicationLoader = null;
let appPassRunning = false;
let appPassesCompleted = 0;

function beforeAttachPassEnabled() {
    return OPTIONS.enabled && anyEnabled(APP_GROUPS) &&
        OPTIONS.earlyAppHooks === true && OPTIONS.hookApplicationAttach === true &&
        OPTIONS.appHookDelayMs === 0;
}

function nativeCoverage() {
    const labels = ['native TLS chain verifier [SSL state]',
        'Fizz certificate chain decision [call site]',
        'Fizz certificate chain decision [libscrollmerged.so]',
        'MNS MbedTLS chain decision [call site]',
        'MbedTLS handshake certificate decision [client]',
        'MNS native pin decision [call site]',
        'DefaultCertificatePinner::check [result object]',
        'SSLVerificationCallbacks::verifySSLCertificate [result object]',
        'SSLVerification::verifyWithMetrics [bool]',
        'HostnameVerifier::verifyHostname [indirect result]'];
    return labels.map(label => ({ check: label, installed: INSTALLED.has(label),
        hits: HITS[label] || 0 }));
}

function log(message) { console.log(PREFIX + ' ' + message); }

function hit(label) {
    HITS[label] = (HITS[label] || 0) + 1;
    if (HITS[label] <= OPTIONS.logFirstHits) log('used ' + label);
}

function error(label, message) {
    const text = String(message);
    if (ERRORS[label] !== text) {
        ERRORS[label] = text;
        log('warning ' + label + ': ' + text);
    }
}

function bytesHex(address, length) {
    return Array.from(new Uint8Array(address.readByteArray(length)),
        b => b.toString(16).padStart(2, '0')).join('');
}

function nativeAttach(module, address, label, callbacks) {
    if (address === null) return false;
    const key = address.toString();
    if (NATIVE_ADDRESSES.has(key)) return true;
    try {
        const listener = Interceptor.attach(address, callbacks);
        LISTENERS.push({ module: module.name, base: module.base.toString(),
            address: key, label: label, listener: listener });
        NATIVE_ADDRESSES.add(key);
        INSTALLED.add(label);
        log('hooked ' + label);
        return true;
    } catch (e) {
        error(label, e);
        return false;
    }
}

function clearStoreError(store, label) {
    if (store === undefined || store === null || store.isNull()) return false;
    try {
        const field = store.add(0xb0);
        const before = field.readS32();
        if (before < 0 || before > 79) {
            error(label, 'unexpected X509 error field; left unchanged: ' + before);
            return false;
        }
        field.writeS32(0);
        return true;
    } catch (e) { error(label + ' context', e); return false; }
}

function nativeDiagnostic(label, detail) {
    const entry = NATIVE_VERIFICATION[label] || { calls: 0 };
    entry.calls++;
    Object.assign(entry, detail);
    NATIVE_VERIFICATION[label] = entry;
    if (entry.calls <= OPTIONS.logFirstHits)
        log(label + ' ' + JSON.stringify(detail));
}

function nativeHostname(address) {
    if (!address || address.isNull()) return null;
    try {
        const tag = address.add(23).readU8();
        const length = (tag & 0x80) !== 0 ? Number(address.add(8).readU64()) : tag;
        if (!Number.isSafeInteger(length) || length < 1 || length > 253 ||
            ((tag & 0x80) === 0 && length > 22)) return null;
        const data = (tag & 0x80) !== 0 ? address.readPointer() : address;
        if (data.isNull()) return null;
        const bytes = new Uint8Array(data.readByteArray(length));
        const value = Array.from(bytes, b => String.fromCharCode(b)).join('');
        return /^[A-Za-z0-9_.:\[\]-]+$/.test(value) ? value : null;
    } catch (_) { return null; }
}

function nativeCallInfo(module, invocation, hostAddress) {
    if (!enabled('nativeTlsDiagnostics')) return null;
    let caller = null;
    try {
        const address = invocation.returnAddress;
        if (address && !address.isNull()) {
            const owner = Process.findModuleByAddress(address);
            caller = owner ? { module: owner.name,
                offset: address.sub(owner.base).toString() } :
                { module: null, address: address.toString() };
        }
    } catch (_) { }
    return { host: nativeHostname(hostAddress), module: module.name, processId: Process.id,
        caller: caller, threadId: invocation.threadId || null,
        timestamp: new Date().toISOString() };
}

function nativeCStringHostname(address) {
    if (!address || address.isNull()) return null;
    try {
        let value = '';
        for (let i = 0; i <= 253; i++) {
            const byte = address.add(i).readU8();
            if (byte === 0)
                return value.length > 0 && /^[A-Za-z0-9_.:\[\]-]+$/.test(value) ? value : null;
            if (i === 253 || byte < 0x21 || byte > 0x7e) return null;
            value += String.fromCharCode(byte);
        }
    } catch (_) { }
    return null;
}

function mbedTlsCallInfo(module, invocation, ssl) {
    if (!enabled('nativeTlsDiagnostics')) return null;
    const info = nativeCallInfo(module, invocation, null);
    try {
        info.sslAddress = ssl.toString();
        info.host = nativeCStringHostname(ssl.add(0x188).readPointer());
    } catch (_) { info.host = null; }
    return info;
}

function nativePathDiagnostic(label, info, detail) {
    if (!enabled('nativeTlsDiagnostics')) return;
    const values = Object.assign({ host: null, module: null, caller: null }, info || {}, detail);
    const key = JSON.stringify([label, values.host, values.module, values.caller]);
    if (!NATIVE_PATHS[key] && Object.keys(NATIVE_PATHS).length >= 64) return;
    const entry = NATIVE_PATHS[key] || { check: label, calls: 0 };
    entry.calls++;
    Object.assign(entry, values);
    NATIVE_PATHS[key] = entry;
    if (entry.calls <= OPTIONS.logFirstHits)
        log('native verification path ' + label + ' ' + JSON.stringify(values));
}

function storeSnapshot(store) {
    if (!store || store.isNull()) return { verifyError: null, depth: null };
    try { return { verifyError: store.add(0xb0).readS32(),
        depth: store.add(0xac).readS32() }; }
    catch (_) { return { verifyError: null, depth: null }; }
}

function nativeResultObject(module, address, label, storeIndex) {
    nativeAttach(module, address, label, {
        onEnter(args) {
            if (storeIndex !== undefined) this.store = args[storeIndex];
            this.path = nativeCallInfo(module, this, args[1]);
            this.originalStore = storeIndex !== undefined ? storeSnapshot(this.store) : null;
        },
        onLeave(retval) {
            if (retval.isNull()) {
                error(label, 'null result; left unchanged');
                return;
            }
            try {
                const before = retval.readU8();
                if (before !== 0 && before !== 1) {
                    error(label, 'unexpected result layout; left unchanged');
                    return;
                }
                retval.writeU8(1);
                if (storeIndex !== undefined) clearStoreError(this.store, label);
                hit(label);
                nativePathDiagnostic(label, this.path, { originalSuccess: before,
                    success: 1, originalStore: this.originalStore || null });
            } catch (e) { error(label, e); }
        }
    });
}

function nativeDecisionPoint(module, address, target) {
    nativeAttach(module, address, target.label, function () {
        hit(target.label);
        try {
            const context = this.context;
            if (target.decision === 'fizz') {
                const before = context.x0.toInt32();
                const store = context[target.storeRegister || 'x23'];
                if (store.isNull()) {
                    nativeDiagnostic(target.label, { originalResult: before,
                        accepted: false, reason: 'null verification context' });
                    return;
                }
                const verifyError = store.add(0xb0).readS32();
                const chainPresent = !store.add(0x98).readPointer().isNull();
                const accepted = (before === 0 || before === 1) && chainPresent &&
                    clearStoreError(store, target.label);
                if (accepted) context.x0 = ptr(1);
                nativeDiagnostic(target.label, { originalResult: before,
                    originalVerifyError: verifyError, chainPresent: chainPresent,
                    accepted: accepted, result: accepted ? 1 : before });
            } else if (target.decision === 'mbedtls') {
                const before = context.x0.toInt32();
                if (context.sp.isNull()) {
                    nativeDiagnostic(target.label, { originalResult: before,
                        accepted: false, reason: 'null stack pointer' });
                    return;
                }
                const flags = context.sp.add(0x74);
                const originalFlags = flags.readU32();
                const accepted = (before === 0 || before === -0x2700) &&
                    originalFlags !== 0xffffffff;
                if (accepted) {
                    flags.writeU32(0);
                    context.x0 = ptr(0);
                }
                nativeDiagnostic(target.label, { originalResult: before,
                    originalFlags: originalFlags, accepted: accepted,
                    result: accepted ? 0 : before,
                    flags: accepted ? 0 : originalFlags });
            } else if (target.decision === 'mnsPins') {
                const before = context.x8.toInt32() >>> 0;
                context.x8 = ptr(0);
                nativeDiagnostic(target.label, { originalPinGate: before,
                    pinGate: 0 });
            } else if (target.decision === 'mbedtlsHandshake') {
                const ssl = context.x19, peer = context.x21;
                const before = context.x8.toInt32();
                const authmode = context.x22.toInt32();
                if (ssl.isNull() || peer.isNull()) {
                    nativePathDiagnostic(target.label, null, { originalResult: before,
                        accepted: false, reason: 'missing SSL or parsed peer certificate' });
                    return;
                }
                const config = ssl.readPointer();
                const session = ssl.add(0x80).readPointer();
                if (config.isNull() || session.isNull()) {
                    nativePathDiagnostic(target.label, mbedTlsCallInfo(module, this, ssl),
                        { originalResult: before, accepted: false,
                          reason: 'missing configuration or negotiating session' });
                    return;
                }
                const endpoint = config.add(8).readU8();
                const sessionPeer = session.add(0x70).readPointer();
                const flags = session.add(0x78);
                const originalFlags = flags.readU32();
                const peerMatches = !sessionPeer.isNull() && peer.equals(sessionPeer);
                const accepted = endpoint === 0 && (authmode === 1 || authmode === 2) &&
                    peerMatches && originalFlags !== 0xffffffff &&
                    [0, -0x2700, -0x7a00, -0x7680].indexOf(before) !== -1;
                if (accepted) {
                    flags.writeU32(0);
                    context.x8 = ptr(0);
                }
                nativePathDiagnostic(target.label, mbedTlsCallInfo(module, this, ssl), {
                    originalResult: before, originalFlags: originalFlags,
                    endpoint: endpoint, authmode: authmode, peerMatches: peerMatches,
                    accepted: accepted, result: accepted ? 0 : before,
                    flags: accepted ? 0 : originalFlags,
                    appPassesCompleted: appPassesCompleted });
            }
        } catch (e) { error(target.label, e); }
    });
}

function installNative(module) {
    if (!anyEnabled(NATIVE_GROUPS)) return;
    if (module.name === 'libscrollmerged.so') {
        installScrollNative(module);
        return;
    }
    if (module.name !== 'libstartup.so') return;

    const targets = [
        { group: 'nativeTlsChain', offset: 0xa33320,
          fingerprint: 'fd7bbda9ae8bf297280040b988000035',
          label: 'native TLS chain verifier [SSL state]', tlsChain: true },
        { group: 'nativeFizzVerifier', offset: 0xa21b30,
          fingerprint: '1f040071a1000054f8031f2aff1700f9',
          label: 'Fizz certificate chain decision [call site]', decision: 'fizz' },
        { group: 'nativeMbedTlsVerifier', offset: 0x6a4aa8,
          fingerprint: 'fc7740b908001c2a68030035285340b9',
          label: 'MNS MbedTLS chain decision [call site]', decision: 'mbedtls',
          guards: [{ offset: 0x6a47a4, length: 16,
                     fingerprint: 'fd7bbaa92cc50094ff431cd1ff0300f9' },
                   { offset: 0x6a4a90, length: 16,
                     fingerprint: 'e7d30191e60315aaffff07a9ff4700f9' }] },
        { group: 'nativeMbedTlsVerifier', offset: 0x6a47a4,
          fingerprint: 'fd7bbaa92cc50094ff431cd1ff0300f9',
          label: 'MNS MbedTLS verifier [error pointer; diagnostic]', outcome: true },
        { group: 'nativeMbedTlsHandshake', offset: 0x5e6b18,
          fingerprint: '48d20035e31200d1e00313aa61018052',
          label: 'MbedTLS handshake certificate decision [client]', decision: 'mbedtlsHandshake',
          guards: [
              { offset: 0x5e3b80, length: 16, fingerprint: 'fd7bbaa9fc6f01a9fa6702a9f85f03a9' },
              { offset: 0x5e69f0, length: 16, fingerprint: '684240f96a0240f9153940f956294039' },
              { offset: 0x5e6a68, length: 16, fingerprint: '680240f9ab8242b90a214039684240f9' },
              { offset: 0x5e6a18, length: 8, fingerprint: '62c640f96b0140f9' },
              { offset: 0x5e8560, length: 12, fingerprint: 'f403082a684240f9087940b9' }
          ] },
        { group: 'nativeTlsDiagnostics', offset: 0xa14204,
          fingerprint: '080040f9080500b4fd7bbea9f44f01a9',
          label: 'MbedTLS TLS alert requested [passive]', mbedAlert: true,
          guards: [
              { offset: 0x5e6a18, length: 8, fingerprint: '62c640f96b0140f9' },
              { offset: 0xa142e8, length: 44,
                fingerprint: '6ab240f9a802805249008052686a01b9e00313aa69ba00f9410100392100805268b240f9020500393851ef97' }
          ] },
        { group: 'nativeMnsPins', offset: 0x6a4ab8,
          fingerprint: 'f6031f2a280e0034280f40f9e80d00b4',
          label: 'MNS native pin decision [call site]', decision: 'mnsPins',
          guards: [{ offset: 0x6a4ab4, length: 4, fingerprint: '285340b9' }] },
        { group: 'nativeTlsDiagnostics', offset: 0xa36b20,
          fingerprint: '3f0000716d000054e0031f2ac0035fd6',
          label: 'native TLS outcome [SSL_get_error]', tlsDiagnostic: true },
        { group: 'nativePinner', offset: 0x61aeec,
          fingerprint: 'fd7bbaa95aeb0294ff4304d159d03bd5',
          label: 'DefaultCertificatePinner::check [result object]', object: true },
        { group: 'nativeVerificationCallbacks', offset: 0x61df30,
          fingerprint: 'fd7bbca9a6e40294ff8300d1f50300aa',
          label: 'SSLVerificationCallbacks::verifySSLCertificate [result object]',
          object: true, storeIndex: 2 },
        { group: 'nativeVerifyWithMetrics', offset: 0x620f74,
          fingerprint: 'fd7bbaa938d30294ff8301d1641800b4',
          label: 'SSLVerification::verifyWithMetrics [bool]', object: false },
        { group: 'nativeHostnameVerifier', offset: 0x622b94,
          fingerprint: 'fd7bbba92bcc0294ff4306d157d03bd5',
          label: 'HostnameVerifier::verifyHostname [indirect result]', hostname: true,
          guards: [{ offset: 0x9455d4, length: 24,
                     fingerprint: 'e8830091a1420091e20300aa6d75f397e883403948010036' }] }
    ].filter(target => enabled(target.group));
    if (targets.length === 0) return;

    if (Process.arch !== 'arm64') {
        error('native architecture', 'C++ hooks require arm64');
        return;
    }
    const ready = [];
    for (const target of targets) {
        const address = module.base.add(target.offset);
        if (NATIVE_ADDRESSES.has(address.toString())) continue;
        try {
            ready.push(target);
        } catch (e) { error(target.label, e); }
    }
    for (const target of ready) {
        const address = module.base.add(target.offset);
        try {
            if (target.mbedAlert) {
                nativeAttach(module, address, target.label, {
                    onEnter(args) {
                        this.path = mbedTlsCallInfo(module, this, args[0]);
                        this.level = args[1].toInt32();
                        this.description = args[2].toInt32();
                    },
                    onLeave(retval) {
                        hit(target.label);
                        const names = { 0: 'close_notify', 40: 'handshake_failure',
                            42: 'bad_certificate', 43: 'unsupported_certificate',
                            44: 'certificate_revoked', 45: 'certificate_expired',
                            46: 'certificate_unknown', 48: 'unknown_ca',
                            49: 'access_denied', 51: 'decrypt_error', 80: 'internal_error' };
                        nativePathDiagnostic(target.label, this.path, {
                            level: this.level, alert: this.description,
                            alertName: names[this.description] || 'unknown_' + this.description,
                            operationResult: retval.toInt32(),
                            outcome: 'alert requested; original result preserved' });
                    }
                });
            } else if (target.hostname) {
                nativeAttach(module, address, target.label, {
                    onEnter(args) {
                        this.output = this.context.x8;
                        this.certificate = args[2];
                        this.path = nativeCallInfo(module, this, args[1]);
                    },
                    onLeave(_retval) {
                        hit(target.label);
                        try {
                            if (!this.output || this.output.isNull() ||
                                !this.certificate || this.certificate.isNull()) return;
                            const flags = [0, 1, 2].map(i => this.output.add(i).readU8());
                            if (flags.some(value => value !== 0 && value !== 1)) {
                                error(target.label, 'unexpected indirect result; left unchanged');
                                return;
                            }
                            this.output.writeU8(1);
                            nativePathDiagnostic(target.label, this.path, {
                                originalSuccess: flags[0], success: 1,
                                auxiliaryFlags: [flags[1], flags[2]] });
                        } catch (e) { error(target.label, e); }
                    }
                });
            } else if (target.tlsDiagnostic) {
                nativeAttach(module, address, target.label, {
                    onEnter(args) {
                        this.ssl = args[0];
                        this.operationResult = args[1].toInt32();
                    },
                    onLeave(retval) {
                        hit(target.label);
                        try {
                            const code = retval.toInt32();
                            const names = ['SSL_ERROR_NONE', 'SSL_ERROR_SSL',
                                'SSL_ERROR_WANT_READ', 'SSL_ERROR_WANT_WRITE',
                                'SSL_ERROR_WANT_X509_LOOKUP', 'SSL_ERROR_SYSCALL',
                                'SSL_ERROR_ZERO_RETURN', 'SSL_ERROR_WANT_CONNECT',
                                'SSL_ERROR_WANT_ACCEPT'];
                            const name = names[code] || 'UNKNOWN_' + code;
                            TLS_OUTCOMES.calls++;
                            TLS_OUTCOMES.errorCounts[name] =
                                (TLS_OUTCOMES.errorCounts[name] || 0) + 1;
                            if (code !== 1 && code !== 5 && code !== 6) return;
                            const detail = { operationResult: this.operationResult,
                                sslError: code, sslErrorName: name,
                                sslVerifyError: this.ssl && !this.ssl.isNull() ?
                                    this.ssl.add(0x5a8).readS64().toString() : null,
                                appPassesCompleted: appPassesCompleted,
                                nativeChecks: nativeCoverage() };
                            TLS_OUTCOMES.lastTerminal = detail;
                            nativeDiagnostic(target.label + ' ' + name, detail);
                        } catch (e) { error(target.label, e); }
                    }
                });
            } else if (target.decision) {
                nativeDecisionPoint(module, address, target);
            } else if (target.outcome) {
                nativeAttach(module, address, target.label, {
                    onLeave(retval) {
                        hit(target.label);
                        nativeDiagnostic(target.label, { errorReturned: !retval.isNull() });
                    }
                });
            } else if (target.tlsChain) {
                nativeAttach(module, address, target.label, {
                    onEnter(args) { this.ssl = args[0]; this.chain = args[1]; },
                    onLeave(retval) {
                        try {
                            if (this.ssl.isNull() || this.chain.isNull()) return;
                            const length = this.chain.readS32();
                            if (length <= 0 || length > 1024) {
                                error(target.label, 'empty/unexpected peer chain; left unchanged');
                                return;
                            }
                            const before = retval.toInt32();
                            if (before < -1 || before > 1) {
                                error(target.label, 'unexpected return value; left unchanged');
                                return;
                            }
                            if (this.ssl.add(0x5a0).readPointer().isNull()) {
                                error(target.label, 'original verifier populated no chain; left unchanged');
                                return;
                            }
                            const field = this.ssl.add(0x5a8);
                            const verifyError = field.readS64().toString();
                            field.writeS64(0);
                            retval.replace(1);
                            hit(target.label);
                            nativeDiagnostic(target.label, { originalResult: before,
                                originalVerifyError: verifyError, result: 1, verifyError: 0 });
                        } catch (e) { error(target.label, e); }
                    }
                });
            } else if (target.object) {
                nativeResultObject(module, address, target.label, target.storeIndex);
            } else {
                nativeAttach(module, address, target.label, {
                    onEnter(args) {
                        this.store = args[1];
                        this.preverify = args[0].toInt32();
                        this.originalStore = storeSnapshot(this.store);
                        this.path = nativeCallInfo(module, this, args[2]);
                        if (clearStoreError(this.store, target.label) &&
                            (this.preverify === 0 || this.preverify === 1)) args[0] = ptr(1);
                    },
                    onLeave(retval) {
                        clearStoreError(this.store, target.label);
                        const before = retval.toInt32();
                        retval.replace(1);
                        hit(target.label);
                        nativeDiagnostic(target.label, { originalPreverify: this.preverify,
                            originalResult: before, result: 1 });
                        nativePathDiagnostic(target.label, this.path, {
                            originalPreverify: this.preverify,
                            originalStore: this.originalStore || null,
                            originalResult: before, result: 1,
                            appPassesCompleted: appPassesCompleted });
                    }
                });
            }
        } catch (e) { error(target.label, e); }
    }
}

function installScrollNative(module) {
    if (!enabled('nativeFizzVerifier') && !enabled('nativeTlsDiagnostics')) return;
    if (Process.arch !== 'arm64') {
        error('native architecture', 'libscrollmerged hooks require arm64');
        return;
    }
    try {
        const label = 'Fizz certificate chain decision [libscrollmerged.so]';
        if (enabled('nativeFizzVerifier')) {
            const owner = Process.findModuleByName('libstartup.so');
            if (!owner) error(label, 'X509 owner module unavailable; skipped');
            else nativeDecisionPoint(module, module.base.add(0x5b756c), {
                label: label, decision: 'fizz', storeRegister: 'x24' });
        }
        if (enabled('nativeTlsDiagnostics')) {
            const label = 'Fizz certificate verifier outcome [libscrollmerged.so]';
            const address = module.base.add(0x5b71f4);
            nativeAttach(module, address, label, {
                onEnter(args) {
                    this.path = nativeCallInfo(module, this,
                        args[0] && !args[0].isNull() ? args[0].add(0x10) : null);
                },
                onLeave(retval) {
                    hit(label);
                    nativePathDiagnostic(label, this.path, { result: retval.toInt32(),
                        chainDecisionHits: HITS['Fizz certificate chain decision [libscrollmerged.so]'] || 0 });
                }
            });
        }
    } catch (e) { error('libscrollmerged installation', e); }
}

function javaUse(name) {
    if (applicationLoader !== null) {
        try { return Java.ClassFactory.get(applicationLoader).use(name); }
        catch (_) { }
    }
    return Java.use(name);
}

function methodLabel(className, methodName, overload) {
    return className + '.' + methodName + '(' +
        overload.argumentTypes.map(t => t.className).join(',') + ')';
}

function hookJava(className, methodName, select, replacement) {
    const pendingKey = className + '.' + methodName;
    let wrapper;
    try { wrapper = javaUse(className); }
    catch (_) { PENDING.add(pendingKey); return false; }
    try {
        const member = wrapper[methodName];
        if (member === undefined) {
            PENDING.delete(pendingKey);
            error(pendingKey, 'method absent in this runtime');
            return false;
        }
        let matched = false;
        for (const overload of member.overloads) {
            if (!select(overload)) continue;
            matched = true;
            const label = methodLabel(className, methodName, overload);
            if (INSTALLED.has(label)) continue;
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                hit(label);
                return replacement.call(this, overload, args);
            };
            INSTALLED.add(label);
            log('hooked ' + label);
        }
        PENDING.delete(pendingKey);
        if (!matched) error(pendingKey, 'no supported overload; left unchanged');
        return matched;
    } catch (e) {
        error(pendingKey, e);
        return false;
    }
}

const isVoid = o => o.returnType.className === 'void';
const isBoolean = o => o.returnType.className === 'boolean';
const noOp = function () {};
const accept = function () { return true; };

function mnsJavaBypass(overload, args) {
    if (!enabled('javaTlsDiagnostics')) return;
    const name = 'com.facebook.mobilenetwork.internal.certificateverifier.CertificateVerifier';
    const label = methodLabel(name, 'verify', overload);
    try {
        const value = args[1] === null || args[1] === undefined ? null : String(args[1]);
        const host = value !== null && value.length >= 1 && value.length <= 253 &&
            /^[A-Za-z0-9_.:\[\]-]+$/.test(value) ? value : null;
        const key = JSON.stringify([label, host]);
        if (!JAVA_VERIFICATION_PATHS[key] &&
            Object.keys(JAVA_VERIFICATION_PATHS).length >= 64) return;
        const length = args[0] === null || args[0] === undefined ? null : args[0].length;
        const entry = JAVA_VERIFICATION_PATHS[key] || { check: label, calls: 0 };
        entry.calls++;
        Object.assign(entry, { host: host, certificateCount:
            Number.isSafeInteger(length) && length >= 0 ? length : null,
            outcome: 'bypassed', timestamp: new Date().toISOString(),
            appPassesCompleted: appPassesCompleted });
        JAVA_VERIFICATION_PATHS[key] = entry;
        if (entry.calls <= OPTIONS.logFirstHits)
            log('Java verification path ' + JSON.stringify(entry));
    } catch (e) { error(label + ' diagnostic', e); }
}

function certificateList(chain) {
    if (chain !== null && chain !== undefined && chain.$className !== undefined &&
        chain.$className.charAt(0) !== '[') return chain;
    const list = Java.use('java.util.ArrayList').$new();
    if (chain !== null && chain !== undefined) {
        for (let i = 0; i < chain.length; i++) list.add(chain[i]);
    }
    return list;
}

function trustedServer(overload, args) {
    if (overload.returnType.className === 'void') return;
    if (overload.returnType.className === '[Ljava.security.cert.X509Certificate;')
        return args[0];
    return certificateList(args[0]);
}

function supportedTrustResult(overload) {
    return ['void', 'java.util.List', '[Ljava.security.cert.X509Certificate;']
        .indexOf(overload.returnType.className) !== -1;
}

function installPlatformJava() {
    if (enabled('javaTlsDiagnostics')) {
        for (const name of ['javax.net.ssl.SSLHandshakeException',
            'javax.net.ssl.SSLPeerUnverifiedException']) {
            hookJava(name, '$init', o => isVoid(o) && o.argumentTypes.length === 1 &&
                o.argumentTypes[0].className === 'java.lang.String',
                function (overload, args) {
                    const result = overload.call(this, ...args);
                    try {
                        const frames = this.getStackTrace();
                        const stack = [];
                        for (let i = 0; i < Math.min(frames.length, 8); i++)
                            stack.push(frames[i].toString());
                        const entry = JAVA_TLS_EXCEPTIONS[name] || { calls: 0 };
                        entry.calls++;
                        entry.message = args[0] === null ? null : String(args[0]);
                        entry.stack = stack;
                        entry.appPassesCompleted = appPassesCompleted;
                        JAVA_TLS_EXCEPTIONS[name] = entry;
                        if (entry.calls <= OPTIONS.logFirstHits)
                            log('TLS exception ' + name + ' ' + JSON.stringify(entry));
                    } catch (e) { error(name + ' diagnostic', e); }
                    return result;
                });
        }
    }
    if (enabled('platformPins'))
        hookJava('android.security.net.config.NetworkSecurityTrustManager',
            'checkPins', isVoid, noOp);
    if (enabled('platformTrust'))
        hookJava('android.security.net.config.NetworkSecurityTrustManager',
            'checkServerTrusted', supportedTrustResult, trustedServer);

    if (!enabled('conscryptTrust')) return;
    for (const name of ['com.android.org.conscrypt.TrustManagerImpl',
        'org.conscrypt.TrustManagerImpl']) {
        hookJava(name, 'verifyChain', o =>
            o.returnType.className === 'java.util.List' &&
            o.argumentTypes.length >= 4 &&
            o.argumentTypes[0].className === 'java.util.List',
            function (overload, args) {
                if (args[3] === true) return overload.call(this, ...args);
                return args[0];
            });
    }
}

function installAppJava() {
    if (!anyEnabled(APP_GROUPS) || appPassRunning) return;
    appPassRunning = true;
    try {
        if (enabled('mnsJavaVerifier')) {
            const mns = 'com.facebook.mobilenetwork.internal.certificateverifier.CertificateVerifier';
            hookJava(mns, 'verify', isVoid, mnsJavaBypass);
        }

        if (enabled('facebookPinningTrust')) {
            hookJava('X.03Hf', 'A00', o => isVoid(o) &&
                o.argumentTypes.length === 1 &&
                o.argumentTypes[0].className === 'java.util.List', noOp);
            hookJava('X.03Hf', 'A01', o => isVoid(o) &&
                o.argumentTypes.length === 1 &&
                o.argumentTypes[0].className === '[Ljava.security.cert.X509Certificate;', noOp);
            hookJava('X.03Hf', 'checkServerTrusted', isVoid, noOp);
        }
        if (enabled('trustManagerWrapper')) {
            hookJava('X.02Hr', 'checkServerTrusted', isVoid, noOp);
            hookJava('X.02Hr', 'AaI', isVoid, noOp);
            hookJava('X.02Hr', 'AaJ', isVoid, noOp);
        }
        if (enabled('hucPinner'))
            hookJava('X.02wl', 'checkCertificates', isVoid, noOp);
        if (enabled('okhttpPinner'))
            hookJava('X.0mB6', 'A01', o => isVoid(o) &&
                o.argumentTypes.length === 2 &&
                o.argumentTypes[0].className === 'java.lang.String' &&
                o.argumentTypes[1].className === 'java.util.List', noOp);

        if (enabled('hostnameVerifiers')) {
            hookJava('X.02xA', 'A02', isBoolean, accept);
            hookJava('X.02xA', 'verify', isBoolean, accept);
            hookJava('X.0sbj', 'A02', isBoolean, accept);
            hookJava('X.0sbj', 'verify', isBoolean, accept);
        }

        if (enabled('mnsConfigConstructors')) {
            const config = 'com.facebook.tigon.tigonmns.TigonMNSConfig';
            hookJava(config, '$init', isVoid, function (overload, args) {
                const result = overload.call(this, ...args);
                this.useMbedtlsCertificateVerifier.value = false;
                return result;
            });
        }
        if (enabled('mnsConfigAccessors')) {
            const config = 'com.facebook.tigon.tigonmns.TigonMNSConfig';
            hookJava(config, 'getUseMbedtlsCertificateVerifier', isBoolean,
                function () { return false; });
            hookJava(config, 'setUseMbedtlsCertificateVerifier', isVoid,
                function (overload, args) {
                    return overload.call(this, false);
                });
        }
        if (anyEnabled(['webviewSslErrors', 'chromiumCertificates', 'chromiumSslErrors']))
            installWebViewJava();
    } finally { appPassesCompleted++; appPassRunning = false; }
}

function installWebViewJava() {
    if (enabled('webviewSslErrors')) {
        for (const name of ['android.webkit.WebViewClient', 'X.0RVD', 'X.0RX6']) {
            hookJava(name, 'onReceivedSslError', o => isVoid(o) &&
                o.argumentTypes.length === 3 &&
                o.argumentTypes[1].className === 'android.webkit.SslErrorHandler',
                function (_overload, args) { args[1].proceed(); });
        }
        hookJava('X.0kyt', 'A03', o => isVoid(o) &&
            o.argumentTypes.length === 3 &&
            o.argumentTypes[1].className === 'android.webkit.SslErrorHandler',
            function (_overload, args) { args[1].proceed(); });
    }

    if (enabled('chromiumCertificates')) {
        hookJava('org.chromium.net.AndroidNetworkLibrary', 'verifyServerCertificates',
            o => o.returnType.className === 'org.chromium.net.AndroidCertVerifyResult' &&
                o.argumentTypes.length === 5 &&
                o.argumentTypes[0].className === '[[B',
            function (_overload, args) {
                const factory = Java.use('java.security.cert.CertificateFactory')
                    .getInstance('X.509');
                const input = Java.use('java.io.ByteArrayInputStream');
                const chain = Java.use('java.util.ArrayList').$new();
                for (let i = 0; i < args[0].length; i++) {
                    const stream = input.$new(args[0][i]);
                    try { chain.add(factory.generateCertificate(stream)); }
                    finally { stream.close(); }
                }
                const result = javaUse('org.chromium.net.AndroidCertVerifyResult').$new(0);
                result.mCertificateChain.value = chain;
                result.mIsIssuedByKnownRoot.value = false;
                return result;
            });
    }
    if (enabled('chromiumSslErrors')) {
        hookJava('com.android.webview.chromium.WebViewContentsClientAdapter',
            'onReceivedSslError', o => isVoid(o) && o.argumentTypes.length === 2 &&
                o.argumentTypes[0].className === 'org.chromium.base.Callback',
            function (_overload, args) {
                args[0].onResult(Java.use('java.lang.Boolean').valueOf(true));
            });
    }
}

function updateApplicationLoader() {
    try {
        const app = Java.use('android.app.ActivityThread').currentApplication();
        if (app !== null) applicationLoader = app.getClassLoader();
    } catch (_) { }
}

function installJava() {
    const platform = anyEnabled(PLATFORM_GROUPS);
    const app = anyEnabled(APP_GROUPS);
    if (!platform && !app) return;
    if (typeof Java === 'undefined' || !Java.available) {
        log('Java bridge unavailable; Java groups skipped. Use the Frida CLI.');
        return;
    }
    if (app && (!Number.isFinite(OPTIONS.appHookDelayMs) || OPTIONS.appHookDelayMs < 0))
        throw new Error('appHookDelayMs must be a nonnegative finite number');
    const early = beforeAttachPassEnabled();
    if (OPTIONS.earlyAppHooks === true && OPTIONS.appHookDelayMs > 0)
        log('early app pass suppressed by positive appHookDelayMs; scheduled delay is respected');
    if (platform || (app && OPTIONS.hookApplicationAttach)) {
        Java.performNow(function () {
            if (platform) installPlatformJava();
            if (app && OPTIONS.hookApplicationAttach) {
                hookJava('android.app.Application', 'attach', isVoid,
                    function (overload, args) {
                        try {
                            applicationLoader = args[0].getClassLoader();
                            if (early) installAppJava();
                        } catch (e) { error('Application.attach app hooks', e); }
                        const result = overload.call(this, ...args);
                        return result;
                    });
            }
        });
    }
    if (!app) return;
    if (early && OPTIONS.hookApplicationAttach)
        log('early app hooks enabled before original Application.attach');
    log('scheduled app hook passes start after ' + OPTIONS.appHookDelayMs + ' ms');
    for (const retry of [0, 1000, 3000, 8000, 20000, 45000]) {
        setTimeout(function () {
            try {
                Java.perform(function () {
                    try {
                        updateApplicationLoader();
                        installAppJava();
                        if (retry === 45000 && PENDING.size !== 0)
                            log('not resolved in this process: ' + Array.from(PENDING).join(', '));
                    } catch (e) { error('app Java installation', e); }
                });
            } catch (e) { error('app Java scheduling', e); }
        }, OPTIONS.appHookDelayMs + retry);
    }
}

rpc.exports = {
    status() {
        return { installed: Array.from(INSTALLED), hits: HITS,
            pending: Array.from(PENDING), errors: ERRORS,
            nativeVerification: NATIVE_VERIFICATION,
            nativePaths: Object.values(NATIVE_PATHS), processId: Process.id,
            javaVerificationPaths: Object.values(JAVA_VERIFICATION_PATHS),
            nativeCoverage: nativeCoverage(), tlsOutcomes: TLS_OUTCOMES,
            javaTlsExceptions: JAVA_TLS_EXCEPTIONS,
            enabled: OPTIONS.enabled, enabledGroups: enabledGroups(),
            disabledGroups: Object.keys(OPTIONS.hooks).filter(name => !enabled(name)),
            appHookDelayMs: OPTIONS.appHookDelayMs,
            hookApplicationAttach: OPTIONS.hookApplicationAttach,
            earlyAppHooks: OPTIONS.earlyAppHooks,
            beforeAttachPassEnabled: beforeAttachPassEnabled(),
            appPassesCompleted: appPassesCompleted,
            arch: Process.arch, frida: Frida.version };
    },
    rescan() {
        if (!anyEnabled(APP_GROUPS))
            return Promise.resolve({ skipped: 'all app hook groups are disabled' });
        if (typeof Java === 'undefined' || !Java.available)
            return Promise.resolve({ error: 'Java bridge unavailable' });
        return new Promise(resolve => Java.perform(function () {
            try {
                updateApplicationLoader();
                installAppJava();
                resolve({ installed: Array.from(INSTALLED), pending: Array.from(PENDING) });
            } catch (e) { resolve({ error: String(e) }); }
        }));
    }
};

log('starting; Frida ' + Frida.version + ', ' + Process.arch + ', PID ' + Process.id);
log('enabled hook groups: ' + (enabledGroups().join(', ') || 'none'));
if (OPTIONS.enabled && OPTIONS.hooks.nativeOpenSsl === true)
    error('nativeOpenSsl', 'quarantined after reported startup crash; use the guarded native verifier groups');
if (anyEnabled(NATIVE_GROUPS)) {
    moduleObserver = Process.attachModuleObserver({
        onAdded(module) {
            try { installNative(module); }
            catch (e) { error('native installation', e); }
        },
        onRemoved(module) {
            for (let i = LISTENERS.length - 1; i >= 0; i--) {
                const item = LISTENERS[i];
                if (item.module !== module.name || item.base !== module.base.toString()) continue;
                try { item.listener.detach(); } catch (_) {}
                NATIVE_ADDRESSES.delete(item.address);
                INSTALLED.delete(item.label);
                LISTENERS.splice(i, 1);
            }
        }
    });
}
try { installJava(); }
catch (e) { error('Java installation', e); }
log('ready; proxy configuration remains external');
