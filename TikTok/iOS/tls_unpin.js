'use strict';

const TARGET_LIB_NAMES = [
    'libboringssl.dylib',
    'libsscronet.dylib',
    'libsscronet.so',
    'sscronet',
    'boringssl',
    'libssl.so'
];

const hookedModules = new Set();
const hookedSetters = new Set();
const hookedCallbacks = new Set();
const hookedFunctions = new Set();
const hookedTrustFunctions = new Set();

const listeners = [];

function log(s) {
    console.log('[TikTok/iOS] ' + s);
}

log('BoringSSL TLS verification bypass');

function moduleKey(module) {
    return (module.path || module.name) + ':' + module.base;
}

function findExport(module, symbol) {
    for (const candidate of [symbol, '_' + symbol]) {
        try {
            if (typeof module.findExportByName === 'function') {
                const p = module.findExportByName(candidate);

                if (p)
                    return p;
            }
        } catch (_) {
        }

        try {
            if (typeof Module.findExportByName === 'function') {
                const p = Module.findExportByName(
                    module.name,
                    candidate
                );

                if (p)
                    return p;
            }
        } catch (_) {
        }
    }

    return null;
}

function normalizeCodePointer(p) {
    if (!p || p.isNull())
        return p;

    try {
        if (typeof p.strip === 'function')
            return p.strip();
    } catch (_) {
    }

    return p;
}

function isTargetModule(module) {
    const basename =
        (module.path || module.name)
            .split('/')
            .pop();

    return TARGET_LIB_NAMES.includes(module.name) ||
           TARGET_LIB_NAMES.includes(basename);
}

function isSecurityModule(module) {
    const identity = (
        (module.name || '') +
        ' ' +
        (module.path || '')
    ).toLowerCase();

    return identity.includes('security.framework') ||
           (module.name || '').toLowerCase() === 'security';
}


function hookCustomVerifyCallback(address, label) {
    address = normalizeCodePointer(address);

    if (!address || address.isNull())
        return;

    const key = 'custom:' + address.toString();

    if (hookedCallbacks.has(key))
        return;

    hookedCallbacks.add(key);

    log(
        'Attaching to original custom verify callback ' +
        address +
        ' [' +
        label +
        ']'
    );

    try {
        const listener = Interceptor.attach(address, {
            onEnter(args) {
                this.ssl = args[0];
                this.outAlert = args[1];
            },

            onLeave(retval) {
                const result = retval.toInt32();

                switch (result) {
                    case 0:
                        log(
                            label +
                            ' verifier -> ssl_verify_ok (0)'
                        );
                        break;

                    case 1:
                        log(
                            label +
                            ' verifier -> ssl_verify_invalid (1)' +
                            ' => forcing ssl_verify_ok (0)'
                        );

                        try {
                            if (
                                this.outAlert &&
                                !this.outAlert.isNull()
                            ) {
                                this.outAlert.writeU8(0);
                            }
                        } catch (_) {
                        }

                        retval.replace(0);
                        break;

                    case 2:
                        log(
                            label +
                            ' verifier -> ssl_verify_retry (2)' +
                            ' [preserved]'
                        );
                        break;

                    default:
                        log(
                            label +
                            ' verifier -> unknown (' +
                            result +
                            ') [preserved]'
                        );
                        break;
                }
            }
        });

        listeners.push(listener);

    } catch (e) {
        log(
            'Could not attach to custom verifier ' +
            address +
            ': ' +
            e
        );
    }
}

function hookLegacyVerifyCallback(address, label) {
    address = normalizeCodePointer(address);

    if (!address || address.isNull())
        return;

    const key = 'legacy:' + address.toString();

    if (hookedCallbacks.has(key))
        return;

    hookedCallbacks.add(key);

    log(
        'Attaching to original legacy verify callback ' +
        address +
        ' [' +
        label +
        ']'
    );

    try {
        const listener = Interceptor.attach(address, {
            onEnter(args) {
                this.preverify = args[0].toInt32();
            },

            onLeave(retval) {
                const result = retval.toInt32();

                if (result === 0) {
                    log(
                        label +
                        ' verifier -> reject (0)' +
                        ' preverify=' +
                        this.preverify +
                        ' => accept (1)'
                    );

                    retval.replace(1);

                } else {
                    log(
                        label +
                        ' verifier -> accept (' +
                        result +
                        ')' +
                        ' preverify=' +
                        this.preverify
                    );
                }
            }
        });

        listeners.push(listener);

    } catch (e) {
        log(
            'Could not attach to legacy verifier ' +
            address +
            ': ' +
            e
        );
    }
}

function hookCertVerifyCallback(address, label) {
    address = normalizeCodePointer(address);

    if (!address || address.isNull())
        return;

    const key = 'cert:' + address.toString();

    if (hookedCallbacks.has(key))
        return;

    hookedCallbacks.add(key);

    log(
        'Attaching to original cert verify callback ' +
        address +
        ' [' +
        label +
        ']'
    );

    try {
        const listener = Interceptor.attach(address, {
            onLeave(retval) {
                const result = retval.toInt32();

                if (result === 0) {
                    log(
                        label +
                        ' cert verifier -> failure (0)' +
                        ' => success (1)'
                    );

                    retval.replace(1);

                } else {
                    log(
                        label +
                        ' cert verifier -> success (' +
                        result +
                        ')'
                    );
                }
            }
        });

        listeners.push(listener);

    } catch (e) {
        log(
            'Could not attach to cert verifier ' +
            address +
            ': ' +
            e
        );
    }
}

function installVerificationSetters(module) {
    const specs = [
        {
            name: 'SSL_CTX_set_custom_verify',
            callbackIndex: 2,
            modeIndex: 1,
            type: 'custom'
        },
        {
            name: 'SSL_set_custom_verify',
            callbackIndex: 2,
            modeIndex: 1,
            type: 'custom'
        },
        {
            name: 'SSL_CTX_set_verify',
            callbackIndex: 2,
            modeIndex: 1,
            type: 'legacy'
        },
        {
            name: 'SSL_set_verify',
            callbackIndex: 2,
            modeIndex: 1,
            type: 'legacy'
        },
        {
            name: 'SSL_CTX_set_cert_verify_callback',
            callbackIndex: 1,
            modeIndex: -1,
            type: 'cert'
        }
    ];

    let installed = 0;

    for (const spec of specs) {
        const address =
            findExport(module, spec.name);

        if (!address)
            continue;

        const key =
            moduleKey(module) +
            ':' +
            spec.name +
            ':' +
            address;

        if (hookedSetters.has(key))
            continue;

        hookedSetters.add(key);

        try {
            const listener = Interceptor.attach(address, {
                onEnter(args) {
                    const callback =
                        args[spec.callbackIndex];

                    let mode = null;

                    if (spec.modeIndex >= 0) {
                        try {
                            mode =
                                args[spec.modeIndex]
                                    .toInt32();
                        } catch (_) {
                        }
                    }

                    log(
                        module.name +
                        ' ' +
                        spec.name +
                        (mode === null
                            ? ''
                            : ' mode=' + mode) +
                        ' callback=' +
                        (
                            callback.isNull()
                                ? 'null'
                                : callback
                        )
                    );

                    if (callback.isNull())
                        return;

                    if (spec.type === 'custom') {
                        hookCustomVerifyCallback(
                            callback,
                            module.name +
                            ' ' +
                            spec.name
                        );

                    } else if (
                        spec.type === 'legacy'
                    ) {
                        hookLegacyVerifyCallback(
                            callback,
                            module.name +
                            ' ' +
                            spec.name
                        );

                    } else if (
                        spec.type === 'cert'
                    ) {
                        hookCertVerifyCallback(
                            callback,
                            module.name +
                            ' ' +
                            spec.name
                        );
                    }
                }
            });

            listeners.push(listener);
            installed++;

        } catch (e) {
            log(
                'Could not hook ' +
                module.name +
                ' ' +
                spec.name +
                ': ' +
                e
            );
        }
    }

    return installed;
}

function installVerifyResultHook(module) {
    const address =
        findExport(
            module,
            'SSL_get_verify_result'
        );

    if (!address)
        return 0;

    const key =
        moduleKey(module) +
        ':SSL_get_verify_result:' +
        address;

    if (hookedFunctions.has(key))
        return 0;

    hookedFunctions.add(key);

    try {
        const listener = Interceptor.attach(address, {
            onLeave(retval) {
                const result =
                    retval.toInt32();

                if (result !== 0) {
                    log(
                        module.name +
                        ' SSL_get_verify_result=' +
                        result +
                        ' => X509_V_OK (0)'
                    );

                    retval.replace(0);

                } else {
                    log(
                        module.name +
                        ' SSL_get_verify_result=X509_V_OK'
                    );
                }
            }
        });

        listeners.push(listener);

        return 1;

    } catch (e) {
        log(
            'Could not hook ' +
            module.name +
            ' SSL_get_verify_result: ' +
            e
        );

        return 0;
    }
}

function installHandshakeDiagnostics(module) {
    let installed = 0;

    for (const name of [
        'SSL_connect',
        'SSL_do_handshake',
        'SSL_accept'
    ]) {
        const address =
            findExport(module, name);

        if (!address)
            continue;

        const key =
            moduleKey(module) +
            ':handshake:' +
            name +
            ':' +
            address;

        if (hookedFunctions.has(key))
            continue;

        hookedFunctions.add(key);

        try {
            const listener = Interceptor.attach(address, {
                onLeave(retval) {
                    log(
                        module.name +
                        ' ' +
                        name +
                        ' returned ' +
                        retval.toInt32()
                    );
                }
            });

            listeners.push(listener);
            installed++;

        } catch (e) {
            log(
                'Could not observe ' +
                module.name +
                ' ' +
                name +
                ': ' +
                e
            );
        }
    }

    return installed;
}

function installBoringSSLHooks(module) {
    let installed = 0;

    installed +=
        installVerificationSetters(module);

    installed +=
        installVerifyResultHook(module);

    installed +=
        installHandshakeDiagnostics(module);

    log(
        'Installed ' +
        installed +
        ' TLS hooks in ' +
        module.name
    );
}

function hookTargetModule(module) {
    if (!isTargetModule(module))
        return;

    const key =
        moduleKey(module);

    if (hookedModules.has(key))
        return;

    hookedModules.add(key);

    log(
        'Hooking native TLS module ' +
        module.name +
        ' @ ' +
        module.base
    );

    installBoringSSLHooks(module);
}

function installAppleTrustHooks(module) {
    if (!isSecurityModule(module))
        return;

    const secTrustEvaluate =
        findExport(
            module,
            'SecTrustEvaluate'
        );

    if (secTrustEvaluate) {
        const key =
            moduleKey(module) +
            ':SecTrustEvaluate:' +
            secTrustEvaluate;

        if (!hookedTrustFunctions.has(key)) {
            hookedTrustFunctions.add(key);

            try {
                const listener =
                    Interceptor.attach(
                        secTrustEvaluate,
                        {
                            onEnter(args) {
                                this.resultOut =
                                    args[1];
                            },

                            onLeave(retval) {
                                try {
                                    if (
                                        this.resultOut &&
                                        !this.resultOut.isNull()
                                    ) {
                                        this.resultOut
                                            .writeU32(1);
                                    }
                                } catch (_) {
                                }

                                const original =
                                    retval.toInt32();

                                log(
                                    'SecTrustEvaluate status=' +
                                    original +
                                    ' => errSecSuccess / Proceed'
                                );

                                retval.replace(0);
                            }
                        }
                    );

                listeners.push(listener);

                log(
                    'Bypassing Apple Security SecTrustEvaluate'
                );

            } catch (e) {
                log(
                    'Could not hook SecTrustEvaluate: ' +
                    e
                );
            }
        }
    }

    const secTrustEvaluateWithError =
        findExport(
            module,
            'SecTrustEvaluateWithError'
        );

    if (secTrustEvaluateWithError) {
        const key =
            moduleKey(module) +
            ':SecTrustEvaluateWithError:' +
            secTrustEvaluateWithError;

        if (!hookedTrustFunctions.has(key)) {
            hookedTrustFunctions.add(key);

            try {
                const listener =
                    Interceptor.attach(
                        secTrustEvaluateWithError,
                        {
                            onEnter(args) {
                                this.errorOut =
                                    args[1];
                            },

                            onLeave(retval) {
                                const original =
                                    retval.toInt32();

                                try {
                                    if (
                                        this.errorOut &&
                                        !this.errorOut.isNull()
                                    ) {
                                        this.errorOut
                                            .writePointer(ptr(0));
                                    }
                                } catch (_) {
                                }

                                log(
                                    'SecTrustEvaluateWithError=' +
                                    original +
                                    ' => trusted (1)'
                                );

                                retval.replace(1);
                            }
                        }
                    );

                listeners.push(listener);

                log(
                    'Bypassing Apple Security SecTrustEvaluateWithError'
                );

            } catch (e) {
                log(
                    'Could not hook SecTrustEvaluateWithError: ' +
                    e
                );
            }
        }
    }
}

function scanModules() {
    const modules =
        Process.enumerateModules();

    for (const module of modules) {
        hookTargetModule(module);
        installAppleTrustHooks(module);
    }
}

scanModules();

if (
    typeof Process.attachModuleObserver ===
    'function'
) {
    try {
        Process.attachModuleObserver({
            onAdded(module) {
                hookTargetModule(module);
                installAppleTrustHooks(module);
            }
        });

        log('Module observer installed');

    } catch (e) {
        log(
            'Could not install module observer: ' +
            e
        );
    }

} else {
    let attempts = 0;

    const timer =
        setInterval(function () {
            scanModules();

            attempts++;

            if (attempts >= 30) {
                clearInterval(timer);
            }
        }, 250);
}

log(
    'TLS bypass installed. '
);
