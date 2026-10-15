
'use strict';
const config = __CONFIG__;

function status(level, text) { send({kind: 'status', level, text}); }

try {
    function native(name, result, args) {
        return new NativeFunction(Module.getGlobalExportByName(name), result, args);
    }
    const getClass = native('objc_getClass', 'pointer', ['pointer']);
    const getClassMethod = native('class_getClassMethod', 'pointer', ['pointer', 'pointer']);
    const getInstanceMethod = native('class_getInstanceMethod', 'pointer', ['pointer', 'pointer']);
    const getImplementation = native('method_getImplementation', 'pointer', ['pointer']);
    const registerSelector = native('sel_registerName', 'pointer', ['pointer']);
    const msgSend = Module.getGlobalExportByName('objc_msgSend');
    const callPointer = new NativeFunction(msgSend, 'pointer', ['pointer', 'pointer']);
    const callLength = new NativeFunction(msgSend, 'ulong', ['pointer', 'pointer']);
    const callEncoding = new NativeFunction(msgSend, 'pointer', ['pointer', 'pointer', 'ulong']);
    const selectors = new Map();
    let sequence = 0;

    function selector(name) {
        if (!selectors.has(name)) {
            selectors.set(name, registerSelector(Memory.allocUtf8String(name)));
        }
        return selectors.get(name);
    }
    function pointer(object, name) {
        return object.isNull() ? NULL : callPointer(object, selector(name));
    }
    function string(object) {
        if (object.isNull()) return null;
        const bytes = pointer(object, 'UTF8String');
        return bytes.isNull() ? null : bytes.readUtf8String();
    }
    function dataBytes(object) {
        if (object.isNull()) throw new Error('NSData argument is nil');
        const length = Number(callLength(object, selector('length')).toString());
        if (length === 0) return new ArrayBuffer(0);
        return pointer(object, 'bytes').readByteArray(length);
    }
    function hex(buffer) {
        return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
    }
    function originalURL(components) {
        try {
            const value = string(pointer(pointer(components, 'URL'), 'absoluteString'));
            return value === null ? null : value.split('?')[0].split('#')[0];
        } catch (_) { return null; }
    }
    function capture(source, bytes, details) {
        send(Object.assign({
            kind: 'plaintext', source, sequence: ++sequence,
            pid: Process.id, captured_at_ms: Date.now(), byte_length: bytes.byteLength
        }, details), bytes);
    }

    const hooks = [];
    if (config.source === 'query' || config.source === 'both') hooks.push({
        className: 'WARegURLEncEnvelope', selector: 'plaintextQueryForComponents:',
        isClassMethod: true,
        callbacks: {
            onEnter(args) { this.originalURL = originalURL(args[2]); },
            onLeave(retval) {
                try {
                    if (retval.isNull()) return;
                    // Convert the returned NSString to the same UTF-8 bytes used by the app.
                    const data = callEncoding(retval, selector('dataUsingEncoding:'), 4);
                    capture('query', dataBytes(data), {
                        original_url: this.originalURL, thread_id: this.threadId,
                        hook: '+[WARegURLEncEnvelope plaintextQueryForComponents:]'
                    });
                } catch (error) { status('error', 'Query capture failed: ' + error); }
            }
        }
    });
    if (config.source === 'aes' || config.source === 'both') hooks.push({
        className: 'WAAESGCMKey', selector: 'encrypt:iv:tagLength:error:',
        isClassMethod: false,
        callbacks: {
            onEnter(args) {
                try {
                    capture('aes', dataBytes(args[2]), {
                        thread_id: this.threadId,
                        hook: '-[WAAESGCMKey encrypt:iv:tagLength:error:]',
                        iv_hex: args[3].isNull() ? null : hex(dataBytes(args[3])),
                        tag_length: args[4].toUInt32(),
                        caller: DebugSymbol.fromAddress(this.returnAddress).toString()
                    });
                } catch (error) { status('error', 'AES capture failed: ' + error); }
            }
        }
    });

    function install() {
        for (const hook of hooks) {
            if (hook.done) continue;
            const klass = getClass(Memory.allocUtf8String(hook.className));
            if (klass.isNull()) continue;
            const lookup = hook.isClassMethod ? getClassMethod : getInstanceMethod;
            const method = lookup(klass, selector(hook.selector));
            if (method.isNull()) continue;
            try {
                Interceptor.attach(getImplementation(method), hook.callbacks);
                status('info', 'Hooked ' + hook.className + ' ' + hook.selector);
            } catch (error) {
                status('fatal', 'Failed to hook ' + hook.className + ': ' + error);
            }
            hook.done = true;
        }
        return hooks.every(hook => hook.done);
    }
    if (!install()) {
        status('info', 'Waiting up to 30 seconds for the target methods...');
        let attempts = 0;
        const timer = setInterval(() => {
            if (install() || ++attempts >= 60) {
                clearInterval(timer);
                for (const hook of hooks) {
                    if (!hook.done) status('fatal', 'Method not found: ' + hook.className + ' ' + hook.selector);
                }
            }
        }, 500);
    }
} catch (error) {
    status('fatal', 'Agent initialization failed: ' + error);
}
