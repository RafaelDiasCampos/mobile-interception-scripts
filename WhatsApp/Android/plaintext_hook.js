'use strict';

const MAX_BODY_BYTES = 1024 * 1024;

(function () {
  const LIBRARY = 'libwhatsapp.so';
  const BUILD_ID_OFFSET = 0x318;
  const ENCRYPT_OFFSET = 0x73d020;
  const GET_CSTRING_PLT = 0xd42280;
  const GET_LENGTH_PLT = 0xd42ae0;
  const HOOK_NAME = 'libwhatsapp.so+0x73d020';
  const sessionId = Date.now().toString(36) + '-' + Process.id;
  const stats = { captured: 0, dropped: 0, readErrors: 0 };
  let buildId = 'unavailable';
  let sequence = 0;
  let hook = null;
  let hookedBase = null;

  if (Process.arch !== 'arm64') {
    throw new Error('[WhatsApp/Android] this hook requires ARM64');
  }

  function status(level, text) {
    send({ kind: 'status', level: level, text: '[WhatsApp/Android] ' + text });
  }

  function hex(buffer) {
    return Array.from(new Uint8Array(buffer), x => x.toString(16).padStart(2, '0')).join('');
  }

  function emitCapture(body, threadId) {
    stats.captured++;
    send({
      kind: 'plaintext',
      capture_id: sessionId + '-' + (++sequence),
      captured_at: new Date().toISOString(),
      thread_id: threadId,
      hook: HOOK_NAME,
      build_id: buildId,
      byte_length: body.byteLength
    }, body);
  }

  function install(module) {
    if (hook !== null) return;
    try { buildId = hex(module.base.add(BUILD_ID_OFFSET).readByteArray(20)); }
    catch (error) { status('warning', 'Build ID unavailable: ' + error); }
    const getCString = new NativeFunction(module.base.add(GET_CSTRING_PLT), 'pointer', ['pointer']);
    const getLength = new NativeFunction(module.base.add(GET_LENGTH_PLT), 'int', ['pointer']);
    const address = module.base.add(ENCRYPT_OFFSET);
    hook = Interceptor.attach(address, {
      onEnter(args) {
        try {
          const object = args[2];
          if (object.isNull()) return;
          const length = getLength(object);
          if (length < 0 || length > MAX_BODY_BYTES) {
            stats.dropped++;
            status('warning', 'Skipped invalid or oversized body: ' + length);
            return;
          }
          const bytes = length === 0 ? new ArrayBuffer(0) : getCString(object).readByteArray(length);
          if (bytes === null) throw new Error('native string bytes are unavailable');
          emitCapture(bytes, this.threadId);
        } catch (error) {
          stats.readErrors++;
          status('error', 'Plaintext read failed: ' + error);
        }
      }
    });
    hookedBase = module.base.toString();
    status('info', 'Hooked ' + HOOK_NAME + ' at ' + address);
  }

  const observer = Process.attachModuleObserver({
    onAdded(module) {
      if (module.name !== LIBRARY) return;
      try { install(module); }
      catch (error) { status('error', 'Hook installation failed: ' + error); }
    },
    onRemoved(module) {
      if (module.name === LIBRARY && module.base.toString() === hookedBase) {
        if (hook !== null) hook.detach();
        hook = null;
        hookedBase = null;
      }
    }
  });

  rpc.exports = {
    status() {
      return Object.assign({}, stats, { hooked: hook !== null, base: hookedBase });
    }
  };
  globalThis.__waPlaintextObserver = observer;
})();
