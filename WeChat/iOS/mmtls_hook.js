'use strict';

const CONFIG = Object.assign({
  maxBodyBytes: 8 * 1024 * 1024,
  cgis: [],
  verbose: false,
  captureTransport: true
}, globalThis.__WECHAT_IOS_CAPTURE_CONFIG__ || {});

let buildUuid = null;
const CORE_HOOKS = [
  {
    key: 'task', className: 'EventService',
    selector: 'req2Buf:Out:Host:sequenceId:'
  },
  {
    key: 'pack', className: 'ProtobufEvent',
    selector: 'InternalPack:Host:sequenceId:'
  }
];

const listeners = new Map();
const serializers = new Set();
const taskFrames = new Map();
const packFrames = new Map();
const tlsScopes = new Map();
const selectors = new Map();
const warningCounts = new Map();
let mainModule = null;
let native = null;
let retryTimer = null;
let moduleObserver = null;
let initialized = false;
let sequence = 0;

function status(level, message, details) {
  send(Object.assign({ type: 'status', level, message }, details || {}));
}

function warn(label, error) {
  const count = (warningCounts.get(label) || 0) + 1;
  warningCounts.set(label, count);
  if (count === 1 || count === 10 || count % 100 === 0)
    status('warning', label + ': ' + String(error), { count });
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}

function moduleUuid(module) {
  const base = module.base;
  if (base.readU32() !== 0xfeedfacf)
    throw new Error('Expected a 64-bit Mach-O executable');
  const count = base.add(16).readU32();
  const commandBytes = base.add(20).readU32();
  if (count > 4096 || commandBytes > 1024 * 1024)
    throw new Error('Invalid Mach-O load commands');
  let offset = 32;
  for (let i = 0; i < count; i++) {
    if (offset + 8 > 32 + commandBytes)
      throw new Error('Truncated Mach-O load command');
    const command = base.add(offset);
    const size = command.add(4).readU32();
    if (size < 8 || offset + size > 32 + commandBytes)
      throw new Error('Invalid Mach-O load command size');
    if (command.readU32() === 0x1b && size >= 24) {
      const value = hex(command.add(8).readByteArray(16));
      return [value.slice(0, 8), value.slice(8, 12), value.slice(12, 16),
        value.slice(16, 20), value.slice(20)].join('-');
    }
    offset += size;
  }
  throw new Error('Executable has no LC_UUID');
}

function exportFunction(name, result, args) {
  return new NativeFunction(Module.getGlobalExportByName(name), result, args);
}

function makeRuntime() {
  const msgSend = Module.getGlobalExportByName('objc_msgSend');
  return {
    getClass: exportFunction('objc_getClass', 'pointer', ['pointer']),
    registerSelector: exportFunction('sel_registerName', 'pointer', ['pointer']),
    getObjectClass: exportFunction('object_getClass', 'pointer', ['pointer']),
    getClassName: exportFunction('class_getName', 'pointer', ['pointer']),
    getMethod: exportFunction('class_getInstanceMethod', 'pointer', ['pointer', 'pointer']),
    getImp: exportFunction('method_getImplementation', 'pointer', ['pointer']),
    getObject: new NativeFunction(msgSend, 'pointer', ['pointer', 'pointer']),
    getUInt: new NativeFunction(msgSend, 'uint', ['pointer', 'pointer']),
    getLength: new NativeFunction(msgSend, 'ulong', ['pointer', 'pointer'])
  };
}

function selector(name) {
  if (!selectors.has(name))
    selectors.set(name, native.registerSelector(Memory.allocUtf8String(name)));
  return selectors.get(name);
}

function methodFor(object, name) {
  if (object.isNull()) return ptr(0);
  return native.getMethod(native.getObjectClass(object), selector(name));
}

function getObject(object, name) {
  if (object.isNull() || methodFor(object, name).isNull()) return ptr(0);
  return native.getObject(object, selector(name));
}

function getUInt(object, name) {
  if (object.isNull() || methodFor(object, name).isNull()) return null;
  return native.getUInt(object, selector(name));
}

function stringValue(object) {
  if (object.isNull()) return null;
  const address = getObject(object, 'UTF8String');
  return address.isNull() ? null : address.readUtf8String();
}

function objectClassName(object) {
  if (object.isNull()) return null;
  return native.getClassName(native.getObjectClass(object)).readUtf8String();
}

function codePointer(address) {
  return typeof address.strip === 'function' ? address.strip() : address;
}

function pushFrame(map, threadId, frame) {
  const stack = map.get(threadId) || [];
  stack.push(frame);
  map.set(threadId, stack);
}

function topFrame(map, threadId) {
  const stack = map.get(threadId);
  return stack && stack.length ? stack[stack.length - 1] : null;
}

function popFrame(map, threadId, frame) {
  const stack = map.get(threadId);
  if (!stack || !frame) return;
  const index = stack.lastIndexOf(frame);
  if (index !== -1) stack.splice(index, 1);
  if (!stack.length) map.delete(threadId);
}

function nativeLength(value) {
  const text = value.toString();
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number < 0)
    throw new Error('Invalid native buffer length: ' + text);
  return number;
}

function captureBytes(metadata, bytes, length) {
  if (length > CONFIG.maxBodyBytes) {
    warn('Transport write exceeds --max-bytes; body skipped', length + ' bytes');
    return;
  }
  if (bytes === null) throw new Error('Cannot read native request bytes');
  send(Object.assign({
    type: 'request', schema_version: 1,
    body_length: length,
    request_content_type: 'application/octet-stream',
    capture_layer: 'transport-plaintext-write',
    request_plaintext_status: 'before-transport-record-encryption'
  }, metadata), bytes);
}

function transportMetadata(source, transport, threadId, details) {
  return Object.assign({
    id: Process.id + '-' + Date.now() + '-' + (++sequence),
    timestamp: new Date().toISOString(),
    process_id: Process.id, thread_id: threadId, platform: 'ios',
    build_uuid: buildUuid,
    task_id: null, sequence_id: null, cgi: null, cgi_name: null,
    uri: null, host: null, channel_type: null, request_class: null,
    source, transport_path: transport,
    request_semantics: 'Transport plaintext; may contain protocol framing or business-layer ciphertext.'
  }, details || {});
}

function hookLegacyCrypt(offset, source, transport) {
  const key = 'transport:' + source;
  if (listeners.has(key)) return;
  const address = mainModule.base.add(offset);
  const range = Process.findRangeByAddress(address);
  if (!range || !range.protection.includes('x'))
    throw new Error(source + ' Crypt entry is not executable at ' + address);
  listeners.set(key, Interceptor.attach(address, {
    onEnter(args) {
      try {
        // Inferred ARM64 ABI: self, nonce, nonce_len, aad, aad_len, input, input_len, output.
        if (args[0].isNull() || args[3].isNull() || args[5].isNull()) return;
        if (args[0].add(0x20).readU8() !== 1) return; // encryption only
        const aadLength = nativeLength(args[4]);
        if (aadLength < 13) return;
        const recordType = args[3].add(8).readU8();
        if (recordType !== 23) return; // TLS application_data; omit handshake/alert records
        const length = nativeLength(args[6]);
        if (length > CONFIG.maxBodyBytes) {
          warn('Transport write exceeds --max-bytes; body skipped', length + ' bytes');
          return;
        }
        const snapshot = length ? args[5].readByteArray(length) : new ArrayBuffer(0);
        const aad = new Uint8Array(args[3].readByteArray(13));
        const sequenceHex = Array.from(aad.slice(0, 8), b => b.toString(16).padStart(2, '0')).join('');
        const metadata = transportMetadata(source, transport, this.threadId, {
          record_type: recordType,
          record_sequence_hex: sequenceHex,
          capture_layer: 'mmtls-record-plaintext',
          request_plaintext_status: 'before-mmtls-record-encryption'
        });
        captureBytes(metadata, snapshot, length);
      } catch (error) {
        warn('MMTLS record capture failed (' + source + ')', error);
      }
    }
  }));
  status('info', 'Hooked MMTLS application-data writer', { source, offset: '0x' + offset.toString(16) });
}

function pushTlsScope(threadId, name) {
  pushFrame(tlsScopes, threadId, { name });
}

function currentTlsScope(threadId) {
  const frame = topFrame(tlsScopes, threadId);
  return frame ? frame.name : null;
}

function hookTlsScope(offset, name) {
  const key = 'transport-scope:' + name;
  if (listeners.has(key)) return;
  const address = mainModule.base.add(offset);
  const range = Process.findRangeByAddress(address);
  if (!range || !range.protection.includes('x'))
    throw new Error(name + ' entry is not executable at ' + address);
  listeners.set(key, Interceptor.attach(address, {
    onEnter() { pushTlsScope(this.threadId, name); this.frame = topFrame(tlsScopes, this.threadId); },
    onLeave() { popFrame(tlsScopes, this.threadId, this.frame); }
  }));
}

function hookSslExport(module, exportName, earlyData) {
  const keyPrefix = 'transport-export:' + module.name + ':' + exportName;
  let address = null;
  try { if (typeof module.findExportByName === 'function') address = module.findExportByName(exportName); } catch (_) {}
  if (address === null && typeof Module.findExportByName === 'function') {
    try { address = Module.findExportByName(module.name, exportName); } catch (_) {}
  }
  if (address === null) {
    try {
      const exports = module.enumerateExports();
      const found = exports.find(item => item.name === exportName || item.name === '_' + exportName);
      if (found) address = found.address;
    } catch (_) {}
  }
  if (address === null) return false;
  const key = keyPrefix + ':' + address;
  if (listeners.has(key)) return true;
  listeners.set(key, Interceptor.attach(address, {
    onEnter(args) {
      this.requested = 0;
      this.snapshot = null;
      this.scope = currentTlsScope(this.threadId);
      this.writeLengthOut = earlyData ? args[3] : ptr(0);
      try {
        if (args[1].isNull()) return;
        const length = earlyData ? nativeLength(args[2]) : args[2].toInt32();
        if (!Number.isSafeInteger(length) || length <= 0) return;
        if (length > CONFIG.maxBodyBytes) {
          warn('TLS write exceeds --max-bytes; body skipped', length + ' bytes');
          return;
        }
        this.requested = length;
        this.snapshot = args[1].readByteArray(length);
      } catch (error) {
        warn(exportName + ' capture failed', error);
      }
    },
    onLeave(result) {
      if (this.snapshot === null) return;
      try {
        let written;
        if (earlyData) {
          if (result.toInt32() !== 1 || this.writeLengthOut.isNull()) return;
          written = nativeLength(this.writeLengthOut.readU64());
        } else {
          written = result.toInt32();
        }
        if (!Number.isSafeInteger(written) || written <= 0 || written > this.requested) return;
        const path = this.scope || 'openssl-' + exportName + '-unclassified';
        const metadata = transportMetadata('openssl.' + exportName, path, this.threadId, {
          capture_layer: 'tls-plaintext-write',
          request_plaintext_status: 'before-tls-record-encryption',
          request_semantics: 'Bytes accepted by OpenSSL TLS write; may contain protocol framing or business-layer ciphertext.'
        });
        captureBytes(metadata, this.snapshot.slice(0, written), written);
      } catch (error) {
        warn(exportName + ' capture failed', error);
      }
    }
  }));
  status('info', 'Hooked OpenSSL plaintext writer', { module: module.path, export: exportName });
  return true;
}

function isOpenSslModule(module) {
  const name = String(module.name || '').toLowerCase();
  const path = String(module.path || '').toLowerCase();
  return name === 'openssl' || path.includes('/openssl.framework/openssl');
}

function installOpenSslHooks(module) {
  if (!isOpenSslModule(module)) return [];
  const pending = [];
  if (!hookSslExport(module, 'SSL_write', false)) pending.push(module.path + ':SSL_write');
  if (!hookSslExport(module, 'SSL_write_early_data', true)) pending.push(module.path + ':SSL_write_early_data');
  return pending;
}

function installTransport() {
  if (!CONFIG.captureTransport) return [];
  const pending = [];
  try { hookLegacyCrypt(0x144bc074, 'mmtls::AesGcmCrypter::Crypt', 'mmtls-legacy'); }
  catch (error) { warn('Main MMTLS hook unavailable', error); pending.push('mmtls-legacy Crypt'); }
  try { hookLegacyCrypt(0x0b83b5d4, 'paymars::mmtls::AesGcmCrypter::Crypt', 'paymars-mmtls-legacy'); }
  catch (error) { warn('Payment MMTLS hook unavailable', error); pending.push('payment MMTLS Crypt'); }
  try { hookTlsScope(0x144aaf5c, 'mmtls2-datawrite'); }
  catch (error) { warn('MMTLS2 DataWrite marker unavailable', error); pending.push('MMTLS2 DataWrite marker'); }
  try { hookTlsScope(0x144a9c08, 'mmtls2-early-data'); }
  catch (error) { warn('MMTLS2 early-data marker unavailable', error); pending.push('MMTLS2 early-data marker'); }
  let opensslFound = false;
  for (const module of Process.enumerateModules()) {
    if (!isOpenSslModule(module)) continue;
    opensslFound = true;
    try { pending.push.apply(pending, installOpenSslHooks(module)); }
    catch (error) {
      warn('OpenSSL writer hook unavailable', error);
      pending.push(module.path + ': SSL writer hook failed');
    }
  }
  if (!opensslFound) pending.push('openssl.framework/openssl (not loaded yet)');
  return pending;
}

function watchOpenSslLoads() {
  if (!CONFIG.captureTransport || !Process.attachModuleObserver || moduleObserver) return;
  moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
      if (!isOpenSslModule(module)) return;
      try {
        const pending = installOpenSslHooks(module);
        status(pending.length ? 'warning' : 'ready',
          pending.length ? 'OpenSSL TLS exports are not available yet' : 'OpenSSL TLS writer module observed',
          { module: module.path, transport_pending: pending });
      } catch (error) { warn('OpenSSL writer hook unavailable', error); }
    }
  });
}

function captureData(frame, data, source) {
  if (!frame || frame.emitted || frame.filtered || data.isNull()) return;
  try {
    if (methodFor(data, 'length').isNull() || methodFor(data, 'bytes').isNull())
      throw new Error('Expected NSData with length and bytes selectors');
    const length = Number(native.getLength(data, selector('length')).toString());
    if (!Number.isSafeInteger(length) || length < 0)
      throw new Error('Invalid NSData length');
    if (length > CONFIG.maxBodyBytes) {
      frame.oversize = true;
      warn('Request exceeds --max-bytes; body skipped', length + ' bytes');
      return;
    }
    const bytes = length ? getObject(data, 'bytes').readByteArray(length) : new ArrayBuffer(0);
    if (bytes === null) throw new Error('Cannot read NSData bytes');
    const payload = Object.assign({}, frame.metadata, {
      type: 'request', schema_version: 1,
      source, body_length: length,
      request_content_type: 'application/x-protobuf',
      capture_layer: 'app-protobuf',
      request_plaintext_status: 'before-business-encryption-and-mmtls'
    });
    send(payload, bytes);
    frame.emitted = true;
  } catch (error) {
    warn('Plaintext capture failed', error);
  }
}

function hookSerializer(request) {
  const method = methodFor(request, 'serializedData');
  if (method.isNull()) throw new Error('Request class has no serializedData method');
  const implementation = codePointer(native.getImp(method));
  const key = implementation.toString();
  if (serializers.has(key)) return;
  const range = Process.findRangeByAddress(implementation);
  if (!range || !range.protection.includes('x'))
    throw new Error('serializedData implementation is not executable');
  const listener = Interceptor.attach(implementation, {
    onEnter(args) {
      this.frame = null;
      const frame = topFrame(packFrames, this.threadId);
      if (frame && !frame.emitted && !frame.filtered && args[0].equals(frame.request)) {
        this.frame = frame;
        frame.serializerDepth = (frame.serializerDepth || 0) + 1;
      }
    },
    onLeave(result) {
      if (this.frame) {
        this.frame.serializerDepth -= 1;
        if (this.frame.serializerDepth === 0)
          captureData(this.frame, result, 'WXPBGeneratedMessage.serializedData');
      }
    }
  });
  listeners.set('serializer:' + key, listener);
  serializers.add(key);
  if (CONFIG.verbose)
    status('info', 'Hooked serializedData', { class_name: objectClassName(request), address: key });
}

function taskCallbacks() {
  return {
    onEnter(args) {
      this.frame = { task_id: args[2].toUInt32() };
      pushFrame(taskFrames, this.threadId, this.frame);
    },
    onLeave() { popFrame(taskFrames, this.threadId, this.frame); }
  };
}

function packCallbacks() {
  return {
    onEnter(args) {
      const parent = topFrame(taskFrames, this.threadId);
      this.frame = { emitted: false, filtered: false, request: ptr(0) };
      pushFrame(packFrames, this.threadId, this.frame);
      try {
        const wrap = getObject(args[0], 'm_pbCGIWrap');
        if (wrap.isNull()) throw new Error('ProtobufEvent has no CGI wrapper');
        const cgi = getUInt(wrap, 'm_uiCgi');
        this.frame.filtered = CONFIG.cgis.length > 0 && !CONFIG.cgis.includes(cgi);
        if (this.frame.filtered) return;
        const request = getObject(wrap, 'm_pbRequest');
        this.frame.request = request;
        this.frame.metadata = {
          id: Process.id + '-' + Date.now() + '-' + (++sequence),
          timestamp: new Date().toISOString(),
          process_id: Process.id, thread_id: this.threadId, platform: 'ios',
          build_uuid: buildUuid,
          task_id: parent ? parent.task_id : null,
          sequence_id: args[4].toUInt32() & 0xffff,
          cgi, cgi_name: stringValue(getObject(wrap, 'm_nsCgiName')),
          uri: stringValue(getObject(wrap, 'm_nsUri')),
          host: stringValue(args[3]) || stringValue(getObject(wrap, 'reqHost')),
          channel_type: getUInt(wrap, 'm_uiChannelType'),
          request_class: objectClassName(request)
        };
        const cached = getObject(wrap, 'requestData');
        if (!cached.isNull()) {
          captureData(this.frame, cached, 'ProtobufCGIWrap.requestData');
        } else if (!request.isNull()) {
          hookSerializer(request);
        } else {
          warn('Request has neither protobuf object nor cached data', cgi);
        }
      } catch (error) {
        warn('Request context failed', error);
      }
    },
    onLeave(result) {
      const frame = this.frame;
      if (frame && !frame.emitted && !frame.filtered && !frame.oversize && result.toInt32() !== 0)
        warn('Successful pack without captured plaintext', 'check request serializer diagnostics');
      popFrame(packFrames, this.threadId, frame);
    }
  };
}

function installCore() {
  const pending = [];
  for (const spec of CORE_HOOKS) {
    if (listeners.has(spec.key)) continue;
    const klass = native.getClass(Memory.allocUtf8String(spec.className));
    if (klass.isNull()) { pending.push(spec.className); continue; }
    const method = native.getMethod(klass, selector(spec.selector));
    if (method.isNull()) throw new Error('Missing method: ' + spec.className + ' ' + spec.selector);
    const implementation = codePointer(native.getImp(method));
    listeners.set(spec.key, Interceptor.attach(implementation,
      spec.key === 'task' ? taskCallbacks() : packCallbacks()));
  }
  if (!pending.length)
    status('ready', 'Request hooks installed', { build_uuid: buildUuid, hooks: CORE_HOOKS.map(h => h.selector) });
  return pending;
}

function stop() {
  if (retryTimer !== null) { clearInterval(retryTimer); retryTimer = null; }
  if (moduleObserver !== null) {
    try { moduleObserver.detach(); } catch (_) {}
    moduleObserver = null;
  }
  for (const listener of listeners.values()) listener.detach();
  listeners.clear();
  serializers.clear();
  taskFrames.clear();
  packFrames.clear();
  tlsScopes.clear();
  initialized = false;
}

rpc.exports = {
  init() {
    if (initialized) return { build_uuid: buildUuid, ready: listeners.has('pack') && listeners.has('task') };
    if (Process.platform !== 'darwin' || Process.arch !== 'arm64' || Process.pointerSize !== 8)
      throw new Error('This hook requires the ARM64 iOS WeChat executable');
    if (Process.codeSigningPolicy === 'required')
      throw new Error('Frida cannot attach Interceptor hooks with the current code-signing policy');
    if (!Number.isSafeInteger(CONFIG.maxBodyBytes) || CONFIG.maxBodyBytes < 1 || CONFIG.maxBodyBytes > 16 * 1024 * 1024)
      throw new Error('maxBodyBytes must be between 1 and 16777216');
    mainModule = Process.findModuleByName('WeChat') || Process.mainModule;
    let actualUuid = null;
    try { actualUuid = moduleUuid(mainModule); }
    catch (error) { warn('Build UUID unavailable', error); }
    buildUuid = actualUuid;
    native = makeRuntime();
    try {
      const pending = installCore();
      watchOpenSslLoads();
      const transportPending = installTransport();
      initialized = true;
      if (CONFIG.captureTransport) {
        status(transportPending.length ? 'warning' : 'info',
          transportPending.length ? 'Transport capture is partially installed' : 'Transport capture hooks installed',
          { transport_pending: transportPending });
      }
      if (pending.length || (transportPending.length && !moduleObserver)) {
        const deadline = Date.now() + 60000;
        retryTimer = setInterval(() => {
          try {
            const stillPending = installCore();
            const stillTransport = installTransport();
            if (!stillPending.length && !stillTransport.length) {
              clearInterval(retryTimer); retryTimer = null;
            } else if (Date.now() > deadline) {
              clearInterval(retryTimer); retryTimer = null;
              if (stillPending.length)
                throw new Error('Classes unavailable after startup: ' + stillPending.join(', '));
              status('warning', 'Some transport hooks remain unavailable', { transport_pending: stillTransport });
            }
          } catch (error) {
            stop();
            status('fatal', String(error));
          }
          }, 250);
      }
      return {
        build_uuid: actualUuid,
        ready: !pending.length,
        transport_ready: !transportPending.length,
        transport_pending: transportPending,
        pending
      };
    } catch (error) {
      stop();
      throw error;
    }
  },
  stop
};
