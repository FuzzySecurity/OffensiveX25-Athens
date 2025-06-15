/**
 * @fileoverview Comprehensive network traffic monitoring and interception system for VS Code extensions.
 * Provides low-level hooks for HTTP/HTTPS, WebSocket, gRPC, and protobuf traffic analysis.
 * @version 1.0.0
 * @author Ruben Boonen
 */

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { createRequire } = require('module');

/**
 * Universal require function that works in both CommonJS and ES modules
 * @type {NodeRequire}
 */
const __require = typeof require === 'function' ? require : createRequire(__filename);

/**
 * Global counter for tracking intercepted network requests
 * @type {number}
 */
let requestCounter = 0;

/**
 * Lazily loaded protobuf root for schema parsing
 * @type {protobuf.Root|null}
 */
let protoRoot = null;

/**
 * Protobuf library instance, loaded on demand
 * @type {typeof import('protobufjs/light')|null}
 */
const protobuf = (() => {
  try { return __require('protobufjs/light'); } catch { return null; }
})();

/**
 * Loads protobuf schema files from the proto directory for message decoding
 * @returns {void}
 * @throws {Error} When proto files cannot be loaded or parsed
 */
function loadProtoSchemas() {
  if (!protobuf || protoRoot) return;
  const protoDir = path.join(__dirname, 'proto');
  if (!fs.existsSync(protoDir)) {
    console.log('🛰  No proto directory found to load schemas');
    return;
  }
  const files = fs.readdirSync(protoDir).filter(f => f.endsWith('.proto')).map(f => path.join(protoDir, f));
  if (!files.length) {
    console.log('🛰  No .proto files found in proto directory');
    return;
  }
  try {
    protoRoot = protobuf.loadSync(files);
    console.log(`🛰  Loaded ${files.length} proto schema file(s)`);
  } catch (e) {
    console.log('🛰  Failed to load proto schemas:', e.message);
  }
}

/**
 * Attempts to decode a protobuf message using loaded schemas
 * @param {Buffer} buffer - The binary protobuf data to decode
 * @param {string} rpcPath - The RPC path to determine message type (e.g., "/service/method")
 * @returns {Object|null} Decoded protobuf message object or null if decoding fails
 */
function tryDecodeProto(buffer, rpcPath) {
  if (!protobuf) return null;
  loadProtoSchemas();
  if (!protoRoot) return null;

  if (buffer.length > 5 && buffer[0] === 0x00) {
    const len = buffer.readUInt32BE(1);
    if (len + 5 === buffer.length) buffer = buffer.slice(5);
  }

  const cleanPath = rpcPath.startsWith('/') ? rpcPath.slice(1) : rpcPath;
  const [svc, method] = cleanPath.split('/');
  if (!svc || !method) return null;

  const service = protoRoot.lookupService(svc);
  if (!service) return null;
  const reqTypeName = service.methods[method]?.requestType;
  if (!reqTypeName) return null;
  const Msg = protoRoot.lookupType(reqTypeName);
  if (!Msg) return null;

  try {
    const msg = Msg.decode(buffer);
    return Msg.toObject(msg, { longs: String, enums: String, bytes: 'base64' });
  } catch {
    return null;
  }
}

/**
 * Logs network request details with timestamp and relevant headers
 * @param {string} source - The source/type of the request (e.g., 'HTTP-REQUEST', 'WEBSOCKET')
 * @param {string} method - HTTP method or connection type
 * @param {string} url - Target URL or endpoint
 * @param {Object} [headers={}] - Request headers to log
 * @returns {void}
 */
function logRequest(source, method, url, headers = {}) {
  requestCounter++;
  const timestamp = new Date().toISOString();
  console.log(`🛰  [${requestCounter}] ${timestamp} ${source} ${method} ${url}`);
  
  const interestingHeaders = ['authorization', 'x-api-key', 'user-agent', 'content-type'];
  for (const header of interestingHeaders) {
    if (headers[header]) {
      console.log(`🛰      ${header}: ${headers[header]}`);
    }
  }
}

/**
 * Installs hooks for Node.js HTTP/HTTPS modules and low-level socket connections
 * Intercepts net.Socket, tls.connect, http.request, and https.request calls
 * @returns {void}
 * @throws {Error} When hooking fails due to module unavailability
 */
function installNodeHooks() {
  try {
    const net = __require('node:net');
    if (net && net.Socket && net.Socket.prototype.connect) {
      const origConnect = net.Socket.prototype.connect;
      net.Socket.prototype.connect = function (...args) {
        const options = args[0];
        if (typeof options === 'object' && (options.port === 80 || options.port === 443 || options.port > 1000)) {
          logRequest('NET-SOCKET', 'CONNECT', `${options.host || options.hostname}:${options.port}`);
        }
        return origConnect.apply(this, args);
      };
    }

    const tls = __require('node:tls');
    if (tls && tls.connect) {
      const origTlsConnect = tls.connect;
      tls.connect = function (...args) {
        const options = args[0];
        if (typeof options === 'object') {
          logRequest('TLS-SOCKET', 'CONNECT', `${options.host || options.hostname}:${options.port || 443}`);
        }
        return origTlsConnect.apply(this, args);
      };
    }

    if (http && http.request) {
      const origHttpRequest = http.request;
      http.request = function (options, callback) {
        const url = typeof options === 'string' ? options : 
          `http://${options.hostname || options.host || 'localhost'}:${options.port || 80}${options.path || '/'}`;
        logRequest('HTTP-REQUEST', options.method || 'GET', url, options.headers || {});
        return origHttpRequest.call(this, options, callback);
      };
    }

    if (https && https.request) {
      const origHttpsRequest = https.request;
      https.request = function (options, callback) {
        const url = typeof options === 'string' ? options : 
          `https://${options.hostname || options.host || 'localhost'}:${options.port || 443}${options.path || '/'}`;
        logRequest('HTTPS-REQUEST', options.method || 'GET', url, options.headers || {});
        return origHttpsRequest.call(this, options, callback);
      };
    }

  } catch (error) {
    console.log('🛰  Error installing Node hooks:', error.message);
  }
}

/**
 * Installs hooks for Electron's networking module with fallback access methods
 * Attempts multiple strategies to access Electron's net module across different contexts
 * @returns {void}
 * @throws {Error} When Electron net module cannot be accessed or hooked
 */
function installElectronHooks() {
  try {
    let electronNet;
    try {
      electronNet = __require('electron').net;
    } catch (e) {
      try {
        const { remote } = __require('electron');
        electronNet = remote && remote.net;
      } catch (e2) {
        electronNet = (global.require || __require) && (global.require || __require)('electron').net;
      }
    }

    if (electronNet && electronNet.request) {
      const origElectronRequest = electronNet.request;
      electronNet.request = function (options) {
        const url = typeof options === 'string' ? options : options.url;
        const method = typeof options === 'object' ? options.method || 'GET' : 'GET';
        logRequest('ELECTRON-NET', method, url);
        return origElectronRequest.apply(this, arguments);
      };
      console.log('🛰  Hooked Electron net module');
    }

  } catch (error) {
    console.log('🛰  Could not hook Electron net:', error.message);
  }
}

/**
 * Installs hooks for WebSocket connections including native WebSocket and ws module
 * Intercepts both browser WebSocket API and Node.js ws library
 * @returns {void}
 * @throws {Error} When WebSocket hooking fails
 */
function installWebSocketHooks() {
  try {
    if (typeof WebSocket !== 'undefined') {
      const OrigWebSocket = WebSocket;
      WebSocket = function (url, protocols) {
        logRequest('WEBSOCKET', 'CONNECT', url);
        return new OrigWebSocket(url, protocols);
      };
      Object.setPrototypeOf(WebSocket, OrigWebSocket);
      Object.assign(WebSocket, OrigWebSocket);
    }

    try {
      const ws = __require('ws');
      if (ws && ws.WebSocket) {
        const OrigWS = ws.WebSocket;
        ws.WebSocket = function (url, protocols, options) {
          logRequest('WS-MODULE', 'CONNECT', url);
          return new OrigWS(url, protocols, options);
        };
        Object.setPrototypeOf(ws.WebSocket, OrigWS);
      }
    } catch (e) {
      // ws module not available
    }

  } catch (error) {
    console.log('🛰  Error installing WebSocket hooks:', error.message);
  }
}

/**
 * Installs hooks for fetch API including global fetch and undici implementations
 * Covers both browser fetch and Node.js 18+ native fetch via undici
 * @returns {void}
 * @throws {Error} When fetch hooking fails
 */
function installFetchHooks() {
  try {
    if (globalThis.fetch && !globalThis.fetch.__hooked) {
      const origFetch = globalThis.fetch;
      globalThis.fetch = async function (input, init = {}) {
        const url = typeof input === 'string' ? input : input.url;
        const method = init.method || 'GET';
        logRequest('GLOBAL-FETCH', method, url, init.headers || {});
        return origFetch.apply(this, arguments);
      };
      globalThis.fetch.__hooked = true;
    }

    try {
      const undici = __require('undici');
      if (undici && undici.fetch && !undici.fetch.__hooked) {
        const origUndici = undici.fetch;
        undici.fetch = async function (input, init = {}) {
          const url = typeof input === 'string' ? input : input.url;
          const method = init.method || 'GET';
          logRequest('UNDICI-FETCH', method, url, init.headers || {});
          return origUndici.apply(this, arguments);
        };
        undici.fetch.__hooked = true;
      }
    } catch (e) {
      // undici not available
    }

  } catch (error) {
    console.log('🛰  Error installing fetch hooks:', error.message);
  }
}

/**
 * Installs hooks for VS Code specific APIs and popular HTTP libraries
 * Intercepts module loading to hook axios, node-fetch, and other HTTP clients
 * Also attempts to discover VS Code internal request services
 * @returns {void}
 * @throws {Error} When VS Code API hooking fails
 */
function installVSCodeHooks() {
  try {
    const Module = __require('module');
    if (Module && Module.prototype && Module.prototype.require) {
      const origRequire = Module.prototype.require;
      
      Module.prototype.require = function (id) {
        const result = origRequire.apply(this, arguments);
        
        if (id.includes('http') || id.includes('fetch') || id.includes('request') || id.includes('axios')) {
          console.log(`🛰  Module loaded: ${id}`);
        }
        
        try {
          if (id === 'axios' && result && result.create) {
            const origCreate = result.create;
            result.create = function (config) {
              const instance = origCreate.apply(this, arguments);
              const origRequest = instance.request;
              instance.request = function (config) {
                logRequest('AXIOS-INSTANCE', config.method?.toUpperCase() || 'GET', config.url || config.baseURL);
                return origRequest.apply(this, arguments);
              };
              return instance;
            };
          }

          if (id === 'node-fetch' && typeof result === 'function') {
            const origNodeFetch = result;
            const wrappedFetch = function (url, options = {}) {
              logRequest('NODE-FETCH', options.method || 'GET', url, options.headers || {});
              return origNodeFetch.apply(this, arguments);
            };
            Object.setPrototypeOf(wrappedFetch, origNodeFetch);
            Object.assign(wrappedFetch, origNodeFetch);
            return wrappedFetch;
          }

        } catch (hookError) {
          // Continue if specific module hooking fails
        }
        
        return result;
      };
    }

    setTimeout(() => {
      try {
        if (global.vscode || globalThis.vscode) {
          console.log('🛰  Found VS Code global object');
        }
        
        const globals = Object.getOwnPropertyNames(globalThis);
        const requestRelated = globals.filter(name => 
          name.toLowerCase().includes('request') || 
          name.toLowerCase().includes('http') ||
          name.toLowerCase().includes('fetch')
        );
        
        if (requestRelated.length > 0) {
          console.log('🛰  Found potential request globals:', requestRelated);
        }
        
      } catch (e) {
        // Ignore errors in global inspection
      }
    }, 1000);

  } catch (error) {
    console.log('🛰  Error installing VS Code hooks:', error.message);
  }
}

/**
 * Installs hooks for XMLHttpRequest to intercept traditional AJAX requests
 * Wraps both open() and send() methods to capture request details
 * @returns {void}
 * @throws {Error} When XMLHttpRequest hooking fails
 */
function installXHRHooks() {
  try {
    if (typeof XMLHttpRequest !== 'undefined') {
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      
      XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
        this._method = method;
        this._url = url;
        return origOpen.apply(this, arguments);
      };
      
      XMLHttpRequest.prototype.send = function (data) {
        if (this._method && this._url) {
          logRequest('XHR', this._method, this._url);
        }
        return origSend.apply(this, arguments);
      };
    }
  } catch (error) {
    console.log('🛰  Error installing XHR hooks:', error.message);
  }
}

/**
 * Installs hooks for HTTP/2 connections and streams with protobuf decoding
 * Intercepts http2.connect and session.request to capture gRPC traffic
 * @returns {void}
 * @throws {Error} When HTTP/2 module is unavailable or hooking fails
 */
function installHttp2Hooks() {
  try {
    const http2 = __require('node:http2');
    if (http2 && http2.connect && !http2.connect.__hooked) {
      const origConnect = http2.connect;
      http2.connect = function (authority, options, listener) {
        logRequest('HTTP2-CONNECT', 'CONNECT', authority);
        const session = origConnect.call(this, authority, options, listener);

        try {
          const origRequest = session.request;
          session.request = function (headers, options) {
            const method = headers[':method'] || 'GET';
            const path = headers[':path'] || '/';
            const scheme = headers[':scheme'] || 'https';
            const authorityHeader = headers[':authority'] || authority;
            const url = `${scheme}://${authorityHeader}${path}`;
            logRequest('HTTP2-REQUEST', method, url, headers);
            const stream = origRequest.call(this, headers, options);

            const chunks = [];
            stream.on('data', c => chunks.push(c));
            stream.on('end', () => {
              const body = Buffer.concat(chunks);
              const decoded = tryDecodeProto(body, path);
              if (decoded) {
                console.log('🛰  DECODED PROTO', JSON.stringify(decoded, null, 2));
              } else {
                const raw = parseRawProto(body);
                if (raw && Object.keys(raw).length) {
                  console.log(`🛰  Proto decode unavailable (len=${body.length}) for ${path} -> raw fields`, JSON.stringify(raw));
                } else {
                  console.log(`🛰  Proto decode unavailable (len=${body.length}) for ${path}`);
                }
              }
            });

            return stream;
          };
        } catch (e) {
          // continue if unable to hook
        }

        return session;
      };
      http2.connect.__hooked = true;
    }
  } catch (error) {
    // http2 not available or hook failed
  }
}

/**
 * Installs hooks for child_process module to detect spawned helper binaries
 * Monitors spawn, execFile, exec, and fork calls for external process communication
 * @returns {void}
 * @throws {Error} When child_process module hooking fails
 */
function installChildProcessHooks() {
  try {
    const cp = __require('node:child_process');
    if (!cp || cp.spawn.__hooked) {
      return;
    }

    /**
     * Creates a wrapper function for child_process methods
     * @param {string} fnName - Name of the child_process method to wrap
     * @returns {void}
     */
    const wrap = (fnName) => {
      const orig = cp[fnName];
      cp[fnName] = function (...args) {
        try {
          const cmd = args[0];
          const argv = Array.isArray(args[1]) ? args[1] : [];
          logRequest('CHILD-PROCESS', fnName.toUpperCase(), `${cmd} ${argv.join(' ')}`);
        } catch (_) {}
        return orig.apply(this, args);
      };
    };

    ['spawn', 'execFile', 'exec', 'fork'].forEach(wrap);
    cp.spawn.__hooked = true;
    console.log('🛰  Hooked child_process module');

  } catch (error) {
    console.log('🛰  Error installing child_process hooks:', error.message);
  }
}

/**
 * Installs hooks for streaming fetch operations to capture gRPC/Connect traffic
 * Intercepts both request and response streams for frame-by-frame analysis
 * @returns {void}
 * @throws {Error} When streaming fetch hooking fails
 */
function hookStreamingFetch() {
  if (!globalThis.fetch || globalThis.fetch.__streamHooked) return;

  /**
   * Creates a frame logger for streaming protobuf data
   * @param {string} label - Label for logging (e.g., 'REQ-STREAM-OUT')
   * @param {string} rpcPath - RPC path for protobuf type resolution
   * @returns {Function} Frame processing function
   */
  function makeFrameLogger(label, rpcPath) {
    let pending = Buffer.alloc(0);
    return (chunk) => {
      if (!chunk) return;
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      while (pending.length >= 5) {
        const compressedFlag = pending[0];
        const length = pending.readUInt32BE(1);
        if (pending.length < 5 + length) break;
        let frame = pending.subarray(5, 5 + length);
        pending = pending.subarray(5 + length);

        if (compressedFlag === 1) {
          try { frame = zlib.gunzipSync(frame); } catch (_) { /* ignore */ }
        }

        const decoded = tryDecodeProto(frame, rpcPath);
        if (decoded) {
          console.log(`🛰  ${label} DECODED`, JSON.stringify(decoded, null, 2));
        } else {
          const rawFields = parseRawProto(frame);
          if (rawFields && Object.keys(rawFields).length) {
            console.log(`🛰  ${label} RAW-FIELDS`, JSON.stringify(rawFields));
          } else {
            console.log(`🛰  ${label} raw`, frame.toString('hex').slice(0, 64) + (frame.length > 32 ? '…' : ''));
          }
        }
      }
    };
  }

  const OrigRequest = globalThis.Request;
  if (OrigRequest && !OrigRequest.__streamHooked) {
    const WrappedRequest = function (input, init = {}) {
      const url = typeof input === 'string' ? input : input.url || '';
      const rpcPath = (() => { try { return new URL(url).pathname; } catch { return ''; } })();

      if (init && init.body && typeof init.body.getReader === 'function') {
        const reader = init.body.getReader();
        const logger = makeFrameLogger('REQ-STREAM-OUT', rpcPath);
        init.body = new ReadableStream({
          start(controller) {
            function pump() {
              reader.read().then(({ done, value }) => {
                if (done) { controller.close(); return; }
                logger(value);
                controller.enqueue(value);
                pump();
              });
            }
            pump();
          }
        });
      }
      return new OrigRequest(input, init);
    };
    Object.setPrototypeOf(WrappedRequest, OrigRequest);
    globalThis.Request = WrappedRequest;
    WrappedRequest.__streamHooked = true;
  }

  const origFetch = globalThis.fetch;
  globalThis.fetch = async function (...args) {
    const url = args[0];
    const rpcPath = (() => { try { return new URL(url).pathname; } catch { return ''; } })();
    const resp = await origFetch.apply(this, args);

    if (resp && resp.body && resp.body.getReader) {
      const reader = resp.body.getReader();
      const logger = makeFrameLogger('RESP-STREAM-IN', rpcPath);

      const rs = new ReadableStream({
        start(controller) {
          function pump() {
            reader.read().then(({ done, value }) => {
              if (done) { controller.close(); return; }
              logger(value);
              controller.enqueue(value);
              pump();
            });
          }
          pump();
        }
      });
      return new Response(rs, resp);
    }
    return resp;
  };

  globalThis.fetch.__streamHooked = true;
  console.log('🛰  Streaming fetch hooks installed');
}

/**
 * Installs hooks for protobufjs decode operations to log all decoded messages
 * Intercepts Type.prototype.decode to capture protobuf message content
 * @returns {void}
 * @throws {Error} When protobufjs hooking fails or library is unavailable
 */
function installProtobufDecodeHook() {
  try {
    const pb = (() => {
      try { return __require('protobufjs/light'); } catch { /* ignore */ }
      try { return __require('protobufjs/minimal'); } catch { /* ignore */ }
      return null;
    })();

    if (!pb || !pb.Type || pb.Type.prototype.__decodeHooked) return;

    const origDecode = pb.Type.prototype.decode;
    pb.Type.prototype.decode = function decodeHook(readerOrBuf, length) {
      const msg = origDecode.call(this, readerOrBuf, length);

      try {
        const obj = this.toObject(msg, { longs: String, enums: String, bytes: 'base64' });
        console.log(`🛰  PROTOBUF-DECODE [${this.fullName || this.name}]`, JSON.stringify(obj, null, 2));
      } catch (_) {
        // Silently ignore stringify errors – never disrupt caller
      }

      return msg;
    };

    pb.Type.prototype.__decodeHooked = true;
    console.log('🛰  Hooked protobufjs Type.decode – logging all decoded messages');
  } catch (error) {
    console.log('🛰  Failed to install protobufjs decode hook:', error.message);
  }
}

/**
 * Generic fallback parser for unknown protobuf messages
 * Extracts raw field numbers and values when schema-based decoding fails
 * @param {Buffer} buffer - Binary protobuf data to parse
 * @returns {Object|null} Object with field numbers as keys and decoded values, or null if parsing fails
 */
function parseRawProto(buffer) {
  if (!protobuf) return null;
  try {
    const reader = protobuf.Reader.create(buffer);
    const out = {};
    while (reader.pos < reader.len) {
      const tag = reader.uint32();
      const fieldNo = tag >>> 3;
      const wireType = tag & 7;
      let value;
      switch (wireType) {
        case 0: {
          const v = reader.uint64();
          value = typeof v === 'object' && v !== null && v.toString ? v.toString() : v;
          break;
        }
        case 1: {
          const lo = reader.uint32();
          const hi = reader.uint32();
          value = `0x${hi.toString(16).padStart(8,'0')}${lo.toString(16).padStart(8,'0')}`;
          break;
        }
        case 2: {
          const len = reader.uint32();
          const bytes = reader.buf.subarray(reader.pos, reader.pos + len);
          reader.pos += len;
          const text = bytes.toString('utf8');
          const printable = /^[\x20-\x7E\t\r\n]+$/.test(text);
          value = printable ? text.trim() : bytes.toString('base64');
          break;
        }
        case 5: {
          const v = reader.uint32();
          value = `0x${v.toString(16).padStart(8,'0')}`;
          break;
        }
        default:
          reader.skipType(wireType);
          continue;
      }
      if (out[fieldNo] === undefined) out[fieldNo] = value;
      else if (Array.isArray(out[fieldNo])) out[fieldNo].push(value);
      else out[fieldNo] = [out[fieldNo], value];
    }
    return out;
  } catch (_) {
    return null;
  }
}

/**
 * Main activation function that installs all network monitoring hooks
 * Coordinates the installation of all hook types and sets up periodic status reporting
 * @returns {void}
 * @throws {Error} When comprehensive hook activation fails
 */
function activateHook() {
  console.log('🛰  Activating COMPREHENSIVE low-level HTTP hooks...');
  console.log('🛰  Target: Capture ALL network traffic in VS Code process');
  
  try {
    installProtobufDecodeHook();
    installNodeHooks();
    installElectronHooks();
    installWebSocketHooks();
    installFetchHooks();
    installHttp2Hooks();
    hookStreamingFetch();
    installChildProcessHooks();
    installVSCodeHooks();
    installXHRHooks();
    
    console.log('🛰  All low-level hooks installed - monitoring ALL network traffic');
    console.log('🛰  Request counter initialized - watching for traffic...');
    
    setInterval(() => {
      if (requestCounter > 0) {
        console.log(`🛰  Total requests captured: ${requestCounter}`);
      }
    }, 30000);
    
  } catch (error) {
    console.log('🛰  Error during comprehensive hook activation:', error.message);
  }
}

module.exports = { activateHook };
