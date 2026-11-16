// Network adapter for hosted Node service processes, part of sealed: sealed
// loads it with `node --import` into every Node service process.
//
// A service process has no network of its own: sealed's confinement allows
// only AF_UNIX sockets. Public APIs are reached only through sealed's egress
// proxy (HTTP CONNECT on the Unix socket $SEAL_EGRESS_SOCKET, to the
// manifest's hosts only) and the model only through sealed's model proxy
// (plain HTTP on the Unix socket $SEAL_MODEL_SOCKET, addressed as host
// `seal-model`). This module sends every TCP connection made through node:net
// and node:tls to those sockets, so fetch, node:http/https, http2 and the
// clients built on them (axios, got, ws, database drivers, ...) work
// unchanged. Host names are resolved by the proxy, not here. It is not a
// security boundary: whatever a program does, the kernel lets it open nothing
// but Unix sockets.
import net from 'node:net'
import tls from 'node:tls'
import { Duplex } from 'node:stream'
import { syncBuiltinESMExports } from 'node:module'

const MODEL_HOST = 'seal-model'
const MAX_HEAD = 8192
const egress = process.env.SEAL_EGRESS_SOCKET
const model = process.env.SEAL_MODEL_SOCKET
const socketConnect = net.Socket.prototype.connect
const tlsConnect = tls.connect

const routeError = (message, code = 'ESEALNOROUTE') => Object.assign(new Error(message), { code })
const hostOf = options => String(options.host || 'localhost').replace(/^\[(.*)\]$/, '$1')
// A TCP connect names a port and no path (http.Agent passes path: null).
const isTCP = options => options.path == null && options.port != null

// refuse fails a connect the way a refused TCP connect fails: asynchronously,
// with 'error' and then 'close'.
function refuse(socket, error) {
  process.nextTick(() => socket.destroy(error))
  return socket
}

// tunnel asks the egress proxy, on a socket already connecting to it, for a
// CONNECT tunnel to host:port, and keeps the proxy's answer out of the
// stream: what the caller reads starts with the first byte from host:port.
// The caller's own writes follow the CONNECT request and the proxy forwards
// them once the tunnel is open; a refusal destroys the socket with the
// proxy's status.
function tunnel(socket, host, port) {
  const authority = `${host.includes(':') ? `[${host}]` : host}:${port}`
  socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
  let head = Buffer.alloc(0)
  const fail = message => {
    delete socket.push
    socket.destroy(routeError(message, 'ESEALEGRESS'))
    return false
  }
  // Node hands every chunk it reads to push(); until the answer is complete
  // the chunks are the proxy's, not the caller's.
  socket.push = function push(chunk, encoding) {
    if (chunk === null) return fail('Egress proxy closed the connection')
    head = Buffer.concat([head, typeof chunk === 'string' ? Buffer.from(chunk, encoding) : chunk])
    const end = head.indexOf('\r\n\r\n')
    if (end < 0) return head.length > MAX_HEAD ? fail('Egress proxy response head too long') : true
    const status = head.subarray(0, head.indexOf('\r\n')).toString('latin1').split(' ')[1]
    if (status !== '200') return fail(`Egress proxy refused ${authority} (HTTP ${status})`)
    delete socket.push
    const rest = head.subarray(end + 4)
    return rest.length ? socket.push(rest) : true
  }
}

net.Socket.prototype.connect = function connect(...args) {
  // net.connect passes its already normalized [options, callback].
  const [options, callback] = Array.isArray(args[0]) ? args[0] : net._normalizeArgs(args)
  if (!isTCP(options) || this instanceof tls.TLSSocket) return socketConnect.apply(this, args)
  const host = hostOf(options)
  if (host === MODEL_HOST) {
    if (!model) return refuse(this, routeError('No model route for this service program'))
    return socketConnect.call(this, { path: model }, callback)
  }
  if (!egress) return refuse(this, routeError('No network route for this service program'))
  socketConnect.call(this, { path: egress }, callback)
  tunnel(this, host, options.port)
  return this
}

// TLS runs over a JS stream on the tunnelled socket: wrapping the socket's
// own handle would hand the proxy's answer to the TLS engine.
tls.connect = function connect(...args) {
  const [normalized, callback] = net._normalizeArgs(args)
  const extra = [args[1], args[2]].find(a => a !== null && typeof a === 'object')
  const options = { ...normalized, ...extra }
  if (options.socket || !isTCP(options)) return tlsConnect.apply(this, args)
  const host = hostOf(options)
  const raw = new net.Socket()
  if (host === MODEL_HOST) refuse(raw, routeError('The model route speaks plain HTTP'))
  else raw.connect({ host, port: options.port })
  const socket = tlsConnect.call(this, { ...options, host, socket: Duplex.from({ readable: raw, writable: raw }) }, callback)
  // An idle keep-alive connection must not hold the process open: the TLS
  // socket's ref state applies to the Unix socket underneath.
  const { ref, unref } = socket
  socket.ref = function () { raw.ref(); return ref.call(this) }
  socket.unref = function () { raw.unref(); return unref.call(this) }
  return socket
}

syncBuiltinESMExports()
if (model) process.env.SEAL_MODEL_URL = `http://${MODEL_HOST}/model`
