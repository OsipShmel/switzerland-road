'use strict'

const { AsyncLocalStorage } = require('node:async_hooks')
const crypto = require('node:crypto')
const http = require('node:http')
const Module = require('node:module')

const storage = new AsyncLocalStorage()
const traces = new Map()
const traceHeader = 'x-vls-trace-id'
const tracePath = /^\/_vls\/trace\/([a-f0-9]{32})$/

function createTrace (traceId) {
  if (traces.has(traceId)) {
    return traces.get(traceId)
  }
  if (traces.size >= 256) {
    traces.delete(traces.keys().next().value)
  }
  const trace = { traceId, events: [] }
  traces.set(traceId, trace)
  return trace
}

function recordSink (sink, cwe) {
  const request = storage.getStore()
  if (request == null) return
  const trace = traces.get(request.traceId) ?? createTrace(request.traceId)
  if (trace.events.length >= 10000) return
  trace.events.push({
    sink,
    cwe,
    method: request.method,
    url: request.url,
    inputs: requestInputHashes(request.request),
    stack: new Error(`vls runtime sink: ${sink}`).stack ?? ''
  })
}

function valueHash (value) {
  const normalized = typeof value === 'string' ? value : JSON.stringify(value)
  return crypto.createHash('sha256').update(normalized ?? '').digest('hex')
}

function objectHashes (value) {
  if (value == null || typeof value !== 'object') return {}
  return Object.fromEntries(
    Object.entries(value).map(([name, item]) => [name, valueHash(item)])
  )
}

function requestInputHashes (request) {
  // значения заменяются хешами до сохранения
  const query = Object.fromEntries(new URL(request.url, 'http://vls').searchParams)
  return {
    query: objectHashes(request.query ?? query),
    path: objectHashes(request.params),
    body: objectHashes(request.body),
    header: objectHashes(request.headers),
    cookie: objectHashes(request.cookies)
  }
}

// трасса привязывается только к запросам с уникальным заголовком
const originalEmit = http.Server.prototype.emit
http.Server.prototype.emit = function (event, request, response, ...args) {
  if (event !== 'request') {
    return originalEmit.call(this, event, request, response, ...args)
  }
  const path = String(request.url ?? '').split('?', 1)[0]
  const traceMatch = tracePath.exec(path)
  if (traceMatch != null) {
    const trace = traces.get(traceMatch[1]) ?? { traceId: traceMatch[1], events: [] }
    traces.delete(traceMatch[1])
    response.statusCode = 200
    response.setHeader('content-type', 'application/json')
    response.end(JSON.stringify(trace))
    return true
  }

  const traceId = String(request.headers?.[traceHeader] ?? '')
  if (!/^[a-f0-9]{32}$/.test(traceId)) {
    return originalEmit.call(this, event, request, response, ...args)
  }
  createTrace(traceId)
  return storage.run(
    { traceId, method: request.method, url: request.url, request },
    () => originalEmit.call(this, event, request, response, ...args)
  )
}

function patchMethod (target, name, sink, cwe) {
  if (target == null || typeof target[name] !== 'function') return
  const original = target[name]
  if (original.__vlsPatched === true) return
  function tracedMethod (...args) {
    recordSink(sink, cwe)
    return original.apply(this, args)
  }
  tracedMethod.__vlsPatched = true
  target[name] = tracedMethod
}

function patchModule (request, loaded) {
  if (request === 'sequelize') {
    const Sequelize = loaded?.Sequelize ?? loaded
    patchMethod(Sequelize?.prototype, 'query', 'sequelize.query', 89)
  }
  if (request === 'express') {
    patchMethod(loaded?.response, 'sendFile', 'express.sendFile', 22)
    patchMethod(loaded?.response, 'redirect', 'express.redirect', 601)
  }
  if (request === 'node:child_process' || request === 'child_process') {
    patchMethod(loaded, 'exec', 'child_process.exec', 78)
    patchMethod(loaded, 'execFile', 'child_process.execFile', 78)
    patchMethod(loaded, 'spawn', 'child_process.spawn', 78)
  }
}

// модули патчатся до загрузки приложения
const originalLoad = Module._load
Module._load = function (request, parent, isMain) {
  const loaded = originalLoad.call(this, request, parent, isMain)
  patchModule(request, loaded)
  return loaded
}
