'use strict'
var EventEmitter = require('events').EventEmitter

var helper = require('../test-helper')
var Connection = require('../../lib/connection')

global.MemoryStream = function () {
  EventEmitter.call(this)
  this.packets = []
}

helper.sys.inherits(MemoryStream, EventEmitter)

var p = MemoryStream.prototype

p.connect = function () {
  // NOOP
}

p.setNoDelay = () => {}

p.write = function (packet, cb) {
  this.packets.push(packet)
  if (cb) {
    cb()
  }
}

p.end = function () {
  p.closed = true
}

p.setKeepAlive = function () {}
p.closed = false
p.writable = true

const createClient = async function () {
  var stream = new MemoryStream()
  var client = new Client({
    connection: new Connection({ stream: stream }),
  })
  await client.connect()
  return client
}

module.exports = Object.assign({}, helper, {
  createClient: createClient,
})
