'use strict'

var net = require('net')
var EventEmitter = require('events').EventEmitter

const { parse, serialize } = require('v-protocol')

const flushBuffer = serialize.flush()
const syncBuffer = serialize.sync()
const endBuffer = serialize.end()

// TODO(bmc) support binary mode at some point
class Connection extends EventEmitter {
  constructor(config) {
    super()
    config = config || {}
    this.stream = config.stream || new net.Socket()
    this._keepAlive = config.keepAlive
    this._keepAliveInitialDelayMillis = config.keepAliveInitialDelayMillis
    this.lastBuffer = false
    this.parsedStatements = {}
    this._ending = false
    this._emitMessage = false
    this.statementCounterBuffer = new SharedArrayBuffer(32)
    this.statementCounter = new Int32Array(this.statementCounterBuffer)
    this.statementCounter[0] = 0

    // encryption
    this.tls_mode = config.tls_mode || 'disable'
    this.tls_key_file = config.tls_key_file
    this.tls_cert_file = config.tls_cert_file

    var self = this
    this.on('newListener', function (eventName) {
      if (eventName === 'message') {
        self._emitMessage = true
      }
    })
  }

  connect(port, host) {
    var self = this

    this._connecting = true
    this.stream.setNoDelay(true)
    this.stream.connect(port, host)

    this.stream.once('connect', function () {
      if (self._keepAlive) {
        self.stream.setKeepAlive(true, self._keepAliveInitialDelayMillis)
      }
      self.emit('connect')
    })

    const reportStreamError = function (error) {
      // errors about disconnections should be ignored during disconnect
      if (self._ending && (error.code === 'ECONNRESET' || error.code === 'EPIPE')) {
        return
      }
      self.emit('error', error)
    }
    this.stream.on('error', reportStreamError)

    this.stream.on('close', function () {
      self.emit('end')
    })

    if (this.tls_mode === 'disable') {
      return this.attachListeners(this.stream)
    }

    this.stream.once('data', function (buffer) {
      var responseCode = buffer.toString('utf8')
      switch (responseCode) {
        case 'S': // Server supports TLS connections, continue with a secure connection
          break
        case 'N': // Server does not support TLS connections
          self.stream.end()
          return self.emit('error', new Error('The server does not support TLS connections'))
        default:
          // Any other response byte, including 'E' (ErrorResponse) indicating a server error
          self.stream.end()
          return self.emit('error', new Error('There was an error establishing a TLS connection'))
      }
      // tls_mode LOGIC
      var tls = require('tls')

      // assume mutual mode is on. If it isn't, then it doesn't matter whether or not the client 
      // key and certificate chain are still undefined. For the client, this means provide the tls_key_file
      // Also, terminology conflicts between vertica documentation and the node tls package may make this 
      // seem confusing. checkServerIdentity is the function equivalent to the hostname verifier.
      // With an undefined checkServerIdentity function, we are still checking to see that the server
      // certificate is signed by the CA (default or provided).

      if (self.tls_mode === 'require') { // basic TLS connection, does not verify CA certificate
        try {

          self.stream = tls.connect({socket: self.stream, 
                                     rejectUnauthorized: false,
                                     pfx: tls_key_file,
                                     checkServerIdentity: (host, cert) => undefined}) 
        }
        catch (err) {
          return self.emit('error', err)
        }
      }
      else if (self.tls_mode === 'verify-ca') { //verify that the server certificate is signed by a trusted CA
        try {
          self.stream = tls.connect({socket: self.stream,
                                     rejectUnauthorized: true, 
                                     pfx: tls_key_file,
                                     ca: fs.readFileSync(self.tls_cert_file).toString(),
                                     checkServerIdentity: (host, cert) => undefined})
        }
        catch (err) {
          return self.emit('error')
        }
      }
      else if (self.tls_mode === 'verify-full') { //verify that the name on the CA-signed server certificate matches it's hostname
          self.stream = tls.connect({socket: self.stream,
                                     rejectUnauthorized: true, 
                                     pfx: tls_key_file,
                                     ca: fs.readFileSync(self.tls_cert_file).toString()})
      }
      else {
        console.log("Made it here");
        self.emit('error', 'Invalid TLS mode has been entered');
      }
      /*if (self.ssl !== true) {
        Object.assign(options, self.ssl)

        if ('key' in self.ssl) {
          options.key = self.ssl.key
        }
      }

      if (net.isIP(host) === 0) { // we may need to include this in verify-full
        options.servername = host
      }
      try {
        self.stream = tls.connect(options)
      } catch (err) {
        return self.emit('error', err)
      }*/
      self.attachListeners(self.stream)
      self.stream.on('error', reportStreamError)

      self.emit('sslconnect')
    })
  }

  attachListeners(stream) {
    stream.on('end', () => {
      this.emit('end')
    })
    parse(stream, (msg) => {
      var eventName = msg.name === 'error' ? 'errorMessage' : msg.name
      if (this._emitMessage) {
        this.emit('message', msg)
      }
      this.emit(eventName, msg)
    })
  }

  requestSsl() {
    this.stream.write(serialize.requestSsl())
  }

  startup(config) {
    this.stream.write(serialize.startup(config))
  }

  cancel(processID, secretKey) {
    this._send(serialize.cancel(processID, secretKey))
  }

  password(password) {
    this._send(serialize.password(password))
  }

  sendSASLInitialResponseMessage(mechanism, initialResponse) {
    this._send(serialize.sendSASLInitialResponseMessage(mechanism, initialResponse))
  }

  sendSCRAMClientFinalMessage(additionalData) {
    this._send(serialize.sendSCRAMClientFinalMessage(additionalData))
  }

  _send(buffer) {
    if (!this.stream.writable) {
      return false
    }
    return this.stream.write(buffer)
  }

  query(text) {
    this._send(serialize.query(text))
  }

  // send parse message
  parse(query) {
    this._send(serialize.parse(query))
  }

  // send bind message
  bind(config) {
    this._send(serialize.bind(config))
  }

  // send execute message
  execute(config) {
    this._send(serialize.execute(config))
  }

  flush() {
    if (this.stream.writable) {
      this.stream.write(flushBuffer)
    }
  }

  sync() {
    this._ending = true
    this._send(flushBuffer)
    this._send(syncBuffer)
  }

  ref() {
    this.stream.ref()
  }

  unref() {
    this.stream.unref()
  }

  end() {
    // 0x58 = 'X'
    this._ending = true
    if (!this._connecting || !this.stream.writable) {
      this.stream.end()
      return
    }
    return this.stream.write(endBuffer, () => {
      this.stream.end()
    })
  }

  close(msg) {
    this._send(serialize.close(msg))
  }

  describe(msg) {
    this._send(serialize.describe(msg))
  }

  sendCopyFromChunk(chunk) {
    this._send(serialize.copyData(chunk))
  }

  endCopyFrom() {
    this._send(serialize.copyDone())
  }

  sendCopyFail(msg) {
    this._send(serialize.copyFail(msg))
  }

  makeStatementName() {
    return "s" + Atomics.add(this.statementCounter, 0, 1)
  }
}

module.exports = Connection
