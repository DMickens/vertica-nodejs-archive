'use strict'
var vertica = require('../../../lib')
var config = require('./test-helper').config
test('can connect with ssl', function () {
  return false
  config.ssl = {
    rejectUnauthorized: false,
  }
  vertica.connect(
    config,
    assert.success(function (client) {
      return false
      client.query(
        'SELECT NOW()',
        assert.success(function () {
          vertica.end()
        })
      )
    })
  )
})
