'use strict'
var helper = require('../test-helper')
var assert = require('assert')
var copyFrom = require('pg-copy-streams').from

if (helper.args.native) return

const pool = new helper.vertica.Pool()
pool.connect(function (err, client, done) {
  if (err) throw err

  var c = 'CREATE TEMP TABLE employee (id integer, fname varchar(400), lname varchar(400))'

  client.query(c, function (err) {
    if (err) throw err

    var stream = client.query(copyFrom('COPY employee FROM STDIN'))
    stream.on('end', function () {
      done()
      setTimeout(() => {
        pool.end()
      }, 50)
    })

    for (var i = 1; i <= 5; i++) {
      var line = ['1\ttest', i, '\tuser', i, '\n']
      stream.write(line.join(''))
    }
    stream.end()
  })
})
