'use strict'
const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')

const path = require('path')
const fixtures = require('haraka-test-fixtures')
const ipaddr = require('ipaddr.js')

const _set_up = (t, done) => {
  this.plugin = new fixtures.plugin('greylist')
  this.plugin.config.root_path = path.resolve(__dirname, '../../config')

  this.plugin.register()
  this.plugin.whitelist = {
    mail: { 'josef@example.com': true },
    rcpt: { 'josef@example.net': true },
    ip: [
      ipaddr.parseCIDR('123.123.123.234/32'),
      ipaddr.parseCIDR('2a02:8204:d600:8060:7920:4040:20ee:9680/128'),
      ipaddr.parseCIDR('123.210.123.234/27'),
      ipaddr.parseCIDR('2a02:8204:d600:8060:7920:eeee::/96'),
    ],
  }
  this.plugin.list = { dyndom: ['sgvps.net'] }

  this.connection = fixtures.connection.createConnection()
  this.connection.init_transaction()

  done()
}

describe('greylist', () => {
  beforeEach(_set_up)

  it('inlist: mail(1)', () => {
    assert.ok(this.plugin.addr_in_list('mail', 'josef@example.com'))
  })

  it('inlist: rcpt(1)', () => {
    assert.ok(this.plugin.addr_in_list('rcpt', 'josef@example.net'))
  })

  it('inlist: dyndom(1)', () => {
    assert.ok(this.plugin.domain_in_list('dyndom', 'sgvps.net'))
  })

  it('inlist: ip(4)', () => {
    assert.ok(this.plugin.ip_in_list('123.123.123.234'))
    assert.ok(this.plugin.ip_in_list('123.210.123.234'))
    assert.ok(this.plugin.ip_in_list('2a02:8204:d600:8060:7920:4040:20ee:9680'))
    assert.ok(this.plugin.ip_in_list('2a02:8204:d600:8060:7920:eeee::ff00'))
  })

  describe('craft_hostid', () => {
    it('should handle valid hostname strings without errors', () => {
      this.connection.remote.host = 'mail.example.com'
      this.connection.remote.ip = '1.2.3.4'
      this.connection.results.add({ name: 'fcrdns' }, { pass: 'fcrdns' })
      this.connection.results.add({ name: 'fcrdns' }, {
        ptr_names: ['mail.example.com'],
      })

      // This should not throw TypeError
      const result = this.plugin.craft_hostid(this.connection)
      assert.ok(result !== null)
    })
  })

  describe('check_rdns_for_special_cases', () => {
    it('should handle domain strings without errors', () => {
      // This should not throw TypeError: domain.lastIndexOf is not a function
      const result = this.plugin.check_rdns_for_special_cases(
        'test.sgvps.net',
        'test',
      )
      assert.ok(result)
      assert.equal(result.type, 'dynamic')
    })

    it('should return false for non-dynamic domains', () => {
      const result = this.plugin.check_rdns_for_special_cases(
        'mail.example.com',
        'mail',
      )
      assert.equal(result, false)
    })
  })

  describe('domain_in_list', () => {
    it('should handle string domains without errors', () => {
      // This should not throw TypeError: domain.lastIndexOf is not a function
      const result = this.plugin.domain_in_list('dyndom', 'test.sgvps.net')
      assert.ok(result)
    })

    it('should match domain suffix correctly', () => {
      assert.ok(this.plugin.domain_in_list('dyndom', 'sgvps.net'))
      assert.ok(this.plugin.domain_in_list('dyndom', 'mail.sgvps.net'))
      assert.ok(this.plugin.domain_in_list('dyndom', 'test.mail.sgvps.net'))
      assert.ok(!this.plugin.domain_in_list('dyndom', 'example.com'))
    })
  })
})
