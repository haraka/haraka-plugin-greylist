'use strict'

const assert = require('node:assert/strict')
const path = require('node:path')
const { beforeEach, describe, it } = require('node:test')

const fixtures = require('haraka-test-fixtures')
const constants = require('haraka-constants')
const tlds = require('haraka-tld')
const ipaddr = require('ipaddr.js')

// ---- in-memory redis double --------------------------------------------
// Mirrors the promise-returning subset of node-redis the plugin uses:
// hgetall/hmset/expire/hincrby plus multi().exec(). `failNext` forces the
// next awaited op to reject so error/catch branches are reachable.
const makeDb = () => {
  const store = new Map()
  const guard = (db, value) => {
    if (db.failNext) {
      db.failNext = false
      return Promise.reject(new Error('redis down'))
    }
    return Promise.resolve(value)
  }
  const db = {
    failNext: false,
    store,
    hgetall: (k) => guard(db, store.has(k) ? { ...store.get(k) } : null),
    hmset: (k, obj) => {
      store.set(k, { ...(store.get(k) || {}), ...obj })
      return guard(db, 'OK')
    },
    expire: (k, ttl) => guard(db, 1 + ttl * 0),
    hincrby: (k, f, n) => {
      const h = store.get(k) || {}
      h[f] = Number(h[f] || 0) + n
      store.set(k, h)
      return guard(db, h[f])
    },
    quit: () => {},
    multi() {
      const ops = []
      const m = {
        hgetall: (k) => (ops.push(() => db.hgetall(k)), m),
        hmset: (k, o) => (ops.push(() => db.hmset(k, o)), m),
        expire: (k, t) => (ops.push(() => db.expire(k, t)), m),
        hincrby: (k, f, n) => (ops.push(() => db.hincrby(k, f, n)), m),
        exec: () =>
          db.failNext
            ? ((db.failNext = false), Promise.reject(new Error('redis down')))
            : Promise.all(ops.map((fn) => fn())),
      }
      return m
    },
  }
  return db
}

// connection with rDNS that craft_hostid resolves to a domain hostid
const makeConn = ({
  ip = '1.2.3.4',
  host = 'mail.example.com',
  relaying = false,
  is_private = false,
} = {}) => {
  const c = fixtures.connection.createConnection()
  c.init_transaction()
  c.relaying = relaying
  c.remote.ip = ip
  c.remote.host = host
  c.remote.is_private = is_private
  c.results.add({ name: 'fcrdns' }, { pass: 'fcrdns' })
  c.results.add({ name: 'fcrdns' }, { ptr_names: [host] })
  c.transaction.mail_from = { address: 'sender@remote.example' }
  return c
}

const _set_up = async () => {
  await tlds.ready // haraka-tld loads its PSL asynchronously

  this.plugin = new fixtures.plugin('greylist')
  this.plugin.config.root_path = path.resolve(__dirname, '../../config')
  this.plugin.register()
  this.plugin.db = makeDb()

  this.plugin.whitelist = {
    mail: { 'josef@example.com': true, 'example.org': true },
    rcpt: { 'josef@example.net': true },
    ip: [
      ipaddr.parseCIDR('123.123.123.234/32'),
      ipaddr.parseCIDR('2a02:8204:d600:8060:7920:4040:20ee:9680/128'),
      ipaddr.parseCIDR('123.210.123.234/27'),
      ipaddr.parseCIDR('2a02:8204:d600:8060:7920:eeee::/96'),
    ],
  }
  this.plugin.list = { dyndom: ['sgvps.net'] }
}

describe('greylist', () => {
  beforeEach(_set_up)

  describe('list membership', () => {
    it('addr_in_list matches exact envelope/rcpt entries', () => {
      assert.ok(this.plugin.addr_in_list('mail', 'josef@example.com'))
      assert.ok(this.plugin.addr_in_list('rcpt', 'josef@example.net'))
    })

    it('addr_in_list falls back to the domain part', () => {
      assert.ok(this.plugin.addr_in_list('mail', 'anyone@example.org'))
    })

    it('addr_in_list is false for unknown / undefined list', () => {
      assert.equal(this.plugin.addr_in_list('mail', 'nope@nowhere.com'), false)
      assert.equal(this.plugin.addr_in_list('bogus', 'a@b.com'), false)
    })

    it('ip_in_list matches singles and CIDR ranges', () => {
      assert.ok(this.plugin.ip_in_list('123.123.123.234'))
      assert.ok(this.plugin.ip_in_list('123.210.123.234'))
      assert.ok(
        this.plugin.ip_in_list('2a02:8204:d600:8060:7920:4040:20ee:9680'),
      )
      assert.ok(this.plugin.ip_in_list('2a02:8204:d600:8060:7920:eeee::ff00'))
      assert.equal(this.plugin.ip_in_list('8.8.8.8'), false)
    })

    it('domain_in_list matches suffixes only', () => {
      assert.ok(this.plugin.domain_in_list('dyndom', 'sgvps.net'))
      assert.ok(this.plugin.domain_in_list('dyndom', 'test.mail.sgvps.net'))
      assert.equal(this.plugin.domain_in_list('dyndom', 'example.com'), false)
      assert.equal(this.plugin.domain_in_list('missing', 'x.com'), false)
    })

    it('check_rdns_for_special_cases flags dynamic domains', () => {
      const r = this.plugin.check_rdns_for_special_cases('test.sgvps.net')
      assert.equal(r.type, 'dynamic')
      assert.equal(
        this.plugin.check_rdns_for_special_cases('mail.x.com'),
        false,
      )
    })
  })

  describe('key crafting', () => {
    it('craft_hostid returns the static domain for good rDNS', () => {
      assert.equal(this.plugin.craft_hostid(makeConn()), 'example.com')
    })

    it('craft_hostid falls back to IP without FcrDNS pass', () => {
      const c = fixtures.connection.createConnection()
      c.init_transaction()
      c.remote.ip = '9.9.9.9'
      c.remote.host = 'mail.example.com'
      assert.equal(this.plugin.craft_hostid(c), '9.9.9.9')
    })

    it('craft_hostid is null without transaction/remote', () => {
      assert.equal(this.plugin.craft_hostid({}), null)
    })

    it('craft_grey_key / craft_white_key embed the hostid', () => {
      const c = makeConn()
      assert.equal(
        this.plugin.craft_grey_key(c, 'a@b.com', 'c@d.com'),
        'grey:example.com:a@b.com:c@d.com',
      )
      assert.equal(this.plugin.craft_grey_key(c, false), 'grey:example.com:<>')
      assert.equal(this.plugin.craft_white_key(c), 'white:example.com')
    })
  })

  describe('skip logic', () => {
    it('should_skip_check: true with no transaction', () => {
      assert.equal(this.plugin.should_skip_check({}), true)
    })

    it('should_skip_check: relaying and private IP skip', () => {
      assert.equal(
        this.plugin.should_skip_check(makeConn({ relaying: true })),
        true,
      )
      assert.equal(
        this.plugin.should_skip_check(makeConn({ is_private: true })),
        true,
      )
    })

    it('should_skip_check: honors config-whitelist / requested marks', () => {
      const c = makeConn()
      c.transaction.results.add(this.plugin, { skip: 'config-whitelist(ip)' })
      assert.equal(this.plugin.should_skip_check(c), true)

      const c2 = makeConn()
      c2.transaction.results.add(this.plugin, { skip: 'requested(dnswl)' })
      assert.equal(this.plugin.should_skip_check(c2), true)
    })

    it('should_skip_check: false for an ordinary host', () => {
      assert.equal(this.plugin.should_skip_check(makeConn()), false)
    })

    it('process_skip_rules matches dnswl.org and mailspike', () => {
      const c = makeConn()
      c.results.add({ name: 'dnswl.org' }, { pass: 'list.dnswl.org(1)' })
      assert.equal(this.plugin.process_skip_rules(c), 'dnswl.org(MED)')

      const c2 = makeConn()
      c2.results.add({ name: 'dnswl.org' }, { pass: 'wl.mailspike.net(18)' })
      assert.equal(this.plugin.process_skip_rules(c2), 'mailspike(H2)')

      assert.equal(this.plugin.process_skip_rules(makeConn()), '')
    })

    it('was_whitelisted_in_session reflects a prior pass', () => {
      const c = makeConn()
      assert.equal(this.plugin.was_whitelisted_in_session(c), false)
      c.transaction.results.add(this.plugin, { pass: 'whitelisted' })
      assert.equal(this.plugin.was_whitelisted_in_session(c), true)
    })
  })

  describe('hook_mail', () => {
    const run = (conn, from) =>
      new Promise((res) =>
        this.plugin.hook_mail((...a) => res(a), conn, [{ address: from }]),
      )

    it('whitelists a configured IP', async () => {
      const c = makeConn({ ip: '123.123.123.234' })
      assert.deepEqual(await run(c, 'x@y.com'), [])
      assert.ok(c.transaction.results.has(this.plugin, 'skip', /ip/))
    })

    it('whitelists a configured envelope', async () => {
      const c = makeConn()
      await run(c, 'josef@example.com')
      assert.ok(c.transaction.results.has(this.plugin, 'skip', /envelope/))
    })

    it('records a requested skip when a skip rule matches', async () => {
      const c = makeConn()
      c.results.add({ name: 'dnswl.org' }, { pass: 'list.dnswl.org(1)' })
      await run(c, 'x@y.com')
      assert.ok(c.transaction.results.has(this.plugin, 'skip', /requested/))
    })

    it('passes through with no whitelist match', async () => {
      const c = makeConn()
      assert.deepEqual(await run(c, 'x@y.com'), [])
      assert.equal(c.transaction.results.has(this.plugin, 'skip', /./), false)
    })

    it('calls next() with no transaction', async () => {
      assert.deepEqual(await run({}, 'x@y.com'), [])
    })
  })

  describe('invoke_outcome_cb', () => {
    it('whitelisted -> bare next()', () => {
      let args = 'unset'
      this.plugin.invoke_outcome_cb((...a) => (args = a), true)
      assert.deepEqual(args, [])
    })

    it('not whitelisted -> DENYSOFT with config text', () => {
      let args
      this.plugin.invoke_outcome_cb((...a) => (args = a), false)
      assert.equal(args[0], constants.DENYSOFT)
      assert.ok(args[1])
    })
  })

  describe('redis-backed helpers', () => {
    it('db_lookup grooms numeric fields', async () => {
      this.plugin.db.store.set('k', { created: '100', tried: '3', x: 'str' })
      const rec = await this.plugin.db_lookup('k')
      assert.equal(rec.created, 100)
      assert.equal(rec.tried, 3)
      assert.equal(rec.x, 'str')
    })

    it('db_lookup rethrows redis errors', async () => {
      this.plugin.db.failNext = true
      await assert.rejects(() => this.plugin.db_lookup('k'), /redis down/)
    })

    it('update_grey creates a record and returns it', async () => {
      const rec = await this.plugin.update_grey('grey:1', true)
      assert.equal(rec.tried, 1)
      assert.equal(rec.lifetime, this.plugin.cfg.period.grey)
      assert.ok(this.plugin.db.store.has('grey:1'))
    })

    it('update_grey on existing record returns false & bumps tried', async () => {
      this.plugin.db.store.set('grey:2', { tried: '1' })
      assert.equal(await this.plugin.update_grey('grey:2', false), false)
      assert.equal(this.plugin.db.store.get('grey:2').tried, 2)
    })

    it('promote_to_white writes a white record', async () => {
      const c = makeConn()
      const res = await this.plugin.promote_to_white(c, {
        created: 1,
        tried: 4,
      })
      assert.equal(res, 1)
      assert.ok(this.plugin.db.store.has('white:example.com'))
    })

    it('check_and_update_white: false when no record', async () => {
      assert.equal(await this.plugin.check_and_update_white(makeConn()), false)
    })

    it('check_and_update_white: race condition throws', async () => {
      this.plugin.db.store.set('white:example.com', {
        updated: '1',
        lifetime: '1',
      })
      await assert.rejects(
        () => this.plugin.check_and_update_white(makeConn()),
        /drunkard/,
      )
    })

    it('check_and_update_white: fresh record is updated', async () => {
      const now = Math.round(Date.now() / 1000)
      this.plugin.db.store.set('white:example.com', {
        updated: String(now),
        lifetime: '3024000',
      })
      const res = await this.plugin.check_and_update_white(makeConn())
      assert.ok(Array.isArray(res))
    })
  })

  describe('process_tuple', () => {
    it('returns undefined without a hostid', async () => {
      assert.equal(
        await this.plugin.process_tuple({}, 's@a.com', 'r@b.com'),
        undefined,
      )
    })

    it('greylists a never-seen tuple (throws notanerror)', async () => {
      await assert.rejects(
        () => this.plugin.process_tuple(makeConn(), 's@a.com', 'r@b.com'),
        (e) => e.notanerror === true && e.record.tried === 1,
      )
    })

    it('promotes a tuple that survived the black period', async () => {
      const c = makeConn()
      const key = this.plugin.craft_grey_key(c, 's@a.com', 'r@b.com')
      const created = Math.round(Date.now() / 1000) - 1000 // > black (850)
      this.plugin.db.store.set(key, {
        created: String(created),
        lifetime: '90000',
      })
      const res = await this.plugin.process_tuple(c, 's@a.com', 'r@b.com')
      assert.equal(res, 1) // promote_to_white -> expire()
    })
  })

  describe('hook_rcpt_ok', () => {
    const run = (conn, rcpt = 'rcpt@dest.example') =>
      new Promise((res) =>
        this.plugin.hook_rcpt_ok((...a) => res(a), conn, { address: rcpt }),
      )

    it('skips when should_skip_check is true', async () => {
      assert.deepEqual(await run(makeConn({ relaying: true })), [])
    })

    it('passes a config-whitelisted recipient', async () => {
      const c = makeConn()
      assert.deepEqual(await run(c, 'josef@example.net'), [])
      assert.ok(c.transaction.results.has(this.plugin, 'skip', /recipient/))
    })

    it('greylists a new sender (DENYSOFT)', async () => {
      const args = await run(makeConn())
      assert.equal(args[0], constants.DENYSOFT)
    })

    it('lets a pre-whitelisted host straight through', async () => {
      const c = makeConn()
      const now = Math.round(Date.now() / 1000)
      this.plugin.db.store.set('white:example.com', {
        updated: String(now),
        lifetime: '3024000',
      })
      assert.deepEqual(await run(c), [])
      assert.ok(c.transaction.results.has(this.plugin, 'pass', 'whitelisted'))
    })

    it('promotes a tuple past the black period', async () => {
      const c = makeConn()
      const key = this.plugin.craft_grey_key(
        c,
        c.transaction.mail_from.address,
        'rcpt@dest.example',
      )
      const created = Math.round(Date.now() / 1000) - 1000
      this.plugin.db.store.set(key, {
        created: String(created),
        lifetime: '90000',
      })
      assert.deepEqual(await run(c), [])
    })

    it('DENYSOFTs on backend failure', async () => {
      const c = makeConn()
      this.plugin.db.failNext = true
      const args = await run(c)
      assert.equal(args[0], constants.DENYSOFT)
    })
  })
})
