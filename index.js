// Greylisting plugin for Haraka

// node builtins
const net = require('net')
const util = require('util')

// Haraka modules
const DSN = require('haraka-dsn')
const tlds = require('haraka-tld')
const net_utils = require('haraka-net-utils')
const { Address } = require('address-rfc2821')

// External NPM modules
const ipaddr = require('ipaddr.js')

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.register = function () {
  this.inherits('haraka-plugin-redis')

  this.load_config()

  this.register_hook('init_master', 'init_redis_plugin')
  this.register_hook('init_child', 'init_redis_plugin')
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.load_config = function () {
  this.cfg = this.config.get(
    'greylist.ini',
    {
      booleans: ['+skip.dnswlorg', '-skip.mailspikewl'],
    },
    () => {
      this.load_config()
    },
  )

  this.merge_redis_ini()
  this.load_config_lists()
}

// Load various configuration lists
exports.load_config_lists = function () {
  this.whitelist = {}
  this.list = {}

  const load_list = (type, file_name) => {
    this.whitelist[type] = {}

    const list = Object.keys(this.cfg[file_name])

    // toLower when loading spends a fraction of a second at load time
    // to save millions of seconds during run time.
    for (const element of list) {
      this.whitelist[type][element.toLowerCase()] = true
    }
    this.logdebug(
      `whitelist {${type}} loaded from ${file_name} with ${list.length} entries`,
    )
  }

  const load_ip_list = (type, file_name) => {
    this.whitelist[type] = []

    const list = Object.keys(this.cfg[file_name])

    for (const element of list) {
      try {
        let addr = element
        if (addr.match(/\/\d+$/)) {
          addr = ipaddr.parseCIDR(addr)
        } else {
          addr = ipaddr.parseCIDR(`${addr}${net.isIPv6(addr) ? '/128' : '/32'}`)
        }

        this.whitelist[type].push(addr)
      } catch (ignore) {}
    }

    this.logdebug(
      `whitelist {${type}} loaded from ${file_name} with ${this.whitelist[type].length} entries`,
    )
  }

  const load_config_list = (type, file_name) => {
    this.list[type] = Object.keys(this.cfg[file_name])

    this.logdebug(
      `list {${type}} loaded from ${file_name} with ${this.list[type].length} entries`,
    )
  }

  load_list('mail', 'envelope_whitelist')
  load_list('rcpt', 'recipient_whitelist')
  load_ip_list('ip', 'ip_whitelist')

  load_config_list('dyndom', 'special_dynamic_domains')
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.shutdown = function () {
  if (this.db) this.db.quit()
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// We check for IP and envelope whitelist
exports.hook_mail = function (next, connection, params) {
  if (!connection.transaction) return next()

  const mail_from = params[0]

  // whitelist checks
  if (this.ip_in_list(connection.remote.ip)) {
    this.loginfo(connection, 'Connecting IP was whitelisted via config')
    connection.transaction.results.add(this, { skip: 'config-whitelist(ip)' })
  } else if (this.addr_in_list('mail', mail_from.address().toLowerCase())) {
    this.loginfo(connection, 'Envelope was whitelisted via config')
    connection.transaction.results.add(this, {
      skip: 'config-whitelist(envelope)',
    })
  } else {
    const why_skip = this.process_skip_rules(connection)

    if (why_skip) {
      this.loginfo(
        connection,
        `Requested to skip the GL because skip rule matched: ${why_skip}`,
      )
      connection.transaction.results.add(this, {
        skip: `requested(${why_skip})`,
      })
    }
  }

  next()
}

//
exports.hook_rcpt_ok = async function (next, connection, rcpt) {
  if (this.should_skip_check(connection)) return next()
  if (this.was_whitelisted_in_session(connection)) {
    this.logdebug(connection, 'host already whitelisted in this session')
    return next()
  }

  const ctr = connection.transaction.results

  // check rcpt in whitelist (email & domain)
  if (this.addr_in_list('rcpt', rcpt.address().toLowerCase())) {
    this.loginfo(connection, 'RCPT was whitelisted via config')
    ctr.add(this, { skip: 'config-whitelist(recipient)' })
    return next()
  }

  try {
    const white_rec = await this.check_and_update_white(connection)

    if (white_rec) {
      this.logdebug(connection, 'host in WHITE zone')
      ctr.add(this, { pass: 'whitelisted' })
      ctr.push(this, { stats: { rcpt: white_rec }, stage: 'rcpt' })
      return next()
    }

    try {
      const white_promo_rec = await this.process_tuple(
        connection,
        connection.transaction.mail_from.address(),
        rcpt.address(),
      )

      if (!white_promo_rec) {
        ctr.add(this, {
          fail: 'greylisted',
          stage: 'rcpt',
        })
        this.invoke_outcome_cb(next, false)
      } else {
        this.loginfo(connection, 'host has been promoted to WHITE zone')
        ctr.add(this, {
          pass: 'whitelisted',
          stats: white_promo_rec,
          stage: 'rcpt',
        })
        ctr.add(this, {
          pass: 'whitelisted',
        })
        this.invoke_outcome_cb(next, true)
      }
    } catch (err2) {
      if (err2 instanceof Error && err2.notanerror) {
        this.logdebug(connection, 'host in GREY zone')

        ctr.add(this, {
          fail: 'greylisted',
        })
        ctr.push(this, {
          stats: {
            rcpt: err2.record,
          },
          stage: 'rcpt',
        })

        return this.invoke_outcome_cb(next, false)
      }

      throw err2
    }
  } catch (err) {
    this.logerror(connection, `Got error: ${util.inspect(err)}`)
    return next(
      DENYSOFT,
      DSN.sec_unspecified(
        'Backend failure. Please, retry later or contact our support.',
      ),
    )
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Main GL engine that accepts tuple and returns matched record or a rejection.
exports.process_tuple = async function (connection, sender, rcpt) {
  const key = this.craft_grey_key(connection, sender, rcpt)
  if (!key) return

  const record = await this.db_lookup(key)

  this.logdebug(connection, `got record: ${util.inspect(record)}`)

  // { created: TS, updated: TS, lifetime: TTL, tried: Integer }
  const now = Date.now() / 1000

  if (
    record &&
    record.created + this.cfg.period.black < now &&
    record.created + record.lifetime >= now
  ) {
    // Host passed greylisting
    return await this.promote_to_white(connection, record)
  }

  const created_record = await this.update_grey(key, !record)
  const err = new Error('in black zone')
  err.record = created_record || record
  err.notanerror = true
  throw err
}

// Checks if host is _white_. Updates stats if so.
exports.check_and_update_white = async function (connection) {
  const key = this.craft_white_key(connection)

  const record = await this.db_lookup(key)

  if (record) {
    if (record.updated + record.lifetime - 2 < Date.now() / 1000) {
      // race "prevention".
      this.logerror(connection, 'Mischief! Race condition triggered.')
      throw new Error('drunkard')
    }

    return await this.update_white_record(key, record)
  }

  return false
}

// invokes next() depending on outcome param
exports.invoke_outcome_cb = function (next, is_whitelisted) {
  if (is_whitelisted) return next()

  next(DENYSOFT, DSN.sec_unauthorized(this.cfg.main.text || '', '451'))
}

// Should we skip greylisting invokation altogether?
exports.should_skip_check = function (connection) {
  if (!connection.transaction) return true

  const ctr = connection.transaction.results

  if (connection.relaying) {
    this.logdebug(connection, 'skipping GL for relaying host')
    ctr.add(this, {
      skip: 'relaying',
    })
    return true
  }

  if (connection.remote?.is_private) {
    connection.logdebug(this, `skipping private IP: ${connection.remote.ip}`)
    ctr.add(this, {
      skip: 'private-ip',
    })
    return true
  }

  if (ctr) {
    if (ctr.has(this, 'skip', /^config-whitelist/)) {
      this.loginfo(connection, 'skipping GL for host whitelisted in config')
      return true
    }
    if (ctr.has(this, 'skip', /^requested/)) {
      this.loginfo(connection, 'skipping GL because was asked to previously')
      return true
    }
  }

  return false
}

// Was whitelisted previously in this session
exports.was_whitelisted_in_session = function (connection) {
  if (!connection?.transaction?.results) return false
  return connection.transaction.results.has(this, 'pass', 'whitelisted')
}

exports.process_skip_rules = function (connection) {
  const cr = connection.results

  const skip_cfg = this.cfg.skip
  if (skip_cfg) {
    if (
      skip_cfg.dnswlorg &&
      cr.has('dnswl.org', 'pass', /^list\.dnswl\.org\([123]\)$/)
    ) {
      return 'dnswl.org(MED)'
    }

    if (
      skip_cfg.mailspikewl &&
      cr.has('dnswl.org', 'pass', /^wl\.mailspike\.net\((1[7-9]|20)\)$/)
    ) {
      return 'mailspike(H2)'
    }
  }

  return ''
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Build greylist DB key (originally, a "tuple") of supplied params.
// When _to_ is false, we craft +sender+ key
// When _to_ is String, we craft +rcpt+ key
exports.craft_grey_key = function (connection, from, to) {
  const crafted_host_id = this.craft_hostid(connection)
  if (!crafted_host_id) return null

  let key = `grey:${crafted_host_id}:${from || '<>'}`
  if (to != undefined) {
    key += `:${to || '<>'}`
  }
  return key
}

// Build white DB key off supplied params.
exports.craft_white_key = function (connection) {
  return `white:${this.craft_hostid(connection)}`
}

// Return so-called +hostid+.
exports.craft_hostid = function (connection) {
  const { transaction, remote } = connection ?? {}
  if (!transaction || !remote) return null

  if (transaction.notes?.greylist?.hostid) {
    return transaction.notes.greylist.hostid // "caching"
  }

  const chsit = (value, reason) => {
    // cache the return value
    if (!value) this.logdebug(connection, `hostid set to IP: ${reason}`)

    transaction.results.add(this, {
      hostid_type: value ? 'domain' : 'ip',
      rdns: value || remote.ip,
      msg: reason,
    }) // !don't move me.

    value = value || remote.ip

    return ((transaction.notes.greylist =
      transaction.notes.greylist || {}).hostid = value)
  }

  // no rDNS . FIXME: use fcrdns results
  if (!remote.host || ['Unknown', 'DNSERROR'].includes(remote.host))
    return chsit(null, 'no rDNS info for this host')

  remote.host = remote.host.replace(/\.$/, '') // strip ending dot, just in case

  const fcrdns = connection.results.get('fcrdns')
  if (!fcrdns) {
    this.logwarn(connection, 'No FcrDNS plugin results, fix this.')
    return chsit(null, 'no FcrDNS plugin results')
  }

  if (!connection.results.has('fcrdns', 'pass', 'fcrdns'))
    // FcrDNS failed
    return chsit(null, 'FcrDNS failed')

  if (connection.results.get('fcrdns').ptr_names.length > 1)
    // multiple PTR returned
    return chsit(null, 'multiple PTR returned')

  if (connection.results.has('fcrdns', 'fail', /^is_generic/))
    // generic/dynamic rDNS record
    return chsit(null, 'rDNS is a generic record')

  if (connection.results.has('fcrdns', 'fail', /^valid_tld/))
    // invalid org domain in rDNS
    return chsit(null, 'invalid org domain in rDNS')

  // strip first label up until the tld boundary.
  const decoupled = tlds.split_hostname(remote.host, 3)
  const vardom = decoupled[0] // "variable" portion of domain
  const dom = decoupled[1] // "static" portion of domain

  // we check for special cases where rdns looks custom/static, but really is dynamic
  const special_case_info = this.check_rdns_for_special_cases(remote.host)
  if (special_case_info) return chsit(null, special_case_info.why)

  let stripped_dom = dom

  if (vardom) {
    // check for decimal IP in rDNS
    if (vardom.match(String(net_utils.ip_to_long(remote.ip))))
      return chsit(null, 'decimal IP')

    // craft the +hostid+
    const label = vardom.split('.').slice(1).join('.')
    if (label) stripped_dom = `${label}.${stripped_dom}`
  }

  return chsit(stripped_dom)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Retrieve _grey_ record
// not implemented
exports.retrieve_grey = async function (rcpt_key, sender_key) {
  const multi = this.db.multi()

  multi.hgetall(rcpt_key)
  multi.hgetall(sender_key)

  try {
    const result = await multi.exec()
    return result
  } catch (err) {
    this.lognotice(`DB error: ${util.inspect(err)}`)
    err.what = 'db_error'
    throw err
  }
}

// Update or create _grey_ record
exports.update_grey = async function (key, create) {
  const multi = this.db.multi()

  const ts_now = Math.round(Date.now() / 1000)
  let new_record

  if (create) {
    const lifetime = this.cfg.period.grey
    new_record = {
      created: ts_now,
      updated: ts_now,
      lifetime,
      tried: 1,
    }

    multi.hmset(key, new_record)
    multi.expire(key, lifetime)
  } else {
    multi.hincrby(key, 'tried', 1)
    multi.hmset(key, {
      updated: ts_now,
    })
  }

  try {
    await multi.exec()
    return create ? new_record : false
  } catch (err) {
    this.lognotice(`DB error: ${util.inspect(err)}`)
    err.what = 'db_error'
    throw err
  }
}

// Promote _grey_ record to _white_.
exports.promote_to_white = async function (connection, grey_rec) {
  const ts_now = Math.round(Date.now() / 1000)
  const white_ttl = this.cfg.period.white

  // { first_connect: TS, whitelisted: TS, updated: TS, lifetime: TTL, tried: Integer, tried_when_greylisted: Integer }
  const white_rec = {
    first_connect: grey_rec.created,
    whitelisted: ts_now,
    updated: ts_now,
    lifetime: white_ttl,
    tried_when_greylisted: grey_rec.tried,
    tried: 1,
  }

  const white_key = this.craft_white_key(connection)
  if (!white_key) return

  try {
    await this.db.hmset(white_key, white_rec)
    const result = await this.db.expire(white_key, white_ttl)
    return result
  } catch (err) {
    this.lognotice(`DB error: ${util.inspect(err)}`)
    err.what = 'db_error'
    throw err
  }
}

// Update _white_ record
exports.update_white_record = async function (key, record) {
  const multi = this.db.multi()
  const ts_now = Math.round(Date.now() / 1000)

  // { first_connect: TS, whitelisted: TS, updated: TS, lifetime: TTL, tried: Integer, tried_when_greylisted: Integer }
  multi.hincrby(key, 'tried', 1)
  multi.hmset(key, {
    updated: ts_now,
  })
  multi.expire(key, record.lifetime)

  try {
    const result = await multi.exec()
    return result
  } catch (err) {
    this.lognotice(`DB error: ${util.inspect(err)}`)
    err.what = 'db_error'
    throw err
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

exports.db_lookup = async function (key) {
  const numVals = [
    'created',
    'updated',
    'lifetime',
    'tried',
    'first_connect',
    'whitelisted',
    'tried_when_greylisted',
  ]

  try {
    const result = await this.db.hgetall(key)

    if (result && typeof result === 'object') {
      // groom known-to-be numeric values
      for (const kk of numVals) {
        if (result[kk] !== undefined) {
          result[kk] = Number(result[kk])
        }
      }
    }
    return result
  } catch (err) {
    this.lognotice(`DB error: ${util.inspect(err)}`, key)
    throw err
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.addr_in_list = function (type, address) {
  if (!this.whitelist[type]) {
    this.logwarn(`List not defined: ${type}`)
    return false
  }

  if (this.whitelist[type][address]) {
    return true
  }

  try {
    const addr = new Address(address)
    return !!this.whitelist[type][addr.host]
  } catch (ignore) {
    return false
  }
}

exports.ip_in_list = function (ip) {
  const ipobj = ipaddr.parse(ip)

  const list = this.whitelist.ip

  for (const element of list) {
    try {
      if (ipobj.match(element)) {
        return true
      }
    } catch (ignore) {}
  }

  return false
}

// Match patterns in the list against (end of) domain
exports.domain_in_list = function (list_name, domain) {
  const list = this.list[list_name]

  if (!list) {
    this.logwarn(`List not defined: ${list_name}`)
    return false
  }

  for (const element of list) {
    if (domain.length - domain.lastIndexOf(element) == element.length)
      return true
  }

  return false
}

// Check for special rDNS cases
// @return {type: 'dynamic'} if rnds is dynamic (hostid should be IP)
exports.check_rdns_for_special_cases = function (domain) {
  // ptr for these is in fact dynamic
  if (this.domain_in_list('dyndom', domain))
    return {
      type: 'dynamic',
      why: 'rDNS considered dynamic: listed in dynamic.domains config list',
    }

  return false
}
