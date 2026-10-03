/*
 * ═══════════════════════════════════════════════════════════════
 *  Rubii 每日签到 · Loon 脚本
 *
 *  服务端【强制校验】HMAC-SHA256 签名（实测：无签名 → 400
 *  request_signature_invalid，伪造签名 → 403 同错），所以必须
 *  用服务端下发的 secret 自行计算签名。
 *
 *  secret 不硬编码在 App 里，由 /auth/ 登录响应下发，本脚本的
 *  响应脚本负责抓取。
 *
 *  签名的消息格式（canonical 串）未公开，且 App 内不存在 \n
 *  常量（69 万个字符串常量里 0 个含换行），因此采用「样本反推」：
 *    1) 请求脚本保存真实请求样本（method/path/query/body/ts/nonce/signature）
 *    2) 用 secret 逐个计算候选格式，本地比对样本签名
 *    3) 比中即锁定格式并记住，之后每次签到都用它
 *  整个反推过程全在本机完成，不需要把 secret 交出去。
 *
 *  接口：POST https://api2.rubii.ai/v1/tasks/daily_ruby/complete
 * ═══════════════════════════════════════════════════════════════
 */

var USER_CONFIG = {
  authorization: '',   // 可手填 "Bearer eyJ..." 或 eyJ...
  refreshToken: '',
  secret: ''            // 可手填；留空则用自动抓到的
};

var CONF = {
  host:        'https://api2.rubii.ai',
  checkinPath: '/v1/tasks/daily_ruby/complete',
  appId:       'rubii-app',
  keyId:       'static-v1',
  ua:          'Dart/3.10 (dart:io)',
  lang:        'zh-cn'
};

var STORE = {
  jwt:   'Rubii_JWT',
  rt:    'Rubii_RefreshToken',
  sec:   'Rubii_Secret',
  kid:   'Rubii_KeyId',
  fmt:   'Rubii_SignFormat',
  smp:   'Rubii_Samples',
  last:  'Rubii_LastResult'
};


// ═══════════════════════════════════════════════════════════════
//  入口分流
//  注意：main() 在文件【末尾】调用。SEPS / ORDERS / BODYVARS / K256
//  这些常量的赋值必须先于 main() 执行，否则反推逻辑会读到
//  undefined（JS 只提升声明、不提升赋值）。
// ═══════════════════════════════════════════════════════════════
function main() {
  var arg = (typeof $argument !== 'undefined' && $argument) ? String($argument) : '';

  if (arg.indexOf('capture=response') >= 0) return captureResponse();
  if (arg.indexOf('diag') >= 0) return runDiag();
  if (typeof $response !== 'undefined' && $response) return captureResponse();
  if (typeof $request !== 'undefined' && $request && $request.headers) return captureRequest();
  return runCheckin();
}


// ═══════════════════════════════════════════════════════════════
//  模式 1：抓请求头 + 保存签名样本
// ═══════════════════════════════════════════════════════════════
function captureRequest() {
  var h = $request.headers || {};
  var got = [];

  var auth = pick(h, 'authorization');
  if (auth) {
    var token = String(auth).replace(/^Bearer\s+/i, '').trim();
    if (token.length > 20) { $persistentStore.write(token, STORE.jwt); got.push('Token'); }
  }
  var rt = pick(h, 'x-refresh-token');
  if (rt) { $persistentStore.write(String(rt), STORE.rt); got.push('RefreshToken'); }
  var kid = pick(h, 'x-key-id');
  if (kid) $persistentStore.write(String(kid), STORE.kid);

  // 保存签名样本，供日后反推 canonical 格式
  var sig = pick(h, 'x-signature');
  var ts  = pick(h, 'x-ts');
  var nce = pick(h, 'x-nonce');
  if (sig && ts && nce) {
    var samples = loadSamples();
    var url = String($request.url || '');
    var s = {
      m: String($request.method || 'GET').toUpperCase(),
      p: urlPath(url),
      q: urlQuery(url),
      b: (typeof $request.body === 'string') ? $request.body : '',
      t: String(ts),
      n: String(nce),
      s: String(sig)
    };
    var key = s.m + ' ' + s.p + ' ' + s.t + ' ' + s.n;
    samples = samples.filter(function (x) {
      return (x.m + ' ' + x.p + ' ' + x.t + ' ' + x.n) !== key;
    });
    samples.push(s);
    if (samples.length > 8) samples = samples.slice(-8);
    $persistentStore.write(JSON.stringify(samples), STORE.smp);
    got.push('Sample');
  }

  if (got.length) console.log('[Rubii] 凭据/样本已更新: ' + got.join(' / '));
  $done({});
}


function loadSamples() {
  var raw = $persistentStore.read(STORE.smp);
  if (!raw) return [];
  try {
    var a = JSON.parse(raw);
    return (a && a.length) ? a : [];
  } catch (e) { return []; }
}


// ═══════════════════════════════════════════════════════════════
//  模式 2：抓登录/刷新响应里的凭据（含签名密钥 secret）
// ═══════════════════════════════════════════════════════════════
function captureResponse() {
  var body = (typeof $response !== 'undefined' && $response) ? $response.body : '';
  if (!body) { $done({}); return; }
  var json = null;
  try { json = JSON.parse(body); } catch (e) { $done({}); return; }

  var got = [];
  var at = deepFind(json, 'access_token');
  var rt = deepFind(json, 'refresh_token');
  var sc = deepFind(json, 'secret');
  var ki = deepFind(json, 'keyIdentifier') || deepFind(json, 'key_id');

  if (at && String(at).length > 20) { $persistentStore.write(String(at), STORE.jwt); got.push('access_token'); }
  if (rt) { $persistentStore.write(String(rt), STORE.rt); got.push('refresh_token'); }
  if (sc) { $persistentStore.write(String(sc), STORE.sec); got.push('secret'); }
  if (ki) { $persistentStore.write(String(ki), STORE.kid); got.push('keyId'); }

  if (got.length) {
    console.log('[Rubii] 响应中已更新: ' + got.join(' / '));
    notify('Rubii 凭据已更新', got.join(' / '), '');
  }
  $done({});
}


// ═══════════════════════════════════════════════════════════════
//  签名格式反推
// ═══════════════════════════════════════════════════════════════
var SEPS = ['', '|', '&', ':', ' ', ',', ';', '-', '_', '#', '.', '/', '\n'];

var ORDERS = [
  ['m','p','q','b','t','n'],
  ['m','p','t','n'],
  ['t','n','m','p'],
  ['m','p','t','n','b'],
  ['m','p','b','t','n'],
  ['m','p','q','t','n'],
  ['m','q','p','t','n'],
  ['t','n','m','p','b'],
  ['m','t','n','p'],
  ['m','p','a','t','n'],
  ['m','p','t','n','a'],
  ['a','m','p','t','n'],
  ['k','m','p','t','n'],
  ['m','p','t','n','k'],
  ['t','n','k','m','p'],
  ['p','t','n'],
  ['p','q','b','t','n','m'],
  ['t','n','p','m'],
  ['n','t','m','p'],
  ['m','p','n','t']
];

var BODYVARS = [
  { id: 'hexlower', fn: function (b) { return hexFromWords(sha256(utf8ToBytes(b))); } },
  { id: 'hexupper', fn: function (b) { return hexFromWords(sha256(utf8ToBytes(b))).toUpperCase(); } },
  { id: 'b64',      fn: function (b) { return base64FromBytes(bytesFromWords(sha256(utf8ToBytes(b)))); } },
  { id: 'raw',      fn: function (b) { return b; } },
  { id: 'none',     fn: function (b) { return null; } }
];

function fieldVal(f, smp, bodyFn) {
  switch (f) {
    case 'm': return smp.m;
    case 'p': return smp.p;
    case 'q': return smp.q;
    case 'b': return bodyFn(smp.b);
    case 't': return smp.t;
    case 'n': return smp.n;
    case 'a': return CONF.appId;
    case 'k': return CONF.keyId;
    default:  return '';
  }
}

function candidates(smp) {
  var out = [];
  for (var oi = 0; oi < ORDERS.length; oi++) {
    for (var si = 0; si < SEPS.length; si++) {
      for (var bi = 0; bi < BODYVARS.length; bi++) {
        var bv = BODYVARS[bi];
        if (ORDERS[oi].indexOf('b') < 0 && bv.id !== 'none') continue;
        var parts = [], skip = false;
        for (var fi = 0; fi < ORDERS[oi].length; fi++) {
          var v = fieldVal(ORDERS[oi][fi], smp, bv.fn);
          if (v === null) { skip = true; break; }
          parts.push(v);
        }
        if (skip) continue;
        out.push({
          name: ORDERS[oi].join('') + '~' + (SEPS[si] === '' ? 'EMPTY' : JSON.stringify(SEPS[si])) + '~' + bv.id,
          msg: parts.join(SEPS[si])
        });
      }
    }
  }
  return out;
}

// 用样本反推格式；命中返回格式名，否则 null
function detectFormat(secret, samples) {
  var cands = candidates(samples[0]);
  for (var ci = 0; ci < cands.length; ci++) {
    if (hmacSha256Base64(secret, cands[ci].msg) !== samples[0].s) continue;
    // 用其余样本交叉验证，避免误命中
    var ok = true;
    for (var si = 1; si < samples.length; si++) {
      if (samples[si].s === samples[0].s) continue;
      if (hmacSha256Base64(secret, rebuildFormat(cands[ci].name, samples[si])) !== samples[si].s) {
        ok = false; break;
      }
    }
    if (ok) return cands[ci].name;
  }
  return null;
}

// 按格式名为某个样本重建消息（交叉验证用）
// 注意：分隔符用 ~ 而非 |，因为候选分隔符里本身就有 |
function rebuildFormat(name, smp) {
  var parts = name.split('~');
  var order = parts[0].split('');
  var sep = (parts[1] === 'EMPTY') ? '' : JSON.parse(parts[1]);
  var bvid = parts[2];
  var bv = BODYVARS.filter(function (x) { return x.id === bvid; })[0] || BODYVARS[4];
  var out = [];
  for (var i = 0; i < order.length; i++) {
    var v = fieldVal(order[i], smp, bv.fn);
    out.push(v === null ? '' : v);
  }
  return out.join(sep);
}

function signWith(secret, fmtName, smp) {
  return hmacSha256Base64(secret, rebuildFormat(fmtName, smp));
}


// ═══════════════════════════════════════════════════════════════
//  模式 3：签到
// ═══════════════════════════════════════════════════════════════
function runCheckin() {
  var cred = getCred();
  var samples = loadSamples();

  if (!cred.jwt) {
    notify('Rubii 签到失败', '缺少 Token', '开 MITM 打开一次 Rubii App');
    finish('❌ 未配置', '打开 App 抓取凭据');
    return;
  }
  if (!cred.sec) {
    notify('Rubii 签到失败', '缺少签名密钥', '需要退出并重新登录一次 Rubii 以触发下发');
    finish('❌ 缺 secret', '重新登录一次即可');
    return;
  }

  var fmt = cred.fmt;
  if (fmt && samples.length) { doCheckin(cred, fmt); return; }

  if (!samples.length) {
    notify('Rubii 签到失败', '缺少签名样本', '打开一次 Rubii App 让脚本记录真实请求');
    finish('❌ 缺样本', '打开 App 产生样本');
    return;
  }

  console.log('[Rubii] 用 ' + samples.length + ' 个样本反推签名格式...');
  var hit = detectFormat(cred.sec, samples);
  if (hit) {
    console.log('[Rubii] 格式已锁定: ' + hit);
    $persistentStore.write(hit, STORE.fmt);
    doCheckin(cred, hit);
  } else {
    console.log('[Rubii] 反推失败，候选 ' + candidates(samples[0]).length + ' 种均未命中');
    notify('Rubii 签到失败', '签名格式未命中', '需人工确认，可把日志发来分析');
    finish('❌ 格式未命中', '需人工分析');
  }
}


function doCheckin(cred, fmtName) {
  var ts = String(Math.floor(Date.now() / 1000));
  var nonce = makeNonce();
  var smp = { m: 'POST', p: CONF.checkinPath, q: '', b: '', t: ts, n: nonce };

  var headers = {
    'user-agent':         CONF.ua,
    'x-app-id':           CONF.appId,
    'x-ts':               ts,
    'authorization':      'Bearer ' + cred.jwt,
    'x-requested-source': 'app',
    'x-nonce':            nonce,
    'x-language':         CONF.lang,
    'content-type':       'application/json',
    'x-sign-alg':         'HMAC-SHA256',
    'x-key-id':           cred.kid || CONF.keyId,
    'x-signature':        signWith(cred.sec, fmtName, smp)
  };
  if (cred.rt) headers['x-refresh-token'] = cred.rt;

  console.log('[Rubii] 格式 ' + fmtName + ' sig=' + headers['x-signature']);

  $httpClient.post({ url: CONF.host + CONF.checkinPath, headers: headers, body: '' },
    function (err, resp, data) {
      if (err) { notify('Rubii 签到失败', '网络错误', String(err)); finish('❌ 网络错误', String(err)); return; }
      var code = resp && resp.status ? resp.status : 0;
      var body = data || '';
      console.log('[Rubii] HTTP ' + code + ' | ' + body.slice(0, 300));
      var json = null;
      try { json = JSON.parse(body); } catch (e) {}

      if (code === 200 && json && json.code === 200) {
        var amt = (json.data && json.data.reward && json.data.reward.amount) || '';
        var line = amt ? ('+' + amt + ' Ruby') : (json.message || '签到成功');
        notify('✅ Rubii 签到成功', line, '格式 ' + fmtName);
        finish('✅ 已签到', line);
        return;
      }
      if (json && (json.code === 400 || json.code === 409) && /already|已签到|已领取/i.test(body)) {
        notify('Rubii', '今天已经签到过了', ''); finish('☑️ 今天已签到', '无需重复'); return;
      }
      if (code === 401 || (json && json.code === 401)) {
        notify('Rubii 签到失败', '登录已过期', '打开一次 Rubii App 即可续期');
        finish('❌ 凭据已过期', '打开 App 续期'); return;
      }
      if (code === 403 || (json && /signature/i.test(body))) {
        $persistentStore.write('', STORE.fmt);
        notify('Rubii 签到失败', '签名被拒', '已清除格式锁定，下次用新样本重推');
        finish('❌ 签名被拒', '下次会自动重新反推');
        return;
      }
      var why = (json && json.message) ? json.message : ('HTTP ' + code);
      notify('Rubii 签到失败', why, body.slice(0, 160));
      finish('❌ 失败', why);
    });
}


// ═══════════════════════════════════════════════════════════════
//  诊断模式
// ═══════════════════════════════════════════════════════════════
function runDiag() {
  var cred = getCred();
  var samples = loadSamples();
  var lines = [];
  lines.push('token=' + (cred.jwt ? '有' : '无'));
  lines.push('secret=' + (cred.sec ? '有' : '无'));
  lines.push('样本=' + samples.length);
  lines.push('格式=' + ($persistentStore.read(STORE.fmt) || '未锁定'));
  if (samples.length) lines.push('候选=' + candidates(samples[0]).length);
  if (cred.sec && samples.length) {
    lines.push('反推=' + (detectFormat(cred.sec, samples) || '未命中'));
  }
  var text = lines.join(' | ');
  console.log('[Rubii] 诊断: ' + text);
  $done({ title: 'Rubii 诊断', content: text });
}


// ═══════════════════════════════════════════════════════════════
//  凭据读取
// ═══════════════════════════════════════════════════════════════
function getCred() {
  var manual = String(USER_CONFIG.authorization || '').trim().replace(/^Bearer\s+/i, '');
  return {
    jwt: manual || ($persistentStore.read(STORE.jwt) || ''),
    rt:  (USER_CONFIG.refreshToken || $persistentStore.read(STORE.rt) || ''),
    sec: (USER_CONFIG.secret || $persistentStore.read(STORE.sec) || ''),
    kid: ($persistentStore.read(STORE.kid) || ''),
    fmt: ($persistentStore.read(STORE.fmt) || '')
  };
}


// ═══════════════════════════════════════════════════════════════
//  URL 工具
// ═══════════════════════════════════════════════════════════════
function urlPath(u) {
  var m = String(u).match(/^[a-z]+:\/\/[^/]+(\/[^?#]*)/i);
  return m ? m[1] : '';
}
function urlQuery(u) {
  var m = String(u).match(/^[a-z]+:\/\/[^/]+\/[^?#]*\?([^#]*)/i);
  return m ? m[1] : '';
}


// ═══════════════════════════════════════════════════════════════
//  通用工具
// ═══════════════════════════════════════════════════════════════
function pick(h, name) {
  var target = name.toLowerCase();
  var keys = Object.keys(h);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === target) return h[keys[i]];
  }
  return null;
}

function deepFind(obj, key) {
  if (obj === null || obj === undefined) return null;
  if (typeof obj !== 'object') return null;
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    var v = obj[key];
    if (v !== null && v !== undefined && v !== '') return v;
  }
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var f = deepFind(obj[keys[i]], key);
    if (f) return f;
  }
  return null;
}

function makeNonce() {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var s = '';
  for (var i = 0; i < 22; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
  return s;
}

function notify(title, sub, body) {
  try { $notification.post(title, sub || '', body || ''); } catch (e) {}
}

function finish(title, content) {
  try { $persistentStore.write(title + ' · ' + new Date().toLocaleString(), STORE.last); } catch (e) {}
  try { $done({ title: title, content: content, icon: 'checkmark.circle.fill', 'icon-color': '#FF4D8D' }); }
  catch (e) { $done(); }
}


// ═══════════════════════════════════════════════════════════════
//  纯 JS SHA-256 / HMAC-SHA256
//  （已用 Python 标准库交叉验证：sha256("")、sha256("abc")、
//    56 字节跨块消息、中文 UTF-8、HMAC key 超 64 字节 —— 五个用例
//    结果与 Python 完全一致）
// ═══════════════════════════════════════════════════════════════
var K256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256(inputBytes) {
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l = inputBytes.length;
  var withPad = l + 1;
  while (withPad % 64 !== 56) withPad++;
  var total = withPad + 8;
  var msg = new Array(total);
  var i;
  for (i = 0; i < l; i++) msg[i] = inputBytes[i] & 0xff;
  msg[l] = 0x80;
  for (i = l + 1; i < withPad; i++) msg[i] = 0;
  var bitLen = l * 8;
  for (i = 0; i < 8; i++) msg[total - 1 - i] = (bitLen / Math.pow(2, 8 * i)) & 0xff;

  var w = new Array(64);
  for (var blk = 0; blk < total; blk += 64) {
    for (i = 0; i < 16; i++) {
      w[i] = (msg[blk + i*4] << 24) | (msg[blk + i*4+1] << 16) | (msg[blk + i*4+2] << 8) | msg[blk + i*4+3];
    }
    for (i = 16; i < 64; i++) {
      var s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      var s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (i = 0; i < 64; i++) {
      var S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
      var S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) | 0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0;
    H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
  }
  return H;
}

function hexFromWords(H) {
  var s = '';
  for (var i = 0; i < 8; i++) s += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
  return s;
}

function bytesFromWords(H) {
  var out = [];
  for (var i = 0; i < 8; i++) {
    var v = H[i] >>> 0;
    out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  return out;
}

function utf8ToBytes(str) {
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      var c2 = str.charCodeAt(i + 1);
      var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      i++;
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return out;
}

function base64FromBytes(bytes) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var out = '';
  for (var i = 0; i < bytes.length; i += 3) {
    var b0 = bytes[i] & 0xff;
    var b1 = i + 1 < bytes.length ? (bytes[i+1] & 0xff) : NaN;
    var b2 = i + 2 < bytes.length ? (bytes[i+2] & 0xff) : NaN;
    out += chars.charAt(b0 >> 2);
    out += chars.charAt(((b0 & 3) << 4) | (isNaN(b1) ? 0 : b1 >> 4));
    out += isNaN(b1) ? '=' : chars.charAt(((b1 & 15) << 2) | (isNaN(b2) ? 0 : b2 >> 6));
    out += isNaN(b2) ? '=' : chars.charAt(b2 & 63);
  }
  return out;
}

function hmacSha256Base64(secretStr, msgStr) {
  var keyBytes = utf8ToBytes(String(secretStr));
  if (keyBytes.length > 64) keyBytes = bytesFromWords(sha256(keyBytes));
  var inner = [], outer = [], i;
  for (i = 0; i < 64; i++) {
    var kb = i < keyBytes.length ? keyBytes[i] : 0;
    inner.push(kb ^ 0x36);
    outer.push(kb ^ 0x5c);
  }
  var innerHash = bytesFromWords(sha256(inner.concat(utf8ToBytes(String(msgStr)))));
  return base64FromBytes(bytesFromWords(sha256(outer.concat(innerHash))));
}


// ═══════════════════════════════════════════════════════════════
//  启动（必须在所有常量赋值之后）
// ═══════════════════════════════════════════════════════════════
main();
