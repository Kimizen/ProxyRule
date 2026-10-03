/*
 * ═══════════════════════════════════════════════════════════════
 *  Rubii 每日签到 · Loon 脚本
 *
 *  一个文件承担三种角色，靠运行上下文自动分流：
 *    1) 请求头模式：App 联网时抓 Authorization / RefreshToken
 *    2) 响应体模式：登录/刷新接口的响应里抓 access_token / refresh_token / secret
 *    3) 定时模式：调签到接口并推送结果
 *
 *  接口：POST https://api2.rubii.ai/v1/tasks/daily_ruby/complete
 *
 *  关于鉴权（已从 App 安装包与抓包核实）：
 *    · Rubii 用 Authorization: Bearer <JWT> 鉴权，不用 Cookie
 *      （抓包中该请求无 Cookie 头；响应里的 set-cookie: GCLB= 是
 *        Google 负载均衡器的健康检查，与鉴权无关）
 *    · JWT 约 30 天过期，refresh_token 用于续期
 *    · x-signature 是 HMAC-SHA256 签名，密钥 secret 由服务端随
 *      登录/刷新响应下发（App 内 token_model 字段：access_token /
 *      refresh_token / secret / keyIdentifier），不硬编码在安装包里
 * ═══════════════════════════════════════════════════════════════
 */

// ───────── 手动配置（不想依赖 MITM 抓取时，直接在这里填） ─────────
// 填了就优先用填的，MITM 没生效也不影响签到。
// 填完把本文件重新导入 Loon 即可。
var USER_CONFIG = {
  // 可填 "Bearer eyJ..." 或只填 eyJ... 均可
  authorization: '',
  refreshToken: '',
  // 可选：服务端下发的签名密钥，填了会在签到时带上（一般用不到）
  secret: ''
};

// ───────── 接口配置 ─────────
var CONF = {
  host:        'https://api2.rubii.ai',
  checkinPath: '/v1/tasks/daily_ruby/complete',
  appId:       'rubii-app',
  ua:          'Dart/3.10 (dart:io)',
  lang:        'zh-cn'
};

// ───────── 持久化存储键名 ─────────
var STORE = {
  jwt:  'Rubii_JWT',
  rt:   'Rubii_RefreshToken',
  sig:  'Rubii_Signature',
  sec:  'Rubii_Secret',
  kid:  'Rubii_KeyId',
  last: 'Rubii_LastResult'
};


// ═══════════════════════════════════════════════════════════════
//  入口分流
// ═══════════════════════════════════════════════════════════════
(function main() {
  var arg = (typeof $argument !== 'undefined' && $argument) ? String($argument) : '';

  // 模式 2：响应阶段。
  // 两种判定方式：新版靠 script() 第二个参数传入 "capture=response"；
  // 旧版没有这个参数，但 http-request 阶段 $response 恒为 undefined，
  // 所以「$response 存在」本身就说明这是响应阶段。
  var isResponse = (arg.indexOf('capture=response') >= 0) ||
                   (typeof $response !== 'undefined' && !!$response);
  if (isResponse) return captureResponse();

  // 模式 1：请求头（Loon 匹配到请求时）
  if (typeof $request !== 'undefined' && $request && $request.headers) return captureRequest();

  // 模式 3：定时任务
  return runCheckin();
})();


// ═══════════════════════════════════════════════════════════════
//  模式 1：抓请求头里的凭据
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

  // 真实签名也存一份（服务端若不把时间戳纳入签名，这个值能长期复用）
  var sig = pick(h, 'x-signature');
  if (sig) { $persistentStore.write(String(sig), STORE.sig); got.push('Signature'); }

  if (got.length) {
    console.log('[Rubii] 凭据已更新: ' + got.join(' / '));
  }

  $done({});   // 保持请求不变
}


// ═══════════════════════════════════════════════════════════════
//  模式 2：抓登录/刷新响应里的凭据
//  这里的 secret（签名密钥）只出现在响应里，必须抓响应才拿得到
// ═══════════════════════════════════════════════════════════════
function captureResponse() {
  var body = (typeof $response !== 'undefined' && $response) ? $response.body : '';
  if (!body) { $done({}); return; }

  var json = null;
  try { json = JSON.parse(body); } catch (e) { $done({}); return; }

  var at = deepFind(json, 'access_token');
  var rt = deepFind(json, 'refresh_token');
  var sc = deepFind(json, 'secret');
  var ki = deepFind(json, 'keyIdentifier') || deepFind(json, 'key_id');

  var got = [];
  if (at && String(at).length > 20) { $persistentStore.write(String(at), STORE.jwt); got.push('access_token'); }
  if (rt) { $persistentStore.write(String(rt), STORE.rt); got.push('refresh_token'); }
  if (sc) { $persistentStore.write(String(sc), STORE.sec); got.push('secret'); }
  if (ki) { $persistentStore.write(String(ki), STORE.kid); got.push('keyId'); }

  if (got.length) {
    console.log('[Rubii] 响应中已更新: ' + got.join(' / '));
    notify('Rubii 凭据已更新', '下次签到将使用', got.join(' / '));
  }

  $done({});   // 保持响应不变
}


// ═══════════════════════════════════════════════════════════════
//  模式 3：执行签到
// ═══════════════════════════════════════════════════════════════
function runCheckin() {
  var cred = getCred();

  if (!cred.jwt) {
    var tip = '未找到凭据。三种办法任选其一：'
            + '① 开 MITM 后打开一次 App；'
            + '② 手动签到时先打开 App 让它登录或刷新；'
            + '③ 把 authorization 填进脚本顶部的 USER_CONFIG。';
    console.log('[Rubii] ' + tip);
    notify('Rubii 签到失败', '缺少凭据', '开 MITM 打开一次 App，或填入 USER_CONFIG');
    finish('❌ 未配置', '打开 App 抓取，或手填 USER_CONFIG');
    return;
  }

  attempt(cred, !!cred.sig, 0);
}


// 带降级重试：先用抓到的真实签名 → 失败则不带签名再试
function attempt(cred, useSig, failCount) {
  var headers = {
    'user-agent':         CONF.ua,
    'x-app-id':           CONF.appId,
    'x-ts':               String(Math.floor(Date.now() / 1000)),
    'authorization':      'Bearer ' + cred.jwt,
    'x-requested-source': 'app',
    'x-nonce':            makeNonce(),
    'x-language':         CONF.lang,
    'content-type':       'application/json'
  };

  if (cred.rt) headers['x-refresh-token'] = cred.rt;

  if (useSig && cred.sig) {
    headers['x-sign-alg']  = 'HMAC-SHA256';
    headers['x-key-id']    = cred.kid || 'static-v1';
    headers['x-signature'] = cred.sig;
  }

  var opts = { url: CONF.host + CONF.checkinPath, headers: headers, body: '' };

  $httpClient.post(opts, function (err, resp, data) {
    if (err) {
      console.log('[Rubii] 网络错误: ' + err);
      notify('Rubii 签到失败', '网络错误', String(err));
      finish('❌ 网络错误', String(err));
      return;
    }

    var code = resp && resp.status ? resp.status : 0;
    var body = data || '';
    console.log('[Rubii] HTTP ' + code + ' | ' + body.slice(0, 300));

    var json = null;
    try { json = JSON.parse(body); } catch (e) {}

    // 成功
    if (code === 200 && json && json.code === 200) {
      var msg  = json.message || '签到成功';
      var amt  = (json.data && json.data.reward && json.data.reward.amount) || '';
      var line = amt ? ('+' + amt + ' Ruby') : msg;
      notify('✅ Rubii 签到成功', line, msg);
      finish('✅ 已签到', line);
      return;
    }

    // 今天已经签过
    if (json && (json.code === 400 || json.code === 409) && /already|已签到|已领取/i.test(body)) {
      notify('Rubii', '今天已经签到过了', '');
      finish('☑️ 今天已签到', '无需重复操作');
      return;
    }

    // 凭据过期 → 打开 App 让它刷新，响应脚本会自动续上
    if (code === 401 || (json && json.code === 401)) {
      notify('Rubii 签到失败', '登录已过期', '打开一次 Rubii App，脚本会自动续期');
      finish('❌ 凭据已过期', '打开 App 重新登录即可自动续期');
      return;
    }

    // 其它失败：换签名策略再试一次
    if (failCount < 1) {
      console.log('[Rubii] 首次失败，切换签名策略重试（useSig=' + (!useSig) + '）');
      attempt(cred, !useSig, failCount + 1);
      return;
    }

    var why = (json && json.message) ? json.message : ('HTTP ' + code);
    notify('Rubii 签到失败', why, body.slice(0, 200));
    finish('❌ 失败', why);
  });
}


// ═══════════════════════════════════════════════════════════════
//  凭据读取：手动配置优先，其次持久化存储
// ═══════════════════════════════════════════════════════════════
function getCred() {
  var manual = String(USER_CONFIG.authorization || '').trim().replace(/^Bearer\s+/i, '');
  return {
    jwt: manual || ($persistentStore.read(STORE.jwt) || ''),
    rt:  (USER_CONFIG.refreshToken || $persistentStore.read(STORE.rt) || ''),
    sig: ($persistentStore.read(STORE.sig) || ''),
    sec: (USER_CONFIG.secret || $persistentStore.read(STORE.sec) || ''),
    kid: ($persistentStore.read(STORE.kid) || '')
  };
}


// ═══════════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════════

// 大小写无关地取请求头（Loon 保留 App 原始大小写，这里做全兼容匹配）
function pick(h, name) {
  var target = name.toLowerCase();
  var keys = Object.keys(h);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === target) return h[keys[i]];
  }
  return null;
}

// 深度查找 JSON 里的第一个指定字段
function deepFind(obj, key) {
  if (obj === null || obj === undefined) return null;
  if (typeof obj !== 'object') return null;
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    var v = obj[key];
    if (v !== null && v !== undefined && v !== '') return v;
  }
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var found = deepFind(obj[keys[i]], key);
    if (found) return found;
  }
  return null;
}

// 生成 22 位随机 nonce（对齐 App 格式）
function makeNonce() {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var s = '';
  for (var i = 0; i < 22; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
  return s;
}

function notify(title, sub, body) {
  try { $notification.post(title, sub || '', body || ''); } catch (e) {}
}

// 兼容 cron 与面板两种调用
function finish(title, content) {
  try {
    $persistentStore.write(title + ' · ' + new Date().toLocaleString(), STORE.last);
  } catch (e) {}
  try {
    $done({ title: title, content: content, icon: 'checkmark.circle.fill', 'icon-color': '#FF4D8D' });
  } catch (e) {
    $done();
  }
}
