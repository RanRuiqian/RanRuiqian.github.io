// 思路树 · 多人协作中转服务（Cloudflare Worker + D1）
// 只保存加密后的修改记录；解密钥匙只在分享链接里，这里看不到任何内容。
// 部署：Worker 绑定一个 D1 数据库，变量名必须是 DB。表会在第一次请求时自动创建。
const ALLOW = ['https://ranruiqian.github.io'];
let ready = null;
function init(env) {
  return ready || (ready = env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY, wh TEXT NOT NULL, created INTEGER)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS changes(seq INTEGER PRIMARY KEY AUTOINCREMENT, share TEXT NOT NULL, ts INTEGER, blob TEXT NOT NULL)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS ix_changes ON changes(share, seq)'),
  ]).catch(e => { ready = null; throw e; }));
}
async function sha(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const ok = ALLOW.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    const cors = { 'Access-Control-Allow-Origin': ok ? origin : ALLOW[0], 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'content-type', 'Vary': 'Origin' };
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'content-type': 'application/json' } });
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(req.url);
    if (url.pathname === '/') return json({ ok: true, service: 'thinking-tree-collab' });
    const m = url.pathname.match(/^\/s\/([A-Za-z0-9_-]{8,40})\/(init|changes|delete)$/);
    if (!m) return json({ error: 'not found' }, 404);
    await init(env);
    const [, id, what] = m;
    const share = await env.DB.prepare('SELECT wh FROM shares WHERE id=?').bind(id).first();
    if (what === 'changes' && req.method === 'GET') {
      if (!share) return json({ error: 'no share' }, 404);
      const after = Math.max(0, parseInt(url.searchParams.get('after') || '0', 10) || 0);
      const r = await env.DB.prepare('SELECT seq, ts, blob FROM changes WHERE share=? AND seq>? ORDER BY seq LIMIT 500').bind(id, after).all();
      return json({ changes: r.results });
    }
    if (req.method !== 'POST') return json({ error: 'method' }, 405);
    const text = await req.text();
    if (text.length > 1500000) return json({ error: 'too large' }, 413);
    let body; try { body = JSON.parse(text); } catch { return json({ error: 'bad json' }, 400); }
    if (what === 'init') {
      if (!/^[0-9a-f]{64}$/.test(body.wh || '')) return json({ error: 'bad hash' }, 400);
      if (share) return json({ ok: share.wh === body.wh }, share.wh === body.wh ? 200 : 409);
      await env.DB.prepare('INSERT INTO shares(id, wh, created) VALUES(?,?,?)').bind(id, body.wh, Date.now()).run();
      return json({ ok: true });
    }
    if (!share) return json({ error: 'no share' }, 404);
    if (typeof body.w !== 'string' || await sha(body.w) !== share.wh) return json({ error: 'forbidden' }, 403);
    if (what === 'delete') {
      await env.DB.batch([env.DB.prepare('DELETE FROM changes WHERE share=?').bind(id), env.DB.prepare('DELETE FROM shares WHERE id=?').bind(id)]);
      return json({ ok: true });
    }
    if (typeof body.blob !== 'string' || !body.blob) return json({ error: 'empty' }, 400);
    const r = await env.DB.prepare('INSERT INTO changes(share, ts, blob) VALUES(?,?,?)').bind(id, Date.now(), body.blob).run();
    return json({ seq: r.meta.last_row_id });
  },
};
