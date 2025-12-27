import { connect } from 'cloudflare:sockets';

const UH = { Connection: 'Upgrade', Upgrade: 'websocket' };
const E = (s, h) => new Response(null, { status: s, headers: h });

// Stealth: Read settings directly without heavy imports
async function g(e) {
    try {
        // Try KV first (standard raw access)
        if (e.MISUB_KV) return (await e.MISUB_KV.get('misub_settings_v1', 'json'))?.sskbConfig;
        // Try D1 (raw query)
        if (e.MISUB_DB) return (await e.MISUB_DB.prepare('SELECT value FROM settings WHERE key = ?').bind('misub_settings_v1').first())?.value?.sskbConfig;
    } catch { }
    return null;
}

export async function handleSSKBRequest(c) {
    const r = c.request, e = c.env;
    let cf = await g(e) || {};

    if (!cf.enabled || !cf.uuid) return new Response(null, { status: 503 });

    const UUID = cf.uuid, PG = cf.proxyIp || 'kr.william.us.ci';
    const uuid = new Uint8Array(16); for (let i = 0; i < 16; i++) uuid[i] = parseInt(UUID.replace(/-/g, '').substr(i * 2, 2), 16);
    const te = new TextEncoder(), td = new TextDecoder();

    let u = r.headers.get('Upgrade'); if (!u || u.toLowerCase() !== 'websocket') return E(426, UH);
    let p = r.headers.get('Sec-WebSocket-Protocol'); if (!p) return E(400);
    let h; try { let b = atob(p.replace(/[-_]/g, m => m === '-' ? '+' : '/')); h = new Uint8Array(b.length); for (let i = 0; i < b.length; i++)h[i] = b.charCodeAt(i) } catch { return E(400) }

    if (h.length < 18) return E(400);
    for (let i = 0; i < 16; i++) if (h[1 + i] !== uuid[i]) return E(403);
    let len = 18 + h[17]; if (len >= h.length) return E(400);

    let rp = (h[len + 1] << 8) | h[len + 2], at = h[len + 3], as = len + 4, ri, ae;
    if (at === 1) { ae = as + 4; ri = h[as] + '.' + h[as + 1] + '.' + h[as + 2] + '.' + h[as + 3] }
    else if (at === 2) { let l = h[as]; ae = as + 1 + l; ri = td.decode(h.subarray(as + 1, ae)) }
    else if (at === 3) { ae = as + 16; ri = ((h[as] << 8) | h[as + 1]).toString(16) + ':' + ((h[as + 2] << 8) | h[as + 3]).toString(16) + ':' + ((h[as + 4] << 8) | h[as + 5]).toString(16) + ':' + ((h[as + 6] << 8) | h[as + 7]).toString(16) + ':' + ((h[as + 8] << 8) | h[as + 9]).toString(16) + ':' + ((h[as + 10] << 8) | h[as + 11]).toString(16) + ':' + ((h[as + 12] << 8) | h[as + 13]).toString(16) + ':' + ((h[as + 14] << 8) | h[as + 15]).toString(16) }
    else return E(400);
    if (ae > h.length) return E(400);

    let s; try { s = connect({ hostname: ri, port: rp }); await s.opened } catch { s = null }
    if (!s && PG) { try { s = connect({ hostname: PG, port: 443 }); await s.opened } catch { return E(502) } }
    if (!s) return E(502);

    let { 0: cl, 1: sv } = new WebSocketPair; sv.accept();
    let rs = new ReadableStream({
        start(c) { if (h.length > ae) c.enqueue(h.subarray(ae)); sv.onmessage = e => { try { c.enqueue(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : te.encode(e.data)) } catch { sv.close() } }; sv.onclose = () => c.close(); sv.onerror = e => c.error(e) },
        cancel() { sv.close() }
    });
    rs.pipeTo(s.writable).catch(() => { sv.close(); s.close() });
    let f = true;
    s.readable.pipeTo(new WritableStream({
        write(c) { if (f) { f = false; const n = new Uint8Array(c.length + 2); n.set(c, 2); sv.send(n) } else sv.send(c) },
        close() { sv.close() }, abort() { sv.close() }
    })).catch(() => { sv.close(); s.close() });
    return new Response(null, { status: 101, webSocket: cl })
}
