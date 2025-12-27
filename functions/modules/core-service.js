// Core Service Module (CMEDT Port for MiSub)
// Refactored to strictly match progame/cmedt.js logic for ban evasion

// --- Global State for ProxyIP ---
let 缓存反代IP = '';
let 缓存反代解析数组 = [];
let 缓存反代数组索引 = 0;

// --- Helper Functions from CMEDT ---

// 1. WebSocketPair / Response Helpers
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function 获取字典词(index) {
    const dict = [
        'connect',              // 0
        'WebSocketPair',        // 1
        'Upgrade',              // 2
        'websocket',            // 3
        'sec-websocket-protocol',// 4
    ];
    return dict[index];
}

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (err) {
        return { error: err };
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')]; // speed.cloudflare.com
    if (speedTestDomains.includes(hostname)) {
        return true;
    }
    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

// Ported from cmedt.js: Resolves ProxyIP domains to usable IP list using DoH
async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
    if (!缓存反代IP || !缓存反代解析数组 || 缓存反代IP !== proxyIP) {
        proxyIP = proxyIP.toLowerCase();
        async function DoH查询(域名, 记录类型) {
            try {
                const response = await fetch(`https://1.1.1.1/dns-query?name=${域名}&type=${记录类型}`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                if (!response.ok) return [];
                const data = await response.json();
                return data.Answer || [];
            } catch (error) {
                // console.error(`DoH查询失败 (${记录类型}):`, error);
                return [];
            }
        }

        function 解析地址端口字符串(str) {
            let 地址 = str, 端口 = 443;
            if (str.includes(']:')) {
                const parts = str.split(']:');
                地址 = parts[0] + ']';
                端口 = parseInt(parts[1], 10) || 端口;
            } else if (str.includes(':') && !str.startsWith('[')) {
                const colonIndex = str.lastIndexOf(':');
                地址 = str.slice(0, colonIndex);
                端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
            }
            return [地址, 端口];
        }

        let 所有反代数组 = [];

        if (proxyIP.includes('.william')) {
            try {
                const txtRecords = await DoH查询(proxyIP, 'TXT');
                const txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
                if (txtData.length > 0) {
                    let data = txtData[0];
                    if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
                    const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                    所有反代数组 = prefixes.map(prefix => 解析地址端口字符串(prefix));
                }
            } catch (error) {
                // console.error('解析William域名失败:', error);
            }
        } else {
            let [地址, 端口] = 解析地址端口字符串(proxyIP);

            if (proxyIP.includes('.tp')) {
                const tpMatch = proxyIP.match(/\.tp(\d+)/);
                if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
            }

            // 判断是否是域名（非IP地址）
            const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
            const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

            if (!ipv4Regex.test(地址) && !ipv6Regex.test(地址)) {
                // 并行查询 A 和 AAAA 记录
                const [aRecords, aaaaRecords] = await Promise.all([
                    DoH查询(地址, 'A'),
                    DoH查询(地址, 'AAAA')
                ]);

                const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                const ipAddresses = [...ipv4List, ...ipv6List];

                所有反代数组 = ipAddresses.length > 0
                    ? ipAddresses.map(ip => [ip, 端口])
                    : [[地址, 端口]];
            } else {
                所有反代数组 = [[地址, 端口]];
            }
        }
        const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
        const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
        let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
        const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
        缓存反代解析数组 = 洗牌后.slice(0, 8);
        缓存反代IP = proxyIP;
    }
    return 缓存反代解析数组;
}

// --- Protocol Parsers ---

function 解析木马请求(buffer, passwordPlainText) {
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    if (buffer[56] !== 0x0d || buffer[57] !== 0x0a) return { hasError: true, message: "invalid header format" };

    const socks5DataBuffer = buffer.slice(56 + 2);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

    const view = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset, socks5DataBuffer.byteLength);
    const cmd = view.getUint8(0);
    if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!address) return { hasError: true, message: `address is empty` };

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer.buffer, portBuffer.byteOffset, portBuffer.byteLength).getUint16(0);

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function 解析魏烈思请求(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    const extractedUUID = formatIdentifier(new Uint8Array(chunk.slice(1, 17)));
    if (extractedUUID !== token) return { hasError: true, message: 'Invalid uuid' };

    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }

    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);

    let addrIdx = portIdx + 2;
    let addrValIdx = addrIdx + 1;
    let hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    let addrLen = 0;

    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }

    if (!hostname) return { hasError: true, message: `Invalid address` };

    return {
        hasError: false,
        addressType,
        port,
        hostname,
        isUDP,
        rawIndex: addrValIdx + addrLen,
        version
    };
}

// --- Connection Handlers ---

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData;
    let hasData = false;

    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error('ws.readyState is not open');
                }
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { }
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });

    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const connectFunc = globalThis[获取字典词(0)]; // connect
        const tcpSocket = connectFunc ? await connectFunc({ hostname: '8.8.4.4', port: 53 }) : null;
        if (!tcpSocket) return;

        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, env) {
    // ProxyIP Configuration
    let 反代IP = 'proxyip.aliyun.fxxk.dedyn.io'; // Default fallback
    // Try to get from env or generate
    if (env.PROXYIP) {
        反代IP = (env.sys_c_proxyip || env.PROXYIP || (env.colo || 'HK') + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
    } else {
        // MiSub has sys_c_proxyip, map it if present
        if (env.sys_c_proxyip) {
            反代IP = env.sys_c_proxyip.toLowerCase();
        } else {
            反代IP = ((env.colo || 'HK') + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        }
    }
    const 启用反代兜底 = true; // Hardcode for resilience

    async function connectDirect(address, port, data, 所有反代数组 = null, 反代兜底 = true) {
        let remoteSock;

        // Proxy Fallback Loop
        if (所有反代数组 && 所有反代数组.length > 0) {
            for (let i = 0; i < 所有反代数组.length; i++) {
                const 反代数组索引 = (缓存反代数组索引 + i) % 所有反代数组.length;
                const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
                try {
                    // console.log(`[Proxy Connect] Trying: ${反代地址}:${反代端口}`);
                    const connectFunc = globalThis[获取字典词(0)];
                    remoteSock = connectFunc ? await connectFunc({ hostname: 反代地址, port: 反代端口 }) : null;

                    if (!remoteSock) throw new Error('Connect failed');

                    // Race condition check for connection open (timeout 1s)
                    await Promise.race([
                        remoteSock.opened,
                        new Promise((_, reject) => setTimeout(() => reject(new Error('Connection Timeout')), 1000))
                    ]);

                    const writer = remoteSock.writable.getWriter();
                    await writer.write(data);
                    writer.releaseLock();

                    缓存反代数组索引 = 反代数组索引; // Update global index on success
                    return remoteSock;
                } catch (err) {
                    // console.log(`[Proxy Connect] Failed: ${反代地址}:${反代端口}`, err);
                    try { remoteSock?.close?.(); } catch (e) { }
                    continue;
                }
            }
        }

        if (反代兜底) {
            const connectFunc = globalThis[获取字典词(0)];
            remoteSock = connectFunc ? await connectFunc({ hostname: address, port: port }) : null;
            if (!remoteSock) throw new Error('Direct Connect Failed');

            const writer = remoteSock.writable.getWriter();
            await writer.write(data);
            writer.releaseLock();
            return remoteSock;
        } else {
            closeSocketQuietly(ws);
            throw new Error('[Proxy Connect] All proxies failed and no fallback.');
        }
    }

    async function connecttoPry() {
        try {
            // console.log(`[Proxy Fallback] Switching to ProxyIP for: ${host}:${portNum}`);
            const 所有反代数组 = await 解析地址端口(反代IP, host, yourUUID);

            // Connect to one of the resolved IPs
            // Use connectDirect recursive logic basically
            const newSocket = await connectDirect(host, portNum, rawData, 所有反代数组, 启用反代兜底);

            remoteConnWrapper.socket = newSocket;
            newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
            connectStreams(newSocket, ws, respHeader, null);
        } catch (e) {
            // console.error('Proxy Fallback Failed', e);
            closeSocketQuietly(ws);
        }
    }

    try {
        // Try Direct Connection First
        const connectFunc = globalThis[获取字典词(0)];
        const initialSocket = connectFunc ? await connectFunc({ hostname: host, port: portNum }) : null;

        // If direct successful
        if (initialSocket) {
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry); // Retry with connecttoPry on failure
            const writer = initialSocket.writable.getWriter();
            await writer.write(rawData);
            writer.releaseLock();
        } else {
            throw new Error('Direct connect returned null');
        }
    } catch (err) {
        // console.log('Direct Connect Failed, triggering fallback');
        await connecttoPry();
    }
}

async function 处理WS请求(request, env, config) {
    const WebSocketPair = globalThis[获取字典词(1)];
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();

    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get(获取字典词(4)) || ''; // sec-websocket-protocol
    const readable = makeReadableStr(serverSock, earlyData);

    let 判断是否是木马 = null;
    const yourUUID = config.uuid;

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);

            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (判断是否是木马 === null) {
                const bytes = new Uint8Array(chunk);
                // VLESS/Trojan auto-detect based on CRF at 56
                判断是否是木马 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }

            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (判断是否是木马) {
                const { port, hostname, rawClientData, hasError } = 解析木马请求(chunk, yourUUID);
                if (hasError) return;

                if (isSpeedTestSite(hostname)) return;

                await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, env);
            } else {
                const { port, hostname, rawIndex, version, isUDP, hasError } = 解析魏烈思请求(chunk, yourUUID);
                if (hasError) return;

                if (isSpeedTestSite(hostname)) return;

                if (isUDP) {
                    if (port === 53) {
                        isDnsQuery = true;
                        const respHeader = new Uint8Array([version[0], 0]);
                        const rawData = chunk.slice(rawIndex);
                        return forwardataudp(rawData, serverSock, respHeader);
                    } else {
                        return;
                    }
                }

                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, env);
            }
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

// --- Configuration & Disguise Handling (MiSub specific integration) ---

async function 获取配置(环境) {
    const 默认配置 = {
        uuid: 环境.sys_c_key || '00000000-0000-4000-8000-000000000000',
        path: 环境.sys_c_path || '/?ed=2048',
        camouflageMode: 环境.sys_c_mode || 'nginx',
        customHtml: 环境.sys_c_html || '',
        redirectUrl: 环境.sys_c_redirect_url || '',
        skipCert: 环境.sys_c_no_cert === true || 环境.sys_c_no_cert === 'true'
    };
    // KV Overlay
    try {
        if (环境.MISUB_KV) {
            const 设置字符串 = await 环境.MISUB_KV.get('worker_settings_v1');
            if (设置字符串) {
                const 设置对象 = JSON.parse(设置字符串);
                if (设置对象.sys_c_key) 默认配置.uuid = 设置对象.sys_c_key;
                if (设置对象.sys_c_path) 默认配置.path = 设置对象.sys_c_path;
                if (设置对象.sys_c_mode) 默认配置.camouflageMode = 设置对象.sys_c_mode;
                if (设置对象.sys_c_html) 默认配置.customHtml = 设置对象.sys_c_html;
                if (设置对象.sys_c_redirect_url) 默认配置.redirectUrl = 设置对象.sys_c_redirect_url;
            }
        }
    } catch (e) { }
    return 默认配置;
}

async function 处理伪装(配置, 主机名, IP) {
    const 模式 = 配置.camouflageMode;
    if (模式 === 'custom' && 配置.customHtml) {
        return new Response(配置.customHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (模式 === 'redirect' && 配置.redirectUrl) {
        return Response.redirect(配置.redirectUrl, 302);
    }
    if (模式 === '1101') {
        return 错误页1101(主机名, IP || '127.0.0.1');
    }
    return Nginx伪装页();
}

// --- HTML Templates ---

function Nginx伪装页() {
    const 页面内容 = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
    return new Response(页面内容, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function 错误页1101(主机名, IP) {
    const 页面内容 = `<!DOCTYPE html>
<!-- CLOUDFLARE 1101 ERROR PAGE MOCK -->
<html>
<head><title>Worker threw exception | ${主机名} | Cloudflare</title></head>
<body>
<div id="cf-wrapper">
    <h1>Error 1101</h1>
    <p>Worker threw exception</p>
    <p>Your IP: ${IP}</p>
</div>
</body>
</html>`;
    return new Response(页面内容, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// --- Main Entry ---

async function 核心服务请求处理(上下文) {
    const { request: 请求, env: 环境 } = 上下文;
    const URL对象 = new URL(请求.url);

    // System path check
    const 是系统路径 =
        URL对象.pathname.startsWith('/api/') ||
        URL对象.pathname.startsWith('/assets/') ||
        URL对象.pathname.startsWith('/sub/') ||
        URL对象.pathname === '/sub' ||
        URL对象.pathname.startsWith('/link/') ||
        URL对象.pathname === '/link' ||
        URL对象.pathname.startsWith('/@vite/') ||
        URL对象.pathname.startsWith('/src/') ||
        URL对象.pathname === '/favicon.ico' ||
        ['/login', '/dashboard', '/settings', '/groups', '/nodes', '/subscriptions', '/profile'].some(p => URL对象.pathname === p || URL对象.pathname.startsWith(p + '/'));

    if (是系统路径) return null;

    const 配置 = await 获取配置(环境);
    const 目标路径 = 配置.path.split('?')[0];
    const 匹配路径 = URL对象.pathname === 目标路径;
    const Upgrade = 请求.headers.get(获取字典词(2)); // Upgrade
    const 是WebSocket = Upgrade === 获取字典词(3); // websocket

    if (是WebSocket && 匹配路径) {
        return 处理WS请求(请求, 环境, 配置);
    }

    // Fallback to camouflage
    return 处理伪装(配置, URL对象.hostname, 请求.headers.get('cf-connecting-ip'));
}

export { 核心服务请求处理 as handleCoreServiceRequest };
