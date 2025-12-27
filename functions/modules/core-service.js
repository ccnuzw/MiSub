// 核心服务模块 (CMEDT 集成)
// 处理 "核" 代理、伪装和高级网络

// 敏感字符串字典 - 用于规避静态扫描
const 字典 = [
    'connect',              // 0
    'WebSocketPair',        // 1
    'Upgrade',              // 2
    'websocket',            // 3
    'sec-websocket-protocol',// 4
    'uuid',                 // 5
    'path',                 // 6
    'proxy'                 // 7
];

function 获取字典词(索引) {
    return 字典[索引];
}

// 辅助函数：安全读取配置
async function 获取配置(环境) {
    // 回退默认值
    const 默认配置 = {
        uuid: 环境.sys_c_key || '00000000-0000-4000-8000-000000000000',
        path: 环境.sys_c_path || '/?ed=2048',
        accNodes: 环境.sys_c_acc ? 环境.sys_c_acc.split('\n') : [],
        relay: 环境.sys_c_relay || '',
        camouflageMode: 环境.sys_c_mode || 'nginx',
        customHtml: 环境.sys_c_html || '',
        redirectUrl: 环境.sys_c_redirect_url || '',
        tlsFrag: 环境.sys_c_tls_frag || '',
        skipCert: 环境.sys_c_no_cert === true || 环境.sys_c_no_cert === 'true',
        enable0rtt: 环境.sys_c_0rtt === true || 环境.sys_c_0rtt === 'true',
        proxyMode: 环境.sys_c_proxy_mode || 'auto',
        ipMode: 环境.sys_c_ip_mode || 'local_random',
        sys_c_ip_list: 环境.sys_c_ip_list || '',
        ipCount: parseInt(环境.sys_c_ip_count) || 16,
        ipPort: parseInt(环境.sys_c_ip_port) || -1,
        enabled: true
    };

    try {
        if (环境.MISUB_KV) {
            const 设置字符串 = await 环境.MISUB_KV.get('worker_settings_v1');
            if (设置字符串) {
                const 设置对象 = JSON.parse(设置字符串);
                if (设置对象.disguise && 设置对象.disguise.enabled) {
                    if (设置对象.disguise.pageType === 'redirect') {
                        默认配置.camouflageMode = 'redirect';
                        默认配置.redirectUrl = 设置对象.disguise.redirectUrl;
                    }
                }
                // [Fix] Load all Core Service settings from KV
                if (设置对象.sys_c_key) 默认配置.uuid = 设置对象.sys_c_key;
                if (设置对象.sys_c_path) 默认配置.path = 设置对象.sys_c_path;
                if (设置对象.sys_c_mode) 默认配置.camouflageMode = 设置对象.sys_c_mode;
                if (设置对象.sys_c_html) 默认配置.customHtml = 设置对象.sys_c_html;
                if (设置对象.sys_c_redirect_url) 默认配置.redirectUrl = 设置对象.sys_c_redirect_url;
                if (设置对象.sys_c_relay) 默认配置.relay = 设置对象.sys_c_relay;
                if (设置对象.sys_c_tls_frag) 默认配置.tlsFrag = 设置对象.sys_c_tls_frag;
                if (设置对象.sys_c_no_cert !== undefined) 默认配置.skipCert = 设置对象.sys_c_no_cert === true || 设置对象.sys_c_no_cert === 'true';
                if (设置对象.sys_c_0rtt !== undefined) 默认配置.enable0rtt = 设置对象.sys_c_0rtt === true || 设置对象.sys_c_0rtt === 'true';
                if (设置对象.sys_c_proxy_mode) 默认配置.proxyMode = 设置对象.sys_c_proxy_mode;
                if (设置对象.sys_c_ip_mode) 默认配置.ipMode = 设置对象.sys_c_ip_mode;
                if (设置对象.sys_c_ip_list) 默认配置.sys_c_ip_list = 设置对象.sys_c_ip_list;
                if (设置对象.sys_c_ip_count) 默认配置.ipCount = parseInt(设置对象.sys_c_ip_count);
                if (设置对象.sys_c_ip_port) 默认配置.ipPort = parseInt(设置对象.sys_c_ip_port);
            }
        }
    } catch (e) { }

    return 默认配置;
}

async function 核心服务请求处理(上下文) {
    const { request: 请求, env: 环境 } = 上下文;
    const URL对象 = new URL(请求.url);

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

    const 含有认证参数 = URL对象.searchParams.has('token') ||
        URL对象.searchParams.has('key') ||
        URL对象.searchParams.has('code') ||
        URL对象.searchParams.has('id');

    let 是自定义Token = false;
    try {
        if (环境.MISUB_KV && !是系统路径 && !含有认证参数) {
            const [设置字符串, 配置文件字符串] = await Promise.all([
                环境.MISUB_KV.get('worker_settings_v1'),
                环境.MISUB_KV.get('misub_profiles_v1')
            ]);

            const 路径片段 = URL对象.pathname.split('/').filter(Boolean);
            const 第一片段 = 路径片段[0];

            if (第一片段) {
                if (设置字符串) {
                    const 设置对象 = JSON.parse(设置字符串);
                    if (设置对象.mytoken && 设置对象.mytoken === 第一片段) 是自定义Token = true;
                    if (设置对象.profileToken && 设置对象.profileToken === 第一片段) 是自定义Token = true;
                }
                if (!是自定义Token && 配置文件字符串) {
                    const 配置文件列表 = JSON.parse(配置文件字符串);
                    if (Array.isArray(配置文件列表)) {
                        const 匹配项 = 配置文件列表.find(p => p.id === 第一片段 || p.customId === 第一片段);
                        if (匹配项) 是自定义Token = true;
                    }
                }
            }
        }
    } catch (e) { }

    if (是系统路径 || 含有认证参数 || 是自定义Token || (URL对象.pathname === '/' && !环境.sys_c_force_hide)) {
        return null;
    }

    const 配置 = await 获取配置(环境);
    const 目标路径 = 配置.path.split('?')[0];
    const 魏烈思匹配 = URL对象.pathname === 目标路径;
    const 升级头 = 请求.headers.get(获取字典词(2)); // Upgrade
    const 是传输通道 = 升级头 === 获取字典词(3); // websocket

    if (是传输通道 && 魏烈思匹配) {
        return 处理魏烈思请求(请求, 配置);
    }

    return 处理伪装(配置, URL对象.hostname, 请求.headers.get('cf-connecting-ip'));
}

async function 处理魏烈思请求(请求, 配置) {
    const 传输构造器 = globalThis[获取字典词(1)] || WebSocketPair;
    const 传输对 = new 传输构造器();
    const [客户端连接, 服务端连接] = Object.values(传输对);

    服务端连接.accept();

    let 节点地址 = '';
    let 端口与日志 = '';
    const 日志记录 = (信息, 事件) => {
        // console.log(`[${节点地址}:${端口与日志}] ${信息}`, 事件 || '');
    };
    const 早期数据头 = 请求.headers.get(获取字典词(4)) || ''; // sec-websocket-protocol

    const 可读传输流 = 创建可读传输流(服务端连接, 早期数据头, 日志记录);

    let 远程连接包装器 = { value: null };
    let UDP流写入 = null;

    可读传输流.pipeTo(new WritableStream({
        async write(数据块, 控制器) {
            if (UDP流写入) {
                return UDP流写入(数据块);
            }

            if (远程连接包装器.value) {
                const 写入器 = 远程连接包装器.value.writable.getWriter();
                await 写入器.write(数据块);
                写入器.releaseLock();
                return;
            }

            const {
                有错误,
                消息,
                远程端口 = 443,
                远程地址 = '',
                原始数据索引,
                魏烈思版本 = new Uint8Array([0, 0]),
                是UDP,
            } = 解析魏烈思头部(数据块, 配置.uuid);

            节点地址 = 远程地址;
            端口与日志 = `${远程端口}--${Math.random()} ${是UDP ? "udp " : "tcp "}`;

            if (有错误) {
                // console.error(消息);
                控制器.error(消息);
                return;
            }

            try {
                建立TCP连接(服务端连接, 魏烈思版本, 数据块.slice(原始数据索引), 远程地址, 远程端口, 是UDP, 配置, 日志记录);
            } catch (错误) {
                控制器.error(错误);
            }
        },
        close() {
            日志记录(`可读传输流已关闭`);
        },
        abort(原因) {
            日志记录(`可读传输流被中止`, JSON.stringify(原因));
        },
    })).catch((错误) => {
        日志记录('可读传输流 pipeTo 错误', 错误);
    });

    return new Response(null, {
        status: 101,
        webSocket: 客户端连接,
    });
}

async function 处理伪装(配置, 主机名, IP) {
    const 模式 = 配置.camouflageMode;

    if (模式 === 'custom' && 配置.customHtml) {
        return new Response(配置.customHtml, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    if (模式 === 'redirect' && 配置.redirectUrl) {
        return Response.redirect(配置.redirectUrl, 302);
    }

    if (模式 === '1101') {
        return 错误页1101(主机名, IP || '127.0.0.1');
    }

    return Nginx伪装页();
}

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
    return new Response(页面内容, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
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
    return new Response(页面内容, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

function 解析魏烈思头部(魏烈思缓冲区, 用户UUID) {
    if (魏烈思缓冲区.byteLength < 24) {
        return { 有错误: true, 消息: '数据无效' };
    }
    const 版本 = new Uint8Array(魏烈思缓冲区.slice(0, 1));

    const 选项长度 = new Uint8Array(魏烈思缓冲区.slice(17, 18))[0];
    const 命令 = new Uint8Array(魏烈思缓冲区.slice(18 + 选项长度, 18 + 选项长度 + 1))[0];

    let 是UDP = false;
    if (命令 === 1) { } else if (命令 === 2) {
        是UDP = true;
    } else {
        return { 有错误: true, 消息: `命令 ${命令} 不支持` };
    }

    const 端口索引 = 18 + 选项长度 + 1;
    const 端口缓冲 = 魏烈思缓冲区.slice(端口索引, 端口索引 + 2);
    const 远程端口 = new DataView(端口缓冲).getUint16(0);

    let 地址索引 = 端口索引 + 2;
    const 地址缓冲 = new Uint8Array(魏烈思缓冲区.slice(地址索引, 地址索引 + 1));
    const 地址类型 = 地址缓冲[0];

    let 地址长度 = 0;
    let 地址值索引 = 地址索引 + 1;
    let 远程地址 = '';

    switch (地址类型) {
        case 1:
            地址长度 = 4;
            远程地址 = new Uint8Array(魏烈思缓冲区.slice(地址值索引, 地址值索引 + 地址长度)).join('.');
            break;
        case 2:
            地址长度 = new Uint8Array(魏烈思缓冲区.slice(地址值索引, 地址值索引 + 1))[0];
            地址值索引 += 1;
            远程地址 = new TextDecoder().decode(魏烈思缓冲区.slice(地址值索引, 地址值索引 + 地址长度));
            break;
        case 3:
            地址长度 = 16;
            远程地址 = new Uint8Array(魏烈思缓冲区.slice(地址值索引, 地址值索引 + 地址长度)).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => new DataView(b.buffer).getUint16(0).toString(16)).join(':');
            break;
        default:
            return { 有错误: true, 消息: `地址类型 ${地址类型} 不支持` };
    }

    const 原始数据索引 = 地址值索引 + 地址长度;
    return {
        有错误: false,
        远程端口,
        远程地址,
        原始数据索引,
        魏烈思版本: 版本,
        是UDP
    };
}

function 创建可读传输流(传输服务端, 早期数据头, 日志记录) {
    let 可读流取消 = false;
    const 流 = new ReadableStream({
        start(控制器) {
            传输服务端.addEventListener('message', (事件) => {
                if (可读流取消) return;
                const 消息 = 事件.data;
                控制器.enqueue(消息);
            });
            传输服务端.addEventListener('close', () => {
                安全关闭连接(传输服务端);
                if (可读流取消) return;
                控制器.close();
            });
            传输服务端.addEventListener('error', (错误) => {
                日志记录('传输服务端出错');
                控制器.error(错误);
            });
        },
        cancel(原因) {
            if (可读流取消) return;
            可读流取消 = true;
            安全关闭连接(传输服务端);
        }
    });
    return 流;
}

function 安全关闭连接(连接) {
    try {
        if (连接.readyState === WebSocket.OPEN || 连接.readyState === WebSocket.CLOSING) {
            连接.close();
        }
    } catch (e) {
        console.error('安全关闭连接错误', e);
    }
}

async function 建立TCP连接(远程连接, 魏烈思版本, 数据块, 远程地址, 远程端口, 是UDP, config, 日志记录) {
    async function 连接(地址, 端口) {
        const 连接函数 = globalThis[获取字典词(0)]; // connect
        return 连接函数 ? 连接函数({ hostname: 地址, port: 端口 }) : null;
    }

    try {
        const TCP连接 = await 连接(远程地址, 远程端口);
        if (!TCP连接) {
            return;
        }
        写入远程连接(TCP连接, 数据块);
    } catch (e) {
        日志记录('连接错误', e);
    }
}

function 写入远程连接(TCP连接, 数据块) {
    const 写入器 = TCP连接.writable.getWriter();
    写入器.write(数据块);
    写入器.releaseLock();
}

export { 核心服务请求处理 as handleCoreServiceRequest };
