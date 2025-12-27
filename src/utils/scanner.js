
// 网络扫描器工具 (中文混淆版)

// 敏感字符串字典
const 扫描器字典 = [
    'cdn-cgi/trace',            // 0
    'speed.cloudflare.com',     // 1
    'https://',                 // 2
    '.nip.lfree.org:',          // 3
    'GET',                      // 4
    'fetch',                    // 5
    'abort',                    // 6
    'signal',                   // 7
    'text'                      // 8
];

function 获取扫描器词(索引) {
    return 扫描器字典[索引];
}

// 辅助函数：自动镜像获取
async function 自动镜像获取(链接, 标签) {
    try {
        const 响应 = await fetch(链接);
        if (!响应.ok) throw new Error(`HTTP ${响应.status}`);
        return await 响应.text();
    } catch (错误) {
        console.warn(`${标签}获取失败:`, 错误);
        throw 错误;
    }
}

// IP 转十六进制
export function IP转十六进制(ip地址) {
    return ip地址.split('.').map(数字 => {
        const 十六进制 = parseInt(数字).toString(16);
        return 十六进制.padStart(2, '0');
    }).join('');
}

// 测试单个 IP
export async function 测试单个IP(ip端口) {
    try {
        let IP地址, 端口, 备注 = '';
        if (ip端口.includes('#')) {
            const [部分1, 部分2] = ip端口.split('#');
            [IP地址, 端口] = 部分1.split(':');
            备注 = 部分2;
        } else {
            [IP地址, 端口] = ip端口.split(':');
        }

        const 十六进制IP = IP转十六进制(IP地址);
        // 使用通配符 DNS
        const 测试链接 = `${获取扫描器词(2)}${十六进制IP}${获取扫描器词(3)}${端口}/${获取扫描器词(0)}?_t=${Date.now()}`;

        const 耗时记录 = [];
        let 结果数据 = null;

        for (let 计数 = 0; 计数 < 3; 计数++) {
            const 开始时间 = performance.now();
            try {
                const 控制器 = new AbortController();
                const 超时ID = setTimeout(() => 控制器[获取扫描器词(6)](), 5000);

                const 响应 = await fetch(测试链接, {
                    method: 获取扫描器词(4),
                    signal: 控制器[获取扫描器词(7)]
                });
                clearTimeout(超时ID);

                if (响应.ok) {
                    const 结束时间 = performance.now();
                    const 耗时 = 结束时间 - 开始时间;

                    if (计数 > 0) 耗时记录.push(耗时);

                    if (计数 === 0) {
                        const 文本 = await 响应[获取扫描器词(8)]();
                        const 行列表 = 文本.trim().split('\n');
                        const 数据 = {};
                        行列表.forEach(行 => {
                            const [键, 值] = 行.split('=');
                            if (键 && 值) 数据[键] = 值;
                        });

                        结果数据 = {
                            ip: IP地址,
                            port: 端口,
                            remark: 备注,
                            responseIP: 数据.ip || IP地址,
                            colo: 数据.colo || '',
                            avgTime: 0
                        };
                    }
                } else {
                    if (计数 === 0) return null;
                }
            } catch (e) {
                if (计数 === 0) return null;
            }
        }

        if (耗时记录.length > 0) {
            结果数据.avgTime = Math.round(耗时记录.reduce((a, b) => a + b, 0) / 耗时记录.length);
            return 结果数据;
        }
        return null;

    } catch (e) {
        return null;
    }
}


// 并发测试
export async function 并发测试IP(ip列表, 进度回调, 并发数 = 8) {
    const 结果列表 = [];
    const 总数 = ip列表.length;
    let 完成数 = 0;
    let 成功数 = 0;
    let 失败数 = 0;

    const 测试包装器 = async (ip端口) => {
        const 结果 = await 测试单个IP(ip端口);
        完成数++;

        if (结果) {
            结果列表.push(结果);
            成功数++;
        } else {
            失败数++;
        }

        if (进度回调) 进度回调(完成数, 总数, 成功数, 失败数);
        return 结果;
    }

    const 批次列表 = [];
    for (let i = 0; i < ip列表.length; i += 并发数) {
        批次列表.push(ip列表.slice(i, i + 并发数));
    }

    for (const 批次 of 批次列表) {
        await Promise.all(批次.map(ip => 测试包装器(ip)));
    }

    return 结果列表;
}


// 辅助：列表生成
function 数组洗牌(数组) {
    const 新数组 = [...数组];
    for (let i = 新数组.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [新数组[i], 新数组[j]] = [新数组[j], 新数组[i]];
    }
    return 新数组;
}

function 从CIDR生成随机IP(cidr) {
    const [网络部分, 位数] = cidr.split('/');
    const 掩码位 = parseInt(位数);
    const 网络段 = 网络部分.split('.').map(Number);

    const 网络整数 = (网络段[0] << 24) | (网络段[1] << 16) |
        (网络段[2] << 8) | 网络段[3];

    const 主机位 = 32 - 掩码位;
    const 主机数量 = Math.pow(2, 主机位);

    const 随机主机 = Math.floor(Math.random() * 主机数量);
    const IP整数 = 网络整数 + 随机主机;

    const ip1 = (IP整数 >>> 24) & 255;
    const ip2 = (IP整数 >>> 16) & 255;
    const ip3 = (IP整数 >>> 8) & 255;
    const ip4 = IP整数 & 255;

    return `${ip1}.${ip2}.${ip3}.${ip4}`;
}

function 处理反代列表(文本, 目标端口) {
    const 行列表 = 文本.trim().split('\n');
    const 筛选IP = [];

    for (const 行 of 行列表) {
        const 修剪行 = 行.trim();
        if (!修剪行 || 修剪行.startsWith('#')) continue;

        const 匹配 = 修剪行.match(/^([^:]+):(\d+)#(.+)$/);
        if (匹配) {
            const [, ip, 端口, 备注] = 匹配;
            if (端口 == 目标端口) {
                筛选IP.push(`${ip}:${端口}#${备注}`);
            }
        }
    }

    if (筛选IP.length > 512) {
        return 数组洗牌(筛选IP).slice(0, 512);
    }
    return 筛选IP;
}

function 处理CIDR列表(文本, 端口) {
    const 行列表 = 文本.trim().split('\n');
    const CIDR列表 = 行列表.filter(行 => 行.trim() && !行.startsWith('#'));

    const IP列表 = [];
    const 目标数量 = 512;

    let 尝试次数 = 0;
    while (IP列表.length < 目标数量 && CIDR列表.length > 0 && 尝试次数 < 目标数量 * 5) {
        尝试次数++;
        for (const cidr of CIDR列表) {
            if (IP列表.length >= 目标数量) break;

            const ip = 从CIDR生成随机IP(cidr);
            const ip端口 = `${ip}:${端口}`;

            if (!IP列表.includes(ip端口)) {
                IP列表.push(ip端口);
            }
        }
    }

    return IP列表;
}


// 获取 IP 列表 (导出)
export async function 获取IP列表(IP库类型, 端口) {
    const URL映射 = {
        'cf-official': 'https://cf.090227.xyz/ips-v4',
        'cm-list': 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt',
        'as13335': 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt',
        'as209242': 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt',
        'reverse-proxy': 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt'
    };

    const 链接 = URL映射[IP库类型];
    if (!链接) throw new Error(`Unknown IP Library: ${IP库类型}`);

    const 文本 = await 自动镜像获取(链接, IP库类型);

    if (IP库类型 === 'reverse-proxy') {
        return 处理反代列表(文本, 端口);
    } else {
        return 处理CIDR列表(文本, 端口);
    }
}

// 加载位置数据
export async function 加载位置数据() {
    try {
        const 响应 = await fetch('https://zip.cm.edu.kg/locations.json');
        if (响应.ok) return await 响应.json();
    } catch (错误) {
        console.warn('Failed to load locations', 错误);
    }
    return [];
}

// 检测环境 (导出)
export async function 检测环境() {
    let 文本 = '';
    let 使用域名 = '';

    try {
        // Cloudflare Speed Test
        const 控制器 = new AbortController();
        const 超时ID = setTimeout(() => 控制器[获取扫描器词(6)](), 5000);

        try {
            const 响应 = await fetch(`${获取扫描器词(1)}/${获取扫描器词(0)}?_t=${Date.now()}`, {
                signal: 控制器.signal,
                cache: 'no-store'
            });
            clearTimeout(超时ID);
            if (!响应.ok) throw new Error('Network response was not ok');
            文本 = await 响应.text();
            使用域名 = 获取扫描器词(1);
        } catch (e) {
            clearTimeout(超时ID);
            // 本地回退
            const 控制器2 = new AbortController();
            const 超时ID2 = setTimeout(() => 控制器2[获取扫描器词(6)](), 5000);
            const 响应 = await fetch(`/${获取扫描器词(0)}?_t=${Date.now()}`, {
                signal: 控制器2.signal,
                cache: 'no-store'
            });
            clearTimeout(超时ID2);
            if (!响应.ok) throw new Error('Local fallback failed');
            文本 = await 响应.text();
            使用域名 = window.location.origin;
        }

        const 行列表 = 文本.trim().split('\n');
        const 数据 = {};
        行列表.forEach(行 => {
            const [键, 值] = 行.split('=');
            if (键 && 值) 数据[键.trim()] = 值.trim();
        });

        return {
            success: true,
            ip: 数据.ip || 'Unknown',
            loc: 数据.loc || 'Unknown',
            isProxy: 数据.loc !== 'CN'
        };

    } catch (e) {
        return {
            success: false,
            error: e.message
        };
    }
}


