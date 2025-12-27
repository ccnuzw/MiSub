/**
 * 订阅请求处理模块
 * 处理MiSub订阅请求的主要逻辑
 */

import { StorageFactory } from '../storage-adapter.js';
import { migrateConfigSettings, formatBytes, getCallbackToken, doubleMD5 } from './utils.js';
import { generateCombinedNodeList } from '../services/subscription-service.js';
import { sendEnhancedTgNotification } from './notifications.js';
import { LogService } from '../services/log-service.js';
import { KV_KEY_SUBS, KV_KEY_PROFILES, KV_KEY_SETTINGS, DEFAULT_SETTINGS as defaultSettings } from './config.js';
import { renderDisguisePage } from './disguise-page.js';
import {
    generateCacheKey,
    getCache,
    setCache,
    triggerBackgroundRefresh,
    createCacheHeaders
} from '../services/node-cache-service.js';

/**
 * 处理MiSub订阅请求
 * @param {Object} context - Cloudflare上下文
 * @returns {Promise<Response>} HTTP响应
 */
export async function handleMisubRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const userAgentHeader = request.headers.get('User-Agent') || "Unknown";

    const storageAdapter = StorageFactory.createAdapter(env, await StorageFactory.getStorageType(env));
    const [settingsData, misubsData, profilesData] = await Promise.all([
        storageAdapter.get(KV_KEY_SETTINGS),
        storageAdapter.get(KV_KEY_SUBS),
        storageAdapter.get(KV_KEY_PROFILES)
    ]);
    const settings = settingsData || {};
    const allMisubs = misubsData || [];
    const allProfiles = profilesData || [];
    // 关键：我们在这里定义了 `config`，后续都应该使用它
    const config = migrateConfigSettings({ ...defaultSettings, ...settings });



    const isBrowser = /Mozilla|Chrome|Safari|Edge|Opera/i.test(userAgentHeader) &&
        !/clash|v2ray|surge|loon|shadowrocket|quantumult|stash|shadowsocks/i.test(userAgentHeader);

    // [Camouflage Logic Moved to Core Service]
    // subscription-handler.js now assumes that if a request reaches here,
    // it has passed the Core Service Guard (valid token/profile/admin).
    // The previous browser-check logic is deprecated in favor of the uniform Core Service Guard.

    let token = '';
    let profileIdentifier = null;
    let isLinkRequest = false;

    // [New] Handle /link/ vs /sub/ routes
    if (url.pathname.startsWith('/link')) {
        isLinkRequest = true;
        token = url.pathname.replace(/^\/link\/?/, '');
        // If token explicitly passed in query param, use that (edge case)
        if (!token) token = url.searchParams.get('token');
    } else {
        // [Fix] Correctly handle /sub vs /sub/... paths
        const cleanPath = url.pathname.replace(/^\/sub\/?/, '');
        const pathSegments = cleanPath ? cleanPath.split('/').filter(Boolean) : [];

        if (pathSegments.length > 0) {
            const firstSegment = pathSegments[0];
            if (pathSegments.length > 1) {
                const firstSeg = pathSegments[0];
                const secondSeg = pathSegments[1];

                if (firstSeg === config.profileToken) {
                    // Standard case: /sub/profiles/ID
                    token = firstSeg;
                    profileIdentifier = secondSeg;
                } else if (firstSeg === config.mytoken) {
                    // Admin token case? Currently not supported for 2 segments but preserving existing var assignment
                    token = firstSeg;
                    profileIdentifier = secondSeg;
                } else {
                    // Custom/Public case: /folder/profileID OR /profileID/filename

                    // 1. Check if the SECOND segment is a valid profile ID (e.g. /test1/work where work is ID)
                    const foundProfileSecond = allProfiles.find(p => (p.customId && p.customId === secondSeg) || p.id === secondSeg);

                    // 2. Check if the FIRST segment is a valid profile ID (e.g. /myprofile/clash where myprofile is ID)
                    const foundProfileFirst = allProfiles.find(p => (p.customId && p.customId === firstSeg) || p.id === firstSeg);

                    if (foundProfileSecond) {
                        // /anything/ID pattern
                        profileIdentifier = secondSeg;
                        token = config.profileToken;
                    } else if (foundProfileFirst) {
                        // /ID/anything pattern
                        profileIdentifier = firstSegment;
                        token = config.profileToken;
                    } else {
                        // Fallback to original behavior (likely invalid)
                        token = firstSegment;
                        profileIdentifier = secondSeg;
                    }
                }
            } else {
                // Check if it's the admin token
                if (firstSegment === config.mytoken) {
                    token = firstSegment;
                } else {
                    // Check if it matches a valid profile (Public Access)
                    const foundProfile = allProfiles.find(p => (p.customId && p.customId === firstSegment) || p.id === firstSegment);
                    if (foundProfile) {
                        // It is a profile! Shim the values to satisfy downstream logic
                        profileIdentifier = firstSegment;
                        token = config.profileToken;
                    } else {
                        token = firstSegment;
                    }
                }
            }
        } else {
            token = url.searchParams.get('token');
        }
    }

    let targetMisubs;
    let subName = config.FileName;
    let effectiveSubConverter;
    let effectiveSubConfig;
    let isProfileExpired = false; // Moved declaration here

    const DEFAULT_EXPIRED_NODE = `trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:443#${encodeURIComponent('您的订阅已失效')}`;

    if (isLinkRequest) {
        // [Core Service] Handle /link/ requests separately
        // Validate against sys_c_key ONLY
        const validCoreToken = config.sys_c_key ? doubleMD5(url.hostname + config.sys_c_key) : null;
        const validLocalhostToken = config.sys_c_key ? doubleMD5('localhost' + config.sys_c_key) : null;

        if (!token || (token !== validCoreToken && token !== validLocalhostToken)) {
            return new Response('Invalid Core Service Token', { status: 403 });
        }

        // Generate Self-Hosted Node (VLESS/Trojan)
        // Logic adapted from CoreServiceSettings.vue
        targetMisubs = [];
        const host = url.hostname;
        const uuid = config.sys_c_key;
        const path = config.sys_c_path || '/?ed=2048';
        const tlsFrag = config.sys_c_tls_frag ? `&fragment=${encodeURIComponent(config.sys_c_tls_frag === 'Happ' ? '3,1,tlshello' : '1,40-60,30-50,tlshello')}` : '';
        const allowInsecure = (config.sys_c_no_cert === true || config.sys_c_no_cert === 'true') ? '&allowInsecure=1' : '';
        const protocol = config.sys_c_protocol || 'vless';
        const ipMode = config.sys_c_ip_mode || 'local_random';

        // Helper to generate node link
        const generateLink = (address, port, alias) => {
            const finalAddress = address || host;
            const finalPort = port || 443;
            const finalAlias = alias ? encodeURIComponent(alias) : finalAddress;

            if (protocol.includes('vless')) {
                return `vless://${uuid}@${finalAddress}:${finalPort}?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&encryption=none${allowInsecure}#${finalAlias}`;
            } else if (protocol.includes('trojan')) {
                return `trojan://${uuid}@${finalAddress}:${finalPort}?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&encryption=none${allowInsecure}#${finalAlias}`;
            }
            return '';
        };

        // CIDR Random Generator Helper
        const generateRandomIP = () => {
            // Common Cloudflare CIDRs
            const cidrs = ['104.16.0.0/12', '172.64.0.0/13', '162.158.0.0/15', '198.41.0.0/16', '197.234.240.0/22'];
            const cidr = cidrs[Math.floor(Math.random() * cidrs.length)];
            const [network, bits] = cidr.split('/');
            const maskBits = parseInt(bits);
            const networkParts = network.split('.').map(Number);
            const networkInt = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
            const hostBits = 32 - maskBits;
            const hostCount = Math.pow(2, hostBits);
            const randomHost = Math.floor(Math.random() * hostCount);
            const ipInt = networkInt + randomHost;
            return `${(ipInt >>> 24) & 255}.${(ipInt >>> 16) & 255}.${(ipInt >>> 8) & 255}.${ipInt & 255}`;
        };

        // 1. Local KV Mode (User Defined List)
        if (ipMode === 'local_kv' && config.sys_c_ip_list) {
            const lines = config.sys_c_ip_list.split('\n');
            lines.forEach(line => {
                const cleanLine = line.trim();
                if (!cleanLine) return;
                // Format: IP:Port#Tag
                const [ipPart, tag] = cleanLine.split('#');
                const [ip, portStr] = ipPart.split(':');
                if (ip) {
                    const port = parseInt(portStr) || 443;
                    const link = generateLink(ip, port, tag || `Opt-${ip}`);
                    targetMisubs.push({ id: `core-opt-${ip}`, url: link, name: tag || `Opt-${ip}`, enabled: true });
                }
            });
        }
        else if (ipMode === 'local_random') {
            // 2. Local Random Mode
            const count = parseInt(config.sys_c_ip_count) || 16;
            const targetPort = config.sys_c_ip_port && config.sys_c_ip_port > 0 ? config.sys_c_ip_port : 443;
            for (let i = 0; i < count; i++) {
                const ip = generateRandomIP();
                const link = generateLink(ip, targetPort, `Random-${i + 1}`);
                targetMisubs.push({ id: `core-rand-${i}`, url: link, name: `Random-${i + 1}`, enabled: true });
            }
        }

        // Fallback: If targetMisubs is still empty (e.g. empty list or errors)
        if (targetMisubs.length === 0) {
            const link = generateLink(host, 443, 'Core Service Node');
            targetMisubs.push({ id: 'core-worker-node', url: link, name: 'Core Service Node', enabled: true });
        }

        subName = 'Core Service';
        effectiveSubConverter = config.subConverter;
        effectiveSubConfig = config.subConfig;

    } else if (profileIdentifier) {
        // [Fix] Allow Core Service Token (doubleMD5)
        // Also check against 'localhost' to handle Vite proxy scenarios where host is rewritten to 127.0.0.1
        const validCoreToken = config.sys_c_key ? doubleMD5(url.hostname + config.sys_c_key) : null;
        const validLocalhostToken = config.sys_c_key ? doubleMD5('localhost' + config.sys_c_key) : null;

        if (!token || (token !== config.profileToken && token !== validCoreToken && token !== validLocalhostToken)) {
            const debugInfo = {
                error: 'Invalid Profile Token',
                receivedToken: token,
                sys_c_key: config.sys_c_key || 'UNDEFINED',
                validCoreToken,
                validLocalhostToken,
                hostname: url.hostname
            };
            return new Response(JSON.stringify(debugInfo, null, 2), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        const profile = allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier);
        if (profile && profile.enabled) {
            // Check if the profile has an expiration date and if it's expired
            if (profile.expiresAt) {
                const expiryDate = new Date(profile.expiresAt);
                const now = new Date();
                if (now > expiryDate) {
                    isProfileExpired = true;
                }
            }

            if (isProfileExpired) {
                subName = profile.name; // Still use profile name for filename
                targetMisubs = [{ id: 'expired-node', url: DEFAULT_EXPIRED_NODE, name: '您的订阅已到期', isExpiredNode: true }]; // Set expired node as the only targetMisub
            } else {
                subName = profile.name;
                const profileSubIds = new Set(profile.subscriptions);
                const profileNodeIds = new Set(profile.manualNodes);
                targetMisubs = allMisubs.filter(item => {
                    const isSubscription = item.url.startsWith('http');
                    const isManualNode = !isSubscription;

                    // Check if the item belongs to the current profile and is enabled
                    const belongsToProfile = (isSubscription && profileSubIds.has(item.id)) || (isManualNode && profileNodeIds.has(item.id));
                    if (!item.enabled || !belongsToProfile) {
                        return false;
                    }
                    return true;
                });
            }
            effectiveSubConverter = profile.subConverter && profile.subConverter.trim() !== '' ? profile.subConverter : config.subConverter;
            effectiveSubConfig = profile.subConfig && profile.subConfig.trim() !== '' ? profile.subConfig : config.subConfig;

            // [新增] 增加订阅组下载计数
            // 仅在非回调请求时及非内部请求时增加计数(避免重复计数)
            // 且仅当开启访问日志时才计数
            const shouldSkipLogging = userAgentHeader.includes('MiSub-Backend') || userAgentHeader.includes('TelegramBot');
            if (!url.searchParams.has('callback_token') && !shouldSkipLogging && config.enableAccessLog) {
                try {
                    // 初始化下载计数(如果不存在)
                    if (typeof profile.downloadCount !== 'number') {
                        profile.downloadCount = 0;
                    }
                    // 增加计数
                    profile.downloadCount += 1;

                    // 更新存储中的订阅组数据
                    const updatedProfiles = allProfiles.map(p =>
                        ((p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier)
                            ? profile
                            : p
                    );

                    // 异步保存,不阻塞响应
                    context.waitUntil(
                        storageAdapter.put(KV_KEY_PROFILES, updatedProfiles)
                            .catch(err => console.error('[Download Count] Failed to update:', err))
                    );


                } catch (err) {
                    // 计数失败不影响订阅服务
                    console.error('[Download Count] Error:', err);
                }
            }
        } else {
            return new Response('Profile not found or disabled', { status: 404 });
        }
    } else {
        // [Correction] Use config variable + Support Core Service Token
        const validCoreToken = config.sys_c_key ? doubleMD5(url.hostname + config.sys_c_key) : null;
        const validLocalhostToken = config.sys_c_key ? doubleMD5('localhost' + config.sys_c_key) : null;

        if (!token || (token !== config.mytoken && token !== validCoreToken && token !== validLocalhostToken)) {
            const debugInfo = {
                error: 'Invalid Token',
                receivedToken: token,
                sys_c_key: config.sys_c_key || 'UNDEFINED',
                validCoreToken,
                validLocalhostToken,
                hostname: url.hostname
            };
            return new Response(JSON.stringify(debugInfo, null, 2), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        targetMisubs = allMisubs.filter(s => s.enabled);
        // [修正] 使用 config 變量
        effectiveSubConverter = config.subConverter;
        effectiveSubConfig = config.subConfig;
    }

    if (!effectiveSubConverter || effectiveSubConverter.trim() === '') {
        return new Response('Subconverter backend is not configured.', { status: 500 });
    }

    let targetFormat = url.searchParams.get('target');
    if (!targetFormat) {
        const supportedFormats = ['clash', 'singbox', 'surge', 'loon', 'base64', 'v2ray', 'trojan'];
        for (const format of supportedFormats) {
            if (url.searchParams.has(format)) {
                if (format === 'v2ray' || format === 'trojan') { targetFormat = 'base64'; } else { targetFormat = format; }
                break;
            }
        }
    }
    if (!targetFormat) {
        const ua = userAgentHeader.toLowerCase();
        // 使用陣列來保證比對的優先順序
        const uaMapping = [
            // Mihomo/Meta 核心的客戶端 - 需要clash格式
            ['flyclash', 'clash'],
            ['mihomo', 'clash'],
            ['clash.meta', 'clash'],
            ['clash-verge', 'clash'],
            ['meta', 'clash'],

            // 其他客戶端
            ['stash', 'clash'],
            ['nekoray', 'clash'],
            ['sing-box', 'singbox'],
            ['shadowrocket', 'base64'],
            ['v2rayn', 'base64'],
            ['v2rayng', 'base64'],
            ['surge', 'surge'],
            ['loon', 'loon'],
            ['quantumult%20x', 'quanx'],
            ['quantumult', 'quanx'],

            // 最後才匹配通用的 clash，作為向下相容
            ['clash', 'clash']
        ];

        for (const [keyword, format] of uaMapping) {
            if (ua.includes(keyword)) {
                targetFormat = format;
                break; // 找到第一個符合的就停止
            }
        }
    }
    if (!targetFormat) { targetFormat = 'base64'; }

    // [Log Deduplication] Skip logging for internal backend requests and Telegram bots
    const shouldSkipLogging = userAgentHeader.includes('MiSub-Backend') || userAgentHeader.includes('TelegramBot');

    if (!url.searchParams.has('callback_token') && !shouldSkipLogging && config.enableAccessLog) {
        const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
        const country = request.headers.get('CF-IPCountry') || 'N/A';
        const domain = url.hostname;

        let additionalData = `*域名:* \`${domain}\`\n*客户端:* \`${userAgentHeader}\`\n*请求格式:* \`${targetFormat}\``;

        if (profileIdentifier) {
            additionalData += `\n*订阅组:* \`${subName}\``;
            const profile = allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier);
            if (profile && profile.expiresAt) {
                const expiryDateStr = new Date(profile.expiresAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
                additionalData += `\n*到期时间:* \`${expiryDateStr}\``;
            }
        }

        // 使用增强版TG通知，包含IP地理位置信息
        context.waitUntil(sendEnhancedTgNotification(config, '🛰️ *订阅被访问*', clientIp, additionalData));

        // [Log Deduplication]
        // Removed the premature LogService.addLog here.
        // We will pass the log metadata to generateCombinedNodeList (or log manually for cache hits)
        // to ensure we have the correct stats and avoid duplicates.
    }

    let prependedContentForSubconverter = '';

    if (isProfileExpired) { // Use the flag set earlier
        prependedContentForSubconverter = ''; // Expired node is now in targetMisubs
    } else {
        // Otherwise, add traffic remaining info if applicable
        const totalRemainingBytes = targetMisubs.reduce((acc, sub) => {
            if (sub.enabled && sub.userInfo && sub.userInfo.total > 0) {
                const used = (sub.userInfo.upload || 0) + (sub.userInfo.download || 0);
                const remaining = sub.userInfo.total - used;
                return acc + Math.max(0, remaining);
            }
            return acc;
        }, 0);
        if (config.enableTrafficNode !== false && totalRemainingBytes > 0) {
            const formattedTraffic = formatBytes(totalRemainingBytes);
            const fakeNodeName = `流量剩余 ≫ ${formattedTraffic}`;
            prependedContentForSubconverter = `trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:443#${encodeURIComponent(fakeNodeName)}`;
        }
    }

    // === 缓存机制：快速响应客户端请求 ===
    const cacheKey = generateCacheKey(
        profileIdentifier ? 'profile' : 'token',
        profileIdentifier || token
    );

    // 检查是否强制刷新（通过 URL 参数）
    const forceRefresh = url.searchParams.has('refresh') || url.searchParams.has('nocache');

    // 获取缓存状态
    const { data: cachedData, status: cacheStatus } = forceRefresh
        ? { data: null, status: 'miss' }
        : await getCache(storageAdapter, cacheKey);

    let combinedNodeList;
    let cacheHeaders = {};

    // 定义刷新函数（用于后台刷新）
    const refreshNodes = async (isBackground = false) => {
        const isDebugToken = (token === 'b0b422857bb46aba65da8234c84f38c6');
        // 组合节点列表
        // 传递 context 对象以获取请求信息用于日志记录
        context.startTime = Date.now();

        // Prepare log metadata to pass down
        const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
        const country = request.headers.get('CF-IPCountry') || 'N/A';
        const domain = url.hostname;

        context.logMetadata = {
            clientIp,
            geoInfo: { country, city: request.cf?.city, isp: request.cf?.asOrganization, asn: request.cf?.asn },
            format: targetFormat,
            token: profileIdentifier ? (profileIdentifier) : token,
            type: profileIdentifier ? 'profile' : 'token',
            domain
        };

        const currentProfile = profileIdentifier ? allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier) : null;
        const generationSettings = {
            ...(currentProfile?.prefixSettings || {}),
            name: subName
        };

        const freshNodes = await generateCombinedNodeList(
            context, // 传入完整 context
            { ...config, enableAccessLog: false }, // [Deferred Logging] Disable service-side logging, we will log manually in handler
            userAgentHeader,
            targetMisubs,
            prependedContentForSubconverter,
            generationSettings,
            isDebugToken
        );
        const sourceNames = targetMisubs
            .filter(s => s.url.startsWith('http'))
            .map(s => s.name || s.url);
        await setCache(storageAdapter, cacheKey, freshNodes, sourceNames);
        return freshNodes;
    };

    if (cacheStatus === 'fresh' && cachedData) {
        // 缓存新鲜：直接返回（当前策略下不会触发，因为 FRESH_TTL=0）

        combinedNodeList = cachedData.nodes;
        cacheHeaders = createCacheHeaders('HIT', cachedData.nodeCount);

        combinedNodeList = cachedData.nodes;
        cacheHeaders = createCacheHeaders('HIT', cachedData.nodeCount);

        // [Stats Export] Populate generation stats from cache for deferred logging
        if (context) {
            context.generationStats = {
                totalNodes: cachedData.nodeCount || 0,
                sourceCount: targetMisubs.length,
                successCount: cachedData.nodeCount || 0,
                failCount: 0,
                duration: 0
            };
        }
    } else if ((cacheStatus === 'stale' || cacheStatus === 'expired') && cachedData) {
        // 有缓存：立即返回缓存数据，同时后台刷新确保下次获取最新

        combinedNodeList = cachedData.nodes;
        cacheHeaders = createCacheHeaders(`REFRESHING`, cachedData.nodeCount);
        // 触发后台刷新，确保缓存始终是最新的
        triggerBackgroundRefresh(context, () => refreshNodes(true));

        // 触发后台刷新，确保缓存始终是最新的
        triggerBackgroundRefresh(context, () => refreshNodes(true));

        // [Stats Export] Populate generation stats from cache for deferred logging
        if (context) {
            context.generationStats = {
                totalNodes: cachedData.nodeCount || 0,
                sourceCount: targetMisubs.length,
                successCount: cachedData.nodeCount || 0,
                failCount: 0,
                duration: 0
            };
        }
    } else {
        // 无缓存（首次访问或缓存已过期）：同步获取并缓存

        combinedNodeList = await refreshNodes(false);
        cacheHeaders = createCacheHeaders('MISS', combinedNodeList.split('\n').filter(l => l.trim()).length);
    }

    if (targetFormat === 'base64') {
        let contentToEncode;
        if (isProfileExpired) {
            contentToEncode = DEFAULT_EXPIRED_NODE + '\n';
        } else {
            contentToEncode = combinedNodeList;
        }
        const headers = { "Content-Type": "text/plain; charset=utf-8", 'Cache-Control': 'no-store, no-cache' };
        Object.entries(cacheHeaders).forEach(([key, value]) => {
            headers[key] = value;
        });

        // [Deferred Logging] Log Success for Base64 (Direct Return)
        if (!url.searchParams.has('callback_token') && !shouldSkipLogging && config.enableAccessLog) {
            const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
            const country = request.headers.get('CF-IPCountry') || 'N/A';
            const domain = url.hostname;
            const stats = context.generationStats || {};

            context.waitUntil(LogService.addLog(env, {
                profileName: subName || 'Unknown Profile',
                clientIp,
                geoInfo: { country, city: request.cf?.city, isp: request.cf?.asOrganization, asn: request.cf?.asn },
                userAgent: userAgentHeader || 'Unknown',
                status: 'success',
                format: targetFormat,
                token: profileIdentifier ? (profileIdentifier) : token,
                type: profileIdentifier ? 'profile' : 'token',
                domain,
                details: {
                    totalNodes: stats.totalNodes || 0,
                    sourceCount: stats.sourceCount || 0,
                    successCount: stats.successCount || 0,
                    failCount: stats.failCount || 0,
                    duration: stats.duration || 0
                },
                summary: `生成 ${stats.totalNodes || 0} 个节点 (成功: ${stats.successCount || 0}, 失败: ${stats.failCount || 0})`
            }));
        }

        return new Response(btoa(unescape(encodeURIComponent(contentToEncode))), { headers });
    }

    const base64Content = btoa(unescape(encodeURIComponent(combinedNodeList)));

    const callbackToken = await getCallbackToken(env);
    const callbackPath = profileIdentifier ? `/${token}/${profileIdentifier}` : `/${token}`;
    const callbackUrl = `${url.protocol}//${url.host}${callbackPath}?target=base64&callback_token=${callbackToken}`;
    if (url.searchParams.get('callback_token') === callbackToken) {
        const headers = { "Content-Type": "text/plain; charset=utf-8", 'Cache-Control': 'no-store, no-cache' };
        return new Response(base64Content, { headers });
    }

    const subconverterUrl = new URL(`https://${effectiveSubConverter}/sub`);
    subconverterUrl.searchParams.set('target', targetFormat);
    subconverterUrl.searchParams.set('url', callbackUrl);
    subconverterUrl.searchParams.set('scv', 'true');
    subconverterUrl.searchParams.set('udp', 'true');
    if ((targetFormat === 'clash' || targetFormat === 'loon' || targetFormat === 'surge') && effectiveSubConfig && effectiveSubConfig.trim() !== '') {
        subconverterUrl.searchParams.set('config', effectiveSubConfig);
    }
    subconverterUrl.searchParams.set('new_name', 'true');

    try {
        const subconverterResponse = await fetch(subconverterUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MiSub-Backend)' },
        });
        if (!subconverterResponse.ok) {
            const errorBody = await subconverterResponse.text();
            throw new Error(`Subconverter service returned status: ${subconverterResponse.status}. Body: ${errorBody}`);
        }
        const responseText = await subconverterResponse.text();

        const responseHeaders = new Headers(subconverterResponse.headers);
        responseHeaders.set("Content-Disposition", `attachment; filename*=utf-8''${encodeURIComponent(subName)}`);
        responseHeaders.set('Content-Type', 'text/plain; charset=utf-8');
        responseHeaders.set('Cache-Control', 'no-store, no-cache');

        // 添加缓存状态头
        Object.entries(cacheHeaders).forEach(([key, value]) => {
            responseHeaders.set(key, value);
        });

        // [Deferred Logging] Log Success for Subconverter
        if (!url.searchParams.has('callback_token') && !shouldSkipLogging && config.enableAccessLog) {
            const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
            const country = request.headers.get('CF-IPCountry') || 'N/A';
            const domain = url.hostname;
            const stats = context.generationStats || {};

            context.waitUntil(LogService.addLog(env, {
                profileName: subName || 'Unknown Profile',
                clientIp,
                geoInfo: { country, city: request.cf?.city, isp: request.cf?.asOrganization, asn: request.cf?.asn },
                userAgent: userAgentHeader || 'Unknown',
                status: 'success',
                format: targetFormat,
                token: profileIdentifier ? (profileIdentifier) : token,
                type: profileIdentifier ? 'profile' : 'token',
                domain,
                details: {
                    totalNodes: stats.totalNodes || 0,
                    sourceCount: stats.sourceCount || 0,
                    successCount: stats.successCount || 0,
                    failCount: stats.failCount || 0,
                    duration: stats.duration || 0
                },
                summary: `生成 ${stats.totalNodes || 0} 个节点 (成功: ${stats.successCount || 0}, 失败: ${stats.failCount || 0})`
            }));
        }

        return new Response(responseText, { status: subconverterResponse.status, statusText: subconverterResponse.statusText, headers: responseHeaders });
    } catch (error) {
        console.error(`[MiSub Final Error] ${error.message}`);

        // [Deferred Logging] Log Error for Subconverter Failures (Timeout/Error)
        if (!url.searchParams.has('callback_token') && !shouldSkipLogging && config.enableAccessLog) {
            const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
            const country = request.headers.get('CF-IPCountry') || 'N/A';
            const domain = url.hostname;
            const stats = context.generationStats || {}; // We might have stats even if conversion failed

            context.waitUntil(LogService.addLog(env, {
                profileName: subName || 'Unknown Profile',
                clientIp,
                geoInfo: { country, city: request.cf?.city, isp: request.cf?.asOrganization, asn: request.cf?.asn },
                userAgent: userAgentHeader || 'Unknown',
                status: 'error',
                format: targetFormat,
                token: profileIdentifier ? (profileIdentifier) : token,
                type: profileIdentifier ? 'profile' : 'token',
                domain,
                details: {
                    totalNodes: stats.totalNodes || 0,
                    sourceCount: stats.sourceCount || 0,
                    successCount: stats.successCount || 0,
                    failCount: stats.failCount || 0,
                    duration: stats.duration || 0,
                    error: error.message
                },
                summary: `转换失败: ${error.message}`
            }));
        }

        return new Response(`Error connecting to subconverter: ${error.message}`, { status: 502 });
    }
}
