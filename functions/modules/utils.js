/**
 * 工具函数模块
 * 包含各种通用的辅助函数
 */

/**
 * 计算数据的简单哈希值，用于检测变更
 * @param {any} data - 要计算哈希的数据
 * @returns {string} - 数据的哈希值
 */
export function calculateDataHash(data) {
    const jsonString = JSON.stringify(data, Object.keys(data).sort());
    let hash = 0;
    for (let i = 0; i < jsonString.length; i++) {
        const char = jsonString.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // 转换为32位整数
    }
    return hash.toString();
}

/**
 * 检测数据是否发生变更
 * @param {any} oldData - 旧数据
 * @param {any} newData - 新数据
 * @returns {boolean} - 是否发生变更
 */
export function hasDataChanged(oldData, newData) {
    if (!oldData && !newData) return false;
    if (!oldData || !newData) return true;
    return calculateDataHash(oldData) !== calculateDataHash(newData);
}

/**
 * 条件性写入KV存储，只在数据真正变更时写入
 * @param {Object} env - Cloudflare环境对象
 * @param {string} key - KV键名
 * @param {any} newData - 新数据
 * @param {any} oldData - 旧数据（可选）
 * @returns {Promise<boolean>} - 是否执行了写入操作
 */
export async function conditionalKVPut(env, key, newData, oldData = null) {
    // 如果没有提供旧数据，先从KV读取
    if (oldData === null) {
        try {
            oldData = await env.MISUB_KV.get(key, 'json');
        } catch (error) {
            // 读取失败时，为安全起见执行写入
            await env.MISUB_KV.put(key, JSON.stringify(newData));
            return true;
        }
    }

    // 检测数据是否变更
    if (hasDataChanged(oldData, newData)) {
        await env.MISUB_KV.put(key, JSON.stringify(newData));
        return true;
    } else {
        return false;
    }
}

/**
 * 格式化字节数为人类可读的格式
 * @param {number} bytes - 字节数
 * @param {number} decimals - 小数位数
 * @returns {string} 格式化后的字符串
 */
export function formatBytes(bytes, decimals = 2) {
    if (!+bytes || bytes < 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    if (i < 0) return '0 B';
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * 检测字符串是否为有效的Base64格式
 * @param {string} str - 要检测的字符串
 * @returns {boolean} - 是否为有效Base64
 */
export function isValidBase64(str) {
    const cleanStr = str.replace(/\s/g, '');
    const base64Regex = /^[A-Za-z0-9+\/=]+$/;
    return base64Regex.test(cleanStr) && cleanStr.length > 20;
}

/**
 * 修复Clash配置中的WireGuard问题
 * @param {string} content - Clash配置内容
 * @returns {string} - 修复后的配置内容
 */
export function clashFix(content) {
    if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
        let lines;
        if (content.includes('\r\n')) {
            lines = content.split('\r\n');
        } else {
            lines = content.split('\n');
        }

        let result = "";
        for (let line of lines) {
            if (line.includes('type: wireguard')) {
                const 备改内容 = `, mtu: 1280, udp: true`;
                const 正确内容 = `, mtu: 1280, remote-dns-resolve: true, udp: true`;
                result += line.replace(new RegExp(备改内容, 'g'), 正确内容) + '\n';
            } else {
                result += line + '\n';
            }
        }
        return result;
    }
    return content;
}

import { SYSTEM_CONSTANTS } from './config.js';

/**
 * 根据客户端类型确定合适的用户代理
 * @param {string} originalUserAgent - 原始用户代理字符串
 * @returns {string} - 处理后的用户代理字符串
 */
export function getProcessedUserAgent(originalUserAgent, url = '') {
    if (!originalUserAgent) return originalUserAgent;

    // CF-Workers-SUB的精华策略：
    // 统一使用v2rayN UA获取订阅，绕过机场过滤同时保证获取完整节点
    return SYSTEM_CONSTANTS.FETCHER_USER_AGENT;
}

/**
 * 名称前缀辅助函数
 * @param {string} link - 节点链接
 * @param {string} prefix - 前缀文本
 * @returns {string} 添加前缀后的链接
 */
export function prependNodeName(link, prefix) {
    if (!prefix) return link;
    const appendToFragment = (baseLink, namePrefix) => {
        const hashIndex = baseLink.lastIndexOf('#');
        const originalName = hashIndex !== -1 ? decodeURIComponent(baseLink.substring(hashIndex + 1)) : '';
        const base = hashIndex !== -1 ? baseLink.substring(0, hashIndex) : baseLink;
        if (originalName.startsWith(namePrefix)) {
            return baseLink;
        }
        const newName = originalName ? `${namePrefix} - ${originalName}` : namePrefix;
        return `${base}#${encodeURIComponent(newName)}`;
    };
    if (link.startsWith('vmess://')) {
        try {
            const base64Part = link.substring('vmess://'.length);
            const binaryString = atob(base64Part);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const jsonString = new TextDecoder('utf-8').decode(bytes);
            const nodeConfig = JSON.parse(jsonString);
            const originalPs = nodeConfig.ps || '';
            if (!originalPs.startsWith(prefix)) {
                nodeConfig.ps = originalPs ? `${prefix} - ${originalPs}` : prefix;
            }
            const newJsonString = JSON.stringify(nodeConfig);
            const newBase64Part = btoa(unescape(encodeURIComponent(newJsonString)));
            return 'vmess://' + newBase64Part;
        } catch (e) {
            console.error("为 vmess 节点添加名称前缀失败，将回退到通用方法。", e);
            return appendToFragment(link, prefix);
        }
    }
    return appendToFragment(link, prefix);
}

/**
 * 创建带超时的请求
 * @param {RequestInfo} input - 请求输入
 * @param {RequestInit} init - 请求初始化选项
 * @param {number} timeout - 超时时间（毫秒）
 * @returns {Promise<Response>} 响应
 */
export function createTimeoutFetch(input, init = {}, timeout = 10000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const fetchPromise = fetch(new Request(input, {
        ...init,
        signal: controller.signal
    }));

    return fetchPromise.finally(() => {
        clearTimeout(timeoutId);
    });
}

/**
 * 带重试机制的请求函数
 * @param {RequestInfo} input - 请求输入
 * @param {RequestInit} init - 请求初始化选项
 * @param {Object} options - 选项
 * @param {number} options.maxRetries - 最大重试次数
 * @param {number} options.timeout - 每次请求超时时间
 * @param {number} options.baseDelay - 基础延迟时间
 * @returns {Promise<Response>} 响应
 */
export async function retryFetch(input, init = {}, options = {}) {
    const {
        maxRetries = 3,
        timeout = 10000,
        baseDelay = 1000
    } = options;

    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            return await createTimeoutFetch(input, init, timeout);
        } catch (error) {
            lastError = error;

            // 如果是最后一次尝试，直接抛出错误
            if (attempt === maxRetries) {
                throw error;
            }

            // 计算延迟时间（指数退避）
            const delay = baseDelay * Math.pow(2, attempt);
            console.warn(`[Retry] Request failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms:`, error.message);

            // 等待延迟
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    throw lastError;
}



/**
 * 安全的存储操作包装器
 * @param {Function} operation - 存储操作函数
 * @param {any} fallback - 操作失败时的默认返回值
 * @param {string} context - 操作上下文
 * @returns {Promise<any>} 操作结果
 */
export async function safeStorageOperation(operation, fallback = null, context = '') {
    try {
        return await operation();
    } catch (error) {
        console.error(`[Storage] ${context} failed:`, error);
        return fallback;
    }
}

/**
 * 通用日志函数
 * @param {string} level - 日志级别 (info, warn, error)
 * @param {string} message - 日志消息
 * @param {any} data - 附加数据
 */
export function log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        message,
        data
    };

    switch (level) {
        case 'info':
            console.info(`[${timestamp}] ${message}`, data);
            break;
        case 'warn':
            console.warn(`[${timestamp}] ${message}`, data);
            break;
        case 'error':
            console.error(`[${timestamp}] ${message}`, data);
            break;
        default:
            console.log(`[${timestamp}] ${message}`, data);
    }

    return logEntry;
}

/**
 * 获取回调令牌
 * @param {Object} env - Cloudflare环境对象
 * @returns {Promise<string>} 回调令牌
 */
export async function getCallbackToken(env) {
    const secret = env.COOKIE_SECRET || 'default-callback-secret';
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode('callback-static-data'));
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

/**
 * 处理配置的向后兼容性，确保新的前缀配置结构存在
 * @param {Object} config - 原始配置对象
 * @returns {Object} - 处理后的配置对象
 */
export function migrateConfigSettings(config) {
    const migratedConfig = { ...config };

    // [Fix] 强制转换为布尔值，防止 KV 中存储了字符串 "false" 导致判断错误
    const toBoolean = (val) => {
        if (typeof val === 'string') {
            return val.toLowerCase() === 'true';
        }
        return !!val;
    };

    if (migratedConfig.hasOwnProperty('enableAccessLog')) {
        migratedConfig.enableAccessLog = toBoolean(migratedConfig.enableAccessLog);
    }
    if (migratedConfig.hasOwnProperty('enableTrafficNode')) {
        migratedConfig.enableTrafficNode = toBoolean(migratedConfig.enableTrafficNode);
    }
    if (migratedConfig.hasOwnProperty('prependSubName')) {
        migratedConfig.prependSubName = toBoolean(migratedConfig.prependSubName);
    }


    // 如果没有新的 prefixConfig，但有老的 prependSubName，则创建默认的 prefixConfig
    if (!migratedConfig.prefixConfig) {
        const fallbackEnabled = migratedConfig.prependSubName ?? true;
        migratedConfig.prefixConfig = {
            enableManualNodes: fallbackEnabled,
            enableSubscriptions: fallbackEnabled,
            manualNodePrefix: '手动节点'
        };
    }

    // 确保 prefixConfig 的所有字段都存在
    if (!migratedConfig.prefixConfig.hasOwnProperty('enableManualNodes')) {
        migratedConfig.prefixConfig.enableManualNodes = migratedConfig.prependSubName ?? true;
    }
    if (!migratedConfig.prefixConfig.hasOwnProperty('enableSubscriptions')) {
        migratedConfig.prefixConfig.enableSubscriptions = migratedConfig.prependSubName ?? true;
    }
    if (!migratedConfig.prefixConfig.hasOwnProperty('manualNodePrefix')) {
        migratedConfig.prefixConfig.manualNodePrefix = '手动节点';
    }
    if (!migratedConfig.prefixConfig.hasOwnProperty('enableNodeEmoji')) {
        migratedConfig.prefixConfig.enableNodeEmoji = true;
    }

    // [Fix] Ensure prefixConfig booleans are also cleaning
    migratedConfig.prefixConfig.enableManualNodes = toBoolean(migratedConfig.prefixConfig.enableManualNodes);
    migratedConfig.prefixConfig.enableSubscriptions = toBoolean(migratedConfig.prefixConfig.enableSubscriptions);
    migratedConfig.prefixConfig.enableNodeEmoji = toBoolean(migratedConfig.prefixConfig.enableNodeEmoji);

    return migratedConfig;
}

/**
 * 创建标准JSON响应
 * @param {Object} data - 响应数据
 * @param {number} status - HTTP状态码
 * @param {Object} headers - 额外的HTTP头
 * @returns {Response}
 */
export function createJsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            ...headers
        }
    });
}

/**
 * 自定义 API 错误类
 */
export class APIError extends Error {
    constructor(message, status = 500, code = 'INTERNAL_ERROR', details = null) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.code = code;
        this.details = details;
    }
}

/**
 * 创建标准错误响应
 * @param {Error|string} error - 错误对象或错误消息
 * @param {number} status - HTTP状态码 (默认500)
 * @returns {Response}
 */
export function createErrorResponse(error, status = 500) {
    let message = 'Internal Server Error';
    let code = 'INTERNAL_ERROR';
    let details = null;

    if (error instanceof APIError) {
        status = error.status;
        message = error.message;
        code = error.code;
        details = error.details;
    } else if (error instanceof Error) {
        message = error.message;
    } else if (typeof error === 'string') {
        message = error;
    }

    return createJsonResponse({
        success: false,
        error: message,
        code,
        details
    }, status);
}

/**
 * MD5 implementation (Frontend Compatible)
 * Ported from src/utils/md5.js to ensure identical token generation.
 */
export function md5(string) {
    function rotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }
    function addUnsigned(lX, lY) {
        var lX4, lY4, lX8, lY8, lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        if (lX4 | lY4) {
            if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
        } else return (lResult ^ lX8 ^ lY8);
    }
    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }
    function FF(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function GG(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function HH(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function II(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function convertToWordArray(string) {
        var lWordCount;
        var lMessageLength = string.length;
        var lNumberOfWords_temp1 = lMessageLength + 8;
        var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        var lWordArray = Array(lNumberOfWords - 1);
        var lBytePosition = 0;
        var lByteCount = 0;
        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
    }
    function wordToHex(lValue) {
        var WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            WordToHexValue_temp = "0" + lByte.toString(16);
            WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
        }
        return WordToHexValue;
    }
    var x = Array();
    var k, AA, BB, CC, DD, a, b, c, d;
    var S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    var S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    var S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    var S41 = 6, S42 = 10, S43 = 15, S44 = 21;
    string = string || '';
    x = convertToWordArray(string);
    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
    for (k = 0; k < x.length; k += 16) {
        AA = a; BB = b; CC = c; DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x04881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }
    var temp = wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);
    return temp.toLowerCase();
}

export function doubleMD5(text) {
    return md5(md5(text).slice(7, 27)).toLowerCase();
}