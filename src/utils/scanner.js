
// Wrapper for fetch to handle mirrors or fallbacks if needed
// Simplified version of fetchWithAutoMirror from original project
async function fetchWithAutoMirror(url, label) {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.text();
    } catch (e) {
        // Fallback logic could be added here if we knew the mirrors
        // The original project defined urlMap with direct links, so fetchWithAutoMirror likely tried mirror domains.
        // For now, we use direct fetch.
        console.warn(`Fetch failed for ${label}:`, e);
        throw e;
    }
}

// IP to Hex conversion for test URL
export function ipToHex(ip) {
    return ip.split('.').map(num => {
        const hex = parseInt(num).toString(16);
        return hex.padStart(2, '0');
    }).join('');
}

// Test a single IP
export async function testSingleIP(ipWithPort) {
    try {
        // Parse IP and Port
        let ip, port, remark = '';
        if (ipWithPort.includes('#')) {
            const [ipPort, remarkPart] = ipWithPort.split('#');
            [ip, port] = ipPort.split(':');
            remark = remarkPart;
        } else {
            [ip, port] = ipWithPort.split(':');
        }

        // Convert to Hex
        const hexIP = ipToHex(ip);
        // Using nip.lfree.org for wildcard DNS resolution
        const testUrl = `https://${hexIP}.nip.lfree.org:${port}/cdn-cgi/trace?_t=${Date.now()}`;

        // Test 3 times, average last 2
        const times = [];
        let resultData = null;

        for (let i = 0; i < 3; i++) {
            const start = performance.now();
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

                const response = await fetch(testUrl, {
                    method: 'GET',
                    signal: controller.signal
                });
                clearTimeout(timeoutId);

                if (response.ok) {
                    const end = performance.now();
                    const time = end - start;

                    if (i > 0) times.push(time);

                    if (i === 0) {
                        const text = await response.text();
                        const lines = text.trim().split('\n');
                        const data = {};
                        lines.forEach(line => {
                            const [key, value] = line.split('=');
                            if (key && value) data[key] = value;
                        });

                        resultData = {
                            ip: ip,
                            port: port,
                            remark: remark,
                            responseIP: data.ip || ip,
                            colo: data.colo || '',
                            avgTime: 0
                        };
                    }
                } else {
                    if (i === 0) return null; // Logic from original: fail on first try = fail
                }
            } catch (e) {
                if (i === 0) return null;
            }
        }

        if (times.length > 0) {
            resultData.avgTime = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
            return resultData;
        }
        return null;

    } catch (e) {
        return null;
    }
}


// Concurrent Testing
// onProgress(completed, total, success, fail)
export async function testIPsConcurrent(ips, onProgress, concurrency = 8) {
    const results = [];
    const total = ips.length;
    let completedCount = 0;
    let successCount = 0;
    let failCount = 0;

    const testIPWrapper = async (ipWithPort) => {
        const result = await testSingleIP(ipWithPort);
        completedCount++;

        if (result) {
            results.push(result);
            successCount++;
        } else {
            failCount++;
        }

        if (onProgress) onProgress(completedCount, total, successCount, failCount);
        return result;
    }

    // Batching
    const batches = [];
    for (let i = 0; i < ips.length; i += concurrency) {
        batches.push(ips.slice(i, i + concurrency));
    }

    for (const batch of batches) {
        await Promise.all(batch.map(ip => testIPWrapper(ip)));
    }

    return results;
}


// Helpers for List Generation
function shuffleArray(array) {
    const newArray = [...array];
    for (let i = newArray.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
    }
    return newArray;
}

function generateRandomIPFromCIDR(cidr) {
    const [network, bits] = cidr.split('/');
    const maskBits = parseInt(bits);
    const networkParts = network.split('.').map(Number);

    // Calculate network address
    const networkInt = (networkParts[0] << 24) | (networkParts[1] << 16) |
        (networkParts[2] << 8) | networkParts[3];

    // Host bits
    const hostBits = 32 - maskBits;
    const hostCount = Math.pow(2, hostBits);

    // Random host
    const randomHost = Math.floor(Math.random() * hostCount);
    const ipInt = networkInt + randomHost;

    // Convert back
    const ip1 = (ipInt >>> 24) & 255;
    const ip2 = (ipInt >>> 16) & 255;
    const ip3 = (ipInt >>> 8) & 255;
    const ip4 = ipInt & 255;

    return `${ip1}.${ip2}.${ip3}.${ip4}`;
}

function processReverseProxyList(text, targetPort) {
    const lines = text.trim().split('\n');
    const filteredIPs = [];

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        // Format: IP:PORT#Remark
        const match = trimmed.match(/^([^:]+):(\d+)#(.+)$/);
        if (match) {
            const [, ip, linePort, remark] = match;
            if (linePort == targetPort) { // Loose equality for string/number match
                filteredIPs.push(`${ip}:${linePort}#${remark}`);
            }
        }
    }

    if (filteredIPs.length > 512) {
        return shuffleArray(filteredIPs).slice(0, 512);
    }
    return filteredIPs;
}

function processCIDRList(text, port) {
    const lines = text.trim().split('\n');
    const cidrs = lines.filter(line => line.trim() && !line.startsWith('#'));

    const ips = [];
    const targetCount = 512;

    // Attempt to generate up to targetCount unique IPs
    // Safety break to prevent infinite loops if CIDR small
    let attempts = 0;
    while (ips.length < targetCount && cidrs.length > 0 && attempts < targetCount * 5) {
        attempts++;
        for (const cidr of cidrs) {
            if (ips.length >= targetCount) break;

            const ip = generateRandomIPFromCIDR(cidr);
            const ipWithPort = `${ip}:${port}`;

            if (!ips.includes(ipWithPort)) {
                ips.push(ipWithPort);
            }
        }
    }

    return ips;
}


// Main Get List Function
export async function getIPList(ipLibrary, port) {
    const urlMap = {
        'cf-official': 'https://cf.090227.xyz/ips-v4',
        'cm-list': 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt',
        'as13335': 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt',
        'as209242': 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt',
        'reverse-proxy': 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt'
    };

    const url = urlMap[ipLibrary];
    if (!url) throw new Error(`Unknown IP Library: ${ipLibrary}`);

    const text = await fetchWithAutoMirror(url, ipLibrary);

    if (ipLibrary === 'reverse-proxy') {
        return processReverseProxyList(text, port);
    } else {
        return processCIDRList(text, port);
    }
}

// Load Locations Data (Used for mapping Colo to Location)
export async function loadLocationsData() {
    // Basic implementation - fetch from the same source as original
    // "https://zip.cm.edu.kg/locations.json" is backup
    // Original used window.detectDomain + '/locations'
    // We will try backup first or just return empty for now if not critical
    // Or try checking if we can fetch from current origin?
    // Since this is generic utility, let's try the public one.

    try {
        const res = await fetch('https://zip.cm.edu.kg/locations.json');
        if (res.ok) return await res.json();
    } catch (e) {
        console.warn('Failed to load locations', e);
    }
    return [];
}

// Detect Environment (Proxy Check)
export async function detectEnvironment() {
    let text = '';
    let usedDomain = '';

    try {
        // Try Cloudflare Speed Test URL first (timeout 5s)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        try {
            const res = await fetch(`https://speed.cloudflare.com/cdn-cgi/trace?_t=${Date.now()}`, {
                signal: controller.signal,
                cache: 'no-store'
            });
            clearTimeout(timeoutId);
            if (!res.ok) throw new Error('Network response was not ok');
            text = await res.text();
            usedDomain = 'https://speed.cloudflare.com';
        } catch (e) {
            clearTimeout(timeoutId);
            console.warn('Primary trace failed, trying local fallback', e);
            // Fallback to local /cdn-cgi/trace
            const controller2 = new AbortController();
            const timeoutId2 = setTimeout(() => controller2.abort(), 5000);
            const res = await fetch(`/cdn-cgi/trace?_t=${Date.now()}`, {
                signal: controller2.signal,
                cache: 'no-store'
            });
            clearTimeout(timeoutId2);
            if (!res.ok) throw new Error('Local fallback failed');
            text = await res.text();
            usedDomain = window.location.origin;
        }

        // Parse Trace
        const lines = text.trim().split('\n');
        const data = {};
        lines.forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) data[key.trim()] = value.trim();
        });

        return {
            success: true,
            ip: data.ip || 'Unknown',
            loc: data.loc || 'Unknown',
            isProxy: data.loc !== 'CN' // Simple heuristic from original project
        };

    } catch (e) {
        return {
            success: false,
            error: e.message
        };
    }
}

