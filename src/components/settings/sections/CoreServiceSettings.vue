<script setup>
import { ref, computed } from 'vue';
import md5 from '@/utils/md5';
import Modal from '../../forms/Modal.vue';

const props = defineProps({
  settings: {
    type: Object,
    required: true
  }
});

// Tabs configuration
const tabs = [
  { id: 'overlay', name: '伪装设置', icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z', safeLabel: 'Site Overlay' },
  { id: 'core', name: '核心配置', icon: 'M13 10V3L4 14h7v7l9-11h-7z', safeLabel: 'Service Core' },
  { id: 'network', name: '网络加速', icon: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064', safeLabel: 'Network' },
  { id: 'optimization', name: '优选设置', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10', safeLabel: 'Preferences' },
  { id: 'preview', name: '配置预览', icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z', safeLabel: 'Preview' }
];

const currentTab = ref('overlay');
const showOnlineOpt = ref(false);
const showOptApi = ref(false);

// Ensure default values exist in settings objects
if (!props.settings.sys_c_mode) props.settings.sys_c_mode = 'nginx'; // Default to Safest
if (!props.settings.sys_c_key) props.settings.sys_c_key = crypto.randomUUID(); // Default to random UUID
if (!props.settings.sys_c_path) props.settings.sys_c_path = '/?ed=2048'; // Default path
if (!props.settings.sys_c_protocol) props.settings.sys_c_protocol = 'vless'; // Default protocol

// Status indicator color
const statusColor = computed(() => {
    return props.settings.sys_c_enabled !== false ? 'bg-green-500' : 'bg-gray-400';
});

const statusText = computed(() => {
    return props.settings.sys_c_enabled !== false ? 'Service Active (Camouflage On)' : 'Service Suspended';
});

const generateNewKey = () => {
    props.settings.sys_c_key = crypto.randomUUID();
};

// Initialize new defaults
if (!props.settings.sys_c_cdn_mode) props.settings.sys_c_cdn_mode = 'direct';
if (!props.settings.sys_c_proxy_mode) props.settings.sys_c_proxy_mode = 'auto';
if (!props.settings.sys_c_ip_list) props.settings.sys_c_ip_list = '';
if (props.settings.sys_c_global === undefined) props.settings.sys_c_global = false;
if (!props.settings.sys_c_ip_count) props.settings.sys_c_ip_count = 16;
if (props.settings.sys_c_ip_port === undefined) props.settings.sys_c_ip_port = -1;

// Advanced Tools & Generator Defaults
if (!props.settings.sys_c_cf_email) props.settings.sys_c_cf_email = '';
if (!props.settings.sys_c_cf_key) props.settings.sys_c_cf_key = '';
if (!props.settings.sys_c_cf_acc_id) props.settings.sys_c_cf_acc_id = '';
if (!props.settings.sys_c_cf_token) props.settings.sys_c_cf_token = '';
if (!props.settings.sys_c_opt_api) props.settings.sys_c_opt_api = '';
if (!props.settings.sys_c_sub_url) props.settings.sys_c_sub_url = '';

function doubleMD5(text) {
    return md5(md5(text).slice(7, 27)).toLowerCase();
}

const computedNodeLink = computed(() => {
    const host = window.location.hostname;
    const uuid = props.settings.sys_c_key;
    const path = props.settings.sys_c_path;
    const tlsFrag = props.settings.sys_c_tls_frag ? `&fragment=${encodeURIComponent(props.settings.sys_c_tls_frag === 'Happ' ? '3,1,tlshello' : '1,40-60,30-50,tlshello')}` : '';
    const allowInsecure = props.settings.sys_c_no_cert ? '&allowInsecure=1' : '';
    
    const protocol = props.settings.sys_c_protocol || 'vless';
    const lines = [];

    if (protocol.includes('vless')) {
        lines.push(`vless://${uuid}@${host}:443?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&encryption=none${allowInsecure}#${host}`);
    }
    if (protocol.includes('trojan')) {
         lines.push(`trojan://${uuid}@${host}:443?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&encryption=none${allowInsecure}#${host}`);
    }
    return lines.join('\n\n');
});

const computedSubLink = computed(() => {
    const host = window.location.hostname;
    const token = doubleMD5(host + props.settings.sys_c_key);
    return `https://${host}/sub?token=${token}`;
});

import { getIPList, testIPsConcurrent, loadLocationsData, detectEnvironment } from '@/utils/scanner';

// State for Online Optimization
const optimizeState = ref({
    running: false,
    progress: { completed: 0, total: 0, success: 0, fail: 0 },
    results: [], // Array of {ip, port, remark, avgTime, colo}
    library: 'cf-official',
    port: 443,
    concurrency: 8
});

const optEnv = ref({
    checking: false,
    ip: '',
    loc: '',
    isProxy: false,
    error: null
});

// Open Modal and Check Env
const openOnlineOptModal = async () => {
    showOnlineOpt.value = true;
    optEnv.value = { checking: true, ip: '', loc: '', isProxy: false, error: null };
    
    // Reset state
    optimizeState.value.results = [];
    optimizeState.value.progress = { completed: 0, total: 0, success: 0, fail: 0 };
    
    const env = await detectEnvironment();
    optEnv.value.checking = false;
    
    if (env.success) {
        optEnv.value.ip = env.ip;
        optEnv.value.loc = env.loc;
        optEnv.value.isProxy = env.isProxy;
    } else {
        optEnv.value.error = env.error;
    }
};

// State for API Optimization
const apiState = ref({
    url: '',
    port: 443,
    verifying: false
});


const startOptimize = async () => {
    optimizeState.value.running = true;
    optimizeState.value.results = [];
    optimizeState.value.progress = { completed: 0, total: 0, success: 0, fail: 0 };
    
    try {
        const ips = await getIPList(optimizeState.value.library, optimizeState.value.port);
        optimizeState.value.progress.total = ips.length;
        
        await testIPsConcurrent(ips, (completed, total, success, fail) => {
            optimizeState.value.progress = { completed, total, success, fail };
        }, optimizeState.value.concurrency).then(results => {
             optimizeState.value.results = results.sort((a, b) => a.avgTime - b.avgTime);
        });
        
    } catch (e) {
        alert('Optimization failed: ' + e.message);
    } finally {
        optimizeState.value.running = false;
    }
};

const saveOptimizeParams = (mode) => { // mode: 'override' or 'append'
    if (optimizeState.value.results.length === 0) return;
    
    // Format: IP:Port#Remark (Top 16)
    const topIPs = optimizeState.value.results.slice(0, 16);
    const content = topIPs.map(r => `${r.ip}:${r.port}#${r.remark || 'OPT'} ${r.avgTime}ms`).join('\n');
    
    if (mode === 'override') {
        props.settings.sys_c_ip_list = content;
    } else {
        props.settings.sys_c_ip_list = (props.settings.sys_c_ip_list ? props.settings.sys_c_ip_list + '\n' : '') + content;
    }
    showOnlineOpt.value = false;
};


const verifyAndAddApi = async () => {
    if (!apiState.value.url) return;
    apiState.value.verifying = true;
    
    try {
        const url = `/admin/getADDAPI?url=${encodeURIComponent(apiState.value.url)}&port=${apiState.value.port}`;
        // Since we are frontend, we call the Worker endpoint.
        // Assuming current domain serves the worker API.
        const res = await fetch(url);
        const data = await res.json();
        
        if (data.success && Array.isArray(data.data)) {
            // Append IPs
            const newContent = data.data.join('\n');
            props.settings.sys_c_ip_list = (props.settings.sys_c_ip_list ? props.settings.sys_c_ip_list + '\n' : '') + newContent;
            showOptApi.value = false;
            alert(`Added ${data.data.length} IPs.`);
        } else {
            throw new Error(data.msg || 'Verification failed');
        }
    } catch (e) {
        alert('API Error: ' + e.message);
    } finally {
        apiState.value.verifying = false;
    }
};
</script>

<template>
  <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
    <!-- Header / Status Bar -->
    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 flex justify-between items-center">
        <div>
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">
                核心服务 (Core Service)
            </h3>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                管理网络接入与其伪装表现
            </p>
        </div>
        <div class="flex items-center gap-3">
            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                <span class="w-1.5 h-1.5 rounded-full" :class="statusColor"></span>
                {{ statusText }}
            </span>
            <!-- Simple Toggle for Enabled/Disabled if needed in future, implementing here as hidden logic or auto-enable -->
        </div>
    </div>

    <div class="flex flex-col md:flex-row min-h-[400px]">
        <!-- Sidebar Tabs -->
        <div class="w-full md:w-48 bg-gray-50 dark:bg-gray-900/30 border-r border-gray-200 dark:border-gray-700">
            <template v-for="tab in tabs" :key="tab.id">
                <button 
                    @click="currentTab = tab.id"
                    class="w-full text-left px-5 py-4 text-sm font-medium transition-colors duration-200 flex items-center gap-3 border-l-2"
                    :class="currentTab === tab.id ? 'bg-white dark:bg-gray-800 text-indigo-600 dark:text-indigo-400 border-indigo-500' : 'text-gray-600 dark:text-gray-400 border-transparent hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-gray-200'"
                >
                    <svg class="w-5 h-5 opacity-70" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="tab.icon" />
                    </svg>
                    <span>{{ tab.name }}</span>
                </button>
            </template>
        </div>

        <!-- Content Area -->
        <div class="flex-1 p-6">
            
            <!-- Tab: Overlay (Camouflage) -->
            <div v-show="currentTab === 'overlay'" class="space-y-6">
                <div>
                    <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-1">伪装模式 (Overlay Mode)</h4>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-4">
                        当非授权流量访问 Worker URL 时展示的内容。优先保障隐蔽性。
                    </p>
                    
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                         <label class="cursor-pointer relative">
                            <input type="radio" value="nginx" v-model="settings.sys_c_mode" class="peer sr-only">
                            <div class="p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-indigo-500 dark:hover:border-indigo-500 peer-checked:border-indigo-600 peer-checked:bg-indigo-50 dark:peer-checked:bg-indigo-900/20 peer-checked:ring-1 peer-checked:ring-indigo-600 transition-all">
                                <span class="block text-sm font-bold text-gray-900 dark:text-white">Nginx 欢迎页</span>
                                <span class="block text-xs text-gray-500 dark:text-gray-400 mt-1">模拟标准服务器初始页</span>
                            </div>
                        </label>
                         <label class="cursor-pointer relative">
                            <input type="radio" value="1101" v-model="settings.sys_c_mode" class="peer sr-only">
                            <div class="p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-indigo-500 dark:hover:border-indigo-500 peer-checked:border-indigo-600 peer-checked:bg-indigo-50 dark:peer-checked:bg-indigo-900/20 peer-checked:ring-1 peer-checked:ring-indigo-600 transition-all">
                                <span class="block text-sm font-bold text-gray-900 dark:text-white">系统错误 (1101)</span>
                                <span class="block text-xs text-gray-500 dark:text-gray-400 mt-1">模拟 Cloudflare 异常页</span>
                            </div>
                        </label>
                         <label class="cursor-pointer relative">
                            <input type="radio" value="custom" v-model="settings.sys_c_mode" class="peer sr-only">
                            <div class="p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-indigo-500 dark:hover:border-indigo-500 peer-checked:border-indigo-600 peer-checked:bg-indigo-50 dark:peer-checked:bg-indigo-900/20 peer-checked:ring-1 peer-checked:ring-indigo-600 transition-all">
                                <span class="block text-sm font-bold text-gray-900 dark:text-white">自定义内容</span>
                                <span class="block text-xs text-gray-500 dark:text-gray-400 mt-1">完全自定义 HTML 展示</span>
                            </div>
                        </label>
                    </div>

                    <div v-if="settings.sys_c_mode === 'custom'">
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">自定义 HTML 内容 (Overlay Data)</label>
                        <textarea 
                            v-model="settings.sys_c_html" 
                            rows="10" 
                            class="w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:text-white text-sm font-mono"
                            placeholder="<html>...</html>"
                        ></textarea>
                    </div>
                </div>
            </div>

            <!-- Tab: Core (Identity) -->
             <div v-show="currentTab === 'core'" class="space-y-6">
                <div>
                     <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-4">核心身份 (Core Identity)</h4>
                     
                     <div class="space-y-5">
                        <div>
                             <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                 客户端密钥 (Client Key / UUID)
                             </label>
                             <div class="relative rounded-md shadow-sm">
                                <input 
                                    type="text" 
                                    v-model="settings.sys_c_key"
                                    class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                >
                                <div class="absolute inset-y-0 right-0 flex items-center pr-3">
                                    <button @click="generateNewKey" class="text-gray-400 hover:text-indigo-500">
                                        <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                        </svg>
                                    </button>
                                </div>
                             </div>
                             <p class="mt-1 text-xs text-gray-500">用于 VLESS 协议的唯一识别 ID</p>
                        </div>

                        <div>
                             <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                 节点协议 (Node Protocol)
                             </label>
                             <select 
                                v-model="settings.sys_c_protocol"
                                class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3"
                             >
                                <option value="vless">VLESS</option>
                                <option value="trojan">Trojan</option>
                                <option value="vless+trojan">VLESS + Trojan</option>
                             </select>
                             <p class="mt-1 text-xs text-gray-500">选择生成的节点协议类型</p>
                        </div>

                        <div>
                             <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                 接入路径 (WS Path)
                             </label>
                             <input 
                                type="text" 
                                v-model="settings.sys_c_path"
                                class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                placeholder="/?ed=2048"
                             >
                             <p class="mt-1 text-xs text-gray-500">WebSocket 握手路径，建议包含 ?ed=2048 以启用 0-RTT</p>
                        </div>

                        <!-- Extended Core Settings -->
                        <div class="pt-2 border-t border-gray-100 dark:border-gray-700">
                             <div class="flex items-center pt-4">
                                <label class="flex items-center cursor-pointer">
                                    <div class="relative">
                                        <input type="checkbox" v-model="settings.sys_c_no_cert" class="sr-only peer">
                                        <div class="w-10 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-indigo-300 dark:peer-focus:ring-indigo-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-indigo-600"></div>
                                    </div>
                                    <span class="ml-3 text-sm font-medium text-gray-700 dark:text-gray-300">跳过证书验证 (Skip Cert Verify)</span>
                                </label>
                             </div>
                        </div>
                     </div>
                </div>
            </div>

            <!-- Tab: Network (Acceleration) -->
            <div v-show="currentTab === 'network'" class="space-y-6">
                <div>
                     <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Cloudflare CDN 访问设置 (Access Settings)</h4>
                     
                     <!-- CDN Access Mode Selector -->
                     <div class="mb-6">
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">访问模式 (Access Mode)</label>
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                            <button 
                                type="button"
                                @click="settings.sys_c_cdn_mode = 'direct'"
                                :class="settings.sys_c_cdn_mode === 'direct' ? 'bg-indigo-50 border-indigo-500 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'"
                                class="px-3 py-2 border rounded-md text-sm font-medium transition-colors"
                            >
                                直连 (Direct)
                            </button>
                            <button 
                                type="button"
                                @click="settings.sys_c_cdn_mode = 'proxyip'"
                                :class="settings.sys_c_cdn_mode === 'proxyip' ? 'bg-indigo-50 border-indigo-500 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'"
                                class="px-3 py-2 border rounded-md text-sm font-medium transition-colors"
                            >
                                ProxyIP 反代
                            </button>
                            <button 
                                type="button"
                                @click="settings.sys_c_cdn_mode = 'socks5'"
                                :class="settings.sys_c_cdn_mode === 'socks5' ? 'bg-indigo-50 border-indigo-500 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'"
                                class="px-3 py-2 border rounded-md text-sm font-medium transition-colors"
                            >
                                SOCKS5 中继
                            </button>
                            <button 
                                type="button"
                                @click="settings.sys_c_cdn_mode = 'http'"
                                :class="settings.sys_c_cdn_mode === 'http' ? 'bg-indigo-50 border-indigo-500 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'"
                                class="px-3 py-2 border rounded-md text-sm font-medium transition-colors"
                            >
                                HTTP 中继
                            </button>
                        </div>
                     </div>

                     <div class="space-y-5">
                        <!-- ProxyIP Settings -->
                        <div v-if="settings.sys_c_cdn_mode === 'proxyip'" class="animate-fadeIn">
                             <div class="flex items-center justify-between mb-2">
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    加速节点列表 (Acceleration Nodes)
                                </label>
                                <div class="flex items-center gap-2">
                                     <label class="text-xs text-gray-700 dark:text-gray-300">策略:</label>
                                     <select v-model="settings.sys_c_proxy_mode" class="text-xs rounded border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white py-1">
                                         <option value="auto">自动获取 (Auto)</option>
                                         <option value="list">手动列表 (Manual List)</option>
                                     </select>
                                 </div>
                             </div>
                             
                             <textarea 
                                v-show="settings.sys_c_proxy_mode === 'list'"
                                v-model="settings.sys_c_acc" 
                                rows="6" 
                                class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                placeholder="example.com&#10;1.1.1.1:443"
                             ></textarea>
                             <div v-show="settings.sys_c_proxy_mode === 'auto'" class="p-4 bg-gray-50 dark:bg-gray-900/50 rounded-md border border-gray-200 dark:border-gray-700 text-sm text-gray-500 text-center">
                                系统将自动获取优选 IP 进行回源
                             </div>
                        </div>

                         <!-- SOCKS5 Settings -->
                         <div v-if="settings.sys_c_cdn_mode === 'socks5'" class="animate-fadeIn">
                             <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    SOCKS5 节点地址
                                </label>
                                <input 
                                    type="text" 
                                    v-model="settings.sys_c_relay"
                                    class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                    placeholder="user:pass@host:port"
                                >
                             </div>
                             <div class="flex items-center">
                                <input type="checkbox" v-model="settings.sys_c_global" class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                                <span class="ml-2 text-sm text-gray-600 dark:text-gray-400">启用全局模式 (Global Mode)</span>
                             </div>
                        </div>

                         <!-- HTTP Settings -->
                         <div v-if="settings.sys_c_cdn_mode === 'http'" class="animate-fadeIn">
                             <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    HTTP 节点地址
                                </label>
                                <input 
                                    type="text" 
                                    v-model="settings.sys_c_relay"
                                    class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                    placeholder="user:pass@host:port"
                                >
                             </div>
                             <div class="flex items-center">
                                <input type="checkbox" v-model="settings.sys_c_global" class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                                <span class="ml-2 text-sm text-gray-600 dark:text-gray-400">启用全局模式 (Global Mode)</span>
                             </div>
                        </div>
                     </div>
                </div>
            </div>

            <!-- Tab: Optimization (Preferences) -->
            <div v-show="currentTab === 'optimization'" class="space-y-6">
                <div>
                     <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-4">优选参数设置 (Optimization Preferences)</h4>
                     
                     <!-- Mode Selection Cards -->
                     <div class="mb-6">
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">生成模式 (Generation Mode)</label>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <!-- Mode: Local Random -->
                            <div 
                                @click="settings.sys_c_ip_mode = 'local_random'"
                                class="cursor-pointer rounded-lg border p-4 transition-all relative overflow-hidden group"
                                :class="settings.sys_c_ip_mode === 'local_random' ? 'bg-indigo-50 border-indigo-500 ring-1 ring-indigo-500 dark:bg-indigo-900/20 dark:border-indigo-500' : 'border-gray-200 dark:border-gray-700 hover:border-indigo-300 dark:hover:border-indigo-700 bg-white dark:bg-gray-800'"
                            >
                                <div class="flex items-center gap-3 mb-2">
                                    <div class="p-2 rounded-md" :class="settings.sys_c_ip_mode === 'local_random' ? 'bg-indigo-100 text-indigo-600 dark:bg-indigo-800 dark:text-indigo-200' : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'">
                                        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                                        </svg>
                                    </div>
                                    <span class="font-medium text-gray-900 dark:text-white text-sm">本地随机 (Random)</span>
                                </div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">
                                    随机生成优选 IP，适合测试和临时使用。
                                </p>
                            </div>

                            <!-- Mode: Local KV -->
                            <div 
                                @click="settings.sys_c_ip_mode = 'local_kv'"
                                class="cursor-pointer rounded-lg border p-4 transition-all relative overflow-hidden group"
                                :class="settings.sys_c_ip_mode === 'local_kv' ? 'bg-indigo-50 border-indigo-500 ring-1 ring-indigo-500 dark:bg-indigo-900/20 dark:border-indigo-500' : 'border-gray-200 dark:border-gray-700 hover:border-indigo-300 dark:hover:border-indigo-700 bg-white dark:bg-gray-800'"
                            >
                                <div class="flex items-center gap-3 mb-2">
                                    <div class="p-2 rounded-md" :class="settings.sys_c_ip_mode === 'local_kv' ? 'bg-indigo-100 text-indigo-600 dark:bg-indigo-800 dark:text-indigo-200' : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'">
                                        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                                        </svg>
                                    </div>
                                    <span class="font-medium text-gray-900 dark:text-white text-sm">本地 KV 库 (Storage)</span>
                                </div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">
                                    从 KV 数据库读取预存的优选 IP 列表。
                                </p>
                            </div>

                            <!-- Mode: Generator -->
                            <div 
                                @click="settings.sys_c_ip_mode = 'generator'"
                                class="cursor-pointer rounded-lg border p-4 transition-all relative overflow-hidden group"
                                :class="settings.sys_c_ip_mode === 'generator' ? 'bg-indigo-50 border-indigo-500 ring-1 ring-indigo-500 dark:bg-indigo-900/20 dark:border-indigo-500' : 'border-gray-200 dark:border-gray-700 hover:border-indigo-300 dark:hover:border-indigo-700 bg-white dark:bg-gray-800'"
                            >
                                <div class="flex items-center gap-3 mb-2">
                                    <div class="p-2 rounded-md" :class="settings.sys_c_ip_mode === 'generator' ? 'bg-indigo-100 text-indigo-600 dark:bg-indigo-800 dark:text-indigo-200' : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'">
                                        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                                        </svg>
                                    </div>
                                    <span class="font-medium text-gray-900 dark:text-white text-sm">优选订阅生成器 (Generator)</span>
                                </div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">
                                    配置在线订阅转换服务生成优选订阅。
                                </p>
                            </div>
                        </div>
                     </div>

                     <!-- Dynamic Settings Area -->
                     <div class="bg-gray-50 dark:bg-gray-900/30 rounded-lg p-5 border border-gray-100 dark:border-gray-700 transition-all duration-300">
                         
                         <!-- Settings for Local Random -->
                         <div v-show="settings.sys_c_ip_mode === 'local_random'" class="animate-fadeIn grid grid-cols-1 md:grid-cols-2 gap-6">
                             <div>
                                 <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                     随机数量 (Count)
                                 </label>
                                 <div class="relative rounded-md shadow-sm">
                                     <input 
                                        type="number" 
                                        v-model.number="settings.sys_c_ip_count"
                                        placeholder="16"
                                        class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3"
                                     >
                                     <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                         <span class="text-gray-500 sm:text-xs">个</span>
                                     </div>
                                 </div>
                                 <p class="mt-1 text-xs text-gray-500">生成的节点数量</p>
                             </div>
                             <div>
                                 <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                     指定端口 (Port)
                                 </label>
                                 <input 
                                    type="number" 
                                    v-model.number="settings.sys_c_ip_port"
                                    placeholder="-1"
                                    class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3"
                                 >
                                 <p class="mt-1 text-xs text-gray-500">-1 表示随机端口 (443/80/2053等)</p>
                             </div>
                         </div>

                         <!-- Settings for Local KV -->
                         <div v-show="settings.sys_c_ip_mode === 'local_kv'" class="animate-fadeIn space-y-6">
                             <div>
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                     优选 IP 列表 (Optimized IP List)
                                </label>
                                <div class="relative">
                                     <textarea 
                                        v-model="settings.sys_c_ip_list"
                                        rows="6"
                                        class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                        placeholder="Examples:
104.16.1.1:443#US-Optimized
172.67.1.1:8443#HK-Line1
[2606:4700::]:443#IPv6-Test"
                                     ></textarea>
                                     <div class="absolute bottom-2 right-2 text-xs text-gray-400">
                                         Format: IP:Port#Tag (One per line)
                                     </div>
                                </div>
                             </div>

                             <!-- Advanced IP Tools (Buttons) -->
                             <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                                <h5 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                                    <svg class="w-4 h-4 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                                    </svg>
                                    高级优选工具 (Advanced Tools)
                                </h5>
                                
                                <div class="flex gap-4">
                                    <button 
                                        @click="openOnlineOptModal"
                                        class="flex-1 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors shadow-sm"
                                    >
                                        在线优选 (Online Opt)
                                    </button>
                                    <button 
                                        @click="showOptApi = true"
                                        class="flex-1 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors shadow-sm"
                                    >
                                        优选 API (Opt API)
                                    </button>
                                </div>
                             </div>
                     </div>
                     



                         <!-- Settings for Generator -->
                         <div v-show="settings.sys_c_ip_mode === 'generator'" class="animate-fadeIn">
                             <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                 优选订阅生成器地址 (Generator Address)
                             </label>
                             <input 
                                type="text" 
                                v-model="settings.sys_c_sub_url"
                                class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm py-2 px-3 font-mono"
                                placeholder="输入优选订阅生成器地址..."
                             >
                         </div>
                     </div>

                </div>
            </div>



            <!-- Tab: Preview -->
            <div v-show="currentTab === 'preview'" class="space-y-6">
                <div>
                     <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-4">配置预览 (Config Preview)</h4>
                     
                     <div class="space-y-4 mb-6">
                         <!-- Node Link -->
                         <div>
                             <label class="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">
                                 节点链接 (Node Link)
                             </label>
                             <div class="relative group">
                                <div class="p-3 bg-gray-50 dark:bg-gray-900/50 rounded border border-gray-200 dark:border-gray-700 font-mono text-xs break-all text-gray-600 dark:text-gray-300 select-all">
                                    {{ computedNodeLink }}
                                </div>
                             </div>
                         </div>

                         <!-- Subscription Link -->
                         <div>
                             <label class="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">
                                 自适应订阅链接 (Adaptive Subscription)
                             </label>
                              <div class="relative group">
                                <div class="p-3 bg-gray-50 dark:bg-gray-900/50 rounded border border-gray-200 dark:border-gray-700 font-mono text-xs break-all text-gray-600 dark:text-gray-300 select-all">
                                    {{ computedSubLink }}
                                </div>
                             </div>
                         </div>
                     </div>
                </div>
            </div>

        </div>
  
    <!-- Modal: Online Optimization (Speed Test) -->
    <Modal :show="showOnlineOpt" @update:show="showOnlineOpt = $event" :confirm-text="'关闭'" @confirm="showOnlineOpt = false" size="5xl">
        <template #title>
            <h3 class="text-lg font-bold text-gray-900 dark:text-white">在线优选 (Online Optimization)</h3>
        </template>
        <template #body>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 h-full">
                <!-- Left Col: Settings & Status -->
                <div class="md:col-span-1 space-y-4 flex flex-col h-full">
                     <!-- Environment Check Banner -->
                    <div class="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 text-xs">
                        <div v-if="optEnv.checking" class="text-gray-500 flex items-center gap-2">
                             <svg class="animate-spin h-3 w-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                             检测网络环境...
                        </div>
                        <div v-else-if="optEnv.error" class="text-red-500">检测失败: {{ optEnv.error }}</div>
                        <div v-else>
                             <div class="mb-1 text-gray-900 dark:text-gray-100 flex flex-col gap-1">
                                <div>IP: <strong class="font-mono">{{ optEnv.ip }}</strong></div>
                                <div>LOC: <strong>{{ optEnv.loc }}</strong></div>
                             </div>
                             <div v-if="optEnv.isProxy" class="mt-2 text-red-600 dark:text-red-400 font-bold border-t border-gray-200 dark:border-gray-600 pt-2 leading-tight">
                                ⚠️ 代理/VPN环境警告！<br>
                                请关闭代理后重试，否则优选结果无效。
                             </div>
                             <div v-else class="mt-2 text-green-600 dark:text-green-400 font-bold border-t border-gray-200 dark:border-gray-600 pt-2 flex items-center gap-1">
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>
                                直连环境 (Direct)
                             </div>
                        </div>
                    </div>

                    <!-- Settings Form -->
                    <div class="space-y-3 p-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                        <div>
                           <label class="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">IP 库 (Library)</label>
                           <select v-model="optimizeState.library" class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-900 text-xs py-1.5 focus:ring-indigo-500 focus:border-indigo-500">
                               <option value="cf-official">官方优选 (Official)</option>
                               <option value="cm-list">CM 列表 (GitHub)</option>
                               <option value="as13335">AS13335 (IPVerse)</option>
                               <option value="as209242">AS209242 (IPVerse)</option>
                               <option value="reverse-proxy">反向代理 (Reverse Proxy)</option>
                           </select>
                        </div>
                        <div class="grid grid-cols-2 gap-3">
                            <div>
                               <label class="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">端口 (Port)</label>
                               <input type="number" v-model.number="optimizeState.port" class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-900 text-xs py-1.5 focus:ring-indigo-500 focus:border-indigo-500" placeholder="443">
                            </div>
                            <div>
                               <label class="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">并发 (Threads)</label>
                               <input type="number" v-model.number="optimizeState.concurrency" class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-900 text-xs py-1.5 focus:ring-indigo-500 focus:border-indigo-500" placeholder="8">
                            </div>
                        </div>
                    </div>

                     <!-- Progress -->
                    <div v-if="optimizeState.running || optimizeState.progress.total > 0" class="space-y-2 p-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                         <div class="h-2 w-full bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                            <div class="h-full bg-indigo-600 transition-all duration-300" :style="{ width: (optimizeState.progress.total ? (optimizeState.progress.completed / optimizeState.progress.total * 100) : 0) + '%' }"></div>
                         </div>
                         <div class="flex justify-between text-[10px] text-gray-500 uppercase tracking-wider">
                            <span>{{ ((optimizeState.progress.completed / (optimizeState.progress.total || 1)) * 100).toFixed(0) }}%</span>
                            <span>{{ optimizeState.progress.completed }}/{{ optimizeState.progress.total }}</span>
                         </div>
                         <div class="grid grid-cols-2 gap-2 text-xs pt-1">
                             <div class="text-green-600 font-medium">Success: {{ optimizeState.progress.success }}</div>
                             <div class="text-red-500 font-medium text-right">Fail: {{ optimizeState.progress.fail }}</div>
                         </div>
                    </div>

                    <div class="pt-2 mt-auto">
                        <button 
                            @click="startOptimize" 
                            :disabled="optimizeState.running || optEnv.isProxy || optEnv.checking" 
                            class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-bold shadow-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                        >
                            <span v-if="optimizeState.running" class="flex items-center justify-center gap-2">
                                <svg class="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                正在优选...
                            </span>
                            <span v-else-if="optEnv.isProxy">⚠️ 仅限直连环境</span>
                            <span v-else>开始优选 (Start)</span>
                        </button>
                    </div>
                </div>

                <!-- Right Col: Results -->
                <div class="md:col-span-2 flex flex-col h-full bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                    <div class="p-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 flex justify-between items-center">
                        <h4 class="font-bold text-gray-900 dark:text-white text-sm">
                            优选结果 (Results)
                            <span class="text-xs font-normal text-gray-500 ml-2" v-if="optimizeState.results.length > 0">Top {{ Math.min(optimizeState.results.length, 16) }} will be saved</span>
                        </h4>
                        <span class="bg-indigo-100 text-indigo-800 text-xs font-medium px-2.5 py-0.5 rounded dark:bg-indigo-900 dark:text-indigo-300">
                            Count: {{ optimizeState.results.length }}
                        </span>
                    </div>

                    <div class="flex-1 overflow-y-auto p-0 scrollbar-thin">
                        <div v-if="optimizeState.results.length === 0" class="h-full flex flex-col items-center justify-center text-gray-400 p-8">
                             <svg class="h-12 w-12 mb-3 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                             </svg>
                             <p class="text-sm">等待优选开始...</p>
                        </div>
                        <table v-else class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead class="bg-gray-50 dark:bg-gray-900/50 sticky top-0">
                                <tr>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Colo</th>
                                    <th scope="col" class="px-3 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Latency</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="(res, idx) in optimizeState.results" :key="idx" class="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                                    <td class="px-3 py-2 whitespace-nowrap text-xs font-mono text-gray-900 dark:text-gray-100">
                                        {{ res.ip }}:{{ res.port }}
                                        <span v-if="idx < 16" class="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                            Saved
                                        </span>
                                    </td>
                                    <td class="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">{{ res.colo }}</td>
                                    <td class="px-3 py-2 whitespace-nowrap text-xs font-medium text-green-600 dark:text-green-400 text-right">{{ res.avgTime }}ms</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="p-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 flex gap-3">
                         <button 
                            @click="saveOptimizeParams('override')" 
                            :disabled="optimizeState.results.length === 0 || optEnv.isProxy" 
                            class="flex-1 px-3 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-bold shadow-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                        >
                            覆盖 (Override)
                        </button>
                        <button 
                            @click="saveOptimizeParams('append')" 
                            :disabled="optimizeState.results.length === 0 || optEnv.isProxy" 
                            class="flex-1 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-xs font-bold shadow-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                        >
                            追加 (Append)
                        </button>
                    </div>
                </div>
            </div>
        </template>
    </Modal>

    <!-- Modal: Optimization API -->
    <Modal :show="showOptApi" @update:show="showOptApi = $event" :confirm-text="'验证并添加'" @confirm="verifyAndAddApi" :confirm-disabled="apiState.verifying">
        <template #title>
            <h3 class="text-lg font-bold text-gray-900 dark:text-white">优选 API (Optimization API)</h3>
        </template>
        <template #body>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">API URL</label>
                    <input type="text" v-model="apiState.url" placeholder="https://api.example.com/best_ip" class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white sm:text-sm py-2 px-3">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">端口 (Port)</label>
                    <input type="number" v-model.number="apiState.port" placeholder="443" class="block w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white sm:text-sm py-2 px-3">
                </div>
                <div v-if="apiState.verifying" class="text-xs text-indigo-500">
                    Verifying...
                </div>
            </div>
        </template>
    </Modal>
  </div>
  </div>
</template>
