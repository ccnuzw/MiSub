<script setup>
import { ref, watch, computed, onMounted } from 'vue';
import { useToastStore } from '../../../stores/toast.js';

const props = defineProps({
  settings: {
    type: Object,
    required: true
  }
});

const { showToast } = useToastStore();

const config = ref({
  enabled: false,
  uuid: '',
  proxyIp: 'kr.william.us.ci',
  // New fields
  nodeName: 'SSKB-Node',
  path: '/',
});

const currentHost = ref('');
const isSecure = ref(true);

onMounted(() => {
  currentHost.value = window.location.hostname;
  isSecure.value = window.location.protocol === 'https:';
});

// Initialize from props
watch(() => props.settings?.sskbConfig, (newVal) => {
  if (newVal) {
    if (newVal.enabled !== config.value.enabled || 
        newVal.uuid !== config.value.uuid || 
        newVal.proxyIp !== config.value.proxyIp ||
        newVal.nodeName !== config.value.nodeName ||
        newVal.path !== config.value.path) {
      
      config.value = {
        enabled: newVal.enabled ?? false,
        uuid: newVal.uuid || '',
        proxyIp: newVal.proxyIp || 'kr.william.us.ci',
        nodeName: newVal.nodeName || 'SSKB-Node',
        path: newVal.path || '/',
      };
    }
  }
}, { immediate: true, deep: true });

// Sync changes back to parent
watch(config, (newConfig) => {
  if (props.settings) {
    if (!props.settings.sskbConfig) {
      props.settings.sskbConfig = {};
    }
    props.settings.sskbConfig.enabled = newConfig.enabled;
    props.settings.sskbConfig.uuid = newConfig.uuid;
    props.settings.sskbConfig.proxyIp = newConfig.proxyIp;
    props.settings.sskbConfig.nodeName = newConfig.nodeName;
    props.settings.sskbConfig.path = newConfig.path;
  }
}, { deep: true });

const generateUUID = () => {
  const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
  config.value.uuid = uuid;
};

// VLESS Link Generation
const vlessLink = computed(() => {
  if (!config.value.uuid) return '';
  
  const host = currentHost.value || 'localhost';
  const port = isSecure.value ? '443' : '80'; // Simplification
  const protocol = 'vless';
  const uuid = config.value.uuid;
  const remarks = encodeURIComponent(config.value.nodeName || 'SSKB');
  const path = encodeURIComponent(config.value.path || '/');
  
  // Params
  const params = new URLSearchParams();
  params.append('encryption', 'none');
  params.append('security', isSecure.value ? 'tls' : 'none');
  params.append('type', 'ws');
  params.append('host', host);
  params.append('path', path);
  params.append('sni', host);
  params.append('fp', 'random');
  
  return `${protocol}://${uuid}@${host}:${port}?${params.toString()}#${remarks}`;
});

const copyLink = async () => {
  if (!vlessLink.value) return;
  try {
    await navigator.clipboard.writeText(vlessLink.value);
    showToast('节点链接已复制', 'success');
  } catch (err) {
    showToast('复制失败', 'error');
  }
};
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-medium text-gray-900 dark:text-white">SSKB 配置</h3>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
          启用内置的 SSKB VLESS 代理服务
        </p>
      </div>
      <div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" v-model="config.enabled" class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 dark:peer-focus:ring-indigo-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-indigo-600"></div>
        </label>
      </div>
    </div>

    <div v-if="config.enabled" class="space-y-6 bg-gray-50 dark:bg-gray-700/30 p-4 rounded-lg border border-gray-100 dark:border-gray-700">
      
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <!-- UUID -->
        <div class="md:col-span-2">
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">UUID</label>
            <div class="flex gap-2">
                <input 
                    v-model="config.uuid"
                    type="text" 
                    class="flex-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-white"
                    placeholder="请输入或生成 UUID"
                >
                <button 
                    @click="generateUUID"
                    type="button"
                    class="inline-flex items-center px-4 py-2 border border-stone-200 dark:border-stone-600 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white dark:bg-gray-800 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none"
                >
                    生成
                </button>
            </div>
            <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">连接密钥</p>
        </div>

        <!-- Node Name -->
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">节点备注</label>
            <input 
                v-model="config.nodeName"
                type="text" 
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-white"
                placeholder="SSKB-Node"
            >
        </div>

        <!-- Path -->
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Websocket Path</label>
            <input 
                v-model="config.path"
                type="text" 
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-white"
                placeholder="/"
            >
        </div>

        <!-- ProxyIP -->
        <div class="md:col-span-2">
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">ProxyIP (落地IP/域名)</label>
            <input 
                v-model="config.proxyIp"
                type="text" 
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-white"
                placeholder="例如: kr.william.us.ci"
            >
            <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">访问受限网站时的落地代理</p>
        </div>
      </div>

      <!-- Link Generator -->
      <div v-if="config.uuid" class="mt-6 border-t border-gray-200 dark:border-gray-600 pt-4">
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">节点分享链接</label>
        <div class="relative rounded-md shadow-sm">
            <textarea 
                :value="vlessLink" 
                readonly
                rows="3"
                class="font-mono text-xs block w-full rounded-md border-gray-300 focus:border-indigo-500 focus:ring-indigo-500 bg-gray-50 dark:bg-gray-900 dark:border-gray-600 dark:text-gray-300 p-2 pr-10 resize-none"
            ></textarea>
            
            <div class="absolute top-2 right-2">
                <button 
                    @click="copyLink"
                    class="p-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-700 text-indigo-600 dark:text-indigo-400 transition-colors"
                    title="复制链接"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                    </svg>
                </button>
            </div>
        </div>
        <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
            支持 VLESS + WebSocket + TLS 模式。
            <span v-if="!isSecure" class="text-amber-500">注意: 当前页面非 HTTPS，生成的链接默认不开启 TLS (port 80)，需在 HTTPS 环境下使用以获得最佳安全性。</span>
        </p>
      </div>

    </div>
  </div>
</template>
