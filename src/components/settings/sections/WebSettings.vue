<script setup>
import { computed } from 'vue';

const props = defineProps({
  settings: {
    type: Object,
    required: true
  }
});

// Computed properties to bridge legacy UI with Core Service settings
const isEnabled = computed({
  get: () => {
      // Logic: Enabled if sys_c_mode is set/valid (and not explicitly disabled via legacy flag if needed)
      // For simplicity, we assume if sys_c_mode exists, it's enabled.
      // Or we can track a separate 'enabled' state if we want to toggle "off" without losing the mode.
      return props.settings.disguise?.enabled !== false; 
  },
  set: (val) => {
      if (!props.settings.disguise) props.settings.disguise = {};
      props.settings.disguise.enabled = val;
      // If disabled, we might want to ensure core service respects this?
      // Core Service currently checks sys_c_mode.
      // We can use a special mode 'disabled' or just rely on the 'disguise.enabled' flag which we merged in core-service.js (defaults).
  }
});

const activeMode = computed({
  get: () => props.settings.sys_c_mode || 'nginx',
  set: (val) => props.settings.sys_c_mode = val
});

</script>

<template>
  <div>
    <h3 class="text-lg font-medium text-gray-900 dark:text-white border-b pb-2 dark:border-gray-700 mb-3">伪装设置</h3>
    <div class="space-y-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
      
      <!-- Enable Switch -->
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-gray-700 dark:text-gray-300">启用 Web 伪装</p>
          <p class="text-xs text-gray-500 dark:text-gray-400">非法访问或浏览器直接访问时显示的伪装页面</p>
        </div>
        <label class="toggle-switch"><input type="checkbox" v-model="isEnabled"><span class="slider"></span></label>
      </div>
      
      <div v-if="isEnabled" class="space-y-4 border-t border-gray-200 dark:border-gray-600 pt-3">
        
        <!-- Mode Selection -->
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">伪装模式</label>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            
            <!-- Default (Nginx) -->
            <label class="relative flex items-start p-3 border rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                   :class="activeMode === 'nginx' ? 'border-indigo-500 ring-1 ring-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600'">
              <div class="flex items-center h-5">
                <input type="radio" value="nginx" v-model="activeMode" class="h-4 w-4 text-indigo-600 border-gray-300 focus:ring-indigo-500">
              </div>
              <div class="ml-3 text-sm">
                <span class="block font-medium text-gray-900 dark:text-gray-100">Nginx 默认页</span>
                <span class="block text-gray-500 dark:text-gray-400 text-xs">伪装成 Nginx 安装成功的欢迎页面</span>
              </div>
            </label>

            <!-- 1101 Error -->
            <label class="relative flex items-start p-3 border rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                   :class="activeMode === '1101' ? 'border-indigo-500 ring-1 ring-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600'">
              <div class="flex items-center h-5">
                <input type="radio" value="1101" v-model="activeMode" class="h-4 w-4 text-indigo-600 border-gray-300 focus:ring-indigo-500">
              </div>
              <div class="ml-3 text-sm">
                <span class="block font-medium text-gray-900 dark:text-gray-100">Cloudflare 1101</span>
                <span class="block text-gray-500 dark:text-gray-400 text-xs">伪装成 Worker 运行错误的报错页面</span>
              </div>
            </label>

            <!-- Redirect -->
            <label class="relative flex items-start p-3 border rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                   :class="activeMode === 'redirect' ? 'border-indigo-500 ring-1 ring-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600'">
              <div class="flex items-center h-5">
                <input type="radio" value="redirect" v-model="activeMode" class="h-4 w-4 text-indigo-600 border-gray-300 focus:ring-indigo-500">
              </div>
              <div class="ml-3 text-sm">
                <span class="block font-medium text-gray-900 dark:text-gray-100">页面重定向</span>
                <span class="block text-gray-500 dark:text-gray-400 text-xs">跳转到指定的任意网址 (如百度)</span>
              </div>
            </label>

            <!-- Custom HTML -->
            <label class="relative flex items-start p-3 border rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                   :class="activeMode === 'custom' ? 'border-indigo-500 ring-1 ring-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600'">
              <div class="flex items-center h-5">
                <input type="radio" value="custom" v-model="activeMode" class="h-4 w-4 text-indigo-600 border-gray-300 focus:ring-indigo-500">
              </div>
              <div class="ml-3 text-sm">
                <span class="block font-medium text-gray-900 dark:text-gray-100">自定义 HTML</span>
                <span class="block text-gray-500 dark:text-gray-400 text-xs">完全自定义返回的网页源码</span>
              </div>
            </label>

          </div>
        </div>
        
        <!-- Redirect Options -->
        <div v-if="activeMode === 'redirect'" class="bg-white dark:bg-gray-700/50 p-3 rounded-md border border-gray-200 dark:border-gray-600">
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">重定向目标 URL</label>
          <input 
            type="url" 
            v-model="settings.sys_c_redirect_url" 
            placeholder="https://www.baidu.com"
            class="block w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md shadow-xs focus:outline-hidden focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm dark:text-white"
          >
          <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">请填写完整的 URL (包含 http/https)</p>
        </div>

        <!-- Custom HTML Options -->
        <div v-if="activeMode === 'custom'" class="bg-white dark:bg-gray-700/50 p-3 rounded-md border border-gray-200 dark:border-gray-600">
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">HTML 代码</label>
          <textarea 
            v-model="settings.sys_c_html" 
            rows="6"
            placeholder="<html><body><h1>Hello World</h1></body></html>"
            class="block w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md shadow-xs focus:outline-hidden focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm dark:text-white font-mono text-xs"
          ></textarea>
        </div>
        
        <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-xs text-blue-800 dark:text-blue-300">
                <strong>智能防误伤已启用:</strong> 您的管理令牌、公共订阅前缀、以及所有的订阅 ID 会被自动识别并放行，不会受到伪装页面的影响。
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Toggle Switch CSS */
.toggle-switch {
  position: relative;
  display: inline-block;
  width: 44px;
  height: 24px;
}
.toggle-switch input { opacity: 0; width: 0; height: 0; }
.slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: #ccc;
  transition: .4s;
  border-radius: 34px;
}
.dark .slider { background-color: #4b5563; }
.slider:before {
  position: absolute;
  content: "";
  height: 20px;
  width: 20px;
  left: 2px;
  bottom: 2px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}
input:checked + .slider { background-color: #4f46e5; }
.dark input:checked + .slider { background-color: #16a34a; }
input:checked + .slider:before { transform: translateX(20px); }
</style>
