
import { build } from 'esbuild';
import JavaScriptObfuscator from 'javascript-obfuscator';
import fs from 'fs/promises';
import path from 'path';

const DIST_DIR = 'dist';
const PUBLIC_DIR = 'dist'; // For Cloudflare Pages, output dir is usually 'dist' or 'public'
const WORKER_OUT = path.join(DIST_DIR, '_worker.js');

async function clean() {
    try {
        await fs.rm(DIST_DIR, { recursive: true, force: true });
        await fs.mkdir(DIST_DIR, { recursive: true });
    } catch (e) {
        console.error('Clean failed:', e);
    }
}

async function copyPublic() {
    // Copy all files from 'public' to 'dist'
    // Simplified: we assume 'public' exists.
    // Note: Cloudflare Pages usually deploys the public folder. 
    // Here we are creating a new 'build' folder that contains everything.
    try {
        // cp -r public/* dist/
        const copyDir = async (src, dest) => {
            await fs.mkdir(dest, { recursive: true });
            const entries = await fs.readdir(src, { withFileTypes: true });
            for (const entry of entries) {
                const srcPath = path.join(src, entry.name);
                const destPath = path.join(dest, entry.name);
                if (entry.isDirectory()) {
                    await copyDir(srcPath, destPath);
                } else {
                    await fs.copyFile(srcPath, destPath);
                }
            }
        };
        // If we are building for Pages, we might want to copy 'dist' (from vite build) instead of 'public' if it's an SPA.
        // But user provided 'public' folder context. Let's assume 'dist' (Vite output) is what we want.
        // Wait, usually flow is: npm run build (Vite -> dist) -> Then we add _worker.js to dist.

        // So this script should take an existing 'dist' (from Vite) and add _worker.js to it?
        // OR it creates a new folder.
        // Since user runs `npm run dev` and `wrangler pages dev .`, likely deploy is `wrangler pages deploy dist`.

        // Let's assume Vite build has run and 'dist' exists. We just append _worker.js to it.
        // If 'dist' doesn't exist, we create it.
        // But wait, if we delete dist in clean(), we wipe the frontend build!
        // We should NOT clean() if we expect Vite build to be there.

        console.log('Use existing dist directory...');
        await fs.mkdir(DIST_DIR, { recursive: true });

    } catch (e) {
        console.error('Copy failed:', e);
    }
}

async function bundleWorker() {
    console.log('Bundling functions to _worker.js...');
    await build({
        entryPoints: ['functions/[[path]].js'],
        bundle: true,
        outfile: WORKER_OUT,
        format: 'esm',
        target: 'es2020',
        platform: 'neutral',
        minify: false, // We will obfuscate later, which includes minification
        sourcemap: false,
        external: ['cloudflare:*'] // Exclude internal modules if any, usually okay
    });
}

async function obfuscateWorker() {
    console.log('Obfuscating _worker.js...');
    const code = await fs.readFile(WORKER_OUT, 'utf-8');

    const obfuscationResult = JavaScriptObfuscator.obfuscate(code, {
        // [Optimization] Reduced obfuscation settings to avoid "Script startup exceeded memory limits"
        // Previous "High" settings were too aggressive for Cloudflare Workers free/pro tier limits.
        compact: true,
        controlFlowFlattening: false, // Disabled: High performance cost
        deadCodeInjection: false,     // Disabled: Increases code size/memory significantly
        debugProtection: false,
        debugProtectionInterval: 0,
        disableConsoleOutput: true,
        identifierNamesGenerator: 'hexadecimal',
        log: false,
        numbersToExpressions: false,  // Disabled: Runtime overhead
        renameGlobals: false,         // Disabled: safer for Worker environment global scope
        rotateStringArray: true,
        selfDefending: true,
        shuffleStringArray: true,
        simplify: true,
        splitStrings: false,          // Disabled: Reduces startup string allocation
        stringArray: true,
        stringArrayCallsTransform: false, // Disabled: High runtime cost
        stringArrayEncoding: [],      // Disabled: 'rc4' provides protection but costs memory
        stringArrayIndexesType: [
            'hexadecimal-number'
        ],
        stringArrayIndexShift: true,
        stringArrayWrappersCount: 1,
        stringArrayWrappersChainedCalls: true,
        stringArrayWrappersParametersMaxCount: 2,
        stringArrayWrappersType: 'variable',
        stringArrayThreshold: 0.75,
        target: 'browser', // Worker environment is browser-like
        transformObjectKeys: false, // Disabled: safer for JSON/KV interactions
        unicodeEscapeSequence: false
    });

    await fs.writeFile(WORKER_OUT, obfuscationResult.getObfuscatedCode());
    console.log('Obfuscation complete!');
}

async function main() {
    // 1. Bundle
    await bundleWorker();
    // 2. Obfuscate
    await obfuscateWorker();

    console.log('Build complete! Deploy directory: ./dist');
    console.log('Run: npx wrangler pages deploy dist');
}

main();
