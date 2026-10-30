import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
export default defineConfig({root:'web',plugins:[svelte()],server:{host:'127.0.0.1',proxy:{'/api':'http://127.0.0.1:3000','/auth':'http://127.0.0.1:3000'}},build:{outDir:'dist',emptyOutDir:true}});
