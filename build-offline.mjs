import {readFileSync,writeFileSync} from 'node:fs';
const read=name=>readFileSync(new URL(name,import.meta.url),'utf8');
let html=read('index.html').replace('<link rel="stylesheet" href="/verify/style.css">','<style>'+read('style.css')+'</style>');
const script=[read('verifier.js').replace(/export /g,''),read('policy.js').replace(/export /g,''),read('app.js').replace(/^import .*;\r?\n/gm,'')].join('\n');
html=html.replace('<script type="module" src="/verify/app.js"></script>','<script type="module">'+script+'</script>');
writeFileSync(new URL('verify-offline.html',import.meta.url),html);
