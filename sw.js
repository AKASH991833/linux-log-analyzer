const C='log-analyzer-59d3c9eb';const FILES=["./", "index.html", "analyzer.js", "app.js", "base.css", "sample.js", "style.css", "theme.js", "assets/icon-192.png", "assets/icon-512.png", "assets/icon.svg", "manifest.webmanifest"];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)))});
