/* Drayber Flex applicant app: lets the app open from the home screen.
   Pages always load fresh from the internet; the saved copy is only used when offline.
   Applicant data is never stored here (it always comes from the server). */
const CACHE = "df-shell-v1";
const SHELL = ["./", "./index.html", "./config.js", "./manifest.webmanifest", "./icons/icon-192.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== "GET" || u.origin !== location.origin) return;
  if (r.mode === "navigate" || SHELL.some(p => u.pathname.endsWith(p.slice(1)) && p !== "./")) {
    e.respondWith(fetch(r).then(res => { if (res.ok) { const c = res.clone(); caches.open(CACHE).then(x => x.put(r.mode === "navigate" ? "./index.html" : r, c)); } return res; })
      .catch(() => caches.match(r.mode === "navigate" ? "./index.html" : r)));
  }
});
