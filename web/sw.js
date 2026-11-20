/**
 * ShadowTrace Web Hub - Offline Service Worker
 * Ensures the entire web hub runs offline in airplane mode.
 */
const CACHE_NAME = 'shadowtrace-web-v9';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './style.css?v=9',
  './threat_iocs.js?v=9',
  './webusb-adb.js?v=9',
  './app.js?v=9',
  './manifest.json',
  './phone/index.html',
  './phone/phone.css?v=1',
  './phone/phone.js?v=1',
  './phone/worker.js?v=1'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  // NEVER intercept dynamic /api/ endpoints! Let browser communicate directly with local bridge
  if (event.request.url.indexOf('/api/') !== -1) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).then((networkResponse) => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });
        return networkResponse;
      }).catch(() => {
        // Offline fallback
        return caches.match('./index.html');
      });
    })
  );
});

