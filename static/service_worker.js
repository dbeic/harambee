// service-worker.js
const CACHE_NAME = "harambeecash-v1";
const OFFLINE_URL = "/offline";

const toCache = [
  "/",
  "/offline",
  "/static/favicon.ico",
  "/static/apple-touch-icon.png",
  "/static/manifest.json",
  "/static/piclog.png",
  "/static/sounds/game_start.mp3",
  "/static/sounds/game_end.mp3"
];

self.addEventListener("install", event => {
  console.log('🔄 Service Worker installing...');
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('📦 Caching app shell');
      return cache.addAll(toCache);
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  console.log('✅ Service Worker activated');
  event.waitUntil(
    caches.keys().then(keyList => {
      return Promise.all(
        keyList.map(key => {
          if (key !== CACHE_NAME) {
            console.log('🗑️ Removing old cache:', key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Skip cross-origin requests
  if (!event.request.url.startsWith(self.location.origin)) return;

  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      // Return cached version if available
      if (cachedResponse) {
        console.log('📂 Serving from cache:', event.request.url);
        return cachedResponse;
      }

      // Otherwise, make network request
      return fetch(event.request).then(response => {
        // Check if we received a valid response
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }

        // Clone the response
        const responseToCache = response.clone();

        // Add to cache for future visits
        caches.open(CACHE_NAME).then(cache => {
          console.log('💾 Caching new resource:', event.request.url);
          cache.put(event.request, responseToCache);
        });

        return response;
      }).catch(error => {
        console.log('❌ Network request failed, serving offline page:', error);
        // If both cache and network fail, show offline page
        return caches.match(OFFLINE_URL);
      });
    })
  );
});

// Listen for messages from the main thread
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// Background sync for offline actions
self.addEventListener('sync', event => {
  if (event.tag === 'background-sync') {
    console.log('🔄 Background sync triggered');
    event.waitUntil(doBackgroundSync());
  }
});

async function doBackgroundSync() {
  // Implement background sync logic here
  // This will run when the user comes back online
  console.log('🔄 Performing background sync...');
}
