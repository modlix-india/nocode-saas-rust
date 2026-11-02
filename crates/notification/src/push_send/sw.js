// Modlix push service worker, served by the notification service at
// /api/notification/push/sw.js with Service-Worker-Allowed: / so it can control the whole site.
// It only shows pushes and opens their url on a click; it caches nothing and never touches
// fetches, so pages load exactly as they do without it.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

// The app's path prefix on a shared host ("/<app>/<client>"), empty on its own domain; the
// client registers the worker with ?base= so a notification's "/page/..." url opens inside it.
const BASE = (new URL(self.location.href).searchParams.get('base') || '').replace(/\/+$/, '');

function withBase(url) {
	if (!BASE || !url.startsWith('/') || url.startsWith('//') || url === BASE || url.startsWith(BASE + '/')) return url;
	return BASE + url;
}

function sameOrigin(url) {
	try {
		return new URL(url, self.location.origin).origin === self.location.origin;
	} catch (e) {
		return false;
	}
}

self.addEventListener('push', event => {
	let data = {};
	try {
		data = event.data ? event.data.json() : {};
	} catch (e) {
		data = { title: event.data ? event.data.text() : '' };
	}
	event.waitUntil(
		self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windows => {
			// A visible tab already shows the in-app toast from its notification stream.
			if (windows.some(w => w.focused && w.visibilityState === 'visible')) return;
			return self.registration.showNotification(data.title || '', {
				body: data.body || '',
				icon: data.image || undefined,
				tag: data.notificationId || undefined,
				data: { url: data.url || '/' },
			});
		}),
	);
});

self.addEventListener('notificationclick', event => {
	event.notification.close();
	const wanted = withBase((event.notification.data && event.notification.data.url) || '/');
	const url = sameOrigin(wanted) ? new URL(wanted, self.location.origin).href : self.location.origin + (BASE || '') + '/';
	event.waitUntil(
		self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windows => {
			const open = windows.find(w => new URL(w.url).origin === self.location.origin);
			if (open)
				return open
					.focus()
					.then(w => (w && w.navigate ? w.navigate(url) : w))
					.catch(() => self.clients.openWindow(url));
			return self.clients.openWindow(url);
		}),
	);
});
