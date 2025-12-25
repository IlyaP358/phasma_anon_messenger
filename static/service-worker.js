self.addEventListener('install', function (event) {
    self.skipWaiting(); // Force update
});

self.addEventListener('activate', function (event) {
    event.waitUntil(clients.claim()); // Take control of all clients immediately
});

self.addEventListener('push', function (event) {
    let data = {};
    if (event.data) {
        data = event.data.json();
    }

    const tag = data.group_id ? `group-${data.group_id}` : 'default';
    const title = data.title || 'Phasma Messenger';

    event.waitUntil(
        self.registration.getNotifications({ tag: tag }).then(function (notifications) {
            let currentNotification = notifications.length > 0 ? notifications[0] : null;
            let count = 1;
            let body = data.body || 'New message';
            let options = {
                icon: '/static/icon.png',
                badge: '/static/badge.png',
                vibrate: [200, 100, 200],
                tag: tag,
                renotify: true,
                requireInteraction: true,
                data: {
                    dateOfArrival: Date.now(),
                    primaryKey: 1,
                    url: data.group_id ? `/group/${data.group_id}/chat` : '/',
                    count: 1
                }
            };

            // Special handling for incoming calls
            if (data.type && data.type.startsWith('call_') && data.type === 'call_offer') {
                body = data.caller ? `Incoming call from ${data.caller}` : (data.body || 'Incoming call');
                options.actions = [
                    { action: 'accept', title: 'Accept' },
                    { action: 'decline', title: 'Decline' }
                ];
                // Use a higher priority tag so call notifications show separately
                options.tag = `call-${data.group_id || 'unknown'}`;
                options.data.url = data.group_id ? `/group/${data.group_id}/chat` : '/';
                options.data.call = true;
            } else {
                if (currentNotification) {
                    const prevCount = currentNotification.data && currentNotification.data.count ? currentNotification.data.count : 1;
                    count = prevCount + 1;
                    body = `${count} new messages`;
                    currentNotification.close();
                }
                options.actions = [ { action: 'open', title: 'Open Chat' } ];
                options.data.count = count;
            }

            options.body = body;

            return self.registration.showNotification(title, options);
        })
    );
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();

    const baseUrl = (event.notification && event.notification.data && event.notification.data.url) ? event.notification.data.url : '/';
    // Append action param so the app can react (accept/decline)
    let urlToOpen = baseUrl;
    if (event.action) {
        const sep = baseUrl.indexOf('?') === -1 ? '?' : '&';
        const caller = event.notification && event.notification.data && event.notification.data.caller ? event.notification.data.caller : '';
        urlToOpen = `${baseUrl}${sep}action=${encodeURIComponent(event.action)}${caller ? `&caller=${encodeURIComponent(caller)}` : ''}`;
    }

    event.waitUntil(
        clients.matchAll({
            type: 'window',
            includeUncontrolled: true
        }).then((windowClients) => {
            // Try to focus an existing client
            for (let i = 0; i < windowClients.length; i++) {
                const client = windowClients[i];
                if (client.url.startsWith(self.registration.scope) && 'focus' in client) {
                    if (client.url !== urlToOpen) {
                        client.navigate(urlToOpen);
                    }
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(urlToOpen);
            }
        })
    );
});
