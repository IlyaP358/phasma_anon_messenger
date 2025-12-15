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

            if (currentNotification) {
                // Extract previous count from data if available, or just increment
                const prevCount = currentNotification.data && currentNotification.data.count ? currentNotification.data.count : 1;
                count = prevCount + 1;

                // If we have a group name, use it in title
                // For now, we just say "X new messages"
                body = `${count} new messages`;

                // Close old notification to ensure replacement works visually on all devices
                currentNotification.close();
            }

            const options = {
                body: body,
                icon: '/static/icon.png',
                badge: '/static/badge.png',
                vibrate: [100, 50, 100],
                sound: '/static/phasma_notification_sound.mp3',
                tag: tag,
                renotify: true,
                data: {
                    dateOfArrival: Date.now(),
                    primaryKey: 1,
                    url: data.group_id ? `/group/${data.group_id}/chat` : '/',
                    count: count // Store count for next time
                }
            };

            return self.registration.showNotification(title, options);
        })
    );
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();

    const urlToOpen = event.notification.data.url || '/';

    event.waitUntil(
        clients.matchAll({
            type: 'window',
            includeUncontrolled: true
        }).then((windowClients) => {
            // Check if there is already a window/tab open with the target URL
            for (let i = 0; i < windowClients.length; i++) {
                const client = windowClients[i];
                if (client.url === urlToOpen && 'focus' in client) {
                    return client.focus();
                }
            }
            // If not, open a new window
            if (clients.openWindow) {
                return clients.openWindow(urlToOpen);
            }
        })
    );
});
