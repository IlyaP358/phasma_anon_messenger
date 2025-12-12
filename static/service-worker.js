self.addEventListener('push', function (event) {
    let data = {};
    if (event.data) {
        data = event.data.json();
    }

    const options = {
        body: data.body || 'New message',
        icon: '/static/icon.png',
        badge: '/static/badge.png',
        vibrate: [100, 50, 100],
        sound: '/static/phasma_notification_sound.mp3',
        tag: data.group_id ? `group-${data.group_id}` : 'default', // Group by group_id
        renotify: true, // Alert user even if replacing existing notification
        data: {
            dateOfArrival: Date.now(),
            primaryKey: 1,
            url: data.group_id ? `/group/${data.group_id}` : '/'
        }
    };

    event.waitUntil(
        self.registration.showNotification('Phasma Messenger', options)
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
