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
        sound: '/static/phasma_notification_sound.mp3', // Try to play sound
        data: {
            dateOfArrival: Date.now(),
            primaryKey: 1
        }
    };

    event.waitUntil(
        self.registration.showNotification('Phasma Messenger', options)
    );
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/')
    );
});
