# Video Analytics Tracker

Selbst-gehostete Video-Analytics-Lösung als Alternative zu Vidalytics. Trackt Video-Wiedergabe und sendet Webhooks bei definierten Meilensteinen.

## Features

- HTML5 Video & Bunny.net Stream Support
- E-Mail-Tracking aus URL-Parametern
- Webhook-basiertes Progress-Tracking
- Prozentuale oder zeitbasierte Meilensteine
- Kein Backend erforderlich (rein clientseitig)
- Leichtgewichtig (~5KB)

## Quick Start

### 1. Dateien auf deinen Server laden

Lade `video-tracker.js` auf deinen Webserver oder CDN.

### 2. In deine Landingpage einbetten

```html
<!-- Video Container -->
<div id="video-player"></div>

<!-- Script laden -->
<script src="pfad/zu/video-tracker.js"></script>

<!-- Konfiguration -->
<script>
    new VideoTracker('video-player', {
        videoUrl: 'https://dein-cdn.com/video.mp4',
        webhookUrl: 'https://dein-n8n-server.de/webhook/video-tracking',
        milestones: {
            type: 'percent',
            values: [25, 50, 75, 100]
        }
    });
</script>
```

### 3. E-Mail über URL übergeben

Verlinke zur Seite mit E-Mail-Parameter:
```
https://deine-seite.de/video?email=max@beispiel.de
```

Unterstützte URL-Parameter:
- `email`
- `e`
- `subscriber_email`
- `contact_email`

## Konfigurationsoptionen

```javascript
new VideoTracker('container-id', {
    // === VIDEO ===
    videoType: 'html5',        // 'html5' oder 'bunny'
    videoUrl: '',              // Video-URL (für HTML5)
    bunnyLibraryId: '',        // Bunny.net Library ID
    bunnyVideoId: '',          // Bunny.net Video ID

    // === PLAYER ===
    autoplay: false,           // Automatisch abspielen
    muted: false,              // Stummgeschaltet (für Autoplay nötig)
    controls: true,            // Steuerelemente anzeigen
    poster: '',                // Thumbnail-Bild URL

    // === WEBHOOK ===
    webhookUrl: '',            // Dein Webhook Endpoint

    // === MEILENSTEINE ===
    milestones: {
        type: 'percent',       // 'percent' oder 'time'
        values: [25, 50, 75, 100]  // Prozent oder Sekunden
    },

    // === STYLING ===
    styles: {
        width: '100%',
        maxWidth: '800px',
        borderRadius: '8px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
    }
});
```

## Webhook Payload

Bei jedem Meilenstein wird folgender JSON-Payload gesendet:

```json
{
    "email": "max@beispiel.de",
    "videoId": "video_abc123",
    "videoUrl": "https://cdn.example.com/video.mp4",
    "event": "milestone_reached",
    "milestoneType": "percent",
    "milestoneValue": 50,
    "milestoneLabel": "50%",
    "duration": 300,
    "percentWatched": 50,
    "timestamp": "2024-01-15T10:30:00.000Z",
    "pageUrl": "https://deine-seite.de/video?email=max@beispiel.de",
    "userAgent": "Mozilla/5.0..."
}
```

## Beispiele

### Prozentuale Meilensteine (Standard)

```javascript
milestones: {
    type: 'percent',
    values: [25, 50, 75, 100]
}
```

### Zeitbasierte Meilensteine

```javascript
milestones: {
    type: 'time',
    values: [30, 60, 300, 600]  // 30s, 1min, 5min, 10min
}
```

### Bunny.net Stream

```javascript
new VideoTracker('video-player', {
    videoType: 'bunny',
    bunnyLibraryId: '12345',
    bunnyVideoId: 'abc-def-ghi',
    webhookUrl: 'https://...',
    milestones: { type: 'percent', values: [50, 100] }
});
```

### Mit Autoplay (stummgeschaltet)

```javascript
new VideoTracker('video-player', {
    videoUrl: 'https://...',
    autoplay: true,
    muted: true,  // Browser erfordern muted für Autoplay
    webhookUrl: 'https://...',
    milestones: { type: 'percent', values: [25, 50, 75, 100] }
});
```

## n8n Webhook Setup

1. Erstelle einen neuen Workflow in n8n
2. Füge einen "Webhook" Node hinzu
3. Wähle HTTP Method: `POST`
4. Kopiere die Webhook-URL in deine Video-Tracker Konfiguration
5. Verbinde weitere Nodes (z.B. ActiveCampaign, E-Mail, etc.)

### Beispiel: ActiveCampaign Tag hinzufügen

```
Webhook → IF (milestoneValue >= 50) → ActiveCampaign (Add Tag "Video 50% watched")
```

## JavaScript API

```javascript
// Tracker-Instanz speichern
const tracker = new VideoTracker('video-player', { ... });

// Status abrufen
tracker.getStatus();
// → { email, videoId, triggeredMilestones, currentTime, duration }

// Meilensteine zurücksetzen (für Tests)
tracker.resetMilestones();
```

## Dateien

```
video-tracker/
├── video-tracker.js   # Haupt-Script (auf Server laden)
├── example.html       # Demo mit Debug-Panel
├── embed.html         # Minimales Embed-Template
└── README.md          # Diese Dokumentation
```

## Browser-Kompatibilität

- Chrome 60+
- Firefox 55+
- Safari 11+
- Edge 79+

## Troubleshooting

### Webhooks werden nicht gesendet
- Prüfe die Browser-Konsole auf Fehler
- Stelle sicher, dass dein Webhook CORS erlaubt
- n8n Webhooks erlauben standardmäßig CORS

### E-Mail wird nicht erkannt
- Prüfe ob der URL-Parameter korrekt ist: `?email=test@example.com`
- Schau in der Konsole nach "VideoTracker initialisiert"

### Bunny.net Tracking funktioniert nicht
- Bunny.net muss postMessage Events senden
- Prüfe ob die Library/Video IDs korrekt sind

## CORS für eigene Backends

Falls du ein eigenes Backend nutzt, muss es CORS-Header senden:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type
```

## Lizenz

MIT - Nutze es wie du willst.
