/**
 * Video Analytics Tracker v2.1.0
 * Selbst-gehostete Alternative zu Vidalytics
 *
 * Production-Ready Features:
 * - Input Validation
 * - HMAC Webhook Signing
 * - Retry mit Exponential Backoff
 * - Error Monitoring
 * - postMessage Origin Verification
 * - Bunny.net Stream & HTML5 Video Support
 * - HLS Streaming Support (für Safari iOS Kompatibilität)
 * - E-Mail-Tracking aus URL-Parametern
 */

(function() {
    'use strict';

    // ============================================
    // VALIDATION UTILITIES
    // ============================================

    const Validators = {
        /**
         * E-Mail Validierung nach RFC 5322 (vereinfacht)
         */
        isValidEmail(email) {
            if (!email || typeof email !== 'string') return false;
            const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            return emailRegex.test(email) && email.length <= 254;
        },

        /**
         * URL Validierung
         */
        isValidUrl(url) {
            if (!url || typeof url !== 'string') return false;
            try {
                const parsed = new URL(url);
                return ['http:', 'https:'].includes(parsed.protocol);
            } catch {
                return false;
            }
        },

        /**
         * Webhook URL Validierung (muss HTTPS sein für Production)
         */
        isValidWebhookUrl(url, requireHttps = false) {
            if (!this.isValidUrl(url)) return false;
            if (requireHttps) {
                return url.startsWith('https://');
            }
            return true;
        },

        /**
         * Milestone Values Validierung
         */
        isValidMilestones(milestones) {
            if (!milestones || typeof milestones !== 'object') return false;
            if (!['percent', 'time'].includes(milestones.type)) return false;
            if (!Array.isArray(milestones.values) || milestones.values.length === 0) return false;

            return milestones.values.every(v => {
                if (typeof v !== 'number' || isNaN(v) || v < 0) return false;
                if (milestones.type === 'percent' && v > 100) return false;
                if (milestones.type === 'time' && v > 86400) return false; // Max 24h
                return true;
            });
        },

        /**
         * Bunny.net IDs Validierung
         */
        isValidBunnyId(id) {
            if (!id || typeof id !== 'string') return false;
            // Bunny IDs sind alphanumerisch mit Bindestrichen
            return /^[a-zA-Z0-9-]+$/.test(id) && id.length >= 1 && id.length <= 100;
        },

        /**
         * Input Sanitization - XSS Prevention
         */
        sanitizeString(input) {
            if (typeof input !== 'string') return '';
            return input
                .replace(/[<>]/g, '') // HTML Tags entfernen
                .trim()
                .slice(0, 1000); // Max Länge
        }
    };

    // ============================================
    // ERROR MONITORING
    // ============================================

    class ErrorMonitor {
        constructor(options = {}) {
            this.errors = [];
            this.maxErrors = options.maxErrors || 100;
            this.onError = options.onError || null;
            this.endpoint = options.errorEndpoint || null;
            this.enabled = options.enabled !== false;
        }

        /**
         * Fehler erfassen und optional senden
         */
        capture(error, context = {}) {
            if (!this.enabled) return;

            const errorEntry = {
                message: error.message || String(error),
                stack: error.stack || null,
                context: context,
                timestamp: new Date().toISOString(),
                url: typeof window !== 'undefined' ? window.location.href : null,
                userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : null
            };

            // In Array speichern (mit Limit)
            this.errors.push(errorEntry);
            if (this.errors.length > this.maxErrors) {
                this.errors.shift();
            }

            // Callback aufrufen falls vorhanden
            if (typeof this.onError === 'function') {
                try {
                    this.onError(errorEntry);
                } catch (e) {
                    console.error('ErrorMonitor callback failed:', e);
                }
            }

            // An Endpoint senden falls konfiguriert
            if (this.endpoint) {
                this.sendToEndpoint(errorEntry);
            }

            console.error('VideoTracker Error:', errorEntry);
            return errorEntry;
        }

        /**
         * Fehler an externes Monitoring senden
         */
        async sendToEndpoint(errorEntry) {
            if (!this.endpoint) return;

            try {
                // Fire-and-forget mit Beacon für Zuverlässigkeit
                if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
                    const blob = new Blob([JSON.stringify(errorEntry)], { type: 'application/json' });
                    navigator.sendBeacon(this.endpoint, blob);
                } else {
                    fetch(this.endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(errorEntry),
                        keepalive: true
                    }).catch(() => {}); // Ignore send errors
                }
            } catch {
                // Silent fail for error reporting
            }
        }

        /**
         * Alle erfassten Fehler abrufen
         */
        getErrors() {
            return [...this.errors];
        }

        /**
         * Fehler-Log leeren
         */
        clear() {
            this.errors = [];
        }
    }

    // ============================================
    // HMAC SIGNING
    // ============================================

    class WebhookSigner {
        constructor(secret) {
            this.secret = secret;
            this.algorithm = 'SHA-256';
        }

        /**
         * HMAC-SHA256 Signatur generieren
         */
        async sign(payload) {
            if (!this.secret) return null;

            const encoder = new TextEncoder();
            const data = encoder.encode(typeof payload === 'string' ? payload : JSON.stringify(payload));

            // Secret Key importieren
            const keyData = encoder.encode(this.secret);
            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: this.algorithm },
                false,
                ['sign']
            );

            // Signatur erstellen
            const signature = await crypto.subtle.sign('HMAC', key, data);

            // Zu Hex-String konvertieren
            return Array.from(new Uint8Array(signature))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }

        /**
         * Signatur verifizieren (für Server-seitige Nutzung)
         */
        async verify(payload, signature) {
            const expectedSignature = await this.sign(payload);
            return this.timingSafeEqual(signature, expectedSignature);
        }

        /**
         * Timing-safe String-Vergleich
         */
        timingSafeEqual(a, b) {
            if (typeof a !== 'string' || typeof b !== 'string') return false;
            if (a.length !== b.length) return false;

            let result = 0;
            for (let i = 0; i < a.length; i++) {
                result |= a.charCodeAt(i) ^ b.charCodeAt(i);
            }
            return result === 0;
        }
    }

    // ============================================
    // RETRY LOGIC MIT EXPONENTIAL BACKOFF
    // ============================================

    class RetryQueue {
        constructor(options = {}) {
            this.maxRetries = options.maxRetries || 3;
            this.baseDelay = options.baseDelay || 1000; // 1 Sekunde
            this.maxDelay = options.maxDelay || 30000; // 30 Sekunden
            this.queue = [];
            this.processing = false;
            this.onRetry = options.onRetry || null;
            this.onFinalFailure = options.onFinalFailure || null;
        }

        /**
         * Request zur Queue hinzufügen
         */
        add(requestFn, context = {}) {
            const item = {
                id: Date.now() + Math.random(),
                requestFn,
                context,
                attempts: 0,
                createdAt: new Date().toISOString()
            };
            this.queue.push(item);
            this.process();
            return item.id;
        }

        /**
         * Queue verarbeiten
         */
        async process() {
            if (this.processing || this.queue.length === 0) return;

            this.processing = true;

            while (this.queue.length > 0) {
                const item = this.queue[0];
                const success = await this.executeWithRetry(item);

                if (success || item.attempts >= this.maxRetries) {
                    this.queue.shift();

                    if (!success && typeof this.onFinalFailure === 'function') {
                        this.onFinalFailure(item);
                    }
                }
            }

            this.processing = false;
        }

        /**
         * Request mit Retry-Logik ausführen
         */
        async executeWithRetry(item) {
            item.attempts++;

            try {
                await item.requestFn();
                return true;
            } catch (error) {
                if (item.attempts < this.maxRetries) {
                    const delay = this.calculateDelay(item.attempts);

                    if (typeof this.onRetry === 'function') {
                        this.onRetry({
                            attempt: item.attempts,
                            maxRetries: this.maxRetries,
                            delay,
                            error: error.message,
                            context: item.context
                        });
                    }

                    await this.sleep(delay);
                    return this.executeWithRetry(item);
                }
                return false;
            }
        }

        /**
         * Exponential Backoff mit Jitter berechnen
         */
        calculateDelay(attempt) {
            // Exponential: 1s, 2s, 4s, 8s, ...
            const exponentialDelay = this.baseDelay * Math.pow(2, attempt - 1);
            // Jitter: +/- 25%
            const jitter = exponentialDelay * 0.25 * (Math.random() * 2 - 1);
            const delay = Math.min(exponentialDelay + jitter, this.maxDelay);
            return Math.round(delay);
        }

        /**
         * Sleep Utility
         */
        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        /**
         * Queue-Status abrufen
         */
        getStatus() {
            return {
                queueLength: this.queue.length,
                processing: this.processing,
                items: this.queue.map(item => ({
                    id: item.id,
                    attempts: item.attempts,
                    context: item.context,
                    createdAt: item.createdAt
                }))
            };
        }

        /**
         * Queue leeren
         */
        clear() {
            this.queue = [];
        }
    }

    // ============================================
    // POSTMESSAGE ORIGIN VERIFIER
    // ============================================

    class OriginVerifier {
        constructor(allowedOrigins = []) {
            this.allowedOrigins = new Set(allowedOrigins);
            // Standard Bunny.net Origins
            this.addOrigin('https://iframe.mediadelivery.net');
            this.addOrigin('https://player.mediadelivery.net');
            this.addOrigin('https://video.bunnycdn.com');
        }

        /**
         * Origin hinzufügen
         */
        addOrigin(origin) {
            if (origin && typeof origin === 'string') {
                // Trailing slash entfernen
                this.allowedOrigins.add(origin.replace(/\/$/, ''));
            }
        }

        /**
         * Origins aus Config hinzufügen
         */
        addOrigins(origins) {
            if (Array.isArray(origins)) {
                origins.forEach(o => this.addOrigin(o));
            }
        }

        /**
         * Origin verifizieren
         */
        isAllowed(origin) {
            if (!origin) return false;
            const normalizedOrigin = origin.replace(/\/$/, '');
            return this.allowedOrigins.has(normalizedOrigin);
        }

        /**
         * PostMessage Event verifizieren
         */
        verifyEvent(event) {
            return this.isAllowed(event.origin);
        }

        /**
         * Alle erlaubten Origins abrufen
         */
        getAllowed() {
            return Array.from(this.allowedOrigins);
        }
    }

    // ============================================
    // STANDARD KONFIGURATION
    // ============================================

    const defaultConfig = {
        // Video Einstellungen
        videoUrl: '',
        videoType: 'html5', // 'html5', 'hls' oder 'bunny'
        bunnyVideoId: '',
        bunnyLibraryId: '',

        // Player Einstellungen
        autoplay: false,
        muted: false,
        controls: true,
        poster: '',

        // Webhook Einstellungen
        webhookUrl: '',
        webhookSecret: '', // HMAC Secret für Signierung
        requireHttps: false, // Nur HTTPS Webhooks erlauben

        // Meilensteine
        milestones: {
            type: 'percent',
            values: [25, 50, 75, 100]
        },

        // Retry Einstellungen
        retry: {
            enabled: true,
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000
        },

        // Error Monitoring
        errorMonitoring: {
            enabled: true,
            errorEndpoint: null,
            onError: null,
            maxErrors: 100
        },

        // Sicherheit
        security: {
            allowedOrigins: [],
            validateEmail: true,
            sanitizeInputs: true
        },

        // Styling
        styles: {
            width: '100%',
            maxWidth: '800px',
            borderRadius: '8px',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }
    };

    // ============================================
    // HAUPTKLASSE: VideoTracker
    // ============================================

    class VideoTracker {
        constructor(containerId, userConfig = {}) {
            // Container finden
            this.container = document.getElementById(containerId);
            if (!this.container) {
                console.error(`VideoTracker: Container mit ID "${containerId}" nicht gefunden.`);
                return;
            }

            // Config zusammenführen
            this.config = this.mergeConfig(defaultConfig, userConfig);

            // Config validieren
            const validationErrors = this.validateConfig();
            if (validationErrors.length > 0) {
                validationErrors.forEach(err => console.error(`VideoTracker Config Error: ${err}`));
                // Bei kritischen Fehlern nicht initialisieren
                if (validationErrors.some(e => e.includes('webhookUrl'))) {
                    return;
                }
            }

            // Komponenten initialisieren
            this.errorMonitor = new ErrorMonitor(this.config.errorMonitoring);
            this.retryQueue = new RetryQueue({
                ...this.config.retry,
                onRetry: (info) => this.handleRetry(info),
                onFinalFailure: (item) => this.handleFinalFailure(item)
            });
            this.webhookSigner = new WebhookSigner(this.config.webhookSecret);
            this.originVerifier = new OriginVerifier(this.config.security.allowedOrigins);

            // Status
            this.video = null;
            this.email = null;
            this.videoId = this.generateVideoId();
            this.triggeredMilestones = new Set();
            this.lastTrackedTime = 0;
            this.webhooksSent = 0;
            this.webhooksFailed = 0;

            // Initialisierung
            this.extractEmailFromUrl();
            this.render();
            this.attachEventListeners();

            console.log('VideoTracker v2.0 initialisiert:', {
                email: this.email,
                videoId: this.videoId,
                milestones: this.config.milestones,
                retryEnabled: this.config.retry.enabled,
                hmacEnabled: !!this.config.webhookSecret
            });
        }

        /**
         * Configs tief zusammenführen
         */
        mergeConfig(defaults, user) {
            const result = { ...defaults };

            for (const key of Object.keys(user)) {
                if (user[key] && typeof user[key] === 'object' && !Array.isArray(user[key])) {
                    result[key] = { ...defaults[key], ...user[key] };
                } else {
                    result[key] = user[key];
                }
            }

            return result;
        }

        /**
         * Konfiguration validieren
         */
        validateConfig() {
            const errors = [];

            // Webhook URL ist Pflicht
            if (!this.config.webhookUrl) {
                errors.push('webhookUrl ist erforderlich');
            } else if (!Validators.isValidWebhookUrl(this.config.webhookUrl, this.config.requireHttps)) {
                errors.push(`webhookUrl ist ungültig${this.config.requireHttps ? ' (HTTPS erforderlich)' : ''}`);
            }

            // Video URL oder Bunny IDs erforderlich
            if (this.config.videoType === 'html5') {
                if (!this.config.videoUrl) {
                    errors.push('videoUrl ist erforderlich für HTML5 Videos');
                } else if (!Validators.isValidUrl(this.config.videoUrl)) {
                    errors.push('videoUrl ist keine gültige URL');
                }
            } else if (this.config.videoType === 'bunny') {
                if (!this.config.bunnyVideoId || !Validators.isValidBunnyId(this.config.bunnyVideoId)) {
                    errors.push('bunnyVideoId ist ungültig');
                }
                if (!this.config.bunnyLibraryId || !Validators.isValidBunnyId(this.config.bunnyLibraryId)) {
                    errors.push('bunnyLibraryId ist ungültig');
                }
            }

            // Milestones validieren
            if (!Validators.isValidMilestones(this.config.milestones)) {
                errors.push('milestones Konfiguration ist ungültig');
            }

            // Poster URL validieren (optional)
            if (this.config.poster && !Validators.isValidUrl(this.config.poster)) {
                errors.push('poster URL ist ungültig');
            }

            return errors;
        }

        /**
         * E-Mail aus URL-Parametern extrahieren mit Validierung
         */
        extractEmailFromUrl() {
            // Try parent window first (for iframe embeds like Framer)
            let search = window.location.search;
            try {
                if (window.parent && window.parent !== window && window.parent.location.search) {
                    search = window.parent.location.search;
                }
            } catch (e) {
                // Cross-origin access denied, use current window
            }
            const urlParams = new URLSearchParams(search);
            const emailParams = ['email', 'e', 'subscriber_email', 'contact_email'];

            for (const param of emailParams) {
                const value = urlParams.get(param);
                if (value) {
                    // Sanitize
                    const sanitized = this.config.security.sanitizeInputs
                        ? Validators.sanitizeString(value)
                        : value;

                    // Validieren
                    if (!this.config.security.validateEmail || Validators.isValidEmail(sanitized)) {
                        this.email = sanitized;
                        break;
                    } else {
                        console.warn(`VideoTracker: Ungültige E-Mail in URL-Parameter "${param}" gefunden.`);
                    }
                }
            }

            if (!this.email) {
                console.warn('VideoTracker: Keine gültige E-Mail in URL gefunden. Webhooks werden ohne E-Mail gesendet.');
            }
        }

        /**
         * Video-ID generieren
         */
        generateVideoId() {
            if (this.config.bunnyVideoId) {
                return `bunny_${Validators.sanitizeString(this.config.bunnyVideoId)}`;
            }
            if (this.config.videoUrl) {
                let hash = 0;
                const str = this.config.videoUrl;
                for (let i = 0; i < str.length; i++) {
                    const char = str.charCodeAt(i);
                    hash = ((hash << 5) - hash) + char;
                    hash = hash & hash;
                }
                return `video_${Math.abs(hash).toString(16)}`;
            }
            return `video_${Date.now()}`;
        }

        /**
         * Player rendern
         */
        render() {
            this.container.style.width = this.config.styles.width;
            this.container.style.maxWidth = this.config.styles.maxWidth;
            this.container.style.margin = '0 auto';

            if (this.config.videoType === 'bunny') {
                this.renderBunnyPlayer();
            } else if (this.config.videoType === 'hls') {
                this.renderHlsPlayer();
            } else {
                this.renderHtml5Player();
            }
        }

        /**
         * HTML5 Video Player rendern
         */
        renderHtml5Player() {
            this.video = document.createElement('video');
            this.video.src = this.config.videoUrl;
            this.video.controls = this.config.controls;
            this.video.autoplay = this.config.autoplay;
            this.video.muted = this.config.muted;
            this.video.playsInline = true;
            this.video.preload = 'metadata';

            if (this.config.poster) {
                this.video.poster = this.config.poster;
            }

            this.video.style.width = '100%';
            this.video.style.display = 'block';
            this.video.style.borderRadius = this.config.styles.borderRadius;
            this.video.style.boxShadow = this.config.styles.boxShadow;
            this.video.style.backgroundColor = '#000';

            // Error Handler für Video-Ladefehler
            this.video.addEventListener('error', () => {
                this.errorMonitor.capture(new Error(`Video load error: ${this.video.error?.message || 'Unknown'}`), {
                    type: 'video_load_error',
                    videoUrl: this.config.videoUrl
                });
            });

            this.container.appendChild(this.video);
        }

        /**
         * HLS Player rendern (für .m3u8 Streams)
         * Nutzt native HLS auf Safari, HLS.js auf anderen Browsern
         */
        renderHlsPlayer() {
            this.video = document.createElement('video');
            this.video.controls = this.config.controls;
            this.video.autoplay = this.config.autoplay;
            this.video.muted = this.config.muted;
            this.video.playsInline = true;
            this.video.preload = 'metadata';

            if (this.config.poster) {
                this.video.poster = this.config.poster;
            }

            this.video.style.width = '100%';
            this.video.style.display = 'block';
            this.video.style.borderRadius = this.config.styles.borderRadius;
            this.video.style.boxShadow = this.config.styles.boxShadow;
            this.video.style.backgroundColor = '#000';

            this.container.appendChild(this.video);

            // Check ob native HLS Support vorhanden ist (Safari)
            if (this.video.canPlayType('application/vnd.apple.mpegurl')) {
                // Safari: Native HLS
                this.video.src = this.config.videoUrl;
                console.log('VideoTracker: Native HLS (Safari)');
            } else {
                // Andere Browser: HLS.js laden
                this.loadHlsJs();
            }

            // Error Handler
            this.video.addEventListener('error', () => {
                this.errorMonitor.capture(new Error(`HLS Video load error: ${this.video.error?.message || 'Unknown'}`), {
                    type: 'hls_load_error',
                    videoUrl: this.config.videoUrl
                });
            });
        }

        /**
         * HLS.js dynamisch laden und initialisieren
         */
        loadHlsJs() {
            // Check ob HLS.js bereits geladen ist
            if (typeof Hls !== 'undefined') {
                this.initHls();
                return;
            }

            // HLS.js von CDN laden
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.7/dist/hls.min.js';
            script.onload = () => {
                console.log('VideoTracker: HLS.js geladen');
                this.initHls();
            };
            script.onerror = () => {
                this.errorMonitor.capture(new Error('Failed to load HLS.js'), {
                    type: 'hls_library_error'
                });
                // Fallback: Direktes src setzen (funktioniert evtl. trotzdem)
                this.video.src = this.config.videoUrl;
            };
            document.head.appendChild(script);
        }

        /**
         * HLS.js initialisieren
         */
        initHls() {
            if (typeof Hls === 'undefined') {
                console.error('VideoTracker: HLS.js nicht verfügbar');
                return;
            }

            if (Hls.isSupported()) {
                this.hls = new Hls({
                    enableWorker: true,
                    lowLatencyMode: false
                });
                this.hls.loadSource(this.config.videoUrl);
                this.hls.attachMedia(this.video);

                this.hls.on(Hls.Events.MANIFEST_PARSED, () => {
                    console.log('VideoTracker: HLS Manifest geladen');
                    if (this.config.autoplay) {
                        this.video.play().catch(() => {});
                    }
                });

                this.hls.on(Hls.Events.ERROR, (event, data) => {
                    if (data.fatal) {
                        this.errorMonitor.capture(new Error(`HLS fatal error: ${data.type}`), {
                            type: 'hls_error',
                            details: data.details
                        });
                        // Versuche Recovery
                        if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                            this.hls.startLoad();
                        } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
                            this.hls.recoverMediaError();
                        }
                    }
                });

                console.log('VideoTracker: HLS.js initialisiert');
            } else {
                console.error('VideoTracker: HLS nicht unterstützt');
                this.errorMonitor.capture(new Error('HLS not supported in this browser'), {
                    type: 'hls_not_supported'
                });
            }
        }

        /**
         * Bunny.net Stream Player rendern
         */
        renderBunnyPlayer() {
            const wrapper = document.createElement('div');
            wrapper.style.position = 'relative';
            wrapper.style.paddingTop = '56.25%';
            wrapper.style.borderRadius = this.config.styles.borderRadius;
            wrapper.style.overflow = 'hidden';
            wrapper.style.boxShadow = this.config.styles.boxShadow;

            const iframe = document.createElement('iframe');
            const bunnyUrl = `https://player.mediadelivery.net/embed/${this.config.bunnyLibraryId}/${this.config.bunnyVideoId}`;
            const params = new URLSearchParams({
                autoplay: this.config.autoplay ? 'true' : 'false',
                preload: 'true',
                responsive: 'true',
                enableApi: 'true',
                api: '1'
            });

            iframe.src = `${bunnyUrl}?${params.toString()}`;
            iframe.style.position = 'absolute';
            iframe.style.top = '0';
            iframe.style.left = '0';
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            iframe.allow = 'accelerometer; gyroscope; autoplay; encrypted-media; picture-in-picture';
            iframe.allowFullscreen = true;

            wrapper.appendChild(iframe);
            this.container.appendChild(wrapper);

            this.bunnyIframe = iframe;
            iframe.id = 'bunny-stream-embed-' + Date.now();
            this.setupBunnyTracking();
        }

        /**
         * Bunny.net Tracking via Player.js API
         */
        setupBunnyTracking() {
            // Load Player.js library
            if (typeof playerjs === 'undefined') {
                const script = document.createElement('script');
                script.src = 'https://assets.mediadelivery.net/playerjs/player-0.1.0.min.js';
                script.onload = () => {
                    console.log('VideoTracker: Player.js geladen');
                    this.initBunnyPlayer();
                };
                script.onerror = () => {
                    console.error('VideoTracker: Player.js konnte nicht geladen werden');
                    this.errorMonitor.capture(new Error('Failed to load Player.js'), {
                        type: 'playerjs_load_error'
                    });
                };
                document.head.appendChild(script);
            } else {
                this.initBunnyPlayer();
            }
        }

        /**
         * Bunny Player.js initialisieren
         */
        initBunnyPlayer() {
            if (typeof playerjs === 'undefined' || !this.bunnyIframe) {
                console.error('VideoTracker: Player.js oder iframe nicht verfügbar');
                return;
            }

            const player = new playerjs.Player(this.bunnyIframe);
            this.bunnyPlayer = player;

            player.on('ready', () => {
                console.log('VideoTracker: Bunny Player ready');

                let videoStarted = false;
                player.on('play', () => {
                    if (!videoStarted) {
                        videoStarted = true;
                        player.getDuration((duration) => {
                            this.sendWebhook({
                                event: 'video_started',
                                currentTime: 0,
                                duration: duration
                            });
                        });
                    }
                });

                player.on('timeupdate', (data) => {
                    player.getDuration((duration) => {
                        if (duration && data.seconds > 0) {
                            this.handleTimeUpdate(data.seconds, duration);
                        }
                    });
                });

                player.on('ended', () => {
                    player.getDuration((duration) => {
                        this.checkMilestone(100, duration);
                    });
                });
            });
        }

        /**
         * Event Listener für HTML5 Video
         */
        attachEventListeners() {
            if (!this.video) return;

            this.video.addEventListener('timeupdate', () => {
                const currentTime = this.video.currentTime;
                const duration = this.video.duration;

                if (duration && currentTime > 0) {
                    this.handleTimeUpdate(currentTime, duration);
                }
            });

            this.video.addEventListener('ended', () => {
                this.checkMilestone(100, this.video.duration);
            });

            this.video.addEventListener('play', () => {
                this.sendWebhook({
                    event: 'video_started',
                    currentTime: this.video.currentTime,
                    duration: this.video.duration
                });
            });
        }

        /**
         * Zeit-Update verarbeiten
         */
        handleTimeUpdate(currentTime, duration) {
            if (currentTime - this.lastTrackedTime < 0.5) return;
            this.lastTrackedTime = currentTime;

            const percentWatched = (currentTime / duration) * 100;

            if (this.config.milestones.type === 'percent') {
                this.checkPercentMilestones(percentWatched, duration);
            } else {
                this.checkTimeMilestones(currentTime, duration);
            }
        }

        /**
         * Prozentuale Meilensteine prüfen
         */
        checkPercentMilestones(percentWatched, duration) {
            for (const milestone of this.config.milestones.values) {
                if (percentWatched >= milestone && !this.triggeredMilestones.has(`percent_${milestone}`)) {
                    this.checkMilestone(milestone, duration);
                }
            }
        }

        /**
         * Zeitbasierte Meilensteine prüfen
         */
        checkTimeMilestones(currentTime, duration) {
            for (const milestone of this.config.milestones.values) {
                if (currentTime >= milestone && !this.triggeredMilestones.has(`time_${milestone}`)) {
                    this.triggeredMilestones.add(`time_${milestone}`);
                    this.sendWebhook({
                        event: 'milestone_reached',
                        milestoneType: 'time',
                        milestoneValue: milestone,
                        milestoneLabel: this.formatTime(milestone),
                        currentTime: currentTime,
                        duration: duration,
                        percentWatched: Math.round((currentTime / duration) * 100)
                    });
                }
            }
        }

        /**
         * Meilenstein verarbeiten
         */
        checkMilestone(percent, duration) {
            const key = `percent_${percent}`;
            if (this.triggeredMilestones.has(key)) return;

            this.triggeredMilestones.add(key);
            this.sendWebhook({
                event: 'milestone_reached',
                milestoneType: 'percent',
                milestoneValue: percent,
                milestoneLabel: `${percent}%`,
                duration: duration,
                percentWatched: percent
            });
        }

        /**
         * Webhook mit Signierung und Retry senden
         */
        async sendWebhook(data) {
            if (!this.config.webhookUrl) {
                console.warn('VideoTracker: Keine Webhook-URL konfiguriert.');
                return;
            }

            const payload = {
                email: this.email,
                videoId: this.videoId,
                videoUrl: this.config.videoUrl || `bunny:${this.config.bunnyLibraryId}/${this.config.bunnyVideoId}`,
                ...data,
                timestamp: new Date().toISOString(),
                pageUrl: window.location.href,
                userAgent: navigator.userAgent,
                trackerVersion: '2.0.0'
            };

            console.log('VideoTracker Webhook:', payload);

            // Request-Funktion für Retry-Queue
            const requestFn = async () => {
                const headers = {
                    'Content-Type': 'application/json'
                };

                // HMAC Signatur hinzufügen falls Secret konfiguriert
                if (this.config.webhookSecret) {
                    const signature = await this.webhookSigner.sign(payload);
                    headers['X-Webhook-Signature'] = signature;
                    headers['X-Signature-Algorithm'] = 'HMAC-SHA256';
                }

                const response = await fetch(this.config.webhookUrl, {
                    method: 'POST',
                    headers: headers,
                    mode: 'cors',
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                this.webhooksSent++;
                console.log('VideoTracker: Webhook erfolgreich gesendet');
            };

            // Mit oder ohne Retry
            if (this.config.retry.enabled) {
                this.retryQueue.add(requestFn, {
                    event: data.event,
                    milestone: data.milestoneLabel || null
                });
            } else {
                try {
                    await requestFn();
                } catch (error) {
                    this.handleWebhookError(error, payload);
                }
            }
        }

        /**
         * Webhook-Fehler behandeln
         */
        handleWebhookError(error, payload) {
            this.webhooksFailed++;

            this.errorMonitor.capture(error, {
                type: 'webhook_error',
                payload: payload
            });

            // Fallback: Beacon API
            if (navigator.sendBeacon) {
                try {
                    const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
                    const sent = navigator.sendBeacon(this.config.webhookUrl, blob);
                    if (sent) {
                        console.log('VideoTracker: Webhook via Beacon gesendet');
                    }
                } catch {
                    // Silent fail
                }
            }
        }

        /**
         * Retry-Event Handler
         */
        handleRetry(info) {
            console.warn(`VideoTracker: Webhook Retry ${info.attempt}/${info.maxRetries} in ${info.delay}ms`, info.context);
        }

        /**
         * Endgültiger Fehler nach allen Retries
         */
        handleFinalFailure(item) {
            this.webhooksFailed++;
            this.errorMonitor.capture(new Error('Webhook failed after all retries'), {
                type: 'webhook_final_failure',
                context: item.context,
                attempts: item.attempts
            });
        }

        /**
         * Zeit formatieren
         */
        formatTime(seconds) {
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        }

        /**
         * Meilensteine zurücksetzen
         */
        resetMilestones() {
            this.triggeredMilestones.clear();
            console.log('VideoTracker: Meilensteine zurückgesetzt');
        }

        /**
         * Erweiterten Status abrufen
         */
        getStatus() {
            return {
                email: this.email,
                videoId: this.videoId,
                triggeredMilestones: Array.from(this.triggeredMilestones),
                currentTime: this.video ? this.video.currentTime : null,
                duration: this.video ? this.video.duration : null,
                webhooksSent: this.webhooksSent,
                webhooksFailed: this.webhooksFailed,
                retryQueue: this.retryQueue.getStatus(),
                errors: this.errorMonitor.getErrors()
            };
        }

        /**
         * Error Monitor Zugriff
         */
        getErrorMonitor() {
            return this.errorMonitor;
        }

        /**
         * Retry Queue Zugriff
         */
        getRetryQueue() {
            return this.retryQueue;
        }
    }

    // ============================================
    // EXPORTS
    // ============================================

    // Für Browser
    window.VideoTracker = VideoTracker;

    // Utilities auch exportieren für Tests und erweiterte Nutzung
    window.VideoTrackerUtils = {
        Validators,
        ErrorMonitor,
        WebhookSigner,
        RetryQueue,
        OriginVerifier
    };

    // Für Node.js/Testing (CommonJS)
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            VideoTracker,
            Validators,
            ErrorMonitor,
            WebhookSigner,
            RetryQueue,
            OriginVerifier
        };
    }
})();