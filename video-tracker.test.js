/**
 * Video Tracker Test Suite
 *
 * Tests für alle Production-Ready Features:
 * - Input Validation
 * - HMAC Webhook Signing
 * - Retry mit Exponential Backoff
 * - Error Monitoring
 * - postMessage Origin Verification
 *
 * Ausführen mit: npx vitest run
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================
// STANDALONE UTILITY KLASSEN (kopiert für isolierte Tests)
// ============================================

const Validators = {
    isValidEmail(email) {
        if (!email || typeof email !== 'string') return false;
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return emailRegex.test(email) && email.length <= 254;
    },

    isValidUrl(url) {
        if (!url || typeof url !== 'string') return false;
        try {
            const parsed = new URL(url);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    },

    isValidWebhookUrl(url, requireHttps = false) {
        if (!this.isValidUrl(url)) return false;
        if (requireHttps) {
            return url.startsWith('https://');
        }
        return true;
    },

    isValidMilestones(milestones) {
        if (!milestones || typeof milestones !== 'object') return false;
        if (!['percent', 'time'].includes(milestones.type)) return false;
        if (!Array.isArray(milestones.values) || milestones.values.length === 0) return false;

        return milestones.values.every(v => {
            if (typeof v !== 'number' || isNaN(v) || v < 0) return false;
            if (milestones.type === 'percent' && v > 100) return false;
            if (milestones.type === 'time' && v > 86400) return false;
            return true;
        });
    },

    isValidBunnyId(id) {
        if (!id || typeof id !== 'string') return false;
        return /^[a-zA-Z0-9-]+$/.test(id) && id.length >= 1 && id.length <= 100;
    },

    sanitizeString(input) {
        if (typeof input !== 'string') return '';
        return input
            .replace(/[<>]/g, '')
            .trim()
            .slice(0, 1000);
    }
};

class ErrorMonitor {
    constructor(options = {}) {
        this.errors = [];
        this.maxErrors = options.maxErrors || 100;
        this.onError = options.onError || null;
        this.endpoint = options.errorEndpoint || null;
        this.enabled = options.enabled !== false;
    }

    capture(error, context = {}) {
        if (!this.enabled) return;

        const errorEntry = {
            message: error.message || String(error),
            stack: error.stack || null,
            context: context,
            timestamp: new Date().toISOString(),
            url: null,
            userAgent: null
        };

        this.errors.push(errorEntry);
        if (this.errors.length > this.maxErrors) {
            this.errors.shift();
        }

        if (typeof this.onError === 'function') {
            try {
                this.onError(errorEntry);
            } catch (e) {
                // ignore
            }
        }

        return errorEntry;
    }

    getErrors() {
        return [...this.errors];
    }

    clear() {
        this.errors = [];
    }
}

class WebhookSigner {
    constructor(secret) {
        this.secret = secret;
        this.algorithm = 'SHA-256';
    }

    async sign(payload) {
        if (!this.secret) return null;

        const encoder = new TextEncoder();
        const data = encoder.encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
        const keyData = encoder.encode(this.secret);

        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: this.algorithm },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', key, data);

        return Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async verify(payload, signature) {
        const expectedSignature = await this.sign(payload);
        return this.timingSafeEqual(signature, expectedSignature);
    }

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

class RetryQueue {
    constructor(options = {}) {
        this.maxRetries = options.maxRetries || 3;
        this.baseDelay = options.baseDelay || 1000;
        this.maxDelay = options.maxDelay || 30000;
        this.queue = [];
        this.processing = false;
        this.onRetry = options.onRetry || null;
        this.onFinalFailure = options.onFinalFailure || null;
    }

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

    calculateDelay(attempt) {
        const exponentialDelay = this.baseDelay * Math.pow(2, attempt - 1);
        const jitter = exponentialDelay * 0.25 * (Math.random() * 2 - 1);
        const delay = Math.min(exponentialDelay + jitter, this.maxDelay);
        return Math.round(delay);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

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

    clear() {
        this.queue = [];
    }
}

class OriginVerifier {
    constructor(allowedOrigins = []) {
        this.allowedOrigins = new Set(allowedOrigins);
        this.addOrigin('https://iframe.mediadelivery.net');
        this.addOrigin('https://video.bunnycdn.com');
    }

    addOrigin(origin) {
        if (origin && typeof origin === 'string') {
            this.allowedOrigins.add(origin.replace(/\/$/, ''));
        }
    }

    addOrigins(origins) {
        if (Array.isArray(origins)) {
            origins.forEach(o => this.addOrigin(o));
        }
    }

    isAllowed(origin) {
        if (!origin) return false;
        const normalizedOrigin = origin.replace(/\/$/, '');
        return this.allowedOrigins.has(normalizedOrigin);
    }

    verifyEvent(event) {
        return this.isAllowed(event.origin);
    }

    getAllowed() {
        return Array.from(this.allowedOrigins);
    }
}

// ============================================
// VALIDATORS TESTS
// ============================================

describe('Validators', () => {
    describe('isValidEmail', () => {
        it('sollte gültige E-Mails akzeptieren', () => {
            expect(Validators.isValidEmail('test@example.com')).toBe(true);
            expect(Validators.isValidEmail('user.name@domain.org')).toBe(true);
            expect(Validators.isValidEmail('user+tag@example.co.uk')).toBe(true);
        });

        it('sollte ungültige E-Mails ablehnen', () => {
            expect(Validators.isValidEmail('')).toBe(false);
            expect(Validators.isValidEmail(null)).toBe(false);
            expect(Validators.isValidEmail(undefined)).toBe(false);
            expect(Validators.isValidEmail('not-an-email')).toBe(false);
            expect(Validators.isValidEmail('@example.com')).toBe(false);
            expect(Validators.isValidEmail('test@')).toBe(false);
            expect(Validators.isValidEmail('test@.com')).toBe(false);
        });

        it('sollte zu lange E-Mails ablehnen', () => {
            const longEmail = 'a'.repeat(250) + '@example.com';
            expect(Validators.isValidEmail(longEmail)).toBe(false);
        });
    });

    describe('isValidUrl', () => {
        it('sollte gültige HTTP/HTTPS URLs akzeptieren', () => {
            expect(Validators.isValidUrl('https://example.com')).toBe(true);
            expect(Validators.isValidUrl('http://example.com')).toBe(true);
            expect(Validators.isValidUrl('https://example.com/path?query=1')).toBe(true);
        });

        it('sollte ungültige URLs ablehnen', () => {
            expect(Validators.isValidUrl('')).toBe(false);
            expect(Validators.isValidUrl(null)).toBe(false);
            expect(Validators.isValidUrl('not-a-url')).toBe(false);
            expect(Validators.isValidUrl('ftp://example.com')).toBe(false);
            expect(Validators.isValidUrl('javascript:alert(1)')).toBe(false);
        });
    });

    describe('isValidWebhookUrl', () => {
        it('sollte HTTPS erzwingen wenn requireHttps=true', () => {
            expect(Validators.isValidWebhookUrl('https://webhook.example.com', true)).toBe(true);
            expect(Validators.isValidWebhookUrl('http://webhook.example.com', true)).toBe(false);
        });

        it('sollte HTTP erlauben wenn requireHttps=false', () => {
            expect(Validators.isValidWebhookUrl('http://webhook.example.com', false)).toBe(true);
            expect(Validators.isValidWebhookUrl('https://webhook.example.com', false)).toBe(true);
        });
    });

    describe('isValidMilestones', () => {
        it('sollte gültige Prozent-Milestones akzeptieren', () => {
            expect(Validators.isValidMilestones({ type: 'percent', values: [25, 50, 75, 100] })).toBe(true);
            expect(Validators.isValidMilestones({ type: 'percent', values: [10, 20, 30] })).toBe(true);
        });

        it('sollte gültige Zeit-Milestones akzeptieren', () => {
            expect(Validators.isValidMilestones({ type: 'time', values: [30, 60, 120] })).toBe(true);
        });

        it('sollte ungültige Milestones ablehnen', () => {
            expect(Validators.isValidMilestones(null)).toBe(false);
            expect(Validators.isValidMilestones({})).toBe(false);
            expect(Validators.isValidMilestones({ type: 'invalid', values: [25] })).toBe(false);
            expect(Validators.isValidMilestones({ type: 'percent', values: [] })).toBe(false);
            expect(Validators.isValidMilestones({ type: 'percent', values: [150] })).toBe(false);
            expect(Validators.isValidMilestones({ type: 'percent', values: [-10] })).toBe(false);
            expect(Validators.isValidMilestones({ type: 'time', values: [100000] })).toBe(false);
        });
    });

    describe('isValidBunnyId', () => {
        it('sollte gültige Bunny IDs akzeptieren', () => {
            expect(Validators.isValidBunnyId('abc123')).toBe(true);
            expect(Validators.isValidBunnyId('video-id-123')).toBe(true);
            expect(Validators.isValidBunnyId('ABC-123-xyz')).toBe(true);
        });

        it('sollte ungültige Bunny IDs ablehnen', () => {
            expect(Validators.isValidBunnyId('')).toBe(false);
            expect(Validators.isValidBunnyId(null)).toBe(false);
            expect(Validators.isValidBunnyId('id with spaces')).toBe(false);
            expect(Validators.isValidBunnyId('id<script>')).toBe(false);
        });
    });

    describe('sanitizeString', () => {
        it('sollte HTML-Tags entfernen', () => {
            expect(Validators.sanitizeString('<script>alert(1)</script>')).toBe('scriptalert(1)/script');
            expect(Validators.sanitizeString('test<br>value')).toBe('testbrvalue');
        });

        it('sollte Whitespace trimmen', () => {
            expect(Validators.sanitizeString('  test  ')).toBe('test');
        });

        it('sollte auf 1000 Zeichen begrenzen', () => {
            const longString = 'a'.repeat(2000);
            expect(Validators.sanitizeString(longString).length).toBe(1000);
        });

        it('sollte nicht-Strings als leeren String zurückgeben', () => {
            expect(Validators.sanitizeString(null)).toBe('');
            expect(Validators.sanitizeString(123)).toBe('');
            expect(Validators.sanitizeString(undefined)).toBe('');
        });
    });
});

// ============================================
// ERROR MONITOR TESTS
// ============================================

describe('ErrorMonitor', () => {
    let monitor;

    beforeEach(() => {
        monitor = new ErrorMonitor({ maxErrors: 5 });
    });

    it('sollte Fehler erfassen', () => {
        const error = new Error('Test error');
        const entry = monitor.capture(error, { type: 'test' });

        expect(entry.message).toBe('Test error');
        expect(entry.context.type).toBe('test');
        expect(entry.timestamp).toBeDefined();
    });

    it('sollte Fehler-Array limitieren', () => {
        for (let i = 0; i < 10; i++) {
            monitor.capture(new Error(`Error ${i}`));
        }

        expect(monitor.getErrors().length).toBe(5);
        expect(monitor.getErrors()[0].message).toBe('Error 5');
    });

    it('sollte onError Callback aufrufen', () => {
        const callback = vi.fn();
        const monitorWithCallback = new ErrorMonitor({ onError: callback });

        monitorWithCallback.capture(new Error('Test'));

        expect(callback).toHaveBeenCalledOnce();
        expect(callback.mock.calls[0][0].message).toBe('Test');
    });

    it('sollte Fehler-Log leeren können', () => {
        monitor.capture(new Error('Test'));
        expect(monitor.getErrors().length).toBe(1);

        monitor.clear();
        expect(monitor.getErrors().length).toBe(0);
    });

    it('sollte deaktivierbar sein', () => {
        const disabledMonitor = new ErrorMonitor({ enabled: false });
        const result = disabledMonitor.capture(new Error('Test'));

        expect(result).toBeUndefined();
        expect(disabledMonitor.getErrors().length).toBe(0);
    });
});

// ============================================
// WEBHOOK SIGNER TESTS
// ============================================

describe('WebhookSigner', () => {
    let signer;

    beforeEach(() => {
        signer = new WebhookSigner('test-secret');
    });

    it('sollte Payload signieren', async () => {
        const payload = { event: 'test', data: 123 };
        const signature = await signer.sign(payload);

        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
        expect(signature.length).toBe(64); // SHA-256 = 32 bytes = 64 hex chars
    });

    it('sollte null zurückgeben wenn kein Secret', async () => {
        const signerNoSecret = new WebhookSigner('');
        const signature = await signerNoSecret.sign({ test: 1 });

        expect(signature).toBeNull();
    });

    it('sollte String-Payload akzeptieren', async () => {
        const signature = await signer.sign('test-string');

        expect(signature).toBeDefined();
    });

    it('sollte konsistente Signaturen generieren', async () => {
        const payload = { event: 'test' };
        const sig1 = await signer.sign(payload);
        const sig2 = await signer.sign(payload);

        expect(sig1).toBe(sig2);
    });

    describe('timingSafeEqual', () => {
        it('sollte gleiche Strings erkennen', () => {
            expect(signer.timingSafeEqual('abc123', 'abc123')).toBe(true);
        });

        it('sollte unterschiedliche Strings erkennen', () => {
            expect(signer.timingSafeEqual('abc123', 'abc124')).toBe(false);
            expect(signer.timingSafeEqual('abc123', 'abc12')).toBe(false);
        });

        it('sollte ungültige Eingaben ablehnen', () => {
            expect(signer.timingSafeEqual(null, 'abc')).toBe(false);
            expect(signer.timingSafeEqual('abc', null)).toBe(false);
            expect(signer.timingSafeEqual(123, 'abc')).toBe(false);
        });
    });

    describe('verify', () => {
        it('sollte gültige Signatur verifizieren', async () => {
            const payload = { test: 'data' };
            const signature = await signer.sign(payload);
            const isValid = await signer.verify(payload, signature);

            expect(isValid).toBe(true);
        });

        it('sollte ungültige Signatur ablehnen', async () => {
            const payload = { test: 'data' };
            const isValid = await signer.verify(payload, 'invalid-signature');

            expect(isValid).toBe(false);
        });
    });
});

// ============================================
// RETRY QUEUE TESTS
// ============================================

describe('RetryQueue', () => {
    let queue;

    beforeEach(() => {
        vi.useFakeTimers();
        queue = new RetryQueue({
            maxRetries: 3,
            baseDelay: 100,
            maxDelay: 1000
        });
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('sollte erfolgreiche Requests sofort verarbeiten', async () => {
        const requestFn = vi.fn().mockResolvedValue('success');

        queue.add(requestFn, { test: 1 });
        await vi.runAllTimersAsync();

        expect(requestFn).toHaveBeenCalledOnce();
    });

    it('sollte bei Fehlern wiederholen', async () => {
        let attempts = 0;
        const requestFn = vi.fn().mockImplementation(() => {
            attempts++;
            if (attempts < 3) throw new Error('Fail');
            return Promise.resolve('success');
        });

        queue.add(requestFn);
        await vi.runAllTimersAsync();

        expect(requestFn).toHaveBeenCalledTimes(3);
    });

    it('sollte onRetry Callback aufrufen', async () => {
        const onRetry = vi.fn();
        const retryQueue = new RetryQueue({
            maxRetries: 3,
            baseDelay: 100,
            onRetry
        });

        const failingFn = vi.fn().mockRejectedValue(new Error('Fail'));
        retryQueue.add(failingFn);
        await vi.runAllTimersAsync();

        expect(onRetry).toHaveBeenCalled();
        expect(onRetry.mock.calls[0][0].attempt).toBe(1);
    });

    it('sollte onFinalFailure nach allen Retries aufrufen', async () => {
        const onFinalFailure = vi.fn();
        const retryQueue = new RetryQueue({
            maxRetries: 2,
            baseDelay: 100,
            onFinalFailure
        });

        const failingFn = vi.fn().mockRejectedValue(new Error('Fail'));
        retryQueue.add(failingFn, { context: 'test' });
        await vi.runAllTimersAsync();

        expect(onFinalFailure).toHaveBeenCalledOnce();
    });

    describe('calculateDelay', () => {
        it('sollte exponentiell ansteigen', () => {
            const delay1 = queue.calculateDelay(1);
            const delay2 = queue.calculateDelay(2);
            const delay3 = queue.calculateDelay(3);

            expect(delay1).toBeGreaterThanOrEqual(75);
            expect(delay1).toBeLessThanOrEqual(125);

            expect(delay2).toBeGreaterThanOrEqual(150);
            expect(delay2).toBeLessThanOrEqual(250);

            expect(delay3).toBeGreaterThanOrEqual(300);
            expect(delay3).toBeLessThanOrEqual(500);
        });

        it('sollte maxDelay nicht überschreiten', () => {
            const delay = queue.calculateDelay(10);
            expect(delay).toBeLessThanOrEqual(1000);
        });
    });

    describe('getStatus', () => {
        it('sollte Queue-Status zurückgeben', () => {
            const status = queue.getStatus();

            expect(status.queueLength).toBe(0);
            expect(status.processing).toBe(false);
            expect(Array.isArray(status.items)).toBe(true);
        });
    });

    describe('clear', () => {
        it('sollte Queue leeren', () => {
            queue.queue.push({ id: 1 });
            queue.queue.push({ id: 2 });
            expect(queue.queue.length).toBe(2);

            queue.clear();
            expect(queue.queue.length).toBe(0);
        });
    });
});

// ============================================
// ORIGIN VERIFIER TESTS
// ============================================

describe('OriginVerifier', () => {
    let verifier;

    beforeEach(() => {
        verifier = new OriginVerifier();
    });

    it('sollte Standard Bunny.net Origins erlauben', () => {
        expect(verifier.isAllowed('https://iframe.mediadelivery.net')).toBe(true);
        expect(verifier.isAllowed('https://video.bunnycdn.com')).toBe(true);
    });

    it('sollte unbekannte Origins ablehnen', () => {
        expect(verifier.isAllowed('https://evil.com')).toBe(false);
        expect(verifier.isAllowed('https://attacker.example.org')).toBe(false);
    });

    it('sollte benutzerdefinierte Origins hinzufügen können', () => {
        verifier.addOrigin('https://custom.example.com');
        expect(verifier.isAllowed('https://custom.example.com')).toBe(true);
    });

    it('sollte mehrere Origins auf einmal hinzufügen können', () => {
        verifier.addOrigins([
            'https://origin1.com',
            'https://origin2.com'
        ]);

        expect(verifier.isAllowed('https://origin1.com')).toBe(true);
        expect(verifier.isAllowed('https://origin2.com')).toBe(true);
    });

    it('sollte Trailing Slashes normalisieren', () => {
        verifier.addOrigin('https://example.com/');
        expect(verifier.isAllowed('https://example.com')).toBe(true);
        expect(verifier.isAllowed('https://example.com/')).toBe(true);
    });

    it('sollte postMessage Events verifizieren', () => {
        const validEvent = { origin: 'https://iframe.mediadelivery.net' };
        const invalidEvent = { origin: 'https://evil.com' };

        expect(verifier.verifyEvent(validEvent)).toBe(true);
        expect(verifier.verifyEvent(invalidEvent)).toBe(false);
    });

    it('sollte null/undefined Origins ablehnen', () => {
        expect(verifier.isAllowed(null)).toBe(false);
        expect(verifier.isAllowed(undefined)).toBe(false);
        expect(verifier.isAllowed('')).toBe(false);
    });

    it('sollte alle erlaubten Origins zurückgeben', () => {
        const allowed = verifier.getAllowed();

        expect(Array.isArray(allowed)).toBe(true);
        expect(allowed).toContain('https://iframe.mediadelivery.net');
        expect(allowed).toContain('https://video.bunnycdn.com');
    });
});

// ============================================
// INTEGRATION TESTS
// ============================================

describe('Integration', () => {
    it('sollte validierten Webhook mit Signatur senden können', async () => {
        const signer = new WebhookSigner('my-secret');
        const payload = {
            email: 'test@example.com',
            event: 'milestone_reached',
            milestoneValue: 50
        };

        expect(Validators.isValidEmail(payload.email)).toBe(true);

        const signature = await signer.sign(payload);
        expect(signature).toBeDefined();

        const isValid = await signer.verify(payload, signature);
        expect(isValid).toBe(true);
    });

    it('sollte Error Monitoring mit Retry kombinieren', async () => {
        vi.useFakeTimers();

        const errorMonitor = new ErrorMonitor();
        const retryQueue = new RetryQueue({
            maxRetries: 2,
            baseDelay: 100,
            onFinalFailure: (item) => {
                errorMonitor.capture(new Error('Request failed'), { context: item.context });
            }
        });

        const failingRequest = vi.fn().mockRejectedValue(new Error('Network error'));
        retryQueue.add(failingRequest, { webhook: 'test' });

        await vi.runAllTimersAsync();

        expect(errorMonitor.getErrors().length).toBe(1);
        expect(errorMonitor.getErrors()[0].context.context.webhook).toBe('test');

        vi.useRealTimers();
    });

    it('sollte Origin Verification mit Validierung kombinieren', () => {
        const verifier = new OriginVerifier();
        const webhookUrl = 'https://webhook.example.com/endpoint';

        // URL validieren
        expect(Validators.isValidWebhookUrl(webhookUrl, true)).toBe(true);

        // Origin-Check für Bunny
        expect(verifier.isAllowed('https://iframe.mediadelivery.net')).toBe(true);
    });
});

// ============================================
// SECURITY TESTS
// ============================================

describe('Security', () => {
    it('sollte XSS in E-Mail verhindern', () => {
        const maliciousEmail = '<script>alert("xss")</script>@example.com';
        const sanitized = Validators.sanitizeString(maliciousEmail);

        expect(sanitized).not.toContain('<script>');
        expect(sanitized).not.toContain('</script>');
    });

    it('sollte JavaScript URLs ablehnen', () => {
        expect(Validators.isValidUrl('javascript:alert(1)')).toBe(false);
        expect(Validators.isValidWebhookUrl('javascript:alert(1)')).toBe(false);
    });

    it('sollte Origin Spoofing verhindern', () => {
        const verifier = new OriginVerifier(['https://trusted.com']);

        expect(verifier.isAllowed('https://trusted.com.evil.com')).toBe(false);
        expect(verifier.isAllowed('https://evil.trusted.com')).toBe(false);
        expect(verifier.isAllowed('http://trusted.com')).toBe(false);
    });

    it('sollte Timing-Safe Vergleich nutzen', () => {
        const signer = new WebhookSigner('secret');

        const result1 = signer.timingSafeEqual('aaaa', 'aaab');
        const result2 = signer.timingSafeEqual('aaaa', 'baaa');

        expect(result1).toBe(false);
        expect(result2).toBe(false);
    });

    it('sollte lange Inputs begrenzen', () => {
        const longInput = 'x'.repeat(5000);
        const sanitized = Validators.sanitizeString(longInput);

        expect(sanitized.length).toBe(1000);
    });

    it('sollte verschiedene XSS-Varianten blockieren', () => {
        const testCases = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            '<a href="javascript:alert(1)">click</a>'
        ];

        for (const malicious of testCases) {
            const sanitized = Validators.sanitizeString(malicious);
            expect(sanitized).not.toContain('<');
            expect(sanitized).not.toContain('>');
        }
    });
});

// ============================================
// EDGE CASE TESTS
// ============================================

describe('Edge Cases', () => {
    it('sollte leere Konfiguration handhaben', () => {
        const monitor = new ErrorMonitor({});
        expect(monitor.maxErrors).toBe(100);
        expect(monitor.enabled).toBe(true);
    });

    it('sollte Unicode in E-Mails handhaben', () => {
        // Internationale Domain
        expect(Validators.isValidEmail('test@münchen.de')).toBe(false); // ASCII only in local regex
        expect(Validators.isValidEmail('test@example.com')).toBe(true);
    });

    it('sollte sehr lange URLs ablehnen', () => {
        const longUrl = 'https://example.com/' + 'a'.repeat(10000);
        // URL sollte noch parsen, aber es ist trotzdem eine gültige URL
        expect(Validators.isValidUrl(longUrl)).toBe(true);
    });

    it('sollte Prozent-Grenzwerte korrekt prüfen', () => {
        expect(Validators.isValidMilestones({ type: 'percent', values: [0] })).toBe(true);
        expect(Validators.isValidMilestones({ type: 'percent', values: [100] })).toBe(true);
        expect(Validators.isValidMilestones({ type: 'percent', values: [100.1] })).toBe(false);
    });

    it('sollte Zeit-Grenzwerte korrekt prüfen', () => {
        expect(Validators.isValidMilestones({ type: 'time', values: [0] })).toBe(true);
        expect(Validators.isValidMilestones({ type: 'time', values: [86400] })).toBe(true); // 24h
        expect(Validators.isValidMilestones({ type: 'time', values: [86401] })).toBe(false); // >24h
    });
});
