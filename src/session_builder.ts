// TypeScript migration of session_builder.js
// TODO: Add proper type annotations
// TODO: Replace require() with import statements
// TODO: Add TypeScript interfaces and types
// TODO: Update exports to use ES6 syntax
import { Mutex, withTimeout, Semaphore, E_CANCELED } from 'async-mutex';
import { BaseKey } from './types';
import type { WhatsAppProtocolAddressType, StorageType, E2ESession, PreKeyWhisperMessageType, KeyPairType } from './types';
import { SessionRecord, SessionEntry } from './session_record';
import { ChainType } from './types';
import { crypto } from './crypto';
import { curve } from './curve';
import { errors } from './errors';
import { MUTEX_TIMEOUT, MUTEX_CLEANUP_INTERVAL, MAX_RETRIES, RETRY_DELAY, OperationPriority } from './mutex_config';

// import { queueJob } from './queue_job'; // Replaced by async-mutex

export class SessionBuilder {
    addr: WhatsAppProtocolAddressType;
    storage: StorageType;
    
    // Static mutex management with enhanced tracking
    private static mutexes = new Map<string, { mutex: Mutex; lastUsed: number }>();
    private static mutexStats = new Map<string, { acquisitions: number; totalWaitTime: number; errors: number }>();
    private static priorityQueues = new Map<string, { high: Semaphore; normal: Semaphore; low: Semaphore }>();
    private static cleanupTimer?: NodeJS.Timeout;
    
    // Instance-level cancellation support
    private abortControllers = new Map<string, AbortController>();

    constructor(storage: StorageType, protocolAddress: WhatsAppProtocolAddressType) {
        this.addr = protocolAddress;
        this.storage = storage;
        
        // Start cleanup timer if not already running
        SessionBuilder.startCleanupTimer();
    }

    /**
     * Get or create a mutex for this specific address with timeout protection
     */
    private getMutex(): Mutex {
        const key = this.addr.toString();
        const now = Date.now();
        
        if (!SessionBuilder.mutexes.has(key)) {
            SessionBuilder.mutexes.set(key, {
                mutex: new Mutex(),
                lastUsed: now
            });
            // Initialize stats
            SessionBuilder.mutexStats.set(key, { acquisitions: 0, totalWaitTime: 0, errors: 0 });
        } else {
            // Update last used time
            SessionBuilder.mutexes.get(key)!.lastUsed = now;
        }
        
        // Return the base mutex - timeout is handled in the execution layer
        return SessionBuilder.mutexes.get(key)!.mutex;
    }

    /**
     * Get or create priority queues for this address
     */
    private getOrCreatePriorityQueues(key: string): { high: Semaphore; normal: Semaphore; low: Semaphore } {
        if (!SessionBuilder.priorityQueues.has(key)) {
            SessionBuilder.priorityQueues.set(key, {
                high: new Semaphore(1),    // High priority: immediate processing
                normal: new Semaphore(1),  // Normal priority: standard processing  
                low: new Semaphore(1)      // Low priority: background processing
            });
        }
        return SessionBuilder.priorityQueues.get(key)!;
    }

    /**
     * Execute operation with retry logic and error recovery
     */
    private async executeWithRetry<T>(
        operation: () => Promise<T>,
        retries: number = MAX_RETRIES,
        operationName: string = 'unknown'
    ): Promise<T> {
        const key = this.addr.toString();
        
        try {
            return await operation();
        } catch (error: any) {
            // Update error stats
            const stats = SessionBuilder.mutexStats.get(key);
            if (stats) {
                stats.errors++;
            }
            
            // Don't retry on cancellation or if no retries left
            if (error === E_CANCELED || retries <= 0) {
                throw error;
            }
            
            // Retry on timeout or deadlock scenarios
            if (error.message?.includes('timeout') || 
                error.message?.includes('deadlock') ||
                error.message?.includes('EBUSY')) {
                console.warn(`[SessionBuilder] Retrying ${operationName} for ${key} after error: ${error.message}, ${retries} retries left`);
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
                return this.executeWithRetry(operation, retries - 1, operationName);
            }
            
            throw error;
        }
    }

    /**
     * Run operation with priority-based execution
     */
    private async runWithPriority<T>(
        priority: OperationPriority,
        operation: () => Promise<T>,
        operationName: string = 'unknown'
    ): Promise<T> {
        const key = this.addr.toString();
        const queues = this.getOrCreatePriorityQueues(key);
        
        const semaphore = priority === OperationPriority.HIGH ? queues.high :
                         priority === OperationPriority.NORMAL ? queues.normal : queues.low;
        
        return await semaphore.runExclusive(async () => {
            return await this.executeWithRetry(operation, MAX_RETRIES, operationName);
        });
    }

    /**
     * Start cleanup timer to remove unused mutexes
     */
    private static startCleanupTimer(): void {
        if (!SessionBuilder.cleanupTimer) {
            SessionBuilder.cleanupTimer = setInterval(() => {
                SessionBuilder.cleanupOldMutexes();
            }, MUTEX_CLEANUP_INTERVAL);
        }
    }

    /**
     * Remove mutexes that haven't been used recently with enhanced cleanup
     */
    private static cleanupOldMutexes(): void {
        const now = Date.now();
        const cutoff = now - MUTEX_CLEANUP_INTERVAL;
        
        for (const [key, entry] of SessionBuilder.mutexes.entries()) {
            if (entry.lastUsed < cutoff && !entry.mutex.isLocked()) {
                // Clean up mutex
                SessionBuilder.mutexes.delete(key);
                
                // Clean up related data structures
                SessionBuilder.mutexStats.delete(key);
                SessionBuilder.priorityQueues.delete(key);
            }
        }
    }

    /**
     * Cancel pending operations for specific address or all addresses
     */
    cancelPendingOperations(address?: string): void {
        if (address) {
            const controller = this.abortControllers.get(address);
            if (controller) {
                controller.abort();
                this.abortControllers.delete(address);
            }
        } else {
            // Cancel all operations for this instance
            for (const controller of this.abortControllers.values()) {
                controller.abort();
            }
            this.abortControllers.clear();
        }
    }

    /**
     * Get comprehensive health metrics for monitoring
     */
    static getMutexHealth(): {
        totalMutexes: number;
        lockedMutexes: number;
        avgWaitTime: number;
        oldestMutex: number;
        totalAcquisitions: number;
        totalErrors: number;
        priorityQueues: number;
    } {
        const now = Date.now();
        let lockedCount = 0;
        let totalWaitTime = 0;
        let totalAcquisitions = 0;
        let totalErrors = 0;
        let oldestTime = now;
        
        // Analyze mutexes
        for (const [key, entry] of SessionBuilder.mutexes.entries()) {
            if (entry.mutex.isLocked()) lockedCount++;
            if (entry.lastUsed < oldestTime) oldestTime = entry.lastUsed;
        }
        
        // Analyze stats
        for (const stats of SessionBuilder.mutexStats.values()) {
            totalWaitTime += stats.totalWaitTime;
            totalAcquisitions += stats.acquisitions;
            totalErrors += stats.errors;
        }
        
        return {
            totalMutexes: SessionBuilder.mutexes.size,
            lockedMutexes: lockedCount,
            avgWaitTime: totalAcquisitions > 0 ? totalWaitTime / totalAcquisitions : 0,
            oldestMutex: now - oldestTime,
            totalAcquisitions,
            totalErrors,
            priorityQueues: SessionBuilder.priorityQueues.size
        };
    }

    /**
     * Reset all mutex statistics (useful for testing or monitoring resets)
     */
    static resetMutexStats(): void {
        SessionBuilder.mutexStats.clear();
    }

    /**
     * Initialize outgoing session with mutex protection
     * Uses NORMAL priority as it's user-initiated but not urgent
     */
    async initOutgoing(device: E2ESession): Promise<void> {
        const key = this.addr.toString();
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            return await this.runWithPriority(
                OperationPriority.NORMAL,
                async () => {
                    if (controller.signal.aborted) {
                        throw new Error('Operation cancelled');
                    }
                    
                    const startTime = Date.now();
                    const mutex = this.getMutex();
                    
                    // Use withTimeout for mutex execution
                    const result = await withTimeout(mutex, MUTEX_TIMEOUT).runExclusive(async () => {
                        // Track acquisition metrics
                        const waitTime = Date.now() - startTime;
                        const stats = SessionBuilder.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.initOutgoingJob(device);
                    });
                    
                    return result;
                },
                'initOutgoing'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    /**
     * Internal implementation for outgoing session initialization
     */
    private async initOutgoingJob(device: E2ESession): Promise<void> {
        const fqAddr = this.addr.toString();
        
        // Validate required parameters
        if (!device.identityKey) {
            throw new Error("Missing required parameter: device.identityKey");
        }
        if (!device.registrationId) {
            throw new Error("Missing required parameter: device.registrationId");
        }
        if (!device.signedPreKey?.keyPair?.pubKey) {
            throw new Error("Missing required parameter: device.signedPreKey.keyPair.pubKey");
        }
        
        if (!await this.storage.isTrustedIdentity(this.addr.id, Buffer.from(device.identityKey))) {
            throw new errors.UntrustedIdentityKeyError(this.addr.id, device.identityKey);
        }
        
        curve.verifySignature(device.identityKey, device.signedPreKey.keyPair.pubKey,
                              device.signedPreKey.signature, true);
        
        const baseKey = curve.generateKeyPair();
        const devicePreKey = device.preKey && device.preKey?.keyPair?.pubKey;
        const session = await this.initSession(true, baseKey, undefined, device.identityKey,
                                               devicePreKey, device.signedPreKey?.keyPair?.pubKey,
                                               device.registrationId);
        
        session.pendingPreKey = {
            signedKeyId: device.signedPreKey?.keyId,
            baseKey: baseKey.pubKey
        };
        
        if (device.preKey?.keyId !== undefined) {
            session.pendingPreKey.preKeyId = device.preKey.keyId;
        }
        
        let record = await this.storage.loadSession(fqAddr);
        if (!record) {
            record = new SessionRecord();
        } else {
            const openSession = record.getOpenSession();
            if (openSession) {
                console.warn("Closing stale open session for new outgoing prekey bundle");
                record.closeSession(openSession);
            }
        }
        
        record.setSession(session);
        await this.storage.storeSession(fqAddr, record);
    }


    /**
     * Process incoming pre-key message with mutex protection (wrapper)
     * Uses HIGH priority as incoming messages are critical for real-time chat
     */
    async initIncoming(record: SessionRecord, message: PreKeyWhisperMessageType): Promise<number | undefined> {
        const key = this.addr.toString();
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            return await this.runWithPriority(
                OperationPriority.HIGH, // High priority for incoming messages
                async () => {
                    if (controller.signal.aborted) {
                        throw new Error('Operation cancelled');
                    }
                    
                    const startTime = Date.now();
                    const mutex = this.getMutex();
                    
                    // Use withTimeout for mutex execution
                    const result = await withTimeout(mutex, MUTEX_TIMEOUT).runExclusive(async () => {
                        // Track acquisition metrics
                        const waitTime = Date.now() - startTime;
                        const stats = SessionBuilder.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processIncomingJob(record, message);
                    });
                    
                    return result;
                },
                'initIncoming'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    /**
     * Internal implementation for incoming pre-key message processing
     */
    private async processIncomingJob(record: SessionRecord, message: PreKeyWhisperMessageType): Promise<number | undefined> {
        const fqAddr = this.addr.toString();

        if (!await this.storage.isTrustedIdentity(fqAddr, Buffer.from(message.identityKey))) {
            throw new errors.UntrustedIdentityKeyError(this.addr.id, message.identityKey);
        }
        
        if (record.getSession(Buffer.from(message.baseKey))) {
            // This just means we haven't replied.
            return undefined;
        }
        
        const preKeyPair = await this.storage.loadPreKey(message.preKeyId);
        if (message.preKeyId && !preKeyPair) {
            throw new errors.PreKeyError('Invalid PreKey ID');
        }   
        
        const signedPreKeyPair = await this.storage.loadSignedPreKey(message.signedPreKeyId);
        if (!signedPreKeyPair) { 
            throw new errors.PreKeyError("Missing SignedPreKey");
        }   
        const existingOpenSession = record.getOpenSession();
        if (existingOpenSession) {
            console.warn("Closing open session in favor of incoming prekey bundle");
            record.closeSession(existingOpenSession);
        }
        record.setSession(await this.initSession(false, preKeyPair?.keyPair, signedPreKeyPair,
                                                 message.identityKey, message.baseKey,
                                                 undefined, message.registrationId));
        // Original Baileys logic: return preKeyId for tracking (line 80 in JS version)
        return message.preKeyId;
    }

    async initSession(isInitiator: boolean, ourEphemeralKey: KeyPairType, ourSignedKey: KeyPairType, theirIdentityPubKey: Uint8Array,
                      theirEphemeralPubKey: Uint8Array, theirSignedPubKey: Uint8Array | undefined, registrationId: number): Promise<SessionEntry> {
        if (isInitiator) {
            if (ourSignedKey) {
                throw new Error("Invalid call to initSession");
            }
            ourSignedKey = ourEphemeralKey;
        } else {
            if (!theirSignedPubKey) {
                theirSignedPubKey = theirEphemeralPubKey;
            }
        }
        
        // Validate required parameters before Buffer.from() calls
        if (!theirIdentityPubKey) {
            throw new Error("theirIdentityPubKey is required for ECDHE");
        }
        if (!theirEphemeralPubKey) {
            throw new Error("theirEphemeralPubKey is required for ECDHE");
        }
        if (!theirSignedPubKey) {
            throw new Error("theirSignedPubKey is required for ECDHE");
        }
        
        let sharedSecret: Uint8Array;
        if (!ourEphemeralKey || !theirEphemeralPubKey) {
            sharedSecret = new Uint8Array(32 * 4);
        } else {
            sharedSecret = new Uint8Array(32 * 5);
        }
        for (var i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff;
        }
        const ourIdentityKey = await this.storage.getOurIdentity();
        const a1 = curve.calculateAgreement(Buffer.from(theirSignedPubKey), ourIdentityKey.privKey);
        const a2 = curve.calculateAgreement(Buffer.from(theirIdentityPubKey), ourSignedKey.privKey);
        const a3 = curve.calculateAgreement(Buffer.from(theirSignedPubKey), ourSignedKey.privKey);
        if (isInitiator) {
            sharedSecret.set(new Uint8Array(a1), 32);
            sharedSecret.set(new Uint8Array(a2), 32 * 2);
        } else {
            sharedSecret.set(new Uint8Array(a1), 32 * 2);
            sharedSecret.set(new Uint8Array(a2), 32);
        }
        sharedSecret.set(new Uint8Array(a3), 32 * 3);
        if (ourEphemeralKey && theirEphemeralPubKey) {
            const a4 = curve.calculateAgreement(Buffer.from(theirEphemeralPubKey), ourEphemeralKey.privKey);
            sharedSecret.set(new Uint8Array(a4), 32 * 4);
        }
        const masterKey = crypto.deriveSecrets(Buffer.from(sharedSecret), Buffer.alloc(32),
                                               Buffer.from("WhisperText"));
        const session = SessionRecord.createEntry();
        session.registrationId = registrationId;
        session.currentRatchet = {
            rootKey: masterKey[0],
            ephemeralKeyPair: isInitiator ? curve.generateKeyPair() : ourSignedKey,
            lastRemoteEphemeralKey: Buffer.from(theirSignedPubKey),
            previousCounter: 0
        };
        session.indexInfo = {
            created: Date.now(),
            used: Date.now(),
            remoteIdentityKey: Buffer.from(theirIdentityPubKey),
            baseKey: isInitiator ? ourEphemeralKey.pubKey : Buffer.from(theirEphemeralPubKey),
            baseKeyType: isInitiator ? BaseKey.OURS : BaseKey.THEIRS,
            closed: -1
        };
        if (isInitiator) {
            // If we're initiating we go ahead and set our first sending ephemeral key now,
            // otherwise we figure itra out when we first maybeStepRatchet with the remote's
            // ephemeral key
            this.calculateSendingRatchet(session, theirSignedPubKey);
        }
        return session;
    }

    calculateSendingRatchet(session: SessionEntry, remoteKey: Uint8Array) {
        const ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(Buffer.from(remoteKey), ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from("WhisperRatchet"));
        session.addChain(ratchet.ephemeralKeyPair.pubKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: ChainType.SENDING
        });
        ratchet.rootKey = masterKey[0];
    }
}
