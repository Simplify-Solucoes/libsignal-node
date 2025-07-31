// TypeScript migration of session_cipher.js
// TODO: Add proper type annotations
// TODO: Replace require() with import statements
// TODO: Add TypeScript interfaces and types
// TODO: Update exports to use ES6 syntax
import { Mutex, withTimeout, Semaphore, E_CANCELED } from 'async-mutex';
import { crypto } from './crypto'; // Assuming crypto.js is in the same directory
import { curve } from './curve';
import type { WhatsAppProtocolAddressType, StorageType, EncryptionResult, Chain } from './types';
import { ChainType, EncryptionResultMessageType } from './types';
import { PreKeyWhisperMessage, WhisperMessage } from './protobufs';
import { SessionRecord, SessionEntry } from './session_record';
import { SessionBuilder } from './session_builder';
import { MUTEX_TIMEOUT, MUTEX_CLEANUP_INTERVAL, MAX_RETRIES, RETRY_DELAY, OperationPriority } from './mutex_config';
import { errors } from './errors';
// vim: ts=4:sw=4:expandtab

const VERSION = 3;

export class SessionCipher {
    storage: StorageType;
    addr: WhatsAppProtocolAddressType;

    private static mutexes = new Map<string, { mutex: Mutex; lastUsed: number }>();
    private static mutexStats = new Map<string, { acquisitions: number; totalWaitTime: number; errors: number }>();
    private static priorityQueues = new Map<string, { high: Semaphore; normal: Semaphore; low: Semaphore }>();
    private static cleanupTimer?: NodeJS.Timeout;
    private abortControllers = new Map<string, AbortController>();

    constructor(storage: StorageType, protocolAddress: WhatsAppProtocolAddressType) {
        this.addr = protocolAddress;
        this.storage = storage;
        SessionCipher.startCleanupTimer();
    }
    /**
     * Get or create a mutex for this specific address with timeout protection
     */
    private getMutex(): Mutex {
        const key = this.addr.toString();
        const now = Date.now();
        
        if (!SessionCipher.mutexes.has(key)) {
            SessionCipher.mutexes.set(key, {
                mutex: new Mutex(),
                lastUsed: now
            });
            // Initialize stats
            SessionCipher.mutexStats.set(key, { acquisitions: 0, totalWaitTime: 0, errors: 0 });
        } else {
            // Update last used time
            SessionCipher.mutexes.get(key)!.lastUsed = now;
        }
        
        // Return the base mutex - timeout is handled in the execution layer
        return SessionCipher.mutexes.get(key)!.mutex;
    }

    /**
     * Get or create priority queues for this address
     */
    private getOrCreatePriorityQueues(key: string): { high: Semaphore; normal: Semaphore; low: Semaphore } {
        if (!SessionCipher.priorityQueues.has(key)) {
            SessionCipher.priorityQueues.set(key, {
                high: new Semaphore(1),    // High priority: immediate processing
                normal: new Semaphore(1),  // Normal priority: standard processing  
                low: new Semaphore(1)      // Low priority: background processing
            });
        }
        return SessionCipher.priorityQueues.get(key)!;
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
            const stats = SessionCipher.mutexStats.get(key);
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
        if (!SessionCipher.cleanupTimer) {
            SessionCipher.cleanupTimer = setInterval(() => {
                SessionCipher.cleanupOldMutexes();
            }, MUTEX_CLEANUP_INTERVAL);
        }
    }

    /**
     * Remove mutexes that haven't been used recently with enhanced cleanup
     */
    private static cleanupOldMutexes(): void {
        const now = Date.now();
        const cutoff = now - MUTEX_CLEANUP_INTERVAL;
        
        for (const [key, entry] of SessionCipher.mutexes.entries()) {
            if (entry.lastUsed < cutoff && !entry.mutex.isLocked()) {
                // Clean up mutex
                SessionCipher.mutexes.delete(key);
                
                // Clean up related data structures
                SessionCipher.mutexStats.delete(key);
                SessionCipher.priorityQueues.delete(key);
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
        for (const [key, entry] of SessionCipher.mutexes.entries()) {
            if (entry.mutex.isLocked()) lockedCount++;
            if (entry.lastUsed < oldestTime) oldestTime = entry.lastUsed;
        }
        
        // Analyze stats
        for (const stats of SessionCipher.mutexStats.values()) {
            totalWaitTime += stats.totalWaitTime;
            totalAcquisitions += stats.acquisitions;
            totalErrors += stats.errors;
        }
        
        return {
            totalMutexes: SessionCipher.mutexes.size,
            lockedMutexes: lockedCount,
            avgWaitTime: totalAcquisitions > 0 ? totalWaitTime / totalAcquisitions : 0,
            oldestMutex: now - oldestTime,
            totalAcquisitions,
            totalErrors,
            priorityQueues: SessionCipher.priorityQueues.size
        };
    }

    /**
     * Reset all mutex statistics (useful for testing or monitoring resets)
     */
    static resetMutexStats(): void {
        SessionCipher.mutexStats.clear();
    }


    _encodeTupleByte(number1: number, number2: number): number {
        if (number1 > 15 || number2 > 15) {
            throw TypeError("Numbers must be 4 bits or less");
        }
        return (number1 << 4) | number2;
    }

    _decodeTupleByte(byte: number): [number, number] {
        return [byte >> 4, byte & 0xf];
    }

    toString(): string {
        return `<SessionCipher(${this.addr.toString()})>`;
    }

    async getRecord(): Promise<SessionRecord | null> {
        const record = await this.storage.loadSession(this.addr.toString());
        return record;
    }

    async storeRecord(record: SessionRecord): Promise<void> {
        record.removeOldSessions();
        await this.storage.storeSession(this.addr.toString(), record);
    }

    async encrypt(data: Uint8Array): Promise<EncryptionResult> {
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
                        const stats = SessionCipher.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processencrypt(data);
                    });
                    
                    return result;
                },
                'encrypt'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    private async processencrypt(data: Uint8Array): Promise<EncryptionResult> {
        const ourIdentityKey = await this.storage.getOurIdentity();
        
            const record = await this.getRecord();
            if (!record) {
                throw new errors.SessionError("No sessions");
            }
            const session = record.getOpenSession();
            if (!session) {
                throw new errors.SessionError("No open session");
            }
            const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }
            const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }
            this.fillMessageKeys(chain, chain.chainKey.counter + 1);
            const keys = crypto.deriveSecrets(chain.messageKeys[chain.chainKey.counter],
                                              Buffer.alloc(32), Buffer.from("WhisperMessageKeys"));
            delete chain.messageKeys[chain.chainKey.counter];
            const msg = new WhisperMessage({});
            msg.ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey;
            msg.counter = chain.chainKey.counter;
            msg.previousCounter = session.currentRatchet.previousCounter;
            msg.ciphertext = crypto.encrypt(keys[0], Buffer.from(data), keys[2].slice(0, 16));
            const msgBuf = msg.serialize();
            const macInput = Buffer.alloc(msgBuf.byteLength + (33 * 2) + 1);
            macInput.set(ourIdentityKey.pubKey);
            macInput.set(session.indexInfo.remoteIdentityKey, 33);
            macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
            macInput.set(msgBuf, (33 * 2) + 1);
            const mac = crypto.calculateMAC(keys[1], macInput);
            const result = Buffer.alloc(msgBuf.byteLength + 9);
            result[0] = this._encodeTupleByte(VERSION, VERSION);
            result.set(msgBuf, 1);
            result.set(mac.slice(0, 8), msgBuf.byteLength + 1);
            await this.storeRecord(record);
            let type: number, body: Buffer;
            if (session.pendingPreKey) {
                type = EncryptionResultMessageType.PreKeyWhisperMessage;
                const preKeyMsg = new PreKeyWhisperMessage({
                    identityKey: ourIdentityKey.pubKey,
                    registrationId: await this.storage.getOurRegistrationId(),
                    baseKey: session.pendingPreKey.baseKey,
                    signedPreKeyId: session.pendingPreKey.signedKeyId,
                    message: result
                });
                if (session.pendingPreKey.preKeyId) {
                    preKeyMsg.preKeyId = session.pendingPreKey.preKeyId;
                }
                body = Buffer.concat([
                    Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                    Buffer.from(
                        preKeyMsg.serialize()
                    )
                ]);
            } else {
                type = EncryptionResultMessageType.WhisperMessage;
                body = result;
            }
            return {
                type,
                body,
                registrationId: session.registrationId
            };
    }
    

    async decryptWithSessions(data: Uint8Array, sessions: SessionEntry[]): Promise<{ session: SessionEntry, plaintext: Buffer }> {
        // Iterate through the sessions, attempting to decrypt using each one.
        // Stop and return the result if we get a valid result.
        if (!sessions.length) {
            throw new errors.SessionError("No sessions available");
        }   
        const errs = [];
        for (const session of sessions) {
            let plaintext: Buffer; 
            try {
                plaintext = await this.doDecryptWhisperMessage(Buffer.from(data), session);
                session.indexInfo.used = Date.now();
                return {
                    session,
                    plaintext
                };
            } catch(e) {
                errs.push(e);
            }
        }
        console.error("Failed to decrypt message with any known session...");
        for (const e of errs) {
            console.error("Session error:" + e, e.stack);
        }
        throw new errors.SessionError("No matching sessions found for message");
    }

    async decryptWhisperMessage(data: Uint8Array): Promise<Buffer> {
        const key = this.addr.toString();
        
        // LOG: Detailed message structure analysis
        console.log('\n=== DECRYPT WHISPER MESSAGE ===');
        console.log('Address:', key);
        console.log('Data length:', data.length);
        console.log('Data type:', data.constructor.name);
        console.log('First 10 bytes:', Array.from(data.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        console.log('Processing via mutex system (PreKey 0 issue resolved)');
        
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            
            return await this.runWithPriority(
                OperationPriority.HIGH, // CRITICAL FIX: Use HIGH priority for all message decryption
                async () => {
                    if (controller.signal.aborted) {
                        throw new Error('Operation cancelled');
                    }
                    
                    const startTime = Date.now();
                    const mutex = this.getMutex();
                    
                    // Optimized timeout for regular message decryption (30 seconds)
                    const MESSAGE_TIMEOUT = 30000; // 30 seconds - sync messages bypass this anyway
                    const result = await withTimeout(mutex, MESSAGE_TIMEOUT).runExclusive(async () => {
                        // Track acquisition metrics
                        const waitTime = Date.now() - startTime;
                        const stats = SessionCipher.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processdecryptWhisperMessage(data);
                    });
                    
                    return result;
                },
                'decryptWhisperMessage'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    private async processdecryptWhisperMessage(data: Uint8Array): Promise<Buffer> {
            const record = await this.getRecord();
            if (!record) {
                throw new errors.SessionError("No session record");
            }
            
            // LOG: WhisperMessage processing details
            console.log('\n=== WHISPER MESSAGE PROCESSING ===');
            console.log('Session record exists:', !!record);
            console.log('Available sessions:', record?.getSessions()?.length || 0);
            console.log('Has open session:', record?.haveOpenSession() || false);
            const result = await this.decryptWithSessions(data, record.getSessions());
            const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }   
            if (record.isClosed(result.session)) {
                // It's possible for this to happen when processing a backlog of messages.
                // The message was, hopefully, just sent back in a time when this session
                // was the most current.  Simply make a note of it and continue.  If our
                // actual open session is for reason invalid, that must be handled via
                // a full SessionError response.
                console.warn("Decrypted message with closed session.");
            }
            await this.storeRecord(record);
            return result.plaintext;
    }

    async decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Buffer> {
        const key = this.addr.toString();
        const versions = this._decodeTupleByte(data[0]);
        
        // LOG: Detailed PreKey message structure analysis
        console.log('\n=== DECRYPT PREKEY WHISPER MESSAGE ===');
        console.log('Address:', key);
        console.log('Data length:', data.length);
        console.log('Data type:', data.constructor.name);
        console.log('Versions:', versions, '(min/max)');
        console.log('First 20 bytes:', Array.from(data.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        console.log('Processing via mutex system (PreKey 0 issue resolved)');
        
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            
            return await this.runWithPriority(
                OperationPriority.HIGH, // CRITICAL FIX: Use HIGH priority for protocol messages
                async () => {
                    if (controller.signal.aborted) {
                        throw new Error('Operation cancelled');
                    }
                    
                    const startTime = Date.now();
                    const mutex = this.getMutex();
                    
                    // Optimized timeout for PreKey protocol messages (1 minute)  
                    const PROTOCOL_MESSAGE_TIMEOUT = 60000; // 1 minute - sync messages bypass this anyway
                    const result = await withTimeout(mutex, PROTOCOL_MESSAGE_TIMEOUT).runExclusive(async () => {
                        // Track acquisition metrics
                        const waitTime = Date.now() - startTime;
                        const stats = SessionCipher.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processdecryptPreKeyWhisperMessage(data);
                    });
                    
                    return result;
                },
                'decryptPreKeyWhisperMessage'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    private async processdecryptPreKeyWhisperMessage(data: Uint8Array): Promise<Buffer> {
        const versions = this._decodeTupleByte(data[0]);
        if (versions[1] > 3 || versions[0] < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }
            let record = await this.getRecord();
            const preKeyProto = PreKeyWhisperMessage.deserialize(data.slice(1));
            
            // LOG: PreKey protocol structure details
            console.log('\n=== PREKEY PROTO ANALYSIS ===');
            console.log('Registration ID:', preKeyProto.registrationId);
            console.log('PreKey ID:', preKeyProto.preKeyId);
            console.log('Signed PreKey ID:', preKeyProto.signedPreKeyId);
            console.log('Base Key length:', preKeyProto.baseKey?.length);
            console.log('Identity Key length:', preKeyProto.identityKey?.length);
            console.log('Message length:', preKeyProto.message?.length);
            console.log('Base Key (hex):', preKeyProto.baseKey ? Array.from(preKeyProto.baseKey.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(' ') + '...' : 'null');
            
            if (!record) {
                if (preKeyProto.registrationId == null) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }
            const builder = new SessionBuilder(this.storage, this.addr);
            const preKeyId = await builder.initIncoming(record, preKeyProto);
            const bufferedMessage = Buffer.from(preKeyProto.message);
            // CRITICAL FIX: Use baseKey for session selection (original Baileys logic)
            const session = record.getSession(Buffer.from(preKeyProto.baseKey));
            
            // LOG: Session building results
            console.log('\n=== SESSION BUILDING RESULTS ===');
            console.log('PreKey ID to remove:', preKeyId);
            console.log('Session found:', !!session);
            console.log('Session registration ID:', session?.registrationId);
            console.log('Session has pending prekey:', !!session?.pendingPreKey);
            const plaintext = await this.doDecryptWhisperMessage(bufferedMessage, session);
            await this.storeRecord(record);
            if (preKeyId) {
                await this.storage.removePreKey(preKeyId);
            }
            return plaintext;
    }

    async doDecryptWhisperMessage(messageBuffer: Buffer, session: SessionEntry): Promise<Buffer> {
        if (!session) {
            throw new TypeError("session required");
        }
        const versions = this._decodeTupleByte(messageBuffer[0]);
        if (versions[1] > 3 || versions[0] < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on WhisperMessage");
        }
        const messageProto = messageBuffer.slice(1, -8);
        const message = WhisperMessage.deserialize(messageProto);
        const bufferedEphemeralKey = Buffer.from(message.ephemeralKey);
        this.maybeStepRatchet(session, bufferedEphemeralKey, message.previousCounter);
        const chain = session.getChain(bufferedEphemeralKey);
        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }
        this.fillMessageKeys(chain, message.counter);
        if (!chain.messageKeys.hasOwnProperty(message.counter)) {
            // Most likely the message was already decrypted and we are trying to process
            // twice.  This can happen if the user restarts before the server gets an ACK.
            throw new errors.MessageCounterError('Key used already or never filled');
        }
        const messageKey = chain.messageKeys[message.counter];
        delete chain.messageKeys[message.counter];
        const keys = crypto.deriveSecrets(messageKey, Buffer.alloc(32),
                                          Buffer.from("WhisperMessageKeys"));
        const ourIdentityKey = await this.storage.getOurIdentity();
        const macInput = Buffer.alloc(messageProto.byteLength + (33 * 2) + 1);
        macInput.set(session.indexInfo.remoteIdentityKey);
        macInput.set(ourIdentityKey.pubKey, 33);
        macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
        macInput.set(messageProto, (33 * 2) + 1);
        // This is where we most likely fail if the session is not a match.
        // Don't misinterpret this as corruption.
        crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);
        const plaintext = crypto.decrypt(keys[0], Buffer.from(message.ciphertext), keys[2].slice(0, 16));
        delete session.pendingPreKey;
        return plaintext;
    }

    fillMessageKeys(chain: Chain<Buffer>, counter: number): void {
        if (chain.chainKey.counter >= counter) {
            return;
        }
        if (counter - chain.chainKey.counter > 2000) {
            throw new errors.SessionError('Over 2000 messages into the future!');
        }
        if (chain.chainKey.key === undefined) {
            throw new errors.SessionError('Chain closed');
        }
        const key = chain.chainKey.key;
        chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, Buffer.from([1]));
        chain.chainKey.key = crypto.calculateMAC(key, Buffer.from([2]));
        chain.chainKey.counter += 1;
        return this.fillMessageKeys(chain, counter);
    }

    maybeStepRatchet(session: SessionEntry, remoteKey: Buffer, previousCounter: number): void {
        if (session.getChain(remoteKey)) {
            return;
        }
        const ratchet = session.currentRatchet;
        let previousRatchet: Chain<Buffer> | undefined = session.getChain(ratchet.lastRemoteEphemeralKey);
        if (previousRatchet) {
            this.fillMessageKeys(previousRatchet, previousCounter);
            delete previousRatchet.chainKey.key;  // Close
        }
        this.calculateRatchet(session, remoteKey, false);
        // Now swap the ephemeral key and calculate the new sending chain
        const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey);
        if (prevCounter) {
            ratchet.previousCounter = prevCounter.chainKey.counter;
            session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
        }
        ratchet.ephemeralKeyPair = curve.generateKeyPair();
        this.calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    calculateRatchet(session: SessionEntry, remoteKey: Buffer, sending: boolean): void {
        let ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey,
                                               Buffer.from("WhisperRatchet"), /*chunks*/ 2);
        const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        session.addChain(chainKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
        });
        ratchet.rootKey = masterKey[0];
    }

    async hasOpenSession(): Promise<boolean> {
        const key = this.addr.toString();
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            return await this.runWithPriority(
                OperationPriority.LOW, // Low priority for cleanup operations
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
                        const stats = SessionCipher.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processhasOpenSession();
                    });
                    
                    return result;
                },
                'hasOpenSession'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    private async processhasOpenSession(): Promise<boolean> {
            const record = await this.getRecord();
            if (!record) {
                return false;
            }
            return record.haveOpenSession();
    }

    async closeOpenSession(): Promise<void> {
        const key = this.addr.toString();
        const controller = new AbortController();
        this.abortControllers.set(key, controller);
        
        try {
            await this.runWithPriority(
                OperationPriority.LOW, // Low priority for cleanup operations
                async () => {
                    if (controller.signal.aborted) {
                        throw new Error('Operation cancelled');
                    }
                    
                    const startTime = Date.now();
                    const mutex = this.getMutex();
                    
                    // Use withTimeout for mutex execution
                    await withTimeout(mutex, MUTEX_TIMEOUT).runExclusive(async () => {
                        // Track acquisition metrics
                        const waitTime = Date.now() - startTime;
                        const stats = SessionCipher.mutexStats.get(key);
                        if (stats) {
                            stats.acquisitions++;
                            stats.totalWaitTime += waitTime;
                        }
                        
                        return await this.processcloseOpenSession();
                    });
                },
                'closeOpenSession'
            );
        } finally {
            this.abortControllers.delete(key);
        }
    }

    private async processcloseOpenSession(): Promise<void> {
            const record = await this.getRecord();
            if (record) {
                const openSession = record.getOpenSession();
                if (openSession) {
                    record.closeSession(openSession);
                    await this.storeRecord(record);
                }
            }
    }
}
