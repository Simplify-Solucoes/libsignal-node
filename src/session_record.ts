// TypeScript migration of session_record.js
// TODO: Add proper type annotations
// TODO: Replace require() with import statements
// TODO: Add TypeScript interfaces and types
// TODO: Update exports to use ES6 syntax

// vim: ts=4:sw=4
import { BaseKey } from './types';
import type { IndexInfoType, CurrentRatchetType, PreKeyType, ChainType, SerializedSessionData, PendingPreKeyType, Chain, SerializedSessionRecordData } from './types';

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';


export class SessionEntry {
    indexInfo!: IndexInfoType;
    currentRatchet!: CurrentRatchetType;
    pendingPreKey: PendingPreKeyType | null = null;
    registrationId!: number;
    _chains: Record<string, Chain<Buffer>> = {};

    constructor() {
        // Properties initialized via definite assignment assertions
    }

    toString() {
        const baseKey = this.indexInfo && this.indexInfo.baseKey &&
            this.indexInfo.baseKey.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
    }

    inspect() {
        return this.toString();
    }

    addChain(key: Buffer, value: Chain<Buffer>) {
        const id = key.toString('base64');
        if (this._chains.hasOwnProperty(id)) {
            throw new Error("Overwrite attempt");
        }
        this._chains[id] = value;
    }

    getChain(key: Buffer): Chain<Buffer> | undefined {
        return this._chains[key.toString('base64')];
    }

    deleteChain(key: Buffer) {
        const id = key.toString('base64');
        if (!this._chains.hasOwnProperty(id)) {
            throw new ReferenceError("Not Found");
        }
        delete this._chains[id];
    }

    *chains() {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    serialize(): SerializedSessionData {
        const data = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: this.currentRatchet.previousCounter,
                rootKey: this.currentRatchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: this.indexInfo.baseKey.toString('base64'),
                baseKeyType: this.indexInfo.baseKeyType,
                closed: this.indexInfo.closed,
                used: this.indexInfo.used,
                created: this.indexInfo.created,
                remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
            },
            pendingPreKey: this.pendingPreKey ? {
                baseKey: this.pendingPreKey.baseKey.toString('base64'),
                ...(this.pendingPreKey.preKeyId !== undefined && { preKeyId: this.pendingPreKey.preKeyId }),
                signedKeyId: this.pendingPreKey.signedKeyId
            } : undefined,
            _chains: this._serialize_chains(this._chains)
        };
        return data;
    }

    static deserialize(data: SerializedSessionData): SessionEntry {
        const obj = new this();
        obj.registrationId = data.registrationId;
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
                privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
            },
            lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
            previousCounter: data.currentRatchet.previousCounter,
            rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
        } as CurrentRatchetType;
        obj.indexInfo = {
            baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
            baseKeyType: data.indexInfo.baseKeyType,
            closed: data.indexInfo.closed,
            used: data.indexInfo.used,
            created: data.indexInfo.created,
            remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
        };
        obj._chains = this._deserialize_chains(data._chains);
        if (data.pendingPreKey) {
            obj.pendingPreKey = {
                baseKey: Buffer.from(data.pendingPreKey.baseKey, 'base64'),
                ...(data.pendingPreKey.preKeyId !== undefined && { preKeyId: data.pendingPreKey.preKeyId }),
                signedKeyId: data.pendingPreKey.signedKeyId
            };
        }
        return obj;
    }

    _serialize_chains(chains: Record<string, Chain<Buffer>>): Record<string, any> {
        const r: Record<string, any> = {};
        for (const key of Object.keys(chains)) {
            const c = chains[key]!;
            const messageKeys: Record<string, string> = {};
            for (const [idx, key] of Object.entries(c.messageKeys)) {
                messageKeys[idx] = key.toString('base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    ...(c.chainKey.key && { key: c.chainKey.key.toString('base64') })
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

    static _deserialize_chains(chains_data: Record<string, {
            chainKey: {
                counter: number;
                key?: string; // base64 encoded, optional like in libsignal-protocol-master
            };
            chainType: ChainType;
            messageKeys: Record<number, string>; // counter -> base64 encoded message key
        }>): Record<string, Chain<Buffer>> {
        const r: Record<string, Chain<Buffer>> = {};
        for (const key of Object.keys(chains_data)) {
            const c = chains_data[key]!;
            const messageKeys: Record<number, Buffer> = {};
            for (const [idx, key] of Object.entries(c.messageKeys)) {
                messageKeys[parseInt(idx)] = Buffer.from(key, 'base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    ...(c.chainKey.key && { key: Buffer.from(c.chainKey.key, 'base64') })
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

}


const migrations = [{
    version: 'v1',
    migrate: function migrateV1(data: any) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const key in sessions) {
                if (!sessions[key].registrationId) {
                    sessions[key].registrationId = data.registrationId;
                }
            }
        } else {
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed === -1) {
                    console.error('V1 session storage migration error: registrationId',
                                  data.registrationId, 'for open session version',
                                  data.version);
                }
            }
        }
    }
}];


export class SessionRecord {
    sessions: Record<string, SessionEntry>;
    version: string;

    static createEntry() {
        return new SessionEntry();
    }

    static migrate(data: any) {
        let run = (data.version === undefined);
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                console.info("Migrating session to:", migrations[i]!.version);
                migrations[i]!.migrate(data);
            } else if (migrations[i]!.version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error("Error migrating SessionRecord");
        }
    }

    static deserialize(data: any): SessionRecord {
        // Keep original Baileys migration logic
        if (data.version !== SESSION_RECORD_VERSION) {
            this.migrate(data);
        }
        
        const obj = new this();
        
        // Keep original Baileys logic: only process if _sessions exists
        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                // Type assertion for the entry since it comes from storage
                obj.sessions[key] = SessionEntry.deserialize(entry as SerializedSessionData);
            }
        }
        
        return obj;
    }

    constructor() {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
    }

    serialize(): SerializedSessionRecordData {
        const _sessions: Record<string, any> = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            _sessions[key] = entry.serialize();
        }
        return {
            _sessions,
            version: this.version
        };
    }

    haveOpenSession(): boolean {
        const openSession = this.getOpenSession();
        return (!!openSession);
    }

    getSession(key: Buffer): SessionEntry | undefined {
        const session = this.sessions[key.toString('base64')];
        if (session && session.indexInfo.baseKeyType === BaseKey.OURS) {
            throw new Error("Tried to lookup a session using our basekey");
        }
        return session;
    }

    getOpenSession(): SessionEntry | undefined {
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                return session;
            }
        }
        return undefined;
    }

    setSession(session: SessionEntry) {
        this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
    }

    getSessions(): SessionEntry[] {
        // Return sessions ordered with most recently used first.
        return Array.from(Object.values(this.sessions)).sort((a, b) => {
            const aUsed = a.indexInfo.used || 0;
            const bUsed = b.indexInfo.used || 0;
            return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
        });
    }

    closeSession(session: SessionEntry): void {
        if (this.isClosed(session)) {
            console.warn("Session already closed", session);
            return;
        }
        console.info("Closing session:", session);
        session.indexInfo.closed = Date.now();
    }

    openSession(session: SessionEntry) {
        if (!this.isClosed(session)) {
            console.warn("Session already open");
        }
        console.info("Opening session:", session);
        session.indexInfo.closed = -1;
    }

    isClosed(session: SessionEntry): boolean {
        return session.indexInfo.closed !== -1;
    }

    removeOldSessions(): void {
        while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
            let oldestKey: string | undefined;
            let oldestSession: SessionEntry | undefined;
            for (const [key, session] of Object.entries(this.sessions)) {
                if (session.indexInfo.closed !== -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
                    oldestKey = key;
                    oldestSession = session;
                }
            }
            if (oldestKey) {
                console.info("Removing old closed session:", oldestSession);
                delete this.sessions[oldestKey];
            } else {
                throw new Error('Corrupt sessions object');
            }
        }
    }

    deleteAllSessions(): void {
        for (const key of Object.keys(this.sessions)) {
            delete this.sessions[key];
        }
    }
}