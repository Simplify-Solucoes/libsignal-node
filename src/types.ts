// Core libsignal types for TypeScript migration
// Based on wppconnect implementation with baileys compatibility
import { textsecure } from './WhisperTextProtocol';
import type { SessionRecord } from './session_record';
export type WhisperMessageType = textsecure.WhisperMessage;
export type PreKeyWhisperMessageType = textsecure.PreKeyWhisperMessage;

export type E2ESession = {
	registrationId: number
	identityKey: Uint8Array
	signedPreKey: SignedPreKeyType
	preKey: PreKeyType
}

export enum ChainType {
    SENDING = 1,
    RECEIVING = 2
}

export interface Chain<T = Buffer> {
    chainType: ChainType
    chainKey: { key?: T; counter: number }
    messageKeys: { [key: number]: T }
}

export enum BaseKey {
  OURS = 1,
  THEIRS = 2
}

export enum EncryptionResultMessageType {
    WhisperMessage = 1,
    PreKeyWhisperMessage = 3,
}

export interface EncryptionResult {
    type: EncryptionResultMessageType
    body: Buffer
    registrationId: number
}

export interface KeyPairType {
  pubKey: Buffer;
  privKey: Buffer;
}

export interface PreKeyType {
  keyId: number;
  keyPair: KeyPairType;
}

export interface SignedPreKeyType {
  keyId: number;
  keyPair: KeyPairType;
  signature: Uint8Array;
}

export interface StorageType {
  loadSession(address: string): Promise<SessionRecord | null>;
  storeSession(address: string, record: any): Promise<void>;
  getOurIdentity(): Promise<KeyPairType>;
  isTrustedIdentity(address: string, identityKey: Buffer): Promise<boolean>;
  getOurRegistrationId(): Promise<number>;
  removePreKey(keyId: number): Promise<void>;
  loadPreKey(keyId: number): Promise<PreKeyType>;
  // Missing signed prekey methods:
  loadSignedPreKey(keyId: number): Promise<KeyPairType>;
  storeSignedPreKey(keyId: number, keyPair: KeyPairType): Promise<void>;
  removeSignedPreKey(keyId: number): Promise<void>;
}

export interface IndexInfoType {
    baseKey: Buffer;
    baseKeyType: BaseKey;
    closed: number;
    used: number;
    created: number;
    remoteIdentityKey: Buffer;
};

// Runtime ratchet state used in Baileys (simpler)
export interface CurrentRatchetType {
    rootKey: Buffer;
    ephemeralKeyPair: KeyPairType;
    lastRemoteEphemeralKey: Buffer;
    previousCounter: number;
}

// Full ratchet type with extended fields (if needed elsewhere)
export interface ExtendedRatchetType extends CurrentRatchetType {
    baseKey: Buffer;
    baseKeyType: BaseKey;
    remoteIdentityKey: Buffer;
    index: number;
    chain: Chain;
    nextChain: Chain;
}

export interface PendingPreKeyType {
    baseKey: Buffer;
    preKeyId?: number;
    signedKeyId: number;
}
// Serialized data structure types for deserialization
export interface SerializedSessionData {
    registrationId: number;
    currentRatchet: {
        ephemeralKeyPair: {
            pubKey: string; // base64 encoded
            privKey: string; // base64 encoded
        };
        lastRemoteEphemeralKey: string; // base64 encoded
        previousCounter: number;
        rootKey: string; // base64 encoded
    };
    indexInfo: {
        baseKey: string; // base64 encoded
        baseKeyType: BaseKey;
        closed: number;
        used: number;
        created: number;
        remoteIdentityKey: string; // base64 encoded
    };
    _chains: Record<string, {
        chainKey: {
            counter: number;
            key?: string; // base64 encoded, optional like in libsignal-protocol-master
        };
        chainType: ChainType;
        messageKeys: Record<number, string>; // counter -> base64 encoded message key
    }>;
    pendingPreKey?: {
        baseKey: string; // base64 encoded
        preKeyId?: number;
        signedKeyId: number;
    };
}

// Serialized SessionRecord data structure
export interface SerializedSessionRecordData {
    version: string;
    _sessions: Record<string, SerializedSessionData>;
}

export interface WhatsAppProtocolAddressType {
    readonly id: string
    readonly deviceId: number
    toString: () => string
}

export type { KeyPairType as KeyPair };
export type { PreKeyType as PreKey };
export type { SignedPreKeyType as SignedPreKey };
export type { StorageType as Storage };
export type { CurrentRatchetType as currentRatchetType }; // Backward compatibility alias