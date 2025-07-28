// Main entry point for libsignal-node TypeScript implementation
// Exports all public APIs for Baileys compatibility

export { SessionBuilder } from './session_builder';
export { SessionCipher } from './session_cipher';
export { SessionRecord } from './session_record';
export { ProtocolAddress } from './protocol_address';
export { KeyHelper } from './keyhelper';
export { curve } from './curve';
export { crypto } from './crypto';
export { errors } from './errors';
export { FingerprintGenerator } from './numeric_fingerprint';
export {
    deriveSecrets,
    decrypt,
    encrypt,
    calculateMAC
 } from './crypto';

export {
    generateKeyPair,
    calculateSignature,
    verifySignature
} from './curve';

// Export types
export type {
    WhatsAppProtocolAddressType,
    StorageType,
    E2ESession,
    KeyPairType,
    PreKeyType,
    SignedPreKeyType,
    EncryptionResult,
    EncryptionResultMessageType
} from './types';

// Export protobuf types
export { WhisperMessage, PreKeyWhisperMessage } from './protobufs';
export type { WhisperMessageType, PreKeyWhisperMessageType } from './types';