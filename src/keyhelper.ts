import { curve } from './curve';
import nodeCrypto from 'crypto';
import type { KeyPair, PreKey, SignedPreKey } from './types';

export class KeyHelper {
    private isNonNegativeInteger(n: number): boolean {
        return (typeof n === 'number' && (n % 1) === 0  && n >= 0);
    }
    generateIdentityKeyPair(): KeyPair {
        return curve.generateKeyPair();
    }
    generateRegistrationId(): number {
        const registrationId = Uint16Array.from(nodeCrypto.randomBytes(2))[0];
        return registrationId & 0x3fff;
    }
    generatePreKey(keyId: number): PreKey {
        if (!this.isNonNegativeInteger(keyId)) {
            throw new TypeError('Invalid argument for keyId: ' + keyId);
        }
        const keyPair = curve.generateKeyPair();
        return {
            keyId,
            keyPair
        };
    };
    generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey {
        if (!(identityKeyPair.privKey instanceof Buffer) ||
            identityKeyPair.privKey.byteLength != 32 ||
            !(identityKeyPair.pubKey instanceof Buffer) ||
            identityKeyPair.pubKey.byteLength != 33) {
            throw new TypeError('Invalid argument for identityKeyPair');
        }
        if (!this.isNonNegativeInteger(signedKeyId)) {
            throw new TypeError('Invalid argument for signedKeyId: ' + signedKeyId);
        }
        const keyPair = curve.generateKeyPair();
        const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);
        return {
            keyId: signedKeyId,
            keyPair: keyPair,
            signature: sig
        };
    };
}

export const keyHelper = new KeyHelper();
