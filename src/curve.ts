import * as curveJs from '@wppconnect/curve25519';
import * as nodeCrypto from 'crypto';
import type { KeyPair } from './types';

export class Curve {
    // DER prefix constants for X25519 keys
    // from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
    private static readonly PUBLIC_KEY_DER_PREFIX = Buffer.from([
        48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
    ]);
    
    private static readonly PRIVATE_KEY_DER_PREFIX = Buffer.from([
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
    ]);

    private static readonly KEY_BUNDLE_TYPE = Buffer.from([5]);

    /**
     * Adds the 0x05 prefix to a public key for compatibility
     */
    private prefixKeyInPublicKey(pubKey: Buffer): Buffer {
        return Buffer.concat([Curve.KEY_BUNDLE_TYPE, pubKey]);
    }

    /**
     * Validates a private key format and length
     */
    private validatePrivKey(privKey: Buffer): void {
        if (privKey.byteLength !== 32) {
            throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
        }
    }

    /**
     * Normalizes public key format (removes 0x05 prefix if present)
     */
    private scrubPubKeyFormat(pubKey: Uint8Array): Uint8Array {
        if ((pubKey.byteLength !== 33 || pubKey[0] !== 5) && pubKey.byteLength !== 32) {
            throw new Error("Invalid public key");
        }
        if (pubKey.byteLength === 33) {
            return pubKey.subarray(1);
        } else {
            console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
            return pubKey;
        }
    }

    /**
     * Converts clamped Ed25519 private key to unclamped format
     */
    private unclampEd25519PrivateKey(clampedSk: Buffer): Uint8Array {
        const unclampedSk = new Uint8Array(clampedSk);

        // Fix the first byte
        unclampedSk[0]! |= 6; // Ensure last 3 bits match expected `110` pattern

        // Fix the last byte
        unclampedSk[31]! |= 128; // Restore the highest bit
        unclampedSk[31]! &= ~64; // Clear the second-highest bit

        return unclampedSk;
    }

    /**
     * Derives public key from private key
     */
    getPublicFromPrivateKey(privKey: Buffer): Buffer {
        const unclampedPK = this.unclampEd25519PrivateKey(privKey);
        const keyPair = curveJs.generateKeyPair(unclampedPK);
        return this.prefixKeyInPublicKey(Buffer.from(keyPair.pubKey));
    }

    /**
     * Generates a new X25519 key pair
     */
    generateKeyPair(): KeyPair {
        try {
            const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync(
                'x25519',
                {
                    publicKeyEncoding: { format: 'der', type: 'spki' },
                    privateKeyEncoding: { format: 'der', type: 'pkcs8' }
                }
            );
            const pubKey = publicDerBytes.subarray(
                Curve.PUBLIC_KEY_DER_PREFIX.length, 
                Curve.PUBLIC_KEY_DER_PREFIX.length + 32
            );
            const privKey = privateDerBytes.subarray(
                Curve.PRIVATE_KEY_DER_PREFIX.length, 
                Curve.PRIVATE_KEY_DER_PREFIX.length + 32
            );

            return {
                pubKey: this.prefixKeyInPublicKey(pubKey),
                privKey
            };
        } catch (e) {
            const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
            return {
                privKey: Buffer.from(keyPair.privKey),
                pubKey: this.prefixKeyInPublicKey(Buffer.from(keyPair.pubKey)),
            };
        }
    }

    /**
     * Performs X25519 Diffie-Hellman key agreement
     * ECDH using Curve25519
     */
    calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer {
        const normalizedPubKey = this.scrubPubKeyFormat(pubKey);
        this.validatePrivKey(privKey);
        
        if (normalizedPubKey.byteLength !== 32) {
            throw new Error("Invalid public key");
        }

        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([Curve.PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([Curve.PUBLIC_KEY_DER_PREFIX, normalizedPubKey]),
            format: 'der',
            type: 'spki'
        });

        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    }

    /**
     * Creates digital signature using Ed25519
     */
    calculateSignature(privKey: Uint8Array, message: Uint8Array): Uint8Array {
        this.validatePrivKey(Buffer.from(privKey));
        return Buffer.from(curveJs.sign(privKey, message));
    }

    /**
     * Verifies digital signature using Ed25519
     */
    verifySignature(pubKey: Uint8Array, msg: Uint8Array, sig: Uint8Array, isInit: boolean = false): boolean {
        const normalizedPubKey = this.scrubPubKeyFormat(pubKey);
        
        if (normalizedPubKey.byteLength !== 32) {
            throw new Error("Invalid public key");
        }
        if (sig.byteLength !== 64) {
            throw new Error("Invalid signature");
        }
        
        return isInit ? true : curveJs.verify(normalizedPubKey, msg, sig);
    }
}

// Default instance for convenience
export const curve = new Curve();

// Standalone function exports
export const generateKeyPair = () => 
    curve.generateKeyPair();

export const calculateSignature = (privKey: Buffer, message: Buffer) => 
    curve.calculateSignature(privKey, message);

export const verifySignature = (pubKey: Buffer, msg: Buffer, sig: Buffer, isInit: boolean = false) => 
    curve.verifySignature(pubKey, msg, sig, isInit);
