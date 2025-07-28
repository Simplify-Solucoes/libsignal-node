// vim: ts=4:sw=4
import * as nodeCrypto from 'crypto';

export class Crypto {
    deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks: number = 3): Buffer[] {
        // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
        if (salt.byteLength !== 32) {
            throw new Error("Got salt of incorrect length");
        }
        if (chunks < 1 || chunks > 3) {
            throw new Error("Chunks must be between 1 and 3");
        }
        
        const PRK = this.calculateMAC(salt, input);
        const infoArray = new Uint8Array(info.byteLength + 1 + 32);
        infoArray.set(info, 32);
        infoArray[infoArray.length - 1] = 1;
        const signed = [this.calculateMAC(PRK, Buffer.from(infoArray.subarray(32)))];
        
        if (chunks > 1) {
            infoArray.set(signed[signed.length - 1]!);
            infoArray[infoArray.length - 1] = 2;
            signed.push(this.calculateMAC(PRK, Buffer.from(infoArray)));
        }
        if (chunks > 2) {
            infoArray.set(signed[signed.length - 1]!);
            infoArray[infoArray.length - 1] = 3;
            signed.push(this.calculateMAC(PRK, Buffer.from(infoArray)));
        }
        return signed;
    }

    calculateMAC(key: Buffer, data: Buffer): Buffer {
        const hmac = nodeCrypto.createHmac('sha256', key);
        hmac.update(data);
        return Buffer.from(hmac.digest());
    }

    encrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
        const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    decrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
        const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    hash(data: ArrayBuffer): Buffer {
        const sha512 = nodeCrypto.createHash('sha512');
        sha512.update(Buffer.from(data));
        return sha512.digest();
    }

    verifyMAC(data: Buffer, key: Buffer, mac: Buffer, length: number): void {
        const calculatedMac = this.calculateMAC(key, data).subarray(0, length);
        if (mac.length !== length || calculatedMac.length !== length) {
            throw new Error("Bad MAC length");
        }
        if (!mac.equals(calculatedMac)) {
            throw new Error("Bad MAC");
        }
    }
}

// Default instance for convenience
export const crypto = new Crypto();

// Standalone function exports
export const deriveSecrets = (input: Buffer, salt: Buffer, info: Buffer, chunks: number = 3) => 
    crypto.deriveSecrets(input, salt, info, chunks);

export const decrypt = (key: Buffer, data: Buffer, iv: Buffer) => 
    crypto.decrypt(key, data, iv);

export const encrypt = (key: Buffer, data: Buffer, iv: Buffer) => 
    crypto.encrypt(key, data, iv);

export const calculateMAC = (key: Buffer, data: Buffer) => 
    crypto.calculateMAC(key, data);