import { crypto } from './crypto';

var VERSION = 0;

export class FingerprintGenerator {

    private iterations: number;

    setIterations(iterations: number): void {
        this.iterations = iterations;
    }

    async createFor(
        localIdentifier: string, 
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string, 
        remoteIdentityKey: ArrayBuffer
    ): Promise<string> {
        return Promise.all([
            this.getDisplayStringFor(localIdentifier, Buffer.from(localIdentityKey), this.iterations),
            this.getDisplayStringFor(remoteIdentifier, Buffer.from(remoteIdentityKey), this.iterations)
        ]).then(function(fingerprints) {
            return fingerprints.sort().join('');
        });
    }

    private async iterateHash(data: Buffer, key: Buffer, count: number): Promise<Buffer> {
        const combined = (new Uint8Array(Buffer.concat([data, key]))).buffer;
        const result = crypto.hash(combined);
        if (--count === 0) {
            return result;
        } else {
            return this.iterateHash(result, key, count);
        }
    }

    private shortToArrayBuffer(number: number): Buffer {
        return Buffer.from(new Uint16Array([number]).buffer);
    }

    private getEncodedChunk(hash: Uint8Array, offset: number): string {
        var chunk = ( hash[offset]   * Math.pow(2,32) +
                    hash[offset+1] * Math.pow(2,24) +
                    hash[offset+2] * Math.pow(2,16) +
                    hash[offset+3] * Math.pow(2,8) +
                    hash[offset+4] ) % 100000;
        var s = chunk.toString();
        while (s.length < 5) {
            s = '0' + s;
        }
        return s;
    }

    private async getDisplayStringFor(identifier: string, key: Buffer, iterations: number): Promise<string> {
        const bytes = Buffer.concat([
            this.shortToArrayBuffer(VERSION),
            key,
            Buffer.from(identifier, 'utf8')
        ]);
        const arraybuf = (new Uint8Array(bytes)).buffer;
        const output = new Uint8Array(await this.iterateHash(Buffer.from(arraybuf), key, iterations));
        return this.getEncodedChunk(output, 0) +
            this.getEncodedChunk(output, 5) +
            this.getEncodedChunk(output, 10) +
            this.getEncodedChunk(output, 15) +
            this.getEncodedChunk(output, 20) +
            this.getEncodedChunk(output, 25);
    }
}

// Default instance for convenience
export const fingerprintGenerator = new FingerprintGenerator();
