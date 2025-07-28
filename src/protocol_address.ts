import type { WhatsAppProtocolAddressType } from './types';

export class ProtocolAddress {
    public id: string;
    public deviceId: number;

    static from(encodedAddress: string): WhatsAppProtocolAddressType {
        if (!encodedAddress.match(/.*\.\d+/)) {
            throw new Error('Invalid address encoding');
        }
        const parts = encodedAddress.split('.');
        return new this(parts[0], parseInt(parts[1]));
    }

    constructor(id: string, deviceId: number) {
        if (id.indexOf('.') !== -1) {
            throw new TypeError('encoded addr detected');
        }
        this.id = id;
        this.deviceId = deviceId;
    }

    toString(): string {
        return `${this.id}.${this.deviceId}`;
    }

    is(other: ProtocolAddress): boolean {
        return other.id === this.id && other.deviceId === this.deviceId;
    }
}
