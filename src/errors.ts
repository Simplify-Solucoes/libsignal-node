// TypeScript migration of errors.js - Signal Protocol Error Classes
// Provides typed error classes for better error handling and debugging

/**
 * Base class for all Signal protocol errors
 */
export class SignalError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'SignalError';
    }
}

/**
 * Error thrown when an identity key is not trusted
 */
export class UntrustedIdentityKeyError extends SignalError {
    public readonly addr: string;
    public readonly identityKey: Uint8Array;

    constructor(addr: string, identityKey: Uint8Array) {
        super(`Untrusted identity key for ${addr}`);
        this.name = 'UntrustedIdentityKeyError';
        this.addr = addr;
        this.identityKey = identityKey;
    }
}

/**
 * Base class for session-related errors
 */
export class SessionError extends SignalError {
    constructor(message: string) {
        super(message);
        this.name = 'SessionError';
    }
}

/**
 * Error thrown when message counter is out of sequence
 */
export class MessageCounterError extends SessionError {
    constructor(message: string) {
        super(message);
        this.name = 'MessageCounterError';
    }
}

/**
 * Error thrown when pre-key operations fail
 */
export class PreKeyError extends SessionError {
    constructor(message: string) {
        super(message);
        this.name = 'PreKeyError';
    }
}

// Export errors object for backward compatibility with existing code
export const errors = {
    SignalError,
    UntrustedIdentityKeyError,
    SessionError,
    MessageCounterError,
    PreKeyError
};
