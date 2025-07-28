// Jest setup file for libsignal-node tests

// Set up global test environment
global.console = {
  ...console,
  // Suppress console.log during tests unless explicitly needed
  log: process.env.NODE_ENV === 'test' ? jest.fn() : console.log,
  debug: process.env.NODE_ENV === 'test' ? jest.fn() : console.debug,
  info: process.env.NODE_ENV === 'test' ? jest.fn() : console.info,
  warn: console.warn,
  error: console.error,
};

// Global test utilities
global.crypto = require('crypto');

// Helper function to create test key pairs
global.createTestKeyPair = () => {
  const privKey = crypto.randomBytes(32);
  return {
    privKey: new Uint8Array(privKey),
    pubKey: new Uint8Array(crypto.randomBytes(33)) // Mock public key
  };
};

// Helper function to create test protocol address
global.createTestAddress = (name = 'test-user', deviceId = 1) => {
  return {
    getName: () => name,
    getDeviceId: () => deviceId,
    toString: () => `${name}.${deviceId}`,
    equals: (other) => other.getName() === name && other.getDeviceId() === deviceId
  };
};

// Mock crypto random bytes for consistent testing
const originalRandomBytes = crypto.randomBytes;
global.mockRandomBytes = (mockData) => {
  crypto.randomBytes = jest.fn().mockReturnValue(mockData);
};

global.restoreRandomBytes = () => {
  crypto.randomBytes = originalRandomBytes;
};

// Test timeout for async operations
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
  // Restore any mocked functions
  if (crypto.randomBytes !== originalRandomBytes) {
    crypto.randomBytes = originalRandomBytes;
  }
});