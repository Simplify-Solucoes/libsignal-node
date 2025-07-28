// Mutex configuration
export const MUTEX_TIMEOUT = 30000; // 30 seconds timeout
export const MUTEX_CLEANUP_INTERVAL = 300000; // 5 minutes cleanup interval
export const MAX_RETRIES = 5;
export const RETRY_DELAY = 1000;

export enum OperationPriority {
    HIGH = 0,    // Incoming messages (critical for real-time chat)
    NORMAL = 1,  // Outgoing messages  
    LOW = 2      // Cleanup operations
}