import { Mutex } from 'async-mutex';
import { ProtocolAddressType } from '../types';

interface LockOptions {
  timeout?: number;
  priority?: number;
}

interface LockStats {
  totalLocks: number;
  activeLocks: number;
  averageWaitTime: number;
  errors: Error[];
}

export class SessionLockManager {
  private locks = new Map<string, Mutex>();

  private stats: LockStats = {
    totalLocks: 0,
    activeLocks: 0,
    averageWaitTime: 0,
    errors: [],
  };

  private waitTimes: number[] = [];

  // Default timeout: 30 seconds
  private readonly DEFAULT_TIMEOUT = 30000;

  /**
   * Run operation exclusively for a given session/device
   */
  async runExclusive<T>(
    identifier: string | ProtocolAddressType,
    operation: () => Promise<T> | T,
    options: LockOptions = {}
  ): Promise<T> {
    const lockKey =
      typeof identifier === 'string' ? identifier : identifier.toString();
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    const mutex = this.getOrCreateMutex(lockKey);
    const startTime = Date.now();

    this.stats.activeLocks++;
    this.stats.totalLocks++;

    try {
      const release = await this.acquireWithTimeout(mutex, timeout);

      try {
        const waitTime = Date.now() - startTime;
        this.recordWaitTime(waitTime);

        const result = await operation();
        return result;
      } finally {
        release();
        this.stats.activeLocks--;
      }
    } catch (error) {
      this.stats.activeLocks--;
      this.stats.errors.push(error as Error);
      throw error;
    }
  }

  /**
   * Get or create mutex for a given key
   */
  private getOrCreateMutex(key: string): Mutex {
    if (!this.locks.has(key)) {
      this.locks.set(key, new Mutex());
    }
    return this.locks.get(key)!;
  }

  /**
   * Acquire mutex with timeout
   */
  private async acquireWithTimeout(mutex: Mutex, timeout: number): Promise<() => void> {
    return new Promise<() => void>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Lock acquisition timeout after ${timeout}ms`));
      }, timeout);

      mutex.acquire().then(release => {
        clearTimeout(timeoutId);
        resolve(release);
      }).catch(error => {
        clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  /**
   * Record wait time for statistics
   */
  private recordWaitTime(waitTime: number): void {
    this.waitTimes.push(waitTime);

    // Keep only last 1000 measurements for rolling average
    if (this.waitTimes.length > 1000) {
      this.waitTimes.shift();
    }

    const total = this.waitTimes.reduce((a, b) => a + b, 0);
    this.stats.averageWaitTime = total / this.waitTimes.length;
  }

  /**
   * Check if a session is currently locked
   */
  isLocked(identifier: string | ProtocolAddressType): boolean {
    const lockKey =
      typeof identifier === 'string' ? identifier : identifier.toString();
    const mutex = this.locks.get(lockKey);
    return mutex ? mutex.isLocked() : false;
  }

  /**
   * Get lock statistics
   */
  getStats(): LockStats {
    return { ...this.stats };
  }

  /**
   * Clear all locks (for testing/cleanup)
   */
  async clearAllLocks(): Promise<void> {
    const promises = Array.from(this.locks.values()).map(mutex =>
      mutex.waitForUnlock()
    );
    await Promise.all(promises);
    this.locks.clear();
  }

  /**
   * Clean up old/unused locks
   */
  cleanup(): void {
    for (const [key, mutex] of this.locks.entries()) {
      if (!mutex.isLocked()) {
        this.locks.delete(key);
      }
    }
  }

  /**
   * Wait for all pending operations to complete
   */
  async waitForAll(): Promise<void> {
    const promises = Array.from(this.locks.values()).map(mutex =>
      mutex.waitForUnlock()
    );
    await Promise.all(promises);
  }
}

// Singleton instance for global use
export const sessionLock = new SessionLockManager();