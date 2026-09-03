// Intelligence In-Memory Cache with In-Flight Promise Deduplication

export interface CacheOptions {
  ttlMs: number;
  maxEntries?: number;
}

interface CacheItem<T> {
  value: T;
  expiresAt: number;
}

export class IntelligenceCache<T> {
  private readonly store = new Map<string, CacheItem<T>>();
  private readonly inFlight = new Map<string, Promise<T>>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(options: CacheOptions) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries || 5000;
  }

  public get(key: string): T | undefined {
    const item = this.store.get(key);
    if (!item) return undefined;
    if (Date.now() > item.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return item.value;
  }

  public set(key: string, value: T, customTtlMs?: number): void {
    if (this.store.size >= this.maxEntries) {
      // Evict oldest 10%
      const keysToDelete = Array.from(this.store.keys()).slice(0, Math.floor(this.maxEntries * 0.1));
      for (const k of keysToDelete) {
        this.store.delete(k);
      }
    }
    this.store.set(key, {
      value,
      expiresAt: Date.now() + (customTtlMs || this.ttlMs)
    });
  }

  public has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  public delete(key: string): boolean {
    return this.store.delete(key);
  }

  public clear(): void {
    this.store.clear();
    this.inFlight.clear();
  }

  public size(): number {
    return this.store.size;
  }

  // Deduplicate concurrent requests for the exact same key
  public async getOrFetch(key: string, fetcher: () => Promise<T>, customTtlMs?: number): Promise<{ value: T; cached: boolean }> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return { value: cached, cached: true };
    }

    const running = this.inFlight.get(key);
    if (running) {
      const value = await running;
      return { value, cached: true };
    }

    const promise = (async () => {
      try {
        const result = await fetcher();
        this.set(key, result, customTtlMs);
        return result;
      } finally {
        this.inFlight.delete(key);
      }
    })();

    this.inFlight.set(key, promise);
    const value = await promise;
    return { value, cached: false };
  }
}

// Global Intelligence Caches with production RFC-compliant TTLs
export const geoIpCache = new IntelligenceCache<any>({ ttlMs: 24 * 60 * 60 * 1000, maxEntries: 10000 }); // 24h
export const asnCache = new IntelligenceCache<any>({ ttlMs: 24 * 60 * 60 * 1000, maxEntries: 10000 }); // 24h
export const dnsCache = new IntelligenceCache<any>({ ttlMs: 60 * 60 * 1000, maxEntries: 5000 }); // 1h
export const rdapCache = new IntelligenceCache<any>({ ttlMs: 24 * 60 * 60 * 1000, maxEntries: 5000 }); // 24h
export const threatIntelCache = new IntelligenceCache<any>({ ttlMs: 12 * 60 * 60 * 1000, maxEntries: 5000 }); // 12h
