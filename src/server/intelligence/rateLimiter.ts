// Provider Quota and Rate Limiter

interface DailyQuota {
  dayUtc: string;
  count: number;
  limit: number;
}

export class ProviderRateLimiter {
  private dailyQuotas = new Map<string, DailyQuota>();
  private requestTimestamps = new Map<string, number[]>();

  private getTodayUtcString(): string {
    return new Date().toISOString().slice(0, 10);
  }

  // Enforces daily limit (e.g., 1,000 req/day for MaxMind GeoLite Web Service)
  public checkDailyQuota(provider: string, limit: number): { allowed: boolean; remaining: number; resetAt: string } {
    const today = this.getTodayUtcString();
    let quota = this.dailyQuotas.get(provider);

    if (!quota || quota.dayUtc !== today) {
      quota = { dayUtc: today, count: 0, limit };
      this.dailyQuotas.set(provider, quota);
    }

    const allowed = quota.count < limit;
    const remaining = Math.max(0, limit - quota.count);
    const tomorrow = new Date();
    tomorrow.setUTCHours(24, 0, 0, 0);

    return { allowed, remaining, resetAt: tomorrow.toISOString() };
  }

  public recordUsage(provider: string): void {
    const today = this.getTodayUtcString();
    let quota = this.dailyQuotas.get(provider);
    if (!quota || quota.dayUtc !== today) {
      quota = { dayUtc: today, count: 0, limit: 1000 };
      this.dailyQuotas.set(provider, quota);
    }
    quota.count += 1;
  }

  // Sliding window rate limit (e.g., max 10 requests per second)
  public checkSlidingWindow(provider: string, maxPerWindow: number = 10, windowMs: number = 1000): boolean {
    const now = Date.now();
    const timestamps = this.requestTimestamps.get(provider) || [];
    const windowStart = now - windowMs;
    const filtered = timestamps.filter(t => t > windowStart);

    if (filtered.length >= maxPerWindow) {
      this.requestTimestamps.set(provider, filtered);
      return false;
    }

    filtered.push(now);
    this.requestTimestamps.set(provider, filtered);
    return true;
  }

  public getUsage(provider: string): { count: number; dayUtc: string } {
    const today = this.getTodayUtcString();
    const quota = this.dailyQuotas.get(provider);
    if (!quota || quota.dayUtc !== today) {
      return { count: 0, dayUtc: today };
    }
    return { count: quota.count, dayUtc: quota.dayUtc };
  }
}

export const providerRateLimiter = new ProviderRateLimiter();
