// Intelligence Layer Structured Errors

export class IntelligenceError extends Error {
  public readonly code: string;
  public readonly provider: string;
  public readonly target: string;
  public readonly retryable: boolean;

  constructor(message: string, code: string, provider: string, target: string, retryable: boolean = false) {
    super(message);
    this.name = 'IntelligenceError';
    this.code = code;
    this.provider = provider;
    this.target = target;
    this.retryable = retryable;
  }
}

export class ValidationError extends IntelligenceError {
  constructor(message: string, target: string) {
    super(message, 'INVALID_INPUT', 'internal_validator', target, false);
    this.name = 'ValidationError';
  }
}

export class ProviderUnavailableError extends IntelligenceError {
  constructor(provider: string, target: string, details?: string) {
    super(
      `Intelligence provider ${provider} unavailable for ${target}${details ? `: ${details}` : ''}`,
      'PROVIDER_UNAVAILABLE',
      provider,
      target,
      true
    );
    this.name = 'ProviderUnavailableError';
  }
}

export class RateLimitError extends IntelligenceError {
  public readonly resetTime?: string;

  constructor(provider: string, target: string, resetTime?: string) {
    super(`Rate limit exceeded for provider ${provider}`, 'RATE_LIMITED', provider, target, false);
    this.name = 'RateLimitError';
    this.resetTime = resetTime;
  }
}
