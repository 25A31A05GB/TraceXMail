import { EvidenceProvenanceType, IntelligenceLookupStatus, ProvenanceMetadata } from './types';

export function createProvenanceMetadata(params: {
  evidenceType: EvidenceProvenanceType;
  provider: string;
  source: string;
  status: IntelligenceLookupStatus;
  cached?: boolean;
  reason?: string;
  limitation?: string;
  copyright?: string;
  license?: string;
}): ProvenanceMetadata {
  return {
    evidenceType: params.evidenceType,
    provider: params.provider,
    source: params.source,
    retrievedAt: new Date().toISOString(),
    cached: Boolean(params.cached),
    status: params.status,
    reason: params.reason,
    limitation: params.limitation,
    copyright: params.copyright,
    license: params.license
  };
}

export const MAXMIND_COPYRIGHT_NOTICE = 'Database and Contents Copyright (c) 2026 MaxMind, Inc.';
export const MAXMIND_LICENSE_NOTICE =
  'Use of this MaxMind product is governed by MaxMind GeoLite End User License Agreement (https://www.maxmind.com/en/geolite/eula). Incorporates GeoNames data.';
