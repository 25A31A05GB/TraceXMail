# TraceXMail Domain, IP & Geolocation Intelligence Audit Report
**Problem Statement:** Smart India Hackathon 2026 — PS 26106  
**Document Artifact:** `docs/INTELLIGENCE_AUDIT.md`  
**Audit Scope:** Full codebase scan of `src/`, `server.ts`, `scripts/`, `data/`, and frontend components.  
**Principle:** **REAL + INCOMPLETE** strictly preferred over **FAKE + COMPLETE**. Never silently invent intelligence.

---

## 1. Intelligence Features Audit Matrix

| Feature | Current Source | Real/Fake | File | Required Change |
| :--- | :--- | :--- | :--- | :--- |
| **MaxMind GeoLite2 IP Geolocation** | `maxmindService.ts` via compiled subnet array & local CSVs | **Partially Real / Static** | `src/server/maxmindService.ts` | Replace static array with official `maxmind` `.mmdb` reader (`maxmind.open`) with long-lived reader instance, official MaxMind Web Service fallback (`geolite.info`), and real local CSV fallback. Never fabricate coordinates. |
| **Unmapped Public IPv4 Fallback** | Deterministic string hash modulo into 10 hardcoded global cities (Tokyo, London, Sydney, Frankfurt, etc.) | **FAKE** | `src/server/maxmindService.ts` (lines 567–595) | **DELETE ENTIRELY.** If IP is unmapped or database unconfigured, return `status = 'unavailable'`, `reason = 'database_not_configured_or_unmapped'`, and all geographic fields `null`. |
| **Private IP & RFC 1918 Demarcation** | `ipExtractor.ts` regex & bitwise mask classifier | **REAL** | `src/server/ipExtractor.ts`, `src/utils/parser.ts` | Retain bitwise RFC 1918 logic; return `isPublic: false`, `lookupStatus: 'not_applicable'`, `reason: 'private_address'`. Never query external providers for RFC 1918 or loopback addresses. |
| **Client-Side GeoIP Fake Fallback** | `LOCAL_MAXMIND_BLOCKS` + IP string hash fallback returning fake Sofia/Tokyo coords & `relay-ip.net` PTR | **FAKE** | `src/utils/maxmindService.ts` (lines 262–296) | **REMOVE FAKE FALLBACK.** Clients must never invent coordinates or PTRs. Client must rely on backend enrichment data or return explicit `found: false`, coordinates `undefined`. |
| **Parser Prefix Geo Mapping** | `KNOWN_GEO` prefix dictionary (185.220 -> Sofia, 89.144 -> Hetzner, etc.) | **FAKE / Hardcoded** | `src/utils/parser.ts` (lines 21–30, 184–187) | **REMOVE HARDCODED PREFIX MAPPING.** If backend enrichment is not provided, mark IP as `UNRESOLVED_UNKNOWN` with no invented city, lat, lng, or ASN. |
| **Domain DNS Resolution (A, MX, TXT, NS)** | Node.js `dns.promises` (resolve4, resolveMx, resolveTxt, resolveNs) | **REAL** | `src/server/domainService.ts` (lines 235–299) | Consolidate into `src/server/intelligence/dns.ts`. Support A, AAAA, MX, NS, CNAME, TXT (SPF, DMARC, DKIM with selector). Add timeout, bounded retry, and structured error handling (`NXDOMAIN`, `SERVFAIL`, `TIMEOUT`). |
| **Domain RDAP Registration** | ICANN/IANA RDAP HTTP client via Verisign and rdap.org | **REAL** | `src/server/domainService.ts` (lines 122–192) | Consolidate into `src/server/intelligence/rdap.ts`. Support bootstrap discovery and query timeout. Retain registration, update, expiration events, and registrar entity parsing. |
| **RDAP Registrar Fallback Strings** | Fallback string assignment (`Brand Registrar (Secured)`, `Domain Registrar`) when registrar is missing | **FAKE** | `src/server/domainService.ts` (line 334) | **REMOVE FAKE STRINGS.** Return `registrar: null`, `status = 'unavailable'` when registrar entity is absent or privacy-redacted in RDAP response. |
| **Domain Typosquatting Analysis** | Levenshtein distance on domain labels + substring matching against recognized enterprise brands | **REAL** | `src/server/domainService.ts` (lines 32–117) | Retain algorithmic Levenshtein and brand matching. Expose target brand, technique, and distance with explicit `source: 'algorithmic_levenshtein'`. |
| **Threat Intelligence (AbuseIPDB)** | Fallback setting `isp = 'Global Hosting Provider'`, `countryCode = 'US'`, Tor exit node if IP starts with `185.220.101.` | **FAKE / Simulated** | `src/server/threatIntelService.ts` (lines 78–89) | **REMOVE SIMULATED VALUES.** If `ABUSEIPDB_API_KEY` is absent, return `status: 'unavailable'`, `reason: 'provider_not_configured'`, score `null`. Never invent reputation scores or ISPs. |
| **Interactive Map Coordinates** | Leaflet rendering markers from `hop.lat` and `hop.lng` | **REAL (When coords exist)** | `src/components/MapView.tsx` | Strictly plot markers ONLY when valid numeric coordinates exist. When zero coordinates are resolved, show clear "Location unavailable" state. Add mandatory network geolocation disclaimer. |
| **Forensic Language & Attribution** | Terminology referring to "Attacker Location" or "Attacker IP" | **SPECULATIVE** | `server.ts`, UI components | Standardize on **"Observed Ingress IP"**, **"Observed Sending Infrastructure"**, and **"Approximate Network Geolocation"**. |
| **Provenance Tracking** | Partial string `lookupMethod` and `source` | **INCOMPLETE** | `server.ts`, `geoService.ts`, `domainService.ts` | Implement formal `provenance` metadata structure on all enriched IP and domain records: `provider`, `source`, `status`, `retrievedAt`, `cached`, `reason`. |
| **Cache & Request Deduplication** | Ad-hoc in-memory `Map` without TTL or in-flight deduplication | **INCOMPLETE** | `src/server/geoService.ts`, `domainService.ts` | Implement centralized TTL cache (`GeoIP: 24h`, `ASN: 24h`, `DNS: 1h`, `RDAP: 24h`) with `Map<lookupKey, Promise<Result>>` in-flight promise deduplication. |
| **MaxMind GeoLite Daily Rate Limiting** | None | **MISSING** | `src/server/geoService.ts` | Implement daily request counter (1,000 req/day limit) + rolling window rate limiter for MaxMind GeoLite Web Service. Gracefully return `status = 'rate_limited'` on threshold. |

---

## 2. Architectural Blueprint for Real Intelligence Pipeline

```text
Incoming Message (.eml)
         ↓
RFC 5322 Ingress & Hop Parser (ipExtractor.ts)
         ↓
Extracted IPs & Domains
         ↓
IP Validation (ipValidation.ts)
 ├── Private / RFC 1918 / Loopback ──→ status: "not_applicable", reason: "private_address" (Zero external calls)
 └── Public Routable IP
         ↓
Deduplication & Cache Layer (cache.ts)
 ├── Cache HIT ──→ Return with cached: true, retrievedAt: timestamp
 └── Cache MISS ──→ In-Flight Promise Map
         ↓
GeoIP & ASN Pipeline (geoip.ts & asn.ts)
 ├── 1. Local MaxMind .mmdb Reader (Long-lived reader via `maxmind` package)
 ├── 2. Verified Local MaxMind CSV Lookup (data/maxmind/)
 ├── 3. MaxMind Web Service (geolite.info with MAXMIND_ACCOUNT_ID/LICENSE_KEY & 1,000/day limit)
 └── 4. Unmapped / Unavailable ──→ status: "unavailable", reason: "database_not_configured_or_unmapped", coords: null
         ↓
Domain DNS & RDAP Pipeline (dns.ts & rdap.ts)
 ├── DNS: Node.js dns.promises (A, AAAA, MX, NS, TXT - SPF/DMARC) with 5s timeout & structured errors
 └── RDAP: Live HTTP RDAP discovery (Verisign / ICANN rdap.org) with 5s timeout; null on missing registrar
         ↓
Correlation Engine (domain → IP → GeoIP → ASN)
         ↓
Provenanced Snapshot Attached to Forensic Case
```

---

## 3. Immediate Action Plan

1. Create modular intelligence engine in `src/server/intelligence/`:
   - `types.ts`: Normalized GeoIP, ASN, DNS, RDAP, Provenance, and Enrichment data contracts.
   - `cache.ts`: Configurable TTL in-memory cache with in-flight Promise deduplication (`requestMap`).
   - `rateLimiter.ts`: Daily quota tracking (1,000 req/day for MaxMind GeoLite) + sliding-window rate limiting.
   - `ipValidation.ts`: Robust IPv4/IPv6 parser and RFC 1918 / RFC 1122 / APIPA demarcation.
   - `geoip.ts`: Multi-tier GeoIP provider (Local `.mmdb` via `maxmind` -> Local CSV -> Official MaxMind Web Service -> Unavailable).
   - `asn.ts`: Multi-tier ASN provider (Local `.mmdb` -> Local CSV -> MaxMind Web Service -> Unavailable).
   - `dns.ts`: Authoritative DNS resolution (A, AAAA, MX, NS, TXT - SPF/DMARC) with timeouts and error types.
   - `rdap.ts`: Live RDAP querying for registration events and registrar entity with zero fake fallbacks.
   - `domain.ts`: Domain extraction, normalization, Levenshtein typosquatting, and correlation.
   - `provenance.ts`: Evidence provenance stamps (`OBSERVED`, `ENRICHED`, `MODEL`, `INFERENCE`).
   - `errors.ts`: Structured forensic errors (`ValidationError`, `ProviderUnavailableError`, `RateLimitError`).
   - `index.ts`: Unified service entry point and batch enrichment API.
2. Refactor `src/server/geoService.ts` and `src/server/domainService.ts` to delegate directly to `src/server/intelligence/`.
3. Eradicate fake modulo-hash city fallback in `src/server/maxmindService.ts` and `src/utils/maxmindService.ts`.
4. Eradicate `KNOWN_GEO` in `src/utils/parser.ts`.
5. Expose REST APIs in `server.ts`:
   - `GET /api/intelligence/ip/:ip`
   - `GET /api/intelligence/domain/:domain`
   - `GET /api/intelligence/dns/:domain`
   - `GET /api/intelligence/rdap/:domain`
   - `POST /api/intelligence/enrich`
6. Update UI components:
   - `OverviewView.tsx`: IP & Domain Intelligence cards with real provenance badges (`OBSERVED`, `ENRICHED`, `MODEL`, `INFERENCE`) and live/cached status.
   - `MapView.tsx`: Strict coordinate verification, "Location unavailable" card, and network geolocation disclaimer.
7. Audit and run regression test suite `npm run test:forensics`, `npm run lint`, and build to verify zero regressions.
