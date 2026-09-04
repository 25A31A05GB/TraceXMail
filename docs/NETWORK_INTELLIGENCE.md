# TraceXMail Network Intelligence & Session Telemetry

## 1. Overview
The **Network Intelligence** panel provides real-time client connection telemetry for investigating SOC analysts. It enables analysts to verify their active workstation network profile, identify external IP/ASN egress points, measure browser-to-backend API latency, and perform on-demand bandwidth estimations without requiring paid third-party dependencies.

> **Forensic Separation Notice:**
> Network information displayed in this panel represents the **current analyst session / workstation environment**. It is strictly isolated from threat-intelligence indicators (originating IP, relay hops, and sender ASNs) extracted from investigated emails.

---

## 2. Free Services & Provider Integration
To maintain production capability without incurring recurring SaaS costs, TraceXMail integrates free public geolocation and network intelligence services with automatic failover:

1. **Primary Provider: `ipwho.is`**
   - **Service:** Public REST endpoint (`https://ipwho.is/` and `https://ipwho.is/{ip}`)
   - **Authentication:** No API keys or credentials required
   - **Data Provided:** Public IP, connection type (IPv4/IPv6), city, region, country, Autonomous System Number (ASN), ISP, and network organization name
   - **Rate Limit:** 10,000 requests per month; handled gracefully via 10-minute server-side in-memory caching (`networkInfoCache`)

2. **Fallback Provider: `ip-api.com`**
   - **Service:** Public REST endpoint (`http://ip-api.com/json/{ip}`)
   - **Authentication:** None required
   - **Data Provided:** IP, city, regionName, country, ISP, organization, and ASN
   - **Rate Limit:** 45 requests per minute

3. **Offline / Isolated Network Fallback:**
   - If third-party APIs timeout (capped at 4,000 ms) or return rate-limit errors, the service degrades gracefully:
     - Returns available connection headers (e.g. IPv4/IPv6 type)
     - Marks missing fields as `"Unavailable"` rather than crashing or throwing 500 errors
     - Sets `source: "unavailable"` and preserves complete system stability

---

## 3. What Information Is Approximate
- **IP-Based Geolocation (City, Region, Country):**
  - **Status: Approximate.**
  - Geolocation derived from IP registry allocations (BGP/RIR routing tables) reflects ISP gateway routing hubs, regional data centers, or carrier-grade NAT aggregation points.
  - **It does not represent exact physical, GPS, or cellular coordinates.**
  - All UI elements and API responses explicitly declare `isApproximate: true` alongside the mandatory disclaimer:
    > *"IP-based location is approximate and may not represent the user's exact location."*

- **Public IP & ASN:**
  - Dynamic public egress address detected behind production reverse proxies (`trust proxy: true`) using sanitized `X-Forwarded-For` chains.
  - ASN represents the autonomous system routing the analyst's outbound connection (e.g., `AS55836` for Reliance Jio or `AS396982` for Google LLC).

- **Hosting Server Location:**
  - Evaluated based on deployment infrastructure environment (e.g., `Singapore (asia-southeast1, Google Cloud Run)`).

---

## 4. Latency Measurement Methodology
- **Endpoint:** `GET /api/network/ping`
- **Methodology:** Browser round-trip time (RTT) measured using the High Resolution Time API:
  ```javascript
  const start = performance.now();
  await fetch("/api/network/ping", { cache: "no-store" });
  const end = performance.now();
  const latencyMs = Math.round(end - start);
  ```
- **Payload:** Lightweight JSON (`{"status":"ok","timestamp":1788538543227}`) with explicit zero-caching HTTP headers (`Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`).
- **Indicator:** Color-coded status in the UI:
  - Green (< 100 ms): Optimal SOC responsiveness
  - Amber (100–250 ms): Moderate network transit
  - Rose (> 250 ms): High latency connection

---

## 5. Bandwidth Measurement (Controlled On-Demand)
- **Automatic Execution:** **Disabled by design.** Bandwidth tests are NEVER executed automatically upon page load to avoid unexpected cellular/metered data consumption.
- **User Control:** Triggered exclusively via explicit user interaction with the **"Test Bandwidth"** button.
- **Endpoint:** `GET /api/network/bandwidth-payload`
- **Payload Size:** Controlled 512 KB (524,288 bytes) pre-allocated binary buffer (`application/octet-stream`).
- **Calculation Formula:**
  $$\text{Throughput (Mbps)} = \frac{\text{Bytes Transferred} \times 8}{\text{Elapsed Seconds} \times 1024 \times 1024}$$
- **Labeling:** Explicitly labeled as **"Estimated Throughput"** in both UI and documentation, acknowledging that a single HTTP stream over ~512 KB provides a directional heuristic rather than a multi-thread synthetic speed test.
- **Data Hygiene:** Results are retained in client component state for the current session only and are not persisted to database tables or audit logs.

---

## 6. Security & Reverse Proxy Compliance
1. **Reverse Proxy Configuration:**
   - Express is configured with `app.set('trust proxy', true)` to accurately resolve client IPs behind Google Cloud Run, Nginx, or Kubernetes ingress controllers.
   - Strips `::ffff:` IPv4-mapped IPv6 prefixes and sanitizes port suffixes.
2. **SSRF Prevention:**
   - Endpoints do not accept arbitrary URLs from caller query parameters. Queries to external IP registries are strictly restricted to validated IPv4/IPv6 address patterns.
3. **Secret Protection:**
   - No API secrets or tokens are stored in or exposed to frontend code.
4. **Request Timeouts:**
   - External fetch calls utilize `AbortController` bounded to a 4,000 ms timeout to prevent thread starvation.
