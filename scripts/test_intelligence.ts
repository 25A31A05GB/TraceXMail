import { validateAndClassifyIp } from '../src/server/intelligence/ipValidation';
import { resolveGeoIp } from '../src/server/intelligence/geoip';
import { resolveAsn } from '../src/server/intelligence/asn';
import { resolveDns } from '../src/server/intelligence/dns';
import { resolveRdap } from '../src/server/intelligence/rdap';
import { resolveDomainIntelligence, analyzeTyposquatting } from '../src/server/intelligence/domain';
import { enrichIpFull } from '../src/server/intelligence/index';
import { providerRateLimiter } from '../src/server/intelligence/rateLimiter';
import { geoIpCache } from '../src/server/intelligence/cache';
import { MAXMIND_COPYRIGHT_NOTICE, MAXMIND_LICENSE_NOTICE } from '../src/server/intelligence/provenance';

let totalTests = 0;
let passedTests = 0;

function assert(condition: boolean, description: string): void {
  totalTests++;
  if (condition) {
    console.log(`  ✅ [PASS] ${description}`);
    passedTests++;
  } else {
    console.error(`  ❌ [FAIL] ${description}`);
    process.exitCode = 1;
  }
}

async function runIntelligenceTests() {
  console.log('================================================================');
  console.log('TraceXMail Intelligence & Provenance Audit Verification Suite');
  console.log('Standards: RFC 1918, RFC 1122, RFC 3927, RFC 7480, RFC 7208');
  console.log('================================================================\n');

  // Test Suite 1: RFC Classification
  console.log('[Group 1: RFC-Compliant IP Address Classification]');
  const ipPrivateA = validateAndClassifyIp('10.50.1.1');
  assert(ipPrivateA.isPrivate && ipPrivateA.isRfc1918 && ipPrivateA.scope === 'PRIVATE_RFC1918', '10.50.1.1 classified as RFC 1918 Class A');

  const ipPrivateB = validateAndClassifyIp('172.20.10.5');
  assert(ipPrivateB.isPrivate && ipPrivateB.isRfc1918 && ipPrivateB.scope === 'PRIVATE_RFC1918', '172.20.10.5 classified as RFC 1918 Class B');

  const ipPrivateC = validateAndClassifyIp('192.168.100.254');
  assert(ipPrivateC.isPrivate && ipPrivateC.isRfc1918 && ipPrivateC.scope === 'PRIVATE_RFC1918', '192.168.100.254 classified as RFC 1918 Class C');

  const ipLoopback = validateAndClassifyIp('127.0.0.1');
  assert(ipLoopback.isPrivate && ipLoopback.scope === 'LOOPBACK_RFC1122', '127.0.0.1 classified as Loopback (RFC 1122)');

  const ipLinkLocal = validateAndClassifyIp('169.254.10.20');
  assert(ipLinkLocal.isPrivate && ipLinkLocal.scope === 'LINK_LOCAL_RFC3927', '169.254.10.20 classified as Link-Local (RFC 3927)');

  const ipCgnat = validateAndClassifyIp('100.64.0.1');
  assert(ipCgnat.isPrivate && ipCgnat.scope === 'SHARED_CGNAT_RFC6598', '100.64.0.1 classified as CGNAT (RFC 6598)');

  const ipPublic = validateAndClassifyIp('8.8.8.8');
  assert(ipPublic.isValid && ipPublic.isPublic && ipPublic.scope === 'PUBLIC_ROUTABLE', '8.8.8.8 classified as Public Routable');

  const ipInvalid = validateAndClassifyIp('999.999.999.999');
  assert(!ipInvalid.isValid && ipInvalid.scope === 'INVALID_SYNTAX', '999.999.999.999 classified as Invalid Syntax');

  // Test Suite 2: Anti-Fabrication Guarantee (No Fake Cities)
  console.log('\n[Group 2: Anti-Fabrication Guarantee (Real Data or Unavailable)]');
  // Unmapped public IP that does not match local sample blocks
  const unmappedPublic = await resolveGeoIp('193.0.0.1');
  assert(unmappedPublic.city === null, 'Unmapped public IP returns null city (NEVER fake Tokyo/London/Sofia)');
  assert(unmappedPublic.latitude === null && unmappedPublic.longitude === null, 'Unmapped public IP returns null coordinates');
  assert(unmappedPublic.lookupStatus === 'unavailable' || unmappedPublic.lookupStatus === 'success', 'Unmapped public IP has explicit forensic lookup status');
  assert(unmappedPublic.provenance !== undefined, 'Unmapped public IP includes full provenance metadata');

  // Private IP returns not_applicable
  const privateGeo = await resolveGeoIp('192.168.1.1');
  assert(privateGeo.lookupStatus === 'not_applicable', 'Private IP GeoIP returns lookupStatus: not_applicable');
  assert(privateGeo.city === null, 'Private IP GeoIP returns null city');
  assert(privateGeo.country === null, 'Private IP GeoIP returns null country');

  // Test Suite 3: Verified Local MaxMind Resolution
  console.log('\n[Group 3: Verified Local MaxMind Dataset Integration]');
  // Mapped public IP in our verified local sample: 185.220.101.5 (Sofia, Bulgaria)
  const mappedIp = await resolveGeoIp('185.220.101.5');
  assert(mappedIp.lookupStatus === 'success', 'Mapped IP 185.220.101.5 lookup status is success');
  assert(mappedIp.countryCode === 'BG', 'Mapped IP 185.220.101.5 resolves to Bulgaria (BG)');
  assert(mappedIp.city === 'Sofia', 'Mapped IP 185.220.101.5 resolves to Sofia');
  assert(typeof mappedIp.latitude === 'number', 'Mapped IP has valid floating point latitude');
  assert(mappedIp.provenance.status === 'success', 'Mapped IP provenance status is success');

  // Test Suite 4: ASN Resolution
  console.log('\n[Group 4: Autonomous System Number (ASN) Resolution]');
  const mappedAsn = await resolveAsn('185.220.101.5');
  assert(mappedAsn.lookupStatus === 'success', 'Mapped IP ASN resolution is success');
  assert(mappedAsn.asn === 'AS200548', 'Mapped IP resolves to AS200548');
  assert(mappedAsn.autonomousSystemOrganization?.includes('Zettahost') ?? false, 'Mapped IP organization is Zettahost Cyber Ltd');

  const privateAsn = await resolveAsn('10.0.0.1');
  assert(privateAsn.lookupStatus === 'not_applicable', 'Private IP ASN resolution returns not_applicable');
  assert(privateAsn.asn === null, 'Private IP ASN is null');

  // Test Suite 5: Typosquatting Analysis
  console.log('\n[Group 5: Typosquatting & Deceptive Domain Detection]');
  const typoSub = analyzeTyposquatting('paypal-security-update.com');
  assert(typoSub.isTyposquat, 'paypal-security-update.com flagged as typosquat');
  assert(typoSub.targetBrand === 'paypal', 'paypal-security-update.com target brand identified as paypal');

  const typoEdit = analyzeTyposquatting('paypa1.com');
  assert(typoEdit.isTyposquat, 'paypa1.com flagged as typosquat');
  assert(typoEdit.distance === 1, 'paypa1.com edit distance is 1');

  const legitDomain = analyzeTyposquatting('google.com');
  assert(!legitDomain.isTyposquat, 'Exact brand domain google.com is NOT flagged as typosquat');

  // Test Suite 6: In-Memory Caching & Deduplication
  console.log('\n[Group 6: In-Memory Caching & Promise Deduplication]');
  geoIpCache.clear();
  const res1 = await resolveGeoIp('185.220.101.5');
  const res2 = await resolveGeoIp('185.220.101.5');
  assert(res1.ip === res2.ip, 'Cached IP resolution returns consistent data');
  assert(res2.cached === true, 'Subsequent lookup is flagged as cached');

  // Test Suite 7: Provider Rate Limiting
  console.log('\n[Group 7: Provider Rate Limiter Quotas]');
  const quota = providerRateLimiter.checkDailyQuota('test-provider', 2);
  assert(quota.allowed && quota.remaining === 2, 'New daily quota check allowed with full remaining');
  providerRateLimiter.recordUsage('test-provider');
  providerRateLimiter.recordUsage('test-provider');
  const quotaExhausted = providerRateLimiter.checkDailyQuota('test-provider', 2);
  assert(!quotaExhausted.allowed && quotaExhausted.remaining === 0, 'Exhausted daily quota correctly rejected');

  // Test Suite 8: Attribution & Provenance
  console.log('\n[Group 8: Legal Attribution & Evidentiary Provenance]');
  assert(MAXMIND_COPYRIGHT_NOTICE.includes('MaxMind'), 'MaxMind copyright notice present');
  assert(MAXMIND_LICENSE_NOTICE.includes('MaxMind') || MAXMIND_LICENSE_NOTICE.includes('License'), 'MaxMind license notice present');

  const fullEnrichment = await enrichIpFull('185.220.101.5');
  assert(fullEnrichment.provenance.evidenceType === 'ENRICHED', 'Full enrichment stamped with ENRICHED evidence type');
  assert(fullEnrichment.provenance.retrievedAt !== undefined, 'Full enrichment stamped with ISO retrievedAt timestamp');

  console.log('\n================================================================');
  console.log(`INTELLIGENCE SUITE RESULTS: ${passedTests} / ${totalTests} PASSED`);
  console.log('================================================================\n');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runIntelligenceTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
