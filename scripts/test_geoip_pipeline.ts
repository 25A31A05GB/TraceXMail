/**
 * Geolocation & MaxMind Fallback Pipeline Verification Test
 * Tests real-world IP resolution against the multi-tier pipeline:
 * Local MaxMind MMDB -> ip-api.com -> ipwho.is -> ipgeolocation.io
 */

import { resolveIpGeolocationWithFallback } from '../src/server/geoService';
import { maxMindDb } from '../src/server/maxmindService';

const TEST_IPS = [
  { ip: '8.8.8.8', expectedOwner: 'Google', type: 'Public Anycast DNS' },
  { ip: '1.1.1.1', expectedOwner: 'Cloudflare', type: 'Public Anycast DNS' },
  { ip: '9.9.9.9', expectedOwner: 'Quad9', type: 'Public Anycast DNS' },
  { ip: '208.67.222.222', expectedOwner: 'OpenDNS / Cisco', type: 'Public Anycast DNS' },
  { ip: '185.220.101.5', expectedOwner: 'Tor Exit Node', type: 'Tor Anonymizer Relay' },
  { ip: '192.168.1.100', expectedOwner: 'Private RFC 1918', type: 'Class C Intranet Subnet' },
  { ip: '10.0.4.15', expectedOwner: 'Private RFC 1918', type: 'Class A Intranet Subnet' }
];

async function runGeoIpTests() {
  console.log('================================================================');
  console.log('TraceXMail Geolocation & Network Intelligence Pipeline Test');
  console.log('================================================================');
  console.log(`Local MMDB Database Active: ${maxMindDb.hasLocalDatabase() ? 'YES (Binary MMDB Reader)' : 'NO (Using Live Fallback Chain)'}`);
  console.log('----------------------------------------------------------------\n');

  let passed = 0;
  let total = TEST_IPS.length;

  for (const testCase of TEST_IPS) {
    const start = Date.now();
    const result = await resolveIpGeolocationWithFallback(testCase.ip);
    const duration = Date.now() - start;

    console.log(`🔍 IP: ${testCase.ip.padEnd(16)} [${testCase.type}]`);
    console.log(`   Resolution Time: ${duration}ms`);
    console.log(`   Source:          ${result.source}`);
    console.log(`   Lookup Method:   ${result.lookupMethod}`);
    console.log(`   Location:        ${result.city || 'N/A'}, ${result.country || 'N/A'} (${result.countryCode || 'N/A'})`);
    console.log(`   Coordinates:     ${result.lat !== null && result.lat !== undefined ? `${result.lat}, ${result.lng}` : 'N/A'}`);
    console.log(`   ASN / Org:       ${result.asn || 'N/A'} - ${result.org || result.isp || 'N/A'}`);
    console.log(`   Tor Exit Node:   ${result.isTor ? '🔴 YES' : 'NO'}`);
    console.log(`   Reverse DNS PTR: ${result.reverseDns || 'N/A'}`);
    console.log(`   Lookup Status:   ${result.lookupStatus}`);

    // Verification assertion
    if (result.isPrivate) {
      if (result.isRfc1918 && result.countryCode === 'LAN') {
        console.log(`   ✅ RFC 1918 Demarcation PASSED`);
        passed++;
      } else {
        console.log(`   ❌ Private IP demarcation FAILED`);
      }
    } else {
      if (result.country && result.countryCode && result.source !== 'unavailable') {
        console.log(`   ✅ Public Geolocation Resolution PASSED`);
        passed++;
      } else {
        console.log(`   ❌ Public IP resolution FAILED or returned unavailable`);
      }
    }
    console.log('----------------------------------------------------------------');
  }

  console.log(`\nResults: ${passed}/${total} test cases passed.`);
  if (passed === total) {
    console.log('🎉 Geolocation pipeline verified successfully!');
  } else {
    console.warn('⚠️ Some lookups did not resolve as expected.');
  }
}

runGeoIpTests()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('Fatal test error:', err);
    process.exit(1);
  });
