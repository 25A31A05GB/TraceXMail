/**
 * TraceXMail Automated Forensic Regression Test Suite
 * Problem Statement: Smart India Hackathon 2026 — PS 26106
 *
 * Test coverage:
 * 1. RFC 1918 Demarcation & Trust Boundary Traversal
 * 2. Hop Ordering & Trust Boundary Identification
 * 3. Authentication Parsing (SPF / DKIM / DMARC)
 * 4. Brand Mismatch & Lookalike Detection
 * 5. Reply-To Diversion Detection
 * 6. Risk Score Bounds (strictly 0 - 100)
 * 7. Forensic Determinism (Bit-level reproducible outputs)
 * 8. Zero NaN / Null / Undefined in Analysis Outputs
 */

import fs from 'fs';
import path from 'path';
import { extractHopsAndOriginIp, classifyIp } from '../src/server/ipExtractor';
import { parseRawEml } from '../src/utils/parser';
import { analyzeTyposquatting } from '../src/server/domainService';
import { classifyEmailForensics } from '../src/server/classifier';

let testsPassed = 0;
let testsFailed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    testsPassed++;
    console.log(`  ✅ [PASS] ${testName}`);
  } else {
    testsFailed++;
    console.error(`  ❌ [FAIL] ${testName}${detail ? ` — ${detail}` : ''}`);
  }
}

async function runTestSuite() {
  console.log('================================================================');
  console.log('TraceXMail Automated Forensic Regression Test Suite');
  console.log('Problem Statement: SIH 2026 — PS 26106');
  console.log('================================================================\n');

  // --------------------------------------------------------------------------
  // Test Group 1: RFC 1918 Demarcation & Subnet Classification
  // --------------------------------------------------------------------------
  console.log('[Group 1: RFC 1918 Demarcation & IP Scopes]');
  const ip10 = classifyIp('10.200.1.10');
  assert(ip10.isPrivate === true, '10.200.1.10 is identified as Private / RFC 1918');
  assert(ip10.subnetType === 'RFC 1918 Class A', '10.200.1.10 identified as RFC 1918 Class A');

  const ip172 = classifyIp('172.16.5.99');
  assert(ip172.isPrivate === true, '172.16.5.99 is identified as Private / RFC 1918');
  assert(ip172.subnetType === 'RFC 1918 Class B', '172.16.5.99 identified as RFC 1918 Class B');

  const ip192 = classifyIp('192.168.1.1');
  assert(ip192.isPrivate === true, '192.168.1.1 is identified as Private / RFC 1918');
  assert(ip192.subnetType === 'RFC 1918 Class C', '192.168.1.1 identified as RFC 1918 Class C');

  const ipLoopback = classifyIp('127.0.0.1');
  assert(ipLoopback.isPrivate === true, '127.0.0.1 is identified as Loopback / RFC 1122');

  const ipPublic = classifyIp('54.187.174.169');
  assert(ipPublic.isPrivate === false, '54.187.174.169 is identified as Public Routable IP');

  // --------------------------------------------------------------------------
  // Test Group 2: Hop Ordering & Trust Boundary Identification
  // --------------------------------------------------------------------------
  console.log('\n[Group 2: Received Hop Ordering & Trust Boundary Traversal]');
  const sampleHeaders = `
Received: by 10.200.1.10 with SMTP id internal-gateway; Tue, 01 Sep 2026 14:22:05 -0700
Received: from mail-relay.stripe.com (mail-relay.stripe.com [54.187.174.169]) by mx.enterprise-corp.internal with ESMTPS; Tue, 01 Sep 2026 14:22:03 -0700
Received: from client.internal.lan (unknown [192.168.10.50]) by mail-relay.stripe.com with ESMTP; Tue, 01 Sep 2026 14:22:00 -0700
  `.trim();

  const extraction = extractHopsAndOriginIp(sampleHeaders);
  assert(extraction.hops.length >= 2, 'Parsed multiple Received hops from header stream');

  // Trust boundary: The earliest untrusted public hop
  assert(Boolean(extraction.originIp), 'Origin/Ingress hop identified across trust boundary');
  assert(extraction.originIp === '54.187.174.169', 'Trust boundary correctly selects public ingress relay over private RFC 1918 hops');

  // --------------------------------------------------------------------------
  // Test Group 3: Authentication Header Parsing (SPF / DKIM / DMARC)
  // --------------------------------------------------------------------------
  console.log('\n[Group 3: Authentication Header Parsing]');
  const authHeaderPass = 'mx.google.com; dkim=pass header.i=@stripe.com; spf=pass (google.com: domain of bounces@stripe.com designates 54.187.174.169 as permitted sender); dmarc=pass (p=REJECT dis=NONE) header.from=stripe.com';
  const parsedPass = parseRawEml(`Authentication-Results: ${authHeaderPass}\nFrom: Stripe <invoices@stripe.com>\nSubject: Test\n`);
  assert(parsedPass.auth.spf.status === 'PASS', 'Parsed SPF PASS correctly');
  assert(parsedPass.auth.dkim.status === 'PASS', 'Parsed DKIM PASS correctly');
  assert(parsedPass.auth.dmarc.status === 'PASS', 'Parsed DMARC PASS correctly');

  const authHeaderFail = 'mx.enterprise.internal; dkim=fail (bad signature); spf=fail (domain of alert@paypal.com does not designate 185.220.101.5 as permitted sender); dmarc=reject';
  const parsedFail = parseRawEml(`Authentication-Results: ${authHeaderFail}\nFrom: PayPal <alert@paypal.com>\nSubject: Phish\n`);
  assert(parsedFail.auth.spf.status === 'FAIL', 'Parsed SPF FAIL correctly');
  assert(parsedFail.auth.dkim.status === 'FAIL', 'Parsed DKIM FAIL correctly');
  assert(parsedFail.auth.dmarc.status === 'REJECT', 'Parsed DMARC REJECT correctly');

  // --------------------------------------------------------------------------
  // Test Group 4: Brand Mismatch & Lookalike Detection
  // --------------------------------------------------------------------------
  console.log('\n[Group 4: Brand Mismatch & Lookalike Domain Detection]');
  const typosquat = analyzeTyposquatting('docusign-envelope-review.net');
  assert(typosquat.isTyposquat === true, 'Detected lookalike domain for docusign-envelope-review.net');
  assert(Boolean(typosquat.targetBrand?.toLowerCase().includes('docusign')), 'Correctly identified targeted brand as DocuSign');

  const paypalSpoof = analyzeTyposquatting('secure-paypal-account-update.net');
  assert(paypalSpoof.isTyposquat === true, 'Detected lookalike domain for secure-paypal-account-update.net');
  assert(Boolean(paypalSpoof.targetBrand?.toLowerCase().includes('paypal')), 'Correctly identified targeted brand as PayPal');

  const legitStripe = analyzeTyposquatting('stripe.com');
  assert(legitStripe.isTyposquat === false, 'Legitimate domain stripe.com is NOT flagged as typosquat');

  // --------------------------------------------------------------------------
  // Test Group 5: Reply-To Diversion Detection
  // --------------------------------------------------------------------------
  console.log('\n[Group 5: Reply-To Redirection & Identity Heuristics]');
  const becEmail = {
    from: 'David Harrison (CEO) <david.harrison@enterprise-corp.com>',
    fromDomain: 'enterprise-corp.com',
    replyTo: 'david.harrison.ceo.office@gmail.com',
    subject: 'Urgent Wire Transfer Needed Today',
    returnPath: 'ceo@executive-office-forwarder.org',
    bodyText: 'Please initiate an urgent wire transfer of $84,500 to our escrow counsel immediately.',
    hops: [],
    auth: {
      spf: { status: 'NEUTRAL' },
      dkim: { status: 'NONE' },
      dmarc: { status: 'FAIL' }
    }
  };

  const analysis1 = classifyEmailForensics(becEmail);
  const replyMismatchFeat = analysis1.features.find(f => f.feature === 'heuristic_identity_rules');
  assert(Boolean(replyMismatchFeat && replyMismatchFeat.triggered && replyMismatchFeat.description.includes('Reply-To')),
    'Reply-To diversion from corporate domain to gmail.com is triggered');

  // --------------------------------------------------------------------------
  // Test Group 6: Risk Score Bounds (Strictly 0 - 100)
  // --------------------------------------------------------------------------
  console.log('\n[Group 6: Threat Score Bounds & Verification]');
  assert(analysis1.threatScore >= 0 && analysis1.threatScore <= 100, `Threat score ${analysis1.threatScore} is bounded [0, 100]`);
  assert(Number.isInteger(analysis1.threatScore), 'Threat score is an integer');
  assert(analysis1.threatScoreBreakdown.total === analysis1.threatScore, 'Breakdown total matches threatScore');

  // Legit invoice test
  const legitEmail = {
    from: 'Stripe Billing <invoices@stripe.com>',
    fromDomain: 'stripe.com',
    subject: 'Your Monthly Stripe Invoice INV-8841',
    returnPath: 'bounces@stripe.com',
    bodyText: 'Your monthly invoice for $1,420.00 is available in your Stripe dashboard.',
    hops: [],
    auth: {
      spf: { status: 'PASS' },
      dkim: { status: 'PASS' },
      dmarc: { status: 'PASS' }
    }
  };
  const analysis2 = classifyEmailForensics(legitEmail);
  assert(analysis2.threatScore >= 0 && analysis2.threatScore <= 100, `Legit threat score ${analysis2.threatScore} is bounded [0, 100]`);
  assert(analysis2.threatScore < 25, `Legitimate invoice receives clean threat score (${analysis2.threatScore}/100)`);
  assert(analysis2.verdict === 'LEGITIMATE', 'Legitimate invoice classified as LEGITIMATE');

  // --------------------------------------------------------------------------
  // Test Group 7: Forensic Determinism (Identical Inputs Produce Identical Outputs)
  // --------------------------------------------------------------------------
  console.log('\n[Group 7: Forensic Determinism]');
  const runA = classifyEmailForensics(becEmail);
  const runB = classifyEmailForensics(becEmail);
  assert(runA.threatScore === runB.threatScore, 'Threat scores are 100% deterministic');
  assert(runA.predictedClass === runB.predictedClass, 'Predicted class is 100% deterministic');
  assert(runA.confidence === runB.confidence, 'Confidence margin is 100% deterministic');
  assert(JSON.stringify(runA.probabilities) === JSON.stringify(runB.probabilities), 'Posterior probabilities are bit-level identical across runs');

  // --------------------------------------------------------------------------
  // Test Group 8: Zero NaN / Null / Undefined in Output Payload
  // --------------------------------------------------------------------------
  console.log('\n[Group 8: Zero NaN / Null / Undefined Sanity Audit]');
  const checkZeroNan = (obj: any, pathStr = ''): boolean => {
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      const curPath = pathStr ? `${pathStr}.${key}` : key;
      if (typeof val === 'number' && isNaN(val)) {
        console.error(`NaN detected at: ${curPath}`);
        return false;
      }
      if (val === undefined) {
        console.error(`Undefined detected at: ${curPath}`);
        return false;
      }
      if (typeof val === 'object' && val !== null) {
        if (!checkZeroNan(val, curPath)) return false;
      }
    }
    return true;
  };

  assert(checkZeroNan(analysis1.probabilities), 'Zero NaN or undefined in probabilities');
  assert(checkZeroNan(analysis1.threatScoreBreakdown), 'Zero NaN or undefined in threatScoreBreakdown');
  assert(!isNaN(analysis1.mlConfidence), 'mlConfidence is a valid floating point number');

  // --------------------------------------------------------------------------
  // Test Group 9: Verification of Safe Demo Fixtures (.eml files)
  // --------------------------------------------------------------------------
  console.log('\n[Group 9: Safe Demo Fixture Ingestion]');
  const demoDir = path.join(process.cwd(), 'data/demo_emails');
  const demoFiles = [
    'legit_invoice.eml',
    'brand_impersonation.eml',
    'credential_harvesting.eml',
    'bec_wire_fraud.eml',
    'suspicious_graymail.eml'
  ];

  for (const filename of demoFiles) {
    const filePath = path.join(demoDir, filename);
    assert(fs.existsSync(filePath), `Fixture exists: ${filename}`);
    const content = fs.readFileSync(filePath, 'utf8');
    assert(content.includes('Received:'), `${filename} contains Received hops`);
    assert(content.includes('Authentication-Results:'), `${filename} contains Authentication-Results`);
  }

  // --------------------------------------------------------------------------
  // Final Test Summary
  // --------------------------------------------------------------------------
  console.log('\n================================================================');
  console.log(`TEST RESULTS: ${testsPassed} PASSED, ${testsFailed} FAILED`);
  console.log('================================================================');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal error running test suite:', err);
  process.exit(1);
});
