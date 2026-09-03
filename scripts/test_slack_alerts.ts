import {
  sendSlackSecurityAlert,
  clearSentAlertCache,
  shouldSendAlert,
  getSlackConfig
} from '../src/server/slackService';

async function runSlackTests() {
  console.log('--- Starting TraceXMail Slack Integration Diagnostic Tests ---');
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}${detail ? `: ${detail}` : ''}`);
      failed++;
    }
  }

  // Save current env vars
  const origToken = process.env.SLACK_BOT_TOKEN;
  const origChannel = process.env.SLACK_CHANNEL_ID;
  const origMinSev = process.env.SLACK_MIN_SEVERITY;
  const origWebhook = process.env.SLACK_WEBHOOK_URL;

  try {
    // Test 1: Severity matching logic
    assert(shouldSendAlert('CRITICAL', 'HIGH') === true, 'CRITICAL >= HIGH');
    assert(shouldSendAlert('HIGH', 'HIGH') === true, 'HIGH >= HIGH');
    assert(shouldSendAlert('MEDIUM', 'HIGH') === false, 'MEDIUM < HIGH (skipped)');
    assert(shouldSendAlert('LOW', 'HIGH') === false, 'LOW < HIGH (skipped)');
    assert(shouldSendAlert('MEDIUM', 'MEDIUM') === true, 'MEDIUM >= MEDIUM');

    // Test 2: Unconfigured Slack -> returns DISABLED log, non-blocking
    delete process.env.SLACK_BOT_TOKEN;
    delete process.env.SLACK_CHANNEL_ID;
    delete process.env.SLACK_WEBHOOK_URL;
    clearSentAlertCache();

    const unconfiguredLog = await sendSlackSecurityAlert({
      id: 'alt_test_unconfig',
      severity: 'CRITICAL',
      subject: 'Test Alert Unconfigured'
    });
    assert(unconfiguredLog?.status === 'DISABLED', 'Unconfigured Slack returns DISABLED status');

    // Test 3: Skipped Severity
    process.env.SLACK_BOT_TOKEN = 'xoxb-dummy-token';
    process.env.SLACK_CHANNEL_ID = 'C1234567';
    process.env.SLACK_MIN_SEVERITY = 'HIGH';
    clearSentAlertCache();

    const skippedSevLog = await sendSlackSecurityAlert({
      id: 'alt_test_medium',
      severity: 'MEDIUM',
      subject: 'Medium Risk Alert'
    });
    assert(skippedSevLog?.status === 'SKIPPED_SEVERITY', 'MEDIUM alert skipped when min severity is HIGH');

    // Test 4: Duplicate alert prevention
    const criticalAlert = {
      id: 'alt_test_dup_001',
      severity: 'CRITICAL',
      subject: 'Critical Alert Duplicate Test'
    };

    // First call (mocking network or attempting)
    const log1 = await sendSlackSecurityAlert(criticalAlert);
    // Since token is dummy xoxb-dummy-token, Slack API will return invalid_auth / network error, status FAILED
    assert(log1?.status === 'FAILED', 'Dummy token fails gracefully with FAILED status without throwing');

    // Second call with same alert ID
    const log2 = await sendSlackSecurityAlert(criticalAlert);
    assert(log2?.status === 'SKIPPED_DUPLICATE', 'Duplicate alert ID is skipped');

    // Test 5: Simulated Slack API error handling (invalid auth)
    assert(log1?.error !== undefined, 'Error message is captured and logged on failure');

  } finally {
    // Restore env vars
    if (origToken !== undefined) process.env.SLACK_BOT_TOKEN = origToken;
    else delete process.env.SLACK_BOT_TOKEN;

    if (origChannel !== undefined) process.env.SLACK_CHANNEL_ID = origChannel;
    else delete process.env.SLACK_CHANNEL_ID;

    if (origMinSev !== undefined) process.env.SLACK_MIN_SEVERITY = origMinSev;
    else delete process.env.SLACK_MIN_SEVERITY;

    if (origWebhook !== undefined) process.env.SLACK_WEBHOOK_URL = origWebhook;
    else delete process.env.SLACK_WEBHOOK_URL;
  }

  console.log(`\nSlack Diagnostic Test Results: ${passed} passed, ${failed} failed.`);
  if (failed > 0) process.exit(1);
}

runSlackTests();
