/**
 * MaxMind GeoLite2 Weekly Refresh Worker
 * Re-downloads the latest biweekly GeoLite2-City and GeoLite2-ASN database updates
 * from MaxMind to keep ASN churn and IP allocations up to date.
 */

import { downloadMaxMindDatabases } from './download_maxmind_db';
import 'dotenv/config';

export async function refreshMaxMindDatabases(): Promise<boolean> {
  console.log(`[MaxMind Refresh Worker] Starting scheduled database update check at ${new Date().toISOString()}...`);
  try {
    const results = await downloadMaxMindDatabases();
    if (results.city.success && results.asn.success) {
      console.log('✅ [MaxMind Refresh Worker] GeoLite2 databases successfully updated.');
      return true;
    } else {
      console.warn('⚠️ [MaxMind Refresh Worker] Database refresh skipped or incomplete:', results.city.error || results.asn.error);
      return false;
    }
  } catch (err) {
    console.error('❌ [MaxMind Refresh Worker] Error refreshing databases:', err);
    return false;
  }
}

// Auto-run if executed directly
if (process.argv[1] && (process.argv[1].endsWith('refresh_maxmind_db.ts') || process.argv[1].endsWith('refresh_maxmind_db.js'))) {
  refreshMaxMindDatabases()
    .then(() => process.exit(0))
    .catch(() => process.exit(0));
}
