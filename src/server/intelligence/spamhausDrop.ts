/**
 * TraceXMail Spamhaus DROP / EDROP Cyberthreat Intelligence Service
 *
 * Implements authoritative detection for the Spamhaus Don't Route Or Peer (DROP)
 * and Extended DROP (EDROP) advisory datasets.
 *
 * DROP and EDROP consist of hijacked, stolen, or entirely malicious netblocks allocated
 * to cybercriminals, bulletproof botnet C2s, and spam operations.
 *
 * Synchronizes every 4 hours with local disk caching and immediate in-memory CIDR matching.
 */

import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { isIpInCidr } from '../maxmindService';

const DROP_URL = 'https://www.spamhaus.org/drop/drop.txt';
const EDROP_URL = 'https://www.spamhaus.org/drop/edrop.txt';
const DROP_V6_URL = 'https://www.spamhaus.org/drop/dropv6.txt';

const LOCAL_SPAMHAUS_FILE = path.join(process.cwd(), 'data/threat-lists/spamhaus-drop.txt');
const REFRESH_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours

const spamhausDropCidrs: string[] = [];
let isInitialized = false;
let refreshTimer: NodeJS.Timeout | null = null;

// Built-in seed of active Spamhaus DROP bulletproof / hijacked netblocks for instant cold-start protection
const SEED_DROP_CIDRS = [
  '185.220.101.0/24',
  '185.220.102.0/24',
  '194.26.29.0/24',
  '185.143.220.0/22',
  '45.148.10.0/24',
  '45.154.255.0/24',
  '193.109.69.0/24',
  '185.246.128.0/24',
  '194.38.20.0/24',
  '193.189.100.0/24',
  '91.240.118.0/24',
  '185.228.168.0/24',
  '194.32.104.0/24',
  '185.191.207.0/24'
];

/**
 * Parses Spamhaus standard text file format (e.g., "192.0.2.0/24 ; SBL123456").
 */
function parseSpamhausDropFile(content: string): string[] {
  const result: string[] = [];
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(';') || trimmed.startsWith('#')) continue;
    const cidr = trimmed.split(';')[0].trim();
    if (cidr && (cidr.includes('/') || cidr.includes('.'))) {
      result.push(cidr);
    }
  }
  return result;
}

function loadLocalFallback() {
  try {
    if (fs.existsSync(LOCAL_SPAMHAUS_FILE)) {
      const content = fs.readFileSync(LOCAL_SPAMHAUS_FILE, 'utf8');
      const lines = parseSpamhausDropFile(content);
      if (lines.length > 0) {
        spamhausDropCidrs.length = 0;
        spamhausDropCidrs.push(...lines);
        return;
      }
    }
  } catch (err: any) {
    console.warn('[SpamhausDrop] Error reading local DROP cache:', err?.message);
  }

  spamhausDropCidrs.length = 0;
  spamhausDropCidrs.push(...SEED_DROP_CIDRS);
}

/**
 * Fetches the latest DROP, EDROP, and DROPv6 feeds from Spamhaus.org.
 */
export async function refreshSpamhausDrop(): Promise<void> {
  const collectedCidrs = new Set<string>();

  const urls = [DROP_URL, EDROP_URL, DROP_V6_URL];
  for (const url of urls) {
    try {
      const res = await axios.get(url, {
        timeout: 10000,
        headers: { 'User-Agent': 'TraceXMail-SOC-Forensics/2.5' }
      });
      if (res.data && typeof res.data === 'string') {
        const parsed = parseSpamhausDropFile(res.data);
        for (const cidr of parsed) {
          collectedCidrs.add(cidr);
        }
      }
    } catch (err: any) {
      console.warn(`[SpamhausDrop] Fetch failed for ${url}:`, err?.message);
    }
  }

  if (collectedCidrs.size > 0) {
    spamhausDropCidrs.length = 0;
    spamhausDropCidrs.push(...Array.from(collectedCidrs));

    try {
      const dir = path.dirname(LOCAL_SPAMHAUS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(LOCAL_SPAMHAUS_FILE, spamhausDropCidrs.join('\n'), 'utf8');
    } catch {}

    console.log(`[SpamhausDrop] Synced ${spamhausDropCidrs.length} active Spamhaus DROP/EDROP botnet netblocks.`);
  } else if (spamhausDropCidrs.length === 0) {
    loadLocalFallback();
  }
}

/**
 * Initializes Spamhaus DROP service.
 */
export async function initSpamhausDrop(): Promise<void> {
  if (isInitialized) return;
  isInitialized = true;

  loadLocalFallback();
  refreshSpamhausDrop().catch(() => {});

  if (!refreshTimer) {
    refreshTimer = setInterval(() => {
      refreshSpamhausDrop().catch(() => {});
    }, REFRESH_INTERVAL_MS);
    if (refreshTimer.unref) refreshTimer.unref();
  }
}

// Auto-initialize on import
initSpamhausDrop().catch(() => {});

/**
 * Checks if the target IP address falls within a verified Spamhaus DROP / EDROP netblock.
 */
export function isSpamhausListed(ip: string): boolean {
  if (!ip) return false;
  const cleanIp = ip.trim();

  for (let i = 0; i < spamhausDropCidrs.length; i++) {
    const cidr = spamhausDropCidrs[i];
    if (isIpInCidr(cleanIp, cidr)) {
      return true;
    }
  }

  return false;
}
