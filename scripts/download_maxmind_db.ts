/**
 * MaxMind GeoLite2 Automated Database Downloader
 * Downloads official GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind
 * using MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY.
 *
 * Signup for a free license key at: https://www.maxmind.com/en/geolite2/signup
 */

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import axios from 'axios';
import 'dotenv/config';

export interface DownloadResult {
  edition: string;
  success: boolean;
  filePath?: string;
  sizeBytes?: number;
  error?: string;
}

/**
 * Extracts a specific file by filename suffix from an in-memory uncompressed TAR buffer.
 */
export function extractFileFromTar(tarBuffer: Buffer, targetFileNameSuffix: string): { fileName: string; data: Buffer } | null {
  let offset = 0;
  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);
    // Check for double null block (end of tar archive)
    if (header.every(b => b === 0)) break;

    // File name: bytes 0-100
    let name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/g, '').trim();
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/g, '').trim();
    if (prefix) {
      name = `${prefix}/${name}`;
    }

    // Size: bytes 124-136 in octal
    const sizeStr = header.subarray(124, 136).toString('utf8').replace(/\0.*$/g, '').trim();
    const size = parseInt(sizeStr, 8);

    offset += 512;
    if (isNaN(size) || size < 0) {
      break;
    }

    if (name.endsWith(targetFileNameSuffix) || name.endsWith(`/${targetFileNameSuffix}`)) {
      const data = tarBuffer.subarray(offset, offset + size);
      return { fileName: name, data: Buffer.from(data) };
    }

    // Data in tar is 512-byte aligned
    const paddedSize = Math.ceil(size / 512) * 512;
    offset += paddedSize;
  }
  return null;
}

/**
 * Downloads and extracts a single GeoLite2 database edition (.tar.gz -> .mmdb).
 */
export async function downloadEdition(edition: 'GeoLite2-City' | 'GeoLite2-ASN', outputDir: string, licenseKey: string, accountId?: string): Promise<DownloadResult> {
  const targetMmdbName = `${edition}.mmdb`;
  const destPath = path.join(outputDir, targetMmdbName);

  console.log(`[MaxMind Setup] Requesting ${edition} from official MaxMind distribution endpoint...`);

  const primaryUrl = `https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${encodeURIComponent(licenseKey)}&suffix=tar.gz`;
  const altUrl = `https://download.maxmind.com/geoip/databases/${edition}/download?suffix=tar.gz`;

  let archiveBuffer: Buffer | null = null;
  let lastError: string | null = null;

  // Try primary download URL
  try {
    const res = await axios.get(primaryUrl, {
      responseType: 'arraybuffer',
      timeout: 30000,
      headers: {
        'User-Agent': 'TraceXMail-Forensics-Setup/1.0'
      }
    });
    archiveBuffer = Buffer.from(res.data);
  } catch (err: any) {
    lastError = err?.response?.data ? String(err.response.data) : (err?.message || String(err));
    // Try alt URL with Basic Auth if Account ID is present
    if (accountId) {
      try {
        console.log(`[MaxMind Setup] Trying authenticated API endpoint for ${edition}...`);
        const altRes = await axios.get(altUrl, {
          auth: {
            username: accountId,
            password: licenseKey
          },
          responseType: 'arraybuffer',
          timeout: 30000,
          headers: {
            'User-Agent': 'TraceXMail-Forensics-Setup/1.0'
          }
        });
        archiveBuffer = Buffer.from(altRes.data);
        lastError = null;
      } catch (altErr: any) {
        lastError = altErr?.response?.data ? String(altErr.response.data) : (altErr?.message || String(altErr));
      }
    }
  }

  if (!archiveBuffer || archiveBuffer.length === 0) {
    return {
      edition,
      success: false,
      error: `Failed to download archive: ${lastError || 'Empty response'}`
    };
  }

  try {
    // 1. Decompress GZIP
    const unzipped = zlib.gunzipSync(archiveBuffer);

    // 2. Extract .mmdb from TAR
    const extracted = extractFileFromTar(unzipped, `${edition}.mmdb`);
    if (!extracted) {
      return {
        edition,
        success: false,
        error: `Could not locate ${edition}.mmdb within downloaded archive payload`
      };
    }

    // 3. Write to destination file
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(destPath, extracted.data);
    const stat = fs.statSync(destPath);

    console.log(`✅ [MaxMind Setup] Successfully extracted and saved ${targetMmdbName} (${(stat.size / (1024 * 1024)).toFixed(2)} MB) to ${destPath}`);

    return {
      edition,
      success: true,
      filePath: destPath,
      sizeBytes: stat.size
    };
  } catch (extractErr: any) {
    return {
      edition,
      success: false,
      error: `Decompression/Extraction failed: ${extractErr?.message || String(extractErr)}`
    };
  }
}

/**
 * Main database download and verification pipeline.
 */
export async function downloadMaxMindDatabases(): Promise<{ city: DownloadResult; asn: DownloadResult }> {
  const licenseKey = process.env.MAXMIND_LICENSE_KEY?.trim();
  const accountId = process.env.MAXMIND_ACCOUNT_ID?.trim();
  const outputDir = path.join(process.cwd(), 'data', 'maxmind');

  console.log('================================================================');
  console.log('TraceXMail MaxMind GeoLite2 Automated Pipeline Setup');
  console.log('================================================================');

  if (!licenseKey) {
    console.warn('\n⚠️ [MaxMind Setup WARNING] MAXMIND_LICENSE_KEY is not configured in .env!');
    console.warn('----------------------------------------------------------------');
    console.warn('To enable binary sub-millisecond local GeoLite2 resolution:');
    console.warn('1. Sign up for a free MaxMind account at:');
    console.warn('   https://www.maxmind.com/en/geolite2/signup');
    console.warn('2. Generate a free license key under "My Account > Manage License Keys"');
    console.warn('3. Add to your .env file:');
    console.warn('   MAXMIND_ACCOUNT_ID=your_account_id');
    console.warn('   MAXMIND_LICENSE_KEY=your_license_key');
    console.warn('4. Re-run: npm run setup:maxmind\n');
    console.warn('ℹ️ TraceXMail is operating gracefully with the live fallback chain:');
    console.warn('   ip-api.com -> ipwho.is -> ipgeolocation.io\n');

    return {
      city: { edition: 'GeoLite2-City', success: false, error: 'MAXMIND_LICENSE_KEY not configured' },
      asn: { edition: 'GeoLite2-ASN', success: false, error: 'MAXMIND_LICENSE_KEY not configured' }
    };
  }

  const cityResult = await downloadEdition('GeoLite2-City', outputDir, licenseKey, accountId);
  const asnResult = await downloadEdition('GeoLite2-ASN', outputDir, licenseKey, accountId);

  return { city: cityResult, asn: asnResult };
}

// Auto-run if executed directly
if (process.argv[1] && (process.argv[1].endsWith('download_maxmind_db.ts') || process.argv[1].endsWith('download_maxmind_db.js'))) {
  downloadMaxMindDatabases()
    .then(results => {
      if (results.city.success && results.asn.success) {
        console.log('\n✨ MaxMind GeoLite2 databases successfully downloaded and ready for offline use.');
        process.exit(0);
      } else {
        console.log('\n⚠️ MaxMind download completed with warnings. Live API fallback chain will remain active.');
        process.exit(0);
      }
    })
    .catch(err => {
      console.error('[MaxMind Setup Error]', err);
      process.exit(0); // non-zero exit would break CI if keys aren't provisioned yet
    });
}
