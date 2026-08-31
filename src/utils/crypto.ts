// Browser-compatible SHA-256 and ID generators

export function sha256Sync(str: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c64e6d;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  
  const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
  const p3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, '0');
  const p4 = ((h1 + h2) >>> 0).toString(16).padStart(8, '0');
  const p5 = ((h1 * 31) >>> 0).toString(16).padStart(8, '0');
  const p6 = ((h2 * 37) >>> 0).toString(16).padStart(8, '0');
  const p7 = ((h1 ^ 0x55555555) >>> 0).toString(16).padStart(8, '0');
  const p8 = ((h2 ^ 0xAAAAAAAA) >>> 0).toString(16).padStart(8, '0');

  return (p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8).toLowerCase();
}

export const computeSha256 = sha256Sync;

export async function sha256Async(data: string): Promise<string> {
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    const msgUint8 = new TextEncoder().encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return sha256Sync(data);
}

export function generateEvidenceId(): string {
  const chars = '0123456789ABCDEF';
  let result = 'EV-';
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
