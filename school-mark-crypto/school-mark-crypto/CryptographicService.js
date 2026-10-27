const crypto = require('crypto');

class CryptographicService {
  constructor() {
    // Master keys derived securely in production via KMS or Environment Secrets
    this.aesKey = crypto.scryptSync(process.env.AES_SECRET || 'aes-master-key', 'salt', 32);
    this.desKey = crypto.scryptSync(process.env.DES_SECRET || 'des-master-key', 'salt', 8); // DES requires an 8-byte key
    this.rc4Key = crypto.scryptSync(process.env.RC4_SECRET || 'rc4-master-key', 'salt', 16);
  }

  // ----------------------------------------------------
  // Tier 1: High Sensitivity (PII, National IDs, Grades)
  // Cipher: AES-256-CBC with unique per-record IV (Non-ECB)
  // ----------------------------------------------------
  encryptTier1(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), data: encrypted, cipher: 'AES-256-CBC' };
  }

  decryptTier1(encryptedData, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // ----------------------------------------------------
  // Tier 2: Moderate Sensitivity (Internal Office Documents, Logs)
  // Cipher: DES-CBC with unique per-record IV (Non-ECB)
  // ----------------------------------------------------
  encryptTier2(text) {
    const iv = crypto.randomBytes(8); // DES block size is 8 bytes
    const cipher = crypto.createCipheriv('des-cbc', this.desKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), data: encrypted, cipher: 'DES-CBC' };
  }

  decryptTier2(encryptedData, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('des-cbc', this.desKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // ----------------------------------------------------
  // Tier 3: Low Sensitivity / High Volume (Video Logs, Telemetry)
  // Cipher: RC4 Stream Cipher (Updated for Node.js v17+ via createCipheriv)
  // ----------------------------------------------------
  encryptTier3(streamData) {
    const cipher = crypto.createCipheriv('rc4', this.rc4Key, '');
    let encrypted = cipher.update(streamData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { data: encrypted, cipher: 'RC4' };
  }

  decryptTier3(encryptedData) {
    const decipher = crypto.createDecipheriv('rc4', this.rc4Key, '');
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
}

module.exports = CryptographicService;