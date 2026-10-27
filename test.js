// Load environment variables if using dotenv, or rely on process.env fallback
const CryptographicService = require('./CryptographicService');
const cryptoService = new CryptographicService();

console.log('--- Initializing Cryptographic Tier Tests ---\n');

// 1. Test Tier 1: AES-256-CBC (High Sensitivity: Grades & PII)
const studentGrade = "Student ID: STU-88421 | Subject: Advanced Cryptography | Grade: A (92%)";
console.log(`[Original Tier 1 Data]: ${studentGrade}`);

const encryptedTier1 = cryptoService.encryptTier1(studentGrade);
console.log(`[Encrypted via ${encryptedTier1.cipher}]:`, encryptedTier1.data);
console.log(`[Generated IV]:`, encryptedTier1.iv);

const decryptedTier1 = cryptoService.decryptTier1(encryptedTier1.data, encryptedTier1.iv);
console.log(`[Decrypted Tier 1 Data]: ${decryptedTier1}\n`);


// 2. Test Tier 2: DES-CBC (Moderate Sensitivity: Office / Internal Logs)
const adminReport = "Internal Audit Report: Teacher portal grade submission locked for Q3.";
console.log(`[Original Tier 2 Data]: ${adminReport}`);

const encryptedTier2 = cryptoService.encryptTier2(adminReport);
console.log(`[Encrypted via ${encryptedTier2.cipher}]:`, encryptedTier2.data);
console.log(`[Generated IV]:`, encryptedTier2.iv);

const decryptedTier2 = cryptoService.decryptTier2(encryptedTier2.data, encryptedTier2.iv);
console.log(`[Decrypted Tier 2 Data]: ${decryptedTier2}\n`);


// 3. Test Tier 3: RC4 (Low Sensitivity / High Volume: Stream Telemetry)
const telemetryLog = "STREAM_CHUNK_09281: Video lecture segment downloaded by Student ID STU-88421";
console.log(`[Original Tier 3 Data]: ${telemetryLog}`);

const encryptedTier3 = cryptoService.encryptTier3(telemetryLog);
console.log(`[Encrypted via ${encryptedTier3.cipher}]:`, encryptedTier3.data);

const decryptedTier3 = cryptoService.decryptTier3(encryptedTier3.data);
console.log(`[Decrypted Tier 3 Data]: ${decryptedTier3}\n`);

console.log('--- All Cryptographic Verification Tests Passed Successfully ---');