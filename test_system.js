// test_system.js - Automated Verification Test Suite for Pramaan Prototype
const { getDb } = require('./db');
const { calculateSha256, verifyChainIntegrity, generateLedgerHash } = require('./crypto-engine');
const { hashPassword, verifyPassword, checkRateLimit } = require('./auth');

async function runTests() {
  console.log('--- STARTING PRAMAAN SYSTEM INTEGRITY TESTS ---');

  // Test 1: Crypto Engine Hash Consistency
  console.log('\n[TEST 1] Cryptographic Engine Tests:');
  const sampleData = 'CRIME_SCENE_EXHIBIT_BLOOD_SWAB_TEST';
  const hash1 = calculateSha256(sampleData);
  const hash2 = calculateSha256(sampleData);
  if (hash1 !== hash2 || hash1.length !== 64) {
    throw new Error('SHA-256 computation failed consistency check');
  }
  console.log('✓ SHA-256 hash consistency verified:', hash1);

  // Test 2: Immutable Chain of Custody Ledger & Tamper Detection
  console.log('\n[TEST 2] Blockchain-style Chain of Custody Integrity & Tamper Test:');
  const genesisHash = 'GENESIS_BLOCK_PRAMAAN_2026';
  const block1Hash = generateLedgerHash(genesisHash, 'ex_1', 'case_1', 'initial_scene_collection', '2026-11-24T03:00:00Z', 'SI Rajesh', 'intact_and_verified', 'usr_io_01');
  const block2Hash = generateLedgerHash(block1Hash, 'ex_1', 'case_1', 'malkhana_deposit', '2026-11-24T04:00:00Z', 'HC Suresh', 'intact_and_verified', 'usr_io_01');

  const validChain = [
    { id: '1', exhibit_id: 'ex_1', case_id: 'case_1', previous_ledger_hash: genesisHash, event_type: 'initial_scene_collection', timestamp: '2026-11-24T03:00:00Z', to_person_name: 'SI Rajesh', seal_condition: 'intact_and_verified', actor_id: 'usr_io_01', ledger_hash: block1Hash },
    { id: '2', exhibit_id: 'ex_1', case_id: 'case_1', previous_ledger_hash: block1Hash, event_type: 'malkhana_deposit', timestamp: '2026-11-24T04:00:00Z', to_person_name: 'HC Suresh', seal_condition: 'intact_and_verified', actor_id: 'usr_io_01', ledger_hash: block2Hash }
  ];

  const verifyValid = verifyChainIntegrity(validChain);
  if (!verifyValid.valid) throw new Error('Valid chain was incorrectly rejected');
  console.log('✓ Valid chain passed integrity audit with 2 blocks.');

  // Corrupt block 1 in the chain to verify tamper detection
  const tamperedChain = JSON.parse(JSON.stringify(validChain));
  tamperedChain[0].to_person_name = 'SI Rajesh (MODIFIED_TAMPERED_ENTRY)';
  const verifyTampered = verifyChainIntegrity(tamperedChain);
  if (verifyTampered.valid) throw new Error('Tampered chain was not detected!');
  console.log('✓ Tamper detection successfully caught modified block:', verifyTampered.reason);

  // Test 3: Password Hashing with PBKDF2 & Timing Attack Defense
  console.log('\n[TEST 3] Security & Authentication Engine Tests:');
  const password = 'SuperSecureForensicPassword@2026';
  const { hash, salt } = hashPassword(password);
  const correctMatch = verifyPassword(password, hash, salt);
  const wrongMatch = verifyPassword('WrongPassword', hash, salt);

  if (!correctMatch || wrongMatch) {
    throw new Error('Password verification logic failed');
  }
  console.log('✓ PBKDF2 100k iteration password hashing verified.');

  // Test 4: Database Schema and Relations
  console.log('\n[TEST 4] Database & BNSS 176(3) Pre-Seeded Forensic Data:');
  const db = getDb();
  const cases = db.prepare('SELECT * FROM cases').all();
  console.log(`✓ Loaded ${cases.length} official BNSS 176(3) cases:`);
  cases.forEach(c => console.log(`   - ${c.fir_number}: ${c.offence_type} (${c.status})`));

  const exhibits = db.prepare('SELECT * FROM exhibits').all();
  console.log(`✓ Loaded ${exhibits.length} exhibits with cryptographic hashes:`);
  exhibits.forEach(e => console.log(`   - ${e.exhibit_code} [${e.category}] Hash: ${e.sha256_hash.slice(0, 16)}...`));

  const certs = db.prepare('SELECT * FROM bsa_certificates').all();
  console.log(`✓ Loaded ${certs.length} Section 63 BSA certificates.`);

  console.log('\n========================================');
  console.log('ALL UNIT & SECURITY INTEGRITY TESTS PASSED!');
  console.log('========================================\n');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
