// crypto-engine.js - Cryptographic Integrity & BSA Section 63 Engine
const crypto = require('node:crypto');

function calculateSha256(bufferOrString) {
  const hash = crypto.createHash('sha256');
  hash.update(bufferOrString);
  return hash.digest('hex');
}

function calculateFileSha256(buffer) {
  return calculateSha256(buffer);
}

function generateLedgerHash(previousHash, exhibitId, caseId, eventType, timestamp, toPerson, sealCondition, actorId) {
  const payload = [
    previousHash || 'GENESIS_BLOCK_PRAMAAN_2026',
    exhibitId,
    caseId,
    eventType,
    timestamp,
    toPerson,
    sealCondition,
    actorId
  ].join('||');
  return calculateSha256(payload);
}

function verifyChainIntegrity(ledgerEntries) {
  if (!ledgerEntries || ledgerEntries.length === 0) {
    return { valid: true, count: 0, brokenAt: null };
  }

  for (let i = 0; i < ledgerEntries.length; i++) {
    const entry = ledgerEntries[i];
    const prevHash = i === 0 ? 'GENESIS_BLOCK_PRAMAAN_2026' : ledgerEntries[i - 1].ledger_hash;

    if (entry.previous_ledger_hash !== prevHash) {
      return {
        valid: false,
        count: ledgerEntries.length,
        brokenAt: entry.id,
        reason: `Previous hash mismatch at step ${i + 1}`
      };
    }

    const expectedHash = generateLedgerHash(
      entry.previous_ledger_hash,
      entry.exhibit_id,
      entry.case_id,
      entry.event_type,
      entry.timestamp,
      entry.to_person_name,
      entry.seal_condition,
      entry.actor_id
    );

    if (entry.ledger_hash !== expectedHash) {
      return {
        valid: false,
        count: ledgerEntries.length,
        brokenAt: entry.id,
        reason: `Hash signature corrupted at step ${i + 1}`
      };
    }
  }

  return { valid: true, count: ledgerEntries.length, brokenAt: null };
}

function generateCertificateVerificationToken(caseId, masterHash, timestamp) {
  const secretKey = 'PRAMAAN_BSA_STATE_FORENSIC_AUTHORITY_KEY';
  return crypto
    .createHmac('sha256', secretKey)
    .update(`${caseId}:${masterHash}:${timestamp}`)
    .digest('hex')
    .slice(0, 32);
}

module.exports = {
  calculateSha256,
  calculateFileSha256,
  generateLedgerHash,
  verifyChainIntegrity,
  generateCertificateVerificationToken
};
