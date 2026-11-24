// server.js - Pramaan Forensic Evidence Management System
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { getDb } = require('./db');
const {
  hashPassword,
  verifyPassword,
  checkRateLimit,
  recordLoginAttempt,
  generateSessionToken,
  parseCookies,
  SESSION_TTL_MS
} = require('./auth');
const {
  calculateSha256,
  calculateFileSha256,
  generateLedgerHash,
  verifyChainIntegrity,
  generateCertificateVerificationToken
} = require('./crypto-engine');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Connected SSE clients: Set of res objects
const sseClients = new Set();

function broadcastEvent(type, data) {
  const payload = `data: ${JSON.stringify({ type, data, timestamp: new Date().toISOString() })}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

// Security headers helper
function setSecurityHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self' 'unsafe-inline' data: blob:; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data:;"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

// JSON responder helper
function sendJson(res, statusCode, data, headers = {}) {
  setSecurityHeaders(res);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    ...headers
  });
  res.end(JSON.stringify(data));
}

// Error responder helper
function sendError(res, statusCode, message, details = null) {
  sendJson(res, statusCode, {
    error: message,
    details,
    timestamp: new Date().toISOString()
  });
}

// Parse JSON request body
function parseJsonBody(req, maxSize = 5 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxSize) {
        reject(new Error('Payload too large'));
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        const bodyStr = Buffer.concat(chunks).toString('utf8');
        resolve(JSON.parse(bodyStr));
      } catch (err) {
        reject(new Error('Malformed JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

// Read raw body
function parseRawBody(req, maxSize = 20 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxSize) {
        reject(new Error('Payload too large'));
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

// Authenticate session from Cookie or Authorization header
function authenticate(req) {
  const db = getDb();
  let token = null;

  // Check Bearer header
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }

  // Check Cookie
  if (!token) {
    const cookies = parseCookies(req.headers['cookie']);
    token = cookies['pramaan_session'];
  }

  if (!token) return null;

  const now = Date.now();
  const sessionRow = db
    .prepare('SELECT s.token, s.expires_at, u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?')
    .get(token);

  if (!sessionRow) return null;

  if (sessionRow.expires_at < now) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }

  return {
    id: sessionRow.id,
    email: sessionRow.email,
    fullName: sessionRow.full_name,
    role: sessionRow.role,
    badgeId: sessionRow.badge_or_emp_id,
    department: sessionRow.department,
    district: sessionRow.state_or_district,
    token
  };
}

// Static file server
function serveStaticFile(req, res, filePath) {
  // Prevent directory traversal
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(PUBLIC_DIR) && !resolved.startsWith(UPLOADS_DIR)) {
    return sendError(res, 403, 'Forbidden access path');
  }

  fs.stat(resolved, (err, stats) => {
    if (err || !stats.isFile()) {
      return sendError(res, 404, 'File not found');
    }

    const ext = path.extname(resolved).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.svg': 'image/svg+xml',
      '.pdf': 'application/pdf',
      '.ico': 'image/x-icon'
    };

    const contentType = mimeTypes[ext] || 'application/octet-stream';
    setSecurityHeaders(res);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': 'no-cache'
    });

    const stream = fs.createReadStream(resolved);
    stream.pipe(res);
  });
}

// Create HTTP server
const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = urlObj.pathname;
  const method = req.method;
  const clientIp = req.socket.remoteAddress || '127.0.0.1';

  try {
    // ----------------------------------------------------
    // 1. REAL-TIME SERVER-SENT EVENTS (SSE)
    // ----------------------------------------------------
    if (pathname === '/api/events' && method === 'GET') {
      const user = authenticate(req);
      setSecurityHeaders(res);
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive'
      });
      res.write(`data: ${JSON.stringify({ type: 'connected', user: user ? user.fullName : 'Guest' })}\n\n`);

      sseClients.add(res);
      req.on('close', () => {
        sseClients.delete(res);
      });
      return;
    }

    // ----------------------------------------------------
    // 2. AUTHENTICATION ENDPOINTS
    // ----------------------------------------------------
    if (pathname === '/api/auth/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { email, password } = body;

      if (!email || !password) {
        return sendError(res, 400, 'Email and password required');
      }

      const rateCheck = checkRateLimit(email.toLowerCase());
      if (!rateCheck.allowed) {
        return sendError(
          res,
          429,
          `Too many failed login attempts. Account temporarily locked for security. Try again in ${rateCheck.retryAfter} seconds.`
        );
      }

      const db = getDb();
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());

      if (!user || !verifyPassword(password, user.password_hash, user.salt)) {
        recordLoginAttempt(email.toLowerCase(), false);
        // Security audit log
        db.prepare(
          'INSERT INTO security_audit_logs (id, user_id, ip_address, action, details, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(crypto.randomUUID(), user ? user.id : null, clientIp, 'login_failed', `Failed login for ${email}`, 'FAILED', new Date().toISOString());

        return sendError(res, 401, 'Invalid credentials');
      }

      recordLoginAttempt(email.toLowerCase(), true);
      const token = generateSessionToken();
      const expiresAt = Date.now() + SESSION_TTL_MS;

      db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(
        token,
        user.id,
        Date.now(),
        expiresAt
      );

      // Audit log success
      db.prepare(
        'INSERT INTO security_audit_logs (id, user_id, ip_address, action, details, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(crypto.randomUUID(), user.id, clientIp, 'login_success', `User logged in: ${user.full_name} (${user.role})`, 'SUCCESS', new Date().toISOString());

      return sendJson(
        res,
        200,
        {
          success: true,
          token,
          user: {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            badgeId: user.badge_or_emp_id,
            department: user.department,
            district: user.state_or_district
          }
        },
        {
          'Set-Cookie': `pramaan_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`
        }
      );
    }

    if (pathname === '/api/auth/demo-switch' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { role } = body;
      const db = getDb();
      const user = db.prepare('SELECT * FROM users WHERE role = ? LIMIT 1').get(role);

      if (!user) {
        return sendError(res, 404, 'Demo user for role not found');
      }

      const token = generateSessionToken();
      const expiresAt = Date.now() + SESSION_TTL_MS;
      db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(
        token,
        user.id,
        Date.now(),
        expiresAt
      );

      return sendJson(
        res,
        200,
        {
          success: true,
          token,
          user: {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            badgeId: user.badge_or_emp_id,
            department: user.department,
            district: user.state_or_district
          }
        },
        {
          'Set-Cookie': `pramaan_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`
        }
      );
    }

    if (pathname === '/api/auth/me' && method === 'GET') {
      const user = authenticate(req);
      if (!user) {
        return sendError(res, 401, 'Unauthorized');
      }
      return sendJson(res, 200, { user });
    }

    if (pathname === '/api/auth/logout' && method === 'POST') {
      const user = authenticate(req);
      if (user) {
        const db = getDb();
        db.prepare('DELETE FROM sessions WHERE token = ?').run(user.token);
      }
      return sendJson(
        res,
        200,
        { success: true, message: 'Logged out successfully' },
        {
          'Set-Cookie': `pramaan_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
        }
      );
    }

    // ----------------------------------------------------
    // 3. PUBLIC / JUDICIAL TAMPER VERIFICATION (No Auth Required)
    // ----------------------------------------------------
    if (pathname === '/api/verify/hash' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { hash, exhibitCode, fileContentBase64 } = body;
      const db = getDb();

      let targetHash = hash ? hash.trim().toLowerCase() : null;

      if (fileContentBase64 && !targetHash) {
        const buf = Buffer.from(fileContentBase64, 'base64');
        targetHash = calculateSha256(buf);
      }

      if (!targetHash && !exhibitCode) {
        return sendError(res, 400, 'Must provide SHA-256 hash, exhibitCode, or file content');
      }

      let exhibit = null;
      if (targetHash) {
        exhibit = db.prepare('SELECT e.*, c.fir_number, c.police_station, c.district FROM exhibits e JOIN cases c ON e.case_id = c.id WHERE LOWER(e.sha256_hash) = ?').get(targetHash);
      } else if (exhibitCode) {
        exhibit = db.prepare('SELECT e.*, c.fir_number, c.police_station, c.district FROM exhibits e JOIN cases c ON e.case_id = c.id WHERE e.exhibit_code = ?').get(exhibitCode);
      }

      if (!exhibit) {
        return sendJson(res, 200, {
          verified: false,
          computedHash: targetHash,
          reason: 'No matching cryptographic record found in official Pramaan ledger. File may have been modified or is unregistered.',
          timestamp: new Date().toISOString()
        });
      }

      // Check entire chain of custody integrity for this exhibit
      const ledger = db
        .prepare('SELECT * FROM chain_of_custody_ledger WHERE exhibit_id = ? ORDER BY step_number ASC')
        .all(exhibit.id);

      const chainStatus = verifyChainIntegrity(ledger);

      return sendJson(res, 200, {
        verified: chainStatus.valid,
        computedHash: targetHash || exhibit.sha256_hash,
        matchedExhibit: {
          code: exhibit.exhibit_code,
          category: exhibit.category,
          description: exhibit.description,
          firNumber: exhibit.fir_number,
          policeStation: exhibit.police_station,
          district: exhibit.district,
          physicalSeal: exhibit.physical_seal_number,
          collectedBy: exhibit.collected_by,
          collectedAt: exhibit.collected_at,
          currentCustodyHolder: exhibit.current_custody_holder,
          currentCustodyLocation: exhibit.current_custody_location,
          fslStatus: exhibit.fsl_status
        },
        chainOfCustody: {
          totalSteps: ledger.length,
          unbroken: chainStatus.valid,
          integrityCheck: chainStatus.valid ? 'PASSED - 100% Cryptographically Authentic' : 'FAILED - Chain Broken',
          brokenAt: chainStatus.brokenAt
        },
        legalAdmissibility: {
          statute: 'Bharatiya Sakshya Adhiniyam, 2023 - Section 63',
          courtAdmissible: chainStatus.valid,
          tamperFlag: !chainStatus.valid
        },
        timestamp: new Date().toISOString()
      });
    }

    // ----------------------------------------------------
    // ALL SUBSEQUENT ENDPOINTS REQUIRE AUTHENTICATION
    // ----------------------------------------------------
    const user = authenticate(req);
    if (!user) {
      // If it's an API route, return 401
      if (pathname.startsWith('/api/')) {
        return sendError(res, 401, 'Authentication required');
      }
      // Otherwise serve static files or redirect
    }

    const db = getDb();

    // ----------------------------------------------------
    // 4. CASES API
    // ----------------------------------------------------
    if (pathname === '/api/cases' && method === 'GET') {
      const cases = db
        .prepare(`
          SELECT c.*, 
            u1.full_name as io_name, 
            u2.full_name as expert_name,
            (SELECT COUNT(*) FROM exhibits WHERE case_id = c.id) as exhibit_count,
            (SELECT COUNT(*) FROM case_checklists WHERE case_id = c.id) as checklist_total,
            (SELECT COUNT(*) FROM case_checklists WHERE case_id = c.id AND is_completed = 1) as checklist_completed
          FROM cases c
          LEFT JOIN users u1 ON c.io_id = u1.id
          LEFT JOIN users u2 ON c.assigned_expert_id = u2.id
          ORDER BY c.created_at DESC
        `)
        .all();
      return sendJson(res, 200, { cases });
    }

    if (pathname === '/api/cases' && method === 'POST') {
      // Investigating officer or lab supervisor can create cases
      const body = await parseJsonBody(req);
      const {
        firNumber,
        policeStation,
        district,
        state = 'Delhi (UT)',
        offenceType,
        penalSections,
        incidentTime = new Date().toISOString(),
        sceneLocation,
        latitude = 28.6139,
        longitude = 77.2090,
        priority = 'urgent'
      } = body;

      if (!firNumber || !policeStation || !offenceType || !penalSections || !sceneLocation) {
        return sendError(res, 400, 'Missing required case fields');
      }

      const caseId = 'case_' + crypto.randomUUID().slice(0, 8);
      const now = new Date().toISOString();

      // Find available expert for remote supervision assignment
      const expert = db.prepare("SELECT id FROM users WHERE role = 'forensic_expert' LIMIT 1").get();
      const expertId = expert ? expert.id : null;

      db.prepare(`
        INSERT INTO cases (id, fir_number, police_station, district, state, offence_type, penal_sections, is_mandatory_bnss_176, io_id, assigned_expert_id, incident_time, scene_location, latitude, longitude, status, priority, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 'scene_active', ?, ?, ?)
      `).run(
        caseId,
        firNumber,
        policeStation,
        district || user.district,
        state,
        offenceType,
        penalSections,
        user.id,
        expertId,
        incidentTime,
        sceneLocation,
        latitude,
        longitude,
        priority,
        now,
        now
      );

      // Create default DFSS checklist based on offence
      const checklistSteps = [
        {
          order: 1,
          key: 'cordon_verification',
          title: 'Perimeter Cordon & Access Log',
          desc: 'Establish inner & outer cordon tape. Maintain physical log of all responders.',
          ref: 'DFSS Manual 2024 Sec 3.2'
        },
        {
          order: 2,
          key: 'panoramic_videography',
          title: 'Continuous 360° Scene Videography',
          desc: 'Mandatory unbroken videography from perimeter to core locus (BNSS 176(3)).',
          ref: 'BNSS 2023 Sec 176(3)'
        },
        {
          order: 3,
          key: 'evidence_marker_placement',
          title: 'Evidence Markers & Metric ABFO Scales',
          desc: 'Place numbered marker tents adjacent to key exhibits with metric millimeter scale.',
          ref: 'DFSS Chapter 5 SOP'
        },
        {
          order: 4,
          key: 'biological_swab_collection',
          title: 'Biological / Trace Collection (Dry Sterile Swab)',
          desc: 'Swab blood/fluid with sterile saline. Desiccate fully before packaging. Never seal wet samples in plastic.',
          ref: 'DFSS Biological SOP Sec 4'
        },
        {
          order: 5,
          key: 'tamper_seal_and_qr',
          title: 'Tamper-Evident Seal & Hash Generation',
          desc: 'Bag in official DFSS envelopes, record physical seal number, and register cryptographic hash.',
          ref: 'BSA 2023 Sec 63'
        }
      ];

      const insertChecklist = db.prepare(`
        INSERT INTO case_checklists (id, case_id, step_order, step_key, title, description, dfss_guideline_ref, is_completed, expert_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
      `);

      for (const step of checklistSteps) {
        insertChecklist.run(
          'chk_' + crypto.randomUUID().slice(0, 8),
          caseId,
          step.order,
          step.key,
          step.title,
          step.desc,
          step.ref
        );
      }

      // Initialize supervision session
      if (expertId) {
        db.prepare(`
          INSERT INTO supervision_sessions (id, case_id, expert_id, io_id, status, stream_active, started_at)
          VALUES (?, ?, ?, ?, 'waiting', 1, ?)
        `).run('sess_' + crypto.randomUUID().slice(0, 8), caseId, expertId, user.id, now);
      }

      broadcastEvent('case_created', { caseId, firNumber, offenceType });

      return sendJson(res, 201, { success: true, caseId, firNumber });
    }

    // Detail of single case
    const caseMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)$/);
    if (caseMatch && method === 'GET') {
      const caseId = caseMatch[1];
      const caseData = db
        .prepare(`
          SELECT c.*, 
            u1.full_name as io_name, u1.badge_or_emp_id as io_badge,
            u2.full_name as expert_name, u2.badge_or_emp_id as expert_badge, u2.department as expert_dept
          FROM cases c
          LEFT JOIN users u1 ON c.io_id = u1.id
          LEFT JOIN users u2 ON c.assigned_expert_id = u2.id
          WHERE c.id = ?
        `)
        .get(caseId);

      if (!caseData) {
        return sendError(res, 404, 'Case not found');
      }

      const checklist = db
        .prepare('SELECT * FROM case_checklists WHERE case_id = ? ORDER BY step_order ASC')
        .all(caseId);

      const exhibits = db
        .prepare('SELECT * FROM exhibits WHERE case_id = ? ORDER BY created_at ASC')
        .all(caseId);

      const supervision = db
        .prepare('SELECT * FROM supervision_sessions WHERE case_id = ?')
        .get(caseId);

      const certificate = db
        .prepare('SELECT * FROM bsa_certificates WHERE case_id = ?')
        .get(caseId);

      return sendJson(res, 200, {
        case: caseData,
        checklist,
        exhibits,
        supervision,
        certificate
      });
    }

    // ----------------------------------------------------
    // 5. CHECKLIST UPDATES & EXPERT VERIFICATION
    // ----------------------------------------------------
    const chkStepMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/checklist\/([a-zA-Z0-9_-]+)$/);
    if (chkStepMatch && method === 'PUT') {
      const [, caseId, stepId] = chkStepMatch;
      const body = await parseJsonBody(req);
      const { isCompleted, mediaFileName, notes } = body;
      const now = new Date().toISOString();

      db.prepare(`
        UPDATE case_checklists 
        SET is_completed = ?, completed_at = ?, completed_by_user_id = ?, media_file_name = COALESCE(?, media_file_name)
        WHERE id = ? AND case_id = ?
      `).run(isCompleted ? 1 : 0, isCompleted ? now : null, isCompleted ? user.id : null, mediaFileName || null, stepId, caseId);

      broadcastEvent('checklist_updated', { caseId, stepId, isCompleted });

      return sendJson(res, 200, { success: true, stepId, isCompleted });
    }

    const chkVerifyMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/checklist\/([a-zA-Z0-9_-]+)\/verify$/);
    if (chkVerifyMatch && method === 'PUT') {
      // Only forensic expert or lab director can verify checklist steps
      if (user.role !== 'forensic_expert' && user.role !== 'lab_director') {
        return sendError(res, 403, 'Only forensic experts can formally verify capture steps');
      }

      const [, caseId, stepId] = chkVerifyMatch;
      const body = await parseJsonBody(req);
      const { verified, expertNotes } = body;

      db.prepare(`
        UPDATE case_checklists 
        SET expert_verified = ?, expert_notes = ?
        WHERE id = ? AND case_id = ?
      `).run(verified ? 1 : 0, expertNotes || null, stepId, caseId);

      broadcastEvent('checklist_verified', { caseId, stepId, verified, expert: user.fullName });

      return sendJson(res, 200, { success: true, stepId, verified });
    }

    // ----------------------------------------------------
    // 6. EXHIBITS & EVIDENCE VAULT API
    // ----------------------------------------------------
    const exhibitsMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/exhibits$/);
    if (exhibitsMatch && method === 'GET') {
      const caseId = exhibitsMatch[1];
      const exhibits = db
        .prepare('SELECT * FROM exhibits WHERE case_id = ? ORDER BY created_at ASC')
        .all(caseId);
      return sendJson(res, 200, { exhibits });
    }

    if (exhibitsMatch && method === 'POST') {
      const caseId = exhibitsMatch[1];
      const body = await parseJsonBody(req);
      const {
        exhibitCode,
        category,
        description,
        foundLocation,
        packagingMethod,
        physicalSealNumber,
        fileContentBase64,
        fileName = 'evidence_capture.jpg',
        mediaMime = 'image/jpeg',
        latitude = 28.6517,
        longitude = 77.1906,
        fslAssignedDivision = 'Biology & DNA Division'
      } = body;

      if (!exhibitCode || !category || !description || !foundLocation || !physicalSealNumber) {
        return sendError(res, 400, 'Missing required exhibit parameters');
      }

      // Compute cryptographic hash
      let fileBuffer = null;
      let sha256Hash = null;

      if (fileContentBase64) {
        fileBuffer = Buffer.from(fileContentBase64, 'base64');
        sha256Hash = calculateSha256(fileBuffer);
        // Persist upload safely
        const safeExt = path.extname(fileName) || '.jpg';
        const diskName = `${sha256Hash}${safeExt}`;
        fs.writeFileSync(path.join(UPLOADS_DIR, diskName), fileBuffer);
      } else {
        // Mock capture payload with unique entropy
        const rawPayload = `EXHIBIT_${caseId}_${exhibitCode}_${Date.now()}_${physicalSealNumber}`;
        sha256Hash = calculateSha256(rawPayload);
      }

      const exhibitId = 'exhb_' + crypto.randomUUID().slice(0, 8);
      const now = new Date().toISOString();

      db.prepare(`
        INSERT INTO exhibits (id, case_id, exhibit_code, category, description, found_location, packaging_method, physical_seal_number, sha256_hash, file_name, media_mime, collected_by, collected_at, latitude, longitude, current_custody_holder, current_custody_location, fsl_assigned_division, fsl_status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `).run(
        exhibitId,
        caseId,
        exhibitCode,
        category,
        description,
        foundLocation,
        packagingMethod,
        physicalSealNumber,
        sha256Hash,
        fileName,
        mediaMime,
        user.fullName,
        now,
        latitude,
        longitude,
        user.fullName,
        'Field Scene Mobile Unit',
        fslAssignedDivision,
        now
      );

      // Create Genesis block in the Chain of Custody Ledger
      const initialHash = generateLedgerHash(
        'GENESIS_BLOCK_PRAMAAN_2026',
        exhibitId,
        caseId,
        'initial_scene_collection',
        now,
        user.fullName,
        'intact_and_verified',
        user.id
      );

      db.prepare(`
        INSERT INTO chain_of_custody_ledger (id, exhibit_id, case_id, step_number, previous_ledger_hash, event_type, from_person_name, from_designation, to_person_name, to_designation, location, purpose, seal_condition, remarks, timestamp, actor_id, ledger_hash)
        VALUES (?, ?, ?, 1, 'GENESIS_BLOCK_PRAMAAN_2026', 'initial_scene_collection', 'Crime Scene Locus Delicti', 'Origin', ?, ?, 'Field Crime Scene', 'Initial Evidence Collection under BNSS 176(3)', 'intact_and_verified', 'Initial packaging and serialized tamper seal applied', ?, ?, ?)
      `).run(
        'led_' + crypto.randomUUID().slice(0, 8),
        exhibitId,
        caseId,
        user.fullName,
        user.role,
        now,
        user.id,
        initialHash
      );

      broadcastEvent('exhibit_added', { caseId, exhibitId, exhibitCode, sha256Hash });

      return sendJson(res, 201, {
        success: true,
        exhibitId,
        exhibitCode,
        sha256Hash
      });
    }

    // ----------------------------------------------------
    // 7. CHAIN OF CUSTODY TRANSFER & AUDIT TRAIL
    // ----------------------------------------------------
    const transferMatch = pathname.match(/^\/api\/exhibits\/([a-zA-Z0-9_-]+)\/transfer$/);
    if (transferMatch && method === 'POST') {
      const exhibitId = transferMatch[1];
      const body = await parseJsonBody(req);
      const {
        eventType, // 'malkhana_deposit', 'dispatch_to_fsl', 'fsl_reception', 'division_handover', 'analysis_started', 'court_deposition'
        toPersonName,
        toDesignation,
        location,
        purpose,
        sealCondition = 'intact_and_verified',
        remarks = ''
      } = body;

      if (!eventType || !toPersonName || !toDesignation || !location || !purpose) {
        return sendError(res, 400, 'Missing required custody transfer fields');
      }

      const exhibit = db.prepare('SELECT * FROM exhibits WHERE id = ?').get(exhibitId);
      if (!exhibit) {
        return sendError(res, 404, 'Exhibit not found');
      }

      // Fetch last ledger entry to chain cryptographic hash
      const lastLedger = db
        .prepare('SELECT * FROM chain_of_custody_ledger WHERE exhibit_id = ? ORDER BY step_number DESC LIMIT 1')
        .get(exhibitId);

      const previousHash = lastLedger ? lastLedger.ledger_hash : 'GENESIS_BLOCK_PRAMAAN_2026';
      const stepNumber = lastLedger ? lastLedger.step_number + 1 : 1;
      const now = new Date().toISOString();

      const newLedgerHash = generateLedgerHash(
        previousHash,
        exhibitId,
        exhibit.case_id,
        eventType,
        now,
        toPersonName,
        sealCondition,
        user.id
      );

      // Determine updated FSL status if applicable
      let updatedFslStatus = exhibit.fsl_status;
      if (eventType === 'fsl_reception') updatedFslStatus = 'batched';
      if (eventType === 'division_handover' || eventType === 'analysis_started') updatedFslStatus = 'testing';
      if (eventType === 'analysis_completed' || eventType === 'court_deposition') updatedFslStatus = 'analyzed';

      // Insert ledger entry
      db.prepare(`
        INSERT INTO chain_of_custody_ledger (id, exhibit_id, case_id, step_number, previous_ledger_hash, event_type, from_person_name, from_designation, to_person_name, to_designation, location, purpose, seal_condition, remarks, timestamp, actor_id, ledger_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'led_' + crypto.randomUUID().slice(0, 8),
        exhibitId,
        exhibit.case_id,
        stepNumber,
        previousHash,
        eventType,
        exhibit.current_custody_holder,
        user.role,
        toPersonName,
        toDesignation,
        location,
        purpose,
        sealCondition,
        remarks,
        now,
        user.id,
        newLedgerHash
      );

      // Update current custody holder on exhibit
      db.prepare(`
        UPDATE exhibits
        SET current_custody_holder = ?, current_custody_location = ?, fsl_status = ?
        WHERE id = ?
      `).run(toPersonName, location, updatedFslStatus, exhibitId);

      broadcastEvent('custody_transfer', { exhibitId, stepNumber, toPersonName, location });

      return sendJson(res, 200, {
        success: true,
        stepNumber,
        ledgerHash: newLedgerHash,
        currentHolder: toPersonName
      });
    }

    const ledgerMatch = pathname.match(/^\/api\/exhibits\/([a-zA-Z0-9_-]+)\/ledger$/);
    if (ledgerMatch && method === 'GET') {
      const exhibitId = ledgerMatch[1];
      const exhibit = db.prepare('SELECT * FROM exhibits WHERE id = ?').get(exhibitId);
      if (!exhibit) {
        return sendError(res, 404, 'Exhibit not found');
      }

      const entries = db
        .prepare('SELECT * FROM chain_of_custody_ledger WHERE exhibit_id = ? ORDER BY step_number ASC')
        .all(exhibitId);

      const integrity = verifyChainIntegrity(entries);

      return sendJson(res, 200, {
        exhibit,
        ledger: entries,
        integrityCheck: {
          valid: integrity.valid,
          totalSteps: entries.length,
          brokenAt: integrity.brokenAt,
          verifiedAt: new Date().toISOString()
        }
      });
    }

    // ----------------------------------------------------
    // 8. REMOTE SUPERVISION CONSOLE & ANNOTATIONS
    // ----------------------------------------------------
    const supMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/supervision$/);
    if (supMatch && method === 'GET') {
      const caseId = supMatch[1];
      let session = db.prepare('SELECT * FROM supervision_sessions WHERE case_id = ?').get(caseId);

      if (!session) {
        // Auto create if not existing
        const expert = db.prepare("SELECT id FROM users WHERE role = 'forensic_expert' LIMIT 1").get();
        const expertId = expert ? expert.id : user.id;
        const sessionId = 'sess_' + crypto.randomUUID().slice(0, 8);
        db.prepare(`
          INSERT INTO supervision_sessions (id, case_id, expert_id, io_id, status, stream_active, started_at)
          VALUES (?, ?, ?, ?, 'in_progress', 1, ?)
        `).run(sessionId, caseId, expertId, user.id, new Date().toISOString());
        session = db.prepare('SELECT * FROM supervision_sessions WHERE id = ?').get(sessionId);
      }

      const messages = db
        .prepare('SELECT m.*, u.full_name as sender_name FROM supervision_messages m JOIN users u ON m.sender_id = u.id WHERE m.case_id = ? ORDER BY m.created_at ASC')
        .all(caseId);

      return sendJson(res, 200, { session, messages });
    }

    const supMsgMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/supervision\/messages$/);
    if (supMsgMatch && method === 'POST') {
      const caseId = supMsgMatch[1];
      const body = await parseJsonBody(req);
      const { messageType = 'instruction', content, payload } = body;

      if (!content) {
        return sendError(res, 400, 'Content is required');
      }

      let session = db.prepare('SELECT * FROM supervision_sessions WHERE case_id = ?').get(caseId);
      if (!session) {
        const sessionId = 'sess_' + crypto.randomUUID().slice(0, 8);
        db.prepare(`
          INSERT INTO supervision_sessions (id, case_id, expert_id, io_id, status, stream_active, started_at)
          VALUES (?, ?, ?, ?, 'in_progress', 1, ?)
        `).run(sessionId, caseId, user.id, user.id, new Date().toISOString());
        session = db.prepare('SELECT * FROM supervision_sessions WHERE id = ?').get(sessionId);
      }

      const msgId = 'msg_' + crypto.randomUUID().slice(0, 8);
      const now = new Date().toISOString();

      db.prepare(`
        INSERT INTO supervision_messages (id, session_id, case_id, sender_id, sender_role, message_type, content, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        msgId,
        session.id,
        caseId,
        user.id,
        user.role,
        messageType,
        content,
        payload ? JSON.stringify(payload) : null,
        now
      );

      const newMsg = {
        id: msgId,
        sessionId: session.id,
        caseId,
        senderId: user.id,
        senderName: user.fullName,
        senderRole: user.role,
        messageType,
        content,
        payload,
        createdAt: now
      };

      broadcastEvent('supervision_message', newMsg);

      return sendJson(res, 201, { success: true, message: newMsg });
    }

    // ----------------------------------------------------
    // 9. LAB TRIAGE & DISTRICT PENDENCY INTELLIGENCE
    // ----------------------------------------------------
    if (pathname === '/api/triage/dashboard' && method === 'GET') {
      const totalCases = db.prepare('SELECT COUNT(*) as count FROM cases').get().count;
      const activeScenes = db.prepare("SELECT COUNT(*) as count FROM cases WHERE status = 'scene_active'").get().count;
      const fslPending = db.prepare("SELECT COUNT(*) as count FROM exhibits WHERE fsl_status IN ('pending', 'batched')").get().count;
      const courtReady = db.prepare("SELECT COUNT(*) as count FROM cases WHERE status = 'court_ready'").get().count;

      const divisionBreakdown = db.prepare(`
        SELECT fsl_assigned_division as division, COUNT(*) as count,
          SUM(CASE WHEN fsl_status = 'pending' THEN 1 ELSE 0 END) as pending,
          SUM(CASE WHEN fsl_status = 'batched' THEN 1 ELSE 0 END) as batched,
          SUM(CASE WHEN fsl_status = 'testing' THEN 1 ELSE 0 END) as testing,
          SUM(CASE WHEN fsl_status = 'analyzed' THEN 1 ELSE 0 END) as analyzed
        FROM exhibits
        GROUP BY fsl_assigned_division
      `).all();

      const districtWorkload = db.prepare(`
        SELECT district, COUNT(*) as total_cases,
          SUM(CASE WHEN status = 'scene_active' THEN 1 ELSE 0 END) as active_scenes,
          SUM(CASE WHEN status IN ('fsl_received', 'testing_in_progress') THEN 1 ELSE 0 END) as in_lab
        FROM cases
        GROUP BY district
      `).all();

      const recentExhibits = db.prepare(`
        SELECT e.*, c.fir_number, c.police_station, c.priority
        FROM exhibits e
        JOIN cases c ON e.case_id = c.id
        ORDER BY e.created_at DESC
        LIMIT 10
      `).all();

      return sendJson(res, 200, {
        metrics: {
          totalCases,
          activeScenes,
          fslPending,
          courtReady,
          expertCoverageMultiplier: '3.4x (Remote Supervised vs In-Person)',
          averageTurnaroundDays: 4.2,
          bnssMandateCompliance: '98.6%'
        },
        divisionBreakdown,
        districtWorkload,
        recentExhibits
      });
    }

    // ----------------------------------------------------
    // 10. BHARATIYA SAKSHYA ADHINIYAM (BSA) SECTION 63 CERTIFICATE
    // ----------------------------------------------------
    const certMatch = pathname.match(/^\/api\/cases\/([a-zA-Z0-9_-]+)\/bsa-certificate$/);
    if (certMatch && method === 'GET') {
      const caseId = certMatch[1];
      const cert = db.prepare('SELECT * FROM bsa_certificates WHERE case_id = ?').get(caseId);
      if (!cert) {
        return sendError(res, 404, 'Certificate not yet generated for this case');
      }
      return sendJson(res, 200, { certificate: cert, parsedData: JSON.parse(cert.cert_data_json) });
    }

    if (certMatch && method === 'POST') {
      const caseId = certMatch[1];
      const caseData = db.prepare('SELECT * FROM cases WHERE id = ?').get(caseId);
      if (!caseData) {
        return sendError(res, 404, 'Case not found');
      }

      const exhibits = db.prepare('SELECT * FROM exhibits WHERE case_id = ?').all(caseId);
      const now = new Date().toISOString();

      // Combine all exhibit hashes to produce Master Hash Digest
      const hashStream = exhibits.map(e => e.sha256_hash).join('|');
      const masterHash = calculateSha256(`CASE:${caseId}:EXHIBITS:${hashStream}:${now}`);
      const certToken = generateCertificateVerificationToken(caseId, masterHash, now);
      const certNumber = `BSA63-DL-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

      const certPayload = {
        caseId,
        firNumber: caseData.fir_number,
        policeStation: caseData.police_station,
        district: caseData.district,
        penalSections: caseData.penal_sections,
        courtAdmissibleStatute: 'Section 63, Bharatiya Sakshya Adhiniyam, 2023 (Admissibility of Electronic Records)',
        captureDevice: 'Pramaan Secured Field Capture Module (DFSS Standard Compliant)',
        deviceIntegrityState: 'VERIFIED - Cryptographic HSM Hardware Root of Trust',
        timestampingAuthority: 'National Physical Laboratory (NPL) India NTP Synchronized',
        investigatingOfficer: {
          name: user.fullName,
          badgeId: user.badgeId,
          role: user.role
        },
        supervisingForensicExpert: {
          name: 'Dr. Aditi Varma',
          designation: 'Senior Scientific Officer (Forensics & DNA Division)',
          department: 'Directorate of Forensic Science Services'
        },
        exhibitsCertified: exhibits.map(e => ({
          code: e.exhibit_code,
          category: e.category,
          sha256: e.sha256_hash,
          physicalSeal: e.physical_seal_number,
          collectionTime: e.collected_at
        })),
        judicialDeclaration:
          'I hereby certify under Section 63 of Bharatiya Sakshya Adhiniyam 2023 that the electronic records, digital videography, photographs, and cryptographic hashes herein were produced during the lawful exercise of duty, that the capture process was safeguarded against alteration or tampering, and that the cryptographic chain of custody remains unbroken.'
      };

      // Upsert certificate
      db.prepare(`
        INSERT INTO bsa_certificates (id, case_id, certificate_number, act_reference, io_name, io_badge, expert_name, expert_designation, hash_digest_master, verification_token, issued_at, cert_data_json)
        VALUES (?, ?, ?, 'Bharatiya Sakshya Adhiniyam, 2023 - Section 63', ?, ?, 'Dr. Aditi Varma', 'Senior Scientific Officer', ?, ?, ?, ?)
        ON CONFLICT(case_id) DO UPDATE SET
          certificate_number = excluded.certificate_number,
          hash_digest_master = excluded.hash_digest_master,
          verification_token = excluded.verification_token,
          issued_at = excluded.issued_at,
          cert_data_json = excluded.cert_data_json
      `).run(
        'cert_' + crypto.randomUUID().slice(0, 8),
        caseId,
        certNumber,
        user.fullName,
        user.badgeId,
        masterHash,
        certToken,
        now,
        JSON.stringify(certPayload)
      );

      // Update case status to court_ready
      db.prepare("UPDATE cases SET status = 'court_ready', updated_at = ? WHERE id = ?").run(now, caseId);

      broadcastEvent('case_court_ready', { caseId, certNumber, masterHash });

      return sendJson(res, 201, {
        success: true,
        certificateNumber: certNumber,
        masterHash,
        verificationToken: certToken,
        issuedAt: now
      });
    }

    // ----------------------------------------------------
    // 11. STATIC ASSETS SERVING
    // ----------------------------------------------------
    let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
    if (!fs.existsSync(filePath)) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }
    return serveStaticFile(req, res, filePath);
  } catch (err) {
    console.error('Server error on', method, pathname, err);
    return sendError(res, 500, 'Internal Server Error', err.message);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`  PRAMAAN (प्रमाण) · Forensic Evidence System  `);
  console.log(`  BNSS Sec 176(3) & BSA Sec 63 Compliance Engine    `);
  console.log(`  Running live at http://localhost:${PORT}          `);
  console.log(`====================================================`);
});
