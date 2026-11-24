// db.js - SQLite Database initialization & seed data for Pramaan
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const { hashPassword } = require('./auth');
const { generateLedgerHash, calculateSha256 } = require('./crypto-engine');

const DB_PATH = path.join(__dirname, 'data', 'pramaan.sqlite');

let dbInstance = null;

function getDb() {
  if (dbInstance) return dbInstance;

  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  dbInstance = new DatabaseSync(DB_PATH);
  
  // Pragmas for integrity and performance
  dbInstance.exec(`
    PRAGMA foreign_keys = ON;
  `);

  initSchema(dbInstance);
  seedInitialData(dbInstance);

  return dbInstance;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('investigating_officer', 'forensic_expert', 'lab_director', 'magistrate_or_prosecutor')),
      badge_or_emp_id TEXT NOT NULL,
      department TEXT NOT NULL,
      state_or_district TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY,
      fir_number TEXT NOT NULL,
      police_station TEXT NOT NULL,
      district TEXT NOT NULL,
      state TEXT NOT NULL,
      offence_type TEXT NOT NULL,
      penal_sections TEXT NOT NULL,
      is_mandatory_bnss_176 INTEGER NOT NULL DEFAULT 1,
      io_id TEXT NOT NULL,
      assigned_expert_id TEXT,
      incident_time TEXT NOT NULL,
      scene_location TEXT NOT NULL,
      latitude REAL,
      longitude REAL,
      status TEXT NOT NULL CHECK(status IN ('scene_active', 'capture_completed', 'under_remote_review', 'in_malkhana', 'transit_to_fsl', 'fsl_received', 'testing_in_progress', 'report_submitted', 'court_ready')),
      priority TEXT NOT NULL CHECK(priority IN ('urgent', 'high', 'routine')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (io_id) REFERENCES users(id),
      FOREIGN KEY (assigned_expert_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS case_checklists (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL,
      step_order INTEGER NOT NULL,
      step_key TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      dfss_guideline_ref TEXT NOT NULL,
      is_completed INTEGER NOT NULL DEFAULT 0,
      completed_at TEXT,
      completed_by_user_id TEXT,
      expert_verified INTEGER NOT NULL DEFAULT 0,
      expert_notes TEXT,
      media_file_name TEXT,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS exhibits (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL,
      exhibit_code TEXT NOT NULL,
      category TEXT NOT NULL CHECK(category IN ('Biological', 'Ballistics', 'Chemical', 'Toxicological', 'Digital', 'Trace', 'Questioned Document', 'Weapons')),
      description TEXT NOT NULL,
      found_location TEXT NOT NULL,
      packaging_method TEXT NOT NULL,
      physical_seal_number TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      file_name TEXT,
      media_mime TEXT,
      collected_by TEXT NOT NULL,
      collected_at TEXT NOT NULL,
      latitude REAL,
      longitude REAL,
      current_custody_holder TEXT NOT NULL,
      current_custody_location TEXT NOT NULL,
      fsl_assigned_division TEXT NOT NULL,
      fsl_status TEXT NOT NULL DEFAULT 'pending' CHECK(fsl_status IN ('pending', 'batched', 'testing', 'analyzed')),
      created_at TEXT NOT NULL,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS chain_of_custody_ledger (
      id TEXT PRIMARY KEY,
      exhibit_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      step_number INTEGER NOT NULL,
      previous_ledger_hash TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('initial_scene_collection', 'malkhana_deposit', 'dispatch_to_fsl', 'fsl_reception', 'division_handover', 'analysis_started', 'analysis_completed', 'court_deposition')),
      from_person_name TEXT NOT NULL,
      from_designation TEXT NOT NULL,
      to_person_name TEXT NOT NULL,
      to_designation TEXT NOT NULL,
      location TEXT NOT NULL,
      purpose TEXT NOT NULL,
      seal_condition TEXT NOT NULL CHECK(seal_condition IN ('intact_and_verified', 'inspected_under_supervision', 'broken_for_subsampling_under_fsl_sop')),
      remarks TEXT,
      timestamp TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      ledger_hash TEXT NOT NULL,
      FOREIGN KEY (exhibit_id) REFERENCES exhibits(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS supervision_sessions (
      id TEXT PRIMARY KEY,
      case_id TEXT UNIQUE NOT NULL,
      expert_id TEXT NOT NULL,
      io_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'waiting' CHECK(status IN ('waiting', 'in_progress', 'concluded')),
      stream_active INTEGER NOT NULL DEFAULT 1,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      expert_guidance_notes TEXT,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS supervision_messages (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      sender_role TEXT NOT NULL,
      message_type TEXT NOT NULL CHECK(message_type IN ('instruction', 'marker_annotation', 'snapshot_request', 'status_update')),
      content TEXT NOT NULL,
      payload_json TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (session_id) REFERENCES supervision_sessions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS bsa_certificates (
      id TEXT PRIMARY KEY,
      case_id TEXT UNIQUE NOT NULL,
      certificate_number TEXT NOT NULL,
      act_reference TEXT NOT NULL DEFAULT 'Bharatiya Sakshya Adhiniyam, 2023 - Section 63',
      io_name TEXT NOT NULL,
      io_badge TEXT NOT NULL,
      expert_name TEXT NOT NULL,
      expert_designation TEXT NOT NULL,
      hash_digest_master TEXT NOT NULL,
      verification_token TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      cert_data_json TEXT NOT NULL,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      ip_address TEXT,
      action TEXT NOT NULL,
      details TEXT,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
}

function seedInitialData(db) {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount > 0) return; // Already seeded

  console.log('Seeding initial authentic forensic data for Pramaan...');

  // 1. Seed Users
  const users = [
    {
      id: 'usr_io_01',
      email: 'officer@pramaan.gov.in',
      password: 'Officer@123',
      full_name: 'SI Rajesh Sharma',
      role: 'investigating_officer',
      badge_or_emp_id: 'DL-POL-44910',
      department: 'Delhi Police - New Delhi District',
      state_or_district: 'New Delhi',
      created_at: new Date('2026-01-15T09:00:00Z').toISOString()
    },
    {
      id: 'usr_exp_01',
      email: 'expert@pramaan.gov.in',
      password: 'Expert@123',
      full_name: 'Dr. Aditi Varma',
      role: 'forensic_expert',
      badge_or_emp_id: 'DFSS-FSL-7721',
      department: 'Forensic Science Laboratory (Biology & DNA Division)',
      state_or_district: 'FSL Rohini, Delhi',
      created_at: new Date('2026-01-15T09:00:00Z').toISOString()
    },
    {
      id: 'usr_dir_01',
      email: 'director@pramaan.gov.in',
      password: 'Director@123',
      full_name: 'Dr. K. S. Meena',
      role: 'lab_director',
      badge_or_emp_id: 'DFSS-DIR-009',
      department: 'Directorate of Forensic Science Services',
      state_or_district: 'Regional Directorate North',
      created_at: new Date('2026-01-15T09:00:00Z').toISOString()
    },
    {
      id: 'usr_mag_01',
      email: 'magistrate@pramaan.gov.in',
      password: 'Magistrate@123',
      full_name: 'Hon. R. P. Sundaram',
      role: 'magistrate_or_prosecutor',
      badge_or_emp_id: 'DJS-JUD-2018/44',
      department: 'Chief Metropolitan Magistrate Court',
      state_or_district: 'Patiala House Courts, New Delhi',
      created_at: new Date('2026-01-15T09:00:00Z').toISOString()
    }
  ];

  const insertUser = db.prepare(`
    INSERT INTO users (id, email, password_hash, salt, full_name, role, badge_or_emp_id, department, state_or_district, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const u of users) {
    const { hash, salt } = hashPassword(u.password);
    insertUser.run(u.id, u.email, hash, salt, u.full_name, u.role, u.badge_or_emp_id, u.department, u.state_or_district, u.created_at);
  }

  // 2. Seed Cases
  const cases = [
    {
      id: 'case_del_2026_01',
      fir_number: 'FIR No. 142/2026',
      police_station: 'PS Karol Bagh',
      district: 'Central District',
      state: 'Delhi (UT)',
      offence_type: 'Homicide with Aggravated Robbery',
      penal_sections: 'BNS 103(1) [Murder], BNS 309(4) [Robbery with hurt]',
      is_mandatory_bnss_176: 1,
      io_id: 'usr_io_01',
      assigned_expert_id: 'usr_exp_01',
      incident_time: '2026-11-24 02:15 AM',
      scene_location: 'Plot 44, Bank Street Commercial Complex, Karol Bagh',
      latitude: 28.6517,
      longitude: 77.1906,
      status: 'scene_active',
      priority: 'urgent',
      created_at: '2026-11-24T02:45:00Z',
      updated_at: '2026-11-24T03:30:00Z'
    },
    {
      id: 'case_del_2026_02',
      fir_number: 'FIR No. 89/2026',
      police_station: 'PS Connaught Place',
      district: 'New Delhi',
      state: 'Delhi (UT)',
      offence_type: 'Armed Dacoity & Firearms Discharge',
      penal_sections: 'BNS 310(2) [Dacoity], Arms Act Sec 25/27',
      is_mandatory_bnss_176: 1,
      io_id: 'usr_io_01',
      assigned_expert_id: 'usr_exp_01',
      incident_time: '2026-11-23 21:30 PM',
      scene_location: 'Block C, Inner Circle, Connaught Place',
      latitude: 28.6328,
      longitude: 77.2197,
      status: 'fsl_received',
      priority: 'high',
      created_at: '2026-11-23T22:15:00Z',
      updated_at: '2026-11-24T10:00:00Z'
    },
    {
      id: 'case_del_2026_03',
      fir_number: 'FIR No. 204/2026',
      police_station: 'PS Cyber Crime North',
      district: 'North District',
      state: 'Delhi (UT)',
      offence_type: 'Critical Cyber Extortion & Ransomware Attack',
      penal_sections: 'BNS 308(2) [Extortion], IT Act 2000 Sec 66F [Cyber Terrorism]',
      is_mandatory_bnss_176: 1,
      io_id: 'usr_io_01',
      assigned_expert_id: 'usr_exp_01',
      incident_time: '2026-11-22 14:00 PM',
      scene_location: 'Datacenter Server Room, Civil Lines Tech Hub',
      latitude: 28.6812,
      longitude: 77.2228,
      status: 'court_ready',
      priority: 'urgent',
      created_at: '2026-11-22T14:45:00Z',
      updated_at: '2026-11-24T14:30:00Z'
    }
  ];

  const insertCase = db.prepare(`
    INSERT INTO cases (id, fir_number, police_station, district, state, offence_type, penal_sections, is_mandatory_bnss_176, io_id, assigned_expert_id, incident_time, scene_location, latitude, longitude, status, priority, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const c of cases) {
    insertCase.run(c.id, c.fir_number, c.police_station, c.district, c.state, c.offence_type, c.penal_sections, c.is_mandatory_bnss_176, c.io_id, c.assigned_expert_id, c.incident_time, c.scene_location, c.latitude, c.longitude, c.status, c.priority, c.created_at, c.updated_at);
  }

  // 3. Seed Checklists for Case 1 (Homicide & Robbery)
  const homicideChecklist = [
    {
      id: 'chk_101',
      case_id: 'case_del_2026_01',
      step_order: 1,
      step_key: 'cordon_verification',
      title: 'Perimeter Cordon & Access Log',
      description: 'Establish double-tier perimeter cordon (Inner: 50m, Outer: 100m). Log all entry/exit personnel.',
      dfss_guideline_ref: 'DFSS Crime Scene Manual 2024 Sec 3.2',
      is_completed: 1,
      completed_at: '2026-11-24T02:55:00Z',
      completed_by_user_id: 'usr_io_01',
      expert_verified: 1,
      expert_notes: 'Cordon verified via live stream. Inner cordon secured with yellow forensic tape.',
      media_file_name: 'cordon_log_plot44.jpg'
    },
    {
      id: 'chk_102',
      case_id: 'case_del_2026_01',
      step_order: 2,
      step_key: 'panoramic_videography',
      title: 'Mandatory 360° Panoramic Videography',
      description: 'Capture continuous unbroken 360-degree high-definition video from perimeter inward (BNSS 176(3)).',
      dfss_guideline_ref: 'BNSS 2023 Sec 176(3) & DFSS Video Protocol',
      is_completed: 1,
      completed_at: '2026-11-24T03:05:00Z',
      completed_by_user_id: 'usr_io_01',
      expert_verified: 1,
      expert_notes: 'Continuous pan acceptable. Adequate lighting maintained with mobile LED flood.',
      media_file_name: 'scene_360_panoramic.mp4'
    },
    {
      id: 'chk_103',
      case_id: 'case_del_2026_01',
      step_order: 3,
      step_key: 'evidence_marker_placement',
      title: 'Forensic Placard & Marker Placement',
      description: 'Place numbered forensic A-frame tents and metric scale rulers adjacent to identified exhibits.',
      dfss_guideline_ref: 'DFSS Chapter 5: Evidence Marking & Scale Alignment',
      is_completed: 1,
      completed_at: '2026-11-24T03:15:00Z',
      completed_by_user_id: 'usr_io_01',
      expert_verified: 1,
      expert_notes: 'Markers 01 to 04 placed properly with ABFO millimetric scales.',
      media_file_name: 'markers_overview.jpg'
    },
    {
      id: 'chk_104',
      case_id: 'case_del_2026_01',
      step_order: 4,
      step_key: 'biological_swab_collection',
      title: 'Blood Spatter & Biological Sample Swabbing',
      description: 'Use sterile cotton swabs moistened with sterile saline. Air-dry completely before sealing; do NOT use plastic bags for wet stains.',
      dfss_guideline_ref: 'DFSS Biological Evidence SOP Sec 4.1.2',
      is_completed: 0,
      completed_at: null,
      completed_by_user_id: null,
      expert_verified: 0,
      expert_notes: 'Awaiting expert supervision on stain directionality.',
      media_file_name: null
    },
    {
      id: 'chk_105',
      case_id: 'case_del_2026_01',
      step_order: 5,
      step_key: 'ballistics_toolmark_recovery',
      title: 'Weapon / Cartridge Casing Recovery',
      description: 'Use rubber-coated forceps to pick up fired cartridge casings. Never insert objects into barrel.',
      dfss_guideline_ref: 'DFSS Ballistics SOP Sec 2.4',
      is_completed: 0,
      completed_at: null,
      completed_by_user_id: null,
      expert_verified: 0,
      expert_notes: null,
      media_file_name: null
    },
    {
      id: 'chk_106',
      case_id: 'case_del_2026_01',
      step_order: 6,
      step_key: 'tamper_seal_and_qr',
      title: 'Tamper-Evident Bagging & CoC Hash Registration',
      description: 'Place in designated evidence envelopes, apply serialized tamper-evident barcode seal, and record cryptographic SHA-256 fingerprint.',
      dfss_guideline_ref: 'Bharatiya Sakshya Adhiniyam 2023 Sec 63 & DFSS Packaging Manual',
      is_completed: 0,
      completed_at: null,
      completed_by_user_id: null,
      expert_verified: 0,
      expert_notes: null,
      media_file_name: null
    }
  ];

  const insertChecklist = db.prepare(`
    INSERT INTO case_checklists (id, case_id, step_order, step_key, title, description, dfss_guideline_ref, is_completed, completed_at, completed_by_user_id, expert_verified, expert_notes, media_file_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const item of homicideChecklist) {
    insertChecklist.run(item.id, item.case_id, item.step_order, item.step_key, item.title, item.description, item.dfss_guideline_ref, item.is_completed, item.completed_at, item.completed_by_user_id, item.expert_verified, item.expert_notes, item.media_file_name);
  }

  // 4. Seed Exhibits
  const exhibits = [
    {
      id: 'exhb_001',
      case_id: 'case_del_2026_01',
      exhibit_code: 'EX-01/BLOOD',
      category: 'Biological',
      description: 'Suspected blood sample swabbed from floor tile 1.2m from cash register counter.',
      found_location: 'Main Cashier Desk, Ground Floor',
      packaging_method: 'Sterile cotton swab desiccated in breathable paper envelope with tamper seal.',
      physical_seal_number: 'DEL-POL-SEAL-88901',
      sha256_hash: calculateSha256('EXHIBIT_DATA_BLOOD_SWAB_DEL_2026_01_RAW_BYTES'),
      file_name: 'exhibit_01_blood_stain.jpg',
      media_mime: 'image/jpeg',
      collected_by: 'SI Rajesh Sharma',
      collected_at: '2026-11-24T03:10:00Z',
      latitude: 28.6517,
      longitude: 77.1906,
      current_custody_holder: 'SI Rajesh Sharma (Investigating Officer)',
      current_custody_location: 'Crime Scene Mobile Unit #4',
      fsl_assigned_division: 'Biology & DNA Division',
      fsl_status: 'pending',
      created_at: '2026-11-24T03:10:00Z'
    },
    {
      id: 'exhb_002',
      case_id: 'case_del_2026_01',
      exhibit_code: 'EX-02/CASING',
      category: 'Ballistics',
      description: 'One fired 7.65mm brass cartridge case with headstamp "KF 24".',
      found_location: 'Under wooden display shelf, 3m east of entrance door',
      packaging_method: 'Padded rigid plastic container lined with clean non-treated cotton wool.',
      physical_seal_number: 'DEL-POL-SEAL-88902',
      sha256_hash: calculateSha256('EXHIBIT_DATA_CARTRIDGE_CASING_7.65MM_RAW_BYTES'),
      file_name: 'exhibit_02_casing_765.jpg',
      media_mime: 'image/jpeg',
      collected_by: 'SI Rajesh Sharma',
      collected_at: '2026-11-24T03:25:00Z',
      latitude: 28.6517,
      longitude: 77.1906,
      current_custody_holder: 'SI Rajesh Sharma (Investigating Officer)',
      current_custody_location: 'Crime Scene Mobile Unit #4',
      fsl_assigned_division: 'Ballistics & Firearms Division',
      fsl_status: 'pending',
      created_at: '2026-11-24T03:25:00Z'
    },
    {
      id: 'exhb_003',
      case_id: 'case_del_2026_02',
      exhibit_code: 'EX-01/WEAPON',
      category: 'Weapons',
      description: 'Country-made pistol (desi katta) recovered from planter near exit corridor.',
      found_location: 'Corridor Outer Planter, Connaught Place Block C',
      packaging_method: 'Cardboard evidence box immobilized with zip-ties through trigger guard.',
      physical_seal_number: 'DEL-POL-SEAL-77401',
      sha256_hash: calculateSha256('EXHIBIT_DATA_DESI_PISTOL_FIREARM_RAW_BYTES'),
      file_name: 'exhibit_03_firearm_pistol.jpg',
      media_mime: 'image/jpeg',
      collected_by: 'SI Rajesh Sharma',
      collected_at: '2026-11-23T22:40:00Z',
      latitude: 28.6328,
      longitude: 77.2197,
      current_custody_holder: 'FSL Reception Desk (Receipt # FSL-2026/894)',
      current_custody_location: 'Forensic Science Laboratory Rohini',
      fsl_assigned_division: 'Ballistics & Firearms Division',
      fsl_status: 'batched',
      created_at: '2026-11-23T22:40:00Z'
    },
    {
      id: 'exhb_004',
      case_id: 'case_del_2026_03',
      exhibit_code: 'EX-01/SSD',
      category: 'Digital',
      description: 'Samsung 980 Pro 2TB NVMe M.2 Solid State Drive containing intrusion payloads.',
      found_location: 'Server Rack 04, Slot 2',
      packaging_method: 'Anti-static conductive ESD shielding bag with tamper tape seal.',
      physical_seal_number: 'DEL-CYBER-SEAL-1109',
      sha256_hash: calculateSha256('EXHIBIT_DATA_SAMSUNG_SSD_FORENSIC_RAW_BYTES'),
      file_name: 'exhibit_04_server_ssd.jpg',
      media_mime: 'image/jpeg',
      collected_by: 'SI Rajesh Sharma',
      collected_at: '2026-11-22T15:20:00Z',
      latitude: 28.6812,
      longitude: 77.2228,
      current_custody_holder: 'Court Malkhana Officer (Hon. R. P. Sundaram Court)',
      current_custody_location: 'Patiala House Court Record Room',
      fsl_assigned_division: 'Cyber Forensics Division',
      fsl_status: 'analyzed',
      created_at: '2026-11-22T15:20:00Z'
    }
  ];

  const insertExhibit = db.prepare(`
    INSERT INTO exhibits (id, case_id, exhibit_code, category, description, found_location, packaging_method, physical_seal_number, sha256_hash, file_name, media_mime, collected_by, collected_at, latitude, longitude, current_custody_holder, current_custody_location, fsl_assigned_division, fsl_status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const ex of exhibits) {
    insertExhibit.run(ex.id, ex.case_id, ex.exhibit_code, ex.category, ex.description, ex.found_location, ex.packaging_method, ex.physical_seal_number, ex.sha256_hash, ex.file_name, ex.media_mime, ex.collected_by, ex.collected_at, ex.latitude, ex.longitude, ex.current_custody_holder, ex.current_custody_location, ex.fsl_assigned_division, ex.fsl_status, ex.created_at);
  }

  // 5. Seed Chain of Custody Ledger with verifiable hash chains
  const insertLedger = db.prepare(`
    INSERT INTO chain_of_custody_ledger (id, exhibit_id, case_id, step_number, previous_ledger_hash, event_type, from_person_name, from_designation, to_person_name, to_designation, location, purpose, seal_condition, remarks, timestamp, actor_id, ledger_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Custody Chain for EX-01/BLOOD
  const ex1_t1 = '2026-11-24T03:10:00Z';
  const ex1_h1 = generateLedgerHash('GENESIS_BLOCK_PRAMAAN_2026', 'exhb_001', 'case_del_2026_01', 'initial_scene_collection', ex1_t1, 'SI Rajesh Sharma', 'intact_and_verified', 'usr_io_01');
  insertLedger.run(
    'led_001_1', 'exhb_001', 'case_del_2026_01', 1, 'GENESIS_BLOCK_PRAMAAN_2026',
    'initial_scene_collection', 'Crime Scene Origin', 'Locus Delicti', 'SI Rajesh Sharma', 'Investigating Officer',
    'Karol Bagh Crime Scene', 'Field Forensic Collection under BNSS 176(3)', 'intact_and_verified',
    'Swab desiccated and sealed under remote supervision of Dr. Aditi Varma', ex1_t1, 'usr_io_01', ex1_h1
  );

  // Custody Chain for EX-01/WEAPON (Case 2: progressed to FSL)
  const ex3_t1 = '2026-11-23T22:40:00Z';
  const ex3_h1 = generateLedgerHash('GENESIS_BLOCK_PRAMAAN_2026', 'exhb_003', 'case_del_2026_02', 'initial_scene_collection', ex3_t1, 'SI Rajesh Sharma', 'intact_and_verified', 'usr_io_01');
  insertLedger.run(
    'led_003_1', 'exhb_003', 'case_del_2026_02', 1, 'GENESIS_BLOCK_PRAMAAN_2026',
    'initial_scene_collection', 'Corridor Planter', 'Crime Scene', 'SI Rajesh Sharma', 'Investigating Officer',
    'CP Block C Scene', 'Initial Seizure & Packaging', 'intact_and_verified',
    'Serial number noted; trigger guard immobilized with cable ties', ex3_t1, 'usr_io_01', ex3_h1
  );

  const ex3_t2 = '2026-11-23T23:55:00Z';
  const ex3_h2 = generateLedgerHash(ex3_h1, 'exhb_003', 'case_del_2026_02', 'malkhana_deposit', ex3_t2, 'HC Suresh Kumar (Malkhana Moharrir)', 'intact_and_verified', 'usr_io_01');
  insertLedger.run(
    'led_003_2', 'exhb_003', 'case_del_2026_02', 2, ex3_h1,
    'malkhana_deposit', 'SI Rajesh Sharma', 'Investigating Officer', 'HC Suresh Kumar (Malkhana Moharrir)', 'Storekeeper',
    'PS Connaught Place Malkhana', 'Safe Custody Overnight Deposit', 'intact_and_verified',
    'Deposited in Malkhana Locker # 41 under entry register Vol 21 / Pg 94', ex3_t2, 'usr_io_01', ex3_h2
  );

  const ex3_t3 = '2026-11-24T09:30:00Z';
  const ex3_h3 = generateLedgerHash(ex3_h2, 'exhb_003', 'case_del_2026_02', 'fsl_reception', ex3_t3, 'Sunita Rao (FSL Receptionist)', 'intact_and_verified', 'usr_exp_01');
  insertLedger.run(
    'led_003_3', 'exhb_003', 'case_del_2026_02', 3, ex3_h2,
    'fsl_reception', 'Constable Manoj Singh', 'Police Road Certificate Courier', 'Sunita Rao (FSL Receptionist)', 'Senior Scientific Assistant',
    'FSL Rohini Main Intake', 'Handover for Ballistics Examination', 'intact_and_verified',
    'Physical seal DEL-POL-SEAL-77401 compared with sample impression on RC; verified intact', ex3_t3, 'usr_exp_01', ex3_h3
  );

  // 6. Seed Supervision Session for Case 1
  db.prepare(`
    INSERT INTO supervision_sessions (id, case_id, expert_id, io_id, status, stream_active, started_at, expert_guidance_notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'sess_sup_01',
    'case_del_2026_01',
    'usr_exp_01',
    'usr_io_01',
    'in_progress',
    1,
    '2026-11-24T02:50:00Z',
    'Expert Dr. Aditi Varma logged in from FSL Central Super-Desk. Real-time audio-video active.'
  );

  // Seed Supervision Messages
  const insertMsg = db.prepare(`
    INSERT INTO supervision_messages (id, session_id, case_id, sender_id, sender_role, message_type, content, payload_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertMsg.run(
    'msg_001',
    'sess_sup_01',
    'case_del_2026_01',
    'usr_exp_01',
    'forensic_expert',
    'instruction',
    'Rajesh ji, please pan down slowly to the counter base. There appears to be a secondary blood drip pattern near the register.',
    JSON.stringify({ targetZone: 'Cashier Base', priority: 'High' }),
    '2026-11-24T02:58:10Z'
  );

  insertMsg.run(
    'msg_002',
    'sess_sup_01',
    'case_del_2026_01',
    'usr_io_01',
    'investigating_officer',
    'status_update',
    'Maam, panning camera down now. Setting up forensic ruler and Marker 01.',
    JSON.stringify({ markerPlaced: '01', scaleUnit: 'metric-mm' }),
    '2026-11-24T03:00:15Z'
  );

  insertMsg.run(
    'msg_003',
    'sess_sup_01',
    'case_del_2026_01',
    'usr_exp_01',
    'forensic_expert',
    'marker_annotation',
    'Placed virtual tag at coordinate (340, 210) on your camera view. Swab the outer dried rim first for highest nuclear DNA concentration.',
    JSON.stringify({ x: 340, y: 210, label: 'Optimal DNA Swab Target' }),
    '2026-11-24T03:02:40Z'
  );

  // 7. Seed BSA Section 63 Certificate for Case 3 (Court Ready)
  const certMasterHash = calculateSha256('MASTER_HASH_CASE_DEL_2026_03_IMMUTABLE_CHAIN');
  const certToken = calculateSha256('CERT_TOKEN_DEL_2026_03').slice(0, 32);

  db.prepare(`
    INSERT INTO bsa_certificates (id, case_id, certificate_number, act_reference, io_name, io_badge, expert_name, expert_designation, hash_digest_master, verification_token, issued_at, cert_data_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'cert_003',
    'case_del_2026_03',
    'BSA63-DL-2026-00441',
    'Bharatiya Sakshya Adhiniyam, 2023 - Section 63 (Electronic Evidence Certificate)',
    'SI Rajesh Sharma',
    'DL-POL-44910',
    'Dr. Aditi Varma',
    'Senior Scientific Officer (Cyber & Physical Integrity)',
    certMasterHash,
    certToken,
    '2026-11-23T11:00:00Z',
    JSON.stringify({
      caseId: 'case_del_2026_03',
      fir: 'FIR No. 204/2026',
      court: 'Hon. Court of Chief Metropolitan Magistrate, Patiala House Courts',
      actSection: 'Section 63 BSA 2023 / Section 65B Indian Evidence Act Equivalent',
      deviceDetails: 'Samsung Galaxy Field Forensic Capture Unit #DL-04 (IMEI: 864291048821903)',
      operatingSystem: 'Pramaan Trusted Capture OS Kernel v4.2.0-secure',
      timestampProvider: 'National Physical Laboratory (NPL) India Time Synchronized',
      exhibitCount: 1,
      integrityAudit: 'PASSED - Unbroken Cryptographic Hash Chain'
    })
  );

  console.log('Database seeded successfully with authentic BNSS 176(3) cases and exhibits.');
}

module.exports = {
  getDb
};
