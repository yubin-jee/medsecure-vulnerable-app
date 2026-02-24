const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, '../../data/medsecure.db'));

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    dob TEXT,
    ssn TEXT,
    diagnosis TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    ssn TEXT,
    reset_token TEXT,
    reset_expiry INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS medical_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    department TEXT,
    status TEXT DEFAULT 'active',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed some demo data
const patientCount = db.prepare('SELECT COUNT(*) as count FROM patients').get();
if (patientCount.count === 0) {
  const insertPatient = db.prepare('INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)');
  insertPatient.run('John Doe', '1985-03-15', '123-45-6789', 'Hypertension');
  insertPatient.run('Jane Smith', '1990-07-22', '987-65-4321', 'Type 2 Diabetes');
  insertPatient.run('Bob Johnson', '1978-11-30', '456-78-9012', 'Asthma');

  const insertUser = db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)');
  insertUser.run('admin', 'admin123', 'admin@medsecure.com', 'admin');
  insertUser.run('drsmith', 'password', 'smith@medsecure.com', 'doctor');
  insertUser.run('nurse_jones', 'nurse123', 'jones@medsecure.com', 'nurse');
}

module.exports = db;
