-- npx wrangler d1 execute roboscratch-users --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT,
  google_id TEXT UNIQUE,
  avatar_url TEXT,
  role TEXT NOT NULL DEFAULT 'student',   -- 'student' | 'teacher' | 'admin'
  is_blocked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_login INTEGER
);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_google   ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_role     ON users(role);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_heartbeat INTEGER,
  ended_at INTEGER,
  duration_seconds INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);

-- Учні прив'язані до вчителя (з довільним ПІБ)
CREATE TABLE IF NOT EXISTS teacher_students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  student_id INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- може бути NULL якщо учень ще не зареєстрований
  full_name TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_ts_teacher ON teacher_students(teacher_id);

-- Відвідуваність: Н, П.П
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  student_id INTEGER NOT NULL,
  date TEXT NOT NULL,        -- YYYY-MM-DD
  status TEXT NOT NULL,      -- 'Н' | 'П.П'
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(teacher_id, student_id, date)
);
CREATE INDEX IF NOT EXISTS idx_att_teacher ON attendance(teacher_id, date);

-- Ключі доступу до адмінки (окремо від ADMIN_KEY з env)
CREATE TABLE IF NOT EXISTS admin_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,   -- bcrypt hash
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Запрошувальні ключі для реєстрації
CREATE TABLE IF NOT EXISTS invite_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  note TEXT,
  used_by INTEGER REFERENCES users(id),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  used_at INTEGER
);

-- Журнал дій
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL DEFAULT (unixepoch()),
  action TEXT NOT NULL,
  user_id INTEGER,
  actor_id INTEGER,
  ip TEXT,
  meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
