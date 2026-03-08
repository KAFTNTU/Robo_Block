-- Запустити ОДИН РАЗ:
-- npx wrangler d1 execute roboscratch-users --file=migrate2.sql --remote
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student';
ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0;
