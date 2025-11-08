const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

const db = new Database(path.join(__dirname, 'users.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

function createUser(username, password, email = null) {
  const hashedPassword = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)');
  try {
    const result = stmt.run(username, hashedPassword, email);
    return { id: result.lastInsertRowid, username, email };
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      throw new Error('Username sudah digunakan');
    }
    throw error;
  }
}

function getUserByUsername(username) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  return stmt.get(username);
}

function getUserById(id) {
  const stmt = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?');
  return stmt.get(id);
}

function verifyPassword(password, hashedPassword) {
  return bcrypt.compareSync(password, hashedPassword);
}

module.exports = {
  createUser,
  getUserByUsername,
  getUserById,
  verifyPassword,
  db
};
