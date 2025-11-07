const path = require('path');
const sqlite3 = require('sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'breaktracker.sqlite3');

const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      must_change_password INTEGER NOT NULL DEFAULT 1,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN (\'admin\', \'manager\', \'employee\')),
      status TEXT NOT NULL DEFAULT 'Active'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS departments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'Active'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      department_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'Active',
      FOREIGN KEY(department_id) REFERENCES departments(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS break_types (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      color TEXT,
      status TEXT NOT NULL DEFAULT 'Active'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      name TEXT NOT NULL,
      department_id INTEGER,
      team_id INTEGER,
      status TEXT NOT NULL DEFAULT 'Active',
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(department_id) REFERENCES departments(id),
      FOREIGN KEY(team_id) REFERENCES teams(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS breaks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      break_type_id INTEGER NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT,
      duration INTEGER,
      FOREIGN KEY(employee_id) REFERENCES employees(id),
      FOREIGN KEY(break_type_id) REFERENCES break_types(id)
    )
  `);
});

module.exports = db;
