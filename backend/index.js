const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

const SECRET_KEY = 'your-secret-key'; // Replace with a secure key in production

// Initialize SQLite database
const db = new sqlite3.Database(':memory:', (err) => {
  if (err) console.error(err.message);
  console.log('Connected to SQLite database.');
});

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS service_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      telephone TEXT NOT NULL,
      email TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      resource TEXT NOT NULL,
      issue TEXT NOT NULL,
      provider_id INTEGER,
      status TEXT DEFAULT 'active',
      timestamp TEXT NOT NULL,
      username TEXT NOT NULL,
      email TEXT NOT NULL,
      FOREIGN KEY (provider_id) REFERENCES service_providers(id),
      FOREIGN KEY (username) REFERENCES users(username)
    )
  `);

  // Insert sample service providers
  db.get('SELECT COUNT(*) as count FROM service_providers', (err, row) => {
    if (row.count === 0) {
      db.run('INSERT INTO service_providers (name, telephone, email) VALUES (?, ?, ?)', ['WaterFix', '123-456-7890', 'waterfix@example.com']);
      db.run('INSERT INTO service_providers (name, telephone, email) VALUES (?, ?, ?)', ['PowerCo', '234-567-8901', 'powerco@example.com']);
      db.run('INSERT INTO service_providers (name, telephone, email) VALUES (?, ?, ?)', ['HeatPro', '345-678-9012', 'heatpro@example.com']);
    }
  });

  // Insert sample users with hashed passwords
  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    if (row.count === 0) {
      const saltRounds = 10;
      bcrypt.hash('password123', saltRounds, (err, hash) => {
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', ['john_doe', 'john@example.com', hash]);
      });
      bcrypt.hash('secure456', saltRounds, (err, hash) => {
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', ['jane_smith', 'jane@example.com', hash]);
      });
      bcrypt.hash('admin789', saltRounds, (err, hash) => {
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', ['admin', 'admin@example.com', hash]);
      });
    }
  });
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) return res.status(401).json({ error: 'Invalid credentials' });
      const token = jwt.sign({ username: user.username, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
      res.json({ token });
    });
  });
});

// Get all service providers (protected)
app.get('/providers', authenticateToken, (req, res) => {
  db.all('SELECT * FROM service_providers', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Submit a new report (protected)
app.post('/reports', authenticateToken, (req, res) => {
  const { resource, issue, provider_id } = req.body;
  const timestamp = new Date().toISOString();
  const status = 'active';
  const { username, email } = req.user;
  db.run(
    'INSERT INTO reports (resource, issue, provider_id, status, timestamp, username, email) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [resource, issue, provider_id, status, timestamp, username, email],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID });
    }
  );
});

// Get active and in-repair reports (protected)
app.get('/reports', authenticateToken, (req, res) => {
  db.all(
    "SELECT id, resource, issue, provider_id, status, timestamp, username, email FROM reports WHERE status IN ('active', 'in repair')",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Update report status (protected)
app.patch('/reports/:id', authenticateToken, (req, res) => {
  const { status } = req.body;
  const id = req.params.id;
  db.run('UPDATE reports SET status = ? WHERE id = ?', [status, id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});

// Get resource statuses (protected)
app.get('/statuses', authenticateToken, (req, res) => {
  const resources = ['water', 'power', 'heating'];
  const statuses = resources.map(resource => {
    return new Promise((resolve) => {
      db.get(
        `SELECT 
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_count,
          SUM(CASE WHEN status = 'in repair' THEN 1 ELSE 0 END) as in_repair_count
        FROM reports WHERE resource = ?`,
        [resource],
        (err, row) => {
          if (err || !row) return resolve({ resource, status: 'green' });
          const activeCount = row.active_count || 0;
          const inRepairCount = row.in_repair_count || 0;
          let status = 'green';
          if (activeCount > 0) status = 'red';
          else if (inRepairCount > 0) status = 'orange';
          resolve({ resource, status });
        }
      );
    });
  });
  Promise.all(statuses).then(data => res.json(data));
});

app.listen(port, () => console.log(`Backend running on port ${port}`));