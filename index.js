import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pool from './db.js'; // Adjust the path as necessary
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Load environment variables
dotenv.config();

// Ensure JWT_SECRET is set
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set in environment variables.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// Create Express app
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['*']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Debug middleware
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  console.log('Request headers:', req.headers);
  console.log('Request body:', req.body);
  next();
});


// Check DB connection
app.get('/api/health', async (req, res) => {
  try {
    const client = await pool.connect();
    client.release();
    res.status(200).json({ status: 'Database connection successful' });
  } catch (error) {
    console.error('Database connection failed:', error);
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    console.log('Authenticated user:', user);
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Apply authentication middleware to protected routes
app.use('/api/tasks', authenticateToken);
app.use('/api/color-mix-formulas', authenticateToken);

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { userId, name } = req.body;
    console.log('[LOGIN] Received:', { userId, name });
    if (!userId || !name) {
      console.log('[LOGIN] Missing userId or name');
      return res.status(400).json({ message: 'User ID and Name are required' });
    }
    let rows;
    try {
      const result = await pool.query(
        'SELECT * FROM users WHERE user_id = $1 AND name = $2',
        [userId, name]
      );
      rows = result.rows;
    } catch (dbError) {
      console.error('[LOGIN] Database error:', dbError);
      if (dbError.code === 'ECONNREFUSED') {
        return res.status(500).json({ message: 'Database connection failed. Please check DB status.' });
      }
      return res.status(500).json({ message: dbError.message || 'Database error' });
    }
    console.log('[LOGIN] DB rows:', rows);
    if (rows.length === 0) {
      console.log('[LOGIN] Invalid credentials');
      return res.status(401).json({ message: 'Invalid User ID or Name' });
    }
    const user = rows[0];
    // Create JWT token
    const token = jwt.sign(
      { id: user.id, userId: user.user_id, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '1d' }
    );
    console.log('[LOGIN] Success for user:', user.user_id, 'role:', user.role);
    res.status(200).json({
      token,
      user: {
        id: user.id,
        userId: user.user_id,
        name: user.name,
        role: user.role,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: error.message || 'Server error' });
  }
});

// Verify token
app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    const rows = result.rows;

    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = rows[0];

    res.status(200).json({
      user: {
        id: user.id,
        userId: user.userId,
        name: user.name,
        role: user.role,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// User Routes
// GET /api/users is public
app.get('/api/users', async (req, res) => {
  try {
    console.log('[GET /api/users] Fetching all users');
    const result = await pool.query('SELECT * FROM users');
    const rows = result.rows;
    console.log(`[GET /api/users] Found ${rows.length} users:`, rows);
    res.status(200).json(rows);
  } catch (error) {
    console.error('[GET /api/users] Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/workers - Get only workers
app.get('/api/workers', async (req, res) => {
  try {
    console.log('[GET /api/workers] Fetching workers only');
    const result = await pool.query('SELECT id, user_id, name, role, created_at FROM users WHERE role = $1', ['worker']);
    const rows = result.rows;
    console.log(`[GET /api/workers] Found ${rows.length} workers:`, rows);
    res.status(200).json(rows);
  } catch (error) {
    console.error('[GET /api/workers] Error fetching workers:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST/PUT/DELETE require authentication and admin/super_admin
function requireAdminOrSuperAdmin(req, res, next) {
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'super_admin')) {
    return res.status(403).json({ message: 'Forbidden: Admin or Super Admin only' });
  }
  next();
}

app.post('/api/users', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { userId, name, role } = req.body;

    if (!userId || !name || !role) {
      return res.status(400).json({ message: 'User ID, Name, and Role are required' });
    }

    // Check if user already exists
    const result = await pool.query('SELECT * FROM users WHERE userId = $1', [userId]);
    const existingUsers = result.rows;

    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'User ID already exists' });
    }

    const newUserResult = await pool.query(
      'INSERT INTO users (userId, name, role) VALUES ($1, $2, $3) RETURNING *',
      [userId, name, role]
    );

    const newUser = newUserResult.rows[0];

    res.status(201).json(newUser);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user
app.put('/api/users/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, name, role } = req.body;
    if (!userId || !name || !role) {
      return res.status(400).json({ message: 'User ID, Name, and Role are required' });
    }
    const result = await pool.query(
      'UPDATE users SET userId = $1, name = $2, role = $3 WHERE id = $4',
      [userId, name, role, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const updatedUserResult = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const updatedUser = updatedUserResult.rows[0];
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete user
app.delete('/api/users/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Machine Routes
app.get('/api/machines', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM machines');
    const rows = result.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching machines:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/machines', authenticateToken, async (req, res) => {
  try {
    const { name, description, status } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Machine name is required' });
    }
    const result = await pool.query(
      'INSERT INTO machines (name, description, status) VALUES ($1, $2, $3) RETURNING *',
      [name, description || '', status || 'active']
    );
    const newMachine = result.rows[0];
    res.status(201).json(newMachine);
  } catch (error) {
    console.error('Error creating machine:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update machine
app.put('/api/machines/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Machine name is required' });
    }
    const result = await pool.query(
      'UPDATE machines SET name = $1, description = $2, status = $3 WHERE id = $4',
      [name, description || '', status || 'active', id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Machine not found' });
    }
    const updatedMachineResult = await pool.query('SELECT * FROM machines WHERE id = $1', [id]);
    const updatedMachine = updatedMachineResult.rows[0];
    res.status(200).json(updatedMachine);
  } catch (error) {
    console.error('Error updating machine:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete machine
app.delete('/api/machines/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM machines WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Machine not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting machine:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Raw Material Routes
app.get('/api/materials', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM raw_materials');
    const rows = result.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching raw materials:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/materials', async (req, res) => {
  try {
    const { name, quantity, unit, threshold, description } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ message: 'Name, quantity, and unit are required' });
    }

    const result = await pool.query(
      'INSERT INTO raw_materials (name, quantity, unit, threshold, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, quantity, unit, threshold || 0, description || '']
    );

    const newMaterial = result.rows[0];

    res.status(201).json(newMaterial);
  } catch (error) {
    console.error('Error creating raw material:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update material
app.put('/api/materials/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, quantity, unit, threshold, description } = req.body;
    if (!name || quantity == null || !unit) {
      return res.status(400).json({ message: 'Name, quantity, and unit are required' });
    }
    const result = await pool.query(
      'UPDATE raw_materials SET name = $1, quantity = $2, unit = $3, threshold = $4, description = $5 WHERE id = $6',
      [name, quantity, unit, threshold || 0, description || '', id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Material not found' });
    }
    const updatedMaterialResult = await pool.query('SELECT * FROM raw_materials WHERE id = $1', [id]);
    const updatedMaterial = updatedMaterialResult.rows[0];
    res.status(200).json(updatedMaterial);
  } catch (error) {
    console.error('Error updating material:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete material
app.delete('/api/materials/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM raw_materials WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Material not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting material:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Color Mix Formulas CRUD
app.get('/api/color-mix-formulas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM color_mix_formulas');
    const rows = result.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching color mix formulas:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/color-mix-formulas', async (req, res) => {
  try {
    const { name, materialCount, formula, colorWeight, createdBy } = req.body;
    if (!name || !materialCount || !formula || !colorWeight || !createdBy) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'INSERT INTO color_mix_formulas (name, materialCount, formula, colorWeight, createdBy) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, materialCount, formula, colorWeight, createdBy]
    );
    const newFormula = result.rows[0];
    res.status(201).json(newFormula);
  } catch (error) {
    console.error('Error creating color mix formula:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/color-mix-formulas/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, materialCount, formula, colorWeight } = req.body;
    if (!name || !materialCount || !formula || !colorWeight) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'UPDATE color_mix_formulas SET name = $1, materialCount = $2, formula = $3, colorWeight = $4 WHERE id = $5',
      [name, materialCount, formula, colorWeight, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Formula not found' });
    }
    const updatedFormulaResult = await pool.query('SELECT * FROM color_mix_formulas WHERE id = $1', [id]);
    const updatedFormula = updatedFormulaResult.rows[0];
    res.status(200).json(updatedFormula);
  } catch (error) {
    console.error('Error updating color mix formula:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/color-mix-formulas/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM color_mix_formulas WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Formula not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting color mix formula:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Color Mix Entries CRUD
app.get('/api/color-mix-entries', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT cme.*, cmf.name as formulaName, cmf.formula as formulaJson
      FROM color_mix_entries cme
      JOIN color_mix_formulas cmf ON cme.formula_id = cmf.id
    `);
    const rows = result.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching color mix entries:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/color-mix-entries', async (req, res) => {
  try {
    const { formulaId, materialWeights, colorRequirement } = req.body;
    console.log('Received materialWeights:', materialWeights, 'Type:', typeof materialWeights);
    if (!formulaId || !materialWeights || !colorRequirement) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    // Accept native array for materialWeights and store as JSON string
    let parsedMaterialWeights = materialWeights;
    if (typeof materialWeights === 'string') {
      try {
        parsedMaterialWeights = JSON.parse(materialWeights);
      } catch (e) {
        return res.status(400).json({ message: 'Invalid materialWeights format' });
      }
    }
    let standardizedMaterialWeights;
    if (Array.isArray(parsedMaterialWeights)) {
      standardizedMaterialWeights = parsedMaterialWeights.map(entry => ({
        materialId: String(entry.materialId),
        quantity: String(entry.quantity)
      }));
    } else if (typeof parsedMaterialWeights === 'object' && parsedMaterialWeights !== null) {
      standardizedMaterialWeights = Object.entries(parsedMaterialWeights).map(([materialId, quantity]) => ({
        materialId: String(materialId),
        quantity: String(quantity)
      }));
    } else {
      return res.status(400).json({ message: 'Invalid materialWeights format' });
    }
    // Store as JSON string for MariaDB JSON column (no CAST)
    const result = await pool.query(
      'INSERT INTO color_mix_entries (formulaId, materialWeights, colorRequirement) VALUES ($1, $2, $3) RETURNING *',
      [formulaId, JSON.stringify(standardizedMaterialWeights), colorRequirement]
    );
    const newEntry = result.rows[0];
    res.status(201).json(newEntry);
  } catch (error) {
    console.error('Error creating color mix entry:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/color-mix-entries/:id', async (req, res) => {
  try {
    let { id } = req.params;
    const { formulaId, materialWeights, colorRequirement } = req.body;
    console.log('PUT /api/color-mix-entries/:id', { id, type: typeof id, formulaId, materialWeights, colorRequirement });
    if (!formulaId || !materialWeights || !colorRequirement) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    // Ensure id is a number
    id = Number(id);
    if (isNaN(id)) {
      return res.status(400).json({ message: 'Invalid id parameter' });
    }
    // Accept native array for materialWeights and store as JSON string
    let parsedMaterialWeights = materialWeights;
    if (typeof materialWeights === 'string') {
      try {
        parsedMaterialWeights = JSON.parse(materialWeights);
      } catch (e) {
        return res.status(400).json({ message: 'Invalid materialWeights format' });
      }
    }
    let standardizedMaterialWeights;
    if (Array.isArray(parsedMaterialWeights)) {
      standardizedMaterialWeights = parsedMaterialWeights.map(entry => ({
        materialId: String(entry.materialId),
        quantity: String(entry.quantity)
      }));
    } else if (typeof parsedMaterialWeights === 'object' && parsedMaterialWeights !== null) {
      standardizedMaterialWeights = Object.entries(parsedMaterialWeights).map(([materialId, quantity]) => ({
        materialId: String(materialId),
        quantity: String(quantity)
      }));
    } else {
      return res.status(400).json({ message: 'Invalid materialWeights format' });
    }
    // Store as JSON string for MariaDB JSON column (no CAST)
    const result = await pool.query(
      'UPDATE color_mix_entries SET formulaId = $1, materialWeights = $2, colorRequirement = $3 WHERE id = $4',
      [formulaId, JSON.stringify(standardizedMaterialWeights), colorRequirement, id]
    );
    console.log('Update result:', result);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Color mix entry not found' });
    }
    const updatedEntryResult = await pool.query('SELECT * FROM color_mix_entries WHERE id = $1', [id]);
    const updatedEntry = updatedEntryResult.rows[0];
    res.status(200).json(updatedEntry);
  } catch (error) {
    console.error('Error updating color mix entry:', error);
    if (error && error.stack) console.error(error.stack);
    res.status(500).json({ message: 'Server error', error: error.message, received: req.body });
  }
});

app.delete('/api/color-mix-entries/:id', async (req, res) => {
  try {
    const { id } = req.params;
    console.log('DELETE /api/color-mix-entries/:id', { id });
    const result = await pool.query('DELETE FROM color_mix_entries WHERE id = $1', [id]);
    console.log('Delete result:', result);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Color mix entry not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting color mix entry:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Moulds Routes
app.get('/api/moulds', async (req, res) => {
  try {
    // Check if moulds table exists in PostgreSQL
    const result = await pool.query(`
      SELECT 1 FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'moulds'
    `);
    if (result.rowCount === 0) {
      // Create moulds table if it doesn't exist
      await pool.query(`
        CREATE TABLE IF NOT EXISTS moulds (
          id SERIAL PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          description TEXT,
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance')),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
    }
    const mouldsResult = await pool.query('SELECT * FROM moulds');
    const rows = mouldsResult.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching moulds:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/moulds', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { name, description, status } = req.body;
    console.log('Received mould data:', req.body);

    if (!name) {
      return res.status(400).json({ message: 'Mould name is required' });
    }

    // Check if moulds table exists
    const result = await pool.query('SHOW TABLES LIKE "moulds"');
    const tables = result.rows;
    if (tables.length === 0) {
      // Create moulds table if it doesn't exist
      await pool.query(`
        CREATE TABLE IF NOT EXISTS moulds (
          id SERIAL PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          description TEXT,
          status ENUM('active', 'inactive', 'maintenance') DEFAULT 'active',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
      `);
    }

    const newMouldResult = await pool.query(
      'INSERT INTO moulds (name, description, status) VALUES ($1, $2, $3) RETURNING *',
      [name, description || '', status || 'active']
    );

    const newMould = newMouldResult.rows[0];
    res.status(201).json(newMould);
  } catch (error) {
    console.error('Error creating mould:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/moulds/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Mould name is required' });
    }

    const result = await pool.query(
      'UPDATE moulds SET name = $1, description = $2, status = $3 WHERE id = $4',
      [name, description || '', status || 'active', id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Mould not found' });
    }

    const updatedMouldResult = await pool.query('SELECT * FROM moulds WHERE id = $1', [id]);
    const updatedMould = updatedMouldResult.rows[0];
    res.status(200).json(updatedMould);
  } catch (error) {
    console.error('Error updating mould:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.delete('/api/moulds/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM moulds WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Mould not found' });
    }

    res.status(204).send();
  } catch (error) {
    console.error('Error deleting mould:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Products Routes (CRUD for products table with correct schema)
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    const rows = result.rows;
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, description, category, status, perhourproduction } = req.body;

    if (!name || !category) {
      return res.status(400).json({ message: 'Product name and category are required' });
    }

    const result = await pool.query(
      'INSERT INTO products (name, description, category, status, perhourproduction) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description || null, category, status || 'active', perhourproduction || null]
    );

    const newProduct = result.rows[0];
    res.status(201).json(newProduct);
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, category, status, perhourproduction } = req.body;

    if (!name || !category) {
      return res.status(400).json({ message: 'Product name and category are required' });
    }

    const result = await pool.query(
      'UPDATE products SET name = $1, description = $2, category = $3, status = $4, perhourproduction = $5 WHERE id = $6',
      [name, description || null, category, status || 'active', perhourproduction || null, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const updatedProductResult = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
    const updatedProduct = updatedProductResult.rows[0];
    res.status(200).json(updatedProduct);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM products WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(204).send();
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Test route to verify server is working
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is working' });
});

// Tasks Routes
app.get('/api/tasks', async (req, res) => {
  console.log('[GET /api/tasks] Fetching all tasks');
  try {
    const { machine_id, mould_id, product_id, worker_id, status } = req.query;
    let whereClauses = [];
    let params = [];
    let paramIndex = 1;

    // Only filter by worker_id if the user is a worker
    if (req.user && req.user.role === 'worker') {
      whereClauses.push(`t.worker_id = $${paramIndex++}`);
      params.push(req.user.id);
    } else if (worker_id && worker_id !== '' && !isNaN(Number(worker_id))) {
      whereClauses.push(`t.worker_id = $${paramIndex++}`);
      params.push(Number(worker_id));
    }

    if (machine_id && machine_id !== '' && !isNaN(Number(machine_id))) {
      whereClauses.push(`t.machine_id = $${paramIndex++}`);
      params.push(Number(machine_id));
    }
    if (mould_id && mould_id !== '' && !isNaN(Number(mould_id))) {
      whereClauses.push(`t.mould_id = $${paramIndex++}`);
      params.push(Number(mould_id));
    }
    if (product_id && product_id !== '' && !isNaN(Number(product_id))) {
      whereClauses.push(`t.product_id = $${paramIndex++}`);
      params.push(Number(product_id));
    }
    if (status && status !== '') {
      whereClauses.push(`t.status = $${paramIndex++}`);
      params.push(status);
    }

    const where = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';
    const query = `
      SELECT t.*, 
        m.name as machine_name,
        mo.name as mould_name,
        p.name as product_name,
        cm.name as color_mix_name,
        u.name as worker_name,
        COALESCE(SUM(hpl.total_pieces), 0) as completed_pieces
      FROM tasks t
      LEFT JOIN machines m ON t.machine_id = m.id
      LEFT JOIN moulds mo ON t.mould_id = mo.id
      LEFT JOIN products p ON t.product_id = p.id
      LEFT JOIN color_mix_formulas cm ON t.color_mix_id = cm.id
      LEFT JOIN users u ON t.worker_id = u.id
      LEFT JOIN hourly_production_logs hpl ON t.id = hpl.id
      ${where}
      GROUP BY t.id, m.name, mo.name, p.name, cm.name, u.name
      ORDER BY t.created_at DESC
    `;
    const result = await pool.query(query, params);
    const tasks = result.rows;
    console.log(`[GET /api/tasks] Successfully fetched ${tasks.length} tasks`);
    res.status(200).json(tasks);
  } catch (error) {
    console.error('[GET /api/tasks] Error fetching tasks:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/tasks', async (req, res) => {
  console.log('[POST /api/tasks] Creating new task');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  try {
    const {
      name,
      description,
      machine_id,
      mould_id,
      product_id,
      color_mix_id,
      worker_id,
      target,
      status = 'pending'
    } = req.body;

    // Validate required fields
    if (!name || !machine_id || !mould_id || !product_id || !color_mix_id || !worker_id || target === undefined) {
      console.log('Missing required fields:', {
        name: !name,
        machine_id: !machine_id,
        mould_id: !mould_id,
        product_id: !product_id,
        color_mix_id: !color_mix_id,
        worker_id: !worker_id,
        target: target === undefined
      });
      return res.status(400).json({
        message: 'Missing required fields',
        missing: {
          name: !name,
          machine_id: !machine_id,
          mould_id: !mould_id,
          product_id: !product_id,
          color_mix_id: !color_mix_id,
          worker_id: !worker_id,
          target: target === undefined
        }
      });
    }

    // Verify all foreign keys exist
    console.log('Verifying foreign keys...');
    const machineResult = await pool.query('SELECT id FROM machines WHERE id = $1', [machine_id]);
    const mouldResult = await pool.query('SELECT id FROM moulds WHERE id = $1', [mould_id]);
    const productResult = await pool.query('SELECT id FROM products WHERE id = $1', [product_id]);
    const colorMixResult = await pool.query('SELECT id FROM color_mix_formulas WHERE id = $1', [color_mix_id]);
    const workerResult = await pool.query('SELECT id FROM users WHERE id = $1', [worker_id]);

    const machine = machineResult.rows;
    const mould = mouldResult.rows;
    const product = productResult.rows;
    const colorMix = colorMixResult.rows;
    const worker = workerResult.rows;

    console.log('Foreign key check results:', {
      machine: machine.length > 0,
      mould: mould.length > 0,
      product: product.length > 0,
      colorMix: colorMix.length > 0,
      worker: worker.length > 0
    });

    if (!machine.length || !mould.length || !product.length || !colorMix.length || !worker.length) {
      return res.status(400).json({
        message: 'Invalid foreign key references',
        invalid: {
          machine: !machine.length,
          mould: !mould.length,
          product: !product.length,
          colorMix: !colorMix.length,
          worker: !worker.length
        }
      });
    }

    const insertQuery = `
      INSERT INTO tasks (
        name, 
        description, 
        machine_id, 
        mould_id, 
        product_id, 
        color_mix_id, 
        worker_id, 
        target, 
        status, 
        created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `;

    const insertParams = [
      name,
      description || null,
      Number(machine_id),
      Number(mould_id),
      Number(product_id),
      Number(color_mix_id),
      Number(worker_id),
      Number(target),
      status,
      req.user?.id || 1
    ];

    console.log('Insert query:', insertQuery);
    console.log('Insert parameters:', insertParams);

    const result = await pool.query(insertQuery, insertParams);
    console.log('Insert result:', result);

    // Fetch the created task with related data
    const selectQuery = `
      SELECT t.*, 
        m.name as machine_name,
        mo.name as mould_name,
        p.name as product_name,
        cm.name as color_mix_name,
        u.name as worker_name,
        COALESCE(SUM(hpl.total_pieces), 0) as completed_pieces
      FROM tasks t
      LEFT JOIN machines m ON t.machine_id = m.id
      LEFT JOIN moulds mo ON t.mould_id = mo.id
      LEFT JOIN products p ON t.product_id = p.id
      LEFT JOIN color_mix_formulas cm ON t.color_mix_id = cm.id
      LEFT JOIN users u ON t.worker_id = u.id
      LEFT JOIN hourly_production_logs hpl ON t.id = hpl.id
      WHERE t.id = $1
      GROUP BY t.id
    `;

    console.log('Select query:', selectQuery);
    console.log('Select parameters:', [result.insertId]);

    const newTaskResult = await pool.query(selectQuery, [result.insertId]);
    const newTask = newTaskResult.rows[0];
    console.log('Created task:', newTask);

    res.status(201).json(newTask);
  } catch (error) {
    console.error('[POST /api/tasks] Error creating task:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/tasks/:id', async (req, res) => {
  console.log('[PUT /api/tasks/:id] Updating task');
  console.log('Task ID:', req.params.id);
  console.log('Request body:', JSON.stringify(req.body, null, 2));

  try {
    const { id } = req.params;
    const {
      name,
      description,
      machine_id,
      mould_id,
      product_id,
      color_mix_id,
      worker_id,
      target,
      status
    } = req.body;

    // Allow status-only update if only status is present
    if (Object.keys(req.body).length === 1 && req.body.status !== undefined) {
      console.log('Performing status-only update');
      const statusQuery = 'UPDATE tasks SET status = $1 WHERE id = $2';
      const statusParams = [status, id];

      console.log('Status update query:', statusQuery);
      console.log('Status update parameters:', statusParams);

      const result = await pool.query(statusQuery, statusParams);
      console.log('Status update result:', result);

      if (result.rowCount === 0) {
        console.log('Task not found for status update');
        return res.status(404).json({ message: 'Task not found' });
      }
    } else {
      console.log('Performing full update');
      // Full update requires all fields
      if (!name || !machine_id || !mould_id || !product_id || !color_mix_id || !worker_id || target === undefined) {
        console.log('Missing fields:', {
          name: !name,
          machine_id: !machine_id,
          mould_id: !mould_id,
          product_id: !product_id,
          color_mix_id: !color_mix_id,
          worker_id: !worker_id,
          target: target === undefined
        });
        return res.status(400).json({
          message: 'All fields are required for full update',
          missing: {
            name: !name,
            machine_id: !machine_id,
            mould_id: !mould_id,
            product_id: !product_id,
            color_mix_id: !color_mix_id,
            worker_id: !worker_id,
            target: target === undefined
          }
        });
      }

      // Verify all foreign keys exist
      console.log('Verifying foreign keys...');
      const machineResult = await pool.query('SELECT id FROM machines WHERE id = $1', [machine_id]);
      const mouldResult = await pool.query('SELECT id FROM moulds WHERE id = $1', [mould_id]);
      const productResult = await pool.query('SELECT id FROM products WHERE id = $1', [product_id]);
      const colorMixResult = await pool.query('SELECT id FROM color_mix_formulas WHERE id = $1', [color_mix_id]);
      const workerResult = await pool.query('SELECT id FROM users WHERE id = $1', [worker_id]);

      const machine = machineResult.rows;
      const mould = mouldResult.rows;
      const product = productResult.rows;
      const colorMix = colorMixResult.rows;
      const worker = workerResult.rows;

      console.log('Foreign key check results:', {
        machine: machine.length > 0,
        mould: mould.length > 0,
        product: product.length > 0,
        colorMix: colorMix.length > 0,
        worker: worker.length > 0
      });

      if (!machine.length || !mould.length || !product.length || !colorMix.length || !worker.length) {
        return res.status(400).json({
          message: 'Invalid foreign key references',
          invalid: {
            machine: !machine.length,
            mould: !mould.length,
            product: !product.length,
            colorMix: !colorMix.length,
            worker: !worker.length
          }
        });
      }

      const updateQuery = `
        UPDATE tasks 
        SET name = $1,
            description = $2,
            machine_id = $3,
            mould_id = $4,
            product_id = $5,
            color_mix_id = $6,
            worker_id = $7,
            target = $8,
            status = $9
        WHERE id = $10
      `;

      const updateParams = [
        name,
        description || null,
        Number(machine_id),
        Number(mould_id),
        Number(product_id),
        Number(color_mix_id),
        Number(worker_id),
        Number(target),
        status || 'pending',
        id
      ];

      console.log('Update query:', updateQuery);
      console.log('Update parameters:', updateParams);

      const result = await pool.query(updateQuery, updateParams);
      console.log('Update result:', result);

      if (result.rowCount === 0) {
        console.log('Task not found for full update');
        return res.status(404).json({ message: 'Task not found' });
      }
    }

    // Fetch updated task with related data
    const selectQuery = `
      SELECT t.*, 
        m.name as machine_name,
        mo.name as mould_name,
        p.name as product_name,
        cm.name as color_mix_name,
        u.name as worker_name,
        COALESCE(SUM(hpl.total_pieces), 0) as completed_pieces
      FROM tasks t
      LEFT JOIN machines m ON t.machine_id = m.id
      LEFT JOIN moulds mo ON t.mould_id = mo.id
      LEFT JOIN products p ON t.product_id = p.id
      LEFT JOIN color_mix_formulas cm ON t.color_mix_id = cm.id
      LEFT JOIN users u ON t.worker_id = u.id
      LEFT JOIN hourly_production_logs hpl ON t.id = hpl.id
      WHERE t.id = $1
      GROUP BY t.id
    `;

    console.log('Select query:', selectQuery);
    console.log('Select parameters:', [id]);

    const updatedTaskResult = await pool.query(selectQuery, [id]);
    const updatedTask = updatedTaskResult.rows[0];
    console.log('Updated task:', updatedTask);

    if (!updatedTask) {
      console.log('Task not found after update');
      return res.status(404).json({ message: 'Task not found after update' });
    }

    res.status(200).json(updatedTask);
  } catch (error) {
    console.error('[PUT /api/tasks/:id] Error updating task:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      message: 'Server error',
      error: error.message,
      details: error
    });
  }
});

app.delete('/api/tasks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM tasks WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }

    res.status(204).send();
  } catch (error) {
    console.error('[DELETE /api/tasks/:id] Error deleting task:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Hourly Production Logs API
app.get('/api/hourly-production-logs/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    const result = await pool.query(
      'SELECT * FROM hourly_production_logs WHERE id = $1 ORDER BY created_at DESC, hour DESC',
      [taskId]
    );
    const logs = result.rows;
    res.status(200).json(logs);
  } catch (error) {
    console.error('Error fetching hourly production logs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/hourly-production-logs', async (req, res) => {
  try {
    const {
      taskId,
      hour,
      totalPieces,
      perfectPieces,
      defectPieces,
      date,
      defective_weight,
      wastage_weight,
      perfect_weight,
      remarks
    } = req.body;

    if (!taskId || !hour || !date) {
      return res.status(400).json({
        message: 'Task ID, hour, and date are required fields',
        missing: {
          taskId: !taskId,
          hour: !hour,
          date: !date
        }
      });
    }

    // Verify task exists
    const taskResult = await pool.query('SELECT id FROM tasks WHERE id = $1', [taskId]);
    const task = taskResult.rows;
    if (!task.length) {
      return res.status(400).json({ message: 'Invalid task ID' });
    }

    const result = await pool.query(
      `INSERT INTO hourly_production_logs 
       (id, hour, totalPieces, perfectPieces, defectPieces, date, 
        defective_weight, wastage_weight, perfect_weight, remarks) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        taskId,
        hour,
        totalPieces || 0,
        perfectPieces || 0,
        defectPieces || 0,
        date,
        defective_weight || null,
        wastage_weight || null,
        perfect_weight || null,
        remarks || ''
      ]
    );

    const insertedRecord = result.rows[0];

    res.status(201).json(insertedRecord);
  } catch (error) {
    console.error('Error creating hourly production log:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/hourly-production-logs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      hour,
      totalPieces,
      perfectPieces,
      defectPieces,
      date,
      defective_weight,
      wastage_weight,
      perfect_weight,
      remarks
    } = req.body;

    if (!hour || !date) {
      return res.status(400).json({ message: 'Hour and date are required' });
    }

    const result = await pool.query(
      `UPDATE hourly_production_logs 
       SET hour = $1, 
           totalPieces = $2, 
           perfectPieces = $3, 
           defectPieces = $4, 
           date = $5, 
           defective_weight = $6, 
           wastage_weight = $7, 
           perfect_weight = $8, 
           remarks = $9
       WHERE id = $10`,
      [
        hour,
        totalPieces || 0,
        perfectPieces || 0,
        defectPieces || 0,
        date,
        defective_weight || null,
        wastage_weight || null,
        perfect_weight || null,
        remarks || '',
        id
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Hourly production log not found' });
    }

    const updatedRecordResult = await pool.query(
      'SELECT * FROM hourly_production_logs WHERE id = $1',
      [id]
    );

    const updatedRecord = updatedRecordResult.rows[0];

    res.status(200).json(updatedRecord);
  } catch (error) {
    console.error('Error updating hourly production log:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.delete('/api/hourly-production-logs/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // First check if the record exists
    const recordResult = await pool.query(
      'SELECT id FROM hourly_production_logs WHERE id = $1',
      [id]
    );

    const record = recordResult.rows;
    if (record.length === 0) {
      return res.status(404).json({ message: 'Hourly production log not found' });
    }

    // If record exists, proceed with deletion
    const result = await pool.query(
      'DELETE FROM hourly_production_logs WHERE id = $1',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Failed to delete hourly production log' });
    }

    res.status(204).send();
  } catch (error) {
    console.error('Error deleting hourly production log:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Utility function to format JS Date to MySQL DATETIME string
function toMySQLDateTime(date) {
  if (!date) return null;
  const d = new Date(date);
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler caught:', err);
  console.error('Error stack:', err.stack);
  console.error('Error details:', {
    message: err.message,
    code: err.code,
    errno: err.errno,
    sqlState: err.sqlState,
    sqlMessage: err.sqlMessage
  });

  res.status(500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log('Registered routes:');
  app._router.stack.forEach((r) => {
    if (r.route && r.route.path) {
      console.log(`${Object.keys(r.route.methods).join(', ').toUpperCase()} ${r.route.path}`);
    }
  });
});