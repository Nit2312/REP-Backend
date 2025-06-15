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

const allowedOrigins = [
  'https://rep-frontend-beryl.vercel.app',
  'https://rep-backend.onrender.com', 
  'http://localhost:5173',
  'http://localhost:5000'

];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
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
app.get('/api/users', async (req, res) => {
  try {
    console.log('[GET /api/users] Fetching all users');
    const result = await pool.query('SELECT id, user_id, name, role, created_at, updated_at FROM users ORDER BY created_at DESC');
    const rows = result.rows;
    console.log(`[GET /api/users] Found ${rows.length} users:`, rows);
    res.status(200).json(rows);
  } catch (error) {
    console.error('[GET /api/users] Error fetching users:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
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

    // Check if user_id already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE user_id = $1', [userId]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User ID already exists' });
    }

    const result = await pool.query(
      'INSERT INTO users (user_id, name, role) VALUES ($1, $2, $3) RETURNING *',
      [userId, name, role]
    );
    const newUser = result.rows[0];
    console.log('[POST /api/users] Created new user:', newUser);
    res.status(201).json(newUser);
  } catch (error) {
    console.error('[POST /api/users] Error creating user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/users/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, name, role } = req.body;
    if (!userId || !name || !role) {
      return res.status(400).json({ message: 'User ID, Name, and Role are required' });
    }

    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (existingUser.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if new user_id is already taken by another user
    const duplicateUser = await pool.query(
      'SELECT * FROM users WHERE user_id = $1 AND id != $2',
      [userId, id]
    );
    if (duplicateUser.rows.length > 0) {
      return res.status(400).json({ message: 'User ID already exists' });
    }

    const result = await pool.query(
      'UPDATE users SET user_id = $1, name = $2, role = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *',
      [userId, name, role, id]
    );
    const updatedUser = result.rows[0];
    console.log('[PUT /api/users/:id] Updated user:', updatedUser);
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error('[PUT /api/users/:id] Error updating user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.delete('/api/users/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (existingUser.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user is referenced in any tasks
    const tasksResult = await pool.query('SELECT COUNT(*) FROM tasks WHERE worker_id = $1', [id]);
    if (parseInt(tasksResult.rows[0].count) > 0) {
      return res.status(400).json({ message: 'Cannot delete user: User is assigned to tasks' });
    }

    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    console.log('[DELETE /api/users/:id] Deleted user:', id);
    res.status(204).send();
  } catch (error) {
    console.error('[DELETE /api/users/:id] Error deleting user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Machine Routes
app.get('/api/machines', async (req, res) => {
  try {
    const machinesResult = await pool.query('SELECT * FROM machines ORDER BY created_at DESC');
    res.status(200).json(machinesResult.rows);
  } catch (error) {
    console.error('Error fetching machines:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/machines', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { name, description, status } = req.body;
    console.log('Received machine data:', req.body);

    if (!name) {
      return res.status(400).json({ message: 'Machine name is required' });
    }

    // Check if machine with same name exists
    const existingMachine = await pool.query(
      'SELECT id FROM machines WHERE name = $1',
      [name]
    );

    if (existingMachine.rows.length > 0) {
      return res.status(400).json({ message: 'A machine with this name already exists' });
    }

    // Insert new machine
    const newMachineResult = await pool.query(
      'INSERT INTO machines (name, description, status) VALUES ($1, $2, $3) RETURNING *',
      [name, description || '', status || 'active']
    );

    const newMachine = newMachineResult.rows[0];
    console.log('Created new machine:', newMachine);
    res.status(201).json(newMachine);
  } catch (error) {
    console.error('Error creating machine:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

app.put('/api/machines/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Machine name is required' });
    }

    // Check if machine exists
    const existingMachine = await pool.query(
      'SELECT id FROM machines WHERE id = $1',
      [id]
    );

    if (existingMachine.rows.length === 0) {
      return res.status(404).json({ message: 'Machine not found' });
    }

    // Check if name is already taken by another machine
    const nameCheck = await pool.query(
      'SELECT id FROM machines WHERE name = $1 AND id != $2',
      [name, id]
    );

    if (nameCheck.rows.length > 0) {
      return res.status(400).json({ message: 'A machine with this name already exists' });
    }

    // Update machine
    const updateResult = await pool.query(
      'UPDATE machines SET name = $1, description = $2, status = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *',
      [name, description || '', status || 'active', id]
    );

    const updatedMachine = updateResult.rows[0];
    console.log('Updated machine:', updatedMachine);
    res.status(200).json(updatedMachine);
  } catch (error) {
    console.error('Error updating machine:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

app.delete('/api/machines/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if machine exists
    const existingMachine = await pool.query(
      'SELECT id FROM machines WHERE id = $1',
      [id]
    );

    if (existingMachine.rows.length === 0) {
      return res.status(404).json({ message: 'Machine not found' });
    }

    // Check if machine is referenced in any tasks
    const taskCheck = await pool.query(
      'SELECT id FROM tasks WHERE machine_id = $1',
      [id]
    );

    if (taskCheck.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Cannot delete machine as it is referenced in existing tasks',
        taskCount: taskCheck.rows.length
      });
    }

    // Delete machine
    await pool.query('DELETE FROM machines WHERE id = $1', [id]);
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting machine:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

// Raw Material Routes
app.get('/api/materials', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM raw_materials ORDER BY created_at DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching raw materials:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/materials', async (req, res) => {
  try {
    console.log('[POST /api/materials] Received request body:', req.body);
    const { name, quantity, unit, threshold, description } = req.body;
    
    // Validate required fields
    if (!name || !quantity || !unit) {
      console.log('[POST /api/materials] Missing required fields:', { name, quantity, unit });
      return res.status(400).json({ message: 'Name, quantity, and unit are required' });
    }

    // Validate numeric fields
    if (isNaN(Number(quantity)) || Number(quantity) < 0) {
      console.log('[POST /api/materials] Invalid quantity:', quantity);
      return res.status(400).json({ message: 'Quantity must be a positive number' });
    }
    if (threshold !== undefined && (isNaN(Number(threshold)) || Number(threshold) < 0)) {
      console.log('[POST /api/materials] Invalid threshold:', threshold);
      return res.status(400).json({ message: 'Threshold must be a positive number' });
    }

    // Check for duplicate name
    console.log('[POST /api/materials] Checking for duplicate name:', name);
    const dup = await pool.query('SELECT * FROM raw_materials WHERE name = $1', [name]);
    if (dup.rows.length > 0) {
      console.log('[POST /api/materials] Duplicate name found');
      return res.status(400).json({ message: 'Material name already exists' });
    }

    // Insert new material
    console.log('[POST /api/materials] Attempting to insert material:', {
      name,
      quantity: Number(quantity),
      unit,
      threshold: threshold ? Number(threshold) : 0,
      description: description || ''
    });

    const insertQuery = `
      INSERT INTO raw_materials (name, quantity, unit, threshold, description) 
      VALUES ($1, $2, $3, $4, $5) 
      RETURNING *
    `;
    const insertParams = [
      name,
      Number(quantity),
      unit,
      threshold ? Number(threshold) : 0,
      description || ''
    ];

    console.log('[POST /api/materials] Executing query:', insertQuery);
    console.log('[POST /api/materials] With parameters:', insertParams);

    const result = await pool.query(insertQuery, insertParams);

    console.log('[POST /api/materials] Successfully inserted material:', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('[POST /api/materials] Error creating raw material:', error);
    console.error('[POST /api/materials] Error details:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      hint: error.hint,
      where: error.where,
      schema: error.schema,
      table: error.table,
      column: error.column,
      dataType: error.dataType,
      constraint: error.constraint,
      stack: error.stack
    });
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack,
      code: error.code,
      detail: error.detail,
      hint: error.hint
    });
  }
});

app.put('/api/materials/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, quantity, unit, threshold, description } = req.body;

    // Validate required fields
    if (!name || !quantity || !unit) {
      return res.status(400).json({ message: 'Name, quantity, and unit are required' });
    }

    // Validate numeric fields
    if (isNaN(Number(quantity)) || Number(quantity) < 0) {
      return res.status(400).json({ message: 'Quantity must be a positive number' });
    }
    if (threshold !== undefined && (isNaN(Number(threshold)) || Number(threshold) < 0)) {
      return res.status(400).json({ message: 'Threshold must be a positive number' });
    }

    // Check if material exists
    const existing = await pool.query('SELECT * FROM raw_materials WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ message: 'Material not found' });
    }

    // Check for duplicate name (excluding self)
    const dup = await pool.query('SELECT * FROM raw_materials WHERE name = $1 AND id != $2', [name, id]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ message: 'Material name already exists' });
    }

    // Update material
    const result = await pool.query(
      'UPDATE raw_materials SET name = $1, quantity = $2, unit = $3, threshold = $4, description = $5 WHERE id = $6 RETURNING *',
      [name, Number(quantity), unit, threshold ? Number(threshold) : 0, description || '', id]
    );

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating material:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

app.delete('/api/materials/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Check if material exists
    const existing = await pool.query('SELECT * FROM raw_materials WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ message: 'Material not found' });
    }

    // Delete material
    await pool.query('DELETE FROM raw_materials WHERE id = $1', [id]);
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting material:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

// Color Mix Formulas CRUD
app.get('/api/color-mix-formulas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM color_mix_formulas');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching color mix formulas:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/color-mix-formulas', async (req, res) => {
  try {
    console.log('POST /api/color-mix-formulas - Request body:', req.body);
    const { name, materialCount, formula, colorWeight, createdBy } = req.body;
    if (!name || !materialCount || !formula || !colorWeight || !createdBy) {
      return res.status(400).json({ 
        message: 'Missing required fields',
        received: { name, materialCount, formula, colorWeight, createdBy }
      });
    }
    // Check for duplicate name
    const dup = await pool.query('SELECT * FROM color_mix_formulas WHERE name = $1', [name]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ message: 'Formula name already exists' });
    }
    const result = await pool.query(
      'INSERT INTO color_mix_formulas (name, material_count, formula, color_weight, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, materialCount, formula, colorWeight, createdBy]
    );
    console.log('POST /api/color-mix-formulas - Created formula:', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating color mix formula:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/color-mix-formulas/:id', async (req, res) => {
  try {
    console.log('PUT /api/color-mix-formulas/:id - Request body:', req.body);
    const { id } = req.params;
    const { name, materialCount, formula, colorWeight } = req.body;
    if (!name || !materialCount || !formula || !colorWeight) {
      return res.status(400).json({ 
        message: 'Missing required fields',
        received: { name, materialCount, formula, colorWeight }
      });
    }
    // Check for duplicate name (excluding self)
    const dup = await pool.query('SELECT * FROM color_mix_formulas WHERE name = $1 AND id != $2', [name, id]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ message: 'Formula name already exists' });
    }
    const result = await pool.query(
      'UPDATE color_mix_formulas SET name = $1, material_count = $2, formula = $3, color_weight = $4 WHERE id = $5 RETURNING *',
      [name, materialCount, formula, colorWeight, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Formula not found' });
    }
    console.log('PUT /api/color-mix-formulas/:id - Updated formula:', result.rows[0]);
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating color mix formula:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
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
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Color Mix Entries API
app.get('/api/color-mix-entries', async (req, res) => {
  try {
    console.log('GET /api/color-mix-entries - Fetching all color mix entries');
    const [rows] = await pool.query(`
      SELECT 
        cme.*,
        f.name as formula_name
      FROM color_mix_entries cme
      LEFT JOIN color_mix_formulas f ON cme.formula_id = f.id
      ORDER BY cme.created_at DESC
    `);
    console.log('GET /api/color-mix-entries - Found entries:', rows.length);
    res.json(rows);
  } catch (error) {
    console.error('GET /api/color-mix-entries - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/color-mix-entries', async (req, res) => {
  try {
    console.log('POST /api/color-mix-entries - Incoming body:', req.body);
    const { formulaId, materialWeights, colorRequirement } = req.body;
    console.log('Fields:', { formulaId, materialWeights, colorRequirement });
    console.log('Types:', {
      formulaId: typeof formulaId,
      materialWeights: typeof materialWeights,
      colorRequirement: typeof colorRequirement
    });
    if (!formulaId) {
      console.error('Missing formulaId');
      return res.status(400).json({ message: 'Missing required field: formulaId', received: req.body });
    }
    if (!materialWeights) {
      console.error('Missing materialWeights');
      return res.status(400).json({ message: 'Missing required field: materialWeights', received: req.body });
    }
    if (colorRequirement === undefined) {
      console.error('Missing colorRequirement');
      return res.status(400).json({ message: 'Missing required field: colorRequirement', received: req.body });
    }
    let parsedMaterialWeights = materialWeights;
    if (typeof materialWeights === 'string') {
      try {
        parsedMaterialWeights = JSON.parse(materialWeights);
      } catch (e) {
        console.error('Invalid materialWeights format:', materialWeights);
        return res.status(400).json({ message: 'Invalid materialWeights format', received: materialWeights });
      }
    }
    if (!Array.isArray(parsedMaterialWeights)) {
      console.error('materialWeights is not an array:', parsedMaterialWeights);
      return res.status(400).json({ message: 'materialWeights must be an array', received: parsedMaterialWeights });
    }
    const colorRequirementNum = Number(colorRequirement);
    if (isNaN(colorRequirementNum)) {
      console.error('colorRequirement is not a number:', colorRequirement);
      return res.status(400).json({ message: 'colorRequirement must be a number', received: colorRequirement });
    }
    const insertQuery = `
      INSERT INTO color_mix_entries (formula_id, material_weights, color_requirement)
      VALUES ($1, $2, $3) RETURNING *
    `;
    const insertParams = [
      formulaId,
      JSON.stringify(parsedMaterialWeights),
      colorRequirementNum
    ];
    console.log('Insert query:', insertQuery);
    console.log('Insert params:', insertParams);
    const result = await pool.query(insertQuery, insertParams);
    const newEntry = result.rows[0];
    res.status(201).json(newEntry);
  } catch (error) {
    console.error('POST /api/color-mix-entries - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/color-mix-entries/:id', async (req, res) => {
  try {
    const { formulaId, materialWeights, colorRequirement } = req.body;
    const { id } = req.params;
    if (!formulaId || !materialWeights || colorRequirement === undefined) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    let parsedMaterialWeights = materialWeights;
    if (typeof materialWeights === 'string') {
      try {
        parsedMaterialWeights = JSON.parse(materialWeights);
      } catch (e) {
        return res.status(400).json({ message: 'Invalid materialWeights format' });
      }
    }
    // Ensure colorRequirement is a number
    const colorRequirementNum = Number(colorRequirement);
    if (isNaN(colorRequirementNum)) {
      return res.status(400).json({ message: 'colorRequirement must be a number' });
    }
    const updateQuery = `
      UPDATE color_mix_entries
      SET formula_id = $1, material_weights = $2, color_requirement = $3
      WHERE id = $4 RETURNING *
    `;
    const updateParams = [
      formulaId,
      JSON.stringify(parsedMaterialWeights),
      colorRequirementNum,
      id
    ];
    const result = await pool.query(updateQuery, updateParams);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Color mix entry not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('PUT /api/color-mix-entries/:id - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Moulds Routes
app.get('/api/moulds', async (req, res) => {
  try {
    const mouldsResult = await pool.query('SELECT * FROM moulds ORDER BY created_at DESC');
    res.status(200).json(mouldsResult.rows);
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

    // Check if mould with same name exists
    const existingMould = await pool.query(
      'SELECT id FROM moulds WHERE name = $1',
      [name]
    );

    if (existingMould.rows.length > 0) {
      return res.status(400).json({ message: 'A mould with this name already exists' });
    }

    // Insert new mould
    const newMouldResult = await pool.query(
      'INSERT INTO moulds (name, description, status) VALUES ($1, $2, $3) RETURNING *',
      [name, description || '', status || 'active']
    );

    const newMould = newMouldResult.rows[0];
    console.log('Created new mould:', newMould);
    res.status(201).json(newMould);
  } catch (error) {
    console.error('Error creating mould:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

app.put('/api/moulds/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Mould name is required' });
    }

    // Check if mould exists
    const existingMould = await pool.query(
      'SELECT id FROM moulds WHERE id = $1',
      [id]
    );

    if (existingMould.rows.length === 0) {
      return res.status(404).json({ message: 'Mould not found' });
    }

    // Check if name is already taken by another mould
    const nameCheck = await pool.query(
      'SELECT id FROM moulds WHERE name = $1 AND id != $2',
      [name, id]
    );

    if (nameCheck.rows.length > 0) {
      return res.status(400).json({ message: 'A mould with this name already exists' });
    }

    // Update mould
    const updateResult = await pool.query(
      'UPDATE moulds SET name = $1, description = $2, status = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *',
      [name, description || '', status || 'active', id]
    );

    const updatedMould = updateResult.rows[0];
    console.log('Updated mould:', updatedMould);
    res.status(200).json(updatedMould);
  } catch (error) {
    console.error('Error updating mould:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

app.delete('/api/moulds/:id', authenticateToken, requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if mould exists
    const existingMould = await pool.query(
      'SELECT id FROM moulds WHERE id = $1',
      [id]
    );

    if (existingMould.rows.length === 0) {
      return res.status(404).json({ message: 'Mould not found' });
    }

    // Check if mould is referenced in any tasks
    const taskCheck = await pool.query(
      'SELECT id FROM tasks WHERE mould_id = $1',
      [id]
    );

    if (taskCheck.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Cannot delete mould as it is referenced in existing tasks',
        taskCount: taskCheck.rows.length
      });
    }

    // Delete mould
    await pool.query('DELETE FROM moulds WHERE id = $1', [id]);
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting mould:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: error.stack 
    });
  }
});

// Products Routes
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, description, category, status, per_hour_production } = req.body;
    if (!name || !category) {
      return res.status(400).json({ message: 'Product name and category are required' });
    }
    // Check for duplicate name
    const dup = await pool.query('SELECT * FROM products WHERE name = $1', [name]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ message: 'Product name already exists' });
    }
    const result = await pool.query(
      'INSERT INTO products (name, description, category, status, per_hour_production) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description || null, category, status || 'active', per_hour_production || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, category, status, per_hour_production } = req.body;
    if (!name || !category) {
      return res.status(400).json({ message: 'Product name and category are required' });
    }
    // Check for duplicate name (excluding self)
    const dup = await pool.query('SELECT * FROM products WHERE name = $1 AND id != $2', [name, id]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ message: 'Product name already exists' });
    }
    const result = await pool.query(
      'UPDATE products SET name = $1, description = $2, category = $3, status = $4, per_hour_production = $5 WHERE id = $6 RETURNING *',
      [name, description || null, category, status || 'active', per_hour_production || null, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
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
    res.status(500).json({ message: 'Server error', error: error.message });
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