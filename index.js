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
    const result = await pool.query(`
      SELECT 
        cme.*,
        f.name as formula_name
      FROM color_mix_entries cme
      LEFT JOIN color_mix_formulas f ON cme.formula_id = f.id
      ORDER BY cme.created_at DESC
    `);
    const rows = result.rows;
    // Parse material_weights if needed
    const entries = rows.map(entry => {
      let materialWeights = entry.material_weights;
      if (typeof materialWeights === 'string') {
        try {
          materialWeights = JSON.parse(materialWeights);
        } catch {
          materialWeights = [];
        }
      }
      return {
        ...entry,
        material_weights: materialWeights
      };
    });
    res.json(entries);
  } catch (error) {
    console.error('GET /api/color-mix-entries - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/color-mix-entries - Create a new color mix entry
app.post('/api/color-mix-entries', async (req, res) => {
  try {
    const { formulaId, materialWeights, colorRequirement } = req.body;
    if (!formulaId || !materialWeights || !colorRequirement) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    // Store materialWeights as JSON string
    const result = await pool.query(
      'INSERT INTO color_mix_entries (formula_id, material_weights, color_requirement) VALUES ($1, $2, $3) RETURNING *',
      [formulaId, JSON.stringify(materialWeights), colorRequirement]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('POST /api/color-mix-entries - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update a color mix entry
app.put('/api/color-mix-entries/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { formulaId, materialWeights, colorRequirement } = req.body;
    if (!formulaId || !materialWeights || !colorRequirement) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'UPDATE color_mix_entries SET formula_id = $1, material_weights = $2, color_requirement = $3 WHERE id = $4 RETURNING *',
      [formulaId, JSON.stringify(materialWeights), colorRequirement, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Color mix entry not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('PUT /api/color-mix-entries/:id - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete a color mix entry
app.delete('/api/color-mix-entries/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM color_mix_entries WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Color mix entry not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('DELETE /api/color-mix-entries/:id - Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Products API
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY id');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Moulds API
app.get('/api/moulds', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM moulds ORDER BY id');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching moulds:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Tasks Router with authentication
const tasksRouter = express.Router();
tasksRouter.use(authenticateToken);

tasksRouter.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tasks ORDER BY id DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

tasksRouter.post('/', async (req, res) => {
  try {
    const { name, description, machine_id, mould_id, product_id, color_mix_id, worker_id, target, status = 'pending', created_by } = req.body;
    if (!name || !machine_id || !mould_id || !product_id || !color_mix_id || !worker_id || target === undefined) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'INSERT INTO tasks (name, description, machine_id, mould_id, product_id, color_mix_id, worker_id, target, status, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
      [name, description || null, machine_id, mould_id, product_id, color_mix_id, worker_id, target, status, created_by || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

tasksRouter.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, machine_id, mould_id, product_id, color_mix_id, worker_id, target, status } = req.body;
    if (!name || !machine_id || !mould_id || !product_id || !color_mix_id || !worker_id || target === undefined) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'UPDATE tasks SET name = $1, description = $2, machine_id = $3, mould_id = $4, product_id = $5, color_mix_id = $6, worker_id = $7, target = $8, status = $9, updated_at = CURRENT_TIMESTAMP WHERE id = $10 RETURNING *',
      [name, description || null, machine_id, mould_id, product_id, color_mix_id, worker_id, target, status, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

tasksRouter.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM tasks WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.use('/api/tasks', tasksRouter);

// Middleware to check if user is worker
function requireWorker(req, res, next) {
  if (!req.user || req.user.role !== 'worker') {
    return res.status(403).json({ message: 'Forbidden: Worker only' });
  }
  next();
}

// Hourly Production Logs API
const hourlyLogsRouter = express.Router();
hourlyLogsRouter.use(authenticateToken);

// Get logs by task ID - this needs to be before the /:id route
hourlyLogsRouter.get('/task/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    console.log('Fetching logs for task ID:', taskId);
    
    // First verify the task exists
    const taskResult = await pool.query('SELECT id FROM tasks WHERE id = $1', [taskId]);
    if (taskResult.rows.length === 0) {
      console.log('Task not found:', taskId);
      return res.status(404).json({ message: 'Task not found' });
    }
    
    const result = await pool.query(
      'SELECT * FROM hourly_production_logs WHERE task_id = $1 ORDER BY date DESC, hour DESC',
      [taskId]
    );
    
    console.log('Query result:', result.rows);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching hourly production logs by task:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// List all logs (admin/super_admin only)
hourlyLogsRouter.get('/', requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM hourly_production_logs ORDER BY id DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get by id (admin/super_admin only)
hourlyLogsRouter.get('/:id', requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM hourly_production_logs WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ message: 'Not found' });
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Create (worker only)
hourlyLogsRouter.post('/', requireWorker, async (req, res) => {
  try {
    const {
      task_id,
      hour,
      date,
      perfect_pieces,
      defect_pieces,
      total_pieces,
      perfect_weight,
      defective_weight,
      wastage_weight,
      remarks
    } = req.body;
    if (
      task_id == null ||
      hour == null ||
      date == null ||
      perfect_pieces == null ||
      defect_pieces == null ||
      total_pieces == null
    ) {
      console.error('[HourlyLog POST] Missing required fields:', req.body);
      return res.status(400).json({ message: 'Missing required fields', fields: req.body });
    }
    const result = await pool.query(
      `INSERT INTO hourly_production_logs 
        (task_id, hour, date, perfect_pieces, defect_pieces, total_pieces, perfect_weight, defective_weight, wastage_weight, remarks)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        task_id,
        hour,
        date,
        perfect_pieces || 0,
        defect_pieces || 0,
        total_pieces || 0,
        perfect_weight || null,
        defective_weight || null,
        wastage_weight || null,
        remarks || ''
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update (admin/super_admin only)
hourlyLogsRouter.put('/:id', requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { hour, produced, rejected, remarks } = req.body;
    const result = await pool.query(
      'UPDATE hourly_production_logs SET hour = $1, produced = $2, rejected = $3, remarks = $4 WHERE id = $5 RETURNING *',
      [hour, produced, rejected, remarks, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete (admin/super_admin only)
hourlyLogsRouter.delete('/:id', requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM hourly_production_logs WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Register the router BEFORE any catch-all routes
app.use('/api/hourly-production-logs', hourlyLogsRouter);

// Production Logs API (admin/super_admin only)
const prodLogsRouter = express.Router();
prodLogsRouter.use(authenticateToken, requireAdminOrSuperAdmin);

prodLogsRouter.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM production_logs ORDER BY id DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
prodLogsRouter.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM production_logs WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ message: 'Not found' });
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
prodLogsRouter.post('/', async (req, res) => {
  try {
    const { task_id, produced, rejected, remarks } = req.body;
    if (!task_id || produced === undefined) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const result = await pool.query(
      'INSERT INTO production_logs (task_id, produced, rejected, remarks, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [task_id, produced, rejected || 0, remarks || '', req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
prodLogsRouter.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { produced, rejected, remarks } = req.body;
    const result = await pool.query(
      'UPDATE production_logs SET produced = $1, rejected = $2, remarks = $3 WHERE id = $4 RETURNING *',
      [produced, rejected, remarks, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
prodLogsRouter.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM production_logs WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
app.use('/api/production-logs', prodLogsRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;