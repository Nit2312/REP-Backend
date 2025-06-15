import pool from '../db.js';

const initializeDatabase = async () => {
  console.log('[DB Init] Starting database initialization...');
  try {
    // Create users table
    console.log('[DB Init] Creating/verifying users table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        role TEXT NOT NULL DEFAULT 'worker' CHECK (role IN ('super_admin', 'admin', 'worker')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Users table created/verified successfully');

    // Create machines table
    console.log('[DB Init] Creating/verifying machines table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS machines (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Machines table created/verified successfully');

    // Create moulds table
    console.log('[DB Init] Creating/verifying moulds table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS moulds (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Moulds table created/verified successfully');

    // Create products table
    console.log('[DB Init] Creating/verifying products table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        category VARCHAR(100) NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        per_hour_production DECIMAL(10,2),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // Reset the sequence to the max id
    await pool.query(`
      SELECT setval('products_id_seq', COALESCE((SELECT MAX(id) FROM products), 0) + 1, false);
    `);
    console.log('[DB Init] Products table created/verified successfully');

    // Create color mix formulas table
    console.log('[DB Init] Creating/verifying color mix formulas table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS color_mix_formulas (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        material_count INTEGER NOT NULL,
        formula TEXT NOT NULL,
        color_weight DECIMAL(10,2) NOT NULL DEFAULT 0.00,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Color mix formulas table created/verified successfully');

    // Create tasks table
    console.log('[DB Init] Creating/verifying tasks table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        machine_id INTEGER NOT NULL REFERENCES machines(id),
        mould_id INTEGER NOT NULL REFERENCES moulds(id),
        product_id INTEGER NOT NULL REFERENCES products(id),
        color_mix_id INTEGER NOT NULL REFERENCES color_mix_formulas(id),
        worker_id INTEGER NOT NULL REFERENCES users(id),
        target INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled')),
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Tasks table created/verified successfully');

    // Create hourly production logs table
    console.log('[DB Init] Creating/verifying hourly production logs table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hourly_production_logs (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        hour TIME NOT NULL,
        total_pieces INTEGER NOT NULL DEFAULT 0,
        perfect_pieces INTEGER NOT NULL DEFAULT 0,
        defect_pieces INTEGER NOT NULL DEFAULT 0,
        date DATE NOT NULL,
        perfect_weight DECIMAL(10,2),
        defective_weight DECIMAL(10,2),
        wastage_weight DECIMAL(10,2),
        remarks TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('[DB Init] Hourly production logs table created/verified successfully');

    // Create raw materials table
    console.log('[DB Init] Creating/verifying raw materials table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS raw_materials (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        quantity DECIMAL(10,2) NOT NULL,
        unit VARCHAR(20) NOT NULL,
        threshold DECIMAL(10,2) DEFAULT 0,
        description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      `);
    console.log('[DB Init] Raw materials table created/verified successfully');

    // Insert default admin user if no users exist
    const usersResult = await pool.query('SELECT COUNT(*) as count FROM users');
    if (usersResult.rows[0].count === '0') {
      console.log('[DB Init] Inserting default users...');
      await pool.query(`
        INSERT INTO users (user_id, name, role) VALUES 
        ('SA001', 'Super Admin', 'super_admin'),
        ('AD001', 'Admin User', 'admin'),
        ('WK001', 'Worker One', 'worker')
      `);
      console.log('[DB Init] Default users inserted successfully');
    }

    console.log('[DB Init] Database initialization completed successfully');
  } catch (error) {
    console.error('[DB Init] Error initializing database:', error);
    throw error;
  }
};

export default initializeDatabase;