import pool from '../db.js';

const initializeDatabase = async () => {
  console.log('[DB Init] Starting database initialization...');
  try {
    // Create machines table
    console.log('[DB Init] Creating/verifying machines table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS machines (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'active',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('[DB Init] Machines table created/verified successfully');

    // Create moulds table
    console.log('[DB Init] Creating/verifying moulds table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS moulds (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'active',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('[DB Init] Moulds table created/verified successfully');

    // Create users table
    console.log('[DB Init] Creating/verifying users table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        userId VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('[DB Init] Users table created/verified successfully');

    // Create tasks table
    console.log('[DB Init] Creating/verifying tasks table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        machine_id INT NOT NULL,
        mould_id INT NOT NULL,
        product_id INT NOT NULL,
        color_mix_id INT NOT NULL,
        worker_id INT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_by INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (machine_id) REFERENCES machines(id),
        FOREIGN KEY (mould_id) REFERENCES moulds(id),
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (color_mix_id) REFERENCES color_mix_formulas(id),
        FOREIGN KEY (worker_id) REFERENCES users(id),
        FOREIGN KEY (created_by) REFERENCES users(id)
      );
    `);
    console.log('[DB Init] Tasks table created/verified successfully');

    // Create color mix formulas table
    console.log('[DB Init] Creating/verifying color mix formulas table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS color_mix_formulas (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        formula TEXT NOT NULL,
        created_by INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
      );
    `);
    console.log('[DB Init] Color mix formulas table created/verified successfully');

    // Create products table
    console.log('[DB Init] Creating/verifying products table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        category VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('[DB Init] Products table created/verified successfully');

    // Create hourly production logs table
    console.log('[DB Init] Creating/verifying hourly production logs table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hourly_production_logs (
        id SERIAL PRIMARY KEY,
        task_id INT NOT NULL,
        hour TIME NOT NULL,
        total_pieces INT NOT NULL,
        perfect_pieces INT NOT NULL,
        defect_pieces INT NOT NULL,
        date DATE NOT NULL,
        perfect_weight DECIMAL(10,2),
        defective_weight DECIMAL(10,2),
        wastage_weight DECIMAL(10,2),
        remarks TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id)
      );
    `);
    console.log('[DB Init] Hourly production logs table created/verified successfully');

    // Add remarks column if it doesn't exist
    console.log('[DB Init] Adding remarks column to hourly production logs table...');
    await pool.query(`
      ALTER TABLE hourly_production_logs
      ADD COLUMN IF NOT EXISTS remarks TEXT
    `);
    console.log('[DB Init] Remarks column added successfully');

    // Insert test data if tables are empty
    console.log('[DB Init] Checking for existing data...');
    const [machines] = await pool.query('SELECT COUNT(*) as count FROM machines');
    console.log(`[DB Init] Found ${machines[0].count} machines`);
    if (machines[0].count === 0) {
      console.log('[DB Init] Inserting test machines...');
      await pool.query(`
        INSERT INTO machines (name, description, status) VALUES 
        ('Machine 1', 'Test machine 1', 'active'),
        ('Machine 2', 'Test machine 2', 'active')
      `);
      console.log('[DB Init] Test machines inserted successfully');
    }

    const [moulds] = await pool.query('SELECT COUNT(*) as count FROM moulds');
    console.log(`[DB Init] Found ${moulds[0].count} moulds`);
    if (moulds[0].count === 0) {
      console.log('[DB Init] Inserting test moulds...');
      await pool.query(`
        INSERT INTO moulds (name, description, status) VALUES 
        ('Mould 1', 'Test mould 1', 'active'),
        ('Mould 2', 'Test mould 2', 'active')
      `);
      console.log('[DB Init] Test moulds inserted successfully');
    }

    // Insert default admin user if no users exist
    const [users] = await pool.query('SELECT COUNT(*) as count FROM users');
    console.log(`[DB Init] Found ${users[0].count} users`);
    if (users[0].count === 0) {
      console.log('[DB Init] Inserting default users...');
      await pool.query(`
        INSERT INTO users (userId, name, role) VALUES 
        ('super_admin', 'Super Admin', 'super_admin'),
        ('admin1', 'Admin User', 'admin'),
        ('worker1', 'Worker One', 'worker'),
        ('worker2', 'Worker Two', 'worker')
      `);
      console.log('[DB Init] Default users inserted successfully');
    }

    // Insert default super admin if not exists
    console.log('[DB Init] Checking for default super admin...');
    const [existingAdmin] = await pool.query('SELECT * FROM users WHERE userId = $1', ['SA001']);
    if (existingAdmin.length === 0) {
      console.log('[DB Init] Creating default super admin...');
      await pool.query(
        'INSERT INTO users (userId, name, role) VALUES ($1, $2, $3)',
        ['SA001', 'Super Admin', 'super_admin']
      );
      console.log('[DB Init] Default super admin created successfully');
    } else {
      console.log('[DB Init] Default super admin already exists');
    }

    console.log('[DB Init] Database initialization completed successfully');
  } catch (error) {
    console.error('[DB Init] Error initializing database:', error);
    console.error('[DB Init] Error stack:', error.stack);
    console.error('[DB Init] Error details:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage
    });
    throw error;
  }
};

// Run initialization
console.log('[DB Init] Starting database initialization process...');
initializeDatabase().catch(error => {
  console.error('[DB Init] Fatal error during database initialization:', error);
  process.exit(1);
});

export default initializeDatabase;