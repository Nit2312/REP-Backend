import { Client } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

async function testConnection() {
  try {
    const client = new Client({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'raameshth_management',
    });
    await client.connect();
    console.log('Successfully connected to PostgreSQL!');
    await client.end();
  } catch (error) {
    console.error('Error connecting to PostgreSQL:', error);
  }
}

testConnection();