import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Authentication token is required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

const requireAdminOrSuperAdmin = (req, res, next) => {
  console.log('[AUTH DEBUG] req.user:', req.user);
  if (!req.user || !['admin', 'super_admin', 'superadmin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Admin or Super Admin privileges required', user: req.user });
  }
  next();
};

export { authenticateToken, requireAdminOrSuperAdmin };