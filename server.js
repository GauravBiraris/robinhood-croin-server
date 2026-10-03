require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Neon
});

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-fallback-key';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// 1. Verify Wallet Signature and Issue JWT
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { address, signature, message } = req.body;
    // Recover address from signature
    const recoveredAddress = ethers.verifyMessage(message, signature);
    
    if (recoveredAddress.toLowerCase() === address.toLowerCase()) {
      const token = jwt.sign({ address: recoveredAddress.toLowerCase() }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Signature verification failed' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Auth error' });
  }
});

// 2. Save New Credit
app.post('/api/credits', authenticateToken, async (req, res) => {
  const { creditId, creditor, debitor, amount, fee, ballotinId, validity, creditorEmail, debitorEmail, message, terms } = req.body;
  
  // Security check: Only the actual creditor can save this record
  if (req.user.address !== creditor.toLowerCase()) return res.status(403).json({ error: 'Unauthorized' });

  try {
    const query = `
      INSERT INTO credits (
        credit_id, creditor, debitor, amount, fee, ballotin_id, validity, 
        creditor_email, debitor_email, message, terms, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Activated')
      RETURNING *;
    `;
    const values = [creditId, creditor.toLowerCase(), debitor.toLowerCase(), amount, fee, ballotinId, validity, creditorEmail, debitorEmail, message, terms];
    
    const result = await pool.query(query, values);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Database error' });
  }
});

// 3. Find Credit by 4 constraints
app.get('/api/credits/find', authenticateToken, async (req, res) => {
  const { creditor, debitor, amount, ballotinId } = req.query;
  try {
    const query = `
      SELECT * FROM credits 
      WHERE creditor = $1 AND debitor = $2 AND amount = $3 AND ballotin_id = $4
    `;
    const values = [creditor.toLowerCase(), debitor.toLowerCase(), amount, ballotinId];
    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// 4. Get Credit History for User
app.get('/api/credits/history', authenticateToken, async (req, res) => {
  try {
    const query = `SELECT * FROM credits WHERE creditor = $1 ORDER BY created_at DESC`;
    const result = await pool.query(query, [req.user.address]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// 5. Validate Trustee for a Credit (Determine Module)
app.get('/api/determine/validate/:creditId', authenticateToken, async (req, res) => {
  const { creditId } = req.params;
  const userAddress = req.user.address;

  try {
    // A. Find the credit to get the ballotin_id
    const creditRes = await pool.query('SELECT * FROM credits WHERE credit_id = $1', [creditId]);
    if (creditRes.rows.length === 0) {
      return res.status(404).json({ error: 'Credit ID not found in database.' });
    }
    const credit = creditRes.rows[0];

    // B. Check if the user is a trustee in the ballots table for that ballotin_id
    const ballotRes = await pool.query(
      'SELECT * FROM ballots WHERE ballotin_id = $1 AND LOWER(wallet_address) = $2',
      [credit.ballotin_id, userAddress.toLowerCase()]
    );
    
    if (ballotRes.rows.length === 0) {
      return res.status(403).json({ error: 'Access Denied: You are not a registered trustee for this Ballotin.' });
    }

    res.json(credit);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Database verification failed' });
  }
});

// 6. Save Vote Decision (Determine Module)
app.post('/api/decisions', authenticateToken, async (req, res) => {
  const { creditId, decision, reason } = req.body;
  const userAddress = req.user.address;

  try {
    const query = `
      INSERT INTO decisions (wallet_address, credit_id, decision, reason) 
      VALUES ($1, $2, $3, $4) RETURNING *;
    `;
    const result = await pool.query(query, [userAddress.toLowerCase(), creditId, decision, reason]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Database error' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Croin Backend running on port ${PORT}`);
});
