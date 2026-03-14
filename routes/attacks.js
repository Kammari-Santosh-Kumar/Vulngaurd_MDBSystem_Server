const express = require('express');
const router = express.Router();
const AttackLog = require('../models/AttackLog');

// @route   GET /api/attacks
// @desc    Get all attack logs
router.get('/', async (req, res) => {
  try {
    const { limit = 100, attackType, severity } = req.query;
    
    let query = {};
    if (attackType) query.attackType = attackType;
    if (severity) query.severity = severity;

    const attacks = await AttackLog.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    res.json(attacks);
  } catch (error) {
    console.error('Error fetching attacks:', error);
    res.status(500).json({ message: 'Error fetching attacks', error: error.message });
  }
});

// @route   GET /api/attacks/stats
// @desc    Get attack statistics
router.get('/stats', async (req, res) => {
  try {
    const totalAttacks = await AttackLog.countDocuments();
    
    const byType = await AttackLog.aggregate([
      {
        $group: {
          _id: '$attackType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    const bySeverity = await AttackLog.aggregate([
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 }
        }
      }
    ]);

    const topAttackers = await AttackLog.aggregate([
      {
        $group: {
          _id: '$sourceIp',
          count: { $sum: 1 },
          lastAttack: { $max: '$timestamp' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    const recentAttacks = await AttackLog.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select('timestamp attackType sourceIp targetEndpoint severity');

    // Attacks over time (last 24 hours)
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const attacksOverTime = await AttackLog.aggregate([
      {
        $match: {
          timestamp: { $gte: oneDayAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d %H:00',
              date: '$timestamp'
            }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json({
      totalAttacks,
      byType,
      bySeverity,
      topAttackers,
      recentAttacks,
      attacksOverTime
    });
  } catch (error) {
    console.error('Error fetching attack stats:', error);
    res.status(500).json({ message: 'Error fetching stats', error: error.message });
  }
});

// HONEYPOT ENDPOINTS - These are fake endpoints to trap attackers

// @route   POST /api/honeypot/admin/login
// @desc    Fake admin login (honeypot)
router.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  await AttackLog.create({
    timestamp: new Date(),
    attackType: 'Credential Stuffing',
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    targetEndpoint: '/api/honeypot/admin/login',
    httpMethod: 'POST',
    payload: { username, password: '***REDACTED***' },
    headers: req.headers,
    severity: 'High'
  });

  // Fake response to deceive attacker
  res.status(401).json({ message: 'Invalid credentials' });
});

// @route   GET /api/honeypot/config/database
// @desc    Fake config endpoint (honeypot)
router.get('/config/database', async (req, res) => {
  await AttackLog.create({
    timestamp: new Date(),
    attackType: 'Path Traversal',
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    targetEndpoint: '/api/honeypot/config/database',
    httpMethod: 'GET',
    payload: req.query,
    headers: req.headers,
    severity: 'Critical'
  });

  res.status(403).json({ message: 'Access Denied' });
});

// @route   GET /api/honeypot/backup
// @desc    Fake backup endpoint (honeypot)
router.get('/backup', async (req, res) => {
  await AttackLog.create({
    timestamp: new Date(),
    attackType: 'Path Traversal',
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    targetEndpoint: '/api/honeypot/backup',
    httpMethod: 'GET',
    payload: req.query,
    headers: req.headers,
    severity: 'High'
  });

  res.status(404).json({ message: 'Not Found' });
});

// @route   POST /api/honeypot/upload
// @desc    Fake upload endpoint (honeypot)
router.post('/upload', async (req, res) => {
  await AttackLog.create({
    timestamp: new Date(),
    attackType: 'Other',
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    targetEndpoint: '/api/honeypot/upload',
    httpMethod: 'POST',
    payload: req.body,
    headers: req.headers,
    severity: 'Medium'
  });

  res.status(400).json({ message: 'Invalid file format' });
});

// @route   GET /api/attacks/:id
// @desc    Get attack by ID
router.get('/:id', async (req, res) => {
  try {
    // Validate if the ID is a valid MongoDB ObjectId
    const mongoose = require('mongoose');
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid attack ID format' });
    }

    const attack = await AttackLog.findById(req.params.id);
    
    if (!attack) {
      return res.status(404).json({ message: 'Attack log not found' });
    }

    res.json(attack);
  } catch (error) {
    console.error('Error fetching attack:', error);
    res.status(500).json({ message: 'Error fetching attack', error: error.message });
  }
});

module.exports = router;
