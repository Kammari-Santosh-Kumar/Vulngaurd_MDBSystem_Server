const express = require('express');
const router = express.Router();
const Vulnerability = require('../models/Vulnerability');

// @route   GET /api/vulnerabilities
// @desc    Get all vulnerabilities with filters
router.get('/', async (req, res) => {
  try {
    const { severity, status, type, limit = 50 } = req.query;
    
    let query = {};
    if (severity) query.severity = severity;
    if (status) query.status = status;
    if (type) query.vulnerabilityType = type;

    const vulnerabilities = await Vulnerability.find(query)
      .sort({ discovered: -1 })
      .limit(parseInt(limit))
      .populate('scanId', 'targetUrl startTime');

    res.json(vulnerabilities);
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
    res.status(500).json({ message: 'Error fetching vulnerabilities', error: error.message });
  }
});

// @route   GET /api/vulnerabilities/:id
// @desc    Get vulnerability by ID
router.get('/:id', async (req, res) => {
  try {
    const vulnerability = await Vulnerability.findById(req.params.id)
      .populate('scanId', 'targetUrl startTime');
    
    if (!vulnerability) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }

    res.json(vulnerability);
  } catch (error) {
    console.error('Error fetching vulnerability:', error);
    res.status(500).json({ message: 'Error fetching vulnerability', error: error.message });
  }
});

// @route   PATCH /api/vulnerabilities/:id
// @desc    Update vulnerability status
router.patch('/:id', async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['Open', 'In Progress', 'Resolved', 'False Positive'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const vulnerability = await Vulnerability.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!vulnerability) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }

    res.json(vulnerability);
  } catch (error) {
    console.error('Error updating vulnerability:', error);
    res.status(500).json({ message: 'Error updating vulnerability', error: error.message });
  }
});

// @route   GET /api/vulnerabilities/stats/summary
// @desc    Get vulnerability statistics
router.get('/stats/summary', async (req, res) => {
  try {
    const total = await Vulnerability.countDocuments();
    
    const bySeverity = await Vulnerability.aggregate([
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 }
        }
      }
    ]);

    const byType = await Vulnerability.aggregate([
      {
        $group: {
          _id: '$vulnerabilityType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    const byStatus = await Vulnerability.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      total,
      bySeverity,
      byType,
      byStatus
    });
  } catch (error) {
    console.error('Error fetching vulnerability stats:', error);
    res.status(500).json({ message: 'Error fetching stats', error: error.message });
  }
});

module.exports = router;
