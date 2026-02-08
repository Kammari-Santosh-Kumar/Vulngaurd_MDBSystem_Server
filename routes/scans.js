const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const VulnerabilityScanner = require('../utils/scanner');
const NmapScanner = require('../utils/nmapScanner');
const OpenVASScanner = require('../utils/openvasScanner'); 
const emailService = require('../services/emailService');

// @route   POST /api/scans
// @desc    Start a new vulnerability scan
router.post('/', async (req, res) => {
  try {
    const { targetUrl, scanType = 'Quick', scanMethod = 'Nmap' } = req.body;

    if (!targetUrl) {
      return res.status(400).json({ message: 'Target URL is required' });
    }

    // Create scan record
    const scan = await Scan.create({
      targetUrl,
      scanType,
      status: 'Running',
      startTime: new Date()
    });

    // Run scan asynchronously with selected method
    runScanAsync(scan._id, targetUrl, scanType, scanMethod);

    res.status(201).json({
      message: 'Scan started successfully',
      scanId: scan._id,
      scanMethod,
      scan
    });
  } catch (error) {
    console.error('Error starting scan:', error);
    res.status(500).json({ message: 'Error starting scan', error: error.message });
  }
});

// Async function to run the scan
// Async function to run the scan
async function runScanAsync(scanId, targetUrl, scanType = 'Quick', scanMethod = 'Nmap') {
  try {
    let vulnerabilities = [];
    
    // Choose scanning method
    // Choose scanning method
if (scanMethod === 'Nmap') {
  console.log('Using Nmap scanner...');
  const nmapScanner = new NmapScanner(targetUrl);
  vulnerabilities = await nmapScanner.runFullScan(scanType);
} else if (scanMethod === 'OpenVAS') {
  console.log('Using OpenVAS scanner...');
  const openvasScanner = new OpenVASScanner(targetUrl);
  vulnerabilities = await openvasScanner.runFullScan(scanType);
} else {
  console.log('Using Regex scanner...');
  const regexScanner = new VulnerabilityScanner(targetUrl);
  vulnerabilities = await regexScanner.runFullScan();
}

    // Count vulnerabilities by severity
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    // Save vulnerabilities to database
    for (const vuln of vulnerabilities) {
      const savedVuln = await Vulnerability.create({
        targetUrl,
        vulnerabilityType: vuln.type,
        severity: vuln.severity,
        description: vuln.description,
        location: vuln.location,
        payload: vuln.payload,
        recommendation: vuln.recommendation,
        scanId
      });

      // Send email alert for critical vulnerabilities
      if (vuln.severity === 'Critical') {
        const scan = await Scan.findById(scanId);
        await emailService.sendCriticalVulnerabilityAlert(savedVuln, scan);
      }

      // Count by severity
      switch (vuln.severity) {
        case 'Critical': criticalCount++; break;
        case 'High': highCount++; break;
        case 'Medium': mediumCount++; break;
        case 'Low': lowCount++; break;
      }
    }

    // Update scan record
    await Scan.findByIdAndUpdate(scanId, {
      status: 'Completed',
      endTime: new Date(),
      totalVulnerabilities: vulnerabilities.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      scanResults: {
        vulnerabilitiesFound: vulnerabilities.length,
        summary: 'Scan completed successfully',
        method: scanMethod
      }
    });

    // Send scan completion email
    const completedScan = await Scan.findById(scanId);
    await emailService.sendScanCompleteNotification(completedScan, vulnerabilities.length);

    console.log(`✓ Scan ${scanId} completed using ${scanMethod}. Found ${vulnerabilities.length} vulnerabilities.`);
  } catch (error) {
    console.error('Error running scan:', error);
    await Scan.findByIdAndUpdate(scanId, {
      status: 'Failed',
      endTime: new Date(),
      scanResults: {
        error: error.message
      }
    });
  }
}
// @route   GET /api/scans
// @desc    Get all scans
router.get('/', async (req, res) => {
  try {
    const scans = await Scan.find().sort({ startTime: -1 }).limit(50);
    res.json(scans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    res.status(500).json({ message: 'Error fetching scans', error: error.message });
  }
});

// @route   GET /api/scans/:id
// @desc    Get scan by ID
router.get('/:id', async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    const vulnerabilities = await Vulnerability.find({ scanId: req.params.id });

    res.json({
      scan,
      vulnerabilities
    });
  } catch (error) {
    console.error('Error fetching scan:', error);
    res.status(500).json({ message: 'Error fetching scan', error: error.message });
  }
});

// @route   GET /api/scans/stats/overview
// @desc    Get scan statistics
router.get('/stats/overview', async (req, res) => {
  try {
    const totalScans = await Scan.countDocuments();
    const completedScans = await Scan.countDocuments({ status: 'Completed' });
    const totalVulnerabilities = await Vulnerability.countDocuments();
    
    const severityCounts = await Vulnerability.aggregate([
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 }
        }
      }
    ]);

    const recentScans = await Scan.find()
      .sort({ startTime: -1 })
      .limit(5)
      .select('targetUrl status totalVulnerabilities startTime');

    res.json({
      totalScans,
      completedScans,
      totalVulnerabilities,
      severityCounts,
      recentScans
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ message: 'Error fetching stats', error: error.message });
  }
});

module.exports = router;
