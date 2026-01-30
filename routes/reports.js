const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const reportGenerator = require('../services/reportGenerator');
const scheduledScanService = require('../services/scheduledScanService');
const emailService = require('../services/emailService');

// @route   GET /api/reports/scan/:scanId
// @desc    Generate PDF report for a scan
router.get('/scan/:scanId', async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.scanId);
    
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    const vulnerabilities = await Vulnerability.find({ scanId: req.params.scanId });

    // Ensure reports directory exists
    const reportsDir = path.join(__dirname, '../reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const fileName = `scan-report-${req.params.scanId}-${Date.now()}.pdf`;
    const filePath = path.join(reportsDir, fileName);

    await reportGenerator.generateScanReport(scan, vulnerabilities, filePath);

    // Send file
    res.download(filePath, fileName, (err) => {
      if (err) {
        console.error('Error sending file:', err);
      }
      // Delete file after sending
      setTimeout(() => {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }, 5000);
    });
  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ message: 'Error generating report', error: error.message });
  }
});

// @route   POST /api/scheduled-scans
// @desc    Create a scheduled scan
router.post('/', async (req, res) => {
  try {
    const { targetUrl, frequency, scanType } = req.body;

    if (!targetUrl || !frequency) {
      return res.status(400).json({ message: 'Target URL and frequency are required' });
    }

    const job = scheduledScanService.scheduleRecurringScan(targetUrl, frequency, scanType);

    res.status(201).json({
      message: 'Scheduled scan created successfully',
      job
    });
  } catch (error) {
    console.error('Error creating scheduled scan:', error);
    res.status(500).json({ message: 'Error creating scheduled scan', error: error.message });
  }
});

// @route   GET /api/scheduled-scans
// @desc    Get all scheduled scans
router.get('/', (req, res) => {
  try {
    const scans = scheduledScanService.getScheduledScans();
    res.json(scans);
  } catch (error) {
    console.error('Error fetching scheduled scans:', error);
    res.status(500).json({ message: 'Error fetching scheduled scans', error: error.message });
  }
});

// @route   DELETE /api/scheduled-scans/:jobId
// @desc    Cancel a scheduled scan
router.delete('/:jobId', (req, res) => {
  try {
    const success = scheduledScanService.cancelScheduledScan(req.params.jobId);
    
    if (success) {
      res.json({ message: 'Scheduled scan cancelled successfully' });
    } else {
      res.status(404).json({ message: 'Scheduled scan not found' });
    }
  } catch (error) {
    console.error('Error cancelling scheduled scan:', error);
    res.status(500).json({ message: 'Error cancelling scheduled scan', error: error.message });
  }
});

// @route   POST /api/email/test
// @desc    Test email configuration
router.post('/test', async (req, res) => {
  try {
    if (!emailService.enabled) {
      return res.status(400).json({ 
        message: 'Email service is not enabled. Please configure email settings in .env file.' 
      });
    }

    const testScan = {
      targetUrl: 'https://example.com',
      startTime: new Date(),
      endTime: new Date(),
      criticalCount: 1,
      highCount: 2,
      mediumCount: 3,
      lowCount: 4
    };

    await emailService.sendScanCompleteNotification(testScan, 10);

    res.json({ message: 'Test email sent successfully!' });
  } catch (error) {
    console.error('Error sending test email:', error);
    res.status(500).json({ message: 'Error sending test email', error: error.message });
  }
});

// @route   GET /api/scans/compare/:scanId1/:scanId2
// @desc    Compare two scans
router.get('/compare/:scanId1/:scanId2', async (req, res) => {
  try {
    const [scan1, scan2] = await Promise.all([
      Scan.findById(req.params.scanId1),
      Scan.findById(req.params.scanId2)
    ]);

    if (!scan1 || !scan2) {
      return res.status(404).json({ message: 'One or both scans not found' });
    }

    const [vulns1, vulns2] = await Promise.all([
      Vulnerability.find({ scanId: req.params.scanId1 }),
      Vulnerability.find({ scanId: req.params.scanId2 })
    ]);

    // Calculate differences
    const comparison = {
      scan1: {
        id: scan1._id,
        date: scan1.startTime,
        totalVulnerabilities: scan1.totalVulnerabilities,
        critical: scan1.criticalCount,
        high: scan1.highCount,
        medium: scan1.mediumCount,
        low: scan1.lowCount
      },
      scan2: {
        id: scan2._id,
        date: scan2.startTime,
        totalVulnerabilities: scan2.totalVulnerabilities,
        critical: scan2.criticalCount,
        high: scan2.highCount,
        medium: scan2.mediumCount,
        low: scan2.lowCount
      },
      changes: {
        totalVulnerabilities: (scan2.totalVulnerabilities || 0) - (scan1.totalVulnerabilities || 0),
        critical: (scan2.criticalCount || 0) - (scan1.criticalCount || 0),
        high: (scan2.highCount || 0) - (scan1.highCount || 0),
        medium: (scan2.mediumCount || 0) - (scan1.mediumCount || 0),
        low: (scan2.lowCount || 0) - (scan1.lowCount || 0)
      },
      newVulnerabilities: vulns2.filter(v2 => 
        !vulns1.some(v1 => v1.vulnerabilityType === v2.vulnerabilityType && v1.location === v2.location)
      ),
      fixedVulnerabilities: vulns1.filter(v1 => 
        !vulns2.some(v2 => v2.vulnerabilityType === v1.vulnerabilityType && v2.location === v1.location)
      )
    };

    res.json(comparison);
  } catch (error) {
    console.error('Error comparing scans:', error);
    res.status(500).json({ message: 'Error comparing scans', error: error.message });
  }
});

module.exports = router;
