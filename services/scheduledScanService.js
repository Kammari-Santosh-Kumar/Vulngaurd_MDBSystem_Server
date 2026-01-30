const cron = require('node-cron');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const VulnerabilityScanner = require('../utils/scanner');
const emailService = require('./emailService');

class ScheduledScanService {
  constructor() {
    this.scheduledScans = new Map();
  }

  // Schedule a recurring scan
  scheduleRecurringScan(targetUrl, frequency, scanType = 'Quick') {
    const cronExpression = this.getCronExpression(frequency);
    
    if (!cronExpression) {
      throw new Error('Invalid frequency');
    }

    const jobId = `${targetUrl}-${frequency}`;
    
    // Cancel existing job if it exists
    if (this.scheduledScans.has(jobId)) {
      this.scheduledScans.get(jobId).stop();
    }

    // Create new scheduled job
    const task = cron.schedule(cronExpression, async () => {
      console.log(`🕐 Running scheduled scan for ${targetUrl}`);
      await this.runScheduledScan(targetUrl, scanType);
    });

    this.scheduledScans.set(jobId, task);
    
    console.log(`✓ Scheduled scan created for ${targetUrl} - ${frequency}`);
    
    return {
      jobId,
      targetUrl,
      frequency,
      cronExpression,
      nextRun: this.getNextRunTime(cronExpression)
    };
  }

  async runScheduledScan(targetUrl, scanType) {
    try {
      // Create scan record
      const scan = await Scan.create({
        targetUrl,
        scanType,
        status: 'Running',
        startTime: new Date()
      });

      // Run the scan
      const scanner = new VulnerabilityScanner(targetUrl);
      const vulnerabilities = await scanner.runFullScan();

      // Count vulnerabilities by severity
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      // Save vulnerabilities
      for (const vuln of vulnerabilities) {
        const savedVuln = await Vulnerability.create({
          targetUrl,
          vulnerabilityType: vuln.type,
          severity: vuln.severity,
          description: vuln.description,
          location: vuln.location,
          payload: vuln.payload,
          recommendation: vuln.recommendation,
          scanId: scan._id
        });

        // Send email alert for critical vulnerabilities
        if (vuln.severity === 'Critical') {
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
      await Scan.findByIdAndUpdate(scan._id, {
        status: 'Completed',
        endTime: new Date(),
        totalVulnerabilities: vulnerabilities.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount
      });

      // Send scan completion email
      await emailService.sendScanCompleteNotification(scan, vulnerabilities.length);

      console.log(`✓ Scheduled scan completed for ${targetUrl}. Found ${vulnerabilities.length} vulnerabilities.`);
    } catch (error) {
      console.error('Error in scheduled scan:', error);
    }
  }

  // Cancel a scheduled scan
  cancelScheduledScan(jobId) {
    if (this.scheduledScans.has(jobId)) {
      this.scheduledScans.get(jobId).stop();
      this.scheduledScans.delete(jobId);
      console.log(`✓ Scheduled scan cancelled: ${jobId}`);
      return true;
    }
    return false;
  }

  // Get all scheduled scans
  getScheduledScans() {
    const scans = [];
    this.scheduledScans.forEach((task, jobId) => {
      const [targetUrl, frequency] = jobId.split('-');
      scans.push({
        jobId,
        targetUrl,
        frequency,
        active: task.options ? true : false
      });
    });
    return scans;
  }

  // Convert frequency to cron expression
  getCronExpression(frequency) {
    const expressions = {
      'hourly': '0 * * * *',           // Every hour
      'daily': '0 0 * * *',            // Every day at midnight
      'weekly': '0 0 * * 0',           // Every Sunday at midnight
      'monthly': '0 0 1 * *',          // First day of month at midnight
      'every-6-hours': '0 */6 * * *',  // Every 6 hours
      'every-12-hours': '0 */12 * * *' // Every 12 hours
    };
    
    return expressions[frequency] || null;
  }

  getNextRunTime(cronExpression) {
    // Simple approximation - for demo purposes
    const frequencies = {
      '0 * * * *': 'Next hour',
      '0 0 * * *': 'Tomorrow at midnight',
      '0 0 * * 0': 'Next Sunday',
      '0 0 1 * *': 'Next month',
      '0 */6 * * *': 'In 6 hours',
      '0 */12 * * *': 'In 12 hours'
    };
    
    return frequencies[cronExpression] || 'Scheduled';
  }
}

module.exports = new ScheduledScanService();
