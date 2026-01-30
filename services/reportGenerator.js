const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

class ReportGenerator {
  generateScanReport(scan, vulnerabilities, outputPath) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        const stream = fs.createWriteStream(outputPath);

        doc.pipe(stream);

        // Header
        this.addHeader(doc);
        
        // Scan Information
        this.addScanInfo(doc, scan);
        
        // Executive Summary
        this.addExecutiveSummary(doc, scan);
        
        // Vulnerabilities Details
        this.addVulnerabilities(doc, vulnerabilities);
        
        // Recommendations
        this.addRecommendations(doc, vulnerabilities);
        
        // Footer
        this.addFooter(doc);

        doc.end();

        stream.on('finish', () => {
          resolve(outputPath);
        });

        stream.on('error', reject);
      } catch (error) {
        reject(error);
      }
    });
  }

  addHeader(doc) {
    doc.fontSize(24)
       .fillColor('#00d4ff')
       .text('🛡️ SECURITY ASSESSMENT REPORT', { align: 'center' })
       .moveDown();
    
    doc.fontSize(12)
       .fillColor('#666')
       .text('VulnGuard Platform - Vulnerability Management System', { align: 'center' })
       .moveDown(2);
    
    doc.moveTo(50, doc.y)
       .lineTo(550, doc.y)
       .strokeColor('#00d4ff')
       .lineWidth(2)
       .stroke()
       .moveDown();
  }

  addScanInfo(doc, scan) {
    doc.fontSize(16)
       .fillColor('#333')
       .text('Scan Information', { underline: true })
       .moveDown(0.5);

    doc.fontSize(11)
       .fillColor('#666')
       .text(`Target URL: ${scan.targetUrl}`)
       .text(`Scan Type: ${scan.scanType}`)
       .text(`Scan Date: ${new Date(scan.startTime).toLocaleString()}`)
       .text(`Duration: ${Math.round((new Date(scan.endTime) - new Date(scan.startTime)) / 1000)} seconds`)
       .text(`Status: ${scan.status}`)
       .moveDown(2);
  }

  addExecutiveSummary(doc, scan) {
    doc.fontSize(16)
       .fillColor('#333')
       .text('Executive Summary', { underline: true })
       .moveDown(0.5);

    // Risk Level Box
    const riskLevel = this.calculateRiskLevel(scan);
    const riskColor = this.getRiskColor(riskLevel);
    
    doc.rect(50, doc.y, 500, 80)
       .fillAndStroke(riskColor, '#333');
    
    doc.fontSize(14)
       .fillColor('#fff')
       .text(`Overall Risk Level: ${riskLevel}`, 60, doc.y - 70, { width: 480 })
       .fontSize(11)
       .text(`Total Vulnerabilities Found: ${scan.totalVulnerabilities || 0}`, 60, doc.y + 10);
    
    doc.moveDown(6);

    // Severity Breakdown
    doc.fontSize(12)
       .fillColor('#333')
       .text('Vulnerability Breakdown:', { underline: true })
       .moveDown(0.3);

    const severities = [
      { label: 'Critical', count: scan.criticalCount || 0, color: '#ff4757' },
      { label: 'High', count: scan.highCount || 0, color: '#ff7f50' },
      { label: 'Medium', count: scan.mediumCount || 0, color: '#ffc107' },
      { label: 'Low', count: scan.lowCount || 0, color: '#28a745' }
    ];

    severities.forEach(severity => {
      if (severity.count > 0) {
        doc.fontSize(11)
           .fillColor(severity.color)
           .text(`• ${severity.label}: ${severity.count}`, { indent: 20 });
      }
    });

    doc.moveDown(2);
  }

  addVulnerabilities(doc, vulnerabilities) {
    doc.addPage();
    
    doc.fontSize(16)
       .fillColor('#333')
       .text('Detailed Vulnerability Report', { underline: true })
       .moveDown();

    if (vulnerabilities.length === 0) {
      doc.fontSize(12)
         .fillColor('#28a745')
         .text('✓ No vulnerabilities detected. The target appears to be secure.')
         .moveDown(2);
      return;
    }

    vulnerabilities.forEach((vuln, index) => {
      // Check if we need a new page
      if (doc.y > 650) {
        doc.addPage();
      }

      const severityColor = this.getSeverityColor(vuln.severity);

      // Vulnerability Header
      doc.rect(50, doc.y, 500, 30)
         .fillAndStroke(severityColor, '#333');
      
      doc.fontSize(12)
         .fillColor('#fff')
         .text(`${index + 1}. ${vuln.vulnerabilityType}`, 60, doc.y - 22);
      
      doc.moveDown(2.5);

      // Severity Badge
      doc.fontSize(10)
         .fillColor(severityColor)
         .text(`Severity: ${vuln.severity}`, { indent: 10 })
         .fillColor('#666');

      // Description
      doc.fontSize(10)
         .fillColor('#333')
         .text('Description:', { indent: 10, underline: true })
         .fontSize(9)
         .fillColor('#666')
         .text(vuln.description, { indent: 10, width: 480 })
         .moveDown(0.5);

      // Location
      if (vuln.location) {
        doc.fontSize(10)
           .fillColor('#333')
           .text('Location:', { indent: 10, underline: true })
           .fontSize(9)
           .fillColor('#666')
           .text(vuln.location, { indent: 10, width: 480 })
           .moveDown(0.5);
      }

      // Payload
      if (vuln.payload) {
        doc.fontSize(10)
           .fillColor('#333')
           .text('Payload:', { indent: 10, underline: true })
           .fontSize(9)
           .fillColor('#666')
           .text(vuln.payload, { indent: 10, width: 480 })
           .moveDown(0.5);
      }

      // Recommendation
      if (vuln.recommendation) {
        doc.rect(50, doc.y, 500, 50)
           .fillAndStroke('#e8f5e9', '#4caf50');
        
        doc.fontSize(9)
           .fillColor('#1b5e20')
           .text(`💡 Recommendation: ${vuln.recommendation}`, 60, doc.y - 40, { width: 480 });
        
        doc.moveDown(4);
      }

      doc.moveDown(1);
    });
  }

  addRecommendations(doc, vulnerabilities) {
    doc.addPage();
    
    doc.fontSize(16)
       .fillColor('#333')
       .text('General Recommendations', { underline: true })
       .moveDown();

    const recommendations = [
      'Implement a regular vulnerability scanning schedule',
      'Prioritize remediation based on severity levels',
      'Keep all software and dependencies up to date',
      'Implement proper input validation and sanitization',
      'Use security headers (CSP, HSTS, X-Frame-Options, etc.)',
      'Enable HTTPS with valid SSL/TLS certificates',
      'Implement proper authentication and authorization',
      'Regular security training for development team',
      'Conduct penetration testing before production deployment',
      'Monitor and log security events continuously'
    ];

    doc.fontSize(10)
       .fillColor('#666');

    recommendations.forEach((rec, index) => {
      doc.text(`${index + 1}. ${rec}`, { indent: 10 })
         .moveDown(0.3);
    });

    doc.moveDown(2);

    // Critical Vulnerabilities Warning
    const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
    if (criticalCount > 0) {
      doc.rect(50, doc.y, 500, 60)
         .fillAndStroke('#ffebee', '#ff4757');
      
      doc.fontSize(11)
         .fillColor('#c62828')
         .text(`⚠️ URGENT: ${criticalCount} Critical vulnerabilities require immediate attention!`, 
               60, doc.y - 45, { width: 480 })
         .text('Please address these issues as soon as possible to prevent security breaches.', 
               60, doc.y + 5, { width: 480 });
    }
  }

  addFooter(doc) {
    doc.moveDown(3);
    
    doc.moveTo(50, doc.y)
       .lineTo(550, doc.y)
       .strokeColor('#ccc')
       .lineWidth(1)
       .stroke()
       .moveDown(0.5);

    doc.fontSize(9)
       .fillColor('#999')
       .text(`Report Generated: ${new Date().toLocaleString()}`, { align: 'center' })
       .text('VulnGuard Platform - Vulnerability Management & Honeypot System', { align: 'center' })
       .text('For educational and authorized security testing only', { align: 'center' });
  }

  calculateRiskLevel(scan) {
    const critical = scan.criticalCount || 0;
    const high = scan.highCount || 0;
    const medium = scan.mediumCount || 0;
    
    if (critical > 0) return 'CRITICAL';
    if (high >= 3) return 'HIGH';
    if (high > 0 || medium >= 5) return 'MEDIUM';
    if (medium > 0) return 'LOW';
    return 'MINIMAL';
  }

  getRiskColor(level) {
    const colors = {
      'CRITICAL': '#d32f2f',
      'HIGH': '#f57c00',
      'MEDIUM': '#fbc02d',
      'LOW': '#7cb342',
      'MINIMAL': '#43a047'
    };
    return colors[level] || '#666';
  }

  getSeverityColor(severity) {
    const colors = {
      'Critical': '#ff4757',
      'High': '#ff7f50',
      'Medium': '#ffc107',
      'Low': '#28a745',
      'Info': '#00d4ff'
    };
    return colors[severity] || '#666';
  }
}

module.exports = new ReportGenerator();
