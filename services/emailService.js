const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = null;
    this.enabled = process.env.ENABLE_EMAIL_ALERTS === 'true';
    
    if (this.enabled) {
      this.initializeTransporter();
    }
  }

  initializeTransporter() {
    try {
      this.transporter = nodemailer.createTransporter({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: false,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD
        }
      });
      console.log('✓ Email service initialized');
    } catch (error) {
      console.error('Email service initialization failed:', error.message);
      this.enabled = false;
    }
  }

  async sendCriticalVulnerabilityAlert(vulnerability, scan) {
    if (!this.enabled || !this.transporter) {
      console.log('Email alerts disabled - skipping');
      return;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: process.env.ALERT_EMAIL,
      subject: `🚨 CRITICAL VULNERABILITY DETECTED - ${vulnerability.vulnerabilityType}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #ff4757 0%, #ff6b7a 100%); padding: 20px; color: white;">
            <h1 style="margin: 0;">🛡️ Critical Security Alert</h1>
          </div>
          
          <div style="padding: 20px; background: #f5f5f5;">
            <h2 style="color: #ff4757; margin-top: 0;">Critical Vulnerability Detected</h2>
            
            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <p style="margin: 5px 0;"><strong>Vulnerability Type:</strong> ${vulnerability.vulnerabilityType}</p>
              <p style="margin: 5px 0;"><strong>Severity:</strong> <span style="color: #ff4757; font-weight: bold;">${vulnerability.severity}</span></p>
              <p style="margin: 5px 0;"><strong>Target URL:</strong> ${scan.targetUrl}</p>
              <p style="margin: 5px 0;"><strong>Discovered:</strong> ${new Date().toLocaleString()}</p>
            </div>

            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <h3 style="margin-top: 0; color: #333;">Description</h3>
              <p style="color: #666;">${vulnerability.description}</p>
            </div>

            ${vulnerability.location ? `
            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <h3 style="margin-top: 0; color: #333;">Location</h3>
              <p style="color: #666; word-break: break-all;">${vulnerability.location}</p>
            </div>
            ` : ''}

            <div style="background: #e8f5e9; padding: 15px; border-radius: 8px; border-left: 4px solid #4caf50;">
              <h3 style="margin-top: 0; color: #2e7d32;">💡 Recommendation</h3>
              <p style="color: #1b5e20; margin: 0;">${vulnerability.recommendation}</p>
            </div>

            <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
              <p style="margin: 0; color: #856404;">
                <strong>⚠️ Action Required:</strong> Please review and remediate this vulnerability as soon as possible.
              </p>
            </div>
          </div>

          <div style="background: #333; padding: 15px; text-align: center; color: white;">
            <p style="margin: 0; font-size: 12px;">
              This is an automated alert from VulnGuard Platform<br>
              For more details, visit your security dashboard
            </p>
          </div>
        </div>
      `
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`✓ Critical vulnerability alert email sent for ${vulnerability.vulnerabilityType}`);
    } catch (error) {
      console.error('Failed to send email alert:', error.message);
    }
  }

  async sendScanCompleteNotification(scan, vulnerabilityCount) {
    if (!this.enabled || !this.transporter) {
      return;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: process.env.ALERT_EMAIL,
      subject: `✅ Scan Complete - ${vulnerabilityCount} Vulnerabilities Found`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #00d4ff 0%, #0088cc 100%); padding: 20px; color: white;">
            <h1 style="margin: 0;">🛡️ Scan Complete</h1>
          </div>
          
          <div style="padding: 20px; background: #f5f5f5;">
            <h2 style="color: #0088cc; margin-top: 0;">Vulnerability Scan Completed</h2>
            
            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <p style="margin: 5px 0;"><strong>Target:</strong> ${scan.targetUrl}</p>
              <p style="margin: 5px 0;"><strong>Scan Time:</strong> ${new Date(scan.startTime).toLocaleString()}</p>
              <p style="margin: 5px 0;"><strong>Duration:</strong> ${Math.round((new Date(scan.endTime) - new Date(scan.startTime)) / 1000)} seconds</p>
            </div>

            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <h3 style="margin-top: 0; color: #333;">Results Summary</h3>
              <p style="margin: 5px 0;"><strong>Total Vulnerabilities:</strong> ${vulnerabilityCount}</p>
              <p style="margin: 5px 0; color: #ff4757;"><strong>Critical:</strong> ${scan.criticalCount || 0}</p>
              <p style="margin: 5px 0; color: #ff7f50;"><strong>High:</strong> ${scan.highCount || 0}</p>
              <p style="margin: 5px 0; color: #ffc107;"><strong>Medium:</strong> ${scan.mediumCount || 0}</p>
              <p style="margin: 5px 0; color: #28a745;"><strong>Low:</strong> ${scan.lowCount || 0}</p>
            </div>
          </div>

          <div style="background: #333; padding: 15px; text-align: center; color: white;">
            <p style="margin: 0; font-size: 12px;">
              VulnGuard Platform - Automated Security Scanning
            </p>
          </div>
        </div>
      `
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`✓ Scan completion email sent`);
    } catch (error) {
      console.error('Failed to send scan complete email:', error.message);
    }
  }

  async sendAttackAlert(attack) {
    if (!this.enabled || !this.transporter) {
      return;
    }

    // Only send for critical/high severity attacks
    if (!['Critical', 'High'].includes(attack.severity)) {
      return;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: process.env.ALERT_EMAIL,
      subject: `🚨 ${attack.severity.toUpperCase()} ATTACK DETECTED - ${attack.attackType}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #ff4757 0%, #ff6b7a 100%); padding: 20px; color: white;">
            <h1 style="margin: 0;">🍯 Attack Detected</h1>
          </div>
          
          <div style="padding: 20px; background: #f5f5f5;">
            <h2 style="color: #ff4757; margin-top: 0;">${attack.attackType} Attempt</h2>
            
            <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
              <p style="margin: 5px 0;"><strong>Attack Type:</strong> ${attack.attackType}</p>
              <p style="margin: 5px 0;"><strong>Severity:</strong> <span style="color: #ff4757; font-weight: bold;">${attack.severity}</span></p>
              <p style="margin: 5px 0;"><strong>Source IP:</strong> ${attack.sourceIp}</p>
              <p style="margin: 5px 0;"><strong>Target:</strong> ${attack.targetEndpoint}</p>
              <p style="margin: 5px 0;"><strong>Time:</strong> ${new Date(attack.timestamp).toLocaleString()}</p>
            </div>

            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;">
              <p style="margin: 0; color: #856404;">
                <strong>⚠️ Action:</strong> Review honeypot logs for detailed attack information.
              </p>
            </div>
          </div>

          <div style="background: #333; padding: 15px; text-align: center; color: white;">
            <p style="margin: 0; font-size: 12px;">
              VulnGuard Honeypot System - Real-time Threat Detection
            </p>
          </div>
        </div>
      `
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`✓ Attack alert email sent for ${attack.attackType}`);
    } catch (error) {
      console.error('Failed to send attack alert email:', error.message);
    }
  }
}

module.exports = new EmailService();
