const nmap = require('node-nmap');
const axios = require('axios');

class NmapVulnerabilityScanner {
  constructor(targetUrl) {
    // Extract hostname from URL
    this.targetUrl = targetUrl;
    this.target = this.extractHostname(targetUrl);
    this.vulnerabilities = [];
    this.scanResults = null;
  }

  extractHostname(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      // If not a valid URL, assume it's just a hostname/IP
      return url.replace(/^https?:\/\//, '').split('/')[0];
    }
  }

  // Main Nmap scan with vulnerability detection
  async performNmapScan() {
    return new Promise((resolve, reject) => {
      const nmapScan = new nmap.NmapScan(this.target);

      // Configure Nmap scan
      nmapScan.on('complete', (data) => {
        this.scanResults = data;
        console.log(`✓ Nmap scan completed for ${this.target}`);
        resolve(data);
      });

      nmapScan.on('error', (error) => {
        console.error('Nmap scan error:', error);
        reject(error);
      });

      // Start comprehensive scan
      // -sV: Service version detection
      // -sC: Default scripts (includes vuln detection)
      // --script vuln: Vulnerability detection scripts
      // -p-: Scan all ports (use -p 1-1000 for faster scans)
      nmapScan.startScan('-sV -sC -p 1-1000 --script vuln');
    });
  }

  // Quick port scan (faster)
  async performQuickScan() {
    return new Promise((resolve, reject) => {
      const quickScan = new nmap.QuickScan(this.target);

      quickScan.on('complete', (data) => {
        this.scanResults = data;
        console.log(`✓ Quick scan completed for ${this.target}`);
        resolve(data);
      });

      quickScan.on('error', (error) => {
        console.error('Quick scan error:', error);
        reject(error);
      });

      quickScan.startScan();
    });
  }

  // Analyze Nmap results and convert to vulnerabilities
  analyzeNmapResults(nmapData) {
    if (!nmapData || !nmapData.length) {
      console.log('No Nmap results to analyze');
      return;
    }

    nmapData.forEach(host => {
      // Check open ports
      if (host.openPorts && host.openPorts.length > 0) {
        host.openPorts.forEach(port => {
          // Detect potentially vulnerable services
          this.detectVulnerableServices(port, host.ip);
          
          // Check for CVEs in service versions
          this.checkServiceVersion(port, host.ip);
        });
      }

      // Analyze OS detection
      if (host.osNmap && host.osNmap.length > 0) {
        this.analyzeOS(host.osNmap, host.ip);
      }
    });
  }

  detectVulnerableServices(port, hostIp) {
    const vulnerableServices = {
      '21': { service: 'FTP', risk: 'High', description: 'FTP service detected - potential anonymous login or brute force target' },
      '23': { service: 'Telnet', risk: 'Critical', description: 'Telnet detected - unencrypted protocol, credentials sent in plaintext' },
      '25': { service: 'SMTP', risk: 'Medium', description: 'SMTP open relay potential - can be used for spam' },
      '53': { service: 'DNS', risk: 'Medium', description: 'DNS service - potential DNS amplification attack vector' },
      '139': { service: 'NetBIOS', risk: 'High', description: 'NetBIOS detected - potential information disclosure' },
      '445': { service: 'SMB', risk: 'Critical', description: 'SMB service - vulnerable to EternalBlue and ransomware attacks' },
      '1433': { service: 'MSSQL', risk: 'High', description: 'Microsoft SQL Server detected - potential SQL injection target' },
      '3306': { service: 'MySQL', risk: 'High', description: 'MySQL database exposed - authentication brute force risk' },
      '3389': { service: 'RDP', risk: 'Critical', description: 'Remote Desktop Protocol - brute force and BlueKeep vulnerability risk' },
      '5432': { service: 'PostgreSQL', risk: 'High', description: 'PostgreSQL database exposed' },
      '6379': { service: 'Redis', risk: 'Critical', description: 'Redis exposed - often misconfigured without authentication' },
      '27017': { service: 'MongoDB', risk: 'Critical', description: 'MongoDB exposed - potential NoSQL injection and data breach' }
    };

    const portNum = port.port.toString();
    if (vulnerableServices[portNum]) {
      const vuln = vulnerableServices[portNum];
      
      let severity = 'Medium';
      if (vuln.risk === 'Critical') severity = 'Critical';
      else if (vuln.risk === 'High') severity = 'High';

      this.vulnerabilities.push({
        type: 'Security Misconfiguration',
        severity: severity,
        location: `${hostIp}:${portNum}`,
        description: `${vuln.service} service detected on port ${portNum}. ${vuln.description}`,
        payload: null,
        recommendation: `Close port ${portNum} if not needed, implement firewall rules, enable authentication, and use encrypted alternatives.`
      });
    }

    // Check for outdated/vulnerable service versions
    if (port.service && port.service.version) {
      this.checkForKnownVulnerabilities(port, hostIp);
    }
  }

  checkServiceVersion(port, hostIp) {
    if (!port.service || !port.service.version) return;

    const service = port.service.name || 'Unknown';
    const version = port.service.version;

    // Example: Detect common vulnerable versions
    const vulnerableVersions = [
      { service: 'Apache', versions: ['2.4.49', '2.4.50'], cve: 'CVE-2021-41773', severity: 'Critical' },
      { service: 'OpenSSH', versions: ['7.4'], cve: 'CVE-2018-15473', severity: 'Medium' },
      { service: 'vsftpd', versions: ['2.3.4'], cve: 'Backdoor', severity: 'Critical' },
      { service: 'ProFTPD', versions: ['1.3.3c'], cve: 'CVE-2010-4221', severity: 'High' },
    ];

    vulnerableVersions.forEach(vuln => {
      if (service.toLowerCase().includes(vuln.service.toLowerCase())) {
        vuln.versions.forEach(vulnVersion => {
          if (version.includes(vulnVersion)) {
            this.vulnerabilities.push({
              type: 'Using Components with Known Vulnerabilities',
              severity: vuln.severity,
              location: `${hostIp}:${port.port}`,
              description: `Vulnerable ${vuln.service} version ${version} detected. Known vulnerability: ${vuln.cve}`,
              payload: null,
              recommendation: `Upgrade ${vuln.service} to the latest stable version immediately. Apply security patches.`
            });
          }
        });
      }
    });
  }

  checkForKnownVulnerabilities(port, hostIp) {
    // Check for services that commonly have vulnerabilities
    const serviceName = (port.service.name || '').toLowerCase();
    
    if (serviceName.includes('http') || serviceName.includes('apache') || serviceName.includes('nginx')) {
      // Web server detected
      this.vulnerabilities.push({
        type: 'Security Misconfiguration',
        severity: 'Low',
        location: `${hostIp}:${port.port}`,
        description: `Web server ${port.service.name} ${port.service.version || ''} detected. Ensure it's properly configured.`,
        payload: null,
        recommendation: 'Review web server configuration, disable directory listing, remove default pages, implement security headers.'
      });
    }

    if (serviceName.includes('ssl') || serviceName.includes('tls')) {
      // Check for SSL/TLS issues
      this.vulnerabilities.push({
        type: 'Sensitive Data Exposure',
        severity: 'Medium',
        location: `${hostIp}:${port.port}`,
        description: 'SSL/TLS service detected. Verify it uses strong ciphers and recent protocol versions.',
        payload: null,
        recommendation: 'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Use TLS 1.2+ with strong cipher suites. Implement HSTS.'
      });
    }
  }

  analyzeOS(osInfo, hostIp) {
    osInfo.forEach(os => {
      if (os.osFamily) {
        // Check for outdated OS
        if (os.osFamily.toLowerCase().includes('windows xp') || 
            os.osFamily.toLowerCase().includes('windows 2003') ||
            os.osFamily.toLowerCase().includes('windows 7')) {
          this.vulnerabilities.push({
            type: 'Security Misconfiguration',
            severity: 'Critical',
            location: hostIp,
            description: `Outdated operating system detected: ${os.osFamily}. No longer receives security updates.`,
            payload: null,
            recommendation: 'Upgrade to a supported operating system version immediately. Outdated systems are highly vulnerable to exploits.'
          });
        }
      }
    });
  }

  // Still perform HTTP-based checks for web apps
  async performWebSecurityChecks() {
    try {
      const response = await axios.get(this.targetUrl, { 
        timeout: 5000,
        validateStatus: () => true // Accept any status
      });
      
      const headers = response.headers;

      // Check security headers
      const securityHeaders = {
        'x-frame-options': { missing: 'Missing X-Frame-Options header - vulnerable to clickjacking', severity: 'Medium' },
        'x-content-type-options': { missing: 'Missing X-Content-Type-Options header', severity: 'Low' },
        'strict-transport-security': { missing: 'Missing HSTS header - vulnerable to man-in-the-middle attacks', severity: 'High' },
        'content-security-policy': { missing: 'Missing Content Security Policy header', severity: 'Medium' },
        'x-xss-protection': { missing: 'Missing X-XSS-Protection header', severity: 'Low' }
      };

      for (const [header, info] of Object.entries(securityHeaders)) {
        if (!headers[header]) {
          this.vulnerabilities.push({
            type: 'Security Misconfiguration',
            severity: info.severity,
            location: this.targetUrl,
            description: info.missing,
            payload: null,
            recommendation: `Implement the ${header} header to enhance security.`
          });
        }
      }

      // Check for information disclosure
      if (headers['server']) {
        this.vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          severity: 'Low',
          location: this.targetUrl,
          description: `Server banner disclosure: ${headers['server']}`,
          payload: null,
          recommendation: 'Remove or obfuscate server version information in HTTP headers.'
        });
      }

      // Check protocol
      if (this.targetUrl.startsWith('http://')) {
        this.vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          severity: 'High',
          location: this.targetUrl,
          description: 'Website served over HTTP instead of HTTPS. Data transmitted is not encrypted.',
          payload: null,
          recommendation: 'Implement HTTPS with a valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.'
        });
      }

    } catch (error) {
      console.error('Error performing web security checks:', error.message);
    }
  }

  // Main scan method
  async runFullScan(scanType = 'Quick') {
    console.log(`Starting ${scanType} Nmap scan for: ${this.target}`);
    
    try {
      // Perform Nmap scan
      let nmapData;
      if (scanType === 'Full') {
        nmapData = await this.performNmapScan();
      } else {
        nmapData = await this.performQuickScan();
      }

      // Analyze Nmap results
      this.analyzeNmapResults(nmapData);

      // Also perform web-based checks if it's a web URL
      if (this.targetUrl.startsWith('http')) {
        await this.performWebSecurityChecks();
      }

      console.log(`✓ Scan completed. Found ${this.vulnerabilities.length} potential vulnerabilities.`);
      
      return this.vulnerabilities;

    } catch (error) {
      console.error('Error during Nmap scan:', error);
      
      // Fallback to web-only checks if Nmap fails
      if (this.targetUrl.startsWith('http')) {
        console.log('Falling back to web-only security checks...');
        await this.performWebSecurityChecks();
        return this.vulnerabilities;
      }
      
      throw error;
    }
  }

  // Get detailed scan results
  getScanResults() {
    return {
      target: this.target,
      vulnerabilities: this.vulnerabilities,
      nmapData: this.scanResults
    };
  }
}

module.exports = NmapVulnerabilityScanner;