const axios = require('axios');
const cheerio = require('cheerio');

class VulnerabilityScanner {
  constructor(targetUrl) {
    this.targetUrl = targetUrl;
    this.vulnerabilities = [];
  }

  // SQL Injection Detection
  async detectSQLInjection() {
    const sqlPayloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin'--",
      "' UNION SELECT NULL--",
      "1' AND '1'='1"
    ];

    const sqlErrors = [
      'sql syntax',
      'mysql_fetch',
      'mysqli',
      'ORA-',
      'PostgreSQL',
      'SQLite',
      'Microsoft SQL',
      'ODBC',
      'syntax error'
    ];

    for (const payload of sqlPayloads) {
      try {
        const testUrl = `${this.targetUrl}?id=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { timeout: 5000 });
        const responseText = response.data.toLowerCase();

        for (const error of sqlErrors) {
          if (responseText.includes(error.toLowerCase())) {
            this.vulnerabilities.push({
              type: 'SQL Injection',
              severity: 'Critical',
              location: testUrl,
              payload: payload,
              description: `SQL Injection vulnerability detected. The application is vulnerable to SQL injection attacks via the 'id' parameter.`,
              recommendation: 'Use parameterized queries or prepared statements. Implement input validation and sanitization.'
            });
            return;
          }
        }
      } catch (error) {
        // Continue testing
      }
    }
  }

  // XSS Detection
  async detectXSS() {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg/onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')">',
      '<body onload=alert("XSS")>'
    ];

    for (const payload of xssPayloads) {
      try {
        const testUrl = `${this.targetUrl}?search=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { timeout: 5000 });
        const responseText = response.data;

        // Check if payload is reflected in response
        if (responseText.includes(payload) || responseText.includes(payload.toLowerCase())) {
          this.vulnerabilities.push({
            type: 'XSS',
            severity: 'High',
            location: testUrl,
            payload: payload,
            description: 'Cross-Site Scripting (XSS) vulnerability detected. User input is reflected without proper sanitization.',
            recommendation: 'Implement output encoding, use Content Security Policy (CSP), and sanitize all user inputs.'
          });
          return;
        }
      } catch (error) {
        // Continue testing
      }
    }
  }

  // Security Headers Check
  async checkSecurityHeaders() {
    try {
      const response = await axios.get(this.targetUrl, { timeout: 5000 });
      const headers = response.headers;

      const securityHeaders = {
        'x-frame-options': 'Missing X-Frame-Options header - vulnerable to clickjacking',
        'x-content-type-options': 'Missing X-Content-Type-Options header',
        'strict-transport-security': 'Missing HSTS header - vulnerable to man-in-the-middle attacks',
        'content-security-policy': 'Missing Content Security Policy header',
        'x-xss-protection': 'Missing X-XSS-Protection header'
      };

      for (const [header, message] of Object.entries(securityHeaders)) {
        if (!headers[header]) {
          this.vulnerabilities.push({
            type: 'Security Misconfiguration',
            severity: header === 'strict-transport-security' ? 'High' : 'Medium',
            location: this.targetUrl,
            description: message,
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
          recommendation: 'Remove or obfuscate server version information.'
        });
      }
    } catch (error) {
      console.error('Error checking security headers:', error.message);
    }
  }

  // Insecure HTTP Check
  async checkHTTPS() {
    if (this.targetUrl.startsWith('http://')) {
      this.vulnerabilities.push({
        type: 'Sensitive Data Exposure',
        severity: 'High',
        location: this.targetUrl,
        description: 'Website is served over HTTP instead of HTTPS. Data transmitted is not encrypted.',
        recommendation: 'Implement HTTPS with a valid SSL/TLS certificate.'
      });
    }
  }

  // Directory Listing Check
  async checkDirectoryListing() {
    const commonPaths = [
      '/admin',
      '/backup',
      '/uploads',
      '/temp',
      '/logs',
      '/config'
    ];

    for (const path of commonPaths) {
      try {
        const testUrl = `${this.targetUrl}${path}`;
        const response = await axios.get(testUrl, { timeout: 5000 });
        const $ = cheerio.load(response.data);
        const title = $('title').text().toLowerCase();

        if (title.includes('index of') || response.data.includes('Parent Directory')) {
          this.vulnerabilities.push({
            type: 'Security Misconfiguration',
            severity: 'Medium',
            location: testUrl,
            description: `Directory listing enabled at ${path}`,
            recommendation: 'Disable directory listing in web server configuration.'
          });
        }
      } catch (error) {
        // Path doesn't exist or other error, continue
      }
    }
  }

  // Robots.txt Analysis
  async analyzeRobotsTxt() {
    try {
      const robotsUrl = `${this.targetUrl}/robots.txt`;
      const response = await axios.get(robotsUrl, { timeout: 5000 });
      
      const sensitivePatterns = ['admin', 'backup', 'config', 'secret', 'private', 'internal'];
      const lines = response.data.split('\n');
      
      for (const line of lines) {
        const lowerLine = line.toLowerCase();
        if (lowerLine.startsWith('disallow:')) {
          for (const pattern of sensitivePatterns) {
            if (lowerLine.includes(pattern)) {
              this.vulnerabilities.push({
                type: 'Sensitive Data Exposure',
                severity: 'Low',
                location: robotsUrl,
                description: `Sensitive path disclosed in robots.txt: ${line.trim()}`,
                recommendation: 'Review robots.txt for sensitive information disclosure.'
              });
              break;
            }
          }
        }
      }
    } catch (error) {
      // robots.txt not found or error
    }
  }

  // Run all scans
  async runFullScan() {
    console.log(`Starting vulnerability scan for: ${this.targetUrl}`);
    
    await this.checkHTTPS();
    await this.checkSecurityHeaders();
    await this.detectSQLInjection();
    await this.detectXSS();
    await this.checkDirectoryListing();
    await this.analyzeRobotsTxt();

    return this.vulnerabilities;
  }
}

module.exports = VulnerabilityScanner;
