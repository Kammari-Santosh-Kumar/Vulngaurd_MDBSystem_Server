const AttackLog = require('../models/AttackLog');
const geoip = require('geoip-lite');

// Detect SQL Injection patterns
const detectSQLInjection = (input) => {
  const sqlPatterns = [
    /(\bOR\b|\bAND\b).*?=.*?/i,
    /'\s*(OR|AND)\s*'?\d+/i,
    /(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i,
    /--|\#|\/\*/i,
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /admin'--/i,
    /'\s*OR\s*1\s*=\s*1/i
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
};

// Detect XSS patterns
const detectXSS = (input) => {
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /<img[^>]+src[^>]*>/i,
    /<svg[^>]*onload/i
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
};

// Detect Path Traversal
const detectPathTraversal = (input) => {
  const pathPatterns = [
    /\.\.[\/\\]/,
    /\.\.%2[fF]/,
    /%2e%2e[\/\\]/i,
    /\/etc\/passwd/i,
    /\/windows\/system32/i
  ];
  
  return pathPatterns.some(pattern => pattern.test(input));
};

// Detect Command Injection
const detectCommandInjection = (input) => {
  const cmdPatterns = [
    /;\s*(ls|cat|pwd|whoami|id|uname)/i,
    /\|\s*(ls|cat|pwd)/i,
    /`.*`/,
    /\$\(.*\)/,
    /&&\s*\w+/
  ];
  
  return cmdPatterns.some(pattern => pattern.test(input));
};

// Main honeypot middleware
const honeypotMiddleware = async (req, res, next) => {
  try {
    const sourceIp = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent');
    const targetEndpoint = req.originalUrl;
    const httpMethod = req.method;

    let attackDetected = false;
    let attackType = 'Other';
    let severity = 'Low';

    // Combine all inputs for analysis
    const allInputs = [
      ...Object.values(req.query || {}),
      ...Object.values(req.body || {}),
      ...Object.values(req.params || {})
    ].join(' ');

    // Detect attack types
    if (detectSQLInjection(allInputs)) {
      attackDetected = true;
      attackType = 'SQL Injection';
      severity = 'Critical';
    } else if (detectXSS(allInputs)) {
      attackDetected = true;
      attackType = 'XSS';
      severity = 'High';
    } else if (detectPathTraversal(allInputs)) {
      attackDetected = true;
      attackType = 'Path Traversal';
      severity = 'High';
    } else if (detectCommandInjection(allInputs)) {
      attackDetected = true;
      attackType = 'Command Injection';
      severity = 'Critical';
    }

    // Log if attack detected
    if (attackDetected) {
      // Get geolocation from IP
      const geo = geoip.lookup(sourceIp);
      
      await AttackLog.create({
        timestamp: new Date(),
        attackType,
        sourceIp,
        userAgent,
        targetEndpoint,
        httpMethod,
        payload: {
          query: req.query,
          body: req.body,
          params: req.params
        },
        headers: req.headers,
        severity,
        blocked: false,
        country: geo ? geo.country : 'Unknown',
        geolocation: geo ? {
          country: geo.country,
          region: geo.region,
          city: geo.city,
          ll: geo.ll, // [latitude, longitude]
          timezone: geo.timezone
        } : null
      });

      console.log(`⚠️  Attack detected: ${attackType} from ${sourceIp} (${geo ? geo.country : 'Unknown'})`);
    }

    next();
  } catch (error) {
    console.error('Error in honeypot middleware:', error);
    next();
  }
};

module.exports = { honeypotMiddleware };
