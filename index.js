
const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs').promises;
const path = require('path');
const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Vulnerability database
const VULNERABILITY_PATTERNS = {
  xss_patterns: [
    '<script>',
    'javascript:',
    'onload=',
    'onerror=',
    'onclick=',
    'onmouseover='
  ],
  sql_injection: [
    'error in your SQL syntax',
    'mysql_fetch_array',
    'ORA-01756',
    'Microsoft OLE DB Provider',
    'PostgreSQL query failed'
  ],
  directory_traversal: [
    '../',
    '..\\',
    '%2e%2e%2f',
    '%2e%2e%5c'
  ],
  information_disclosure: [
    'phpinfo()',
    'Server: Apache',
    'X-Powered-By:',
    'index of /',
    'directory listing'
  ]
};

// Common vulnerable endpoints
const COMMON_ENDPOINTS = [
  '/admin',
  '/login',
  '/wp-admin',
  '/phpmyadmin',
  '/config.php',
  '/robots.txt',
  '/.env',
  '/backup',
  '/test',
  '/debug'
];

class WebSecurityScanner {
  constructor(target) {
    this.target = target;
    this.vulnerabilities = [];
    this.headers = {
      'User-Agent': 'SecurityScanner/1.0 (Educational Purpose)'
    };
  }

  async scanTarget() {
    console.log(`🔍 Starting security scan for: ${this.target}`);
    
    try {
      await this.checkBasicInfo();
      await this.scanCommonEndpoints();
      await this.checkHeaders();
      await this.scanForXSS();
      await this.checkDirectoryTraversal();
      await this.scanForSQLInjection();
      await this.checkSSL();
      
      return this.generateReport();
    } catch (error) {
      console.error('Scan error:', error.message);
      return { error: error.message };
    }
  }

  async checkBasicInfo() {
    try {
      const response = await axios.get(this.target, { 
        headers: this.headers,
        timeout: 10000 
      });
      
      const $ = cheerio.load(response.data);
      
      // Check for sensitive information in HTML
      if (response.data.includes('password') || response.data.includes('admin')) {
        this.addVulnerability('INFO_DISCLOSURE', 
          'Sensitive keywords found in HTML',
          'Low',
          'HTML source contains sensitive keywords'
        );
      }

      // Check for comments with sensitive info
      const comments = response.data.match(/<!--[\s\S]*?-->/g) || [];
      comments.forEach(comment => {
        if (comment.toLowerCase().includes('password') || 
            comment.toLowerCase().includes('todo') ||
            comment.toLowerCase().includes('bug')) {
          this.addVulnerability('INFO_DISCLOSURE',
            'Sensitive information in HTML comments',
            'Medium',
            `Found: ${comment.substring(0, 100)}...`
          );
        }
      });

    } catch (error) {
      console.log('Basic info check failed:', error.message);
    }
  }

  async scanCommonEndpoints() {
    console.log('🔍 Scanning common endpoints...');
    
    for (const endpoint of COMMON_ENDPOINTS) {
      try {
        const url = this.target + endpoint;
        const response = await axios.get(url, { 
          headers: this.headers,
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200) {
          this.addVulnerability('ENDPOINT_EXPOSURE',
            `Accessible endpoint found: ${endpoint}`,
            'Medium',
            `Endpoint ${endpoint} is publicly accessible (Status: ${response.status})`
          );
        }

        if (response.status === 403) {
          this.addVulnerability('ENDPOINT_FORBIDDEN',
            `Forbidden endpoint detected: ${endpoint}`,
            'Low',
            `Endpoint exists but access is forbidden (Status: ${response.status})`
          );
        }

      } catch (error) {
        // Endpoint not found or error - this is good
      }
    }
  }

  async checkHeaders() {
    console.log('🔍 Analyzing security headers...');
    
    try {
      const response = await axios.head(this.target, { 
        headers: this.headers,
        timeout: 5000 
      });

      const securityHeaders = [
        'X-Frame-Options',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy'
      ];

      securityHeaders.forEach(header => {
        if (!response.headers[header.toLowerCase()]) {
          this.addVulnerability('MISSING_SECURITY_HEADER',
            `Missing security header: ${header}`,
            'Medium',
            `The ${header} security header is not set`
          );
        }
      });

      // Check for information disclosure headers
      const infoHeaders = ['Server', 'X-Powered-By'];
      infoHeaders.forEach(header => {
        if (response.headers[header.toLowerCase()]) {
          this.addVulnerability('INFO_DISCLOSURE',
            `Information disclosure in headers: ${header}`,
            'Low',
            `Header reveals: ${response.headers[header.toLowerCase()]}`
          );
        }
      });

    } catch (error) {
      console.log('Header check failed:', error.message);
    }
  }

  async scanForXSS() {
    console.log('🔍 Testing for XSS vulnerabilities...');
    
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      'javascript:alert("XSS")',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>'
    ];

    for (const payload of xssPayloads) {
      try {
        const testUrl = `${this.target}?q=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { 
          headers: this.headers,
          timeout: 5000 
        });

        if (response.data.includes(payload)) {
          this.addVulnerability('XSS',
            'Potential XSS vulnerability detected',
            'High',
            `Payload reflected: ${payload}`
          );
        }

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async checkDirectoryTraversal() {
    console.log('🔍 Testing for directory traversal...');
    
    const traversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ];

    for (const payload of traversalPayloads) {
      try {
        const testUrl = `${this.target}?file=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { 
          headers: this.headers,
          timeout: 5000 
        });

        if (response.data.includes('root:') || 
            response.data.includes('localhost') ||
            response.data.includes('[hosts]')) {
          this.addVulnerability('DIRECTORY_TRAVERSAL',
            'Directory traversal vulnerability detected',
            'High',
            `Payload successful: ${payload}`
          );
        }

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async scanForSQLInjection() {
    console.log('🔍 Testing for SQL injection...');
    
    const sqlPayloads = [
      "' OR '1'='1",
      "' UNION SELECT NULL--",
      "'; DROP TABLE users--",
      "' AND 1=1--",
      "' OR 1=1#"
    ];

    for (const payload of sqlPayloads) {
      try {
        const testUrl = `${this.target}?id=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { 
          headers: this.headers,
          timeout: 5000 
        });

        VULNERABILITY_PATTERNS.sql_injection.forEach(pattern => {
          if (response.data.toLowerCase().includes(pattern.toLowerCase())) {
            this.addVulnerability('SQL_INJECTION',
              'Potential SQL injection vulnerability',
              'Critical',
              `Error pattern found: ${pattern}`
            );
          }
        });

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async checkSSL() {
    console.log('🔍 Checking SSL configuration...');
    
    if (!this.target.startsWith('https://')) {
      this.addVulnerability('SSL_NOT_USED',
        'Website does not use HTTPS',
        'Medium',
        'The website is not using secure HTTPS protocol'
      );
    }
  }

  addVulnerability(type, title, severity, description) {
    this.vulnerabilities.push({
      type,
      title,
      severity,
      description,
      timestamp: new Date().toISOString(),
      poc: this.generatePOC(type, description)
    });
  }

  generatePOC(type, description) {
    const pocTemplates = {
      XSS: `
        // XSS Proof of Concept
        // Target: ${this.target}
        // Test with: ${this.target}?q=<script>alert('XSS')</script>
        // Description: ${description}
      `,
      SQL_INJECTION: `
        // SQL Injection Proof of Concept
        // Target: ${this.target}
        // Test with: ${this.target}?id=' OR '1'='1
        // Description: ${description}
      `,
      DIRECTORY_TRAVERSAL: `
        // Directory Traversal Proof of Concept
        // Target: ${this.target}
        // Test with: ${this.target}?file=../../../etc/passwd
        // Description: ${description}
      `
    };

    return pocTemplates[type] || `// POC for ${type}\n// ${description}`;
  }

  generateReport() {
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };

    this.vulnerabilities.forEach(vuln => {
      severityCounts[vuln.severity]++;
    });

    return {
      target: this.target,
      scanTimestamp: new Date().toISOString(),
      summary: {
        totalVulnerabilities: this.vulnerabilities.length,
        severityBreakdown: severityCounts
      },
      vulnerabilities: this.vulnerabilities,
      recommendations: this.generateRecommendations()
    };
  }

  generateRecommendations() {
    const recommendations = [];
    
    if (this.vulnerabilities.some(v => v.type === 'XSS')) {
      recommendations.push('Implement proper input validation and output encoding');
    }
    
    if (this.vulnerabilities.some(v => v.type === 'SQL_INJECTION')) {
      recommendations.push('Use parameterized queries and prepared statements');
    }
    
    if (this.vulnerabilities.some(v => v.type === 'MISSING_SECURITY_HEADER')) {
      recommendations.push('Implement proper security headers');
    }

    return recommendations;
  }
}

// API Routes
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Web Security Scanner</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; }
            .form-group { margin: 20px 0; }
            input[type="url"] { width: 100%; padding: 10px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            .results { margin-top: 30px; }
            .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
            .critical { border-left: 5px solid #dc3545; }
            .high { border-left: 5px solid #fd7e14; }
            .medium { border-left: 5px solid #ffc107; }
            .low { border-left: 5px solid #28a745; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Web Security Scanner</h1>
            
            <div class="warning">
                <strong>⚠️ ETHICAL USE ONLY</strong><br>
                This tool is for educational purposes and authorized testing only. 
                Only scan websites you own or have explicit permission to test.
                Unauthorized scanning may be illegal.
            </div>

            <div class="form-group">
                <label>Target URL:</label>
                <input type="url" id="targetUrl" placeholder="https://example.com" />
                <button onclick="startScan()">Start Security Scan</button>
            </div>

            <div id="results" class="results"></div>
        </div>

        <script>
            async function startScan() {
                const url = document.getElementById('targetUrl').value;
                if (!url) {
                    alert('Please enter a valid URL');
                    return;
                }

                document.getElementById('results').innerHTML = '<p>⏳ Scanning in progress...</p>';

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target: url })
                    });

                    const result = await response.json();
                    displayResults(result);
                } catch (error) {
                    document.getElementById('results').innerHTML = '<p>❌ Error: ' + error.message + '</p>';
                }
            }

            function displayResults(result) {
                if (result.error) {
                    document.getElementById('results').innerHTML = '<p>❌ Error: ' + result.error + '</p>';
                    return;
                }

                let html = '<h2>📊 Scan Results</h2>';
                html += '<div><strong>Target:</strong> ' + result.target + '</div>';
                html += '<div><strong>Scan Time:</strong> ' + result.scanTimestamp + '</div>';
                html += '<div><strong>Total Vulnerabilities:</strong> ' + result.summary.totalVulnerabilities + '</div>';
                
                html += '<h3>Severity Breakdown:</h3>';
                html += '<div>Critical: ' + result.summary.severityBreakdown.Critical + '</div>';
                html += '<div>High: ' + result.summary.severityBreakdown.High + '</div>';
                html += '<div>Medium: ' + result.summary.severityBreakdown.Medium + '</div>';
                html += '<div>Low: ' + result.summary.severityBreakdown.Low + '</div>';

                if (result.vulnerabilities.length > 0) {
                    html += '<h3>🚨 Vulnerabilities Found:</h3>';
                    result.vulnerabilities.forEach(vuln => {
                        html += '<div class="vulnerability ' + vuln.severity.toLowerCase() + '">';
                        html += '<h4>' + vuln.title + ' (' + vuln.severity + ')</h4>';
                        html += '<p>' + vuln.description + '</p>';
                        html += '<details><summary>Proof of Concept</summary><pre>' + vuln.poc + '</pre></details>';
                        html += '</div>';
                    });
                }

                if (result.recommendations && result.recommendations.length > 0) {
                    html += '<h3>💡 Recommendations:</h3><ul>';
                    result.recommendations.forEach(rec => {
                        html += '<li>' + rec + '</li>';
                    });
                    html += '</ul>';
                }

                document.getElementById('results').innerHTML = html;
            }
        </script>
    </body>
    </html>
  `);
});

app.post('/scan', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target || !target.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }

    // Rate limiting check (basic)
    console.log(`Starting authorized scan for: ${target}`);
    
    const scanner = new WebSecurityScanner(target);
    const results = await scanner.scanTarget();
    
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Web Security Scanner running on port ${PORT}`);
  console.log(`⚠️  Remember: Only scan websites you own or have permission to test!`);
});
