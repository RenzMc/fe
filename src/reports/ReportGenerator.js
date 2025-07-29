
export class ReportGenerator {
  constructor(vulnerabilities, statistics, target) {
    this.vulnerabilities = vulnerabilities;
    this.statistics = statistics;
    this.target = target;
  }

  generateComprehensiveReport() {
    const report = {
      target: this.target,
      scanInfo: this.generateScanInfo(),
      executiveSummary: this.generateExecutiveSummary(),
      vulnerabilities: this.categorizeVulnerabilities(),
      statistics: this.generateStatistics(),
      recommendations: this.generateRecommendations(),
      technicalDetails: this.generateTechnicalDetails(),
      proofOfConcepts: this.generateProofOfConcepts(),
      timeline: this.generateTimeline(),
      compliance: this.generateComplianceReport(),
      riskMatrix: this.generateRiskMatrix(),
      mitigationStrategies: this.generateMitigationStrategies()
    };

    return report;
  }

  generateScanInfo() {
    return {
      target: this.target,
      scanDate: new Date().toISOString(),
      scanDuration: this.statistics.endTime - this.statistics.startTime,
      scannerVersion: '3.0.0',
      scanType: 'Comprehensive Security Assessment',
      methodology: 'OWASP Testing Guide v4.2',
      totalRequests: this.statistics.requestsCount,
      totalErrors: this.statistics.errorsCount,
      coverage: this.calculateCoverage()
    };
  }

  generateExecutiveSummary() {
    const criticalCount = this.vulnerabilities.filter(v => v.severity === 'Critical').length;
    const highCount = this.vulnerabilities.filter(v => v.severity === 'High').length;
    const mediumCount = this.vulnerabilities.filter(v => v.severity === 'Medium').length;
    const lowCount = this.vulnerabilities.filter(v => v.severity === 'Low').length;
    const infoCount = this.vulnerabilities.filter(v => v.severity === 'Info').length;

    const riskLevel = this.calculateOverallRisk(criticalCount, highCount, mediumCount);

    return {
      totalVulnerabilities: this.vulnerabilities.length,
      severityBreakdown: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        info: infoCount
      },
      overallRiskLevel: riskLevel,
      keyFindings: this.getKeyFindings(),
      businessImpact: this.assessBusinessImpact(),
      priorityActions: this.getPriorityActions()
    };
  }

  categorizeVulnerabilities() {
    const categories = {};
    
    for (const vuln of this.vulnerabilities) {
      const category = vuln.category || 'Miscellaneous';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(vuln);
    }

    // Sort vulnerabilities by severity within each category
    for (const category in categories) {
      categories[category].sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity));
    }

    return categories;
  }

  generateStatistics() {
    return {
      ...this.statistics,
      vulnerabilityStats: {
        total: this.vulnerabilities.length,
        bySeverity: this.getVulnerabilityCountBySeverity(),
        byCategory: this.getVulnerabilityCountByCategory(),
        byType: this.getVulnerabilityCountByType()
      },
      performanceMetrics: {
        requestsPerSecond: this.calculateRequestsPerSecond(),
        averageResponseTime: this.calculateAverageResponseTime(),
        errorRate: this.calculateErrorRate(),
        coverage: this.calculateCoverage()
      }
    };
  }

  generateRecommendations() {
    const recommendations = [];

    // Critical vulnerabilities
    const critical = this.vulnerabilities.filter(v => v.severity === 'Critical');
    if (critical.length > 0) {
      recommendations.push({
        priority: 'Immediate',
        category: 'Critical Vulnerabilities',
        description: `Address ${critical.length} critical vulnerabilities immediately`,
        actions: critical.map(v => `Fix ${v.title}: ${v.recommendation || 'Apply security patch'}`),
        timeline: 'Within 24 hours'
      });
    }

    // High severity vulnerabilities
    const high = this.vulnerabilities.filter(v => v.severity === 'High');
    if (high.length > 0) {
      recommendations.push({
        priority: 'High',
        category: 'High Risk Vulnerabilities',
        description: `Remediate ${high.length} high-risk vulnerabilities`,
        actions: high.map(v => `Fix ${v.title}: ${v.recommendation || 'Apply security controls'}`),
        timeline: 'Within 1 week'
      });
    }

    // Security headers
    const headerIssues = this.vulnerabilities.filter(v => v.category === 'Security Headers');
    if (headerIssues.length > 0) {
      recommendations.push({
        priority: 'Medium',
        category: 'Security Headers',
        description: 'Implement missing security headers',
        actions: [
          'Implement Content Security Policy (CSP)',
          'Add X-Frame-Options header',
          'Set Strict-Transport-Security',
          'Configure X-Content-Type-Options',
          'Add Referrer-Policy header'
        ],
        timeline: 'Within 2 weeks'
      });
    }

    // General security improvements
    recommendations.push({
      priority: 'Medium',
      category: 'General Security',
      description: 'Implement security best practices',
      actions: [
        'Regular security assessments',
        'Web Application Firewall (WAF) implementation',
        'Input validation and sanitization',
        'Secure coding practices training',
        'Dependency vulnerability scanning'
      ],
      timeline: 'Within 1 month'
    });

    return recommendations;
  }

  generateTechnicalDetails() {
    return {
      scanMethodology: {
        phases: [
          'Information Gathering & Reconnaissance',
          'Advanced Endpoint Discovery',
          'Multi-vector Vulnerability Testing',
          'Advanced Security Analysis',
          'Business Logic Testing'
        ],
        techniques: [
          'OWASP Top 10 Testing',
          'Injection Attack Vectors',
          'Authentication & Session Management',
          'Security Misconfiguration Analysis',
          'Sensitive Data Exposure Testing'
        ]
      },
      toolsUsed: [
        'Custom Web Security Scanner v3.0',
        'Advanced Payload Generator',
        'Comprehensive Vulnerability Database',
        'Evasion Techniques Module',
        'Business Logic Analyzer'
      ],
      testingScope: {
        target: this.target,
        endpoints: Array.from(this.statistics.testedEndpoints),
        files: Array.from(this.statistics.foundFiles),
        parameters: this.getTestedParameters()
      }
    };
  }

  generateProofOfConcepts() {
    return this.vulnerabilities
      .filter(v => v.poc)
      .map(v => ({
        vulnerability: v.title,
        severity: v.severity,
        poc: v.poc,
        steps: v.steps || [],
        impact: v.impact,
        remediation: v.recommendation
      }));
  }

  generateTimeline() {
    const events = [];
    
    events.push({
      time: new Date(this.statistics.startTime).toISOString(),
      event: 'Scan Started',
      description: `Initiated comprehensive security scan for ${this.target}`
    });

    // Add vulnerability discovery events
    this.vulnerabilities.forEach(v => {
      if (v.timestamp) {
        events.push({
          time: v.timestamp,
          event: 'Vulnerability Discovered',
          description: `${v.severity} severity: ${v.title}`,
          vulnerability: v
        });
      }
    });

    events.push({
      time: new Date(this.statistics.endTime).toISOString(),
      event: 'Scan Completed',
      description: `Found ${this.vulnerabilities.length} vulnerabilities`
    });

    return events.sort((a, b) => new Date(a.time) - new Date(b.time));
  }

  generateComplianceReport() {
    const owaspTop10 = this.checkOWASPTop10Compliance();
    const pcidss = this.checkPCIDSSCompliance();
    const gdpr = this.checkGDPRCompliance();

    return {
      owasp: owaspTop10,
      pcidss: pcidss,
      gdpr: gdpr,
      iso27001: this.checkISO27001Compliance(),
      nist: this.checkNISTCompliance()
    };
  }

  generateRiskMatrix() {
    const matrix = {
      critical: { count: 0, items: [] },
      high: { count: 0, items: [] },
      medium: { count: 0, items: [] },
      low: { count: 0, items: [] },
      info: { count: 0, items: [] }
    };

    this.vulnerabilities.forEach(v => {
      const severity = v.severity.toLowerCase();
      if (matrix[severity]) {
        matrix[severity].count++;
        matrix[severity].items.push({
          title: v.title,
          category: v.category,
          cvss: v.cvss || 'N/A'
        });
      }
    });

    return matrix;
  }

  generateMitigationStrategies() {
    const strategies = [];

    // Input validation strategy
    const injectionVulns = this.vulnerabilities.filter(v => 
      ['XSS', 'SQL Injection', 'Command Injection', 'XXE'].includes(v.category)
    );
    
    if (injectionVulns.length > 0) {
      strategies.push({
        strategy: 'Input Validation & Sanitization',
        description: 'Implement comprehensive input validation',
        techniques: [
          'Whitelist input validation',
          'Parameterized queries',
          'Output encoding',
          'Content Security Policy',
          'Input length restrictions'
        ],
        affectedVulnerabilities: injectionVulns.length
      });
    }

    // Authentication strategy
    const authVulns = this.vulnerabilities.filter(v => 
      ['Authentication', 'Session Management', 'Authorization'].includes(v.category)
    );
    
    if (authVulns.length > 0) {
      strategies.push({
        strategy: 'Authentication & Authorization Hardening',
        description: 'Strengthen authentication mechanisms',
        techniques: [
          'Multi-factor authentication',
          'Strong password policies',
          'Session timeout implementation',
          'Proper session management',
          'Role-based access control'
        ],
        affectedVulnerabilities: authVulns.length
      });
    }

    // Security headers strategy
    const headerVulns = this.vulnerabilities.filter(v => 
      v.category === 'Security Headers'
    );
    
    if (headerVulns.length > 0) {
      strategies.push({
        strategy: 'Security Headers Implementation',
        description: 'Configure essential security headers',
        techniques: [
          'Content Security Policy (CSP)',
          'HTTP Strict Transport Security (HSTS)',
          'X-Frame-Options',
          'X-Content-Type-Options',
          'Referrer-Policy'
        ],
        affectedVulnerabilities: headerVulns.length
      });
    }

    return strategies;
  }

  calculateOverallRisk(critical, high, medium) {
    if (critical > 0) return 'Critical';
    if (high > 5) return 'High';
    if (high > 0 || medium > 10) return 'Medium';
    if (medium > 0) return 'Low';
    return 'Minimal';
  }

  getSeverityWeight(severity) {
    const weights = { 'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1 };
    return weights[severity] || 0;
  }

  getKeyFindings() {
    return this.vulnerabilities
      .filter(v => ['Critical', 'High'].includes(v.severity))
      .slice(0, 5)
      .map(v => ({
        title: v.title,
        severity: v.severity,
        impact: v.impact || 'Security risk identified',
        category: v.category
      }));
  }

  assessBusinessImpact() {
    const critical = this.vulnerabilities.filter(v => v.severity === 'Critical').length;
    const high = this.vulnerabilities.filter(v => v.severity === 'High').length;

    if (critical > 0) {
      return 'Severe - Immediate business risk with potential for data breach, system compromise, or service disruption';
    } else if (high > 0) {
      return 'High - Significant security risks that could lead to unauthorized access or data exposure';
    } else {
      return 'Moderate - Security weaknesses present but with limited immediate business impact';
    }
  }

  getPriorityActions() {
    const actions = [];
    
    const critical = this.vulnerabilities.filter(v => v.severity === 'Critical');
    if (critical.length > 0) {
      actions.push(`Address ${critical.length} critical vulnerabilities immediately`);
    }

    const sqlInjection = this.vulnerabilities.filter(v => v.category === 'SQL Injection');
    if (sqlInjection.length > 0) {
      actions.push('Implement parameterized queries to prevent SQL injection');
    }

    const xss = this.vulnerabilities.filter(v => v.category === 'XSS');
    if (xss.length > 0) {
      actions.push('Implement output encoding and CSP to prevent XSS');
    }

    if (actions.length === 0) {
      actions.push('Continue regular security monitoring and assessments');
    }

    return actions;
  }

  getVulnerabilityCountBySeverity() {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    this.vulnerabilities.forEach(v => {
      if (counts.hasOwnProperty(v.severity)) {
        counts[v.severity]++;
      }
    });
    return counts;
  }

  getVulnerabilityCountByCategory() {
    const counts = {};
    this.vulnerabilities.forEach(v => {
      const category = v.category || 'Miscellaneous';
      counts[category] = (counts[category] || 0) + 1;
    });
    return counts;
  }

  getVulnerabilityCountByType() {
    const counts = {};
    this.vulnerabilities.forEach(v => {
      const type = v.type || 'Unknown';
      counts[type] = (counts[type] || 0) + 1;
    });
    return counts;
  }

  calculateRequestsPerSecond() {
    const duration = (this.statistics.endTime - this.statistics.startTime) / 1000;
    return duration > 0 ? (this.statistics.requestsCount / duration).toFixed(2) : 0;
  }

  calculateAverageResponseTime() {
    // This would need to be tracked during scanning
    return 'N/A';
  }

  calculateErrorRate() {
    return this.statistics.requestsCount > 0 
      ? ((this.statistics.errorsCount / this.statistics.requestsCount) * 100).toFixed(2) + '%'
      : '0%';
  }

  calculateCoverage() {
    // Calculate based on tested endpoints, parameters, etc.
    return {
      endpoints: this.statistics.testedEndpoints.size,
      files: this.statistics.foundFiles.size,
      parameters: this.getTestedParameters().length,
      coveragePercentage: 'N/A' // Would need baseline for calculation
    };
  }

  getTestedParameters() {
    // Extract tested parameters from vulnerabilities
    const parameters = new Set();
    this.vulnerabilities.forEach(v => {
      if (v.parameter) {
        parameters.add(v.parameter);
      }
    });
    return Array.from(parameters);
  }

  checkOWASPTop10Compliance() {
    const owaspCategories = [
      'Injection', 'Broken Authentication', 'Sensitive Data Exposure',
      'XML External Entities (XXE)', 'Broken Access Control',
      'Security Misconfiguration', 'Cross-Site Scripting (XSS)',
      'Insecure Deserialization', 'Using Components with Known Vulnerabilities',
      'Insufficient Logging & Monitoring'
    ];

    const findings = {};
    owaspCategories.forEach(category => {
      findings[category] = this.vulnerabilities.filter(v => 
        v.owasp && v.owasp.includes(category)
      ).length;
    });

    return findings;
  }

  checkPCIDSSCompliance() {
    // Basic PCI DSS compliance check
    const requirements = {
      'Network Security': 0,
      'Data Protection': 0,
      'Access Control': 0,
      'Monitoring': 0
    };

    // Map vulnerabilities to PCI DSS requirements
    this.vulnerabilities.forEach(v => {
      if (v.category === 'Security Headers' || v.category === 'HTTPS') {
        requirements['Network Security']++;
      }
      if (v.category === 'Information Disclosure') {
        requirements['Data Protection']++;
      }
      if (v.category === 'Authentication' || v.category === 'Authorization') {
        requirements['Access Control']++;
      }
    });

    return requirements;
  }

  checkGDPRCompliance() {
    const gdprIssues = this.vulnerabilities.filter(v => 
      v.category === 'Information Disclosure' || 
      v.category === 'Data Protection' ||
      v.title.toLowerCase().includes('personal') ||
      v.title.toLowerCase().includes('privacy')
    );

    return {
      dataProtectionIssues: gdprIssues.length,
      findings: gdprIssues.map(v => v.title)
    };
  }

  checkISO27001Compliance() {
    // Basic ISO 27001 compliance indicators
    return {
      informationSecurityControls: this.vulnerabilities.length,
      riskLevel: this.calculateOverallRisk(
        this.vulnerabilities.filter(v => v.severity === 'Critical').length,
        this.vulnerabilities.filter(v => v.severity === 'High').length,
        this.vulnerabilities.filter(v => v.severity === 'Medium').length
      )
    };
  }

  checkNISTCompliance() {
    // Basic NIST Cybersecurity Framework mapping
    const functions = {
      'Identify': 0,
      'Protect': 0,
      'Detect': 0,
      'Respond': 0,
      'Recover': 0
    };

    this.vulnerabilities.forEach(v => {
      if (v.category === 'Information Disclosure') functions['Identify']++;
      if (v.category === 'Security Headers' || v.category === 'Authentication') functions['Protect']++;
      if (v.category === 'Monitoring') functions['Detect']++;
    });

    return functions;
  }
}
