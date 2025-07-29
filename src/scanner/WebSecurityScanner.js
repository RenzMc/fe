
import { Logger } from '../utils/Logger.js';
import { VulnerabilityDatabase } from '../data/VulnerabilityDatabase.js';
import { PayloadGenerator } from '../payloads/PayloadGenerator.js';
import { ReportGenerator } from '../reports/ReportGenerator.js';

// Import all scanner modules
import { XSSScanner } from './modules/XSSScanner.js';
import { SQLInjectionScanner } from './modules/SQLInjectionScanner.js';
import { DirectoryTraversalScanner } from './modules/DirectoryTraversalScanner.js';
import { CommandInjectionScanner } from './modules/CommandInjectionScanner.js';
import { AuthenticationScanner } from './modules/AuthenticationScanner.js';
import { SessionManagementScanner } from './modules/SessionManagementScanner.js';
import { BusinessLogicScanner } from './modules/BusinessLogicScanner.js';
import { CryptographicScanner } from './modules/CryptographicScanner.js';
import { InformationDisclosureScanner } from './modules/InformationDisclosureScanner.js';
import { SecurityHeadersScanner } from './modules/SecurityHeadersScanner.js';
import { CORSScanner } from './modules/CORSScanner.js';
import { SSRFScanner } from './modules/SSRFScanner.js';
import { XXEScanner } from './modules/XXEScanner.js';
import { FileInclusionScanner } from './modules/FileInclusionScanner.js';
import { NoSQLInjectionScanner } from './modules/NoSQLInjectionScanner.js';
import { CSRFScanner } from './modules/CSRFScanner.js';
import { ClickjackingScanner } from './modules/ClickjackingScanner.js';
import { SubdomainTakeoverScanner } from './modules/SubdomainTakeoverScanner.js';
import { RateLimitingScanner } from './modules/RateLimitingScanner.js';
import { HTTPSRedirectionScanner } from './modules/HTTPSRedirectionScanner.js';

export class WebSecurityScanner {
  constructor(target, options = {}) {
    this.target = target;
    this.options = {
      deepScan: options.deepScan || false,
      aggressiveMode: options.aggressiveMode || false,
      evasionMode: options.evasionMode || false,
      businessLogic: options.businessLogic || false,
      maxConcurrency: options.maxConcurrency || 20,
      timeout: options.timeout || 30000,
      userAgent: options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      ...options
    };
    
    this.logger = new Logger();
    this.vulnerabilities = [];
    this.scanStatistics = {
      startTime: Date.now(),
      endTime: null,
      requestsCount: 0,
      errorsCount: 0,
      testedEndpoints: new Set(),
      foundFiles: new Set(),
      scanCoverage: {}
    };

    // Initialize scanner modules
    this.scanners = this.initializeScanners();
    
    this.logger.info(`🔧 Initialized ${this.scanners.length} scanner modules`);
  }

  initializeScanners() {
    const scanners = [
      new InformationDisclosureScanner(this),
      new SecurityHeadersScanner(this),
      new XSSScanner(this),
      new SQLInjectionScanner(this),
      new NoSQLInjectionScanner(this),
      new DirectoryTraversalScanner(this),
      new CommandInjectionScanner(this),
      new FileInclusionScanner(this),
      new XXEScanner(this),
      new SSRFScanner(this),
      new CSRFScanner(this),
      new AuthenticationScanner(this),
      new SessionManagementScanner(this),
      new CryptographicScanner(this),
      new CORSScanner(this),
      new ClickjackingScanner(this),
      new SubdomainTakeoverScanner(this),
      new RateLimitingScanner(this),
      new HTTPSRedirectionScanner(this)
    ];

    // Add business logic scanner if enabled
    if (this.options.businessLogic) {
      scanners.push(new BusinessLogicScanner(this));
    }

    return scanners;
  }

  async scanTarget() {
    this.logger.info(`🔍 Starting comprehensive security scan for: ${this.target}`);
    this.logger.info(`📋 Scan configuration:`, this.options);
    
    try {
      // Phase 1: Information Gathering
      await this.informationGathering();
      
      // Phase 2: Endpoint Discovery
      await this.endpointDiscovery();
      
      // Phase 3: Vulnerability Testing
      await this.vulnerabilityTesting();
      
      // Phase 4: Advanced Testing
      await this.advancedTesting();
      
      // Phase 5: Business Logic Testing (if enabled)
      if (this.options.businessLogic) {
        await this.businessLogicTesting();
      }
      
      this.scanStatistics.endTime = Date.now();
      return this.generateReport();
      
    } catch (error) {
      this.logger.error('Scan error:', error);
      this.scanStatistics.endTime = Date.now();
      this.scanStatistics.errorsCount++;
      return { error: error.message, statistics: this.scanStatistics };
    }
  }

  async informationGathering() {
    this.logger.info('📊 Phase 1: Information Gathering & Reconnaissance');
    
    const infoScanners = this.scanners.filter(scanner => 
      scanner.constructor.name.includes('InformationDisclosure') ||
      scanner.constructor.name.includes('SecurityHeaders')
    );

    await this.runScannersInParallel(infoScanners);
  }

  async endpointDiscovery() {
    this.logger.info('🔍 Phase 2: Advanced Endpoint Discovery');
    
    // Run endpoint discovery logic here
    const endpointScanners = this.scanners.filter(scanner => 
      scanner.hasEndpointDiscovery && scanner.hasEndpointDiscovery()
    );

    await this.runScannersInParallel(endpointScanners);
  }

  async vulnerabilityTesting() {
    this.logger.info('⚡ Phase 3: Multi-vector Vulnerability Testing');
    
    const vulnScanners = this.scanners.filter(scanner => 
      !scanner.constructor.name.includes('InformationDisclosure') &&
      !scanner.constructor.name.includes('SecurityHeaders') &&
      !scanner.constructor.name.includes('BusinessLogic')
    );

    await this.runScannersInParallel(vulnScanners);
  }

  async advancedTesting() {
    this.logger.info('🛡️ Phase 4: Advanced Security Analysis');
    
    const advancedScanners = this.scanners.filter(scanner => 
      scanner.constructor.name.includes('CORS') ||
      scanner.constructor.name.includes('Subdomain') ||
      scanner.constructor.name.includes('Clickjacking') ||
      scanner.constructor.name.includes('RateLimit') ||
      scanner.constructor.name.includes('HTTPS')
    );

    await this.runScannersInParallel(advancedScanners);
  }

  async businessLogicTesting() {
    this.logger.info('📈 Phase 5: Business Logic & Advanced Security Analysis');
    
    const businessScanners = this.scanners.filter(scanner => 
      scanner.constructor.name.includes('BusinessLogic')
    );

    await this.runScannersInParallel(businessScanners);
  }

  async runScannersInParallel(scanners) {
    const concurrency = Math.min(this.options.maxConcurrency, scanners.length);
    const chunks = this.chunkArray(scanners, concurrency);
    
    for (const chunk of chunks) {
      const promises = chunk.map(async (scanner) => {
        try {
          this.logger.debug(`🔧 Running ${scanner.constructor.name}`);
          await scanner.scan();
          this.logger.debug(`✅ Completed ${scanner.constructor.name}`);
        } catch (error) {
          this.logger.error(`❌ Error in ${scanner.constructor.name}:`, error);
          this.scanStatistics.errorsCount++;
        }
      });
      
      await Promise.all(promises);
    }
  }

  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  addVulnerability(vulnerability) {
    // Add unique ID and timestamp
    vulnerability.id = this.generateId();
    vulnerability.timestamp = new Date().toISOString();
    vulnerability.target = this.target;
    
    this.vulnerabilities.push(vulnerability);
    this.logger.info(`🚨 Vulnerability found: ${vulnerability.title} (${vulnerability.severity})`);
  }

  generateId() {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  generateReport() {
    const reportGenerator = new ReportGenerator(this.vulnerabilities, this.scanStatistics, this.target);
    return reportGenerator.generateComprehensiveReport();
  }

  // Utility methods for scanners
  async makeRequest(url, options = {}) {
    this.scanStatistics.requestsCount++;
    
    const defaultOptions = {
      timeout: this.options.timeout,
      headers: {
        'User-Agent': this.options.userAgent,
        ...options.headers
      },
      validateStatus: () => true,
      maxRedirects: 5
    };

    try {
      const axios = (await import('axios')).default;
      return await axios({
        url,
        ...defaultOptions,
        ...options
      });
    } catch (error) {
      this.scanStatistics.errorsCount++;
      throw error;
    }
  }

  shouldApplyEvasion() {
    return this.options.evasionMode;
  }

  shouldRunAggressiveTests() {
    return this.options.aggressiveMode;
  }

  shouldRunDeepScan() {
    return this.options.deepScan;
  }
}
