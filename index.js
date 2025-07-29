import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { WebSecurityScanner } from './src/scanner/WebSecurityScanner.js';
import { UIController } from './src/controllers/UIController.js';
import { ScanController } from './src/controllers/ScanController.js';
import { Logger } from './src/utils/Logger.js';

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for development
}));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize logger
const logger = new Logger();

// Routes
app.get('/', UIController.renderUI);
app.post('/scan', ScanController.performScan);
app.get('/health', (req, res) => {
  res.json({
    status: 'operational',
    service: 'Advanced Modular Web Security Scanner',
    version: '3.0.0',
    timestamp: new Date().toISOString(),
    modules: [
      'XSS Scanner', 'SQL Injection', 'NoSQL Injection', 'Directory Traversal',
      'Command Injection', 'File Inclusion', 'XXE', 'SSRF', 'CSRF',
      'Authentication Bypass', 'Authorization Flaws', 'Session Management',
      'Cryptographic Issues', 'Input Validation', 'Output Encoding',
      'Information Disclosure', 'Security Headers', 'CORS Misconfiguration',
      'Clickjacking', 'Subdomain Takeover', 'DNS Vulnerabilities',
      'SSL/TLS Issues', 'Rate Limiting', 'Business Logic Flaws'
    ]
  });
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error('Application error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`🚀 Advanced Modular Web Security Scanner running on port ${PORT}`);
  logger.info(`🛡️ Comprehensive vulnerability assessment system ready`);
  logger.info(`⚠️  AUTHORIZED TESTING ONLY - Ensure you have permission!`);
  logger.info(`🔗 Access the scanner: http://0.0.0.0:${PORT}`);
});

export default app;