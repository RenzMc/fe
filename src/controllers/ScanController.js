
import { WebSecurityScanner } from '../scanner/WebSecurityScanner.js';
import { Logger } from '../utils/Logger.js';

const logger = new Logger();

export class ScanController {
  static async performScan(req, res) {
    try {
      const { target, options = {} } = req.body;
      
      if (!target || !target.match(/^https?:\/\/.+/)) {
        return res.status(400).json({ 
          error: 'Invalid target URL. Must start with http:// or https://' 
        });
      }

      logger.info(`🚀 Starting authorized comprehensive scan for: ${target}`, options);
      
      const scanner = new WebSecurityScanner(target, options);
      const results = await scanner.scanTarget();
      
      logger.success(`✅ Scan completed. Found ${results.vulnerabilities?.length || 0} vulnerabilities`);
      
      res.json(results);
    } catch (error) {
      logger.error('Scan error:', error);
      res.status(500).json({ error: error.message });
    }
  }
}
