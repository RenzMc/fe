
export class Logger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'info';
    this.colors = {
      error: '\x1b[31m',
      warn: '\x1b[33m',
      info: '\x1b[36m',
      debug: '\x1b[37m',
      success: '\x1b[32m',
      reset: '\x1b[0m'
    };
  }

  log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const color = this.colors[level] || this.colors.info;
    const resetColor = this.colors.reset;
    
    console.log(`${color}[${timestamp}] [${level.toUpperCase()}] ${message}${resetColor}`);
    
    if (data) {
      console.log(JSON.stringify(data, null, 2));
    }
  }

  error(message, data = null) {
    this.log('error', message, data);
  }

  warn(message, data = null) {
    this.log('warn', message, data);
  }

  info(message, data = null) {
    this.log('info', message, data);
  }

  debug(message, data = null) {
    if (this.logLevel === 'debug') {
      this.log('debug', message, data);
    }
  }

  success(message, data = null) {
    this.log('success', message, data);
  }
}
