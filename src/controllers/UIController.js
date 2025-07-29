
export class UIController {
  static renderUI(req, res) {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Advanced Modular Web Security Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 3rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 15px;
        }
        
        .header p {
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 20px;
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            color: white;
            font-size: 0.9rem;
        }
        
        .warning {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
            border-left: 5px solid #ff4757;
        }
        
        .warning strong {
            display: block;
            font-size: 1.3rem;
            margin-bottom: 10px;
        }
        
        .scan-section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 20px;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
        }
        
        .form-group {
            margin: 30px 0;
        }
        
        .form-group label {
            display: block;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 15px;
            color: #333;
        }
        
        .url-input {
            width: 100%;
            padding: 20px;
            border: 3px solid #e1e5e9;
            border-radius: 15px;
            font-size: 1.1rem;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.9);
        }
        
        .url-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 5px rgba(102, 126, 234, 0.1);
            transform: translateY(-2px);
        }
        
        .scan-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .scan-option {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            border: 2px solid transparent;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .scan-option:hover {
            border-color: #667eea;
            transform: translateY(-2px);
        }
        
        .scan-option input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.2);
        }
        
        .scan-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 40px;
            border: none;
            border-radius: 15px;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 20px;
        }
        
        .scan-button:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4);
        }
        
        .scan-button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .loading {
            text-align: center;
            padding: 60px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            margin: 20px 0;
        }
        
        .spinner {
            width: 60px;
            height: 60px;
            border: 6px solid #f3f3f3;
            border-top: 6px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 30px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .progress-steps {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
        }
        
        .progress-step {
            display: flex;
            align-items: center;
            padding: 10px 0;
            font-size: 1.1rem;
        }
        
        .progress-step.active {
            color: #667eea;
            font-weight: 600;
        }
        
        .progress-step.completed {
            color: #28a745;
        }
        
        .results {
            margin-top: 30px;
        }
        
        .results-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 20px 20px 0 0;
            text-align: center;
        }
        
        .results-content {
            background: white;
            border-radius: 0 0 20px 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-card {
            text-align: center;
            padding: 25px;
            border-radius: 15px;
            color: white;
            font-weight: 600;
        }
        
        .stat-number {
            font-size: 2.5rem;
            display: block;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .vulnerability {
            border: 2px solid #e1e5e9;
            margin: 20px 0;
            border-radius: 15px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .vulnerability:hover {
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .vuln-header {
            padding: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .vuln-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin: 0;
        }
        
        .vuln-severity {
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .vuln-content {
            padding: 0 25px 25px;
        }
        
        .vuln-details {
            margin: 15px 0;
            line-height: 1.6;
        }
        
        .poc-details {
            background: #f8f9fa;
            border-radius: 10px;
            margin-top: 20px;
            overflow: hidden;
        }
        
        .poc-details summary {
            padding: 20px;
            cursor: pointer;
            font-weight: 600;
            background: #e9ecef;
            transition: background 0.3s ease;
        }
        
        .poc-details summary:hover {
            background: #dee2e6;
        }
        
        .poc-content {
            padding: 20px;
            background: white;
        }
        
        .poc-content pre {
            background: #1e1e1e;
            color: #f8f8f2;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 0.9rem;
            line-height: 1.4;
            border-left: 4px solid #667eea;
        }
        
        /* Vulnerability severity colors */
        .critical { border-left: 6px solid #dc3545; }
        .critical .vuln-header { background: linear-gradient(135deg, #dc3545, #c82333); color: white; }
        .severity-critical { background: #dc3545; color: white; }
        
        .high { border-left: 6px solid #fd7e14; }
        .high .vuln-header { background: linear-gradient(135deg, #fd7e14, #e55a00); color: white; }
        .severity-high { background: #fd7e14; color: white; }
        
        .medium { border-left: 6px solid #ffc107; }
        .medium .vuln-header { background: linear-gradient(135deg, #ffc107, #e0a800); color: #333; }
        .severity-medium { background: #ffc107; color: #333; }
        
        .low { border-left: 6px solid #28a745; }
        .low .vuln-header { background: linear-gradient(135deg, #28a745, #1e7e34); color: white; }
        .severity-low { background: #28a745; color: white; }
        
        .info { border-left: 6px solid #17a2b8; }
        .info .vuln-header { background: linear-gradient(135deg, #17a2b8, #138496); color: white; }
        .severity-info { background: #17a2b8; color: white; }
        
        .recommendations {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            margin: 30px 0;
        }
        
        .recommendation {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 2rem; }
            .vuln-header { flex-direction: column; gap: 15px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced Modular Web Security Scanner</h1>
            <p>Comprehensive vulnerability assessment and penetration testing platform</p>
            <div class="features-grid">
                <div class="feature-card">🔍 25+ Vulnerability Types</div>
                <div class="feature-card">⚡ Multi-threaded Scanning</div>
                <div class="feature-card">🎯 Precision Targeting</div>
                <div class="feature-card">📊 Detailed Reporting</div>
                <div class="feature-card">🛡️ Advanced Evasion</div>
                <div class="feature-card">🔬 Deep Analysis</div>
            </div>
        </div>
        
        <div class="warning">
            <strong>⚠️ AUTHORIZED TESTING ONLY</strong>
            This advanced security scanner is designed for authorized penetration testing and bug bounty research only. 
            Only scan websites you own or have explicit written permission to test.
            Unauthorized scanning may violate laws and terms of service.
        </div>

        <div class="scan-section">
            <div class="form-group">
                <label for="targetUrl">🎯 Target URL:</label>
                <input type="url" id="targetUrl" class="url-input" 
                       placeholder="https://example.com" required />
            </div>
            
            <div class="scan-options">
                <div class="scan-option">
                    <input type="checkbox" id="deepScan" checked>
                    <label for="deepScan">Deep Vulnerability Scan</label>
                </div>
                <div class="scan-option">
                    <input type="checkbox" id="aggressiveMode">
                    <label for="aggressiveMode">Aggressive Mode</label>
                </div>
                <div class="scan-option">
                    <input type="checkbox" id="evasionMode" checked>
                    <label for="evasionMode">WAF Evasion</label>
                </div>
                <div class="scan-option">
                    <input type="checkbox" id="businessLogic">
                    <label for="businessLogic">Business Logic Tests</label>
                </div>
            </div>
            
            <button onclick="startAdvancedScan()" class="scan-button" id="scanBtn">
                🚀 Start Advanced Security Scan
            </button>
        </div>

        <div id="results" class="results"></div>
    </div>

    <script>
        async function startAdvancedScan() {
            const url = document.getElementById('targetUrl').value;
            if (!url) {
                alert('Please enter a valid URL');
                return;
            }

            const options = {
                deepScan: document.getElementById('deepScan').checked,
                aggressiveMode: document.getElementById('aggressiveMode').checked,
                evasionMode: document.getElementById('evasionMode').checked,
                businessLogic: document.getElementById('businessLogic').checked
            };

            const scanBtn = document.getElementById('scanBtn');
            const resultsDiv = document.getElementById('results');
            
            scanBtn.disabled = true;
            scanBtn.textContent = '🔍 Initializing Advanced Scan...';
            
            resultsDiv.innerHTML = \`
                <div class="loading">
                    <div class="spinner"></div>
                    <h3>🔍 Advanced Security Scan in Progress</h3>
                    <p>This comprehensive scan may take 10-15 minutes. Please wait...</p>
                    
                    <div class="progress-steps">
                        <div class="progress-step active" id="step1">
                            📊 Phase 1: Intelligence Gathering & Reconnaissance
                        </div>
                        <div class="progress-step" id="step2">
                            🔍 Phase 2: Advanced Endpoint Discovery
                        </div>
                        <div class="progress-step" id="step3">
                            ⚡ Phase 3: Multi-vector Vulnerability Testing
                        </div>
                        <div class="progress-step" id="step4">
                            🛡️ Phase 4: Business Logic & Advanced Security Analysis
                        </div>
                        <div class="progress-step" id="step5">
                            📈 Phase 5: Deep Analysis & Exploitation Verification
                        </div>
                    </div>
                </div>
            \`;

            // Simulate progress updates
            setTimeout(() => updateProgress('step2'), 2000);
            setTimeout(() => updateProgress('step3'), 5000);
            setTimeout(() => updateProgress('step4'), 8000);
            setTimeout(() => updateProgress('step5'), 11000);

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: url, options })
                });

                const result = await response.json();
                displayAdvancedResults(result);
            } catch (error) {
                resultsDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            } finally {
                scanBtn.disabled = false;
                scanBtn.textContent = '🚀 Start Advanced Security Scan';
            }
        }

        function updateProgress(stepId) {
            // Mark previous steps as completed
            const steps = ['step1', 'step2', 'step3', 'step4', 'step5'];
            const currentIndex = steps.indexOf(stepId);
            
            steps.forEach((step, index) => {
                const element = document.getElementById(step);
                if (element) {
                    element.classList.remove('active');
                    if (index < currentIndex) {
                        element.classList.add('completed');
                    } else if (index === currentIndex) {
                        element.classList.add('active');
                    }
                }
            });
        }

        function displayAdvancedResults(result) {
            if (result.error) {
                document.getElementById('results').innerHTML = 
                    '<div class="error">❌ Error: ' + result.error + '</div>';
                return;
            }

            let html = \`
                <div class="results-header">
                    <h2>📊 Advanced Security Assessment Results</h2>
                    <div><strong>Target:</strong> \${result.target}</div>
                    <div><strong>Scan Completed:</strong> \${new Date(result.scanTimestamp).toLocaleString()}</div>
                    <div><strong>Risk Level:</strong> \${result.summary.riskLevel}</div>
                    <div><strong>Scan Coverage:</strong> \${result.technicalDetails.scanStatistics.scanCoverage.endpoints}</div>
                </div>
                
                <div class="results-content">
                    <div class="stats-grid">
                        <div class="stat-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                            <span class="stat-number">\${result.summary.totalVulnerabilities}</span>
                            <span class="stat-label">Total Vulnerabilities</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);">
                            <span class="stat-number">\${result.summary.riskScore}</span>
                            <span class="stat-label">Risk Score</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%);">
                            <span class="stat-number">\${result.summary.testedEndpoints}</span>
                            <span class="stat-label">Endpoints Tested</span>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #45b7d1 0%, #96c93d 100%);">
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
                html += '<h3 style="margin: 30px 0 20px; font-size: 1.5rem; color: #333;">🚨 Discovered Vulnerabilities:</h3>';
                result.vulnerabilities.forEach((vuln, index) => {
                    html += \`
                        <div class="vulnerability \${vuln.severity.toLowerCase()}">
                            <div class="vuln-header">
                                <h4 class="vuln-title">\${vuln.title}</h4>
                                <span class="vuln-severity severity-\${vuln.severity.toLowerCase()}">\${vuln.severity}</span>
                            </div>
                            <div class="vuln-content">
                                <div class="vuln-details"><strong>Type:</strong> \${vuln.type}</div>
                                <div class="vuln-details"><strong>CVSS Score:</strong> \${vuln.cvss}</div>
                                <div class="vuln-details"><strong>Description:</strong> \${vuln.description}</div>
                                <div class="vuln-details"><strong>Remediation:</strong> \${vuln.remediation}</div>
                                <details class="poc-details">
                                    <summary>🔍 Proof of Concept & Exploitation Details</summary>
                                    <div class="poc-content">
                                        <pre>\${vuln.poc}</pre>
                                    </div>
                                </details>
                            </div>
                        </div>
                    \`;
                });
            } else {
                html += \`
                    <div style="text-align: center; padding: 60px; background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%); 
                                color: white; border-radius: 20px; margin: 30px 0;">
                        <h3 style="font-size: 2rem; margin-bottom: 15px;">✅ Excellent Security Posture!</h3>
                        <p style="font-size: 1.2rem;">No vulnerabilities detected in this comprehensive scan.</p>
                        <p style="margin-top: 10px; opacity: 0.9;">The target appears to have robust security measures in place.</p>
                    </div>
                \`;
            }

            if (result.recommendations && result.recommendations.length > 0) {
                html += \`
                    <div class="recommendations">
                        <h3 style="margin-bottom: 20px; color: #333;">💡 Security Recommendations:</h3>
                \`;
                result.recommendations.forEach(rec => {
                    html += \`
                        <div class="recommendation">
                            <div style="font-weight: 600; color: #667eea; margin-bottom: 8px;">
                                \${rec.priority} Priority - \${rec.category}
                            </div>
                            <div>\${rec.recommendation}</div>
                        </div>
                    \`;
                });
                html += '</div>';
            }

            html += '</div>'; // Close results-content

            document.getElementById('results').innerHTML = html;
        }

        // Auto-focus and enter key support
        document.getElementById('targetUrl').focus();
        document.getElementById('targetUrl').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                startAdvancedScan();
            }
        });
    </script>
</body>
</html>`;
    
    res.send(html);
  }
}
