import os  # whitespace change for commit
import sys
import json
import tempfile
import shutil
import re
import time

# Try to import Flask - if this fails, the function can't work
try:
    from flask import Flask, request, Response, render_template_string, jsonify, stream_with_context
except ImportError as e:
    # Create a minimal WSGI app that returns the error
    def handler(environ, start_response):
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [f'Flask import failed: {str(e)}'.encode()]
    raise

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

app = Flask(__name__)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')

# Comprehensive secret patterns with severity levels
SECRET_PATTERNS = {
    # Critical severity
    'private_key': {
        'pattern': r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
        'severity': 'critical',
        'description': 'Private cryptographic key exposed'
    },
    'aws_secret': {
        'pattern': r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
        'severity': 'critical',
        'description': 'AWS Secret Access Key'
    },
    'aws_access_key': {
        'pattern': r'(?i)(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
        'severity': 'critical',
        'description': 'AWS Access Key ID'
    },
    'github_token': {
        'pattern': r'(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})',
        'severity': 'critical',
        'description': 'GitHub Personal Access Token'
    },
    'stripe_secret': {
        'pattern': r'sk_live_[a-zA-Z0-9]{24,}',
        'severity': 'critical',
        'description': 'Stripe Secret API Key'
    },
    
    # High severity
    'api_key': {
        'pattern': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?',
        'severity': 'high',
        'description': 'API Key detected'
    },
    'token': {
        'pattern': r'(?i)(token|auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-\.]{20,}["\']?',
        'severity': 'high',
        'description': 'Authentication token'
    },
    'secret': {
        'pattern': r'(?i)(secret|client[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?',
        'severity': 'high',
        'description': 'Secret key or client secret'
    },
    'bearer': {
        'pattern': r'(?i)["\']?bearer\s+[A-Za-z0-9_\-\.]{20,}["\']?',
        'severity': 'high',
        'description': 'Bearer token in code'
    },
    'jwt': {
        'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'severity': 'high',
        'description': 'JSON Web Token (JWT)'
    },
    'google_api': {
        'pattern': r'AIza[0-9A-Za-z_-]{35}',
        'severity': 'high',
        'description': 'Google API Key'
    },
    
    # Medium severity
    'password': {
        'pattern': r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?[^\s"\']{6,}["\']?',
        'severity': 'medium',
        'description': 'Password in code'
    },
    'authorization': {
        'pattern': r'(?i)authorization\s*[=:]\s*["\']?[A-Za-z0-9_\-\.]+["\']?',
        'severity': 'medium',
        'description': 'Authorization header value'
    },
    'database_url': {
        'pattern': r'(?i)(mongodb|mysql|postgres|postgresql|redis):\/\/[^\s"\']+',
        'severity': 'medium',
        'description': 'Database connection string'
    },
    'connection_string': {
        'pattern': r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\']?[^\s"\']+["\']?',
        'severity': 'medium',
        'description': 'Connection string'
    },
    
    # Low severity
    'email': {
        'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'severity': 'low',
        'description': 'Email address (potential PII)'
    },
    'ip_address': {
        'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'severity': 'low',
        'description': 'IP Address hardcoded'
    },
}

# Vulnerability patterns (code issues)
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'pattern': r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\'].*%s.*["\']|f["\'].*SELECT.*{',
        'severity': 'critical',
        'description': 'Potential SQL Injection'
    },
    'xss': {
        'pattern': r'(?i)(innerHTML|outerHTML|document\.write)\s*=',
        'severity': 'high',
        'description': 'Potential XSS vulnerability'
    },
    'eval_usage': {
        'pattern': r'\beval\s*\(',
        'severity': 'high',
        'description': 'Dangerous eval() usage'
    },
    'exec_usage': {
        'pattern': r'\bexec\s*\(',
        'severity': 'high',
        'description': 'Dangerous exec() usage'
    },
    'shell_injection': {
        'pattern': r'(?i)(os\.system|subprocess\.call|subprocess\.run|shell\s*=\s*True)',
        'severity': 'high',
        'description': 'Potential shell injection'
    },
    'insecure_random': {
        'pattern': r'(?i)random\.(random|randint|choice)\s*\(',
        'severity': 'medium',
        'description': 'Insecure random for crypto'
    },
    'hardcoded_secret': {
        'pattern': r'(?i)(secret|password|api_key|token)\s*=\s*["\'][^"\']+["\']',
        'severity': 'medium',
        'description': 'Hardcoded secret value'
    },
    'debug_mode': {
        'pattern': r'(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)',
        'severity': 'medium',
        'description': 'Debug mode enabled'
    },
    'cors_wildcard': {
        'pattern': r'(?i)(Access-Control-Allow-Origin|CORS).*\*',
        'severity': 'medium',
        'description': 'CORS wildcard enabled'
    },
    'http_without_tls': {
        'pattern': r'http://(?!localhost|127\.0\.0\.1)',
        'severity': 'low',
        'description': 'HTTP without TLS'
    },
}

def parse_github_url(repo_url):
    """Parse GitHub URL to extract owner and repo name."""
    import re
    patterns = [
        r'github\.com[/:]([^/]+)/([^/.]+?)(?:\.git)?$',
        r'github\.com[/:]([^/]+)/([^/.]+?)/?$'
    ]
    for pattern in patterns:
        match = re.search(pattern, repo_url)
        if match:
            return match.group(1), match.group(2)
    return None, None

def download_repo_via_api(repo_url):
    """Download repository files using GitHub API (no git required)."""
    import requests
    import zipfile
    import io
    
    owner, repo = parse_github_url(repo_url)
    if not owner or not repo:
        return None, "Invalid GitHub URL format"
    
    try:
        # Download the default branch as a zip
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        headers = {'Accept': 'application/vnd.github+json'}
        
        response = requests.get(zip_url, headers=headers, timeout=60, allow_redirects=True)
        
        if response.status_code == 404:
            return None, "Repository not found or is private"
        elif response.status_code != 200:
            return None, f"GitHub API error: {response.status_code}"
        
        # Extract to temp directory
        temp_dir = tempfile.mkdtemp(prefix='repo_')
        
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            # Get the root folder name in the zip
            root_folder = zf.namelist()[0].split('/')[0]
            
            for member in zf.namelist():
                # Skip the root folder itself
                if member == root_folder + '/':
                    continue
                
                # Remove the root folder from the path
                relative_path = '/'.join(member.split('/')[1:])
                if not relative_path:
                    continue
                
                target_path = os.path.join(temp_dir, relative_path)
                
                if member.endswith('/'):
                    os.makedirs(target_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, 'wb') as f:
                        f.write(zf.read(member))
        
        return temp_dir, None
        
    except requests.Timeout:
        return None, "Download timed out - repository may be too large"
    except Exception as e:
        return None, str(e)

def clone_repo(repo_url):
    """Download a GitHub repository (uses API, no git required)."""
    return download_repo_via_api(repo_url)

def get_file_content(filepath, max_size=500000):
    """Read file content with size limit."""
    try:
        if os.path.getsize(filepath) > max_size:
            return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        return None

def scan_file_for_secrets(filepath, content):
    """Scan a single file for secret patterns."""
    findings = []
    
    for keyword, config in SECRET_PATTERNS.items():
        try:
            matches = re.finditer(config['pattern'], content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                
                findings.append({
                    'type': 'secret',
                    'keyword': keyword,
                    'severity': config['severity'],
                    'description': config['description'],
                    'line': line_num,
                    'match': match.group()[:80] + '...' if len(match.group()) > 80 else match.group(),
                    'context': line_content.strip()[:120]
                })
        except Exception:
            pass
    
    return findings

def scan_file_for_vulnerabilities(filepath, content):
    """Scan a single file for vulnerability patterns."""
    findings = []
    
    for vuln_type, config in VULNERABILITY_PATTERNS.items():
        try:
            matches = re.finditer(config['pattern'], content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                
                findings.append({
                    'type': 'vulnerability',
                    'keyword': vuln_type,
                    'severity': config['severity'],
                    'description': config['description'],
                    'line': line_num,
                    'match': match.group()[:80] + '...' if len(match.group()) > 80 else match.group(),
                    'context': line_content.strip()[:120]
                })
        except Exception:
            pass
    
    return findings

def scan_repository_generator(repo_path):
    """Generator that yields findings as they're discovered."""
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', 
                 'vendor', 'bower_components', '.next', '.nuxt', 'coverage', '.cache'}
    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', 
                       '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz', '.pdf',
                       '.exe', '.dll', '.so', '.dylib', '.pyc', '.pyo', '.class',
                       '.svg', '.webp', '.bmp', '.min.js', '.min.css', '.map'}
    
    total_files = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in skip_extensions and not filename.startswith('.'):
                total_files += 1
    
    yield {'type': 'total_files', 'count': total_files}
    
    scanned = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in skip_extensions or filename.startswith('.'):
                continue
            
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, repo_path)
            
            content = get_file_content(filepath)
            if content is None:
                continue
            
            scanned += 1
            
            secret_findings = scan_file_for_secrets(filepath, content)
            vuln_findings = scan_file_for_vulnerabilities(filepath, content)
            all_findings = secret_findings + vuln_findings
            
            yield {
                'type': 'file_scanned',
                'file': relative_path,
                'scanned': scanned,
                'total': total_files,
                'findings_count': len(all_findings),
                'findings': all_findings
            }

def analyze_finding_with_gemini(finding, file_path, model):
    """Analyze a single finding with Gemini AI."""
    try:
        prompt = f"""Analyze this security finding and provide a brief assessment:

File: {file_path}
Type: {finding['type']} - {finding['keyword']}
Severity: {finding['severity']}
Description: {finding['description']}
Line {finding['line']}: {finding['context']}
Match: {finding['match']}

Provide in 2-3 sentences:
1. Why this is a security risk
2. How to fix it
3. Potential impact if exploited

Be concise and specific."""

        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Analysis unavailable: {str(e)}"

def get_overall_assessment(findings, repo_url, model):
    """Get overall security assessment from Gemini."""
    try:
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            severity_counts[f.get('severity', 'low')] += 1
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical'][:5]
        high_findings = [f for f in findings if f.get('severity') == 'high'][:5]
        sample = critical_findings + high_findings
        
        prompt = f"""Provide a comprehensive security assessment for the GitHub repository: {repo_url}

Summary of Findings:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Total: {len(findings)}

Sample of Critical/High Findings:
{json.dumps(sample[:10], indent=2)}

Provide:
1. Overall Security Score (0-100)
2. Risk Level (Critical/High/Medium/Low)
3. Top 3 Priority Actions
4. Security Recommendations
5. Brief summary of the repository's security posture

Format as a clear, professional security report."""

        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Overall assessment unavailable: {str(e)}"

# Inline HTML template for Vercel compatibility
INDEX_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CipherGuard - AI Security Scanner</title>
  <link rel="stylesheet" href="/static/css/style.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
  <div class="app-container">
    <main class="main-content">
      <div class="hero-section">
        <div class="shield-icon">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 6c1.4 0 2.8 1.1 2.8 2.5V11c.6.2 1.2.8 1.2 1.5v3c0 .8-.7 1.5-1.5 1.5h-5c-.8 0-1.5-.7-1.5-1.5v-3c0-.7.5-1.3 1.2-1.5V9.5C9.2 8.1 10.6 7 12 7zm0 1.2c-.8 0-1.5.5-1.5 1.3v1.5h3V9.5c0-.8-.7-1.3-1.5-1.3z"/>
          </svg>
        </div>
        <h1 class="app-title">CipherGuard</h1>
        <div class="gemini-badge" id="geminiBadge">
          <i class="fas fa-spinner fa-spin"></i>
          <span>Connecting to Gemini AI...</span>
        </div>
        <p class="app-subtitle">Intelligent security analysis for folders and GitHub repositories</p>
      </div>
      <div class="scan-card">
        <form id="scanForm" class="scan-form">
          <div class="input-group">
            <label for="repo"><i class="fas fa-crosshairs"></i> Target Path or GitHub URL</label>
            <input type="text" id="repo" name="repo" placeholder="https://github.com/username/repo" required>
          </div>
          <div class="input-group">
            <label for="severity"><i class="fas fa-filter"></i> Min Severity:</label>
            <div class="select-wrapper">
              <select id="severity" name="severity">
                <option value="quick">Low+ (Quick Scan)</option>
                <option value="standard">Medium+ (Standard)</option>
                <option value="high" selected>High+ (Deep Scan + AI)</option>
              </select>
              <i class="fas fa-chevron-down select-arrow"></i>
            </div>
          </div>
          <button type="button" id="scanBtn" class="scan-button">
            <i class="fas fa-robot"></i><span>Start AI Scan</span>
          </button>
        </form>
      </div>
      <section id="resultsSection" class="results-section" style="display: none;">
        <div id="loadingState" class="loading-state">
          <div class="loading-spinner"><div class="spinner-ring"></div><i class="fas fa-shield-halved spinner-icon"></i></div>
          <h2 id="loadingTitle">Initializing scan...</h2>
          <p id="loadingSub">Preparing security analysis</p>
          <div id="progressContainer" class="progress-container"></div>
          <div id="fileList" class="file-list"></div>
        </div>
        <div id="completedResults" class="completed-results" style="display: none;">
          <div id="statsGrid" class="stats-grid"></div>
          <div class="action-buttons">
            <button class="action-btn" onclick="copyResults()"><i class="fas fa-copy"></i> Copy Results</button>
            <button class="action-btn" id="toggleRawJson"><i class="fas fa-code"></i> View Raw JSON</button>
            <button class="action-btn primary" onclick="resetScan()"><i class="fas fa-plus"></i> New Scan</button>
          </div>
          <div class="findings-section">
            <h3 class="findings-title"><i class="fas fa-list-check"></i> Detailed Findings</h3>
            <div id="findingsContainer" class="findings-container"></div>
            <div id="noFindings" class="no-findings" style="display: none;">
              <i class="fas fa-check-circle"></i><h3>All Clear!</h3><p>No security vulnerabilities detected.</p>
            </div>
          </div>
          <div id="aiSummarySection" class="ai-summary-section" style="display: none;">
            <h3 class="ai-summary-title"><i class="fas fa-robot"></i> AI Security Analysis</h3>
            <div id="aiSummaryContent" class="ai-summary-content"></div>
          </div>
          <div id="rawJsonPanel" class="raw-json-panel" style="display: none;"><pre id="rawJson"></pre></div>
        </div>
      </section>
    </main>
    <footer class="app-footer"><p>CipherGuard v2.0 - AI-Powered Security Scanner</p></footer>
  </div>
  <script src="/static/js/main.js"></script>
</body>
</html>'''

@app.route('/')
def index():
    return INDEX_HTML

@app.route('/api/test_gemini')
def test_gemini():
    """Test Gemini API connection."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content("Say 'Gemini API connected!' in exactly those words.")
        return jsonify({
            'status': 'ok',
            'message': response.text,
            'api_key_configured': bool(GEMINI_API_KEY)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'api_key_configured': bool(GEMINI_API_KEY)
        })

@app.route('/scan_stream')
def scan_stream():
    repo_url = request.args.get('repo', '')
    scan_mode = request.args.get('severity', 'standard')
    
    def generate():
        yield f"event: status\ndata: {json.dumps({'step': 'Initializing', 'message': 'Starting security scan...', 'progress': 0})}\n\n"
        
        if not repo_url:
            yield f"event: error\ndata: {json.dumps({'error': 'No repository URL provided'})}\n\n"
            return
        
        yield f"event: status\ndata: {json.dumps({'step': 'Cloning Repository', 'message': f'Cloning {repo_url}...', 'progress': 5})}\n\n"
        
        repo_path, error = clone_repo(repo_url)
        if error:
            yield f"event: error\ndata: {json.dumps({'error': f'Clone failed: {error}'})}\n\n"
            return
        
        try:
            yield f"event: status\ndata: {json.dumps({'step': 'Analyzing Files', 'message': 'Counting files to scan...', 'progress': 10})}\n\n"
            
            all_findings = []
            total_files = 0
            scanned_files = 0
            
            for result in scan_repository_generator(repo_path):
                if result['type'] == 'total_files':
                    total_files = result['count']
                    yield f"event: status\ndata: {json.dumps({'step': 'Scanning Files', 'message': f'Found {total_files} files to scan', 'progress': 15, 'total_files': total_files})}\n\n"
                
                elif result['type'] == 'file_scanned':
                    scanned_files = result['scanned']
                    progress = 15 + int((scanned_files / max(total_files, 1)) * 50)
                    
                    yield f"event: file_progress\ndata: {json.dumps({'file': result['file'], 'scanned': scanned_files, 'total': total_files, 'progress': progress})}\n\n"
                    
                    if result['findings']:
                        for finding in result['findings']:
                            finding['file'] = result['file']
                            all_findings.append(finding)
                        
                        yield f"event: findings\ndata: {json.dumps({'file': result['file'], 'findings': result['findings']})}\n\n"
                    
                    time.sleep(0.02)
            
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
            
            yield f"event: status\ndata: {json.dumps({'step': 'Pattern Scan Complete', 'message': f'Found {len(all_findings)} potential issues', 'progress': 65})}\n\n"
            
            ai_analyses = []
            overall_assessment = None
            
            if scan_mode == 'high' and GEMINI_API_KEY:
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=GEMINI_API_KEY)
                    model = genai.GenerativeModel('gemini-2.0-flash')
                    
                    yield f"event: status\ndata: {json.dumps({'step': 'AI Analysis Starting', 'message': 'Connecting to Gemini AI...', 'progress': 68})}\n\n"
                    
                    priority_findings = [f for f in all_findings if f.get('severity') in ['critical', 'high']][:15]
                    
                    if priority_findings:
                        yield f"event: status\ndata: {json.dumps({'step': 'AI Analyzing Findings', 'message': f'Analyzing {len(priority_findings)} priority findings...', 'progress': 70})}\n\n"
                        
                        for i, finding in enumerate(priority_findings):
                            progress = 70 + int((i / len(priority_findings)) * 15)
                            yield f"event: ai_progress\ndata: {json.dumps({'current': i + 1, 'total': len(priority_findings), 'file': finding['file'], 'finding': finding['keyword'], 'progress': progress})}\n\n"
                            
                            analysis = analyze_finding_with_gemini(finding, finding['file'], model)
                            ai_analyses.append({
                                'finding': finding,
                                'analysis': analysis
                            })
                            
                            yield f"event: ai_analysis\ndata: {json.dumps({'finding': finding, 'analysis': analysis})}\n\n"
                            time.sleep(0.3)
                    
                    yield f"event: status\ndata: {json.dumps({'step': 'Generating Report', 'message': 'Creating overall security assessment...', 'progress': 88})}\n\n"
                    
                    overall_assessment = get_overall_assessment(all_findings, repo_url, model)
                    
                    yield f"event: overall_assessment\ndata: {json.dumps({'assessment': overall_assessment})}\n\n"
                    
                except Exception as e:
                    yield f"event: ai_error\ndata: {json.dumps({'error': f'AI analysis error: {str(e)}'})}\n\n"
            
            yield f"event: status\ndata: {json.dumps({'step': 'Finalizing', 'message': 'Preparing final report...', 'progress': 95})}\n\n"
            
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for f in all_findings:
                severity_counts[f.get('severity', 'low')] += 1
            
            result = {
                'repository': repo_url,
                'scan_mode': scan_mode,
                'total_files_scanned': scanned_files,
                'total_findings': len(all_findings),
                'severity_counts': severity_counts,
                'findings': all_findings,
                'ai_analyses': ai_analyses if ai_analyses else None,
                'overall_assessment': overall_assessment,
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            }
            
            yield f"event: status\ndata: {json.dumps({'step': 'Complete', 'message': 'Scan completed successfully!', 'progress': 100})}\n\n"
            yield f"event: result\ndata: {json.dumps({'result': result})}\n\n"
            
        finally:
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path, ignore_errors=True)
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok', 
        'gemini_configured': bool(GEMINI_API_KEY),
        'version': '2.0'
    })

@app.route('/api/debug')
def debug():
    """Debug endpoint to check file paths on Vercel."""
    import glob
    paths = {
        'BASE_DIR': BASE_DIR,
        'cwd': os.getcwd(),
        '__file__': __file__,
        'dirname_file': os.path.dirname(__file__),
    }
    
    # Check what files exist
    try:
        paths['vuln_ui_exists'] = os.path.exists(os.path.join(BASE_DIR, 'vulnerability_ui'))
        paths['static_exists'] = os.path.exists(os.path.join(BASE_DIR, 'vulnerability_ui', 'static'))
        paths['css_exists'] = os.path.exists(os.path.join(BASE_DIR, 'vulnerability_ui', 'static', 'css', 'style.css'))
    except:
        pass
    
    # List top-level dirs
    try:
        paths['base_dir_contents'] = os.listdir(BASE_DIR)[:20]
    except:
        paths['base_dir_contents'] = 'error listing'
    
    try:
        paths['cwd_contents'] = os.listdir(os.getcwd())[:20]
    except:
        paths['cwd_contents'] = 'error listing'
    
    return jsonify(paths)

@app.route('/static/css/style.css')
def serve_css():
    # Try multiple paths for Vercel compatibility
    paths_to_try = [
        os.path.join(BASE_DIR, 'vulnerability_ui', 'static', 'css', 'style.css'),
        os.path.join(os.path.dirname(__file__), '..', 'vulnerability_ui', 'static', 'css', 'style.css'),
        '/var/task/vulnerability_ui/static/css/style.css',
        '/vercel/path0/vulnerability_ui/static/css/style.css'
    ]
    for css_path in paths_to_try:
        try:
            with open(css_path, 'r') as f:
                return Response(f.read(), mimetype='text/css')
        except:
            continue
    return Response('/* CSS not found */', mimetype='text/css')

@app.route('/static/js/main.js')
def serve_js():
    # Try multiple paths for Vercel compatibility
    paths_to_try = [
        os.path.join(BASE_DIR, 'vulnerability_ui', 'static', 'js', 'main.js'),
        os.path.join(os.path.dirname(__file__), '..', 'vulnerability_ui', 'static', 'js', 'main.js'),
        '/var/task/vulnerability_ui/static/js/main.js',
        '/vercel/path0/vulnerability_ui/static/js/main.js'
    ]
    for js_path in paths_to_try:
        try:
            with open(js_path, 'r') as f:
                return Response(f.read(), mimetype='application/javascript')
        except:
            continue
    return Response('// JS not found', mimetype='application/javascript')




