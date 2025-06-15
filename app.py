"""
CipherGuard - AI-Powered GitHub Vulnerability Scanner
Local Flask Development Server
"""

import os
import sys

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

from api.index import app

if __name__ == '__main__':
    print("=" * 50)
    print("CipherGuard - AI Security Scanner")
    print("=" * 50)
    print("Starting local development server...")
    print("Open http://localhost:8080 in your browser")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=8080)
