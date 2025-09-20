# 🛡️ CipherGuard - AI-Powered GitHub Vulnerability Scanner

CipherGuard is a modern web application that scans GitHub repositories for security vulnerabilities, exposed secrets, API keys, passwords, tokens, and other sensitive data. It features optional AI-powered analysis using Google Gemini for deeper security insights.

![CipherGuard](https://img.shields.io/badge/CipherGuard-Security%20Scanner-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-red?style=for-the-badge&logo=flask)

## ✨ Features

- 🔍 **Secret Detection**: Scans for passwords, API keys, tokens, private keys, and more
- 🤖 **AI Analysis**: Optional deep analysis powered by Google Gemini 2.0
- 🎨 **Modern Dark UI**: Beautiful, responsive interface with real-time updates
- 📊 **Severity Rankings**: Categorizes findings by criticality (Critical/High/Medium/Low)
- 🌐 **Real-time Streaming**: Live updates as files are scanned
- ☁️ **Vercel Ready**: Deployable as a serverless application

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/CipherGuard.git
   cd CipherGuard
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   # Create .env file with your Gemini API key
   echo "GEMINI_API_KEY=your_api_key_here" > .env
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open your browser**
   Navigate to `http://localhost:5000`

## 📁 Project Structure

```
CipherGuard/
├── api/
│   └── index.py          # Vercel serverless entry point & main Flask app
├── vulnerability_ui/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css # Dark theme styles
│   │   └── js/
│   │       └── main.js   # Frontend JavaScript
│   ├── templates/
│   │   └── index.html    # Main HTML template
│   └── __init__.py
├── app.py                 # Local Flask development server
├── requirements.txt       # Python dependencies
├── vercel.json           # Vercel deployment configuration
├── .env                  # Environment variables (not in git)
└── README.md
```

## 🔐 Secret Patterns Detected

| Type | Description |
|------|-------------|
| `password` | Password assignments in code |
| `api_key` | API keys and credentials |
| `token` | Authentication tokens |
| `secret` | Client secrets |
| `private_key` | RSA/SSH private keys |
| `aws_secret` | AWS secret access keys |
| `bearer` | Bearer tokens |
| `authorization` | Authorization headers |

## 🎯 Scan Modes

1. **Quick Scan**: Fast pattern matching for common secrets
2. **Standard Scan**: Comprehensive secret detection
3. **Deep Scan + AI Analysis**: Full scan with Gemini AI security assessment

## ☁️ Vercel Deployment

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Add your API key as a secret**
   ```bash
   vercel secrets add gemini-api-key "your_api_key_here"
   ```

3. **Deploy**
   ```bash
   vercel --prod
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google Gemini API key for AI analysis | Optional |

### Getting a Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Add it to your `.env` file

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for security research and educational purposes. Always ensure you have permission to scan a repository before using this tool. The developers are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- [Google Gemini](https://deepmind.google/technologies/gemini/) for AI capabilities
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Font Awesome](https://fontawesome.com/) for icons

---

Made with ❤️ by the CipherGuard Team
 
 
 
 
 
 
 
 
 
 
 
 
 
 
