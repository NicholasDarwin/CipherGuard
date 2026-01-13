from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return '<html><body><h1>CipherGuard Works!</h1></body></html>'

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})

def handler(environ, start_response):
    return app(environ, start_response)
