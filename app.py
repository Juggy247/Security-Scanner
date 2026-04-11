from flask import Flask, request, render_template, render_template_string, jsonify, redirect, url_for, session
#from scanner.ml_integration import EnhancedSecurityScanner, add_ml_to_verdict
from scanner.core import SecurityScanner, ScanReport
import json
from flasgger import Swagger
from dotenv import load_dotenv
from urllib.parse import urlparse
import os   
import ipaddress 
from admin_bp import admin_bp

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') 


app.register_blueprint(admin_bp)

scanner = SecurityScanner()

app.config['SWAGGER'] = {
    'title': 'Security Scanner API',
    'description': 'Ethical web security scanner for HTTPS, SSL, headers, and forms',
    'version': '1.0',
    'uiversion': 3,
    'specs_route': '/apidocs/'
}
swagger = Swagger(app)

def is_safe_url(url:str) -> tuple[bool, str]:
    "block private ips, localhost, non http schemes"
    try:
        parsed = urlparse(url)

        #Only allow http and https
        if parsed.scheme not in ('http','https'):
            return False, "Only HTTP and HTTPS URLs are allowed"
        
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL"
        
        #Block localhost
        if hostname in ('localhost', '127.0.0.1', '::1'):
            return False, "Scanning Localhost is not allowed"
        
        #Block private ip ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                return False, "Scanning private/Internal ip address is not allowed"
        except ValueError:
            pass
        return True,""
    
    except Exception as e:
        return False,f"Invalid: {str(e)}"

@app.route('/')
def home():
    """Home page with scan form."""
    return render_template('home.html')


@app.route('/scan', methods=['POST'])
def scan():
    """
    Scan a website for security issues.
    ---
    parameters:
      - name: url
        in: formData
        type: string
        required: true
        description: Website URL to scan
    responses:
      200:
        description: Redirect to report page
    """
    url = request.form.get('url')
    if not url:
        return "URL required", 400
    
    if not url.startswith('http'):
        url = 'https://' + url

    safe, reason = is_safe_url(url)
    if not safe:
        return f"URL not allowed: {reason}", 400
    
    # Perform scan
    report = scanner.scan(url)
    
    #if not report.success:
     #   return f"Scan failed: {report.error}", 500
    if not report.success and report.error == "Invalid URL":
        return f"Scan failed: {report.error}", 400
    
    # Get verdict
    verdict = report.get_verdict()
    
    # Store in session instead of URL
    session['scan_data'] = {
        'url': url,
        'verdict': verdict,
        'raw': report.to_dict()
    }
    
    return redirect(url_for('report'))


@app.route('/report')
def report():
    """Display scan report with detailed analysis."""
    from datetime import datetime
    
    # Get data from session
    data = session.get('scan_data')
    
    if not data:
        return redirect(url_for('home'))
    
    verdict = data.get('verdict', {})
    raw_data = data.get('raw', {})
    
    # Create ScanReport object from raw data for template
    scan_report = ScanReport(**raw_data)
    
    # Determine verdict class for styling
    verdict_text = verdict.get('verdict', '').upper()
    if 'SUSPICIOUS' in verdict_text:
        verdict_class = 'suspicious'
    elif 'SAFE' in verdict_text:
        verdict_class = 'safe'
    else:
        verdict_class = 'warning'
    
    # Get current timestamp
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Render template with scan_report object
    return render_template('report.html',
        url=data.get('url', 'Unknown'),
        verdict=verdict,
        verdict_class=verdict_class,
        scan_report=scan_report,
        current_time=current_time
    )


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    API endpoint to scan a URL and return JSON verdict.
    ---
    parameters:
      - name: url
        in: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              example: https://example.com
    responses:
      200:
        description: Scan results with verdict
    """
    data = request.get_json()
    url = data.get('url') if data else None
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL not allowed: {reason}"}), 400
    
    report = scanner.scan(url)

    if not report.success and report.error == "Invalid URL":
        return f"Scan failed: {report.error}", 400
    #if not report.success:
    #    return jsonify({"error": report.error}), 500
    
    verdict = report.get_verdict()
    
    return jsonify({
        "url": url,
        "verdict": verdict,
        "scan_data": report.to_dict()
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)