import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from clamav_scanner import scan_with_clamav
from xss_scanner import scan_url_for_xss
from threat_intel import threat_intel_bp


app = Flask(__name__)
app.register_blueprint(threat_intel_bp)

UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
XSS_LOG_PATH = os.path.join(LOG_FOLDER, 'xss_scanner.log')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner', methods=['GET','POST'])
def file_scanner():
    result = None
    uploaded_file = request.files.get('file')
    if uploaded_file and uploaded_file.filename != '':
        filename = secure_filename(uploaded_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(filepath)
        result = scan_with_clamav(filepath)
    return render_template('file_scan.html', result=result)

@app.route('/xss', methods=['GET', 'POST'])
def xss_scanner():
    results = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            results = scan_url_for_xss(url)

    return render_template('xss.html', results=results)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

