from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
import os
from scanner import XSSScanner, SQLScanner, CSRFScanner
import concurrent.futures
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_scanner(scanner_class, url):
    """Run a specific scanner and return its results."""
    try:
        scanner = scanner_class(url)
        return scanner.scan_url()
    except Exception as e:
        logger.error(f"Error in {scanner_class.__name__}: {str(e)}")
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    url = request.args.get('url')
    if not url:
        return redirect(url_for('index'))
    return render_template('scan.html')

@app.route('/results')
def results_page():
    return render_template('results.html')

@app.route('/test')
def test_site():
    return send_from_directory('test_site', 'index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        # Initialize results dictionary
        results = {
            'url': url,
            'vulnerabilities': {
                'xss': [],
                'sql_injection': [],
                'csrf': []
            },
            'status': 'success'
        }

        # Run scanners in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            scanner_tasks = {
                'xss': executor.submit(run_scanner, XSSScanner, url),
                'sql_injection': executor.submit(run_scanner, SQLScanner, url),
                'csrf': executor.submit(run_scanner, CSRFScanner, url)
            }

            # Collect results
            for scanner_type, future in scanner_tasks.items():
                try:
                    scanner_result = future.result()
                    if 'error' in scanner_result:
                        results['vulnerabilities'][scanner_type].append(
                            f"Scanner error: {scanner_result['error']}"
                        )
                    else:
                        # Extract vulnerabilities from scanner results
                        vulns = scanner_result.get('vulnerabilities', [])
                        results['vulnerabilities'][scanner_type].extend(
                            [v['description'] for v in vulns]
                        )
                except Exception as e:
                    logger.error(f"Error collecting results from {scanner_type}: {str(e)}")
                    results['vulnerabilities'][scanner_type].append(
                        f"Error collecting results: {str(e)}"
                    )

        return jsonify(results)

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({
            'error': 'An error occurred during the scan',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)
