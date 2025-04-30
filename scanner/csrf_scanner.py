from .vulnerability_scanner import VulnerabilityScanner
import re

class CSRFScanner(VulnerabilityScanner):
    def __init__(self, url):
        super().__init__(url)
        self.csrf_token_names = [
            'csrf_token',
            'csrftoken',
            'xsrf_token',
            'xsrf',
            '_csrf',
            '_csrftoken',
            'csrf',
            '__RequestVerificationToken'
        ]

    def check_csrf_protection(self, form):
        """Check if a form has CSRF protection."""
        form_details = self.get_form_details(form)
        
        # Check for CSRF token in form inputs
        has_csrf_token = False
        for input_field in form_details["inputs"]:
            input_name = input_field.get("name", "").lower()
            input_type = input_field.get("type", "").lower()
            
            # Check if input name matches known CSRF token patterns
            if any(token in input_name for token in self.csrf_token_names):
                has_csrf_token = True
                break
            
            # Check for hidden input fields that might be CSRF tokens
            if input_type == "hidden" and input_field.get("value"):
                # Look for token-like values
                value = input_field.get("value")
                if len(value) > 20:  # Most CSRF tokens are long strings
                    has_csrf_token = True
                    break

        return has_csrf_token

    def check_security_headers(self, response):
        """Check for security headers related to CSRF protection."""
        headers = response.headers
        
        # Check for SameSite cookie attribute
        cookies = response.cookies
        has_samesite = any('samesite' in cookie.lower() for cookie in cookies.keys())
        
        # Check security headers
        if 'X-Frame-Options' not in headers:
            self.add_vulnerability(
                "Missing X-Frame-Options header (clickjacking protection)",
                "medium",
                "HTTP Headers"
            )
        
        if not has_samesite:
            self.add_vulnerability(
                "Cookies do not have SameSite attribute",
                "medium",
                "Cookie Security"
            )

    def test_csrf_vulnerability(self, url, form_details):
        """Test for CSRF vulnerability in a form."""
        try:
            # First request to get the original form
            response1 = self.session.get(url)
            
            # Second request with the same form data
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] != "submit":
                    data[input_field["name"]] = input_field["value"]

            if form_details["method"] == "post":
                response2 = self.session.post(url, data=data)
            else:
                response2 = self.session.get(url, params=data)

            # If both requests are successful without CSRF protection,
            # the form might be vulnerable
            if response1.status_code == 200 and response2.status_code == 200:
                return True

        except Exception as e:
            self.logger.error(f"Error testing CSRF vulnerability: {str(e)}")
        return False

    def scan_url(self):
        """Perform CSRF vulnerability scan."""
        self.logger.info(f"Starting CSRF scan for {self.url}")
        
        try:
            # Get initial response to check security headers
            response = self.session.get(self.url)
            self.check_security_headers(response)

            # Crawl and find forms
            self.crawl()

            # Check each form for CSRF vulnerabilities
            for form in self.forms:
                form_details = self.get_form_details(form)
                
                # Skip forms that don't modify state (GET forms with no sensitive actions)
                if form_details["method"] == "get":
                    continue
                
                # Check if form has CSRF protection
                if not self.check_csrf_protection(form):
                    # Test if the form is actually vulnerable
                    if self.test_csrf_vulnerability(self.url, form_details):
                        self.add_vulnerability(
                            f"Potential CSRF vulnerability found in form at {self.url}",
                            "high",
                            f"Form action: {form_details['action']}, Method: {form_details['method']}"
                        )

        except Exception as e:
            self.logger.error(f"Error during CSRF scan: {str(e)}")
        finally:
            self.clean_session()

        return self.get_results()

    def verify_token_implementation(self, form_details):
        """Verify if CSRF token implementation is secure."""
        try:
            # Make multiple requests to check if tokens change
            tokens = set()
            for _ in range(3):
                response = self.session.get(self.url)
                soup = BeautifulSoup(response.content, 'html.parser')
                form = soup.find('form', action=form_details['action'])
                
                if form:
                    for input_field in form.find_all('input'):
                        if input_field.get('name', '').lower() in self.csrf_token_names:
                            tokens.add(input_field.get('value', ''))
            
            # If all tokens are same, it might be using a static token
            if len(tokens) == 1:
                self.add_vulnerability(
                    "Static CSRF token detected",
                    "medium",
                    f"Form action: {form_details['action']}"
                )
                
        except Exception as e:
            self.logger.error(f"Error verifying token implementation: {str(e)}")
