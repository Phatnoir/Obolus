#!/usr/bin/env python3
"""
Example of using Obolus over email.

This script demonstrates a simple workflow:
1. Generate a challenge for an action
2. Send the challenge as an email attachment
3. Wait for and process the response
"""

import json
import smtplib
import argparse
import imaplib
import email
import email.mime.application
import email.mime.multipart
import email.mime.text
import time
import os
import sys
import subprocess
from datetime import datetime

# You can import the Obolus modules directly, but for this example,
# we'll use the CLI tools to show how they can be used in a script

def generate_challenge(action, expiry=60):
    """Generate an Obolus challenge using the CLI tool"""
    cmd = ["python", "tools/challenge-gen.py", action, "--expiry", str(expiry)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout

def verify_response(challenge_file, response_file, public_key):
    """Verify an Obolus response using the CLI tool"""
    cmd = ["python", "tools/obolus-verify.py", 
           "--key", public_key, 
           "--challenge", challenge_file, 
           "--response", response_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout

class EmailTransport:
    def __init__(self, smtp_server, smtp_port, imap_server, imap_port, email_address, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.email_address = email_address
        self.password = password
    
    def send_challenge(self, recipient_email, action, expiry=60):
        """Generate a challenge and send it via email"""
        # Generate challenge
        challenge_json = generate_challenge(action, expiry)
        challenge = json.loads(challenge_json)
        
        # Create email
        msg = email.mime.multipart.MIMEMultipart()
        msg['From'] = self.email_address
        msg['To'] = recipient_email
        msg['Subject'] = f"Obolus Authentication: {action}"
        
        # Email body
        body = f"""
        Please confirm this action: {action}
        
        Challenge ID: {challenge['id']}
        Expires at: {challenge['expires_at']}
        
        To approve, sign the attached challenge.json file using your Obolus client and reply with the response.json.
        """
        msg.attach(email.mime.text.MIMEText(body, 'plain'))
        
        # Attach challenge.json
        attachment = email.mime.application.MIMEApplication(challenge_json, _subtype="json")
        attachment.add_header('Content-Disposition', 'attachment', filename='challenge.json')
        msg.attach(attachment)
        
        # Save a copy of the challenge for verification
        temp_dir = os.path.join(os.getcwd(), "temp")
        os.makedirs(temp_dir, exist_ok=True)
        challenge_file = os.path.join(temp_dir, f"challenge_{challenge['id']}.json")
        with open(challenge_file, "w") as f:
            f.write(challenge_json)
        
        # Send email
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_address, self.password)
            server.send_message(msg)
            server.quit()
            print(f"Challenge sent to {recipient_email}")
            return challenge['id'], challenge_file
        except Exception as e:
            print(f"Failed to send email: {e}")
            return None, None
    
    def wait_for_response(self, challenge_id, challenge_file, public_key, timeout=300):
        """Wait for a response email with the signed challenge"""
        start_time = time.time()
        temp_dir = os.path.join(os.getcwd(), "temp")
        os.makedirs(temp_dir, exist_ok=True)
        
        while time.time() - start_time < timeout:
            try:
                # Connect to IMAP server
                mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
                mail.login(self.email_address, self.password)
                mail.select('inbox')
                
                # Search for emails with response attachment
                search_query = f'SUBJECT "Re: Obolus Authentication"'
                status, data = mail.search(None, search_query)
                
                if status != 'OK':
                    print("No response emails found yet")
                    time.sleep(10)  # Wait before checking again
                    mail.logout()
                    continue
                
                for num in data[0].split():
                    status, data = mail.fetch(num, "(RFC822)")
                    email_msg = email.message_from_bytes(data[0][1])
                    
                    # Process attachments
                    for part in email_msg.walk():
                        if part.get_content_maintype() == 'multipart':
                            continue
                        if part.get('Content-Disposition') is None:
                            continue
                        
                        filename = part.get_filename()
                        if filename and filename.endswith('.json'):
                            # Save attachment
                            response_data = part.get_payload(decode=True).decode('utf-8')
                            response = json.loads(response_data)
                            
                            # Check if this is a response to our challenge
                            if response.get('id') == challenge_id:
                                # Save response to file for verification
                                response_file = os.path.join(temp_dir, f"response_{challenge_id}.json")
                                with open(response_file, "w") as f:
                                    f.write(response_data)
                                
                                # Verify the response
                                success, output = verify_response(challenge_file, response_file, public_key)
                                return success, output
                
                mail.logout()
                time.sleep(10)  # Wait before checking again
                
            except Exception as e:
                print(f"Error checking email: {e}")
                time.sleep(10)  # Wait before trying again
        
        print(f"Timeout waiting for response after {timeout} seconds")
        return False, "timeout"

def main():
    parser = argparse.ArgumentParser(description="Obolus Email Transport Example")
    parser.add_argument("--smtp-server", required=True, help="SMTP server address")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP server port")
    parser.add_argument("--imap-server", required=True, help="IMAP server address")
    parser.add_argument("--imap-port", type=int, default=993, help="IMAP server port")
    parser.add_argument("--email", required=True, help="Your email address")
    parser.add_argument("--password", required=True, help="Your email password")
    parser.add_argument("--recipient", required=True, help="Recipient email address")
    parser.add_argument("--action", required=True, help="Action to authenticate")
    parser.add_argument("--public-key", required=True, help="Path to public key for verification")
    args = parser.parse_args()
    
    transport = EmailTransport(
        args.smtp_server,
        args.smtp_port,
        args.imap_server,
        args.imap_port,
        args.email,
        args.password
    )
    
    # Send challenge
    challenge_id, challenge_file = transport.send_challenge(args.recipient, args.action)
    if not challenge_id:
        print("Failed to send challenge")
        return
    
    print(f"Waiting for response to challenge {challenge_id}...")
    success, output = transport.wait_for_response(challenge_id, challenge_file, args.public_key)
    
    if success:
        print(f"✅ Authentication successful!")
        print(output)
    else:
        print(f"❌ Authentication failed.")
        print(output)

if __name__ == "__main__":
    main()