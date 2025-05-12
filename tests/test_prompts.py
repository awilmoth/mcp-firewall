#!/usr/bin/env python3
import sys
import json
import requests
import argparse

def redact_prompt(text, server_url="http://localhost:6366"):
    """Send a prompt for redaction and return the result"""
    try:
        response = requests.post(
            f"{server_url}/redact",
            json={"text": text}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}

def print_redaction_result(result):
    """Print redaction result in a readable format"""
    if "error" in result:
        print(f"Error: {result['error']}")
        return
    
    print("\n=== Original vs Redacted ===")
    print(f"Original: {result.get('original_text', 'N/A')}")
    print(f"Redacted: {result.get('redacted_text', 'N/A')}")
    
    matches = result.get("matches", [])
    if matches:
        print("\n=== Redactions Applied ===")
        for i, match in enumerate(matches, 1):
            print(f"{i}. {match.get('original', 'N/A')} → {match.get('replacement', 'N/A')} ({match.get('rule_name', 'Unknown')})")
    else:
        print("\nNo redactions applied.")

def run_example_prompts():
    """Run a set of example prompts through the MCP Firewall"""
    examples = [
        {
            "name": "Personal Information",
            "prompt": """
            Please analyze this customer profile:
            Name: John Smith
            SSN: 123-45-6789
            Email: john.smith@example.com
            Phone: (555) 123-4567
            Credit Card: 4111-1111-1111-1111
            """
        },
        {
            "name": "Technical Configuration",
            "prompt": """
            I'm trying to debug my AWS configuration:
            Server IP: 192.168.1.100
            Database: mysql://root:password123@localhost:3306/mydb
            API Key: api_key=1234567890abcdef
            AWS Key: AKIAIOSFODNN7EXAMPLE
            """
        },
        {
            "name": "Non-sensitive Text",
            "prompt": """
            Can you explain how machine learning works?
            I'm particularly interested in neural networks and deep learning.
            """
        },
        {
            "name": "Mix of Code and Sensitive Data",
            "prompt": """
            Here's my Python code that's not working:
            
            ```python
            def connect_to_database():
                password = "supersecretpassword123"
                conn_string = f"postgresql://admin:{password}@db.example.com:5432/myapp"
                # Connect to database
                return conn_string
            
            api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
            ```
            
            Why am I getting an error?
            """
        }
    ]
    
    for example in examples:
        print(f"\n\n{'='*50}")
        print(f"EXAMPLE: {example['name']}")
        print(f"{'='*50}")
        
        print("\n--- Original Prompt ---")
        print(example["prompt"])
        
        result = redact_prompt(example["prompt"])
        
        # Add original text to result for display
        result["original_text"] = example["prompt"]
        
        print_redaction_result(result)

def main():
    parser = argparse.ArgumentParser(description="Test MCP Firewall with example prompts")
    parser.add_argument("--url", default="http://localhost:6366", help="MCP Firewall server URL")
    args = parser.parse_args()
    
    print("MCP FIREWALL PROMPT TESTING")
    print("===========================")
    print(f"Server URL: {args.url}")
    
    run_example_prompts()

if __name__ == "__main__":
    main()