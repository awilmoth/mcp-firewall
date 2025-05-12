#!/usr/bin/env python3
import sys
import os
import json
import unittest

# Add parent directory to path to import the app module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the implementation function directly
from app.mcp_firewall import process_text_impl, DEFAULT_RULES, rules

class TestTextProcessing(unittest.TestCase):
    def setUp(self):
        # Reset rules to defaults for each test
        global rules
        rules.clear()
        rules.extend(DEFAULT_RULES)

    def test_ssn_processing(self):
        text = "My SSN is 123-45-6789"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "My SSN is <SSN>")
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["original"], "123-45-6789")
        self.assertEqual(result["matches"][0]["replacement"], "<SSN>")

    def test_credit_card_processing(self):
        text = "My credit card is 4111-1111-1111-1111"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "My credit card is <CREDIT_CARD>")
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["original"], "4111-1111-1111-1111")
        self.assertEqual(result["matches"][0]["replacement"], "<CREDIT_CARD>")

    def test_email_processing(self):
        text = "My email is test@example.com"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "My email is <EMAIL>")
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["original"], "test@example.com")
        self.assertEqual(result["matches"][0]["replacement"], "<EMAIL>")

    def test_phone_processing(self):
        text = "My phone is (555) 123-4567"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "My phone is <PHONE>")
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["replacement"], "<PHONE>")

    def test_multiple_rules(self):
        text = "My SSN is 123-45-6789 and my email is test@example.com"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "My SSN is <SSN> and my email is <EMAIL>")
        self.assertEqual(len(result["matches"]), 2)

    def test_no_matches(self):
        text = "This text contains no sensitive information"
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], text)
        self.assertEqual(len(result["matches"]), 0)

    def test_empty_input(self):
        text = ""
        result = process_text_impl(text)
        self.assertEqual(result["processed_text"], "")
        self.assertEqual(len(result["matches"]), 0)

if __name__ == "__main__":
    unittest.main()