#!/usr/bin/env python3
"""
MITRE ATT&CK Campaign Mapper
Maps campaign techniques to CSV format for ML workflows
"""

import csv
import re
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import uuid

class MITRECampaignMapper:
    def __init__(self, campaign_url):
        self.campaign_url = campaign_url
        self.campaign_id = self._extract_campaign_id(campaign_url)
        self.techniques = []
        
    def _extract_campaign_id(self, url):
        """Extract campaign ID from URL (e.g., C0017)"""
        match = re.search(r'C\d+', url)
        return match.group(0) if match else None
    
    def fetch_campaign_data(self):
        """Fetch and parse campaign page"""
        response = requests.get(self.campaign_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all technique links in the page
        technique_links = soup.find_all('a', href=re.compile(r'/techniques/T\d+'))
        
        seen_techniques = set()
        for link in technique_links:
            href = link.get('href')
            # Extract technique ID (e.g., T1071, T1071.001)
            match = re.search(r'T\d+(?:\.\d+)?', href)
            if match:
                technique_id = match.group(0)
                if technique_id not in seen_techniques:
                    seen_techniques.add(technique_id)
                    self.techniques.append({
                        'technique_id': technique_id,
                        'technique_name': link.text.strip(),
                        'url': f"https://attack.mitre.org{href}"
                    })
        
        return self.techniques
    
    def generate_csv_data(self, output_file='attack_mapping.csv'):
        """Generate CSV with the specified structure"""
        
        if not self.techniques:
            self.fetch_campaign_data()
        
        rows = []
        base_timestamp = datetime.now()
        
        for idx, technique in enumerate(self.techniques):
            # Generate unique session_id for this analysis
            session_id = str(uuid.uuid4())
            
            row = {
                'created_at': base_timestamp.isoformat(),
                'attack_id': self.campaign_id,  # Campaign ID (C0017)
                'aml_id': technique['technique_id'],  # MITRE ATT&CK Technique ID
                'base_url': self.campaign_url,
                'session_id': session_id
            }
            rows.append(row)
        
        # Write to CSV
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['created_at', 'attack_id', 'aml_id', 'base_url', 'session_id']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"✓ Generated {len(rows)} rows in {output_file}")
        return rows
    
    def print_summary(self):
        """Print summary of extracted techniques"""
        print(f"\nCampaign: {self.campaign_id}")
        print(f"Total Techniques: {len(self.techniques)}\n")
        print("Extracted Techniques:")
        print("-" * 80)
        for tech in sorted(self.techniques, key=lambda x: x['technique_id']):
            print(f"{tech['technique_id']:12} {tech['technique_name']}")
        print("-" * 80)


def main():
    # Initialize mapper with C0017 campaign
    campaign_url = "https://attack.mitre.org/campaigns/C0017/"
    
    print("MITRE ATT&CK Campaign Mapper")
    print("=" * 80)
    
    mapper = MITRECampaignMapper(campaign_url)
    
    # Fetch campaign data
    print(f"\nFetching data from: {campaign_url}")
    mapper.fetch_campaign_data()
    
    # Print summary
    mapper.print_summary()
    
    # Generate CSV
    print("\nGenerating CSV output...")
    mapper.generate_csv_data()
    
    print("\n✓ Complete! CSV file ready for ML workflow.")


if __name__ == "__main__":
    main()