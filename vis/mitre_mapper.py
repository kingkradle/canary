import requests
from bs4 import BeautifulSoup
import csv
from datetime import datetime
import uuid
import time

def extract_all_campaigns():
    """
    Extracts all campaigns from MITRE ATT&CK campaigns page
    """
    base_url = "https://attack.mitre.org"
    campaigns_url = f"{base_url}/campaigns/"
    
    print(f"Fetching campaigns from {campaigns_url}...")
    
    # Get the main campaigns page
    response = requests.get(campaigns_url)
    response.raise_for_status()
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all campaign links in the table
    campaigns = []
    
    # Look for the campaigns table
    table = soup.find('table', {'class': 'table-techniques'})
    
    if not table:
        # Try alternative selectors
        table = soup.find('table')
    
    if table:
        rows = table.find_all('tr')[1:]  # Skip header row
        
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 2:
                # Extract campaign ID and name
                campaign_link = cols[0].find('a')
                if campaign_link:
                    campaign_id = campaign_link.text.strip()
                    campaign_url = base_url + campaign_link['href']
                    campaign_name = cols[1].text.strip() if len(cols) > 1 else ""
                    
                    campaigns.append({
                        'id': campaign_id,
                        'name': campaign_name,
                        'url': campaign_url
                    })
                    print(f"Found: {campaign_id} - {campaign_name}")
    
    print(f"\nTotal campaigns found: {len(campaigns)}")
    return campaigns

def extract_techniques_for_campaign(campaign_url, campaign_id):
    """
    Extracts all techniques (TTPs) for a specific campaign
    """
    print(f"\nExtracting techniques for {campaign_id}...")
    
    try:
        response = requests.get(campaign_url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        techniques = []
        
        # Find the techniques table
        # Look for table with techniques
        tables = soup.find_all('table')
        
        for table in tables:
            # Check if this is the techniques table
            header = table.find('thead')
            if header and ('Technique' in header.text or 'ID' in header.text):
                rows = table.find_all('tr')[1:]  # Skip header
                
                for row in rows:
                    cols = row.find_all('td')
                    if cols:
                        # Try to find technique ID
                        technique_link = row.find('a', href=lambda x: x and '/techniques/' in x)
                        if technique_link:
                            technique_id = technique_link.text.strip()
                            techniques.append(technique_id)
        
        # Remove duplicates
        techniques = list(set(techniques))
        print(f"Found {len(techniques)} techniques for {campaign_id}")
        
        return techniques
        
    except Exception as e:
        print(f"Error extracting techniques for {campaign_id}: {e}")
        return []

def main():
    # Extract all campaigns
    campaigns = extract_all_campaigns()
    
    # Prepare CSV data
    csv_data = []
    
    # For each campaign, extract techniques
    for i, campaign in enumerate(campaigns, 1):
        print(f"\n[{i}/{len(campaigns)}] Processing {campaign['id']}...")
        
        techniques = extract_techniques_for_campaign(campaign['url'], campaign['id'])
        
        # Create CSV rows
        timestamp = datetime.now().isoformat()
        
        if techniques:
            for technique in techniques:
                csv_data.append({
                    'created_at': timestamp,
                    'attack_id': campaign['id'],
                    'aml_id': technique,
                    'base_url': campaign['url'],
                    'session_id': str(uuid.uuid4())
                })
        else:
            # Even if no techniques found, add campaign entry
            csv_data.append({
                'created_at': timestamp,
                'attack_id': campaign['id'],
                'aml_id': '',
                'base_url': campaign['url'],
                'session_id': str(uuid.uuid4())
            })
        
        # Be respectful - add a small delay between requests
        if i < len(campaigns):
            time.sleep(1)
    
    # Write to CSV
    output_file = 'mitre_campaigns_full.csv'
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['created_at', 'attack_id', 'aml_id', 'base_url', 'session_id']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(csv_data)
    
    print(f"\n✓ Data saved to {output_file}")
    print(f"Total campaigns: {len(campaigns)}")
    print(f"Total rows: {len(csv_data)}")

if __name__ == "__main__":
    main()