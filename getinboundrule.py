import boto3
import csv

# Replace with your desired SG Group IDs
sg_group_ids = ['sg-0e8395d957c1caa7d']  # Example SG IDs
output_file = 'ibound_Sg_rules.csv'

# Initialize Boto3 EC2 client
ec2 = boto3.client('ec2')

def fetch_inbound_rules(sg_ids):
    """Fetches inbound rules for the given SG group IDs."""
    try:
        response = ec2.describe_security_groups(GroupIds=sg_ids)
        inbound_rules = []
        
        for sg in response['SecurityGroups']:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', '')
            
            for permission in sg['IpPermissions']:
                # Extract protocol, port range, and CIDR blocks
                protocol = permission.get('IpProtocol', 'N/A')
                from_port = permission.get('FromPort', 'All')  # 'All' if no port range
                to_port = permission.get('ToPort', 'All')
                
                # Extract CIDR ranges
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', 'N/A')
                    description = ip_range.get('Description', 'N/A')
                    
                    # Append the extracted data
                    inbound_rules.append({
                        'SecurityGroupID': group_id,
                        'GroupName': group_name,
                        'Type': 'Inbound',
                        'Protocol': protocol,
                        'PortRange': f"{from_port}-{to_port}" if from_port != 'All' else "All",
                        'SourceCIDR': cidr,
                        'Description': description
                    })
                    
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def save_to_csv(data, filename):
    """Saves the inbound rules to a CSV file."""
    if not data:
        print("No data to save.")
        return
    
    try:
        keys = ['SecurityGroupID', 'GroupName', 'Type', 'Protocol', 'PortRange', 'SourceCIDR', 'Description']
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        
        print(f"Data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving to CSV: {e}")

if __name__ == "__main__":
    print("Fetching inbound rules for the specified security groups...")
    inbound_data = fetch_inbound_rules(sg_group_ids)
    save_to_csv(inbound_data, output_file)
