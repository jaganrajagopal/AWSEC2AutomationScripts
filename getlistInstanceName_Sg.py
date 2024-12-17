import boto3
import csv
import sys
import argparse

#sggroup=sys.argv[0]
# Replace with your desired Security Group IDs
#sg_group_ids = sg_ids ; #  ['sg-0123456789abcdef0']  # Example Security Group IDs

output_file = 'ec2_instance_sg_details.csv'
aws_regions = ['us-east-1', 'us-west-2']  # List of AWS regions to search


def get_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Fetch EC2 instance details for specified Security Group IDs.")
    parser.add_argument(
        '--sg_ids', 
        type=str, 
        required=True, 
        help="Comma-separated list of Security Group IDs (e.g., sg-1234abcd,sg-5678efgh)"
    )
    
    return parser.parse_args()

def get_ec2_instances(sg_ids, regions):
    """Fetches EC2 instance details for the given SG Group IDs across regions."""

    instance_data = []

    try:
        for region in regions:
            print(f"Checking region: {region}")
            ec2 = boto3.client('ec2', region_name=region)

            # Describe instances with filters for the given SG group IDs
            response = ec2.describe_instances(
                Filters=[
                    {'Name': 'instance.group-id', 'Values': sg_ids}
                ]
            )

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Extract instance details
                    instance_id = instance.get('InstanceId', 'N/A')
                    private_ip = instance.get('PrivateIpAddress', 'N/A')
                    nic_count = len(instance.get('NetworkInterfaces', []))
                    region_name = region
                    
                    # Extract Security Group Details
                    security_groups = instance.get('SecurityGroups', [])
                    for sg in security_groups:
                        sg_id = sg.get('GroupId', 'N/A')
                        sg_name = sg.get('GroupName', 'N/A')

                        # Extract instance name from Tags
                        tags = instance.get('Tags', [])
                        instance_name = 'N/A'
                        for tag in tags:
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                        
                        # Append data to the list
                        instance_data.append({
                            'InstanceName': instance_name,
                            'InstanceID': instance_id,
                            'PrivateIPAddress': private_ip,
                            'NIC_Count': nic_count,
                            'SG_GroupID': sg_id,
                            'SG_GroupName': sg_name,
                            'Region': region_name
                        })

    except Exception as e:
        print(f"Error fetching EC2 instance details: {e}")
    
    return instance_data

def save_to_csv(data, filename):
    """Saves the collected instance data to a CSV file."""
    if not data:
        print("No data to save.")
        return
    
    try:
        keys = ['InstanceName', 'InstanceID', 'PrivateIPAddress', 'NIC_Count', 'SG_GroupID', 'SG_GroupName', 'Region']
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        
        print(f"Data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving to CSV: {e}")

if __name__ == "__main__":
    print("Fetching EC2 instances for the specified security groups...")
    args = get_arguments()
    sg_ids = args.sg_ids.split(',')
    instance_details = get_ec2_instances(sg_ids, aws_regions)
    save_to_csv(instance_details, output_file)
