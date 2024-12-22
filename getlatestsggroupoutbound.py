import boto3
import csv
from datetime import datetime, timedelta
import json
import sys, os

# Initialize the EC2 client
ec2_client = boto3.client('ec2', region_name='us-east-1')  # Replace 'your-region' with the appropriate AWS region

# Parent Security Group ID
security_group_id = 'sg-0e8395d957c1caa7d'  # Replace with your security group ID

# Calculate the time range for the last two days
end_time = datetime.utcnow()
start_time = end_time - timedelta(days=2)

# Function to get the security group change logs
def get_security_group_changes():
    try:
        # Use the CloudTrail client to filter security group changes
        cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1')

        # Filter events related to security group changes
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'ResourceName', 'AttributeValue': security_group_id}
            ],
            StartTime=start_time,
            EndTime=end_time
        )

        events = response['Events']
        changes = []

        for event in events:
            event_detail = event['CloudTrailEvent']
            event_time = event['EventTime']
            event_name = event['EventName']
            changes.append({
                'EventTime': event_time,
                'EventName': event_name,
                'Details': event_detail
            })
            # Filter for security group details
            # if 'requestParameters' in  event_detail['requestParameters'] and 'groupId' in event_detail['requestParameters']:
            #     group_id = event_detail['requestParameters']['groupId']
            #     if group_id == security_group_id:
            #         #ip_permissions = event_detail['requestParameters'].get('ipPermissions', {})
            #         event_group_id= event_detail['requestParameters']['ipPermissions']
            #         print(event_group_id)
            #         changes.append({
            #             'EventTime': event_time,
            #             'EventName': event_name,
            #             'GroupId': group_id
            #             #'IpPermissions': json.dumps(ip_permissions)
            #         })
            
            # if 'requestParameters' in event_detail and 'ipPermissions' in event_detail['requestParameters']:
            #     ip_permissions = event_detail['requestParameters']['ipPermissions']['items']
                
            #     # Iterate through the ipPermissions
            #     for permission in ip_permissions:
            #         group_items = permission.get('groups', {}).get('items', [])
            #         for group in group_items:
            #             # Append each group's details
            #             changes.append({
            #                 "groupId": group.get("groupId"),
            #                 "description": group.get("description"),
            #                 "ipProtocol": permission.get("ipProtocol"),
            #                 "fromPort": permission.get("fromPort"),
            #                 "toPort": permission.get("toPort")
            #             })
        return changes

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        return []

# Function to write changes to a CSV file
def write_to_csv(changes):
    csv_file = 'outbound_rules_sg.csv'

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['EventTime', 'EventName', 'Details'])
        writer.writeheader()
        writer.writerows(changes)

    print(f"Security group changes have been written to {csv_file}")

# Main execution
if __name__ == "__main__":
    changes = get_security_group_changes()

    if changes:
        write_to_csv(changes)
    else:
        print("No changes found for the specified security group in the last two days.")
