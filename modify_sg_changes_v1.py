import boto3
import csv
import json
from datetime import datetime, timedelta

# AWS configuration
aws_region = "us-east-1"  # Update with your AWS region
parent_sg_ids = ["sg-081eaa2ddb056954c","sg-03dc1e65602297291"]  # Replace with your parent security group IDs
output_csv = "Modify_security_group_changes.csv"

# Initialize boto3 clients
cloudtrail_client = boto3.client('cloudtrail', region_name=aws_region)

# Time range (last 24 hours)
end_time = datetime.utcnow()
start_time = end_time - timedelta(hours=24)

def get_sg_changes_from_cloudtrail(sg_id):
    """Fetch security group changes from CloudTrail."""
    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {"AttributeKey": "ResourceName", "AttributeValue": sg_id}
        ],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )
    changes = []
    for event in response.get("Events", []):
        details = json.loads(event["CloudTrailEvent"])
        request_params = details.get("requestParameters", {})
        if request_params:
            changes.append({
                "EventTime": event.get("EventTime"),
                "EventName": event.get("EventName"),
                "RequestParameters": request_params,
                "UserIdentity": details.get("userIdentity", {}).get("arn", "N/A"),
                "SourceIPAddress": details.get("sourceIPAddress", "N/A"),
            })
    return changes

def analyze_changes(changes):
    """Analyze changes and extract before and after states."""
    analyzed_changes = []
    for change in changes:
        event_name = change["EventName"]
        params = change["RequestParameters"]
        
        if event_name in ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]:
            for permission in params.get("ipPermissions", []):
                for ip_range in permission.get("ipRanges", []):
                    cidr = ip_range.get("cidrIp", "N/A")
                    port = permission.get("fromPort", "N/A")
                    protocol = permission.get("ipProtocol", "N/A")
                    if event_name == "AuthorizeSecurityGroupIngress":
                        analyzed_changes.append({
                            "EventTime": change["EventTime"],
                            "EventName": event_name,
                            "User": change["UserIdentity"],
                            "CIDR": cidr,
                            "Port": port,
                            "Protocol": protocol,
                            "ChangeType": "Added",
                            "BeforeState": None,
                            "AfterState": {"Port": port, "Protocol": protocol, "CIDR": cidr}
                        })
                    elif event_name == "RevokeSecurityGroupIngress":
                        analyzed_changes.append({
                            "EventTime": change["EventTime"],
                            "EventName": event_name,
                            "User": change["UserIdentity"],
                            "CIDR": cidr,
                            "Port": port,
                            "Protocol": protocol,
                            "ChangeType": "Removed",
                            "BeforeState": {"Port": port, "Protocol": protocol, "CIDR": cidr},
                            "AfterState": None
                        })
    return analyzed_changes

def write_to_csv(events):
    """Write events to a CSV file."""
    with open(output_csv, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        # Write the header
        csv_writer.writerow([
            "Event Time", "Event Name", "User", "CIDR", "Port", "Protocol",
            "Change Type", "Before State", "After State"
        ])

        for event in events:
            csv_writer.writerow([
                event["EventTime"], event["EventName"], event["User"],
                event["CIDR"], event["Port"], event["Protocol"],
                event["ChangeType"], json.dumps(event["BeforeState"]),
                json.dumps(event["AfterState"])
            ])

if __name__ == "__main__":
    all_changes = []
    for sg_id in parent_sg_ids:
        print(f"Fetching changes from CloudTrail for Security Group: {sg_id}...")
        changes = get_sg_changes_from_cloudtrail(sg_id)
        if changes:
            print(f"Analyzing changes for Security Group: {sg_id}...")
            analyzed_changes = analyze_changes(changes)
            print("analyis logs")
            print(analyze_changes)
            all_changes.extend(analyzed_changes)

    if all_changes:
        print(f"Generating CSV report...")
        write_to_csv(all_changes)
        print(f"CSV report generated: {output_csv}")
    else:
        print("No changes detected for the provided Security Groups.")
