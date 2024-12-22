import boto3
import datetime
import time
import csv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
import os
from email import encoders

# Initialize AWS clients
ec2_client = boto3.client('ec2')
logs_client = boto3.client('logs')
SECURITY_GROUP_ID = "sg-0f88628462b1ae545"

def get_instance_id_by_private_ip(private_ip):
    """
    Fetch the instance ID associated with the specified private IP.
    """
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'private-ip-address',
                    'Values': [private_ip]
                }
            ]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                return instance['InstanceId']
        return None
    except Exception as e:
        print(f"Error fetching instance ID: {e}")
        return None

def query_logs_old(log_group_name, private_ip):
    """
    Query logs in a specified log group with a given private IP address.
    """
    try:
        query = f"""
        fields @timestamp, @message, @LogStream, @Log
        | filter srcAddr = '{private_ip}' and action = 'REJECT' and protocol != -1
        | sort @timestamp desc
        | stats count(*) by @timestamp, srcAddr, srcPort, dstAddr, dstPort, protocol
        """
        
        # Start query
        start_query_response = logs_client.start_query(
            logGroupName=log_group_name,
            startTime=int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp()),
            endTime=int(datetime.datetime.now().timestamp()),
            queryString=query,
            limit=100
        )
        
        query_id = start_query_response['queryId']
        print(f"Query started with ID: {query_id}")
        
        # Wait for the query results
        while True:
            response = logs_client.get_query_results(queryId=query_id)
            if response['status'] == 'Complete':
                #print("Result")
                #print(response['results'])
                return response['results']
            print("Waiting for query to complete...")
            time.sleep(1)
    
    except Exception as e:
        print(f"Error querying logs: {e}")
        return []
    
def query_logs(log_group_name, private_ips):
    """
    Query logs in a specified log group for multiple private IP addresses.
    """
    try:
        # Build the filter condition for multiple private IPs
        ip_filter = " or ".join([f"srcAddr = '{ip}'" for ip in private_ips])
        
        # Define the CloudWatch Insights Query
        query = f"""
        fields @timestamp, @message, @LogStream, @Log
        | filter ({ip_filter}) and action = 'REJECT' and protocol != -1
        | sort @timestamp desc
        | stats count(*) by @timestamp, srcAddr, srcPort, dstAddr, dstPort, protocol
        """
        
        # Start the query
        start_query_response = logs_client.start_query(
            logGroupName=log_group_name,
            startTime=int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp()),
            endTime=int(datetime.datetime.now().timestamp()),
            queryString=query,
            limit=100
        )
        #print("my query")
        #print(query)
        query_id = start_query_response['queryId']
        print(f"Query started with ID: {query_id}")
        print ("query value")
        print(query)
        # Wait for the query results
        while True:
            response = logs_client.get_query_results(queryId=query_id)
            if response['status'] == 'Complete':
                print("Query complete")
                return response['results']
            elif response['status'] in ['Cancelled', 'Failed']:
                print(f"Query {response['status']}")
                return []
            print("Waiting for query to complete...")
            time.sleep(1)
    
    except Exception as e:
        print(f"Error querying logs: {e}")
        return []    
def fetch_instance_private_ips(security_group_id):
    try:
        instances = ec2_client.describe_instances(
            Filters=[
                {'Name': 'instance.group-id', 'Values': [security_group_id]}
            ]
        )
        private_ips = [instance['PrivateIpAddress'] for reservation in instances['Reservations'] for instance in reservation['Instances']]
        instance_ids = [instance['InstanceId'] for reservation in instances['Reservations'] for instance in reservation['Instances']]
        return private_ips, instance_ids
    except Exception as e:
        print(f"Error fetching instance private IPs: {e}")
        return [], []    

def write_logs_to_csv(logs, filename):
    try:
        if not logs:
            print("No logs to write.")
            return

        with open(filename, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)

            # Write headers from the first log result
            header = [field['field'] for field in logs[0]]
            csv_writer.writerow(header)

            # Write rows
            for log in logs:
                row = [field.get('value', '') for field in log]
                csv_writer.writerow(row)

        print(f"Logs written to {filename}")
    except Exception as e:
        print(f"Error writing logs to CSV: {e}")

def send_email_with_attachment():
    try:
        smtp_server = "smtp.gmail.com"
        port = 587
        sender_email = "awscloudtrainers@gmail.com"
        sender_password = "xxxx"  # Use an App Password if 2FA is enabled
        recipient_email = "jaganrajagopalme@gmail.com"
        subject = "CSV File Attachment"
        body = "Please find the attached CSV file."
        attachment_path = "vpc_flow_results.csv"
        # Create the email object
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject

        # Attach the email body
        msg.attach(MIMEText(body, 'plain'))

        # Attach the file
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}'
            )
            msg.attach(part)
        else:
            print("Attachment not found or path is invalid.")

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)

        print("Email sent successfully!")

    except Exception as e:
        print(f"Failed to send email: {e}")        
def main():
    # Input parameters
    #private_ip = "10.200.132.88"
    log_group_name = "flgg-traditional-devtest"  # Replace with your log group name
    private_ips, instance_ids = fetch_instance_private_ips(SECURITY_GROUP_ID)
    # Fetch instance ID using the private IP
    #print ("value for private ips")
    #print(private_ips)
    # instance_id = get_instance_id_by_private_ip(private_ips)
    # if not instance_id:
    #     print(f"No instance found for private IP: {private_ips}")
    #     return

    # print(f"Instance ID for private IP {private_ips}: {instance_id}")

    # Query logs for the given private IP in the log group
    logs = query_logs(log_group_name, private_ips)

    if logs:
        print("Query Results:")
        csv_file = "vpc_flow_results.csv"
        write_logs_to_csv(logs, csv_file)
        for log in logs:
            print(log)
            #sending mail 
            print("preparing for sending mail...")
            send_email_with_attachment()
    else:
        print(f"No logs found for private IP {private_ips} in log group {log_group_name}.")

if __name__ == "__main__":
    main()
