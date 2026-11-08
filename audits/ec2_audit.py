import boto3
from botocore.exceptions import ClientError

def audit_ec2():
    ec2 = boto3.client('ec2')
    findings = []

    try:
        response = ec2.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])

        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            has_critical_issue = False
            
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
        
                is_risky_port = False
                if from_port is not None and to_port is not None:
                    if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                        is_risky_port = True

                if is_risky_port:
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        if cidr == '0.0.0.0/0':
                            has_critical_issue = True
                            port_str = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                            findings.append({
                                "resource": f"SecurityGroup: {group_id} ({group_name})",
                                "status": "CRITICAL",
                                "details": f"Port {port_str} is open to the entire internet (0.0.0.0/0)."
                            })

            if not has_critical_issue:
                findings.append({
                    "resource": f"SecurityGroup: {group_id} ({group_name})",
                    "status": "COMPLIANT",
                    "details": "No critical management ports (22, 3389) open to 0.0.0.0/0."
                })
            


    except ClientError as error: 
        findings.append(
            {
                "resource": "EC2", 
                "status": "ERROR", 
                "details": f"Failed to describe security groups: {str(error)}"
            }
        )
        return findings
    
    

    return findings