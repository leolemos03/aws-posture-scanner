import boto3
from botocore.exceptions import ClientError

def audit_iam():

    findings = []
    iam = boto3.client('iam')
    try:
        response = iam.list_users()
        users = response.get('Users', [])

        for user in users:
            username = user['UserName']
            mfa = iam.list_mfa_devices( UserName = username )
            active_mfa = mfa.get('MFADevices', [])
            if not active_mfa:
                findings.append(
                    {
                        "resource": username,
                        "status": "WARNING",
                        "details": "User does not have MFA enabled.",
                    }
                )
            else:
                findings.append(
                    {
                        "resource": username, 
                        "status": "COMPLIANT",
                        "details": "MFA is enabled.",
                    }
                )

            access_keys = iam.list_access_keys(UserName=username)
            all_keys = access_keys.get('AccessKeyMetadata', [])

            active_keys = [k for k in all_keys if k['Status'] == 'Active']

            if active_keys:
                findings.append(
                        {
                        "resource": username,
                        "status": "INFO",
                        "details": f"User has {len(active_keys)} active access key(s)."
                        }
                    )
            




    except ClientError as error:
        findings.append(
            {
                "resource": "IAM", 
                "status": "ERROR", 
                "details": f"Failed to list IAM users: {str(error)}"
            }
        )
        return findings


    return findings


