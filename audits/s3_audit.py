import boto3
from botocore.exceptions import ClientError

def audit_s3():
    s3 = boto3.client('s3')
    findings = []

    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        for bucket in buckets:

            bucket_name = bucket['Name']

            try:
                pab_response = s3.get_public_access_block( Bucket = bucket_name )
                pab_config = pab_response.get('PublicAccessBlockConfiguration', {})

                is_secure = (
                    pab_config.get("BlockPublicAcls")
                    and pab_config.get("IgnorePublicAcls")
                    and pab_config.get("BlockPublicPolicy")
                    and pab_config.get("RestrictPublicBuckets")
                )

                if is_secure:
                    findings.append(
                        {
                            "resource": bucket_name,
                            "status": "COMPLIANT",
                            "details": "All 4 Public Access Block settings are enabled.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "resource": bucket_name,
                            "status": "WARNING",
                            "details": "One or more Public Access Block settings are disabled.",
                        }
                    )
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchPublicAccessBlockConfiguration': 
                    findings.append(
                       {
                            "resource": bucket_name,
                            "status": "CRITICAL",
                            "details": "No Public Access Block configuration found (bucket may be completely public).",
                       }
                    )
                    
                else:
                    findings.append(
                        {
                            "resource": bucket_name, 
                            "status": "ERROR", 
                            "details": f"Failed to check bucket: {error_code}"
                        }
                    )
    except ClientError as e:
        findings.append(
            {
                "resource": "S3 Service",
                "status": "ERROR", 
                "details": f"Failed to list buckets: {e.response['Error']['Code']}"
            }
        )

    return findings





