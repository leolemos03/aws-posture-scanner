import json 
import os
from datetime import datetime
from audits.s3_audit import audit_s3
from audits.iam_audit import audit_iam
from audits.ec2_audit import audit_ec2


def main():

    print("=" * 50)
    print("       AWS POSTURE SCANNER - AUDIT REPORT        ")
    print("=" * 50)    

    all_findings = []

    print("\n[*] Auditing AWS S3...")
    s3_findings = audit_s3()
    all_findings.extend(s3_findings)

    print("\n[*] Auditing AWS IAM...")
    iam_findings = audit_iam()
    all_findings.extend(iam_findings)

    print("\n[*] Auditing AWS EC2 Security Groups...")
    ec2_findings = audit_ec2()
    all_findings.extend(ec2_findings)
    
    for finding in all_findings:
        resource = finding['resource']
        status = finding['status']
        details = finding['details']

        print(f"[{status}] {resource} - {details}")

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"reports/scan_{timestamp}.json"

    with open(filepath, "w") as file:
        json.dump(all_findings, file, indent=4)

    print(f"\n[+] Report saved to {filepath}")



if __name__ == "__main__":
    main()

