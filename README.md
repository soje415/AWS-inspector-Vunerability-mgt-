# AWS-inspector-Vunerability-mgt-
CVSS


## Objective:

This project demonstrates the detection and remediation of vulnerabilities in AWS Lambda functions using AWS Inspector. By deliberately deploying insecure Lambda code, we will simulate real-world vulnerabilities and assess them using the NIST Common Vulnerability Scoring System (CVSS) framework. The project also outlines the remediation process for each identified vulnerability.

Create to lambda function and ingest the vunerable code below and tools and service used:

##Tools & Services:

AWS Lambda
AWS Inspector
NIST CVSS Framework
Amazon S3 (for logging)
Boto3 (AWS SDK for Python)

## Vulnerable Lambda Code
A Lambda function is created with common security flaws such as improper input validation, hardcoded credentials. These vulnerabilities are injected into the code to test AWS Inspector's ability to detect them.


1. Command Inject from the OS level

   ![cmd ijn os](https://github.com/user-attachments/assets/8916e428-2887-42d2-95e1-d514c3c5e639)

2. Handcoded AWS Credentials

 ![aws credentila ](https://github.com/user-attachments/assets/4a2b0bb6-1a13-4250-bcf0-69036cdd4385)

 ## AWS Inspector Configuration

 
# Setting Up Amazon Inspector


Enable AWS Inspector: Go to the Amazon Inspector service in the AWS Console and enable it for Lambda.
Configure the Lambda Assessment: Target the deployed Lambda function by setting up continuous vulnerability scanning with Amazon Inspector. AWS Inspector will analyze the code and dependencies of the Lambda function and report vulnerabilities.

Below are the findings from AWS Inspector

![critical findings](https://github.com/user-attachments/assets/23a6069e-401b-43f1-b063-f0b0224f9769)

![findings2](https://github.com/user-attachments/assets/e1d555ce-29f3-421c-b536-3defdff45924)



CWE-798 - Hardcoded credentials

![CWV severity](https://github.com/user-attachments/assets/0b850875-d4bf-4339-a7c8-5c783d9a58c0)


Command Injection Findings


![cmd injection](https://github.com/user-attachments/assets/f23ee942-a6cd-4bc5-be87-66e237ceba1a)


CWE-77,78,88 - OS command injection

![CMD W ](https://github.com/user-attachments/assets/b7017cc7-1b59-46f9-b739-a9f248e58b7e)


![AWS FINDINGS ](https://github.com/user-attachments/assets/d01f751a-db20-443b-926e-49c10adc955a)


## Remediation of Vulnerabilities


1. Hardcoded Credentials
   
Issue: Hardcoding sensitive credentials in the code is a severe risk as attackers can gain access to AWS resources.
Remediation: Replace hardcoded credentials with AWS IAM Roles and use AWS Secrets Manager for securely storing secrets.

2. Command Injection
Issue: Using os.system without input sanitization can allow command injection attacks.
Remediation: Use safe functions, validate inputs thoroughly, and avoid running shell commands unless necessary.
