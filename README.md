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
<details>
1. [About The Project](#about-the-project)
2. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
3. [Usage](#usage)
4. [Roadmap](#roadmap)
5. [Contributing](#contributing)
6. [License](#license)
7. [Contact](#contact)
8. [Acknowledgments](#acknowledgments)
</details>


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

### Get a Tenant ID from a domain
The testing flow generally begins by enumerating the Tenant ID from their domain name, this can be done in Entruder through:
```bash
entruder get tenant -d <DOMAIN_NAME>
```
<img width="1034" height="287" alt="image" src="https://github.com/user-attachments/assets/e3a4451c-d7fe-43b1-a82a-06f9e50cf972" />

### Discovering valid users via a wordlist
After getting the tenant we can use the brute module with a predefined wordlist to discover valid users
```bash
entruder brute users -d <DOMAIN_NAME> -l <PATH_TO_WORDLIST>
```
<img width="804" height="199" alt="image" src="https://github.com/user-attachments/assets/ade197d4-f735-495c-8f8f-5a44ed0dcdcf" />

### Password Spraying
After discovering valid users we can spray a password list across them using brute pwspray
```bash
entruder brute pwspray -u <USER_LIST> --passwords <PASSWORD_LIST> -t <TENANT_ID> -c <CLIENT_ID>
```
In the below example we can see that a valid password is discovered, with Entruder warning us that the user must be enrolled in MFA upon a successful login.
<img width="1288" height="213" alt="image" src="https://github.com/user-attachments/assets/70fa0c2a-1563-485f-a384-08091d04e3b4" />

A successful login against an account without MFA enrolled means we can register our own authenticator app as the MFA method, giving us persistent authenticated access to the account.

### Device Login



[python-shield]: https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge
[contributors-shield]: https://img.shields.io/github/contributors/github_username/repo_name.svg?style=for-the-badge
[contributors-url]: https://github.com/github_username/repo_name/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/github_username/repo_name.svg?style=for-the-badge
[forks-url]: https://github.com/github_username/repo_name/network/members
[stars-shield]: https://img.shields.io/github/stars/github_username/repo_name.svg?style=for-the-badge
[stars-url]: https://github.com/github_username/repo_name/stargazers
[issues-shield]: https://img.shields.io/github/issues/github_username/repo_name.svg?style=for-the-badge
[issues-url]: https://github.com/github_username/repo_name/issues
[license-shield]: https://img.shields.io/github/license/github_username/repo_name.svg?style=for-the-badge
[license-url]: https://github.com/github_username/repo_name/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
