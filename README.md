# UR Cybersecurity Red Team / Blue Team Capstone Project 2
Assessment, Analysis, and Hardening of a vulnerable system. This presentation includes playing the role of both (Red Team) pentester and (Blue Team) SOC analyst on a vulnerable WebDAV server.

  - As the Red Team, I attacked a vulnerable virtual webserver and gained root access, exposing several critical weaknesses along the way. 
  - As the Blue Team, I used Kibana to review and analyze logs taken during the Red Team attack. 
    - Logs were used to extract hard data and visualizations for the report 
    - Log data was then used to suggest mitigation measures for each exploit

Here is the [PowerPoint Presentation](https://github.com/cltempleton1127/UR-Cybersecurity-Red-Team-Blue-Team/blob/4ddb170e9f82d3a24ca27d020900d09c8868aca6/Red%20Team_Blue%20Team_Presentation%20.pdf) that lays out the process and achievements of the project.

# Network Topology

The following machines live on the network:

| **Name**     | **IP Address** |
|----------|------------|
| Kali    |  192.168.1.90  |
| Target    | 192.168.1.105   |
|ELK | 192.168.1.100   |
|Azure Hyper-V ML-RefVm-684427 | 192.168.1.1   |

![Network Diagram](https://github.com/cltempleton1127/UR-Cybersecurity-Red-Team-Blue-Team/blob/main/Project%202%20Network%20Topology.jpg)

# **Red Team**

While the web server suffers from several vulnerabilities, the three below are the most critical:

| | **Vulnerability**     | **Description** | **Impact** |
|-|----------|------------|------------|
| 1 | **Sensitive Data Exposure** **OWASP Top 10 #3 Critical** | The secret_folder is publicly accessible, but contains sensitive data intended only for authorized personnel. |The exposure compromises credentials that attackers can use to break into the web server.  |
| 2 | **Unauthorized File Upload Critical**  | Users are allowed to upload arbitrary files to the web server.   | This vulnerability allows attackers to upload PHP scripts to the server.  |
| 3 |**Remote Code Execution via Command Injection** **OWASP Top 10 #1 Critical** | Attackers can use PHP scripts to execute arbitrary shell commands. | Vulnerability allows attackers to open a reverse shell to the server.|

Additional vulnerabilities include:

| **Vulnerability**     | **Description** | **Impact** |
|----------|------------|------------|
|**Directory Indexing Vulnerability** **[CWE-548](https://cwe.mitre.org/data/definitions/548.html "CWE-548")** |  Attacker can view and download content of a directory located on a vulnerable device. CWE-548 refers to an informational leak through directory listing.  | The attacker can gain access to source code, or devise other exploits. The directory listing can compromise private or confidential data.  |
| **Hashed Passwords**  | If a password is not salted it can be cracked via online tools such as www.crackstation.net/ or programs such as hashcat.  | Once the password is cracked, and if a username is already known, a hacker can access system files.  |
|**Weak Usernames and Passwords** | Commonly used passwords such as simple words, and the lack of password complexity, such as the inclusion of symbols, numbers and capitals.  | System access could be discovered by social engineering. https://thycotic.com/resources/password-strength-checker/ suggests that ‘Leopoldo’ could be cracked in 21 seconds by a computer. |
|**Port 80 Open with Public Access** **[CVE-2019-6579](https://nvd.nist.gov/vuln/detail/CVE-2019-6579 "CVE-2019-6579")** | Open and unsecured access to anyone attempting entry using Port 80.  | Files and Folders are readily accessible. Sensitive (and secret) files and folders can be found. |
|**Brute Force** - **Ability to discover passwords by Brute Force** **[CVE-2019-3746](https://nvd.nist.gov/vuln/detail/CVE-2019-3746 "CVE-2019-3746")** |  When an attacker uses numerous username and password combinations to access a device and/or system. | Easy system access by use of brute force with common password lists such as rockyou.txt by programs such as Hydra  |
|**HTTP and WebDAV: Plaintext Protocols** | Without the use of secure protocols information of all kinds is unsecured and vulnerable to interception |Using plain text protocols like HTTP and WebDAV presents opportunities for sensitive data exposure, traffic redirection, malware installation, corruption of critical information, and installation of client-side code|

## Exploits

  - **Explotation: Sensitive Data Exposure**
    - Tools & Processes
      - `nmap` to [scan network](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_Kali_Nmap_scan.png)
      - `dirb` to map URLs
      - Browser to explore

    - **Achievements**
      - The exploit revealed a `secret_folder` directory
      - This directory is [password protected](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/2021-11-13%2017_06_23-Day1_Secret_Folder_revealed.png), but susceptible to **brute-force**

    - **Exploitation**
      - The login prompt reveals that the user is `ashton` 
      - This information is used to run a [brute force attack](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_Rockyou_ashton_password_find.png) and [steal senstive data](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_Secret_Folder_Login_Corp_server_message_ashton_password%20-%20Copy.png).

  - **Explotation: Sensitive Data Exposure**
    - **Tools & Processes**
      - [Crack stolen credentials](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_CrackStation_hashed_pwd_linux4u.png)
      - Generate custom web shell with [msfconsole](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_metasploit%20exploit%20setup.png)
      - [Upload shell](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_reverse_shell_webdav.png) via WebDAV 

    - **Achievements**
      - [Uploading a shell](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/shell_uploaded.png) allows us to execute arbitrary shell commands on the target

    - **Aftermath**
      - Running arbitrary shell commands allows Meterpreter to open a [full-fledged connection](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Day1_downloaded_Flag1.png) to the target.

# **Blue Team**

A considerable amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:

  - Traffic from attack VM to target, including unusually high volume of requests
  - Access to sensitive data in the secret_folder directory
  - Brute-force attack against the HTTP server
  - POST request corresponding to upload of shell.php

**Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target.
Time: 11/06/2021  12:00-18:00 PM

**The top hosts creating traffic at this time are the attacking IP of 192.168.1.90 and the target at 192.168.1.105:**

![alt text](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/TopHostsCreatingTrafficNov6.png)

In addition, note the connection spike in the HTTP Requests around 2:50pm [Packetbeat Flows] ECS, as well as the spike in errors, then a sudden switch to "OK" or succesful transaction status around the time of the spike also [Packetbeat] ECS

![alt text](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/HTTP%20Transacctions.png)

![alt text](https://github.com/cltempleton1127/Red-Team_Blue-Team-Project2/blob/master/Supplemental%20Resources/Error_Success_transactions.png)

**Access to Sensitive Data in secret_folder**: On the dashboard you built, a look at your Top 10 HTTP requests [Packetbeat] ECS panel. In this example, this folder was requested 14,430 times.

![alt text](https://)

**HTTP Brute Force Attack**: Searching for url.path: /company_folders/secret_folder/ shows conversations involving the sensitive data. Specifically, the results contain requests from the brute-forcing tool Hydra, identified under the user_agent.original section:

![alt text](https://)

In addition, the logs contain evidence of a large number of requests for the sensitive data, of which only 6 were successful. This is a telltale signature of a brute-force attack. 

  - 14,340 HTTP requests to http://192.168.1.105/company_folders/secrets_folder
  - 6 successful attempts
  - 11/06/2021  12:00-18:00 PM
  - Source IP: 192.168.1.105

![alt text](https://)

WebDAV Connection & Upload of shell.php: The logs also indicate that an unauthorized actor was able to access protected data in the webdav directory. The passwd.dav file was requested via GET, and shell.php uploaded via POST.

## Mitigation steps for each vulnerability above are provided below.

  * Blocking the Port Scan

    * The local firewall can be used to throttle incoming connections
    * Firewall should be regularly patched to minimise new attacks
    * ICMP traffic can be filtered
    * An IP allowed list can be enabled
    * Regularly run port scans to detect and audit any open ports

  * High Volume of Traffic from Single Endpoint

    * Rate-limiting traffic from a specific IP address would reduce the web server's susceptibility to DoS conditions, as well as provide a hook against which to trigger alerts against suspiciously suspiciously fast series of requests that may be indicative of scanning.

  * Access to sensitive data in the secret_folder directory

    * The secret_folder directory should be protected with stronger authentication. 
    * Data inside of secret_folder should be encrypted at rest.
    * Filebeat should be configured to monitor access to the secret_folder directory and its contents.
    * Access to secret_folder should be whitelisted, and access from IPs not on this whitelist, logged.

  * Brute-force attack against the HTTP server

    * The [fail2ban utility](https://www.fail2ban.org/wiki/index.php/Main_Page) can be enabled to protect against brute force attacks.
    * Create a policy that locks out accounts after 10 failed attempts
    * Create a policy that increases password complexity (requirements)
    * Enable MFA

  * POST request corresponding to upload of **shell.php**

    * File uploads should require authentication.
    * In addition, the server should implement an upload filter and forbid users from uploading files that may contain executable code.

## Assessment Summary

| **Red Team**     | **Blue Team** |
|----------|------------|
| Accessed the system via HTTP Port 80 **CVE-2019-6579**   |  Confirmed that a port scan occurred  |
| Found Root accessibility  | Found requests for a hidden directory   |
|Found the occurrence of simplistic usernames and weak passwords | Found evidence of a brute force attack |
|Brute forced passwords to gain system access **CVE-2019-3746** | Found requests to access critical system folders and files |
|Cracked a hashed password to gain system access and use a reverse shell script | Identified a WebDAV vulnerability |
|Identified Directory Indexing Vulnerability **CWE-548**| Recommended alarms   |
|   |  Recommended mitigation measures and system hardening |


## Group
- [Courtney Templeton](https://github.com/cltempleton1127)
- [Josh Black](https://github.com/joshblack07)
- [Laura Pratt](https://github.com/laurapratt87)
- [Robbie Drescher](https://github.com/RobDresch)
- Julian Baker
