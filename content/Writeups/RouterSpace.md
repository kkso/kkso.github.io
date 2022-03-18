---
title: "RouterSpace - Easy"
date: 2022-03-06
---
### Tools Used
- Nmap
- Virtualised Android Machine
-  Burp Suite
-  linpeas
-  CVE-2021-3156 Proof of Concept script
# User
### Enumeration 
```
Nmap scan report for 10.10.11.148
Host is up (0.063s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
80/tcp open  http
|_http-title: RouterSpace
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-9802
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 65
|     ETag: W/"41-HxO0Q/PimO73JhQv5GJkuRap/30"
|     Date: Sun, 06 Mar 2022 05:33:50 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: USS C U m 72 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-38102
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Sun, 06 Mar 2022 05:33:49 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-45749
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Sun, 06 Mar 2022 05:33:49 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-favicon: Unknown favicon MD5: 63884385E642E4AAD06B21EBE2E2EE6C
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%)
 ```
 The initial Nmap scans shows 2 active services:
- 1 SSH service open on port 22
- 1 HTTP service open on port 80 
 
 Viewing the website shows the RouterSpace landing page, with the only option to download an apk. All other links lead to a page stating "Suspicious Activity" followed by a random code.
 ![image](/img/RouterSpace/image1.png)
 
## Foothold

Downloading the apk and running the app results in landing page with 1 button to check the status. ![image](/img/RouterSpace/image2.png)
 
Proxiying the traffic from android device to Burp Suite reveals a post request sent when interacting with the app.
 
 ```
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 16
Host: routerspace.htb
Connection: close
Accept-Encoding: gzip, deflate

{"ip":"0.0.0.0"}
```
With a response of:
```
HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-6909
Content-Type: application/json; charset=utf-8
Content-Length: 11
ETag: W/"b-ANdgA/PInoUrpfEatjy5cxfJOCY"
Date: Mon, 07 Mar 2022 06:46:35 GMT
Connection: close

"0.0.0.0\n"
```
Entering `{"ip":"~"}` in place of the ip however results in a return of "home/user/paul" which means that bash is being used to access which is returned as json. With this knowledge entering `{"ip":"0.0.0.0 | whoami "}` results in paul instead of just "whoami" being returned. This shows that commands are being executed by the machine therefore we can commit Remote Code Execution. By making a file in  /user/paul/.ssh/authorized_keys and appending our public ssh key, we can then ssh into the machine as user.

# Privilege  Escalation
Running linpeas.sh results in showing its sudo version is 1.8.31 which can be verified by typing `sudoedit -s Y`. The version can be verified as only 1.8.31 will result in system asking for a password. By using a [CVE-2021-3156 Proof of Concept](https://github.com/CptGibbon/CVE-2021-3156) the user can be escalated to root. 
