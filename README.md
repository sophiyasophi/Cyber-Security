Cyber security: Securing data,devices etc.,
Networks: Medium to communicate
Hacking: Gaining unaunthorized access
Ethical hacking: Gaining unaunthorized access with written concern
Vulnerability: Weakness in an information system that could be exploited by a threat source
Cyber security tools:
    Hashcat: Password hacking tool
    Bruteforce technique
    Attacks
    RAT(Remote Access Trojan)
    Metasploit
Implementing security:
     Physical control  
     Administrative control  
     Logical control
Port scanning
Protocol: Set of rules
TCP/UDP: 
    To connect the hardware and software
    Connects Top layer to Bottom layer
    TCP contains 65,535 ports
    UDP contains 65,535 ports
    Totally 1,30,070 ports
    The ports are entry gates of a system
    443-https(safe) and 80-http(unsafe)
Differnce between HTTPS and HTTP
Block chain
Exploit: 
      A particular attack
      Exploits system vulnerabilities
SQL injection
Session hijacking
Phishing
DNS
IP address
Cloud
Cryptography
Spoofing
Hashing
Specific hacking
Web application penetration testing
    Web page:
    Web application: User interaction
    Web site: Collection of webpages
    Web server:
Career opportunities: 
    Offensive- red team
    Defensive (SOC analyst)- blue team
    Both-purple team
Types of hackers:
    White hat- Software architecture is completely known(architecture-blueprint of entire software application)
    Black hat- Hackers(without any information or knowledge)
    Grey hat- Both white and black hat(dangerous)
    Script kiddies- Using tools without knowledge
    Hacktivism- Hacking for social causes
    Blue hat- 
    Red hat-
    State sponsored hackers(govt)- Government pays and make them to hack other state information
CIA(Network Security):
    Confidentiality
    Integrity
    Availability
Confidentiality:
Authentication: Verifying one's identity
To verify one's authentication:
    Knowledge(Something known) Eg:DOB,Secret questions etc.,
    Physical(Something you have) Eg:Aadhar,Passport,Phone number etc.,
    Biometrics(behavioural patterns) Eg:Fingerprints,Physical appearances etc.,
Authorisation(Access control): Permission to access
UAC: User Access Control
Integrity: Originality
    Safe data transfer-https
    SSL: Secured Software Layer
    Encryption: Conversion of clear texts to cipher texts
Availability: 
    Eg: ATM availability(demonitization)
    Firewall
    Antivirus
Breach: Loss of control,a person other than an authorised user accesses identifiable information   
Event: Observable occurance in a network or system
Incident: Actually or potentially jeopardizes(affects) the CIA of an information system
Intrusion: 
    A security event
Threat: 
    Event with potential to adversely impact organisational operations
    High occurance of threat is classfied as high risk
    Vulnerability + Threat = Risk
Zero day: A previously unknown system vulnerability with potential of exploitation without risk of detection
TOE: Target Of Evaluation
IPV4-32 bits 0-9 
IPV6-128 bits 0-9,A,B,C,D,E,F
Commands: powershell,ipconfig
Http: port 80
CIDR: Classless Inter Domain Routing 
Notepad: To hang someone's system
@echo off
start mspaint
start cmd
Save in desktop and open
Windows open multiple times and system will hang
If command given in command prompt doesn't work:
Environmental variable->System variable->Path->Edit->Select path->Add->New->Save path->Last/->Enter->Ok
Ping: A tool to test connectivity
Command: ping mkce.ac.in -n 10
Help command: ipconfig --help
Same types of devices: Cross over
Different types of devices: Staight through
For connecting 2 routers: Serial cables or coaxial
Router: Transmits packets from one route to another route
Half duplex: One side packet transmission
Full duplex: Double side packet transmission
NIC: Network Interface Card
MAC: Medium Access Control
IP address-dynamic
DHCP-Dynamic Host Configuration Protocol-default IP address
LINUX FUNDAMENTALS:
windows-command prompt,powershell
ls for linux dir for windows-read file
linux commands can be run in powershell
cd .. backward
cd directory forward
where-used to know where a program is installed(command prompt not in powershell)
cd ../../../ - Fast navigation
Tab shows all the present directories
">>" adding contents(append) to files
more-to read file(cmd) 
cat-to read file(powershell)
File extension is important in windows
notepad .\filename-contents of file will be displayed in notepad
mkdir works in windows and in linux
d-directory
a-attribute file
mv-move works in linux also
../ navigates backward directory
cp-copy
File sharing
python -m http.server 80(default port 80)
python -m http.server 9999
other port should be given for running
echo "Hello World!" > index.html
website monitoring- SOC analyst(Security Operations Center)
rm- remove(powershell) 
dl- delete(command prompt)
OSI layers:
1.Physical-USB,Bluetooth
2.Datalink-ATM,SLIP,Frame relay,PPP
3.Network-IPV4,IPV6,ICMP,IGP,IPSec
4.Transport-TCp,UDP
5.Session-PPTP,SIP,SAP,NetBIOS
6.Presentation-SSL,TLS
7.Application-HTTP,FTP,SMTP
Wireshark
Proxy- Middleman between client and server
VPN- encrypt connection between server and client
RSA AES- Cipher text
Symmetric Encryption- Single key
Asymmetric Encryption- Public/Private key
ip.addr==163.70.138.35(facebook.com)
Three way handshake:
SYN
SYN-ACK
ACK
TLS handshake(Transport Layer Security)
Request (client)-----> Response(server)----> DB
HTTP Methods: GET,POST,PUT,OPTIONS,DELETE
Testing can be done in:
Production environment- Live websites/web app- Risky testing
Staging environment- Actual copy of productipon environment
QA environment- Test build
SDLC: Software Development Life Cycle
Response code:
1xx- Informational messages(changing protocols)
2xx- OK(success)
3xx- Redirection
4xx- Client-side error(404 not found)
5xx- Server-side error(maintanance,server down)
Client--->Burp Proxy---->Server
Tor: darkweb
Client--->Proxy1---->Proxy2---->Proxy3---->Proxy4---->Proxy5---->Proxy6---->Server-unsafe-different geographical locations-payment in bitcoins
1Bitcoin=$67000
Brup suite:
User agent- browser
ISO: International Organisation of Standardisation
cat /etc/apt/sources.list
nano /etc/apt/sources.list (right click-copy)
sudo nano /etc/apt/sources.list
ctrl+shift+c-copy
ctrl+shift+v-paste
https://http.kali.org/kali
^-ctrl
ctrl+O
ctrl+X
q- Quit
http://www.example.com/index.html
http://www.example.com/directory1/directory2/filename.html
Web protocol- http/https
Domain- Example.com

sudo service apache2 start
ls/var/ww/html
ls -l /var/ww/html
pwd
http://127.0.0.1/files/index.html
http://var/www/html/files/index.html
Linux basic path- /var/www/html
windows- C:\inetpub\wwwroot
HTTP/2- HTTPS
HTTP/1.0,1.1,1.2- HTTP
GET /v1/tiles HTTP/2
Host: contile.services.mozilla.com
https://contile.services.mozilla.com/v1/tiles
Username Enumeration
grep- search and extract
WAF:  Web applicaiom firewall
WAF + rate limiting
Vulnerability Assessment(VA): 
     Process of identifying,quantifying and prioritizing vulnerabilities within a system,network,application or organization
     Systematic review of potential weakness that could be exploited by attackers ti compromise CIA of assets
VA Process:
     Asset discovery
     Vulnerability scanning
     Vulnerability assessment
     Vulnerability remediation






































 













