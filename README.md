# powersack

![Fan Art!](https://github.com/s1xtw03/powersack/raw/master/fan_art/fan_art2.jpg)

This script attempts to "ransack" files on SMB shares for strings of text. It takes a list of hosts, a list of credentials to try authenticating with, and a list of strings to search for. All testing was performed on Powershell version 5, though you may have luck on earlier versions.

This technique has a very high rate of successful privilege escalation once a set of domain credentials are discovered. Organizations do not typically give much attention to how their staff set ACLs on network shares. As we so frequently gather many sets of credentials, this tool helps determine which have access to given shares.

Common discoveries include

* Production database backups
* IT / Systems scripts (powershell/batch)
* Code repositories or applications
* Service account passwords
* Virtual machine disk storage
* Bulk regulated data (medical, legal, HR)
* Private keys

**For a complete list of options and examples, check out its help page with `Get-Help .\PowerSack.ps1 -Full`**

![Introduction](https://gitlab.na.nccgroup.com/jmcg/powersack/raw/f4eb0dd4632964da96c621434e1976ba2ce9026d/fan_art/fan_art2.jpg)

On a large or unfamiliar network, it's usually best to start with an information-only scan, which will return a list of the shares on each host, along with the files present in the share root. It's also recommended to use the Verbose flag so you can keep an eye on overall progress, and redirect stdout to a file. 

Sample information gathering search:

~~~
PS p:\> .\PowerSack.ps1 -HostListFile C:\Users\jmcg\Desktop\dev-sharehosts.txt -CredentialListFile C:\Users\jmcg\Desktop\dev-sharecreds.txt -Verbose -InfoOnly
[06/17 21:31:44] Starting scan!

VERBOSE: [06/17 21:31:45] ************ Connecting to WIN-S35BCPQ74FS...
VERBOSE: Could not connect to port 445 on WIN-S35BCPQ74FS. Moving on.
VERBOSE: [06/17 21:31:46] ************ Connecting to 192.168.178.139...
VERBOSE: [06/17 21:31:46] Connecting as Administrator@192.168.178.139
VERBOSE: Could not map 192.168.178.139 as Administrator. Moving on.
VERBOSE: [06/17 21:32:07] Connecting as share1user@192.168.178.139
VERBOSE: [06/17 21:32:08] Found the following shares: ADMIN$, C$, HiddenShare$, Users
VERBOSE: [06/17 21:32:08] ****** Starting : ADMIN$
VERBOSE: [06/17 21:32:08] share1user does not have read access to ADMIN$
VERBOSE: [06/17 21:32:08] ****** Starting : C$
VERBOSE: [06/17 21:32:08] share1user does not have read access to C$
VERBOSE: [06/17 21:32:08] ****** Starting : HiddenShare$
VERBOSE: [06/17 21:32:08] Super! share1user does have read access to HiddenShare$
VERBOSE: [06/17 21:32:08] ****** Finished : HiddenShare$
VERBOSE: [06/17 21:32:08] ****** Starting : Users
VERBOSE: [06/17 21:32:08] Super! share1user does have read access to Users
VERBOSE: [06/17 21:32:08] ****** Finished : Users
VERBOSE: Done with share1user@192.168.178.139
VERBOSE: [06/17 21:32:11] Connecting as share2user@192.168.178.139
VERBOSE: Could not map 192.168.178.139 as share2user. Moving on.
[06/17 21:32:32] Share access info for 192.168.178.139 :

Share Name   Users With Access Top Level Directory Contents
----------   ----------------- ----------------------------
HiddenShare$ share1user        FINDME
                               My Music
                               My Pictures
                               My Videos
                               afweawef.txt
                               desktop.ini
                               New Text Document.txt

Users        share1user        Administrator
                               Default
                               desktop.ini

C$
ADMIN$
~~~


Simple search usage demo:

~~~
PS p:\> .\PowerSack.ps1 -HostListFile C:\Users\jmcg\Desktop\dev-sharehosts.txt -Verbose -CredentialListFile C:\Users\jmcg\Desktop\dev-sharecreds.txt -FileContentsKeywordListFile .\contentkeywords.txt -FileNameKeywordListFile .\filenamekeywords.txt
[06/17 21:13:33] Starting scan!
VERBOSE: [06/17 21:13:33] ************ Connecting to 192.168.178.128...
VERBOSE: Could not connect to port 445 on 192.168.178.128. Moving on.
VERBOSE: [06/17 21:13:34] ************ Connecting to 192.168.178.138...
VERBOSE: [06/17 21:13:34] Connecting as Administrator@192.168.178.138
VERBOSE: Could not map 192.168.178.138 as Administrator. Moving on.
VERBOSE: [06/17 21:13:55] Connecting as share1user@192.168.178.138
VERBOSE: Could not map 192.168.178.138 as share1user. Moving on.
VERBOSE: [06/17 21:14:16] Connecting as share2user@192.168.178.138
VERBOSE: [06/17 21:14:17] Found the following shares: ADMIN$, C$, Documents, Users
VERBOSE: [06/17 21:14:17] After share filtering, only scanning files in: Documents
VERBOSE: [06/17 21:14:17] ****** Starting : ADMIN$
VERBOSE: [06/17 21:14:17] share2user does not have read access to ADMIN$
VERBOSE: [06/17 21:14:17] ****** Starting : C$
VERBOSE: [06/17 21:14:17] share2user does not have read access to C$
VERBOSE: [06/17 21:14:17] ****** Starting : Documents
VERBOSE: [06/17 21:14:17] share2user does not have read access to Documents
VERBOSE: [06/17 21:14:17] ****** Starting : Users
VERBOSE: [06/17 21:14:17] Super! share2user does have read access to Users
VERBOSE: [06/17 21:14:17] Not scanning files in Users as due to filter
VERBOSE: Done with share2user@192.168.178.138
[06/17 21:14:20] Share access info for 192.168.178.138 :

Share Name Users With Access
---------- -----------------
Documents
Users      share2user

C$
ADMIN$

VERBOSE: [06/17 21:14:20] ************ Connecting to WIN-S35BCPQ74FS...
VERBOSE: Could not connect to port 445 on WIN-S35BCPQ74FS. Moving on.
VERBOSE: [06/17 21:14:21] ************ Connecting to 192.168.178.139...
VERBOSE: [06/17 21:14:21] Connecting as Administrator@192.168.178.139
VERBOSE: Could not map 192.168.178.139 as Administrator. Moving on.
VERBOSE: [06/17 21:14:43] Connecting as share1user@192.168.178.139
VERBOSE: [06/17 21:14:44] Found the following shares: ADMIN$, C$, HiddenShare$, Users
VERBOSE: [06/17 21:14:44] After share filtering, only scanning files in: HiddenShare$
VERBOSE: [06/17 21:14:44] ****** Starting : ADMIN$
VERBOSE: [06/17 21:14:44] share1user does not have read access to ADMIN$
VERBOSE: [06/17 21:14:44] ****** Starting : C$
VERBOSE: [06/17 21:14:44] share1user does not have read access to C$
VERBOSE: [06/17 21:14:44] ****** Starting : HiddenShare$
VERBOSE: [06/17 21:14:44] Super! share1user does have read access to HiddenShare$
VERBOSE: [06/17 21:14:44] Mapping directory: FINDME
Keyword match in filesystem path: \\192.168.178.139\HiddenShare$\FINDME\id_rsa.txt

VERBOSE: [06/17 21:14:44] Mapping directory: My Music
VERBOSE: [06/17 21:14:44] Mapping directory: My Pictures
VERBOSE: [06/17 21:14:44] Mapping directory: My Videos
VERBOSE: [06/17 21:14:44] Mapping directory: afweawef.txt
VERBOSE: [06/17 21:14:44] Mapping directory: desktop.ini
VERBOSE: [06/17 21:14:44] Mapping directory: New Text Document.txt
VERBOSE: [06/17 21:14:44] ****** Starting : Users
VERBOSE: [06/17 21:14:44] Super! share1user does have read access to Users
VERBOSE: [06/17 21:14:44] Not scanning files in Users as due to filter
VERBOSE: Done with share1user@192.168.178.139
VERBOSE: [06/17 21:14:47] Connecting as share2user@192.168.178.139
VERBOSE: Could not map 192.168.178.139 as share2user. Moving on.
\\192.168.178.139\HiddenShare$\FINDME\Secretfile.txt:1:Privatekey
\\192.168.178.139\HiddenShare$\New Text Document.txt:1:convertto-securestring
[06/17 21:15:08] Share access info for 192.168.178.139 :



Share Name   Users With Access
----------   -----------------
HiddenShare$ share1user

Users        share1user

C$
ADMIN$
~~~
