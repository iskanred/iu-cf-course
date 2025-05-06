- **Name**: Iskander Nafikov
- **E-mail**: [i.nafikov@innopolis.university](mailto:i.nafikov@innopolis.university)
- **GitHub**: [https://github.com/iskanred](https://github.com/iskanred)
---
# CCF Lab 3 - Sandboxing & Malware Analysis
---
>[!Task Description]
> In this lab, you will get the skills to work with sandboxes. A sandbox is a limited environment on your system for executing guest programs without access to the main operating system. It is a mechanism for the safe execution of programs. Sandboxes are often used to run untested code, unverified code from unknown sources, and to run and detect malware. After that, you will also learn how to detect malicious code artifacts using static analysis.
## Task 1 - Preparation
---
### 1.
>[!Task Description]
> Prepare and install a sandboxing solution that allows you to configure the sandbox environment LOCALLY. For example, **Сuckoo**.
#### Definitions
- A **sandbox** is a tool that is used to launch malware in a secure and isolated environment, the idea is the sandbox fools the malware into thinking it has infected a genuine host.
- **Cuckoo** is an open source automated malware analysis system. It’s used to automatically run and analyze files and collect comprehensive analysis results that outline what the malware does while running inside an isolated operating system. It can retrieve the following type of results:
	 - Traces of calls performed by all processes spawned by the malware.
	 - Files being created, deleted and downloaded by the malware during its execution.
	 - Memory dumps of the malware processes.
	 - Network traffic trace in PCAP format.
	 - Screenshots taken during the execution of the malware.
	 - Full memory dumps of the machines.
#### Setting up VM for Cuckoo
- Unfortunately, the latest release was made in 2018 and now the GitHUb repository of the tool is archived
	![[Pasted image 20250502190923.png]]
- The recommended system I found in the Cuckoo docs is Ubuntu 16.04
	![[Pasted image 20250502190814.png]]
- I downloaded Ubuntu Desktop 16.04.7 64-bit ISO image
	supports ![[Pasted image 20250503015453.png]]
- Then I checked if my KVM nested virtualization was enabled and the answer was `Y` which means "yes"
	![[Pasted image 20250503014735.png]]
- So then I created a new virtual machine based on the downloaded OS
	![[Pasted image 20250503021141.png]]
- I installed Ubuntu 16.04 to my virtual machine
	![[Pasted image 20250503023141.png]]
- I configured an SSH server there
	![[Pasted image 20250503030117.png]]
- And connected to my VM via SSH to make my work more comfortable
	![[Pasted image 20250503030238.png]]
#### Setting Up Cuckoo
- I started with installing all the necessary dependencies
	![[Pasted image 20250503031844.png]]
- After **hours spent** trying to configure everything and install dependencies with right versions I finally set up Cuckoo using this super detailed [article](https://habr.com/ru/articles/350392/). I decided not to include all the steps since **there are a lot of them**. Below I initialized Cuckoo with a default configuration which I will change next
	![[Pasted image 20250503044652.png]]
### 2.
>[!Task Description]
> Use any virtualization environment, better to use the latest version (check repo and official website).
- In previous section I installed VirtualBox since I want to use it as a machinery for the Cuckoo
	![[Pasted image 20250503044909.png]]
### 3.
>[!Task Description]
> Create a Virtual Machine and set up it with your sandboxing solution. Make sure that VM uses a **HOST ONLY** network adapter.
#### Creating Windows VM
- As a sandbox environment I used Windows 7 64-bit because this is the last version of Windows that [was supported fully](https://github.com/cuckoosandbox/cuckoo/issues/2916)
	![[Pasted image 20250503051016.png]]
- So, I created a new VM inside my Ubuntu 16.04 VM using VirtualBox
	![[Pasted image 20250503052734.png]]
- I installed Windows 7 SP 1 there
	![[Pasted image 20250503052857.png]]
	![[Pasted image 20250503062916.png]]
#### Configuring Windows VM
- I installed Python
	![[Pasted image 20250503072510.png]]
- Also, I changed appearance theme to simple one to make system more performant
	![[Pasted image 20250503175633.png]]
- I disabled Windows Firewall
	![[Pasted image 20250503181404.png]]
- And automatic updates
	![[Pasted image 20250503181610.png]]
- I changed network to "Host-Only" adapter as it was recommended in the [docs](https://cuckoo.readthedocs.io/en/latest/installation/guest/network/)
	![[Pasted image 20250503184219.png]]
- And configured static IP address for Windows VM $=$ `192.168.56.101/24`
	![[Pasted image 20250503200019.png]]
- Then I configured IP forwarding in `systctl` and NAT in `iptables` for the `192.168.56.0/24` network and `vboxnet0` adapter
	![[Pasted image 20250503200404.png]]
- Finally, I was able to access internet from my VM through the host and access VM from my host
	![[Pasted image 20250503200612.png]]![[Pasted image 20250503200737.png]]
- The final step was to transfer `/home/iskanred/.cuckoo/agent/agent.py` from host to guest. I made it using [Yandex Disk](https://disk.yandex.ru/)
	![[Pasted image 20250503201014.png]]
- So, I ran it
	![[Pasted image 20250503201228.png]]
#### Saving snapshot
- I created system's snapshot using VirtualBox
	![[Pasted image 20250504072629.png]]
- After that I closed VM and restored it from the snapshot and it was restores instantly
	![[Pasted image 20250503201914.png]]
#### Configuring Cuckoo
- Then I configured Cuckoo to work with this VM
	![[Pasted image 20250503051308.png]]
	![[Pasted image 20250503051408.png]]
- Finally, I was able to run Cuckoo with no problem
	![[Pasted image 20250503203336.png]]
- However, as you see it suggested me to download Cuckoo Signatures, Yara rules and more goodies using `cuckoo community`, so I downloaded other useful modules using this command
	![[Pasted image 20250504084049.png]]
- And ran it again in debug mode
	![[Pasted image 20250504084128.png]]
	![[Pasted image 20250504084229.png]]
- Then I ran Cuckoo Web interface
	![[Pasted image 20250504084431.png]]
- And could access my Cuckoo web page from my host machine (Ubuntu 24.04)
	![[Pasted image 20250504090043.png]]
	![[Pasted image 20250504090122.png]]
## Task 2 - Let's get some malware
---
### 1.
>[!Task Description]
> Download some malware/ransomware from the Internet (*for example, TheZoo repo*). Please be careful when you run them, **THESE ARE REAL MALWARE**.
- [ytisf/TheZoo](https://github.com/ytisf/theZoo) is a popular a repository of LIVE malware. **theZoo** is a project created to make the possibility of malware analysis open and available to the public.
- I cloned the repo
	![[Pasted image 20250504011528.png]]
- I selected **`VBS.LoveLetter`** malware to analyse. I unzipped it to the `~/malwares/loveletter`
	![[Pasted image 20250504015049.png]]
### 2.
>[!Task Description]
> Select at least two malware that you want to analyse in the sandbox VM that you prepared in Task 1.
- The second malware I selected was ransomware **`Win32.Vobfus`**. I also unzipped it to the `~/malwares/vobfus`
	![[Pasted image 20250506013738.png]]
- There were several executables, so I selected the first one called **`323CANON.EXE_WORM_VOBFUS.SM01`**
## Task 3 - Sandbox Analysis
---
### 1.
>[!Task Description]
> See what kind of traces, artifacts, and connections your sandbox VM detects.
#### Love Letter
##### Submission
- Finally, I submitted **`VBS.LoveLetter`**  for analysis to sandbox
	![[Pasted image 20250504090355.png]]
	![[Pasted image 20250504222351.png]]
- The score is $5.6 / 10$
##### Artifacts
###### Malware file
- The malware file is called `VBS.LoveLetter.txt.vbs`. Its size is only 9.5Kb which seems actually small.
	![[Pasted image 20250504233946.png]]
- The malware file itself is ran under `wscript.exe` which means it is a Windows script.
	![[Pasted image 20250504230111.png]]
- The file itself pretends to look like a simple **TXT** file because it contains a suffix `.txt.vbs` which may easily confuse a user who has file extensions hidden which is a default Windows setting. However this file type is **VBS** (Visual Basic Scripting). VBS files are script files written in VBScript, a lightweight scripting language developed by Microsoft. They are used to automate tasks in Windows, like managing files, modifying settings, or running commands. ❗ Microsoft is **phasing out VBScript** due to **security risks**, favoring PowerShell instead.
- Also, the name of the file (`LoveLetter.txt`) gives us an idea that is was used in **phishing attacks**. The file is specially named in such a way that a receiver would like to open it and read this "exciting love letter".
###### Registry modifications
- Internet explorer's start page was tried to be modified to `www.playboy.com`, `www.o2.pl`, `www.playboy.pl`, `http://www.skyinet.net/~chu/sdgfhjksdfjklNBmnfgkKLHjkqwtuHJBhAFSDGjkhYUgqwerasdjhPhjasfdglkNBhbqwebmznxcbvnmadshfgqw237461234iuy7thjg/WIN-BUGSFIX.exe`
	![[Pasted image 20250504224147.png]]
	![[Pasted image 20250505030743.png]]
- The last URL is some file which is named `WIN-BUGSFIX.exe`, but since it is malware and the address is so suspicious, I believe this is not related to official Windows bug fixes or any other changes. The domain name is still in use, but there no HTTP server on it
	![[Pasted image 20250505033107.png]]
##### Files
- Accessing file `C:\Windows\debug\PASSWD.LOG` which does not seem suspicious because this file **was only read** and basically it does not contain any sensitive info
	![[Pasted image 20250504225659.png]]
	![[Pasted image 20250504225822.png]]![[Pasted image 20250504225903.png]]
- The same is applied for the files `C:\Windows\System32\mfcsubs.dll` and `C:\Windows\bootstat.dat`: only reading file attributes and content **with no modifications**
	![[Pasted image 20250504231739.png]]
	![[Pasted image 20250504232133.png]]
	![[Pasted image 20250504232205.png]]
- Also, it accessed some Cuckoo Sandbox files inside the VM such as `agent.py` and `analyzer.py`. I checked there were only reads too **with no modifications**
	![[Pasted image 20250504232516.png]]
- The same happened to Yandex Browser files: only reading file attributes and content
	![[Pasted image 20250504233026.png]]
- And the same with links or shortcuts: only reading file attributes and content
	![[Pasted image 20250504233255.png]]
- Therefore, I **concluded** that the malware just reads all the files in a filesystem which triggers many **false positive file checks** above.
- However, it seems that files were not read without a reason. Some of them **were replaced to the `VBS` scripts** with the same name but `.vbs` extension appended. In total 226 such events happened.
	![[Pasted image 20250504234643.png]]
- For example, file `C:\Python27\Tools\pynche\webcolors.txt` was accessed, then a `VBS` script file `webcolors.txt.vbs` was created with same attributes and location, and then the original file became hidden to a user.
	![[Pasted image 20250504233821.png]]
	![[Pasted image 20250504234538.png]]
- At the same time some of the original files were even deleted: 472 events but they are repeated twice or even thrice, so there were $\approx$ 188 files.
	![[Pasted image 20250504235859.png]]
	![[Pasted image 20250504235603.png]]
- For instance, `C:\Users\cuckoo\AppData\Local\Microsoft\Windows Mail\Stationery\ShadesOfBlue.jpg`
	![[Pasted image 20250504235133.png]]
##### Network
- One GET HTTP request made to `www.msftncsi.com` successfully which is a default Windows 7 check for an internet access.
	![[Pasted image 20250505000200.png]]
- And corresponding DNS, [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution), and [Mailslot](https://ru.wikipedia.org/wiki/Mailslot) packets
	![[Pasted image 20250505002333.png]]
- Also, I found no suspicious URLs inside the processing memory barring to `http://skyinet.net`. Others seem to be generated and used by the system.
	![[Pasted image 20250505070434.png]]
- In summary, **nothing really interesting happened in a network**
##### Script
- Now let's check what does the original and replicated `.VBS` script do
	![[Pasted image 20250505005143.png]]
- I opened it in a text editor
	![[Pasted image 20250505005220.png]]
- After analysis I got the following insights:
	- Not all the files were replaced, only with a specific extensions: `js`,  `css`, `hta`, `jpg`, `bmp`,`doc`, `mp3`. Some of them (`doc`, `mp3`, `html`, `dbx`, `avi`) are not even deleted because may be needed for successful exploitation (such as `dbx` which is an Outlook Express Mail Database file).
		![[Pasted image 20250505005710.png]]
	- Three additional scripts are created `MSKernel.vbs`, `WinDll.vbs`, `RACHUNK.TXT.vbs`. "RACHUNK" in Polish means a check or a receipt.
		![[Pasted image 20250505033332.png]]
		![[Pasted image 20250505010011.png]]
		![[Pasted image 20250505030146.png]]
		![[Pasted image 20250505030237.png]]
	- Also, we can see how the Internet Explorer start page is set randomly
		![[Pasted image 20250505033241.png]]
	- This script works as a worm since it is distributes itself across the [IRC](https://en.wikipedia.org/wiki/IRC) (text-based chat system)
		![[Pasted image 20250505034003.png]]
		![[Pasted image 20250505034034.png]]
	- In addition, it distributes the script through E-mail if Outlook is present with the following content: "`Wysy³amy wam w za³aczniku rachunek prosimy o szybk¹ odpowiedz`" which translates as "`We will send you a bill in the form, please reply quickly" in Polish.
		![[Pasted image 20250505034209.png]]
	- Below is the HTML file for for a e-mail that contains a script
		![[Pasted image 20250505040733.png]]
#### Vobfus
##### Submission
- After that, I submitted **`323CANON.EXE_WORM_VOBFUS.SM01`**
	![[Pasted image 20250506014041.png]]
	![[Pasted image 20250506014220.png]]
- The score is $5.4 / 10$
##### Artifacts
###### Malware file
- The file **`323CANON.EXE_WORM_VOBFUS.SM01`** is a `PE32` executable file for Intel 80386 architecture which is designed to be executed on Windows.
	![[Pasted image 20250506015407.png]]
- It is the standard format for executables on Windows NT-based systems, including files such as `.exe`, `.dll`, `.sys`, and `.mui`. At its core, the PE format is a structured data container that gives the Windows operating system loader everything it needs to properly manage the executable code it contains. This includes references for dynamically linked libraries, tables for importing and exporting APIs, resource management data and thread-local storage (TLS) information.
- I checked `SM01` file extension but have not found anything which could mean the **file extension is a fiction**. The same is applied to other file extensions in the archive `Win32.Vobfus.zip`: `SMA3`, `SMIS`, `SMM2`.
###### Registry modifications
- The malware created an executable `doudi.exe` which was installed for autorun at Windows startup with different options
	![[Pasted image 20250506025902.png]]
- What is more, the malware tried to prevent hidden file from being displayed
	![[Pasted image 20250506030003.png]]
- And this action was only once run by the original malware file and many times by the generated executable `doudi.exe`
	![[Pasted image 20250506030500.png]]
- The same happened to installing `doudi.exe` to autorun
	![[Pasted image 20250506030901.png]]
- This gave me an idea that both **putting an executable at system startup** and **file hiding** was scheduled to be **executed continuously** in order to avoid manual change in settings.
###### Files
- This malware spawns a file `C:\Users\cuckoo\doudi.exe` and executes it
	![[Pasted image 20250506031804.png]]
	![[Pasted image 20250506050343.png]]
- Also, the program tried to create the network socket file with a write access which is be shared to other files. `AFD` is the user-mode interface to the Windows TCP/IP stack. Any network activity (HTTP, FTP, etc.) goes through AFD. This means that the malware could prepare the environment for network access.
	![[Pasted image 20250506032717.png]]
###### Processes
- The PID of `323CANON.EXE_WORM_VOBFUS.SM01` is `2160`, while PID of `doudi.exe` is `200`
	![[Pasted image 20250506031931.png]]
- An interesting thing is that the original process was involved only 43 pages of events
	![[Pasted image 20250506033127.png]]
- Meanwhile, a majority of events was happened to its child process $= 1382$ pages
	![[Pasted image 20250506033244.png]]
- At the same time the malware listed all the processes being run for some reason. It might need to detect antivirus software and close it.
	![[Pasted image 20250506033435.png]]
- Another signature identified an interest in a `smss.exe` process which is an analogue to `init` process in Linux. However, it was only listed as other processes and other processes were listed many times too. So, I think this signature is **false positive**.
	![[Pasted image 20250506034315.png]]
###### Memory
- The malware faced 15 kernel level exceptions while being executed. All this exceptions are related to the `msvbvm60.dll` shared library. This DLL is a Visual Basic 6 runtime. Exception code `0xc000008f` translates as `STATUS_FLOAT_INVALID_OPERATION` which can tell about memory corruption while performing `leave` instruction.
	![[Pasted image 20250506042705.png]]
- Such an exception could happen in the following cases:
	1. Malicious software tried to access or execute a part of memory it shouldn't. For example, it could exploit [CVE-2018-8174](https://www.cve.org/CVERecord?id=CVE-2018-8174) vulnerability.
		![[Pasted image 20250506045033.png]]
	2. It was an intended exception to bypass some checks as described in this [artice](https://billdemirkapi.me/abusing-exceptions-for-code-execution-part-2/).
		![[Pasted image 20250506044407.png]]
- Overall, we can see that `msvbvm60.dll` was used in malware's source code. This indicates the the **malware written in VB6**.
	![[Pasted image 20250506045255.png]]
- What else, I got the message that the malware changed its virtual memory permission to execute code inside the memory. This again may tell that it injects some executable code to its memory.
	![[Pasted image 20250506045700.png]]
	![[Pasted image 20250506050032.png]]
###### Network
- First, I checked URLs in process memory dump. There are 495 URLs of popular websites (wikipedia, google, adobe, different media)
	![[Pasted image 20250506051310.png]]
- Some of these URLs contain links to different certificates and certificates authorities
	![[Pasted image 20250506051601.png]]
- HTTP was executed once and it was just `www.msftncsi.com` for Windows system to check internet access.
	![[Pasted image 20250506052212.png]]
- Nevertheless, there were some suspicious DNS requests to `ns1.music*.*` resources and one of them to `ns1.musicmixb.co` was even successful receiving IP address $=$ `34.136.111.81`
	![[Pasted image 20250506052341.png]]
- I found that exactly the malicious process `323CANON.EXE_WORM_VOBFUS.SM01` tried to contact this IP address by 8000 port which may be HTTP.
	![[Pasted image 20250506053118.png]]
- I haven't found that this address or domain name is malicious, but I found that is was also contacted in other malwares: [Win.Trojan.Acnu-7601993-0](https://otx.alienvault.com/indicator/file/efb10dc40cf2c9cab204959da8954b34ec3b9ebc5476c98ba864cd6694122f9f),  [vobfus](https://any.run/report/328a25ee98030865ce42661e7a3b5848d2835e6e0e633cafad9e56644c1c3d77/42473ccc-4bb4-4a7f-a485-f3520f8d3446). The key moment is that I haven't found any other information about this domain other than it was requested by many different malicious files.
	![[Pasted image 20250506054235.png]]
###### Devices
- It seems also that malware tried to communicate with different devices most probably to replicate itself
	![[Pasted image 20250506054812.png]]
	![[Pasted image 20250506054903.png]]
	![[Pasted image 20250506054944.png]]
### 2.
>[!Task Description]
> Analyze the behavior of the malware, and then write about what the malware does and what its goal is.
#### LoveLetter
- After a thorough examination of the artifacts I can conclude:
	> This malware is a `RACHUNEK.txt.vbs` file or `RACHUNEK.html.vbs`, which is a malicious Visual Basic Script. It actively distributes itself via IRC, Outlook E-mail, and replacing many files (`js`, `jse`, `css`, `wsh`, `sct`, `hta`, `jpg`, `jpeg`, `bmp`, `gif`, `doc`, `mp3`, `html`, `htm`, `txt`, xls`,` `wri`, `elm`, `dbx`, `avi`, `mpg`, `wav`, `mpeg`) in the system, while deleting the original files (except `doc`, `mp3`, `html`, `htm`, `txt`, `xls`, `wri`, `elm`, `dbx`, `avi`, `mpg`, `wav`, `mpeg`). It also replaces the start page of the Internet Explorer browser with one of the following sites: `www.playboy.com `, `www.o2.pl `, `www.playboy.pl `, or even downloads an executable file WIN-BUGSFIX.exe from the website www.skyinet.net. This program is most likely malicious, but the website is currently unavailable. The script is intended for a Polish audience since the text is Polish: name of file, and e-mail body.
#### Vobfus
- After a thorough examination of the artifacts I can conclude:
	> This malware seems to be a worm which most probably replicates itself to removable devices. It is written in a Visual Basic 6. It spawns a new executable with some random name, runs it, and puts it to autorun at Windows startup which is performed continuously. Another continuous action is to make hidden files not being displayed. It also monitors which processes are launched to detect antivirus or to hide itself if task manager was launched, for instance. It contains a large database of different URLs including certificate authorities. In addition, it communicates with some suspicious addresses. This can lead tell that malware may try to exfiltrate some confidential data or download a trojan. 
### 3.
>[!Task Description]
> Does the malware have some sandbox detection? If yes, try to defeat/detect the techniques that are used for that.
#### LoveLetter
- No
#### Vobfus
- Maybe. It monitors currently running process.
- To defeat antivirus or sandboxes can do:
	- **Masking**: Some antivirus or sandbox programs can disguise their processes as regular system processes or parts of them, making them less visible to malware.
	- **Behavioral analysis**: Software can use other techniques to detect a malware even if it is not laucnhed.
	- **Self-protection**: Antiviruses or sandbox environments use self-protection techniques to prevent stopping them by malwares.
### 4.
>[!Task Description]
> Extract a memory dump of the sandbox analysis and analyze it using **Volatility** or any other supported tool. Can you trace some of Cuckoo's findings in the dump? (*write any other potential IoC you find*)
- I have used Volatility which was installed in `~/volatility/vol.py` of version 2.6.1
#### LoveLetter
- For `LoveLetter` I haven't found anything interesting in the memory dump excepted to processes. I tried the following Volatility commands: `pslist`, `malfind`, `pstree`, `cmdscan`, `netscan`, `hivelist`, `printkey`
##### Processes
- **Command**:
	```shell
	python ~/volatility/vol.py pslist --profile=Win7SP1x64 -f memory.dmp
	```
- **Output**:
	![[Pasted image 20250505075327.png]]
- **Explanation**:
	- We can see the `wscript.exe` process was running. This was instantly and easily detected by Cuckoo
#### Vobfus
- For `Vobfus` I either haven't found anything exciting in the memory dump or it such an information required much more thorough analysis. Only some commands gave me interesting results.
##### Processes
- **Command**:
	```shell
	python ~/volatility/vol.py pslist --profile=Win7SP1x64 -f memory.dmp
	```
- **Output**:
	![[Pasted image 20250506061949.png]]
- **Explanation**:
	- We see that both malicious processes were run. The original executable had 3 threads.
###### Network
- **Command**:
	```shell
	python ~/volatility/vol.py netscan --profile=Win7SP1x64 -f memory.dmp
	```
- **Output**:
	![[Pasted image 20250506062517.png]]
- **Explanation**:
	 - We see mentioned request to `34.132.102.6:8000` which TCP connection was even established, but no real packets were transmitted, only connection was maintained. This means that through this interface an attacker could gain remote access to the victim's machine. Another scenario is that this interface can be used in data exfiltration or trojan downloading.
		 ![[Pasted image 20250506063016.png]]
###### DLL
- **Command**:
	```shell
	python ~/volatility/vol.py dlllist --profile=Win7SP1x64 -f memory.dmp
	```
- **Output**:
	![[Pasted image 20250506064051.png]]
- **Explanation**:
	- We can check which DLLs the malwares have been used. For example, we can see the `MSVBVM60.DLL` which caused stack exceptions what we found using Cuckoo.
### 5.
>[!Task Description]
> Try to use other online tools (*for example, any.run , hybrid analysis, …*), figure out if these online platforms will manage to detect more artifacts than what you have found.
- I have used Hybrid Analysis
#### LoveLetter
- The file `VBS.LoveLetter.txt.vbs` seemed to be recognized by its hash value, so the analysis didn't take any time
	![[Pasted image 20250505082757.png]]
- The malware was previously ran inside three different environments: Windows 10 64-bit, Windows 7 32-bit, Windows 7 64-bit
	![[Pasted image 20250505082926.png]]
- Also, it detected a malicious generated files (HTM and VBS) with classification: `ScriptWORM.Generic`
	![[Pasted image 20250505083021.png]]
	![[Pasted image 20250505083207.png]]
- In addition, I got even MIT&RE classification and community feedback
	![[Pasted image 20250505083116.png]]
- It even detected that the malware tried to access e-mail address info stored in Outlook
	![[Pasted image 20250505083711.png]]
- Basically, it is a really powerful developing cloud-based tool which allows not only check files quickly but also to coordinate them with MITRE ATT&CK techniques and share feedback with community.
- At the same time **it didn't detect or show** changing in a Internet Explorer start page, for instance. However, Cuckoo contained **more false-positive** signatures triggered.
#### Vobfus
- The file `323CANON.EXE_WORM_VOBFUS.SM01` seemed to be recognized by its hash value, so the analysis didn't take any time.
	![[Pasted image 20250506065149.png]]
- Besides what Cuckoo have found Hybrid Analysis examined the follwoing risks:
	<img src="Pasted image 20250506065718.png" width=700 />
- So, in this case Hybrid Analysis **have found much more interesting details** than Cuckoo have done. Meanwhile, Cuckoo detected prevention of seeing hidden files and the online tool did not.
#### Conclusion
- After analyzing two malware I can say that both of these tools are powerful, but each of them missed something that other detected. Therefore, I recommend to use both for detailed and thorough malware analysis.
#### Comparison
| Feature                      | **Hybrid Analysis**                                   | **Cuckoo Sandbox**                       |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------------- |
| **Deployment**               | Cloud-based service                                   | Self-hosted (on-premises)                |
| **Analysis Type**            | Combines static and dynamic analysis                  | Primarily dynamic analysis               |
| **Ease of Use**              | User-friendly web interface                           | Requires setup and configuration         |
| **Threat Intelligence**      | Integrates with various threat intelligence sources   | Limited built-in threat intelligence     |
| **Report Generation**        | Comprehensive reports with visualizations             | Detailed reports, but less visualization |
| **Resource Requirements**    | Utilizes cloud resources                              | Local resources needed for hosting       |
| **Sample Submission**        | Via web interface (file upload or URL)                | Via web interface or command line        |
| **Integration Capabilities** | API available for integrations                        | APIs and custom integrations possible    |
| **Community Support**        | Provides community access but is primarily commercial | Strong open-source community support     |
##### When to Use Hybrid Analysis:
- **Quick Analysis**: When you need to quickly analyze malware without the overhead of setting up and maintaining your infrastructure.
- **Comprehensive Findings**: When you want access to a platform that provides both static and dynamic analysis combined with integrated threat intelligence.
- **Web-Based Interface**: When you prefer an easier approach to submit samples and view results through a user-friendly online dashboard.
- **Limited Technical Resources**: When you lack the technical expertise or resources to set up and manage your malware analysis environment.
##### When to Use Cuckoo Sandbox:
- **On-Premises Solutions**: When you need to keep your analysis private, especially for sensitive or proprietary data.
- **Customization Needs**: When you require an analysis platform that is customizable to fit your specific needs or workflows.
- **Research and Testing**: When you want to set up a controlled environment for extensive research on malware behavior or test variations of malware.
- **Resource Management**: When you have sufficient resources to run and manage your virtual environments.

## Task 4 - Static Analysis
---
### 1.
>[!Task Description]
> Use any tool for static analysis of your selected malware (*for example, Ghidra, IDA, Binary Ninja, Hopper, Radare2, …*)
#### LoveLetter
- Since the file is a simple Visual Basic script which code can be easily analyzed without any static analysis tool, I skipped this step.
#### Vobfus
- First, I Installed **Ghidra** using `snap`
- Then I launched Ghidra, created a new project, imported the malware, and started analysis
	![[Pasted image 20250506073141.png]]
- Unfortunately, decompiler encountered bad instruction data and was not able to decompile anything useful
	![[Pasted image 20250506074825.png]]
 - Below are the functions found
	 ![[Pasted image 20250506075210.png]]
- Then I checked defined strings which contained a lot of noise, but I found a name of DLL which we discussed
	![[Pasted image 20250506080024.png]]
- Also, there some commands could be found
	![[Pasted image 20250506080208.png]]
- And other strings which gives an idea that the executable is some game about fighting
	![[Pasted image 20250506080312.png]]
- Also, some called functions' names 
	![[Pasted image 20250506080501.png]]
- Then I opened disassembler and discovered that the malware contains a lot of zeros in head which may be done to confuse a reader
	![[Pasted image 20250506080847.png]]
- Actually, I haven **not found anything** really interesting because **without a decompiler** it is really **hard to analyze** such an executable with no expertise. This executable **strongly rely** on the `msvbvm60.dll` which is a Visual Basic 6 Runtime, so **without knowing how things work** there it is almost **impossible to figure something out**.
### 2.
>[!Task Description]
> Try to see if there are some artifacts that dynamic analysis did not manage to find, for example a piece of code that did not run inside the sandbox VM.
#### LoveLetter
- Now let's imagine the script's source code was hidden somehow. If so, it would be impossible to analyze the source code by only running it in a sandbox VM. In this case source code analysis could really help and explain what's happening.
	1. For example, malware replication was not detected since I had no Outlook or mIRC chat on the VM.
	2. Another block that wasn't executed is download of `WIN-BUGSFIX.exe` because the web-site is currently unavailable. Moreover, to access this site we need to start Internet Explorer and we can got luck with $25\%$ probability only. However, Cuckoo does not start browser during analysis.
	3. Another important detail is an examination of file formats which would be replaced to `VBS` completely with removal of an original file or just hiding it.
#### Vobfus
- Yes, actually some strings were useful such as names of functions and those game elements (`welcome to ERACER`, `use arrow keys...`, `new fighter arrived`, etc.). Maybe it is something to distract analyzer or antivirus because it's hard to imagine which game can be fit in 300Kb. Another reason why I think so is that ERACER is actually a racing game, but other strings imply that the game must be a fighting :)
### 3.
>[!Task Description]
> Try to describe which method is better (Sandboxing V.S. Static analysis) is better, and which one is more useful in which case.
#### Sandboxing
**➕ Advantages**
- Detects real-time malicious actions (e.g., file encryption, network calls).  
- Catches obfuscated/zero-day threats that evade static analysis.  
- Useful for behavioral analysis (e.g., ransomware, spyware).  
**➖ Disadvantages**  
- Slower and resource-intensive: requires time and hardware resources to execute a malware.
- May miss dormant malware (e.g., logic bombs, buffer overflow).
- Evasion techniques (malware can detect sandboxes).
- Potential risk of accidentally infecting systems if proper containment measures aren’t taken.
#### Static analysis
**➕ Advantages**  
- Fast & small: no execution needed, does not require a lot of resources.
- Easily detects known patterns (YARA and other rules, hashes comparison).
- Works on non-executables (documents).  
**➖ Disadvantages**  
- Struggles with obfuscation/packing.
- Struggles with zero-day vulnerabilities exploitation.
- Misses runtime-only behaviors.
#### Comparison
- Choosing between **static** and **dynamic analysis** depends on your specific needs, resources, and the characteristics of the malware being studied.
- For preliminary assessments and quick identification of known threats, **static analysis** is often sufficient.
- However, for a deeper understanding of how malware operates and interacts with systems, **dynamic analysi**s is essential. 
#### Conclusion
- In practice, many security analysts and researchers employ a hybrid approach that leverages both static and dynamic analysis for a more comprehensive understanding of malware:
	1. **Preliminary Static Analysis**: Used to get initial insight, develop a hypothesis, or filter out benign files.
	2. **Follow-Up Dynamic Analysis**: Applied to samples suspected of malicious intent to validate hypotheses and observe real-world behaviors.