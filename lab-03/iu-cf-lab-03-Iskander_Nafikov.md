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
- The second malware I selected was ransomware **`Ransomware.Mamba`**. I also unzipped it to the `~/malwares/mamba`
	![[Pasted image 20250504015315.png]]
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
#### Mamba
##### Submission
- After that, I submitted **`Ransomware.Mambacuckoo community`**
- 
##### Artifacts
###### Malware file
- 
- 
###### Registry modifications
- 
- 
###### Files
- 
- 
###### Network
- 
- 
### 2.
>[!Task Description]
> Analyze the behavior of the malware, and then write about what the malware does and what its goal is.
#### LoveLetter
- After a thorough examination of the artifacts I can conclude:
	> This malware is a `RACHUNEK.txt.vbs` file or `RACHUNEK.html.vbs`, which is a malicious Visual Basic Script. It actively distributes itself via IRC, Outlook E-mail, and replacing many files (`js`, `jse`, `css`, `wsh`, `sct`, `hta`, `jpg`, `jpeg`, `bmp`, `gif`, `doc`, `mp3`, `html`, `htm`, `txt`, xls`,` `wri`, `elm`, `dbx`, `avi`, `mpg`, `wav`, `mpeg`) in the system, while deleting the original files (except `doc`, `mp3`, `html`, `htm`, `txt`, `xls`, `wri`, `elm`, `dbx`, `avi`, `mpg`, `wav`, `mpeg`). It also replaces the start page of the Internet Explorer browser with one of the following sites: `www.playboy.com `, `www.o2.pl `, `www.playboy.pl `, or even downloads an executable file WIN-BUGSFIX.exe from the website www.skyinet.net. This program is most likely malicious, but the website is currently unavailable. The script is intended for a Polish audience since the text is Polish: name of file, and e-mail body.
#### Mamba
- 
### 3.
>[!Task Description]
> Does the malware have some sandbox detection? If yes, try to defeat/detect the techniques that are used for that.
#### LoveLetter
- No
#### Mamba
- 
### 4.
>[!Task Description]
> Extract a memory dump of the sandbox analysis and analyze it using **Volatility** or any other supported tool. Can you trace some of Cuckoo's findings in the dump? (*write any other potential IoC you find*)
#### LoveLetter
- 
#### Mamba
- 
### 5.
>[!Task Description]
> Try to use other online tools (*for example, any.run , hybrid analysis, …*), figure out if these online platforms will manage to detect more artifacts than what you have found.
#### LoveLetter
- 
#### Mamba
- 
## Task 4 - Static Analysis
---
### 1.
>[!Task Description]
> Use any tool for static analysis of your selected malware (*for example, Ghidra, IDA, Binary Ninja, Hopper, Radare2, …*)
#### LoveLetter
- Since the file is a simple Visual Basic script which code can be easily analyzed without any static analysis tool, I skipped this step.
#### Mamba
- 
### 2.
>[!Task Description]
> Try to see if there are some artifacts that dynamic analysis did not manage to find, for example a piece of code that did not run inside the sandbox VM.
#### LoveLetter
- Now let's imagine the script's source code was hidden somehow. If so, it would be impossible to analyze the source code by only running it in a sandbox VM. In this case source code analysis could really help and explain what's happening.
	1. For example, malware replication was not detected since I had no Outlook or mIRC chat on the VM.
	2. Another block that wasn't executed is download of `WIN-BUGSFIX.exe` because the web-site is currently unavailable. Moreover, to access this site we need to start Internet Explorer and we can got luck with $25\%$ probability only. However, Cuckoo does not start browser during analysis.
	3. Another important detail is an examination of file formats which would be replaced to `VBS` completely with removal of an original file or just hiding it.
#### Mamba
- 
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