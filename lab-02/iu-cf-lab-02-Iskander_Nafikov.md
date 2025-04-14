- **Name**: Iskander Nafikov
- **E-mail**: [i.nafikov@innopolis.university](mailto:i.nafikov@innopolis.university)
- **GitHub**: [https://github.com/iskanred](https://github.com/iskanred)
---
# CCF Lab 2 - Forensic file system analysis
> [!Task Description]
> In this lab, you will learn how to investigate a forensic analysis of a compromised file system. This is one of the basic and at the same time relevant and actual areas in forensic science.

## Task 1 - Download the evidence file
> [!Task Description]
> You are offered to investigate the image of compromised system

- Since my student number is $15$ which means odd I used [case-1](https://drive.google.com/file/d/1LBdv8Wvzi5ihzclJwzG4oDIojxSPjynL/view?usp=sharing) system
	![[Pasted image 20250407194220.png]]

## Task 2 - Black box Forensics analysis
> [!Task Description]
> Use any forensics tools that you want. Different forensics tools can help you to analyze:
> - Figure out the platform, system and file system type
> - Perform a malware search
> - Create and analyze a timeline
> - Find artifacts in Windows components:
> 	- Windows Registry
> 	- Logs
> 	- Personal data of users
> 	- Network
> 	- Mail
> 	- Browser
> 	- Messengers
> 	- Windows libraries and configuration files
> 	- Other assets found in the compromised system
### **Image file investigation**
- First, I ran `file` command on my Windows machine using MinGW to investigate what type of file I received
	![[Pasted image 20250407231639.png]]
- Here we can see that this is actually some Windows OS image because it contains:
	- NTFS filesystem
	- DOS/MBR boot sector with 1.5Gb of size
	- [BOOTMGR](https://en.wikipedia.org/wiki/Windows_Boot_Manager) which used starting from Windows Vista or Windows Server 2008
### **AutoPsy configuration**
- I decided to use it **AutoPsy** since it is a very powerful tool that brings simplicity in working with registry, files, logs, events, browser, databases, network and etc.
- I added the image to investigate as a new AutoPsy case with all the modules enabled (including [Plaso](https://plaso.readthedocs.io/en/latest/) which we used manually in the previous lab to generate timeline from logs - `log2timeline`)
	![[Pasted image 20250407230100.png]]
- Ingesting all the modules for this case took **a lot of time**: $\approx 3 \text{ days}$ (that's why I submitted it much later that I supposed 😔)
- Finally, it ended and I got the following picture:
	![[Pasted image 20250409223647.png]]
### **Investigation**
#### Basic system information & Timeline
Let's begin with figuring some standard system info such as username, hostname, IP address, and etc.
- From the section `Operating System Information` we can extract a lot of useful information
	![[Pasted image 20250411194317.png]]
- **OS version** = `Windows 8.1 Enterprise`
	![[Pasted image 20250411201326.png]]
- **Hostname** = `4ORENSICS`
	![[Pasted image 20250411201345.png]]
- **Owner's username** = `hunter`
	![[Pasted image 20250411201410.png]]
- **IP address** = `10.0.2.15/24`. To figure it out I went to the Windows Registry hive: `HKEY_LOCAL_MACHINE\SYSTEM` (`C:/Windows/System32/config/SYSTEM`). Below we can also see DHCP server information such as its address, lease time, and etc.
	![[Pasted image 20250411200936.png]]
- In addition, using this metadata section we see this registry part modification time from which we can infer that the last time the the IP address was assigned to this interface using DHCP was `2016-06-21 02:23:12 GMT+00:00` or `2016-06-20 04:23:12 GMT+03:00` which is quite late, so let's try to determine the user's timezone. Also checking registry option `LeaseObtainedTime` we can also prove that since `1466475852` in UNIX is exactly the timestamp we inferred.
	![[Pasted image 20250411202242.png]]
- **Timezone & location** = `UTC-8:00` which is the same as Pacific Standard Time. I also found it inside the registry hive `HKEY_LOCAL_MACHINE\SYSTEM`. This means that the last DHCP lease obtain time was actually `2016-06-20 18:23:12 GMT-08:00`.
	![[Pasted image 20250411203100.png]]
- **OS usage**, by my first assumption, is $\approx 3$ years (Jun 2013 - Jun 2016) since the absolute majority of events happened in this time period which I obtained using AutoPsy timeline. An interesting part is that the device was most actively used periodically (22nd of August 2013, 18th of March 2014, 21st June 2016) and the most active usage happened right before the end of the interval in a last month which looks suspicious. Moreover, the web activity also happened only in Jun 2016. That's why I decided to explore some user's logging in information. 
	![[Pasted image 20250411203657.png]]
	![[Pasted image 20250411203909.png]]
	![[Pasted image 20250413164600.png]]
	![[Pasted image 20250413165621.png]]
	![[Pasted image 20250413165335.png]]
	![[Pasted image 20250413165515.png]]
	![[Pasted image 20250413165905.png]]
- But before moving to the login information I decided to check the **system installation timestamp** which is `2013-08-22 17:25:41 GMT+03:00`. I took it from the creation date of `system.ini` file. Also, we see that it was changed exactly at the `2016-06-21`.
	![[Pasted image 20250412192052.png]]
- Also, I decided to check **Installation date** inside the `SOFTWARE` registry hive and found that it was `2016-06-21 11:37:45 GMT+03:00`. This most probably means that the system update was installed on this date.
	![[Pasted image 20250411213621.png]]
	![[Pasted image 20250411213711.png]]
- **Login information** 
	- From the AutoPsy `OS Accounts` section I got that the user's **login count** is just 3
		![[Pasted image 20250411210852.png]]
	- From the same screenshot we see that the **last login** is `2016-06-21 04:42:40 GMT+03:00`
	- The **account creation** timestamp is `2016-06-21 11:37:43 GMT+03:00`
		![[Pasted image 20250411213858.png]]
- **Summary**:
	- There is a basic system timeline:
		- **`2013-08-22 17:25:41 GMT+03:00`** :  The system was created. ❗️ However, Windows 8.1 was not released at this moment.
		- **`2016-06-20 04:23:12 GMT+03:00`** :  The system obtained the IPv4 address by DHCP.
		- **`2016-06-21 04:42:40 GMT+03:00`** :  The user Hunter logged in the system last time
		- **`2016-06-21 11:37:43 GMT+03:00`** :  The account was created
		- **`2016-06-21 11:37:45 GMT+03:00`** :  The system was installed ❗️ or updated
		- **`2016-06-21 15:53:04 GMT+03:00`** :  The password fail date
	- The user logged in 3 times at all.
	- The system logged most number of events at these dates: 22nd of August 2013, 18th of March 2014, 21st of June 2016
	- However, the web activity was only detected at the 21st of June 2016.
- **Conclusion**:
	- From all above I can conclude that there are several possible options why everything looks so strange:
		1. The system may be installed first in 2013 on Windows 7 or Windows 8, then updated in 2014 by some administrator, finally updated in 2016 and used by Hunter.
		2. Someone changed the proper date information trying to hide the actual timeline.
		3. If this is a study case and not a real one, then probably the creators just did everything at once in the system, turned it off and created an image from this meaning that the "timeline" part is not important for investigation.
	- Whatever it was, we had a strong fact:
		- The system was used by Hunter user actively on Jun 21 and everything we should investigate seems to happen on this date.
#### Applications
- Afterwards, I started analysing user's installed programs and their usage
- First, I found USBPcap which is a USB sniffer and 7-zip
	![[Pasted image 20250413184319.png]]
- I found that he had a **VirtualBox** installed which means he's not a usual user of PC but some IT guy
	![[Pasted image 20250412184546.png]]
- Also, I found **Wireshark**, so the owner is definitely some IT guys who is related to Network and probably even Security
	![[Pasted image 20250412184704.png]]
- Btw, he has an antivirus **McAfee** installed
	![[Pasted image 20250412190150.png]]
- Also, the user has **Notepad++**, **Skype**, **Dropbox**, **Google Drive**, and **TeamViewer** installed which is is not something suspicious but it can be used by attackers easily.
	![[Pasted image 20250413184434.png]]
- Finally, I got something really interesting. The use had **BCWipe** software which is necessary for complete wiping data with no ability to recover it after. It might mean the user wanted to hide some data from the possible investigators 
	![[Pasted image 20250412190338.png]]
	![[Pasted image 20250412190446.png]]
- Another one bingo! **Nmap** is used for port scanning, but why Hunter needed it? For penetration testing or performing real attacks?
	![[Pasted image 20250412190637.png]]
- The **VirtualBox** was used on Jun 21
	![[Pasted image 20250413174850.png]]
- Also, **TeamViewer** was used at the same time with the Skype
	![[Pasted image 20250413175105.png]]
- **Wireshark** was also used
	![[Pasted image 20250413175845.png]]
- **Tor Browser** was used
	![[Pasted image 20250413180051.png]]
- Yeah, **Nmap** too
	![[Pasted image 20250413180215.png]]
- **7-zip**, **Ccleaner** and **BSWipe** were used at the same time after Nmap
	![[Pasted image 20250413180308.png]]
- **Skype**, **TeamViewer**, **Google Drive**, **DropBox**, **Tor Browser**, Nmap **were** actively used actually
	![[Pasted image 20250413180602.png]]
- **FTK Imager** together with already mentioned 
	![[Pasted image 20250413180825.png]]
- What is more, I found [Zenmap](https://nmap.org/zenmap/) which is a powerful GUI tool for port scanning based on Nmap
	![[Pasted image 20250413180916.png]]
- **Conclusion**:
	- From all above, I can conclude that the owner used: Tor Browser for something probably not legal, port scanning using Zenmap, BCWipe and CCleaner for wiping data, TeamViewer for remote access (maybe someone worked instead of him), Skype for communications, DropBox, Google Drive, 7-zip, FTK-Imager for compressing and stealing some data, Wireshark for capturing Network/USB data, and VBox for some other purposes.
	- I may be wrong with my assumption further, but let's see
#### Communications: Email
- Well, we saw active Skype usage in the date of using Tor, Zenmap, Wireshark, BCWipe. Therefore, I decided to carefully explore user's communications in Skype and other places.
- Since AutoPsy provides an ability to check e-mails from scratch using default ingesting modules I decided firstly to check e-mails and it explored that it not for nothing 😏
	<img src="Pasted image 20250413195415.png" width=400/>
- First, I discovered all the E-Mail accounts participated in communications on this device including skype
	![[Pasted image 20250413195231.png]]
- It seems that the PC owners' e-mail is `ehptmsgs@gmail.com` since this email was participated in each communication either as a receiver or a sender. What I found is that this email can be related to the EH Techniques organization which is **Energy Harvesting** or **EHPT** which is the either **Ericsson Hewlett Packard Telecom** or **Ethical Hacker & Penetration Tester**. However, it still can be a personal account, but it looks more as an account of organization.
	![[Pasted image 20250413202253.png]]
- I found an e-mail from a representer of [AccessData](https://en.wikipedia.org/wiki/AccessData) company which was a software development company that developed [Forensic Toolkit (FTK)](https://en.wikipedia.org/wiki/Forensic_Toolkit "Forensic Toolkit") and FTK Imager until it was acquired by Exterro. This e-mail contains information about some data privacy education event. This could mean that the owner of this e-mail somehow related to the world of Cyber Security.
	![[Pasted image 20250413202343.png]]
- Then I found `New sign-in from Chrome Linx` which means that this person has some Linux account (but currently we're observing Linux) somewhere and could be hacked  at `2016-06-21 02:01:29+03:00`. What is more, I found the next e-mail with the similar content `Your recovery email address changed` and `New sign-in from Chrome on Windows`. And everything happened around the same time.
	![[Pasted image 20250413203554.png]]
	![[Pasted image 20250413204937.png]]
	![[Pasted image 20250413205011.png]]
- Also, I found a strange e-mail from Skype in Arabic language which is basically just an invitation to install Skype and find your friends there
	![[Pasted image 20250413205728.png]]
- And further there is a long conversation between the `ehptmsgs@gmail.com` and `linux-rul3z@hotmail.com` which I described shortly below:
	![[Pasted image 20250413210703.png]]
- So, the content of this E-mail conversation is the following
	- Hunter connected with some guy who seems to understand something in attacks / penetration testing to teach him and help him to attack or pentest some network (probably of their organization but I am not sure yet).
	- Their dialogue established with a Hunter's message about TeamViewer which I suppose lets the other guy to access his device remotely.
	- They conversate via E-mail and Skype.
	- In Skype there is some password that can help to unarchive some 7-zip attachments from Hunter with pictures.
	- The other guy sent to Hunter links on YouTube videos about **Data Exfiltration** ❗️ and advices Hunter to disguise file using changing their extensions. So, Hunter uses this method and send him a PDF document with the JPG extension
		<img src="Pasted image 20250413221843.png" width=600/>
		<img src="Pasted image 20250413222746.png" width=500 />


	- Furthemore, Hunter tried to save this YouTube video links but the other guy told him to remove it, so Hunter wiped them (probably using the BSWipe)
	- Also, Hunter suggested to use Hangouts for communication but received no answer
	- Hunter sent the other guy a network design sample but got responded that the original print for the network is required to investigate what systems, apps, tools, appliances are used.
		![[Pasted image 20250413222451.png]]
	- Finally, Hunter asked the other guy to finish the project ASAP and told him that his out Outlook setup is working correctly.
#### Communications: Skype
- So, after this conversation I became even more convinced that I need to check their Skype conversation and find out more useful information and the mentioned password to check pictures sent via e-mail.
- Using the web I easily found where the Skype messages are stored locally. So I accessed the SQLite DB file and was able to explore the data right from AutoPsy. I selected `Messages` table and now I can easily see all the messages of the `hunterepht` which is a Hunter's username in Skype with the `linux-rul3z` which is an other guy's username.
	![[Pasted image 20250413224114.png]]
- From their conversation I got that Hunter asking `linux-rul3z` to help him to transfer some pictures and documents outside an organization's network since it is monitored. This guys agreed to help him and asks if he is able to access Hunter's device remotely via TemViewer. Hunter downloaded TeamViewer and then their conversation goes to e-mail which we already saw.
- Also, I got a Hunter's birthday which does not look like a real and a city which seems to be real since the mail from Skype were in Arabic: `1990-01-01`, `Amman, Jordan`
	![[Pasted image 20250414001043.png]]
- Unfortunately, I couldn't find any password Hunter told about in mails to unarchive `Pics.7z` or `fakeporn.7z` neither in Skype databases, nor in Skype journals. It seems that Hunter quickly removed this message.
	![[Pasted image 20250414001611.png]]
	![[Pasted image 20250414001630.png]]
#### Files
- After figuring out what's probably happened I finally need to investigate Hunter's files and check for a suspicious things
- In `Downloads` I found a lot of interesting installers. Besides the programs I've mentioned in `Applicaitons` section I also found out the following:
	- **Ollydbg** which is a 32-bit assembler level analysing debugger for Windows.
		![[Pasted image 20250414002739.png]]
	- **Hash Suite Free** which is a Windows program to test security of password hashes.
		![[Pasted image 20250414002753.png]]
	- **BurpSuite** which is a proprietary software tool for security assessment and penetration testing of web applications.
		![[Pasted image 20250414002850.png]]
	- **Eraser** which is a secure data removal tool for Windows.
		![[Pasted image 20250414003008.png]]
	- **Putty** which is a PuTTY is an SSH and telnet client
		![[Pasted image 20250414003150.png]]
	- **PSCP** which is a PSCP, the PuTTY Secure Copy client, is a tool for transferring files securely between computers using an SSH connection
		![[Pasted image 20250414003124.png]]
	- **SetupSSH** which is a OpenSSH client.
		![[Pasted image 20250414003212.png]]
	- **SysinternalSuite** which are technical resources and utilities to manage, diagnose, troubleshoot, and monitor a Windows environment.
		![[Pasted image 20250414003235.png]]
- In `Documents` folder I found 4 documents related to performing Data Exfiltration using different techniques (DNS, FTP, SQL Injection, etc.) and Bypassing Firewall.
	<img src="Pasted image 20250414003521.png" width=400 />
- Inside the `Google Drive` folder I found a proposal for Hunter to buy Forensics courses which are quite expensibe and some other interesting documents
	![[Pasted image 20250414161335.png]]
- Some tools list
	![[Pasted image 20250414161553.png]]
- And accounts list, unfortunately without passwords 😅
	![[Pasted image 20250414161618.png]]
- Inside the `Pictures` I found a folder named `Exfil` which also contained some information about Exfiltration tecniques
	![[Pasted image 20250414161838.png]]
	![[Pasted image 20250414162213.png]]
- Inside the `Pictures/Private` there are a log of kittys' photos. Maybe he sent some of them to `linux-r3lz`
	![[Pasted image 20250414162513.png]]
- Inside the `Pictures/background` there a lot of wallpapers on hackers, securityf, Kali Linux and all this stuff
	![[Pasted image 20250414162622.png]]
- Inside the Recycle Bin I found two JPG files. One of them was actual corrupted JPG image which copy is still stored inside the `Pictures/Private`, while another file only has `.jpg` extension, but it some file with certificates and public RSA keys for Tor Browser as far as I got (from this [`dir-key-certificate-version`](****)).
	![[Pasted image 20250414164604.png]]
	![[Pasted image 20250414164830.png]]
- Also inside the user's folder I found `.zenmap` folder with Zenmap configuration from which I figured out that the version of Zenmap is `7.12`. He scanned only `scanme.nmap.org` for training purposes maybe. I found no traces that he tried to scan his organization's network. The recent scans are saved to `C:\Users\Hunter\Desktop\nmapscan.xml`. This triggered me to check `Desktop` folder.
	![[Pasted image 20250414165450.png]]
	![[Pasted image 20250414165610.png]]
- On the Desktop he had already had all the necessary links 😄 
	![[Pasted image 20250414003827.png]]
- And bingo! The file `nmapscan.xml` was there. I immediately marked it as highly notable as you can see 😄
	![[Pasted image 20250414170422.png]]
- To see it beautiful I used [Onine Nmap Viewer](https://www.devoven.com/tools/nmap-viewer). We can see there which ports, protocols, and clients were available: OpenSSH, SMPT, RSFTP, Apache HTTP, Nping Echo, Ncat. Four of them were open (22, 80, 9929, 31337). There were 1000 ports scanned in total. However, GUI was not so detailed as XML, e.g. form XML file I also extracted the timestamp of performing this scan, again `2016-06-21`.
	![[Pasted image 20250414171437.png]]
	![[Pasted image 20250414171944.png]]
- Since I explored that BCWipe was actually used I thought that the user could use it for deleting files and applications also. So, I decided to check if BCWipe has logs about its actions. Unfortunately but not surprisingly there were no such information. However, BCWipe's directory contained exactly one `.log` file which purpose I haven't got: `UnInstall.log` file. Nevertheless, inside this file I also haven't found any interesting but the [Crypto Swap](https://www.jetico.com/file-downloads/web_help/bcwipe7/SwapFileEncryption.html) which is a function of BCWipe that allows to encrypt Windows Swap file. I haven't found if Hunter actually used it, but we should take into account that he could 
	![[Pasted image 20250413200713.png]]
#### Web history
- Analyzing files related to web browsers (Edge, Tor, Chrome), but haven't found anything really interesting, so he just visited all the sites of the tools we have already explored (Tor, FTK, BCWipe, etc.) to download them
	<img src="Pasted image 20250414173424.png" width=300 />
#### Block Devices
- I haven't found anything interesting also in USB Devices that were attached to this device. Two of them were identified.
	![[Pasted image 20250414182000.png]]
## Task 3 - Create a Forensics Report
> [!Task Description]
> Prepare a forensic report on the results of the investigation on behalf of the investigator. This should include a timestamp, evidence/artifact, proof (specify your action, tool, screenshot - if possible). Try to follow to the the generally accepted standards for the preparation of a report on forensics. [Example](https://online.fliphtml5.com/rllbc/zdmn/#p=1). However, it is not strict and mandatory to observe exactly such formatting.

- Since I did the report in a free format above I will not focus on much detail I have already mentioned because there a lot of findings as you can see. So, I will try to include the most important artifacts only:
	- Presence of attacking software
	- Conversation with `linux-rul3z` and important attachments
	- Port scanning results with Nmap
### **Innopolis University: Digital Forensics Report**
- **Prepared by**: Iskander Nafikov
- **Specialist field**: Digital Forensics
---
#### Tools
The forensic tools employed in the performance of this investigation were as follows:
- **Forensics analysis and collecting data** - AutoPsy 4.22.0
- Displaying the port scanning results - [Nmap Viewer](https://www.devoven.com/tools/nmap-viewer)
#### Analysis

| Key                  | Value                   | Found in                                      |
| -------------------- | ----------------------- | --------------------------------------------- |
| **System**           | Windows 8.1 Enterprise  | AutoPsy: OS Information                       |
| **Owner's username** | Hunter                  | AutoPsy: OS Accounts                          |
| **PC Name**          | 4ORENSICS               | AutoPsy: OS Information                       |
| **Timezone**         | Pacific Standard Time   | /img_case1.001/Windows/System32/config/SYSTEM |
| **IP address**       | 10.0.2.15/25            | /img_case1.001/Windows/System32/config/SYSTEM |
| **Login count**      | 3                       | AutoPsy: OS Accounts                          |
| **Last login**       | 2016-06-21 04:42:40 MSK | AutoPsy: OS Accounts<br>                      |

| Key                   | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Artifact Name**     | E-mail conversation with linux-rul3z@hotmail.com                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **File name**         | ehptmsgs@gmail.com.ost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **File path**         | /img_case1.001/Users/Hunter/AppData/Local/Microsoft/Outlook/<br>ehptmsgs@gmail.com.ost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Created timestamp** | 2016-06-21 16:07:07 MSK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Discovering**       | AutoPsy: Emails                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Owner's mail**      | ehptmsgs@gmail.com                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Useful Content**    | The conversation provides the following information:<br>- Hunter connected with some guy who seems to understand something in attacks / penetration testing to teach him and help him to attack or pentest some network (probably of their organization but I am not sure yet).<br>- Their dialogue established with a Hunter's message about TeamViewer which I suppose lets the other guy to access his device remotely.<br>- They conversate via E-mail and Skype.<br>- In Skype there is some password that can help to unarchive some 7-zip attachments from Hunter with pictures.<br>- The other guy sent to Hunter links on YouTube videos about Data Exfiltration and advices Hunter to disguise file using changing their extensions. So, Hunter uses this method and send him a PDF document with the JPG extension<br> |
| **Screenshot**        | ![[Pasted image 20250414201541.png]]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

| Key                     | Value                                                                                                                                                                                                                                                                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Artifact Name**       | Skype conversation with linux-rul3z@hotmail.com                                                                                                                                                                                                                                                                                            |
| **File name**           | main.db                                                                                                                                                                                                                                                                                                                                    |
| **File path**           | /img_case1.001/Users/Hunter/AppData/Roaming/Skype/hunterehpt/main.db                                                                                                                                                                                                                                                                       |
| **Created timestamp**   | 2016-06-21 12:08:36 MSK                                                                                                                                                                                                                                                                                                                    |
| **Discovering**         | AutoPsy: Data source exploration                                                                                                                                                                                                                                                                                                           |
| **Owner's Skype login** | hunterehpt                                                                                                                                                                                                                                                                                                                                 |
| **Useful Content**      | Hunter asks `linux-rul3z` to help him to transfer some pictures and documents outside an organization's network since it is monitored. This guys agreed to help him and asks if he is able to access Hunter's device remotely via TemViewer. Hunter downloaded TeamViewer and then their conversation goes to e-mail which we already saw. |
| **Screenshot**          | ![[Pasted image 20250414203724.png]]                                                                                                                                                                                                                                                                                                       |

| Key                   | Value                                                                                           |
| --------------------- | ----------------------------------------------------------------------------------------------- |
| **Artifact Name**     | Data exfiltration instructions                                                                  |
| **Folder name**       | Documents                                                                                       |
| **Folder path**       | /img_case1.001/Users/Hunter/Documents                                                           |
| **Created timestamp** | 2016-06-21 11:37:46 MSK                                                                         |
| **Discovering**       | AutoPsy: Data source exploration                                                                |
| **Useful Content**    | 5 PDF documents that provide instructions on performing data exfiltration or firewall bypassing |
| **Screenshot**        | ![[Pasted image 20250414204237.png]]                                                            |

| Key                   | Value                                                                                                                                                                                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Artifact Name**     | Attacking or suspicious software                                                                                                                                                                                                                             |
| **Folder name**       | Downloads                                                                                                                                                                                                                                                    |
| **Folder path**       | /img_case1.001/Users/Hunter/Downloads                                                                                                                                                                                                                        |
| **Created timestamp** | 2016-06-21 11:37:46 MSK                                                                                                                                                                                                                                      |
| **Discovering**       | AutoPsy: Data source exploration                                                                                                                                                                                                                             |
| **Useful Content**    | Installers or executables of the following tools:<br>- Hash Suite Free<br>- BurpSuite<br>- Eraser<br>- Putty<br>- PSCP<br>- SetupSSH<br>- SysinternalSuite<br>- Zenmap<br>- Tor Browser<br>- Wireshark<br>- Skype<br>- TeamViewer<br>- BCWipe<br>- Notepad++ |
| **Screenshot**        | ![[Pasted image 20250414205300.png]]                                                                                                                                                                                                                         |

| Key                   | Value                                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **Artifact Name**     | Port scanning results                                                                                             |
| **File name**         | nmapscan.xml                                                                                                      |
| **File path**         | /img_case1.001/Users/Hunter/Desktop/nmapscan.xml                                                                  |
| **Created timestamp** | 2016-06-21 15:13:57 MSK                                                                                           |
| **Scan target**       | scanme.nmap.org (45.33.32.156)                                                                                    |
| **Discovering**       | AutoPsy: Data source exploration                                                                                  |
| **Useful Content**    | Hunter used Zenmap actually to make port scanning, but for training purposes only on the website: scanme.nmap.org |
| **Screenshot**        | ![[Pasted image 20250414205757.png]]                                                                              |
#### Opinion based on findings
Summing up all the artifacts found, I can summarize that Hunter tried to upload pictures and documents containing the organization's documentation, despite the fact that this is prohibited. He spent some time studying data exfiltration, hacking, firewallbypassing techniques and consulted with an outsider via E-mail and Skype. There is reason to believe that he is not an expert in this field, so he resorted to numerous training materials and consultations. Unfortunately, it is not known for sure whether Hunter achieved the desired result, but since this image ended up in my hands, it was probably quickly detected when trying to perform data exfiltration using constant network monitoring. Nevertheless, he definitely had the intention to steal the organization's data.