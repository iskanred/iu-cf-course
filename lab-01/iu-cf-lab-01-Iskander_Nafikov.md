- **Name**: Iskander Nafikov
- **E-mail**: [i.nafikov@innopolis.university](mailto:i.nafikov@innopolis.university)
- **GitHub**: [https://github.com/iskanred](https://github.com/iskanred)
---
>[!Task Description]
> This lab will introduce you to forensic imaging and data handling using a live environment.
> You also will work in groups (2 persons per group) in Task 3
# Task 1 - Setting up your environment
>[!Task Description]
> You need to prepare 2 USB drives. The first one should have a [CAINE live environment](https://www.caine-live.net/) that will be used to collect evidence. On the second one (this drive will be called drive A) you should deploy that [disk image](https://mega.nz/file/CdtQjKgC#90sNQGrcrlJxcFKa-Cs-ZoitWuMwQ8k4MEaZd6qZLKU). The disk image is compressed with special utility that preserves original bits intact. You should uncompress it (using [FTK imager](https://go.exterro.com/l/43312/2023-05-03/fc4b78)) and burn it on the flash drive (do not forget about unallocated space).
- So, I prepared two USB drives
- Firstly, I downloaded CAINE ISO images from the official website
	![[Pasted image 20250323165111.png]]
- The instruction on the website stated that it's better to compare checksums to prove image's integrity
	![[Pasted image 20250323164756.png]]
	![[Pasted image 20250323164745.png]]
	✅
- Then I wrote CAINE live CD/DVD image to the first one drive using [UltraISO](https://en.wikipedia.org/wiki/UltraISO)
	![[Pasted image 20250323164302.png]]
- Secondly, I uncompressed the image of the evidence to my host machine using `dd` method to keep unallocated space too.
  ![[Pasted image 20250323170823.png]]
	![[Pasted image 20250323170944.png]]
	![[Pasted image 20250323171526.png]]
- Finally, I wrote this disk image to my second USB flash drive using [Rufus](https://rufus.ie/en/)
	<img src="Pasted image 20250323172450.png" width=500/>
---
# Task 2 - Imaging
## 1.
> [!Task Description]
> Discuss how you can retrieve an image from an, currently off-line, USB stick in a forensically sound manner. Create and describe this method.

1. **Boot CAINE**: Start your system using the CAINE Live CD/USB. Ensure you're using a read-only medium or a properly installed CAINE to prevent altering the evidence.
2. **Connect the USB Stick**: Insert the USB stick into the machine running CAINE. Make sure to note which device it is using `lsblk` (e.g., `/dev/sdb`).
3. **Create a Forensic Image**: We can use `dd` or `Guymager` to create a bit-by-bit copy of the USB stick. This process is crucial as it preserves the original data by creating a forensic image. It's better to choose `E01` image format since `E01` images contain a lot of additional integrity data that makes it easy to check if the image file is damaged or modified and where.
4. **Calculate and Verify Checksums**: Finally, we should check image's integrity comparing all the necessary `MD5` and `SHA1` checksums which are computed by `Guymanager` automatically or we can do this manually using `md5sum`, `sha1sum`. This is also a crucial step to be sure that the `E01` image was stored without any issues and it contains exactly the same data as USB drive does.
5. **Start analysis and documentation**: Register the timestamp right after creating the `E01` image and start analysis and reporting the image.
## 2.
> [!Task Description]
> Write a one-line description, or note a useful feature for the following tools included in CAINE: `Guymager`, `Disk Image Mounter`, `dcfldd` / `dc3dd`, `kpartx`.

- **Guymager**: A graphical tool for creating and verifying forensic disk images, supporting multiple image formats and hash verification for ensuring data integrity.
- **Disk Image Mounter**: This tool allows for easy mounting of disk images as virtual filesystems, enabling forensic analysis of the contents without altering the original image.
- **dcfldd / dc3dd**: Enhanced versions of `dd` that include features for hashing on-the-fly, progress monitoring, and error recovery, making them ideal for forensic imaging.
- **kpartx**: A utility that creates device mappings for partitions within disk images, allowing users to easily access and interact with individual partitions for forensic analysis.
- **Autopsy**: A web-based forensic analysis tool.
- **The Sleuth Kit**: Command-line analysis tools for filesystems.
- **TestDisk**: For data recovery from lost partitions.
- **dmesg**: For viewing kernel messages, which are useful in troubleshooting.
## 3.
> [!Task Description]
> Follow your method to retrieve the image from drive A. Please use timestamps, explain every tool and note down the version. For the purpose of speed. Make sure both team members have access to the retrieved image. You can use your PCs as an evidence sharing platform

- I ran `lsblk` and detected that `/dev/sda` is my USB flash drive since it has `sda1` partition with 3 Gb of memory which is exactly the size of the burnt image
	![[Pasted image 20250323230340.png]]
- So then I ran Guymager tool
	![[Pasted image 20250323230449.png]]
- I acquired the image, input necessary fields and selected toggles: MD5, SHA-1, SHA-256 and re-read source for double verification.
	![[Pasted image 20250323231153.png]]
- I started acquisition at `20:47:50` and it took `22:13` minutes.
	![[Pasted image 20250324000504.png]]
- We already see that the image was verified successfully but I still checked the `evidence.info` to check hash values manually
	![[Pasted image 20250324000644.png]]
- So now we see that everything was OK ✅
## 4.
> [!Task Description]
> Read about CAINE Linux and its features while waiting on the dump to finish.

- **CAINE** (Computer Aided INvestigative Environment) is a Linux-based distribution designed for digital forensics, providing a comprehensive suite of tools for data recovery and analysis. 
- It operates as a **live system**, allowing users to boot from USB or DVD without altering the host machine, which is crucial for preserving evidence integrity.
- CAINE **defaults to read-only mounting** of storage media to ensure that original data remains unaltered during investigations, and it **supports a variety of filesystems**, enabling forensic examination across different storage devices.
- The distribution includes **user-friendly forensic tools** such as Guymager, Autopsy, and The Sleuth Kit, facilitating both novice and expert users in their analysis. 
- With **extensive documentation and community support**, CAINE is an essential tool for forensic investigators and law enforcement professionals executing nonintrusive evidence collection and thorough analyses.
### 4.1.
> [!Task Description]
> Why would you use a Forensic distribution and what are the main differences between a regular distribution?

1. **Toolset**: Forensic distributions come preloaded with specialised forensic tools for data recovery and analysis, while regular distributions include general-purpose software that often requires separate installations for similar tools.
2. **Default Behavior**: Forensic distributions typically mount drives in read-only mode to prevent data alteration, whereas regular distributions generally use read-write access by default.
3. **User Interface**: Forensic distributions feature interfaces optimised for investigative workflows, including guided processes and reporting, while regular distributions focus on general usability for everyday tasks.
4. **Security Features**: Forensic distributions prioritise maintaining evidence integrity and often include built-in security measures, while regular distributions lack these specialised protections.
5. **Compliance Standards**: Forensic distributions are designed to comply with legal standards and best practices in forensic investigations, unlike regular distributions, which may not consider these requirements.
### 4.2.
> [!Task Description]
> When would you use a live environment and when would you use an installed environment?

- You would use a **live environment** for CAINE when conducting forensic investigations on a potentially compromised machine, as it allows you to operate without altering the system or its data, preserving the integrity of the evidence. This setup is ideal for initial data collection and analysis in the field or when working with sensitive evidence.
- An **installed environment** would be more suitable for prolonged analysis, extensive data processing, or when utilizing advanced tool configurations, as it provides enhanced hardware support and allows for faster access to resources. Additionally, an installed environment is beneficial for users who require a stable operating platform for ongoing forensic training or complex investigations that demand multiple tools and applications.
### 4.3.
> [!Task Description]
> What are the policies of CAINE?

1. **Preservation of Evidence**: CAINE emphasises the importance of maintaining the integrity of digital evidence. Tools and processes are designed to prevent any alteration of original data during forensic analysis.
2. **Non-Intrusiveness**: The live environment allows users to conduct investigations without interacting with the host operating system, which helps protect the evidence from being compromised.
3. **Open Source Philosophy**: CAINE adheres to the principles of open source software, promoting transparency, collaboration, and community-driven development. Users are encouraged to contribute to the improvement of tools and solutions.
4. **Compliance with Legal Standards**: The tools and practices supported by CAINE are intended to align with legal standards and best practices in digital forensics, ensuring that evidence can be utilised in legal contexts without issues regarding admissibility.
5. **User Education and Support**: CAINE prioritises education through documentation, tutorials, and community support, enabling users, particularly those new to forensic investigations, to understand and effectively utilize the tools available.
6. **Community Contribution**: The CAINE community encourages feedback, contributions, and collaboration among users to continuously enhance the functionality and usability of the distribution.
## 5.
> [!Task Description]
> As soon as your dump finishes, start a tool to create a timeline on the image. You will need this timeline later in the assignment. Hints: `log2timeline.py`.

- I used the pre-installed `log2timeline.py` tool from the [Plaso](https://plaso.readthedocs.io/en/latest/) forensics analysis framework. This tool extracts timestamped events from the image and generates a timeline in the Plaso format.
	```shell
	log2timeline.py --partitions all --storage_file timeline.plaso evidence.E01
	```
	![[Pasted image 20250324003330.png]]
- I generated the Plaso timeline and exported it to CSV format it using `psort.py`
	```shell
	psort.py -w timeline.csv timeline.plaso
	```
	![[Pasted image 20250324004544.png]]
- Finally, I was able to see these logs. There are almost 490,000 logs are here, so it must be difficult to analyze
	![[Pasted image 20250324033114.png]]
- 
---
# Task 3 - Verification
> [!Task Description]
> Verification of the retrieved evidence is also required. You are going to exchange your evidence between your group of students. This can be done by sharing your USB device (drive A) with your teammate.
## 1.
> [!Task Description]
> Create and describe a method that enables the verification of your method. Write this down in steps that your teammate can follow.
### Preparation steps for a sender

1. First, I ran the following command to convert `.ewf` (`.e0{N}`) file into a `.raw` file.
	```shell
	ewfexport evidence.E01 # in the suggested options name the output file `verify.raw`
	```
2. Now the sender has the `verify.raw` file, so he should burn this file to the flash drive using `dcfldd` also computing the checksum hash values:
	```shell
	sudo dcfldd if=verify.raw of=/dev/sd{device}{partition} hash=md5,sha256 md5log=md5.txt sha256log=sha256.txt conv=sync,noerror bs=512 hashconv=after
	```
	- **`dcfldd`**: It is a modified version of `dd` that provides additional features for forensic purposes, such as hashing and logging.
	- **`if=evidence.raw`**: The `if` (input file) option specifies the input file to be read, which in this case is `evidence.raw`.
	- **`of=/dev/sdb`**: The `of` (output file) option specifies the output destination. In our case it must be the USB flash drive we want to transfer to our partner.
	- **`hash=md5,sha256`**: This option indicates that `dcfldd` should calculate both MD5 and SHA256 hashes of the input data as it is being processed.
	- **`md5log=md5.txt sha256log=sha256.txt`**: These options specify the filenames (`md5.txt`, `sha256.txt`) where the MD5 and SHA256 hash logs will be written.
	- **`conv=sync,noerror`**: These options tell `dcfldd` to pad the output blocks with zeroes if they are less than the specified block size, ensuring that the output remains consistent and aligned with no error produced, which is important for forensic purposes .
	- **`bs=512`**: This option sets the block size for reading and writing to 512 bytes. This is a common block size for disk operations and can improve performance during the copying process.
	- **`hashconv=after`**: This option indicates that the hashing should be computed after the data transfer is complete; this ensures that the entire output is hashed rather than hashing as the data is being read and written simultaneously.
3. Now the image is burnt to the USB flash drive (`/dev/sd{device}{partition}`) and its MD5 and SHA256 checksums are stored in the `md5.txt` and `sha256.txt` correspondingly. The sender now should share the USB drive with the receiver, along with the hash values (from `md5.txt` and `sha256.txt`).
### Verification steps for a receiver
1. Receive suspected USB drive, `md5.txt` and `sha256.txt` files.
2. Insert the USB drive and determine USB name ( e.g., `/dev/sdb`) using `lsblk` or `dmesg`:
	```shell
	sudo dmesg | tail tee
	```
3. Display the the information about the drive. It should be the same as I provided (look at the screenshot below)
	```shell
	cat /proc/scsi/usb-storage/{number}
	```
	![[Pasted image 20250325013511.png]]
4. Check the size of the block device (USD drive) and other parameters. They should be the same as I provided (look at the screenshot below)
	```shell
	sudo fdisk -l /dev/sdb
	```
	![[Pasted image 20250325013924.png]]
5. Create directories for further mount and logs
	```shell
	mkdir /evidence      # for hash logs
	mkdir /mnt/evidence  # to mount copied disk for analysis
	```
6. Now copy the content of the flash drive to a new disk image and compute MD5 and SHA256 hash values using `dcfldd`
	```shell
	dcfldd if=/dev/sdb1 of=/mnt/evidence/image.raw hash=md5,sha256 md5log=/evidence/md5.txt sha256log=/evidence/sha256.txt sizeprobe=if conv=sync,noerror hashconv=after
	```
7. Compare the calculated hashes in `/evidence/md5.txt` and `/evidence/sha256.txt` with those provided by me (from `md5.txt` and `sha256.txt` correspondingly).
8. If they match everything is okay! If not => evidence was corrupted, do not trust it!
## 2.
> [!Task Description]
> Exchange USB images with your partner. Verify the procedure that he used and the resulting image. Write a small paragraph of max 200 words. Write as if you were verifying the evidence gathering procedure for a court case.

We did this task together with with Mohamad Bahja ([m.bahja@innopolis.university](mailto:m.bahja@innopolis.university))
### My actions as a sender
As a sender I completed all the steps I described above ⬆️
1. I started with decompressing `E01` to `raw`:
	![[Screenshot at 2025-03-24 21-20-51.png]]
2. Then I burned the image to my USB flash drive with computing its SHA256 and MD5 hash values
	![[Screenshot at 2025-03-24 21-52-56.png]]
3. Finally, I provided the flash drive to Mohamad alongside with the `md5.txt` and `sha256.txt` files.
	<img src="Pasted image 20250325020432.png" width=500 />
### My actions as a receiver
As a receiver I again completed all the steps I described above ⬆️
1. I received a USB stick from Mohamad together with his `md5.txt` and `sha256.txt`
	<img src="Pasted image 20250325020545.png" width=500 />
2. I plugged it to my PC, ran `dmesg` to figure the name of this block device. The name was `dev/sdb` and a partition was `/dev/sdb1`
	![[Pasted image 20250325012501.png]]
3. After, I displayed information about this flash drive in `/proc/scsi/usb-storage/` and ensured that this info was the same: Netac OnlyDisk.
	![[Screenshot at 2025-03-24 23-16-19.png]]
4. I checked the size of the image and also ensured it was the same: `15728640` sectors
	![[Screenshot at 2025-03-24 23-18-29.png]]
5. I created directories for further mount and hash logs
	![[Pasted image 20250325025415.png]]
6. Then I copied the content of the flash drive to a new disk image and computed MD5 and SHA256 hash values using `dcfldd`:
	![[Pasted image 20250326234821.png]]
7. I compared the hashes I computed and the hashes from Mohamad and found they match, so everything is okay and USB flash drive was not corrupted! 
	![[Pasted image 20250327001841.png]]
---
# Task 4 - Technical analysis

## 1.
> [!Task Description]
> Mount your image (image of drive A) and make sure that it is mounted as read-only.

- To mount the suspected drive to the system I used the easisest method with Mounter pre-installed application
	![[Pasted image 20250326235246.png]]
	![[Pasted image 20250326235305.png]]
- Finally, I checked that my device is mounted in read-only now
	```shell
	cat /proc/mounts
	```
	![[Pasted image 20250326235332.png]]
	> Note: This flags (`ro`, `noexec`, etc) are essential not to alter the evidence
- We could do the same with `mount` command specifying flags and calculating offsets and sizelimits but it is simply harder :)
## 2.
> [!Task Description]
> Identify and write a small paragraph of max 200 words about what kind of image it is. Don’t go into file specific details just yet. This includes but is not limited to:
> - What is the size of the image?
> - What partition type(s) does this image have?
> - Does it have an MBR/GPT?
> - etc.

- To check the size of image I used `fdsk`. The size is 7.52 GiB
	```shell
	sudo fdisk -l /dev/sdb
	```
	![[Pasted image 20250326231129.png]]
- To check partition type(s) I used `blkid`. The partition type is NTFS, the block size is default $=512$ 
	```shell
	sudo blkid /dev/sdb1
	```
	![[Pasted image 20250326231211.png]]
- To check MBR/GPT record I used `gdisk`. We see MBR was there but GPT was invalid and there is an overlap.
	```shell
	sudo gdisk /dev/sdb1
	```
	![[Pasted image 20250326231326.png]]
	
- In total I can state that:
	The 3 GiB disk image contains a corrupted MBR partition table with nonsensical entries, such as 866 GiB partitions on a 3 GiB disk. Although I found the presence of an NTFS filesystem, `gdisk` reports invalid overlaps and alignment problems with the GPT. The discrepancies between the MBR and GPT structures point to significant corruption, most likely resulting from unsuccessful partitioning or formatting attempts. In its current condition, the disk's metadata is damaged and cannot be utilised.
## 3.
> [!Task Description]
> Using the information from the timeline you create above, write a small paragraph on what you think happened on this specific USB device. The device owner is suspected in a crime. Try to find the evidence that can support this accusation. Please remain objective, as you would be preparing evidence for a court case. Make it a maximum of 300 words, and use timestamps

- First, I downloaded AutoPsy for Windows since it is more modern that is default used in Caine.
	![[Pasted image 20250326230518.png]]
- `22:40`: I entered the system and started the search
	![[Pasted image 20250326234151.png]]
-  `22:52` I felt into user's search history and found something interesting. Why he would need `trucrypt` and `veracrypt`
	![[Pasted image 20250326234344.png]]
- `22:55` I made an assumption that the user actually downloaded and installed these crypto programs
	![[Pasted image 20250326234532.png]]
- `23:32` I found he searched for artifact hiding, therefore I made an assumption he wanted to hide something after the some crime. It was one day before the installing crypto programs (`2016-08-25`).
	![[Pasted image 20250326235626.png]]
- `23:41` Also, I found that the user removed Mozilla cache file for some reason
	![[Pasted image 20250327000637.png]]
- `23:56` I found many text and HTML files that contained JavaScript snippets to extract some info from the client such as cookies
	![[Pasted image 20250326235907.png]]
	![[Pasted image 20250327000116.png]]
- `00:13` Also, I found many suspicious addresses
	![[Pasted image 20250327000944.png]]
- `00:16` Also, I found funny hints
	![[Pasted image 20250327000537.png]]
- `00:21` Finally, many suspicious cookies was found with repetitions and non-real usernames
	![[Pasted image 20250327001232.png]]
- `00:34` So, based on all this information I made an assumption that:
	```
	The user was involved in cookie theft, as evidenced by a significant collection of cookies from various websites. These cookies were likely exploited to create fraudulent sessions impersonating victims. His Google search history suggests attempts to obfuscate his activities, indicating a conscious effort to hide his actions.
	
	Additionally, numerous suspicious JavaScript scripts were found embedded in HTML pages, along with fake email addresses in his address book, hinting at possible spamming schemes. He downloaded security tools like TrueCrypt and VeraCrypt while on Windows 10, which may have been used for file encryption or concealment.
	
	There is a strong likelihood that he distributed binary files to capture cookies and manipulated the Zone Identifier to alter Alternate Data Streams on victims' systems. His deliberate erasure of web cache further points to a sophisticated understanding of digital forensics and cybercrime. Lastly, his use of OneDrive indicates potential file transfer between multiple devices.
	```
### 4.
> [!Task description]
> What would help to investigate this evidence further?

- Analysis of files and directories for deeper insights.
- Examination of deleted files and those with Unicode-based names.
- Reviewing raw file content and extract hexadecimal and ASCII strings.
- Performing a hash database check to assess potential malicious activity.
- Establishing a timeline of file activity to reveal system interactions and highlight evidence.
- Analyzing timestamps for valuable information on the sequence of events and data recovery.
- Conducting metadata analysis to recover deleted content and identify file locations.
- Correlating time-based events (file modifications, IDS alerts, firewall logs) for a comprehensive view of network activity.
