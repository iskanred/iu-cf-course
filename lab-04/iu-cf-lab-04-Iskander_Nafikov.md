- **Name**: Iskander Nafikov
- **E-mail**: [i.nafikov@innopolis.university](mailto:i.nafikov@innopolis.university)
- **GitHub**: [https://github.com/iskanred](https://github.com/iskanred)
---
# CCF Lab 4 - Incident response and log management
> [!Task Description]
> In this lab, you will set up a complete environment for detecting and responding to security incidents using the Wazuh security platform. You will simulate real-world attacks, configure automated responses, and explore best practices for managing logs and system alerts. This hands-on exercise is designed to reinforce key concepts in incident detection, active response, and log retention.

## Task 1 - Preparation
---
### 1.
> [!Task Description]
> Deploy Wazuh central components (server, indexer, and dashboard) on your host machine or use an alternate method like Docker.

- First, I deployed 3 VMs inside the GNS3
	![[Pasted image 20250427201807.png]]
- I entered the Wazuh server (manager + indexer + dashboard) VM and exported `$TYPE` environment variable
	![[Pasted image 20250427201348.png]]
- Then I installed the Wazuh following the [Quickstart](https://documentation.wazuh.com/current/quickstart.html) instruction from the official website
	![[Pasted image 20250427203433.png]]
- Finally, I was able to access Wazuh dashboard through HTTPS
	![[Pasted image 20250427205338.png]]
- After logging in with generated password I went to the Dashboard's 
	![[Pasted image 20250427205443.png]]
- As we see Wazuh components were deployed as `systemd` services
	![[Pasted image 20250427205723.png]]
### 2.
> [!Task Description]
>Set up a second machine with a Unix-like OS, install the Wazuh agent, and enroll it with the Wazuh manager. Enable SSH and create a test user account.
- I entered the Wazuh agent for Ubuntu VM  and exported `$TYPE` environment variable
	![[Pasted image 20250427201603.png]]
- I deployed an agent using the generated command on the Wazuh Dasbhoard
	![[Pasted image 20250427210252.png]]
- Finally, I launched the `systemd` service of the Wazuh Agent
	![[Pasted image 20250427210414.png]]
- After this I could see this agent on the Wazuh Dasbhoard
	![[Pasted image 20250427210527.png]]
- Also, I could see its logs
	![[Pasted image 20250427210836.png]]
### 3.
> [!Task Description]
> Prepare a third machine to act as the "attacker" endpoint to simulate cyber attacks. You can collaborate with your colleagues to simulate attacks if you don't have enough hardware resources for three machines.
- I entered the attacker's Ubuntu VM  and exported `$TYPE` environment variable
	![[Pasted image 20250427201632.png]]
## Task 2 - Configure active response
---
### 1.
> [!Task Description]
> Enable the Wazuh active response feature to disable a user account for 10 minutes when a brute force attempt is detected.
#### Configuration
- Firstly, I found an [instruction](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/disabling-user-account.html) how to disable Linux user account in case of brute force attack on the Wazuh official website
	![[Pasted image 20250428015016.png]]
- Following the instruction I added a new alert group and a rule inside it that detects "possible password guess" for a specific user on the Wazuh Server. I made the rule triggered after 4 failed login tries in one minute. Also, I assigned the MIT&RE attack ID $=T1110$ which is a [Brute Force](https://attack.mitre.org/techniques/T1110/).
	![[Pasted image 20250428020350.png]]
-  I made sure that there is a `disable-account` command listed inside the `/var/ossec/etc/ossec.conf
	![[Pasted image 20250428021010.png]]
- Then I added a new active response action inside the `/var/ossec/etc/ossec.conf`. This action executes `disable-account` command whenever the rule with ID $=120100$ (which is a rule I defined to detect a brute force attack) is triggered. Also, we that this action has a required timeout for 10 minutes (600 seconds). After that period, the Active Response reverts its action and re-enables the account.
	![[Pasted image 20250428022031.png]]
- Finally, to apply new changes I restarted the `wazuh-manager` daemon
	![[Pasted image 20250428022640.png]]
### 2.
> [!Task Description]
> Also configure it to block the attacker's IP address for 10 minutes.
- Now I need to perform similar action. The packets from attacker's IP must be dropped for 10 minutes if the brute force is detected. I found an  [instruction](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/index.html) that is pretty similar to the previous one on the Wazuh official website.
- First, let's start with making sure that the `firewall-drop` command exists inside the Wazuh Manager config 
	![[Pasted image 20250428030621.png]]
- Then I added a new active response action that drops attacker's packets if the same rule with ID $=120100$, which I defined in the previous sub-task, is triggered
	![[Pasted image 20250428033256.png]]
- Finally, I again restarted the Wazuh Manager daemon 
	![[Pasted image 20250428031832.png]]
### 3.
> [!Task Description]
> Create `/home/<USERNAME>/malwarefiles/` on the monitored endpoint. Integrate malware detection (e.g., VirusTotal or YARA), and monitor this directory for malware. Configure Wazuh to automatically delete detected malware files.
- Again, I found a useful [instruction](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html) to detect and delete malware files using VirusTotal on the Wazuh official website.
- First, I signed up VirusTotal to obtain an API key in order to allow Wazuh to make requests for checking a file.
	![[Pasted image 20250428042300.png]]
#### Wazuh Agent
- Then I made sure that the FIM is enabled on the `wazuh-agent` inside the `/var/ossec/etc/ossec.conf` config. 1. Wazuh FIM looks for any file addition, change, or deletion on the monitored folders. This module has the hash of these files stored and triggers alerts when it detects any changes.
	![[Pasted image 20250428040719.png]]
- Then I also added `/home/ubuntu/malwarefiles` to be monitored in near real-time.
	![[Pasted image 20250428041150.png]]
- Afterwards, I installed `jq` tool which will help us to read a log easily in order to make proper active response actions
	![[Pasted image 20250428041958.png]]
- Then I copied an active response script that removes malware file.
	![[Pasted image 20250428042526.png]]
- Moving further, I changed the permissions and file ownership for this script in order to allow only Wazuh Agent to run it.
	![[Pasted image 20250428042944.png]]
- Finally, I restarted the Wazuh Agent daemon on my `wazuh-agent` endpoint
	![[Pasted image 20250428043131.png]]
#### Wazuh Server
- I added two new rules that are triggered whenever a file was added or modified inside the `/home/ubuntu/malwarefiles` directory
	![[Pasted image 20250428044337.png]]
- These rules are triggered when FIM basic rules are triggered
	![[Pasted image 20250428044812.png]]
- Then I added VirusTotal integration inside the Wazuh Manager config. My API Key is masked. This allows to trigger a VirusTotal query whenever any of the rules `100200` and `100201` are triggered.
	![[Pasted image 20250428045323.png]]
- Also, I added a `remove-threat` command that executes my `remove-threat.sh` script created above and `remove-thread` active response action that uses this command whenever a rule with ID$=87105$ is triggered.
	![[Pasted image 20250428050931.png]]
- The rule `87105` is triggered when VirusTotal detects a malware inside the file sent to it.
	![[Pasted image 20250428051241.png]]
- Then I added two more rules that says if removing a malware file was successful or not
	![[Pasted image 20250428052528.png]]
- The rule `657` is triggered whenever an active response action is done
	![[Pasted image 20250428052609.png]]
- Finally, I restarted Wazuh Manager daemon
	![[Pasted image 20250428052738.png]]
- To sum up the steps to detect, remove, and notify are the following:
	1. FIM detects a file added or modified inside the `/home/ubuntu/malwarefiles` 
	2. The rules about file addition modification is triggered
	3. Modified or added files are sent to the VirusTotal
	4. After VirusTotal returns the result Wazuh checks if files are malware
	5. If so, the active response is started: the files are removed.
	6. If removal is successful, the rule is triggered
	7. If not, another rule is triggered
## Task 3 - Simulate attacks
---
### 1.
> [!Task Description]
> Launch an SSH brute force attack from the attacker endpoint against the test user
- First, I created a test user on the `wazuh-agent`
	![[Pasted image 20250428060635.png]]
- Also, I installed [hydra](https://github.com/vanhauser-thc/thc-hydra) tool on the `attacker` machine. This tool allows to make brute force attacks easily.
	![[Pasted image 20250428055354.png]]
- I created 4 password to make 4 login tries through SSH
	![[Pasted image 20250428063209.png]]
- I started a brute force attack which was completed quickly with exactly 4 login tries
	![[Pasted image 20250428061732.png]]
### 2.
> [!Task Description]
> Show relevant alerts on the Wazuh dashboard.
- Below we see that the alerts actually appeared on the dashboard
	![[Pasted image 20250428062712.png]]
- From them we can see that the MIT&RE attack type was successfully recognized (Brute Force). We see the attacker's IP address and rules description.
	- `Host Blocked`
	- `disable-account - add`
- Also, we see alerts that also notifies us about disabling applied active response actions after exactly 10 minutes
	- `Host Unblocked`
	- `disable account - delete`
### 3.
> [!Task Description]
> Provide evidence that the user account was disabled and the attacker IP blocked. Include dashboard alerts and screenshots from the endpoint involved.
- We see that the attacker's **IP address was blocked** since an attacker cannot successfully ping the `wazuh-agent` endpoint
	![[Pasted image 20250428061854.png]]
- Meanwhile, ping requests were sent successfully but with no reply
	![[Pasted image 20250428062039.png]]
- Also, we see that the `test1` **user account was disabled**
	![[Pasted image 20250428062135.png]]

	![[Pasted image 20250428062237.png]]
- And after 10 minutes everything works again
	![[Pasted image 20250428063113.png]]
	![[Pasted image 20250428063133.png]]
### 4.
> [!Task Description]
> Download a malware sample into the `/home/<USERNAME>/malwarefiles/` directory. Confirm detection and show that it was automatically removed.
- First, let me check if our rules work correctly
- I added a new file to the `/home/ubuntu/malwarefiels/` directory which is a safe empty file
	![[Pasted image 20250428221620.png]]
- And we can instantly see the alerts fired on Wazuh Dashboard
	![[Pasted image 20250428221929.png]]
- We see that this file was not malware. Hence, it was not removed
	![[Pasted image 20250428222100.png]]
- Now let's check a malware file
- I downloaded a file that is used to check if antivirus software works: [eicar.com](https://www.eicar.org/download-anti-malware-testfile/)
	![[Pasted image 20250428222342.png]]
- As we see the file was actually created
- However, it had been quickly deleted
	![[Pasted image 20250428222620.png]]
- And on the dashboard we can see that the files was actually sent to VirusTotal and deleted after
	![[Pasted image 20250428223124.png]]
## Task 4 - Log management
---
### 1.
> [!Task Description]
> Define what a log retention policy is.
- A **log retention policy** is a defined set of guidelines that specifies how long log records should be retained, stored, and eventually deleted. This policy typically considers factors such as:
	- Compliance requirements: Meeting legal or regulatory mandates concerning data retention.
	- Storage limitations: Managing disk space and storage costs by determining how long logs should be kept.
	- Operational needs: Establishing a timeframe for which logs are useful for troubleshooting, auditing, or performance monitoring.
- A well-defined log retention policy helps organizations balance the need for retaining logs for analysis and compliance against the costs and risks associated with storing large volumes of data. 
### 2.
> [!Task Description]
> Explain how logs are rotated on Linux and how disk space is managed in relation to logs.
#### How logs are rotated
- **Log rotation** is the process of renaming, archiving, and managing log files to prevent them from consuming excessive disk space while maintaining a manageable history of log entries for analysis and auditing. In Linux, log rotation is typically handled by tools and services such as **`logrotate`**. It is configured through a set of configuration files (commonly located in `/etc/logrotate.conf` and individual configuration files in `/etc/logrotate.d/`).
	![[Pasted image 20250428224348.png]]
- `logrotate` allows customization of rotation policies, including:
	- **Frequency**: Logs can be rotated daily, weekly, monthly, or based on size.
	- **Retention**: Determine how many old log files to keep (e.g., keep the last 4 rotated logs).
	- **Compression**: Old logs can be compressed (e.g., using gzip) to save disk space.
	- **Post-rotation actions**: Commands can be specified to run after rotation, such as restarting services (e.g., systemd services or rsyslog).
- Example of a `logrotate` configuration:
	```shell
    /var/log/example.log {
	    daily                  # Rotate daily
	    missingok              # Don't throw an error if the log file is missing
	    rotate 7               # Keep the last 7 logs
		compress               # Compress old logs
        delaycompress          # Delay compression until the next rotation
        notifempty             # Do not rotate the log if it is empty
        create 0640 root adm   # Create a new log file with given permissions and ownership
        sharedscripts          # Run post-rotate scripts only once for multiple logs
        postrotate
			systemctl reload example.service
		endscript
    }
	```
- Example of a `logrotate` configuration from the `wazuh-server` machine
	![[Pasted image 20250428224646.png]]
- Program-specific configs
	![[Pasted image 20250428224802.png]]
- Example of a `rsyslog` logrotate config which I found on the `wazuh-server`
	![[Pasted image 20250429010757.png]]
#### How disk space is managed in relation to logs
- **Space Consumption**. Logs can grow rapidly, depending on the amount of data generated by applications and services. Without proper management, logs can fill up disk space, leading to system performance issues and potential service interruptions.
- **Preventing Disk Full Conditions**. Using log rotation helps prevent disk full conditions by periodically cleaning up old log files. By specifying retention periods and ensuring that logs are compressed, organizations can effectively manage disk space usage.
- **Monitoring Disk Usage**. It's important to monitor disk usage statistics regularly to ensure that log rotation is effectively reducing space usage. Tools like `du`, `df`, and logging monitoring frameworks can help track how much space is consumed by logs.
- **Archiving and Offloading**. In some cases, organizations may need to archive old logs for future reference or compliance. This can involve transferring old log files to secondary storage or a centralized log management solution, such as using services like [ELK](https://www.elastic.co/elastic-stack) stack, [Splunk](https://splunk.com/), or [SageDB](https://rnd.tbank.ru/technologies/sage-bd/).
### 3.
> [!Task Description]
> Create a configuration to automatically delete Wazuh alert log files older than 90 days
- I have read that actually "By default, the Wazuh server retains logs and does not delete them automatically. However, you can choose when to manually or automatically delete these logs according to your legal and regulatory requirements." So that's why we actually may need to configure log retention!
- I explored that alert log files are stored on Wazuh Manager or `wazuh-server` in my case inside the `/var/ossec/logs/alerts/` directory
	![[Pasted image 20250429003000.png]]
- Both `alerts.log` and `alerts.json` keep the same logs in a different format, while `2025` directory stores only compressed log files and their checksum that are signed daily
	![[Pasted image 20250429003324.png]]
- As we see both files have no information about `Apr 27` logs
	![[Pasted image 20250429005615.png]]
- While for `Apr 28` (today) there are lots of log records
	![[Pasted image 20250429005721.png]]
- From all this I inferred that Wazuh Server already rotates logs daily! Then I found [proofs](https://github.com/wazuh/wazuh/blob/v4.4.0/src/client-agent/rotate_log.c) of this inference. However, as far as I got this works only together **`monitord`** component which is responsible for "product" logs (`ossec.log`, `logs/wazuh`, not "event" (`logs/alerts`, `logs/archives`, etc.). But **`analysisd`** component is responsible for event logs.
	![[Pasted image 20250429022037.png]]
	![[Pasted image 20250429022118.png]]
- After I realized it, I tried to find some setting for Wazuh Server configuration to enable log retention for event logs. However, after a small research I found an official [issue](https://github.com/wazuh/wazuh/issues/3072) that states that log rotation mechanism for event logs will become configurable only in version 5.0 which is not released yet 😞
	![[Pasted image 20250429020342.png]]
- Also, I haven't found a possibility to disable default log rotation policy. There were some [closed issues](https://github.com/wazuh/wazuh/issues/2964) only. Therefore, I cannot inject my own log rotation and retention mechanism such as **logrotate**
- Hence, the only option to make log retention I had is to write my own script making it a cron job.
- Below is the my script
	```bash
	#!/bin/bash
	
	BASE_DIR="/var/ossec/logs/alerts"
	
	# retention after 90 days
	OLD_DATE=$(date -d '90 days ago' '+%Y-%b-%d')
	OLD_YEAR=$(date -d "$OLD_DATE" '+%Y')
	OLD_MONTH=$(date -d "$OLD_DATE" '+%b')
	OLD_DAY=$(date -d "$OLD_DATE" '+%d')
	
	find "$BASE_DIR/$OLD_YEAR/$OLD_MONTH" -type f -name "ossec-alerts-$OLD_DAY.*" -exec rm -f {} \;
	```
- And here is the configuration of a cronjob that runs my script 3 times a day (at 6am, 12pm, 6pm) every day.
	```
	0 6,12,18 * * * /path/to/your/script/clean_old_logs.sh
	```
- So, I created my script on the `wazuh-server`
	![[Pasted image 20250429025707.png]]
- And created a cronjob
	![[Pasted image 20250429025849.png]]
## Bonus
---
### 1.
>[!Task Description]
> What are indices, and how do they differ from log files?
#### Definition
- An **index** in Elasticsearch or similar log database (such as Wazuh Indexer) is a collection of documents that share similar characteristics. It is akin to a database in traditional relational database management systems. Each index is essentially a **data structure optimized for fast search and retrieval operations**. Indices hold documents in a format that Elasticsearch can efficiently process. Each document represents a discrete piece of data (like a JSON object) and can contain various fields with associated values.
#### Comparison to log files
- **Purpose**:
	- **Log Files**: Serve as raw data sources where events and logs are generated. They are the initial form of data storage before any processing.
	- **Indices**: Serve as organized collections of processed data that enable fast querying and analysis. They allow for efficient searching and aggregations based on structured data.
- **Structure**:
	- **Log Files**: Typically unstructured or semi-structured text files, which can be difficult to query without processing.
	- **Indices**: Structured data storage with defined mappings and fields, optimized for rapid searches and analyses based on those fields.
- **Lifecycle**:
	- **Log Files**: May be stored on disk in a particular location or directory for a specified duration, governed by log rotation policies.
	- **Indices**: Managed and retained according to index lifecycle policies in a database, which can include retention, aliasing, and deletion strategies.
- **Querying**:
	- **Log Files**: Queries against raw log files require additional tools or scripts to search through plain text data.
	- **Indices**: Queries against indices can leverage Elasticsearch's powerful search capabilities, allowing for precise queries and visualizations.
### 2.
>[!Task Description]
> Create an index retention policy to delete Wazuh alert indices after 90 days.
- As always I found an [instruction](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html) on the Wazuh official website
- I went to the `Indexer Management` -> `Index Management`
	![[Pasted image 20250428230931.png]]
- I was suggested to select a method to create a new policy:
	- Visual editor in Web UI
	- Or in JSON editor
- Using a visual editor I created a new `test-policy` policy and configured two states for `wazuh-alerts-*` indices:
	- `inital`: logs are initially in this state
	- `delete`: after 90 days logs are transited to this state
- After a transition to `delete` state logs are immediately deleted
- The result is below
	![[Pasted image 20250428232324.png]]
- Then I simply selected to modify the policy this time using the JSON editor
	![[Pasted image 20250428232340.png]]
- The JSON editor was appeared and I could see the configuration of my log retention policy in a JSON format
	![[Pasted image 20250428232441.png]]
- So, below is the configuration of my log retention policy
	```json
	{
	  "policy": {
	    "policy_id": "test-policy",
	    "description": "A policy to clear logs older than 90 days",
	    "last_updated_time": 1745871765015,
	    "schema_version": 21,
	    "error_notification": null,
	    "default_state": "initial",
	    "states": [
	      {
	        "name": "initial",
	        "actions": [],
	        "transitions": [
	          {
	            "state_name": "delete_alerts",
	            "conditions": {
	              "min_index_age": "90d"
	            }
	          }
	        ]
	      },
	      {
	        "name": "delete_alerts",
	        "actions": [
	          {
	            "retry": {
	              "count": 3,
	              "backoff": "exponential",
	              "delay": "1m"
	            },
	            "delete": {}
	          }
	        ],
	        "transitions": []
	      }
	    ],
	    "ism_template": [
	      {
	        "index_patterns": [
	          "wazuh-alerts-*"
	        ],
	        "priority": 1,
	        "last_updated_time": 1745871200545
	      }
	    ]
	  }
	}
	```
- Then I applied this policy to the existing `wazuh-alerts-*` indices manually
	![[Pasted image 20250428232747.png]]
	![[Pasted image 20250428232806.png]]
- Finally, I could see that my policy was applied to the `wazuh-alerts` indices
	![[Pasted image 20250428232904.png]]