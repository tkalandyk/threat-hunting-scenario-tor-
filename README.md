# threat-hunting-scenario-tor-

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/tkalandyk/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "mathodman" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-06T21:18:19.0000000Z`. These events began at `2026-01-06T21:17:43.0000000Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "wutang"  
| where InitiatingProcessAccountName == "methodman"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-06T21:18:07.1084878Z) 
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1077" height="420" alt="image" src="https://github.com/user-attachments/assets/7bb36bf8-1365-4fce-9966-0e01556b3a93" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64". Based on the logs returned, at `2026-01-06T21:17:43.9557981Z`, an employee on the "wutang" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "wutang"
| where ProcessCommandLine contains "tor-browser-windows-x86_64"
| project Timestamp,DeviceName, ActionType,FileName,FolderPath,SHA256,AccountName,ProcessCommandLine
```
<img width="1169" height="156" alt="image" src="https://github.com/user-attachments/assets/96bc38d4-e79e-4e2e-afa7-fc570a90ec29" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "wutang" actually opened the TOR browser. There was evidence that they did open it at `2026-01-06T21:19:35.8427702Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "wutang"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1139" height="426" alt="image" src="https://github.com/user-attachments/assets/f42bf49c-caf4-45c4-9aaa-cb059df82b8c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-06T21:20:55.7751044Z`, an employee on the "wutang" device successfully established a connection to the remote IP address `81.201.202.101` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\methodman\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "wutang"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1159" height="326" alt="image" src="https://github.com/user-attachments/assets/edd3dcb2-114a-44dd-b24a-9de808512b36" />


---
## Chronological Event Timeline 

### 1. File Download – TOR Installer

- **Timestamp:** `2026-01-06T21:17:43.0000000Z`
- **Event:** The user "methodman" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\methodman\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

---

### 2. Process Execution – TOR Browser Installation

- **Timestamp:** `2026-01-06T21:18:07.0000000Z`
- **Event:** The user "methodman" executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3.exe /S`
- **File Path:** `C:\Users\methodman\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

---

### 3. Process Execution – TOR Browser Launch

- **Timestamp:** `2026-01-06T21:19:35.0000000Z`
- **Event:** User "methodman" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser–related executables detected.
- **File Path:** `C:\Users\methodman\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe`

---

### 4. Network Connection – TOR Network

- **Timestamp:** `2026-01-06T21:20:55.0000000Z`
- **Event:** A network connection to IP `81.201.202.101` on port `9001` by user "methodman" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\methodman\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe`

---

### 5. Additional Network Connections – TOR Browser Activity

- **Timestamps:**
  - `2026-01-06T21:20:55Z` – Multiple Tor relay connections on port `9001`
  - `2026-01-06T21:21:07Z` – Encrypted Tor traffic on port `443`
  - `2026-01-06T21:20:47Z` – Local proxy activity on `127.0.0.1:9150`
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "methodman" through the TOR browser.
- **Action:** Multiple successful connections detected.

---

### 6. File Creation – TOR Shopping List

- **Timestamp:** `2026-01-06T21:18:19.0000000Z`
- **Event:** The user "methodman" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\methodman\Desktop\tor-shopping-list.txt`

---

## Summary

The user "methodman" on the "wutang" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `wutang` by the user `methodman`. The device was isolated, and the user's direct manager was notified.

