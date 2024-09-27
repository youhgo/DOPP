# Dfir ORC Parser Project

To have more info about DOPP:

* How to install DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-install-EN/)
* How to use DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-use-EN/)
* DOPP result architecture, explained [here](https://youhgo.github.io/DOPP-Results/)
* How to configure DFIR-ORC tutorial [here](https://youhgo.github.io/DOPP-Config-ORC-EN/)


## What is DOPP ?

The purpose of DOPP is to provide the necessary tools for parsing Windows artifacts (event logs, MFT, registry hives, amcache, etc.) as part of a digital forensics investigation.
Dopp produces extremely simple and readable results, allowing analysts to find the information they need directly.

Dopp was designed to process archives provided by the [DFIR-ORC](https://github.com/dfir-orc) collection tool from ANSSI but will be compatible with all formats soon.

DOPP is:

* Fast: ~5 minutes to process a 500MB archive (excluding PLASO);
* Easily installable with Docker;
* Simple to use.

The tool contain a web server with an API for sending archive and consulting the status of processing.

There is NO Web or GUI interface to see the results.
All the results are CSV files formated to be easy to read and to GREP.

Soon, Json output is will be available for SIEM ingestion.

This architecture is perfect for teamwork because it regroups all the tools and evidences.
Any analyst can send evidence for processing or access their results as long as they have access to the api for sending
and to the share result folder for consulting.

![](./ressources/images/DOPP_SIMPLE.png)

## What does DOPP do ?

DOPP Will : 
* Process a DFIR ORC Archive;
* Parse the evidences;
* Create a Timeline.

All the results are formated in a "human-readable way".
Here is an example of the results. We can directly see:

* The use of Mimikatz;
* The Cobalt Strike beacon;
* The backdoor;
* The ransomware;
* The disabling of the antivirus;
* The compromised user's connections.


```bash
 rg -i "2021-01-07\|03.(3|4|5)" user_logon_id4624.csv new_service_id7045.csv amcache.csv app_compat_cache.csv powershell.csv windefender.csv 
windefender.csv

2021-01-07|03:32:30|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable
2021-01-07|03:33:13|1117 - Action|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|Remove
2021-01-07|03:35:44|1116 - Detection|HackTool:Win64/Mikatz!dha|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|file:_C:\Users\Public\mimikatz.exe|Not Applicable

app_compat_cache.csv
2021-01-07|03:39:31|beacon.exe|C:\Users\Public\beacon.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:41:21|mimikatz.exe|C:\Users\Public\mimikatz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:56:55|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672

powershell.csv
2021-01-07|03:37:03|600|powershell Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus

new_service_id7045.csv
2021-01-07|03:32:30|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO

user_logon_id4624.csv
2021-01-07|03:30:12|4624|-|GRAAL$|::1|65229|3
2021-01-07|03:31:26|4624|-|MSOL_0537fce40030|192.168.88.136|54180|3
2021-01-07|03:31:38|4624|-|arthur|192.168.88.137|54028|3
2021-01-07|03:32:12|4624|-|GRAAL$|::1|65235|3
2021-01-07|03:32:30|4624|-|arthur|192.168.88.137|54100|3
2021-01-07|03:32:45|4624|-|GRAAL$|-|-|3
2021-01-07|03:32:57|4624|-|arthur|192.168.88.137|54140|3
```


Dopp uses externals tools listed here :

* [SRUM PARSER](https://github.com/MarkBaggett/srum-dump)
* [PREFETCH PARSER](http://www.505forensics.com)
* [PLASO](https://github.com/log2timeline/plaso)
* [EVTX DUMP](https://github.com/0xrawsec/golang-evtx)
* [ESE-analyst](https://github.com/MarkBaggett/ese-analyst)
* [analyzeMFT](https://github.com/rowingdude/analyzeMFT)
* [RegRipper](https://github.com/keydet89/RegRipper3.0)
* [regpy](https://pypi.org/project/regipy/)
* [MaximumPlasoParser](https://github.com/Xbloro/maximumPlasoTimelineParser)
*  [HAYABUSA](https://github.com/Yamato-Security/hayabusa)

## How does it work ?
![](./ressources/images/DOPP.png)

Everything is dockerized.

Container used are :

- Traefik as a reverse proxy;
- redis as a broker;
- Flask + Celery as the API server / broker workers;
- Dopp engine as the main working code.

Everything is enclosed to the docker-compose.yml and Dockerfile











