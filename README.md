
> [!CAUTION]
> ***This repository is in alpha***

> [!WARNING]
> ***This repository works with both the original and the forked version of the Primitive FTPd Android SFTP server!***
> - ***install my fork from https://github.com/lmagyar/prim-ftpd - and use the prim-ctrl-lmagyar Automate flow below***
> - ***install the original version from https://github.com/wolpi/prim-ftpd - and use the prim-ctrl Automate flow below***

# Primitive Ctrl

Remote control of your phone's [Primitive FTPd Android SFTP server](https://github.com/wolpi/prim-ftpd) and optionally [Tailscale VPN](https://tailscale.com/).

Though Primitive FTPd consumes minimal power when it is not used, remote start/stop can be usefull. But in case of Tailscale, it is a real battery and mobile network data drain when not used, remote start/stop is de facto very useful.

With the help of this script you can sync your phone eg. with your home NAS server whereever your phone is on a WiFi network - or even on cellular. Your phone doesn't have to be on the same LAN to make zeroconf working.

See my other project, https://github.com/lmagyar/prim-sync, for bidirectional and unidirectional sync over SFTP (multiplatform Python script optimized for the Primitive FTPd SFTP server).

## Features

- Remote start/stop of Primitive FTPd Android SFTP server and Tailscale VPN
- Using VPN on cellular can be refused
- Backup states before starting them, restore when stopping (ie. they won't be stopped if they were running before the script were asked to start them)

## Installation

You need to install:
- Automate on your phone - see: https://llamalab.com/automate/
- Python 3.12+, pip and venv - see: https://www.python.org/downloads/ or
  <details><summary>Unix</summary>

  ```
  sudo apt update
  sudo apt upgrade
  sudo apt install python3 python3-pip python3-venv
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  choco install python3 -y
  ```
  </details>
- This repo
  <details><summary>Unix</summary>

  ```
  git clone https://github.com/lmagyar/prim-ctrl
  cd prim-ctrl
  python3 -m venv --upgrade-deps .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  git clone https://github.com/lmagyar/prim-ctrl
  cd prim-ctrl
  py -m venv --upgrade-deps .venv
  .venv\Scripts\activate
  pip install -r requirements.txt
  ```
  </details>

Optionally you can install:
- Tailscale on your phone and laptop - see: https://tailscale.com/download

## Configuration

### Automate

- Depending on whether you installed the [forked](https://github.com/lmagyar/prim-ftpd) or the [original](https://github.com/wolpi/prim-ftpd) version of Primitive FTPd, download the appropriate Automate flow to your phone:
  - Flow for the **forked** Primitive FTPd: https://github.com/lmagyar/prim-ctrl/blob/main/res/prim-ctrl-lmagyar.flo (see [image](https://raw.githubusercontent.com/lmagyar/prim-ctrl/main/res/prim-ctrl-lmagyar.png) of the flow)
  - Flow for the **original** Primitive FTPd: https://github.com/lmagyar/prim-ctrl/blob/main/res/prim-ctrl.flo (see [image](https://raw.githubusercontent.com/lmagyar/prim-ctrl/main/res/prim-ctrl.png) of the flow)
- Import it with the ... menu / Import command
- Enable all privileges
- Click on the flow, edit the 2. block ("Set variable google_account to...), enter your Google account and press Save
- Start the flow
- Settings
  - Run on system startup: enable

### Primitive FTPd

- Configuration tab
  - UI
    - Show notification to start/stop server(s): disable - this is necessary to determine whether Primitive FTPd is running on the phone or not, because the Automate flow determines whether the server is started with checking the existence of it's notification, and if the notification is always shown, that would make it false positive; please use another way, eg. a Quick Settings Tile to start/stop the server manually

### Tailscale VPN (optional)

Follow Tailscale's instructions on how to configure Tailscale VPN on your phone and laptop.

For more details see: https://login.tailscale.com/start

### Tailscale Funnel (optional)

You can configure Tailscale Funnel on your laptop (for incoming connections to this script's webhooks from the internet). Until the Tailscale VPN is up on the phone, the phone can't send information directly to your laptop, to this script's webhooks. But Tailscale Funnel makes it possible to access a Tailscale VPN connected device's services from the wider internet.

For more details see: https://tailscale.com/kb/1223/funnel

An example Tailscale Funnel config command for this script is: `tailscale funnel --bg --https=8443 --set-path=/prim-ctrl "http://127.0.0.1:12345"`

## Usage

If you decide to use this script, I suggest to configure Tailscale VPN and Tailscale Funnel, this will provide the most functionality.

Without any VPN, the script will start and stop the Primitive FTPd app on your phone making a best effort and assumes the phone is on the same LAN (ie. zeroconf works). This is fine if you start the script manually and your phone is with you.

But if the script runs scheduled, we can't be sure whether the phone is on WiFi, is on the same WiFi as your laptop: it is better to configure the VPN and Funnel. And I suggest to use the backup and restore functionality also, in this case a scheduled script will not interfere with a manually started Primitive FTPd or VPN, you won't notice the synchronization is running while you are doing something else on the phone with the Primitive FTPd or the VPN.

Notes:
- Even when -b option is **not** used, the script will output 'connected=(local|remote)', what you can use to determine whether to use -a option for the prim-sync script

### Options

```
usage: prim-ctrl.py Automate [-h] [-i {test,start,stop}] [-t] [-s] [--debug] [--tailscale tailnet remote-machine-name sftp-port] [--funnel local-machine-name local-port local-path external-port] [-ac] [-b]
                             [-r STATE]
                             automate-account automate-device automate-tokenfile server-name

Remote control of your phone's Primitive FTPd and optionally Tailscale app statuses via the Automate app, for more details see https://github.com/lmagyar/prim-ctrl

Note: you must install Automate app on your phone, download prim-ctrl flow into it, and configure your Google account in the flow to receive messages (see the project's GitHub page for more details)
Note: optionally if your phone is not accessible on local network but your laptop is part of the Tailscale VPN then Tailscale VPN can be started on the phone
Note: optionally if your laptop is accessible through Tailscale Funnel then VPN on cellular can be refused and app statuses on the phone can be backed up and restored

Output: even when -b option is not used, the script will output 'connected=(local|remote)', what you can use to determine whether to use -a option for the prim-sync script

positional arguments:
  automate-account                 your Google account email you set up in the Automate flow's first Set variable block's Value field
  automate-device                  the device name you can see at the Automate flow's Cloud receive block's This device field
  automate-tokenfile               filename containing Automates's Secret that located under your .secrets folder
                                   (generated on https://llamalab.com/automate/cloud, use the same Google account you set up on the Cloud receive block)
  server-name                      the Servername configuration option from Primitive FTPd app

options:
  -h, --help                       show this help message and exit
  -i {test,start,stop}, --intent {test,start,stop}
                                   what to do with the apps, default: test

logging:
  -t, --timestamp                  prefix each message with an UTC timestamp
  -s, --silent                     only errors printed
  --debug                          use debug level logging and add stack trace for exceptions, disables the --silent and enables the --timestamp options

VPN:
  To use --tailscale option you must install Tailscale and configure Tailscale VPN on your phone and your laptop
  To use --funnel option you must configure Tailscale Funnel on your laptop for prim-ctrl's local webhook to accept responses from the Automate app
     (eg.: tailscale funnel --bg --https=8443 --set-path=/prim-ctrl "http://127.0.0.1:12345")
  Note: --funnel, --backup-state and --restore-state options can be used only when --tailscale is used
  Note: --backup-state is accurate only, when --funnel is used
  Note: --accept-cellular option can be used only when --funnel is used

  --tailscale tailnet remote-machine-name sftp-port
                                   tailnet:             your Tailscale tailnet name (eg. tailxxxx.ts.net)
                                   remote-machine-name: your phone's name within your tailnet (just the name, without the tailnet)
                                   sftp-port:           Primitive FTPd's sftp port
  --funnel local-machine-name local-port local-path external-port
                                   local-machine-name:  your laptop's name within your tailnet (just the name, without the tailnet)
                                   local-port:          12345 - if you used the example tailscale funnel command above (the local webhook will be started on this port)
                                   local-path:          /prim-ctrl - if you used the example tailscale funnel command above
                                   external-port:       8443 - if you used the example tailscale funnel command above
  -ac, --accept-cellular           in case of start, if WiFi is not connected, don't return error, but start VPN up
  -b, --backup-state               in case of start, backup current state to stdout as single string (in case of an error, it will try to restore the original state but will not write it to stdout)
  -r STATE, --restore-state STATE  in case of stop, restore previous state from STATE (use -b to get a valid STATE string)
```

### Some example

<details><summary>Unix</summary>

```
prim-ctrl.sh Automate youraccount@gmail.com "SOME MANUFACTURER XXX" automate a-unique-server-name --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 -t -i start -b
prim-ctrl.sh Automate youraccount@gmail.com "SOME MANUFACTURER XXX" automate a-unique-server-name --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 -t -i stop -r ${PREV_STATE}
```
</details>
<details><summary>Windows</summary>

```
prim-ctrl.cmd Automate youraccount@gmail.com "SOME MANUFACTURER XXXX" automate a-unique-server-name --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 -t -i start -b
prim-ctrl.cmd Automate youraccount@gmail.com "SOME MANUFACTURER XXXX" automate a-unique-server-name --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 -t -i stop -r !PREV_STATE!
```
</details>

### Elaborate example on how to use it together with the prim-sync script

Unix (under construction...)

<details><summary>Windows</summary>

Tested on Windows 11:

```
@echo off
setlocal EnableDelayedExpansion EnableExtensions

rem This script can be called:
rem - without arguments: it syncs all the folders and pause
rem - with one of the folders' name as argument: it syncs only that folder and pause
rem - with "scheduled" as argument: it syncs all the folders without pause and with less log messages, but with some extra log lines that are practical when the output is appended to a log file
rem Additionally any prim-sync options (starting with "-") can be added after the above arguments, they will be passed to the prim-sync command.

set ctrl_args=Automate youraccount@gmail.com "SOME MANUFACTURER XXXX" automate a-unique-server-name --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 -t
set sync_args=a-unique-server-name id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" --ignore-locks 360
set sync_args_vpn=-a your-phone.tailxxxx.ts.net 2222

set arg1=%1

if "!arg1!"=="scheduled" (
    for /F "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /VALUE 2^>NUL`) do if '.%%i.'=='.LocalDateTime.' set ldt=%%j
    set timestamp=!ldt:~0,4!-!ldt:~4,2!-!ldt:~6,2! !ldt:~8,2!:!ldt:~10,2!:!ldt:~12,6!
    echo !timestamp! = STARTED = %~nx0 %*
)

rem ----------------------------------------

rem handle arguments
if "!arg1!"=="scheduled" (
    set ctrl_args=!ctrl_args! -s
    set sync_args=!sync_args! -ss
    shift /1
) else if not "!arg1:~0,1!"=="-" (
    set folder_to_sync=!arg1!
    shift /1
)
if "!folder_to_sync!"=="" set folder_to_sync=all
set sync_args=!sync_args! %1 %2 %3 %4 %5 %6 %7 %8 %9

rem this testing is useful when as a scheduled task is executed after an awake and networking is not ready yet
rem it is approx 10 minutes
set cnt=120
:testnetworking
ping -n 1 1.1.1.1 | find "TTL=" >nul
if errorlevel 1 (
    set /a cnt-=1
    if not "!cnt!"=="0" (
        timeout 2 /nobreak >nul
        goto :testnetworking
    )
    for /F "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /VALUE 2^>NUL`) do if '.%%i.'=='.LocalDateTime.' set ldt=%%j
    set timestamp=!ldt:~0,4!-!ldt:~4,2!-!ldt:~6,2! !ldt:~8,2!:!ldt:~10,2!:!ldt:~12,6!
    echo !timestamp! %~nx0: ERROR: Networking is down
) else (
    rem these 2 lines prevent parallel execution by locking the lock file, file descriptor 3 is not used, so nothing is written to the lock file
    2>nul (
        3>%~dp0SyncWithMobile.lock 2>&1 (
            rem stores stdout in a variable (the braindead way of windows cli)
            for /f "usebackq tokens=*" %%s in (`call C:\...\prim-ctrl\prim-ctrl.cmd !ctrl_args! -i start -b`) do set PREV_STATE=%%s
            rem use response on stdout, errorlevel will be messed up by the for command
            if not "!PREV_STATE!" == "" (
                echo "!PREV_STATE!" | find "connected=remote" >NUL
                if not errorlevel 1 set sync_args=!sync_args! !sync_args_vpn!

                for %%a in (all Music) do if "!folder_to_sync!"=="%%a" call C:\...\prim-sync\prim-sync.cmd !sync_args! "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Music" "*"
                for %%a in (all Camera) do if "!folder_to_sync!"=="%%a" call C:\...\prim-sync\prim-sync.cmd !sync_args! "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Camera" "DCIM/Camera"
                for %%a in (all Screenshots) do if "!folder_to_sync!"=="%%a" call C:\...\prim-sync\prim-sync.cmd !sync_args! "D:\Mobile" "/fs/storage/emulated/0" "*" "Screenshots" "DCIM/Screenshots"

                call C:\...\prim-ctrl\prim-ctrl.cmd !ctrl_args! -i stop -r !PREV_STATE!
            )
            rem set errorlevel to 0
            ver > nul
        ) || (
            rem locking failed
            for /F "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /VALUE 2^>NUL`) do if '.%%i.'=='.LocalDateTime.' set ldt=%%j
            set timestamp=!ldt:~0,4!-!ldt:~4,2!-!ldt:~6,2! !ldt:~8,2!:!ldt:~10,2!:!ldt:~12,6!
            echo !timestamp! %~nx0: ERROR: Already running
        )
    )
)

rem ----------------------------------------

if "!arg1!"=="scheduled" (
    for /F "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /VALUE 2^>NUL`) do if '.%%i.'=='.LocalDateTime.' set ldt=%%j
    set timestamp=!ldt:~0,4!-!ldt:~4,2!-!ldt:~6,2! !ldt:~8,2!:!ldt:~10,2!:!ldt:~12,6!
    echo !timestamp! = STOPPED = %~nx0 %*
)

if not "!arg1!"=="scheduled" pause
```

You can schedule a Task Scheduler task with a "Start a program" action with the below parameters to start the above scrpit:
- Command: `C:\Windows\System32\StartMinimized.vbs`
- Arguments: `"title=Scheduled SyncWithMobile" C:\Windows\System32\cmd.exe /C C:\...\SyncWithMobile.cmd scheduled ^>^> C:\Temp\SyncWithMobile.log 2^>^&1`

Where the StartMinimized.vbs script is to start the script in a minimized window without any pop-up (this is a general script that is useful to start anything minimized from Task Scheduler):

```
Dim start, title
If(WScript.Arguments.Count >= 1 And Left(WScript.Arguments(0), 6) = "title=") Then
  start = 1
  title = Mid(WScript.Arguments(0), 7)
Else
  start = 0
  title = "Command Prompt"
End If
ReDim args(WScript.Arguments.Count - 1 - start)
For i = start To WScript.Arguments.Count - 1
  If InStr(WScript.Arguments(i), " ") > 0 Then
    args(i - start) = """" + WScript.Arguments(i) + """"
  Else
    args(i - start) = WScript.Arguments(i)
  End If
Next
CreateObject("Wscript.Shell").Run "C:\Windows\System32\cmd.exe /c start """ & title & """ /min " & Join(args, " "), 0, False
```
</details>
