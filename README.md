
# Primitive Ctrl

Remote control of your phone's [Primitive FTPd Android SFTP server](https://github.com/wolpi/prim-ftpd) and optionally [Tailscale VPN](https://tailscale.com/).

Though Primitive FTPd consumes minimal power when it is not used, remote start/stop can be usefull for zeroconf (DNS-SD). Android doesn't reply DSN-SD queries when the screen is off, but Android announces the new service when the Primitive FTPd server starts up. So SFTP clients can/should capture and cache the announcement at Primitive FTPd server startup to connect to a phone through zeroconf even when the screen is off.

But in case of Tailscale, it is a real battery and mobile network data drain when not used, local and remote start/stop is de facto very useful.

With the help of this script you can sync your phone with eg. your home NAS server whereever your phone is on a WiFi network - or even on cellular. Your phone doesn't have to be on the same LAN to make zeroconf working when you have alternative access through VPN.

See my other project, https://github.com/lmagyar/prim-sync, for bidirectional and unidirectional sync over SFTP (multiplatform Python script optimized for the Primitive FTPd SFTP server).

See my other project, https://github.com/lmagyar/prim-batch, for batch execution of prim-ctrl and prim-sync commands.

**Note:** These are my first ever Python projects, any comments on how to make them better are appreciated.

## Features

- Remote start/stop of Primitive FTPd Android SFTP server and optionally local and remote start/stop of Tailscale VPN
- Using VPN on cellular can be refused
- Backup sftp server and VPN states before starting them, restore when stopping (ie. they won't be stopped if they were running before the script were asked to start them)

## Installation

You need to install:
- Automate on your phone - see: https://llamalab.com/automate/

- Python 3.12+, pip and venv on your laptop - see: https://www.python.org/downloads/ or
  <details><summary>Ubuntu</summary>

  ```
  sudo apt update
  sudo apt upgrade
  sudo apt install python3 python3-pip python3-venv
  ```
  </details>
  <details><summary>Windows</summary>

  - Install from Microsoft Store the latest [Python 3](https://apps.microsoft.com/search?query=python+3&department=Apps) (search), [Python 3.12](https://www.microsoft.com/store/productId/9NCVDN91XZQP) (App)
  - Install from Winget: `winget install Python.Python.3.12`
  - Install from Chocolatey: `choco install python3 -y`
  </details>

- pipx - see: https://pipx.pypa.io/stable/installation/#installing-pipx or
  <details><summary>Ubuntu</summary>

  ```
  sudo apt install pipx
  pipx ensurepath
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  py -m pip install --user pipx
  py -m pipx ensurepath
  ```
  </details>

- This repo
  ```
  pipx install prim-ctrl
  ```

Optionally you can install:
- Tailscale on your phone and laptop - see: https://tailscale.com/download

Optionally, if you want to edit or even contribute to the source, you also need to install:
- poetry - see: https://python-poetry.org/
  ```
  pipx install poetry
  ```

## Configuration

### Automate

- Download the https://raw.githubusercontent.com/lmagyar/prim-ctrl/main/res/prim-ctrl.flo Automate flow to your phone (see [image](https://raw.githubusercontent.com/lmagyar/prim-ctrl/main/res/prim-ctrl.png) of the flow)
- Import it with the ... menu / Import command
- Enable all privileges
- Click on the flow, edit the 2nd block (Set variable google_account to...), enter your Google account's email and press Save
  - Optionally, if the Google account your phone is registered to is different from the Google account you use to send messages to Automate (eg. you manage a phone that is a jukebox or a family member's phone and you use your personal account to send messages), edit the 3rd block (Set variable other_managing_accounts to...), enter one or more Google account's email (separated with space or comma) and press Save
- Start the flow
- Settings
  - Safety
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
- If local Tailscale VPN was disconnected for a longer period (several hours), the public DNS records for Funnel are removed by Tailscale, and after connecting local Tailscale VPN to the tailnet it can take up to 10 minutes for Funnel's public DNS records to show up for your tailnet domain. If the script connects local Tailscale VPN to the tailnet, then it regularly checks and waits up to 10 minutes for the public DNS records to get updated.

### Some example

<details><summary>Ubuntu</summary>

```
prim-ctrl Automate youraccount@gmail.com "SOME MANUFACTURER XXX" automate your-phone-pftpd id_ed25519_sftp --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 tailscale-secretfile -t -i start -b
prim-ctrl Automate youraccount@gmail.com "SOME MANUFACTURER XXX" automate your-phone-pftpd id_ed25519_sftp --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 tailscale-secretfile -t -i stop -r ${PREV_STATE}
```
</details>
<details><summary>Windows</summary>

```
prim-ctrl Automate youraccount@gmail.com "SOME MANUFACTURER XXXX" automate your-phone-pftpd id_ed25519_sftp --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 tailscale-secretfile -t -i start -b
prim-ctrl Automate youraccount@gmail.com "SOME MANUFACTURER XXXX" automate your-phone-pftpd id_ed25519_sftp --tailscale tailxxxx.ts.net your-phone 2222 --funnel your-laptop 12345 /prim-ctrl 8443 tailscale-secretfile -t -i stop -r !PREV_STATE!
```
</details>

### Options

```
usage: prim-ctrl Automate [-h] [-i {test,start,stop}] [-t] [-s] [--debug] [--tailscale tailnet remote-machine-name sftp-port] [--funnel local-machine-name local-port local-path external-port secretfile] [-ac] [-b] [-r STATE]
                          automate-account automate-device automate-tokenfile server-name keyfile

Remote control of your phone's Primitive FTPd and optionally Tailscale app statuses via the Automate app, for more details see https://github.com/lmagyar/prim-ctrl

Note: you must install Automate app on your phone, download prim-ctrl flow into it, and configure your Google account in the flow to receive messages (see the project's GitHub page for more details)
Note: optionally if your phone is not accessible on local network but your laptop and phone is part of the Tailscale VPN then Tailscale VPN can be started on the phone
Note: optionally if your laptop is accessible through Tailscale Funnel then VPN on cellular can be refused and app statuses on the phone can be backed up and restored

Output: even when -b option is not used, the script will output 'connected=(local|remote)', what you can use to determine whether to use -a option for the prim-sync script

positional arguments:
  automate-account                 your Google account email you set up in the Automate flow's 2nd block's (Set variable google_account to...) Value field
  automate-device                  the device name you can see at the Automate flow's Cloud receive block's This device field
  automate-tokenfile               filename containing Automates's Secret that located under your .secrets folder
                                   (generated on https://llamalab.com/automate/cloud, use the same Google account you set the automate_account option to)
                                   Note: if the account you use to send messages is different from the automate_account option,
                                   set it up in the Automate flow's 3rd block's (Set variable other_managing_accounts to...) Value field
  server-name                      the Servername configuration option from Primitive FTPd app
  keyfile                          private SSH key filename located under your .ssh folder, see the documentation of prim-sync for more details

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
  --funnel local-machine-name local-port local-path external-port secretfile
                                   local-machine-name:  your laptop's name within your tailnet (just the name, without the tailnet)
                                   local-port:          12345 - if you used the example tailscale funnel command above (the local webhook will be started on this port)
                                   local-path:          /prim-ctrl - if you used the example tailscale funnel command above
                                   external-port:       8443 - if you used the example tailscale funnel command above
                                   secretfile:          filename containing Tailscale's Client secret (not API access token, not Auth key) that located under your .secrets folder
                                                        (generated on https://login.tailscale.com/admin/settings/oauth, with 'devices:core:read' scope,
                                                        save only the Client secret in the file, the Client ID is part of it)
  -ac, --accept-cellular           in case of start, if WiFi is not connected, don't return error, but start VPN up
  -b, --backup-state               in case of start, backup current state to stdout as single string (in case of an error, it will try to restore the original state but will not write it to stdout)
  -r STATE, --restore-state STATE  in case of stop, restore previous state from STATE (use -b to get a valid STATE string)
```
