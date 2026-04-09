# Cobalt Strike Initial Commands  

The objective of this lab is to familiarse yourself with Cobalt Strike.  You will create listeners, generate payloads, and interact with Beacon.

* [Beacon commands](https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops&unit=696a1d7abd92eef9e30f7537Unit)

===

# Launch Cobalt Strike

1. On the Windows taskbar, click on the Cobalt Strike icon.
1. Fill in the connection details for the team server.
  1. Host: `10.0.0.5`
  1. Port: `50050`
  1. Password: `Passw0rd!`

===

# Create Listeners

1. Go to **Cobalt Strike > Listeners** to bring  up the Listeners tab.
1. Click **Add** to create a new listener.

Add the following listeners:

## HTTP

1. Name: `http`
1. Payload: Beacon HTTP
1. HTTP Hosts: `www.bleepincomputer.com`
1. HTTP Host (Stager) : `www.bleepincomputer.com`

## SMB

1. Name: `smb`
1. Payload: Beacon SMB
1. Pipename: `TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337`

## TCP

1. Name: `tcp`
1. Payload: Beacon TCP
1. Port: `4444`
1. Bind to localhost: False

## TCP (local)

1. Name: `tcp-local`
1. Payload: Beacon TCP
1. Port: `1337`
1. Bind to localhost: True

===

# Generate Payloads

1. Generate payloads for each listener.
  1. Go to **Payloads > Windows Stageless Generate All Payloads**
  1. Folder: `C:\Payloads`
  1. Click **Generate**

===

# Interact with Beacon

1. Run *C:\Payloads\http_x64.exe* and a new Beacon session should appear.
1. Familiarise yourself with the client UI and running commands in Beacon.

> [!HINT] Use the `help` command to list all of the available commands, and `help [alias]` to get help for a specific command.

<br />

> [!KNOWLEDGE] In this lab, you have begun to explore the basics of using Cobalt Strike.
