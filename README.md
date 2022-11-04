# MoreImpacketExamples
This repository contains a few short python scripts that were created using the [Impacket](https://github.com/SecureAuthCorp/impacket) library. The primary goal of this project is to help myself and others who are looking to transition from using the provided impacket examples to modifying/creating scripts of their own. These scripts are not necessarily optimized for utility or OPSEC concerns, however I've tried to make them as dynamic as possible in case anyone wants to change their default behavior.

![remote_ssp_dump intro gif](https://user-images.githubusercontent.com/79864975/199787106-d708265b-0ea0-41f6-baff-3f954bc30c7b.gif)

## wmi_reg_exec.py
The `wmi_reg_exec.py` script is designed to execute a file exclusively over WMI by writing to the windows registry. It does this by first writing the base64 encoded file to a target registry location along with a PowerShell AMSI/ETW bypass. A PowerShell stager is then used to execute the AMSI/ETW bypass and the given file in memory reflectively. C# binaries are supported 'natively' so long as their main namespace, class, and method are all publicly available. If not supplied, the script will automatically try to guess the namespace based on the filename. If a Non-.NET file is supplied, it is first turned into shellcode using [@s4ntiago_p's](https://twitter.com/s4ntiago_p) [Donut syscall branch](https://github.com/S4ntiagoP/donut/tree/syscalls) and then inserted into [@Snovvcrash's](https://twitter.com/snovvcrash) C# D/Invoke self-injector. The self-injector is then compiled using MCS and used the same as any other C# binary.

<details>
  <summary>See Example .NET Demo</summary>

<img alt="wmi_reg_exec.py .NET demo" src="https://user-images.githubusercontent.com/79864975/199818888-96e11cc9-f47d-4419-99c6-7d7347eb7c60.gif"/>
</details>
<details>
  <summary>See Example PE Demo</summary>

<img alt="wmi_reg_exec.py PE demo" src="https://user-images.githubusercontent.com/79864975/199815998-5d4aeb09-7da5-4240-8331-8e95bfc2c011.gif"/>
</details>

```
usage: wmi_reg_exec.py [-h] [-f file] [-a args] [-n namespace] [-r key] [-p patch] [-rp remotePath] [-nooutput] [-H hash] [-k]
                       [-dc-ip IPAddress]
                       target

Store exe in registry and execute via powershell

positional arguments:
  target                Target host to execute file on

optional arguments:
  -h, --help            show this help message and exit
  -f file, -file file   File to execute
  -a args, -args args   Command line arguments for file
  -n namespace, -namespace namespace
                        Namespace.Class containing main method to execute (Ex: Rubeus.Program)
  -r key, -reg-key key  Registry key to write file to (Default: HKLM\Software\Microsoft\Edge)
  -p patch, -patch patch
                        File containing AMSI/ETW patch to perform before execution
  -rp remotePath, -remote-path remotePath
                        The remote path to write files to (Default: C:\Windows\Temp)
  -nooutput             Do not attempt to get/print output

authentication:
  -H hash, -hash hash   NTHash for login via PtH
  -k                    Use Kerberos authentication with credentials from the KRB5CCNAME ccache file
  -dc-ip IPAddress      IP Address of the domain controller (useful for Kerberos auth)
```
## dll_proxy_exec.py
The `dll_proxy_exec.py` script is designed to execute a given DLL file using a LOLBin via DLL Hijacking/Proxying/Side-Loading/whatever you call it. The given DLL will first be uploaded to the target over SMB. The script will then copy the specified System32 exe into the same folder as the uploaded DLL. Finally, the System32 exe will be executed from the new location, resulting in it loading/executing the given DLL.
<details>
  <summary>See Example Demo</summary>

<img alt="dll_proxy_exec.py demo" src="https://user-images.githubusercontent.com/79864975/199827505-08128121-34c5-4d1c-937b-f635ff8e5ae1.gif"/>
</details>

```
usage: dll_proxy_exec.py [-h] [-f file] [-e exe] [-output] [-H hash] [-k] [-dc-ip IPAddress] [-rp remotePath] target

Execute file via DLL proxying on a remote host.

positional arguments:
  target                [[domain/]username[:password]@]<hostname or address>

optional arguments:
  -h, --help            show this help message and exit
  -f file, -file file   DLL file to execute
  -e exe, -exe exe      System32 EXE used to execute DLL file
  -output               Attempt to get output
  -rp remotePath, -remote-path remotePath
                        The remote path to write files to (Default: C:\Windows\Temp)

authentication:
  -H hash, -hash hash   NTHash for login via PtH
  -k                    Use Kerberos authentication with credentials from the KRB5CCNAME ccache file
  -dc-ip IPAddress      IP Address of the domain controller (useful for Kerberos auth)
```
## remote_ssp_dump.py
The `remote_ssp_dump.py` script is designed to dump creds from LSASS from a remote host using [Nanodump's](https://github.com/helpsystems/nanodump) SSP DLL. By default, the script will use the unmodified SSP DLL and loader, which are embedded in the file. Alternatively, the script will use a modified DLL or Loader if present in the current directory with their standard names (`nanodump_ssp.x64.dll` and `load_ssp.x64.exe` respectively). When executed, the script will upload the DLL and loader to the target, execute the loader, download the LSASS dump, and parse it for hashes using [Pypykatz](https://github.com/skelsec/pypykatz). In addition, this script has been integrated with the `wmi_reg_exec.py` and `dll_proxy_exec.py` scripts, allowing for different ways of executing the SSP loader.

<details>
  <summary>See Example Demo</summary>

<img alt="remote_ssp_dump.py demo" src="https://user-images.githubusercontent.com/79864975/199787106-d708265b-0ea0-41f6-baff-3f954bc30c7b.gif"/>
</details>

```
usage: remote_ssp_dump.py [-h] [-t timeout] [-rp remotePath] [-re] [-dp] [-f dll] [-e exe] [-r key] [-H hash] [-k]
                          [-dc-ip IPAddress]
                          target

Dump creds from LSASS remotely using Nanodump SSP

positional arguments:
  target                [[domain/]username[:password]@]<hostname or address>

optional arguments:
  -h, --help            show this help message and exit
  -t timeout, -timeout timeout
                        Timeout in seconds to wait for LSASS dump file to be created (Default: 3)
  -rp remotePath, -remote-path remotePath
                        The remote path to write files to (Default: C:\Windows\Temp)
  -re, -reg-exec        Execute SSP loader by writing it to the registry and executing it in memory with PowerShell
  -dp, -dll-proxy       Execute SSP loader via DLL Proxying (See below for options)

dll proxying options:
  -f dll, -file dll     DLL file to execute
  -e exe, -exe exe      System32 EXE used to execute DLL file

registry execute options:
  -r key, -reg-key key  Registry key to write file to (Default: HKLM\Software\Microsoft\Edge)

authentication:
  -H hash, -hash hash   NTHash for login via PtH
  -k                    Use Kerberos authentication with credentials from the KRB5CCNAME ccache file
  -dc-ip IPAddress      IP Address of the domain controller (useful for Kerberos auth)
```
## dump_ntds_creds.py
The `dump_ntds_creds.py` script is designed to dump, exfiltrate, and parse all domain hashes from a target domain controller. It first executes the ntdsutil.exe LOLBin over WMI to create the dump and then downloads the resulting ntds.dit, SYSTEM, and SECURITY files over SMB. It will then parse all the domain credentials from the dumped file and save the results to a file.

<details>
  <summary>See Example Demo</summary>

<img alt="dump_ntds_creds.py demo" src="https://user-images.githubusercontent.com/79864975/199824508-e9783b0c-0f2b-4622-8582-314559d48fa0.gif"/>
</details>

```
usage: dump_ntds_creds.py [-h] [-nooutput] [-o filename] [-H hash] [-k] [-dc-ip IPAddress] [-rp remotePath] target

Dump NTDS.dit file, exfiltrate, and parse locally.

positional arguments:
  target                [[domain/]username[:password]@]<hostname or address>

optional arguments:
  -h, --help            show this help message and exit
  -nooutput             Do not print dumped hashes to console
  -o filename, -outfile filename
                        Name to save output files with (Default: DomainDump)
  -rp remotePath, -remote-path remotePath
                        The remote path to write files to (Default: C:\Windows\Temp)

authentication:
  -H hash, -hash hash   NTHash for login via PtH
  -k                    Use Kerberos authentication with credentials from the KRB5CCNAME ccache file
  -dc-ip IPAddress      IP Address of the domain controller (useful for Kerberos auth)
```
## Known Issues
* The `wmi_reg_exec.py` script cannot get the output of a Non-.NET PE file without writing to disk. If you want to attempt to get output in this case, you must have the PE file itself write its own output using the filename specified in the script. This could be hardcoded into the PE file, or it could be supplied via the script's `-a` flag if the PE already has an argument to write its output to a file. For an example of this, see the "Example PE Demo" gif which demonstrates this process with Mimikatz.
* The way in which the `wmi_reg_exec.py` script writes to the registry is **SLOW**. From my testing, it can take upwards of 4 minutes per MB. I'm not really sure why this is. If you know of a way to speed it up without needing to re-write the whole thing, pull requests are always welcome. :)

## Greetz & Credit:
* [@SecureAuthCorp](https://github.com/SecureAuthCorp) for their Impacket project, which this entire project utilizes to interact with windows services: https://github.com/SecureAuthCorp/impacket
* [@s4ntiago_p](https://twitter.com/s4ntiago_p) for their NanoDump project, used by the `remote_ssp_dump.py` script: https://github.com/helpsystems/nanodump
* [@s4ntiago_p](https://twitter.com/s4ntiago_p) again for their syscall enabled Donut branch, used by the `wmi_reg_exec.py` script: https://github.com/S4ntiagoP/donut/tree/syscalls
* [@snovvcrash](https://twitter.com/snovvcrash) for their C# D/Invoke self-injector, used by the `wmi_reg_exec.py` script: https://twitter.com/snovvcrash/status/1558837027122167810
