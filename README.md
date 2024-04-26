# 2204-network-project

**>The broadcast ip must be specified on the 5th line of main.py**

Required External Libraries: pynput, base64, pydes
So you need to run
```shell
pip install pynput base64 pydes
```

!! COMMENTLER GÖZDEN GEÇİRİLECEK


### Faced Challenges:

Locked Input meselesi

return ip address because ip addreses are keys

two way key exchange was a real challenge

### Known Limitations:

* Within Windows Defender Firewall Advanced Settings page, you need to add an Inbound Rule for UDP 6000 and TCP 6001 ports otherwise you can not get messages or peer discovery packets on Windows Operating System.

* Sometimes pynput library does not simulate "Enter" button when the public key received for a secure chat request. So the user should hit Enter for continueing the thread.