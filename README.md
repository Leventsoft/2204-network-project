# 2204-network-project

**The broadcast ip must be specified on the 7th line of main.py**

Required External Libraries: pynput, pydes
So you need to run
```shell
pip install pynput pydes
```

### How It works/How to Use?

0. There are 4 threads in this program which works under ```main.py``` and all the function features are defined in ```functions.py```.
For running this program you need to run ```python3 main.py``` after installing the required external libraries.
1. You have to specify the broadcast IP address of the network you are desiring to use on the 7th line of ```main.py```
2. User inputs a username and ```Announcer_Thread``` starts announcing user's username and ip address every 8 seconds over 6000 UDP port.
3. ```Chat_Initiator``` thread asks for an action, which can be done by typing the whole name of the function or just entering the first letter of the function. Either works with any combination of capital or non-capital letters.
4. Meanwhile, ```Peer_Discovery``` thread listens for UDP port 6000 indefinitely and waits for the broadcasted usernames, when they arrive they are written into a local shared dictionary between functions.

### Known Limitations:

* Within Windows Defender Firewall Advanced Settings page, you need to add an Inbound Rule for UDP 6000 and TCP 6001 ports otherwise you can not get messages or peer discovery packets on Windows Operating System.

* Sometimes pynput library does not simulate "Enter" button when the public key received for a secure chat request. So the user must hit Enter for continuing the thread (in case this happens).


### Features

* ```Secure Chat``` gets activated when the Chat_Responder thread receives a {key:YYYY} json information from 6001 TCP port. It makes Chat_Initiator stop. Chat_Initiator continues after the secure message transmission is over.
* When the program is requiring an action; ```History```, ```Chat```, ```Users```, ```Exit``` can be chosen by its initial letters or any combination of uppercase or lowercase characters of given words.
* Every message sent or received is being logged in ```chat_log.txt``` which gets created If it does not exist and every message appends at the end of the file. When you choose ```History``` function, last 10 lines of the log are displayed in reverse order. (Last message is displayed on the top of the program.)
* ```Users``` function shows online and away users.
* ```Exit``` function exits the program by closing all active sockets immediately and finishing all the active threads.