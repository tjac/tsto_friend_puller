# tsto_friend_puller
Tool for downloading you and your friends' The Simpsons: Tapped Out towns


# How to use

Once you have installed the necessary modules (see the requirements.txt file), 
simply run the script as:

 ```python friend_puller.py```
 
The script will ask you for your email address. This will generate a verification
code that is sent to your email. Enter the verification code at the prompt and
the script will begin by first downloading your town (and your currency state)
immediately followed by pulling the towns of each of your friends. 

All saved towns (yours and your friends) are stored in the towns\ directory. 
These worlds can be loaded using one of the local TSTO servers available such as
[TSTO Server](https://github.com/tjac/tsto_server) or [GameServer-Reborn](https://github.com/TappedOutReborn/GameServer-Reborn).