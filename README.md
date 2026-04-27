# PasswordSafe (WIP)
A safe for all your password, only local, and managed by you and you only.


# 1) how does it works ?

## Compilation
At first, compile the PasswordSafe.cpp file (if you get rid of the windows.h import it should work correctly).
For example on Windows : 
```cl /std:c++17 /EHsc PasswordSafe.cpp bcrypt.lib kernel32.lib```


## How to run it ?
on windows : click on the icone or run 
```.\PasswordSafe.exe```
in the same folder of the compiled file.

on Linux: 
```
chmod +x PasswordSafe
./PasswordSafe

```
In the same folder of the compiled file.

## What should i do next ?
### if you don't have a file you might want to generate one first, so when you are prompted :
```
 choose between openning a file or creating one :
 [0] open an existing file
 [1] creat a new file
 [2] Quit
```
Type 1 and then enter filname when asked to.

Then you can either choose to quit (2) or to open a file (0).

### If you choosed to open a file:
enter the source file when asked : 
```
Source folder:
```
then type your password (nothing should be prompt to show that you have to type it).

### if its your first time openning a file : 
you might encounter the following message: 
```
got issue while loading security measures with LD_SEC
```
nothing wrong with it at that point, as there is no encrypted BLOBs, the parser LD_SEC did not found anything.

Enter website name, username, and password when prompted to.

you should get the following message:
```
entry saved correctly
```
And then be asked to enter a password (same thing everytime the password file will be saved).

### if it isn't the first time you open a file :

Enjoy the software ;) 
(all info are prompted when running)


# 2) File Format:

```
Plaintext block (encrypted as a whole):
   [4B] entry count N
   For each entry:
     [1B] name length
     [website bytes]
     [1B] number of entry
     For each entry : 
         [1B] username length
         [username bytes]
         [1B] password length\
         [password bytes]

On-disk file:
   Magic   : "KRG1" (4 bytes)
   Salt    : 16 bytes
   IV+tag+ciphertext (rest of file)
```

# 3) Limit of a single file :
Limit of website : 65535 websites\
limit of entries for a single website : 256 passwords and usernames
