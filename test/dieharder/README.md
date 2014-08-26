##Dieharder test for Titan Secure Volume##

This program uses the Titan Secure Volume library to create volumes on the fly, and dump them to stdout.
The result can then be fed into Dieharder to test the randomness of TSVs.


**To compile for linux**
* make

**To compile for x86 (Cygwin's MinGW)**
* make CYGWIN_MINGW=1
