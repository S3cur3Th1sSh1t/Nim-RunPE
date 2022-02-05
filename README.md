# Nim-RunPE

A Nim implementation of reflective PE-Loading from memory. The base for this code was taken from [RunPE-In-Memory](https://github.com/aaaddress1/RunPE-In-Memory) - which I ported to Nim.

The technique itself it pretty old, but I didn't find a Nim implementation yet. So this has changed now. :)

![alt text](https://github.com/S3cur3Th1sSh1t/Nim-RunPE/raw/main/Nim-RunPE.PNG)

My private [Packer](https://twitter.com/ShitSecure/status/1482428360500383755) will also get weaponized with this technique - but all Win32 functions will be replaced with Syscalls there which will make the technique stealthier.
