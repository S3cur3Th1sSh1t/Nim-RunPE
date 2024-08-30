# Nim-RunPE

A Nim implementation of reflective PE-Loading from memory. The base for this code was taken from [RunPE-In-Memory](https://github.com/aaaddress1/RunPE-In-Memory) - which I ported to Nim.

You'll need to install the following dependencies:

`nimble install ptr_math winim`

I did test this with Nim Version 1.6.2 only, so use that version for testing or I cannot guarantee no errors when using another version.

## Compile

If you want to pass arguments on runtime or don't want to pass arguments at all compile via:

`nim c NimRunPE.nim`

If you want to hardcode custom arguments modify `const exeArgs` to your needs and compile with:

`nim c -d:args NimRunPE.nim` - this was contributed by [@glynx](https://github.com/glynx), thanks! :sunglasses:

If you want full Thread Local Storage (TLS) callback support, **allowing execution of Rust PEs** etc, compile with:

`nim c -d:full_tls NimRunPE.nim`

Credit to [BlackBone](https://github.com/DarthTon/Blackbone) & [lander's blog](https://landaire.net/reflective-pe-loader-for-xbox/)/[solstice-loader](https://github.com/exploits-forsale/solstice/tree/main/crates/solstice_loader)
for the implementation of the `full_tls` option.

## More Information

The technique itself it pretty old, but I didn't find a Nim implementation yet. So this has changed now. :)

![alt text](https://github.com/S3cur3Th1sSh1t/Nim-RunPE/raw/main/Nim-RunPE.PNG)

If you plan to load e.g. Mimikatz with this technique - make sure to compile a version from source on your own, as the release binaries don't accept arguments after being loaded reflectively by this loader. Why? I really don't know it's strange but a fact. If you compile on your own it will still work:

![alt text](https://github.com/S3cur3Th1sSh1t/Nim-RunPE/raw/main/Mimiload.PNG)

My private [Packer](https://twitter.com/ShitSecure/status/1482428360500383755) is also weaponized with this technique - but all Win32 functions are replaced with Syscalls there. That makes the technique stealthier.
