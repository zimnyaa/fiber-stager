# fiber-stager
 A simple Nim stager (w/ fiber execution)

## tl;dr


This repo accompanies a post on https://tishina.in/execution/nim-fibers

It is essentially a simple stager PoC that uses syscalls+FreshCopy for `ntdll` unhooking and fibers for shellcode execution


## usage
`python3 encoder.py <shcode_file>` to encode the shellcode (AES encryption coming soon™).

Upload the resulting `<shcode_file>.html` somewhere and change the URL in the fiberstager (you can also regenerate the `syscalls.nim` file with NimlineWhispers2)

fiber-stager is built with just `nim c` and your preferred flags. 

**dependencies:** winim, ptr_math

# credits
@[ajpc500](https://github.com/ajpc500) for NimlineWhispers2
@[khchen](https://github.com/khchen) for Winim
@[byt3bl33d3r](https://github.com/byt3bl33d3r) for the ntdll unhooking example
