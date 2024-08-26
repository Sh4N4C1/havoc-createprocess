# havoc-createprocess

1. lanuch a process via ntcreateuserprocess
2. find target process RWX memory hole
3. inject `while(TRUE){ Sleep(1000); }` shellcode into RWX memory hole
4. the trampoline will patched runtime, replace the addr to RWX memory hole addr.
5. install Trampoline on Target process exit function 
6. when call process exit function, the trampolie will jump to our never exit shellcode

## usage

```
# normal create process
createprocess C:\Windows\System32\cmd.exe "/c whoami" 0

# create a no exit process
createprocess C:\Windows\System32\cmd.exe "/c whoami" 1
```

## credits
https://github.com/capt-meelo/NtCreateUserProcess

https://github.com/merlinepedra/ShellcodeTemplate
