# NoMoreBugCheck

Prevent Windows from BSODing no matter what happens!

# Warning

Using this is the equivalent of disabling the circuit breaker in your house.
Windows BSODs whenever a serious problem occurs to prevent memory/data corruption.
Although your computer won't blow up you could corrupt memory/data present on the system.
This was done only for fun and should not be used for any serious purposes.
I am not responsible for loss of any data or damage to the system.

# What does it hook?

The driver inline-hooks every entry point of the bugcheck machinery (x64 only):

| Target              | Found by                                                  |
|---------------------|-----------------------------------------------------------|
| `KeBugCheckEx`      | Exported symbol                                            |
| `KeBugCheck2`       | Scanning `KeBugCheckEx` body + prologue validation + fallback |
| `KiBugCheckDispatch`| Scanning `KeBugCheckEx` body for `pushfq` prologue         |
| `KiDisplayBlueScreen` | Pattern-scanning the wrapper after `KiBugCheckDispatch`  |

## Version compatibility

Verified against **all 31 major ntoskrnl versions** from Windows 10 1507
(build 10240) through Windows 11 Insider (build 29639).

| Era                  | Builds           | KeBugCheck2 prologue                     |
|----------------------|------------------|------------------------------------------|
| Win10 1507           | 10240            | `mov [rsp+8], rbx`                       |
| Win10 1511 ~ Win11 23H2 | 10586–22621   | `mov [rsp+18h], rbx; push rbp`           |
| Win11 24H2+ / Insider   | 26100+         | 8 pushes (`rbp,rbx,rsi,rdi,r12..r15`)   |

The scan logic automatically:
1. Finds the actual function boundary (`ret + padding`) to avoid scanning into neighboring functions.
2. Tries multiple prologue patterns.
3. Falls back to taking the last unclassified call in `KeBugCheckEx` (which is always `KeBugCheck2`).

`KiBugCheckDispatch` (`pushfq; mov [rcx+78h],rax`) and `KiDisplayBlueScreen` (wrapper pattern) are consistent across all builds.

# How to use?

1. Enable test signing

```
bcdedit /set testsigning on
```

2. Create a service using SC

```
sc create NoMoreBugCheck binPath=C:\where\ever\the\driver\is\NoMoreBugCheck.sys type=kernel start=manual
```

3. Run it!

```
sc start NoMoreBugCheck
```

# Demo

https://user-images.githubusercontent.com/51860844/146301386-68e4b170-89c1-441e-97b0-c5bdd2b16ed8.mp4

# Note

- If you want to revert the changes just unload the driver by running
```
sc stop NoMoreBugCheck
```

- The system can hang if the problem was severe.

# Analysis scripts

The `analysis/` directory contains Python scripts used to reverse-engineer
the bugcheck chain across all major ntoskrnl versions.  These can be
re-run on any machine with `pefile` and `capstone` installed:

```bash
pip install pefile capstone
python analysis/verify_all_final.py
```
