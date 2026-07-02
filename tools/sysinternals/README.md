# Optional Sysinternals Tools

Place official Microsoft Sysinternals binaries here if you want richer output. Download them directly from Microsoft:

- https://learn.microsoft.com/en-us/sysinternals/
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck

```text
autorunsc.exe
autorunsc64.exe
autorunsc64a.exe
sigcheck.exe
```

The audit also searches a root-level `Sysinternals` folder and subfolders. It selects the best Autoruns command-line binary for the current system architecture automatically.

The project does not redistribute these binaries; keep their original Microsoft license terms.
