# Build-Blocklist

A PowerShell tool that builds a **Windows App Control for Business (WDAC)** *blocklist* policy from a folder of executables, with safety guards that refuse to deny core system or antivirus binaries. Optionally applies, tests, and removes the policy on the local machine.

It produces an "allow everything except these" policy (Microsoft's `AllowAll` base + Publisher and FileName **deny** rules), which is the right shape for blocking a handful of specific unwanted apps without locking down the whole device.

---

## ⚠️ Disclaimer

App Control / WDAC operates in the kernel. A misapplied policy can render a machine **unbootable or unusable**, or can block security and management tooling. This script is provided **as-is, with no warranty**. Test on an isolated VM or a pilot device you can recover before using it anywhere that matters, and keep a recovery path (the policy GUID and `CiTool --remove-policy`). You are responsible for what you deploy.

This script builds in **enforce** mode and offers to apply immediately - it does not run in audit mode. Understand that before answering the apply prompt.

---

## What it does

- Scans the **current folder** (top level only) for `*.exe`.
- Generates **Publisher** deny rules - one per unique signing certificate, so a single rule covers every binary that vendor signs regardless of filename or version.
- Generates **FileName** deny rules - one per exe, as a version- and CA-agnostic backstop (with a hash fallback for unsigned files).
- Merges those into Microsoft's shipped `AllowAll` base, names the policy after the first exe, stamps a fresh GUID (so multiple policies coexist), strips the build path from rule names, and compiles the `.cip`.
- Then asks whether to **apply** it for testing, lets you test, and asks whether to **remove** it.

## Safety guard

Before building, it captures the identity of the running PowerShell host, core Windows binaries (kernel32, ntdll, explorer, winlogon, lsass, services, csrss, smss, svchost, cmd, conhost, regedit, mmc, rundll32, dllhost, CiTool), and the **registered antivirus product(s)** discovered from Security Center. For each it records the signing-cert thumbprint, the publisher identity (leaf CN + issuing CA), and the OriginalFileName.

It then **refuses to build** if any staged exe would produce a rule matching one of those - because a Publisher deny built from a Microsoft-signed binary would brick the OS, and a FileName deny on a system filename would break it. The publisher check (not just the thumbprint) is what actually catches this, since signing certs rotate but the publisher identity a WDAC rule keys on does not.

## Requirements

- Windows 10 1903+ (Windows 11 recommended for rebootless policy apply via `CiTool`).
- **Windows PowerShell 5.1** - the WDAC `ConfigCI` cmdlets don't run natively under PowerShell 7. The script auto-relaunches itself into 5.1 if started from 7.
- Run **as Administrator**.
- App Control for Business available on the device.

## Usage

```powershell
# Put the binaries you want to block in a folder, then:
cd C:\path\to\staged-binaries
.\Build-Blocklist.ps1
```

The script reports what it found, builds the policy and `.cip`, then prompts:

1. `Do you want to apply it for testing?` - applies via `CiTool --update-policy`.
2. `Test now ... press Enter to continue` - try launching the blocked app.
3. `Do you want to remove it?` - removes via `CiTool --remove-policy`.

It prints the policy GUID and the manual removal command so you can clean up even if you reboot to test.

## Deploying at scale

The compiled `.cip` and the policy `.xml` are both written next to the binaries. For fleet deployment, upload the **XML** to an Intune **App Control for Business** policy (Intune compiles it). The `.cip` is only needed for the custom OMA-URI route.

## License

See `LICENSE` (choose one appropriate to your situation - e.g. MIT for a personal utility, subject to any employer/engagement constraints on the code).
