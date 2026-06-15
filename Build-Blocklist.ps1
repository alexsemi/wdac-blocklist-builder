#Requires -RunAsAdministrator
<#
  Build an App Control (WDAC) blocklist from the EXEs in the CURRENT folder, then
  optionally apply / test / remove it on this machine.

  Zero input for the build: scans the current directory (top level only), names the
  output XML after the first exe found. AllowAll base + Publisher denies (one per
  unique signing cert) + FileName denies (one per exe). Multiple Policy Format
  BASE policy with a fresh GUID. Builds in ENFORCE mode (audit forced off) and
  compiles the .cip.

  SAFETY: before anything is built, it captures the identities (thumbprint,
  publisher = CN+issuing CA, and OriginalFileName) of the running PowerShell host,
  core Windows binaries, AND the registered antivirus product(s) from Security
  Center, then REFUSES to build if any staged exe would produce a rule matching
  one of them - that would brick or cripple the machine.

  cd into the folder with the staged binaries and run it.
#>

# ConfigCI/WDAC cmdlets are Windows PowerShell only. Under PS7 the Rule objects
# deserialize across the compat boundary and Merge-CIPolicy -Rules fails to bind,
# so re-launch in Windows PowerShell 5.1 if we're on Core (runs as-is in 5.1).
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Host "Re-launching under Windows PowerShell 5.1 (WDAC cmdlets require it)..." -ForegroundColor Yellow
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '$($PWD.Path)'; & '$PSCommandPath'"
    return
}

# 0. Locate the shipped AllowAll base
$allowAll = Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
if (-not (Test-Path $allowAll)) { throw "AllowAll.xml not found at $allowAll" }

# ============================================================================
# SAFETY GUARD (built first) - identities we must NEVER deny.
#   Publisher deny  -> keys on (leaf CN + issuing CA)  -> brick risk
#   FileName deny   -> keys on embedded OriginalFileName
#   Captured from the running PowerShell host, core system binaries, AND the
#   registered AV product(s): thumbprint, publisher (Subject + issuing CA),
#   and OriginalFileName.
# ============================================================================
$protectedThumbs    = New-Object 'System.Collections.Generic.HashSet[string]'
$protectedPubs      = New-Object 'System.Collections.Generic.HashSet[string]'
$protectedFileNames = New-Object 'System.Collections.Generic.HashSet[string]'

$selfHost = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName   # the PS host you're in
$sys32    = Join-Path $env:windir 'System32'

# Discover registered antivirus product(s) from Security Center and protect their
# signed binaries too. (root\SecurityCenter2 is client-OS only; wrapped in try.)
$avBins = @()
try {
    foreach ($av in Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop) {
        $rt = ('{0:X6}' -f [int]$av.productState).Substring(2,2)   # middle byte: 10/11 = real-time ON
        $on = $rt -in '10','11'
        Write-Host ("  AV registered  : {0}  ({1})" -f $av.displayName, $(if ($on) {'active'} else {'present/off'})) -ForegroundColor Cyan
        foreach ($p in @($av.pathToSignedProductExe, $av.pathToSignedReportingExe)) {
            if ($p -and (Test-Path -LiteralPath $p)) { $avBins += $p }   # Defender often reports a URI here, not a path
        }
    }
} catch {
    Write-Warning "Security Center query failed (root\SecurityCenter2 is client-OS only): $($_.Exception.Message)"
}
# Defender reports 'windowsdefender://' rather than a file path, so grab its live engine if running.
$mp = Get-Process MsMpEng -ErrorAction SilentlyContinue | Select-Object -First 1
if ($mp -and $mp.Path) { $avBins += $mp.Path }
$avBins = $avBins | Select-Object -Unique
if ($avBins) { Write-Host ("  AV binaries    : {0}" -f ($avBins -join '; ')) -ForegroundColor Cyan }

$guardFiles = (@(
    $selfHost,                                  # the PowerShell host you're running
    (Join-Path $sys32      'kernel32.dll'),     # core Win32 API
    (Join-Path $sys32      'ntdll.dll'),        # lowest-level user-mode DLL
    (Join-Path $env:windir 'explorer.exe'),     # the shell
    (Join-Path $sys32      'winlogon.exe'),     # logon
    (Join-Path $sys32      'wininit.exe'),      # Windows init
    (Join-Path $sys32      'csrss.exe'),        # client/server runtime
    (Join-Path $sys32      'services.exe'),     # service control manager
    (Join-Path $sys32      'lsass.exe'),        # local security authority
    (Join-Path $sys32      'smss.exe'),         # session manager
    (Join-Path $sys32      'svchost.exe'),      # service host
    (Join-Path $sys32      'cmd.exe'),          # recovery shell
    (Join-Path $sys32      'conhost.exe'),      # console host (cmd/PS windows need it)
    (Join-Path $env:windir 'regedit.exe'),      # registry editor (recovery)
    (Join-Path $sys32      'mmc.exe'),          # management consoles
    (Join-Path $sys32      'rundll32.exe'),     # common Windows host process
    (Join-Path $sys32      'dllhost.exe'),      # COM surrogate host
    (Join-Path $sys32      'CiTool.exe')        # the tool that REMOVES WDAC policies - never ban it
) + $avBins) | Select-Object -Unique           # MsMpEng.exe / 3rd-party AV come in via $avBins (path is version-stamped)

foreach ($g in $guardFiles) {
    if (-not (Test-Path -LiteralPath $g)) { Write-Warning "Guard file missing (skipped): $g"; continue }
    $gsig = Get-AuthenticodeSignature -FilePath $g
    if ($gsig.SignerCertificate) {
        [void]$protectedThumbs.Add($gsig.SignerCertificate.Thumbprint)
        [void]$protectedPubs.Add(('{0}||{1}' -f $gsig.SignerCertificate.Subject, $gsig.SignerCertificate.Issuer))
    } else {
        Write-Warning "Guard file unsigned, publisher not captured: $g"
    }
    $gon = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($g).OriginalFilename
    if ($gon) { [void]$protectedFileNames.Add($gon.ToLowerInvariant()) }
}
Write-Host ("Safety guard   : {0} certs / {1} publishers / {2} filenames protected" -f `
    $protectedThumbs.Count, $protectedPubs.Count, $protectedFileNames.Count) -ForegroundColor Cyan

function Get-GuardViolation($Signature, [string]$OriginalName) {
    # returns a reason string if a rule from this binary would endanger a protected identity
    if ($Signature.SignerCertificate) {
        if ($protectedThumbs.Contains($Signature.SignerCertificate.Thumbprint)) {
            return 'signing-cert thumbprint matches a protected system/AV binary'
        }
        $pub = '{0}||{1}' -f $Signature.SignerCertificate.Subject, $Signature.SignerCertificate.Issuer
        if ($protectedPubs.Contains($pub)) {
            return 'publisher (leaf CN + issuing CA) matches a protected system/AV binary - a Publisher deny would brick the OS or kill the AV'
        }
    }
    # --- optional hardening: refuse ANY Microsoft-signed binary (uncomment to enable) ---
    # if ($Signature.SignerCertificate -and (
    #     $Signature.SignerCertificate.Subject -match 'Microsoft' -or
    #     $Signature.SignerCertificate.Issuer  -match 'Microsoft')) {
    #     return 'signed by Microsoft - refusing to deny Microsoft-signed code'
    # }
    if ($OriginalName -and $protectedFileNames.Contains($OriginalName.ToLowerInvariant())) {
        return "OriginalFileName '$OriginalName' matches a protected system/AV binary - a FileName deny would break it"
    }
    return $null
}

# 1. Current folder EXEs (top level only). First exe (sorted) names the output.
$stagingPath = (Get-Location).Path
$exes = Get-ChildItem -Path $stagingPath -Filter *.exe -File | Sort-Object Name
if (-not $exes) { throw "No .exe files found in $stagingPath" }

# SAFETY pre-flight - refuse to build if ANY staged exe would endanger a protected binary.
$violations = @()
foreach ($exe in $exes) {
    $vsig = Get-AuthenticodeSignature -FilePath $exe.FullName
    $von  = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe.FullName).OriginalFilename
    $reason = Get-GuardViolation $vsig $von
    if ($reason) { $violations += [pscustomobject]@{ File = $exe.FullName; Reason = $reason } }
}
if ($violations.Count) {
    Write-Host ""
    Write-Host "ABORTED - staged binaries would endanger the system:" -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host ("  {0}" -f $v.File) -ForegroundColor Red
        Write-Host ("      -> {0}" -f $v.Reason) -ForegroundColor Red
    }
    Write-Host ""
    throw "Refusing to build. Remove the flagged file(s) from the staging folder and re-run."
}
Write-Host "Safety check   : passed (no staged binary matches a protected identity)" -ForegroundColor Cyan

$first      = $exes[0]
$policyName = "Block - $($first.BaseName)"
$outputXml  = Join-Path $stagingPath "$($first.BaseName).xml"
Write-Host ("Current folder : {0}" -f $stagingPath)
Write-Host ("EXEs found     : {0}" -f $exes.Count)
Write-Host ("Output policy  : {0}  (name: {1})" -f $outputXml, $policyName)

# 2. Copy AllowAll to the output file
Copy-Item -Path $allowAll -Destination $outputXml -Force

$deny      = @()
$seenCerts = @{}
$seenNames = @{}

# 3. Publisher deny rules - one per UNIQUE signing cert (block the signer regardless
#    of trust/expiry; presence of a SignerCertificate is the only test)
foreach ($exe in $exes) {
    $sig = Get-AuthenticodeSignature -FilePath $exe.FullName
    if ($sig.SignerCertificate) {
        $tp = $sig.SignerCertificate.Thumbprint
        if (-not $seenCerts.ContainsKey($tp)) {
            $seenCerts[$tp] = $true
            Write-Host ("  Publisher  <- {0}  [{1}]" -f $exe.Name, $sig.SignerCertificate.Subject)
            $deny += New-CIPolicyRule -DriverFilePath $exe.FullName -Level Publisher -Deny -Fallback FileName
        }
    } else {
        Write-Warning ("  {0} unsigned - FileName/Hash only" -f $exe.Name)
    }
}

# 4. FileName deny rules - one per exe (embedded OriginalFileName; Hash fallback)
foreach ($exe in $exes) {
    if (-not $seenNames.ContainsKey($exe.Name)) {
        $seenNames[$exe.Name] = $true
        Write-Host ("  FileName   <- {0}" -f $exe.Name)
        $deny += New-CIPolicyRule -DriverFilePath $exe.FullName -Level FileName -Deny -Fallback Hash
    }
}
Write-Host ("Deny rules     : {0}  ({1} unique certs)" -f $deny.Count, $seenCerts.Count)

# 5. Merge deny rules into AllowAll
Merge-CIPolicy -PolicyPaths $outputXml -Rules $deny -OutputFilePath $outputXml | Out-Null

# 6. Options: UMCI on (governs user-mode apps). Audit mode forced OFF -> ENFORCE.
Set-RuleOption -FilePath $outputXml -Option 0                                          # Enabled:UMCI
Set-RuleOption -FilePath $outputXml -Option 3 -Delete -ErrorAction SilentlyContinue    # make sure NOT audit

# 7. Fresh GUID + name -> lets multiple policies coexist on a device
Set-CIPolicyIdInfo -FilePath $outputXml -PolicyName $policyName -ResetPolicyID | Out-Null

# 7b. Strip the build/staging path out of rule FriendlyNames (cosmetic - keeps
#     "C:\Staging\..." from riding along in the policy that ships to devices)
[xml]$doc = Get-Content -LiteralPath $outputXml -Raw
$rx = [regex]::Escape("$stagingPath\")
foreach ($node in $doc.SelectNodes('//*[@FriendlyName]')) {
    $fn = $node.GetAttribute('FriendlyName')
    $node.SetAttribute('FriendlyName', [regex]::Replace($fn, $rx, '', 'IgnoreCase'))
}
$doc.Save($outputXml)
Write-Host "Done: $outputXml"

# 8. Compile the .cip (named by the policy GUID; Intune App Control takes the XML instead)
$guid = ($doc.SiPolicy.PolicyID) -replace '[{}]',''
$cip  = Join-Path $stagingPath "$guid.cip"
ConvertFrom-CIPolicy -XmlFilePath $outputXml -BinaryFilePath $cip | Out-Null
Write-Host "Compiled: $cip"

# 9. Apply on THIS machine for testing -> test -> remove
function Confirm-Step([string]$Message) {
    return ((Read-Host "$Message [y/N]") -match '^(y|yes)$')
}

Write-Host ""
if (Confirm-Step "Do you want to apply it for testing?") {
    CiTool --update-policy $cip
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Applied (enforce). Policy ID: $guid" -ForegroundColor Green
    } else {
        Write-Warning "CiTool returned exit code $LASTEXITCODE - check the message above."
    }
    Write-Host "On Win11 a fresh enforce policy is active right away. If the app still runs," -ForegroundColor DarkGray
    Write-Host "reboot once and re-test. Cleanup after a reboot: CiTool --remove-policy $guid" -ForegroundColor DarkGray
    Write-Host ""

    Read-Host "Test now - try launching the blocked app, then press Enter to continue"

    if (Confirm-Step "Do you want to remove it?") {
        CiTool --remove-policy $guid
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Removed. Reboot to fully unload if anything lingers." -ForegroundColor Green
        } else {
            Write-Warning "CiTool returned exit code $LASTEXITCODE - remove manually: CiTool --remove-policy $guid"
        }
    } else {
        Write-Host "Left in place. Remove later with: CiTool --remove-policy $guid"
    }
} else {
    Write-Host "Not applied. Apply later with: CiTool --update-policy `"$cip`""
}
