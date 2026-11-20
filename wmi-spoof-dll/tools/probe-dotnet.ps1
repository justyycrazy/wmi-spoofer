# probe-dotnet.ps1 -- .NET System.Management probe (PowerShell 5.1, ASCII only).
# Exercises the remaining consumer interception paths:
#   1) ManagementClass.GetInstances()  -> CreateInstanceEnum
#   2) [wmi] single instance           -> GetObject
# When WMI_PROBE_OUT is set (inherited by the injected child), all output is also
# written there as UTF-8 so probe results survive console codepage mangling.
$ErrorActionPreference = "Continue"
if ($env:WMI_PROBE_OUT) {
    Start-Transcript -Path $env:WMI_PROBE_OUT -Force | Out-Null
}

function Dump($ex) {
    if ($ex) {
        Write-Output ("EXC: {0}" -f $ex.GetType().FullName)
        Write-Output ("MSG: {0}" -f $ex.Message)
        $mgmt = $ex -as [System.Management.ManagementException]
        if ($mgmt) { Write-Output ("WMI HR: 0x{0:X8}" -f $mgmt.ErrorCode) }
        if ($ex.InnerException) { Write-Output ("INNER: {0} | {1}" -f $ex.InnerException.GetType().FullName, $ex.InnerException.Message) }
    } else {
        Write-Output "EXC: none"
    }
}

Write-Output "--- 1) ManagementClass.GetInstances ---"
$bb = $null
try {
    $bb = [wmiclass]'Win32_BaseBoard'
    Write-Output ("[wmiclass] ctor ok: path={0}" -f $bb.Path.Path)
} catch { Write-Output "CTOR FAILED:"; Dump $_.Exception }

try {
    $instances = $bb.GetInstances()
    $n = 0
    foreach ($i in $instances) {
        $n++
        Write-Output ("GetInstances #{0} SerialNumber={1}" -f $n, $i.SerialNumber)
    }
    Write-Output ("GetInstances count={0}" -f $n)
} catch { Write-Output "GETINSTANCES FAILED:"; Dump $_.Exception }

Write-Output "--- 2) [wmi] single instance (keyed path) ---"
try {
    $single = [wmi]'Win32_Processor.DeviceID="CPU0"'
    Write-Output ("[wmi] ProcessorId={0}" -f $single.ProcessorId)
} catch { Write-Output "WMI CAST FAILED:"; Dump $_.Exception }

if ($env:WMI_PROBE_OUT) { Stop-Transcript | Out-Null }
