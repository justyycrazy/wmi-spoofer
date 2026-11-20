' probe-wbemdisp.vbs -- WMI scripting-layer probe (WbemScripting / SWbemServices)
' Exercises the scripting-layer consumer paths (InstancesOf / moniker GetObject /
' moniker ExecQuery); keep ASCII-only so
' cscript parses it on any OEM codepage. Per-step error reporting on purpose.
'   1) explicit locator -> ConnectServer -> InstancesOf
'   2) moniker GetObject single-instance path (Win32_Processor.DeviceID="CPU0")
'   3) moniker ExecQuery control (already-covered path)
On Error Resume Next

WScript.Echo "--- 1) InstancesOf (explicit locator) ---"
Set loc = CreateObject("WbemScripting.SWbemLocator")
Set svc = loc.ConnectServer(".", "root\cimv2")
If Err.Number <> 0 Then
    WScript.Echo "ConnectServer failed: 0x" & Hex(Err.Number)
    WScript.Quit 1
End If
Set objs = svc.InstancesOf("Win32_BaseBoard")
If Err.Number <> 0 Then
    WScript.Echo "InstancesOf call failed: 0x" & Hex(Err.Number)
    Err.Clear
End If
n = 0
On Error GoTo 0
For Each o In objs
    n = n + 1
    v = o.SerialNumber
    WScript.Echo "InstancesOf #" & n & " SerialNumber=" & v
Next
If Err.Number <> 0 Then
    WScript.Echo "ENUM ERR: 0x" & Hex(Err.Number) & " (instances so far: " & n & ")"
    Err.Clear
End If
On Error Resume Next
WScript.Echo "InstancesOf count=" & n

WScript.Echo "--- 2) GetObject moniker single instance ---"
Set bbObj = GetObject("winmgmts:root\cimv2:Win32_Processor.DeviceID=""CPU0""")
If Err.Number <> 0 Then
    WScript.Echo "GetObject DeviceID=""CPU0"" failed: 0x" & Hex(Err.Number)
    Err.Clear
Else
    On Error GoTo 0
    v = bbObj.ProcessorId
    WScript.Echo "GetObject ProcessorId=" & v
    If Err.Number <> 0 Then
        WScript.Echo "PROP READ ERR: 0x" & Hex(Err.Number)
        Err.Clear
    End If
    On Error Resume Next
End If

WScript.Echo "--- 3) ExecQuery (moniker, control) ---"
Set q = GetObject("winmgmts:root\cimv2")
Set rs = q.ExecQuery("SELECT * FROM Win32_BaseBoard")
m = 0
On Error GoTo 0
For Each o In rs
    m = m + 1
    v = o.SerialNumber
    WScript.Echo "ExecQuery(vbs) #" & m & " SerialNumber=" & v
Next
If Err.Number <> 0 Then
    WScript.Echo "ENUM ERR: 0x" & Hex(Err.Number) & " (instances so far: " & m & ")"
    Err.Clear
End If
On Error Resume Next
WScript.Echo "ExecQuery(vbs) count=" & m
