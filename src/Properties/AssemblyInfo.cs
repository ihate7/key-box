using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[assembly: AssemblyTitle("KeyBox")]
[assembly: AssemblyDescription("Portable encrypted password vault")]
[assembly: AssemblyProduct("KeyBox")]
[assembly: AssemblyVersion("1.1.0.0")]
[assembly: AssemblyFileVersion("1.1.0.0")]
[assembly: ComVisible(false)]

// Программа рассчитана на .NET Framework 4.8 — он входит в состав Windows 10 и 11.
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

// Системные библиотеки загружаются только из System32: подложенная рядом с программой
// (например, на флешке) bcrypt.dll или user32.dll не будет подхвачена.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
