// hello.cs — Minimal .NET assembly for CLR load testing.
// Compile on Win11:
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:hello.exe /platform:anycpu hello.cs
using System;

class Program {
    static int Main(string[] args) {
        Console.WriteLine("PASS:clr_assembly:hello_from_dotnet");
        if (args.Length > 0)
            Console.WriteLine("PASS:clr_assembly:args=" + args[0]);
        return 0;
    }
}
