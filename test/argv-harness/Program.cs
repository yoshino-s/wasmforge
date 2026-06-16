using System;

namespace ArgvTest
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            Console.Error.WriteLine("[ARGV-TEST] Main entry");
            Console.Error.WriteLine("[ARGV-TEST] argc=" + (args == null ? -1 : args.Length));
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    Console.Error.WriteLine("[ARGV-TEST] argv[" + i + "]=" + args[i]);
                }
            }
            Console.Error.WriteLine("[ARGV-TEST] done");
            return 0;
        }
    }
}
