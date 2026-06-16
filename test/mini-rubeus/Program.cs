using System;
using System.Collections.Generic;

namespace MiniRubeus
{
    // Mimic Rubeus's ICommand interface
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }

    // Mimic Rubeus's ArgumentParser.Parse
    public static class ArgumentParser
    {
        public static Dictionary<string, string> Parse(IEnumerable<string> args)
        {
            var arguments = new Dictionary<string, string>();
            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    idx = argument.IndexOf('=');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        arguments[argument] = string.Empty;
                    }
                }
            }
            return arguments;
        }
    }

    // 4 failing verb commands - mimic Rubeus naming exactly
    public class Asktgt : ICommand
    {
        public static string CommandName => "asktgt";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Ask TGT");
            if (!arguments.ContainsKey("/user"))
            {
                Console.WriteLine("[X] You must supply a /user");
                return;
            }
            Console.WriteLine("[*] user=" + arguments["/user"]);
            // Force trim to keep WfTcp + Networking surface (mimics Rubeus)
            var result = WasmForge.Helpers.WfTcp.SendRecv("127.0.0.1", 88, new byte[] { 0x00 });
            Console.WriteLine("[*] WfTcp returned " + (result == null ? "null" : result.Length + " bytes"));
        }
    }

    public class Asktgs : ICommand
    {
        public static string CommandName => "asktgs";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Ask TGS");
        }
    }

    public class Kerberoast : ICommand
    {
        public static string CommandName => "kerberoast";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Kerberoasting");
        }
    }

    public class Asreproast : ICommand
    {
        public static string CommandName => "asreproast";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: AS-REP roasting");
        }
    }

    // Some working verbs to compare
    public class Triage : ICommand
    {
        public static string CommandName => "triage";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: triage");
        }
    }

    public class Klist : ICommand
    {
        public static string CommandName => "klist";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: klist");
        }
    }

    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        public CommandCollection()
        {
            _availableCommands.Add(Asktgs.CommandName, () => new Asktgs());
            _availableCommands.Add(Asktgt.CommandName, () => new Asktgt());
            _availableCommands.Add(Asreproast.CommandName, () => new Asreproast());
            _availableCommands.Add(Kerberoast.CommandName, () => new Kerberoast());
            _availableCommands.Add(Triage.CommandName, () => new Triage());
            _availableCommands.Add(Klist.CommandName, () => new Klist());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            if (string.IsNullOrEmpty(commandName) || !_availableCommands.ContainsKey(commandName))
                return false;

            var command = _availableCommands[commandName].Invoke();
            command.Execute(arguments);
            return true;
        }
    }

    internal static class Program
    {
        public static void Main(string[] args)
        {
            Console.Error.WriteLine("[MINI-DBG-1] Main entry argc=" + (args == null ? -1 : args.Length));
            Console.Error.Flush();
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("Usage: mini-rubeus <verb> [args]");
                return;
            }

            var parsed = ArgumentParser.Parse(args);
            Console.Error.WriteLine("[MINI-DBG-2] Parsed " + parsed.Count + " args");
            Console.Error.Flush();

            var commandName = args[0];
            Console.Error.WriteLine("[MINI-DBG-3] commandName=" + commandName);
            Console.Error.Flush();

            var found = new CommandCollection().ExecuteCommand(commandName, parsed);
            Console.Error.WriteLine("[MINI-DBG-4] commandFound=" + found);
            Console.Error.Flush();

            if (!found)
                Console.WriteLine("Unknown verb: " + commandName);
        }
    }
}
