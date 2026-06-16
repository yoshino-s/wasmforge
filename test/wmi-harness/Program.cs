// wmi-harness — direct exercise of the host-side wmi_query_r env import.
// Mirrors crypto-harness/lsa-harness. Goal: pin down why Seatbelt's AntiVirus
// and WMIEventConsumer commands return empty, given the patcher already
// routes them through WfWmi.QueryRestricted (which calls wmi_query_r below).
//
// Tests three layers:
//  L1: raw env import wmi_query_r — sanity of host bridge.
//  L2: WfWmi.QueryRestricted     — same path Seatbelt uses; surfaces any
//                                  bug in the JSON walk or EnsureInitialized.
//  L3: AntiVirusDTO-style class with object getters + reflection — surfaces
//      any NativeAOT trim issue with getter-only properties (the actual bug).

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using WasmForge.Helpers;

namespace WmiTest
{
    internal static unsafe class Bridge
    {
        [DllImport("env", EntryPoint = "wmi_query_r")]
        internal static extern uint WmiQueryRestricted(
            uint queryPtr, uint queryLen,
            uint nsPtr,    uint nsLen,
            uint outBufPtr, uint outBufLen);
    }

    // Mirrors Seatbelt's AntiVirusDTO exactly: getter-only object properties
    // set in constructor. This is the shape DefaultTextFormatter reflects over.
    internal class AntiVirusDTO
    {
        public AntiVirusDTO(object engine, object productExe, object reportingExe)
        {
            Engine = engine;
            ProductEXE = productExe;
            ReportingEXE = reportingExe;
        }
        public object Engine { get; }
        public object ProductEXE { get; }
        public object ReportingEXE { get; }
    }

    internal static class Program
    {
        static int L1_RawEnv(string nspace, string wql)
        {
            Console.WriteLine();
            Console.WriteLine("[L1 raw env] " + nspace + " ::: " + wql);

            byte[] queryBytes = Encoding.UTF8.GetBytes(wql);
            byte[] nsBytes    = Encoding.UTF8.GetBytes(nspace);
            byte[] outBuf     = new byte[131072];
            uint written;
            unsafe
            {
                fixed (byte* qp = queryBytes, np = nsBytes, op = outBuf)
                {
                    written = Bridge.WmiQueryRestricted(
                        (uint)(ulong)qp, (uint)queryBytes.Length,
                        (uint)(ulong)np, (uint)nsBytes.Length,
                        (uint)(ulong)op, (uint)outBuf.Length);
                }
            }
            Console.WriteLine("  written: " + written + " bytes");
            if (written == 0) { Console.WriteLine("  → EMPTY"); return 1; }
            string json = Encoding.UTF8.GetString(outBuf, 0, (int)written);
            Console.WriteLine("  JSON head: " + (json.Length > 256 ? json.Substring(0, 256) + "..." : json));
            return 0;
        }

        static int L2_WfWmi(string nspace, string wql)
        {
            Console.WriteLine();
            Console.WriteLine("[L2 WfWmi.QueryRestricted] " + nspace + " ::: " + wql);
            List<Dictionary<string, object>> rows = null;
            try
            {
                rows = WfWmi.QueryRestricted(nspace, wql);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  THREW: " + ex.GetType().Name + ": " + ex.Message);
                return 1;
            }
            if (rows == null) { Console.WriteLine("  rows==null"); return 1; }
            Console.WriteLine("  rows.Count=" + rows.Count);
            int i = 0;
            foreach (var row in rows)
            {
                i++;
                Console.WriteLine("  row[" + i + "]: " + row.Count + " keys");
                foreach (var kv in row)
                {
                    string vs = kv.Value == null ? "<null>" : kv.Value.ToString();
                    if (vs.Length > 60) vs = vs.Substring(0, 60) + "...";
                    Console.WriteLine("    " + kv.Key + " = " + vs);
                }
            }
            return rows.Count > 0 ? 0 : 1;
        }

        // L3 simulates Seatbelt's DefaultTextFormatter: create the DTO, call
        // type.GetProperties(), print name + value. If trim strips the
        // getter-only properties on AntiVirusDTO, this returns 0 properties
        // and silently prints nothing — matching the seatbelt-test.exe symptom.
        static int L3_DtoReflection()
        {
            Console.WriteLine();
            Console.WriteLine("[L3 DTO + reflection]");
            var rows = WfWmi.QueryRestricted(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            if (rows == null || rows.Count == 0) { Console.WriteLine("  no rows"); return 1; }

            var dto = new AntiVirusDTO(
                rows[0].ContainsKey("displayName") ? rows[0]["displayName"] : null,
                rows[0].ContainsKey("pathToSignedProductExe") ? rows[0]["pathToSignedProductExe"] : null,
                rows[0].ContainsKey("pathToSignedReportingExe") ? rows[0]["pathToSignedReportingExe"] : null);

            var type = dto.GetType();
            var props = type.GetProperties();
            Console.WriteLine("  GetProperties() returned " + props.Length + " props");
            foreach (var p in props)
            {
                object val = null;
                try { val = p.GetValue(dto, null); }
                catch (Exception ex) { val = "<threw " + ex.GetType().Name + ">"; }
                Console.WriteLine("  " + p.Name.PadRight(20) + " : " + (val == null ? "<null>" : val.ToString()));
            }
            return props.Length > 0 ? 0 : 1;
        }

        static int Main()
        {
            Console.WriteLine("=== WMI Bridge Triage (wmi_query_r) ===");
            int failures = 0;

            // L1 — raw bridge (already confirmed working in prior run).
            failures += L1_RawEnv("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            failures += L1_RawEnv("ROOT\\Subscription",    "SELECT * FROM __EventConsumer");

            // L2 — through WfWmi.QueryRestricted (same path Seatbelt uses).
            failures += L2_WfWmi("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            failures += L2_WfWmi("ROOT\\Subscription",    "SELECT * FROM __EventConsumer");

            // L3 — DTO with getter-only props + reflection (Seatbelt formatter).
            failures += L3_DtoReflection();

            Console.WriteLine();
            Console.WriteLine(failures == 0 ? "=== ALL PASS ===" : "=== " + failures + " FAILED ===");
            return failures;
        }
    }
}
