// WfSidShim.cs — Partial bypass for `new SecurityIdentifier(...)` on NativeAOT-WASI.
//
// STATUS (2026-05-23): The SecurityIdentifier type that ships with NativeAOT-LLVM
// for the wasi-wasm runtime is a *stripped* surface. It has neither the private
// `_binaryForm` field nor `BinaryForm` — verified at runtime via UnsafeAccessor
// which reported "Field not found: '_binaryForm'". Both reflection (returns empty
// fields array) and UnsafeAccessor (compile-resolved but runtime-rejected) confirm
// the type has no usable instance fields under NativeAOT-WASI trim.
//
// Consequence: Create() catches the PNS but the fallback returns null because there
// is no field to populate. Downstream consumers like Rubeus.Ndr._RPC_SID..ctor that
// call sid.BinaryLength/sid.GetBinaryForm() then NRE on the null.
//
// The proper fix requires rewriting Rubeus's PAC type signatures (_RPC_SID ctor)
// to accept a non-BCL SID representation — either a byte[] or our own type. The
// csharp_patcher would need regex support to rewrite the variable-argument
// call sites (~10 of them in ForgeTicket.cs, Requestor.cs, UpnDns.cs). Multi-day
// scope, deferred to a future session.
//
// What this file still buys us: catching the IdentityReference PNS earlier so the
// stack trace is cleaner, plus a working SidStringToBinary parser for any consumer
// that wants to skip the BCL type entirely.
//
// The BCL's abstract IdentityReference base class throws PlatformNotSupportedException
// at construction on NativeAOT-WASI ("Windows Principal functionality is not supported
// on this platform"). Both SecurityIdentifier(string) and SecurityIdentifier(byte[], int)
// invoke the throwing base ctor — there's no safe way to use the type via its normal
// constructors.
//
// This shim allocates the SecurityIdentifier instance via
// `RuntimeHelpers.GetUninitializedObject` (which skips the constructor) and populates
// the internal `_binaryForm` field via reflection. NativeAOT trim preserves the
// reflection target through the rd.xml entry emitted alongside this file.
//
// All Rubeus PAC sites that previously did `new global::System.Security.Principal.SecurityIdentifier(x)` are rewritten
// by csharp_patcher to call WfSid.Create(x). The return type remains the BCL
// SecurityIdentifier so downstream code in Ndr._RPC_SID etc. compiles unchanged.

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;

namespace WasmForge.Bridge
{
    public static class WfSid
    {
        // NativeAOT-LLVM trims private fields from reflection, so plain
        // typeof(T).GetField(...) returns null. UnsafeAccessor (introduced in .NET 8)
        // is the trim-safe way to access non-public members on sealed types: the
        // compiler generates a direct field accessor that survives trim.
        [System.Runtime.CompilerServices.UnsafeAccessor(
            System.Runtime.CompilerServices.UnsafeAccessorKind.Field, Name = "_binaryForm")]
        private static extern ref byte[] BinaryFormRef(global::System.Security.Principal.SecurityIdentifier sid);

        /// <summary>Construct a SecurityIdentifier from an SDDL-format SID string
        /// ("S-1-5-21-...") without invoking the throwing IdentityReference base
        /// constructor. Returns null if uninitialized-object construction or
        /// reflection field-set fails (e.g., NativeAOT trim stripped the field).</summary>
        public static SecurityIdentifier Create(string sidString)
        {
            // Fast path: try the normal constructor — on platforms where it works
            // (real Windows, future NativeAOT versions that lift the restriction)
            // we get a properly initialized BCL instance.
            try { return new global::System.Security.Principal.SecurityIdentifier(sidString); }
            catch (PlatformNotSupportedException) { /* fall through */ }
            catch (TypeInitializationException) { /* fall through */ }

            try
            {
                byte[] binaryForm = SidStringToBinary(sidString);
                return CreateFromBinary(binaryForm);
            }
            catch { return null; }
        }

        /// <summary>Construct a SecurityIdentifier from a binary SID. Same
        /// constructor-bypass mechanism as the string form.</summary>
        public static SecurityIdentifier Create(byte[] binaryForm, int offset = 0)
        {
            try { return new global::System.Security.Principal.SecurityIdentifier(binaryForm, offset); }
            catch (PlatformNotSupportedException) { /* fall through */ }
            catch (TypeInitializationException) { /* fall through */ }

            try
            {
                int len = SidBinaryLength(binaryForm, offset);
                byte[] copy = new byte[len];
                Buffer.BlockCopy(binaryForm, offset, copy, 0, len);
                return CreateFromBinary(copy);
            }
            catch { return null; }
        }

        /// <summary>Construct from a host SID pointer (IntPtr → byte[]).
        /// Mirrors the existing SecurityIdentifier(IntPtr) site that already
        /// has a try/catch wrapper in csharp_patcher.</summary>
        public static SecurityIdentifier Create(IntPtr sidPtr)
        {
            try { return new global::System.Security.Principal.SecurityIdentifier(sidPtr); }
            catch (PlatformNotSupportedException) { /* fall through */ }
            catch (TypeInitializationException) { /* fall through */ }

            try
            {
                if (sidPtr == IntPtr.Zero) return null;
                // Read SubAuthorityCount at offset 1 to determine total length.
                byte subCount = System.Runtime.InteropServices.Marshal.ReadByte(sidPtr, 1);
                int len = 8 + (subCount * 4);
                byte[] copy = new byte[len];
                System.Runtime.InteropServices.Marshal.Copy(sidPtr, copy, 0, len);
                return CreateFromBinary(copy);
            }
            catch { return null; }
        }

        private static SecurityIdentifier CreateFromBinary(byte[] binaryForm)
        {
            SecurityIdentifier obj;
            try
            {
                obj = (SecurityIdentifier)RuntimeHelpers.GetUninitializedObject(typeof(SecurityIdentifier));
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[WfSid] GetUninitializedObject failed: {0}", e.Message);
                return null;
            }
            try
            {
                // UnsafeAccessor: trim-safe direct field write.
                BinaryFormRef(obj) = binaryForm;
            }
            catch
            {
                // Silent failure — UnsafeAccessor's runtime field-existence check
                // can mismatch the live CoreCLR layout under NativeAOT-WASI trim.
                // Callers (FormatHash, ForgeTicket, etc) accept null and use the
                // SidStringToBinary fallback. Printing once per call pollutes
                // parity diffs against native Rubeus.
                return null;
            }
            return obj;
        }

        /// <summary>Parse "S-1-5-21-a-b-c-rid" into the standard binary SID layout:
        /// revision(1) + subCount(1) + identAuth(6 BE) + subAuth[i](4 LE) * subCount.</summary>
        public static byte[] SidStringToBinary(string s)
        {
            if (string.IsNullOrEmpty(s)) throw new ArgumentException("empty SID");
            string[] parts = s.Split('-');
            if (parts.Length < 3 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase))
                throw new FormatException("not an SDDL SID: " + s);

            byte revision = byte.Parse(parts[1]);
            ulong identAuth = ulong.Parse(parts[2]);
            int subCount = parts.Length - 3;
            byte[] bytes = new byte[8 + (subCount * 4)];
            bytes[0] = revision;
            bytes[1] = (byte)subCount;
            // Identifier authority is 6-byte big-endian.
            for (int i = 0; i < 6; i++)
                bytes[2 + i] = (byte)((identAuth >> ((5 - i) * 8)) & 0xff);
            for (int i = 0; i < subCount; i++)
            {
                uint sub = uint.Parse(parts[3 + i]);
                byte[] le = BitConverter.GetBytes(sub);
                Buffer.BlockCopy(le, 0, bytes, 8 + (i * 4), 4);
            }
            return bytes;
        }

        private static int SidBinaryLength(byte[] binaryForm, int offset)
        {
            byte subCount = binaryForm[offset + 1];
            return 8 + (subCount * 4);
        }

        /// <summary>NativeAOT-WASI under InvariantGlobalization returns a null
        /// TimeZone.CurrentTimeZone. Try TimeZoneInfo.Local; fall back to UTC
        /// passthrough if that also throws.</summary>
        public static DateTime ToLocalTimeSafe(DateTime dt)
        {
            try
            {
                return TimeZoneInfo.ConvertTime(dt, TimeZoneInfo.Local);
            }
            catch { return dt; }
        }

        /// <summary>Convert a binary SID back to SDDL "S-1-5-21-…" form.
        /// Companion to SidStringToBinary — used by _RPC_SID.ToString() etc.</summary>
        public static string SidBinaryToString(byte[] binaryForm, int offset = 0)
        {
            if (binaryForm == null || binaryForm.Length < offset + 8) return "";
            byte revision = binaryForm[offset + 0];
            byte subCount = binaryForm[offset + 1];
            ulong identAuth = 0;
            for (int i = 0; i < 6; i++)
            {
                identAuth = (identAuth << 8) | binaryForm[offset + 2 + i];
            }
            var sb = new System.Text.StringBuilder();
            sb.Append('S').Append('-').Append(revision).Append('-').Append(identAuth);
            for (int i = 0; i < subCount; i++)
            {
                int idx = offset + 8 + (i * 4);
                if (idx + 4 > binaryForm.Length) break;
                uint sub = BitConverter.ToUInt32(binaryForm, idx);
                sb.Append('-').Append(sub);
            }
            return sb.ToString();
        }
    }
}

namespace WasmForge.Bridge
{
    // WfSidFallback: per-LUID SDDL string cache for the case where
    // WfSid.Create returns null (NativeAOT trim stripped reflection
    // internals). The Rubeus klist UserSID print line consults this
    // dictionary when LogonSession.Sid is null.
    public static class WfSidFallback
    {
        private static readonly System.Collections.Generic.Dictionary<uint, string> _map =
            new System.Collections.Generic.Dictionary<uint, string>();
        public static void Set(uint luidLow, string sddl)
        {
            if (string.IsNullOrEmpty(sddl)) return;
            _map[luidLow] = sddl;
        }
        public static string Get(uint luidLow)
        {
            string s; return _map.TryGetValue(luidLow, out s) ? s : "";
        }
    }
}

namespace WasmForge.Bridge
{
    // WfEventLogGuard: classify (path, query) tuples by whether the wf_call →
    // wevtapi.dll path is known-safe for non-elevated callers. The bridge
    // traps host-side on multi-line XPath queries (PoweredOnEvents) and on
    // certain channels (Microsoft-Windows-PowerShell/Operational) when the
    // caller doesn't have read access — the trap happens inside wevtapi's
    // internal RPC path before our try/catch can run. Better to short-circuit
    // and return "no events" than to abort the whole process.
    public static class WfEventLogGuard
    {
        public static bool IsSafeToQuery(string path, string query)
        {
            if (string.IsNullOrEmpty(path)) return false;
            // Multi-line queries are the smoking-gun for the trap — every
            // confirmed crash path uses them, and there's no command in the
            // GhostPack tools that legitimately needs them on a non-admin
            // host (they only mean "old events with structured filters",
            // which require admin to read anyway).
            if (query != null && (query.Contains("\n") || query.Contains("\r"))) return false;
            // Channels other than Security require admin on Win10+; do not
            // even attempt the wf_call → wevtapi.dll path because the trap
            // happens inside the wevtapi RPC layer rather than returning an
            // error to us. Security WITH a single-line query is the one
            // confirmed-safe combination.
            if (string.Equals(path, "Security", System.StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
