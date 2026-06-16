// System.DirectoryServices.AccountManagement stub for NativeAOT-WASI.
// Provides PrincipalContext and related types used by Rubeus.

using System;
using System.Collections;
using System.Collections.Generic;

namespace System.DirectoryServices.AccountManagement
{
    public class PrincipalContext : IDisposable
    {
        public PrincipalContext(ContextType contextType) { }
        public PrincipalContext(ContextType contextType, string name) { }
        public PrincipalContext(ContextType contextType, string name, string container) { }
        public PrincipalContext(ContextType contextType, string name, string container, ContextOptions options) { }
        public PrincipalContext(ContextType contextType, string name, string username, string password) { }
        public PrincipalContext(ContextType contextType, string name, string container, string username, string password) { }

        public string ConnectedServer => throw new PlatformNotSupportedException("AccountManagement not available in NativeAOT-WASI");
        // Rubeus brute uses this to test password validity. Returning false is
        // safe — the brute path is expected to fall back to its own AS-REQ.
        public bool ValidateCredentials(string userName, string password) => false;
        public bool ValidateCredentials(string userName, string password, ContextOptions options) => false;
        public void Dispose() { }
    }

    public class UserPrincipal : Principal
    {
        public UserPrincipal(PrincipalContext context) : base() { }
        public static UserPrincipal Current { get { throw new PlatformNotSupportedException(); } }
        public static new UserPrincipal FindByIdentity(PrincipalContext context, string identityValue) => null;
        public static UserPrincipal FindByIdentity(PrincipalContext context, IdentityType identityType, string identityValue) => null;
        public PrincipalValueCollection<string> ServicePrincipalNames => new PrincipalValueCollection<string>();
        public string DisplayName { get; set; }
        public bool? Enabled { get; set; }
        public bool PasswordNotRequired { get; set; }
        public void SetPassword(string newPassword) { }
    }

    public class GroupPrincipal : Principal
    {
        public GroupPrincipal(PrincipalContext context) : base() { }
        public static new GroupPrincipal FindByIdentity(PrincipalContext context, string identityValue) => null;
        public PrincipalCollection Members => new PrincipalCollection();
    }

    public class ComputerPrincipal : Principal
    {
        public ComputerPrincipal(PrincipalContext context) : base() { }
        public static new ComputerPrincipal FindByIdentity(PrincipalContext context, string identityValue) => null;
        public string[] ServicePrincipalNames => Array.Empty<string>();
    }

    public abstract class Principal : IDisposable
    {
        public string Name { get; set; }
        public string SamAccountName { get; set; }
        public string DistinguishedName { get; set; }
        public string Sid => null;
        public string UserPrincipalName { get; set; }
        public string Description { get; set; }
        public PrincipalContext Context => null;
        public static Principal FindByIdentity(PrincipalContext context, string identityValue) => null;
        public static Principal FindByIdentity(PrincipalContext context, IdentityType identityType, string identityValue) => null;
        public void Save() { }
        public void Dispose() { }
    }

    public class PrincipalCollection : IEnumerable
    {
        public int Count => 0;
        public IEnumerator GetEnumerator() { yield break; }
        public void Add(Principal principal) { }
        public bool Remove(Principal principal) => false;
        public void Clear() { }
    }

    public class PrincipalValueCollection<T> : IEnumerable<T>
    {
        public int Count => 0;
        public IEnumerator<T> GetEnumerator() { yield break; }
        IEnumerator IEnumerable.GetEnumerator() { yield break; }
    }

    public class PrincipalSearcher : IDisposable
    {
        public PrincipalSearcher() { }
        public PrincipalSearcher(Principal queryFilter) { }
        public Principal QueryFilter { get; set; }
        public PrincipalSearchResult<Principal> FindAll() => new PrincipalSearchResult<Principal>();
        public Principal FindOne() => null;
        public void Dispose() { }
    }

    public class PrincipalSearchResult<T> : IEnumerable<T>, IDisposable
    {
        public IEnumerator<T> GetEnumerator() { yield break; }
        IEnumerator IEnumerable.GetEnumerator() { yield break; }
        public void Dispose() { }
    }

    public enum ContextType { Machine = 0, Domain = 1, ApplicationDirectory = 2 }
    public enum IdentityType { SamAccountName = 0, Name = 1, UserPrincipalName = 2, DistinguishedName = 3, Sid = 4, Guid = 5 }
    [Flags] public enum ContextOptions { Negotiate = 1, SimpleBind = 2, SecureSocketLayer = 4, Signing = 8, Sealing = 16, ServerBind = 32 }
}
