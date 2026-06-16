// System.IdentityModel.Tokens stub for NativeAOT-WASI compilation.
// Provides Kerberos security token types referenced by Rubeus.

using System;

namespace System.IdentityModel.Tokens
{
    public class KerberosReceiverSecurityToken
    {
        public KerberosReceiverSecurityToken(byte[] request) { Request = request; }
        public byte[] Request { get; }
        public string Id => "";
    }

    public class KerberosRequestorSecurityToken
    {
        public KerberosRequestorSecurityToken(string servicePrincipalName)
        {
            ServicePrincipalName = servicePrincipalName;
        }

        // Roast.cs uses this 4-arg form: (spn, tokenImpersonationLevel, credentials, contextId).
        // The extra args are silently ignored on the WASI side — the actual
        // ticket retrieval is done via the LSA host bridge.
        public KerberosRequestorSecurityToken(string servicePrincipalName,
            object tokenImpersonationLevel, object networkCredential, string contextId)
        {
            ServicePrincipalName = servicePrincipalName;
        }

        public string ServicePrincipalName { get; }
        public string Id => "";

        /// <summary>
        /// Gets the Kerberos ticket bytes. In NativeAOT-WASI, this calls
        /// the LsaHostHelper to retrieve the ticket from the cache.
        /// </summary>
        public byte[] GetRequest()
        {
            throw new PlatformNotSupportedException(
                "KerberosRequestorSecurityToken.GetRequest() not available in NativeAOT-WASI. " +
                "Use LsaHostHelper.RetrieveTicket() instead.");
        }
    }

    public class SecurityToken
    {
        public string Id => "";
        public DateTime ValidFrom => DateTime.MinValue;
        public DateTime ValidTo => DateTime.MaxValue;
    }

    public class SecurityTokenException : Exception
    {
        public SecurityTokenException() { }
        public SecurityTokenException(string message) : base(message) { }
        public SecurityTokenException(string message, Exception innerException) : base(message, innerException) { }
    }
}
