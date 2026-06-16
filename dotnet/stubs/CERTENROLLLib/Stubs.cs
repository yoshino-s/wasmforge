// CERTENROLLLib stub for NativeAOT-WASI compilation.
// Provides type surface for Certify (GhostPack) to compile to WASM.
// All COM-backed methods throw PlatformNotSupportedException at runtime —
// certificate enrollment operations are non-functional until real COM
// host functions are implemented.

using System;

namespace CERTENROLLLib
{
    public enum EncodingType
    {
        XCN_CRYPT_STRING_BASE64 = 0x1,
        XCN_CRYPT_STRING_HEXRAW = 0xC,
        X509 = 0x1,
    }

    public enum X509CertificateEnrollmentContext
    {
        ContextUser = 1,
        ContextMachine = 2,
    }

    public enum X509KeySpec
    {
        XCN_AT_KEYEXCHANGE = 1,
        XCN_AT_SIGNATURE = 2,
    }

    public enum X509PrivateKeyExportFlags
    {
        XCN_NCRYPT_ALLOW_EXPORT_FLAG = 1,
    }

    public enum X500NameFlags
    {
        XCN_CERT_NAME_STR_NONE = 0,
        XCN_CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000,
    }

    public enum InstallResponseRestrictionFlags
    {
        AllowUntrustedRoot = 0x4,
    }

    public enum AlternativeNameType
    {
        XCN_CERT_ALT_NAME_RFC822_NAME = 2,
        XCN_CERT_ALT_NAME_DNS_NAME = 3,
        XCN_CERT_ALT_NAME_URL = 7,
        XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = 11,
    }

    public enum X509PrivateKeyUsageFlags
    {
        XCN_NCRYPT_ALLOW_ALL_USAGES = 0x00ffffff,
    }

    public enum ObjectIdGroupId
    {
        XCN_CRYPT_ANY_GROUP_ID = 0,
    }

    public enum ObjectIdPublicKeyFlags
    {
        XCN_CRYPT_OID_INFO_PUBKEY_ANY = 0,
    }

    public enum AlgorithmFlags
    {
        AlgorithmFlagsNone = 0,
    }

    public interface IX500DistinguishedName
    {
        void Encode(string strDistinguishedName, X500NameFlags dwFlags);
    }

    public interface IX509CertificateRequestPkcs10
    {
        IX500DistinguishedName Subject { get; set; }
    }

    public interface IX509PrivateKey
    {
        int Length { get; set; }
        X509PrivateKeyExportFlags ExportPolicy { get; set; }
        X509KeySpec KeySpec { get; set; }
        string ProviderName { get; set; }
        bool MachineContext { get; set; }
        int KeyProtection { get; set; }
        X509PrivateKeyUsageFlags KeyUsage { get; set; }
        object CspInformations { get; set; }
        string Export(string exportType, EncodingType encoding);
        void Create();
    }

    public class CX509Extensions { public void Add(CX509Extension ext) { } }
    public class CX509NameValuePairs { public void Add(CX509NameValuePair pair) { } }

    public class CX509CertificateRequestPkcs10 : IX509CertificateRequestPkcs10
    {
        public IX500DistinguishedName Subject { get; set; }
        public object CspInformations { get; set; }
        public CX509Extensions X509Extensions { get; } = new CX509Extensions();
        public CX509NameValuePairs NameValuePairs { get; } = new CX509NameValuePairs();

        public void InitializeFromPrivateKey(
            X509CertificateEnrollmentContext context,
            IX509PrivateKey pPrivateKey,
            string strTemplateName)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void InitializeFromTemplateName(
            X509CertificateEnrollmentContext context,
            string strTemplateName)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CX509PrivateKey : IX509PrivateKey
    {
        public int Length { get; set; }
        public X509PrivateKeyExportFlags ExportPolicy { get; set; }
        public X509KeySpec KeySpec { get; set; }
        public string ProviderName { get; set; }
        public bool MachineContext { get; set; }
        public int KeyProtection { get; set; }
        public X509PrivateKeyUsageFlags KeyUsage { get; set; }
        public object CspInformations { get; set; }

        public void Create()
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
        public string Export(string exportType, EncodingType encoding)
        {
            throw new PlatformNotSupportedException();
        }
    }

    public class CCspInformations
    {
        public void AddAvailableCsps()
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CX509Enrollment
    {
        public string CertificateFriendlyName { get; set; }
        public string CertificateDescription { get; set; }

        public void Initialize(X509CertificateEnrollmentContext context)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void InitializeFromRequest(IX509CertificateRequestPkcs10 pRequest)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public string CreateRequest(EncodingType encoding)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void InstallResponse(
            InstallResponseRestrictionFlags dwFlags,
            string strResponse,
            EncodingType encoding,
            string strPassword)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public string CreatePFX(
            string strPassword,
            X509PrivateKeyExportFlags dwFlags,
            EncodingType encoding)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CX509Extension
    {
        public bool Critical { get; set; }

        public CX509Extension() { }

        public CX509Extension(CObjectId pObjectId, EncodingType encoding, string strEncodedData)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void Initialize(CObjectId pObjectId, EncodingType encoding, string strEncodedData)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public CX509RawData RawData { get; } = new CX509RawData();
    }

    public class CX509RawData
    {
        public string this[EncodingType encoding]
        {
            get { throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI"); }
        }
    }

    public class CX509ExtensionTemplateName : CX509Extension
    {
        public void InitializeEncode(string strTemplateName)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CAlternativeNames
    {
        public void Add(CAlternativeNameClass pVal)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CAlternativeNamesClass : CAlternativeNames
    {
    }

    public class CX509ExtensionAlternativeNamesClass : CX509Extension
    {
        public void InitializeEncode(CAlternativeNames pValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CCertificatePolicies
    {
        public void Add(CCertificatePolicy pVal)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CCertificatePoliciesClass : CCertificatePolicies
    {
    }

    public class CX509ExtensionCertificatePoliciesClass : CX509Extension
    {
        public void InitializeEncode(CCertificatePolicies pValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CX509ExtensionMSApplicationPoliciesClass : CX509Extension
    {
        public void InitializeEncode(CCertificatePolicies pValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CX509NameValuePair
    {
        public CX509NameValuePair() { }

        public CX509NameValuePair(string strName, string strValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void Initialize(string strName, string strValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CObjectId
    {
        public void InitializeFromValue(string strValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }

        public void InitializeFromName(
            ObjectIdGroupId groupId,
            ObjectIdPublicKeyFlags publicKeyFlags,
            AlgorithmFlags algorithmFlags,
            string strName)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CObjectIdClass : CObjectId
    {
    }

    public class CAlternativeNameClass
    {
        public void InitializeFromString(AlternativeNameType type, string strValue)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CCertificatePolicy
    {
        public CCertificatePolicies PolicyQualifiers { get; } = new CCertificatePoliciesClass();

        public void Initialize(CObjectId pObjectId)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    public class CCertificatePolicyClass : CCertificatePolicy
    {
    }

    public class CX500DistinguishedName : IX500DistinguishedName
    {
        public void Encode(string strDistinguishedName, X500NameFlags dwFlags)
        {
            throw new PlatformNotSupportedException("COM certificate enrollment not available in NativeAOT-WASI");
        }
    }

    // Additional types needed by Certify CertEnrollment.cs

    public interface IX509CertificateRequestPkcs10V3 : IX509CertificateRequestPkcs10
    {
        void InitializeFromPrivateKey(X509CertificateEnrollmentContext context, IX509PrivateKey pPrivateKey, string strTemplateName);
        CX509Extensions X509Extensions { get; }
        CX509NameValuePairs NameValuePairs { get; }
        string Encode();
    }

    public class CX509CertificateRequestPkcs7 : IX509CertificateRequestPkcs10
    {
        // IX509CertificateRequestPkcs10 members
        public IX500DistinguishedName Subject { get; set; }
        public void InitializeFromPrivateKey(X509CertificateEnrollmentContext context, IX509PrivateKey pPrivateKey, string strTemplateName) { throw new PlatformNotSupportedException(); }

        public void InitializeFromInnerRequest(IX509CertificateRequestPkcs10 innerRequest) { throw new PlatformNotSupportedException(); }
        public void InitializeFromCertificate(X509CertificateEnrollmentContext context, bool renew, string strCertificate) { throw new PlatformNotSupportedException(); }
        public void InitializeFromCertificate(X509CertificateEnrollmentContext context, bool renew, string strCertificate, EncodingType encoding, X509RequestInheritOptions inheritOptions) { throw new PlatformNotSupportedException(); }
        public IX509CertificateRequestPkcs10 InnerRequest { get { throw new PlatformNotSupportedException(); } }
        public CSignerCertificate SignerCertificate { get; set; }
        public string RequesterName { get; set; }
    }

    public class CSignerCertificate
    {
        public void Initialize(bool machineContext, X509PrivateKeyVerify verify, EncodingType encoding, string cert) { throw new PlatformNotSupportedException(); }
    }

    public enum X509PrivateKeyVerify
    {
        VerifyNone = 0,
        VerifySilent = 1,
        VerifySmartCardNone = 2,
        VerifySmartCardSilent = 3,
        VerifyAllowUI = 4,
    }

    [Flags]
    public enum X509RequestInheritOptions
    {
        InheritDefault = 0x00000000,
        InheritNewDefaultKey = 0x00000001,
        InheritNewSimilarKey = 0x00000002,
        InheritPrivateKey = 0x00000003,
        InheritPublicKey = 0x00000004,
        InheritKeyMask = 0x0000000F,
        InheritNone = 0x00000010,
        InheritRenewalCertificateFlag = 0x00000020,
        InheritTemplateFlag = 0x00000040,
        InheritSubjectFlag = 0x00000080,
        InheritExtensionsFlag = 0x00000100,
        InheritSubjectAltNameFlag = 0x00000200,
        InheritValidityPeriodFlag = 0x00000400,
        InheritReserved80000000 = unchecked((int)0x80000000),
    }
}
