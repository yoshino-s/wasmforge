// ActiveDs stub assembly for NativeAOT-WASI builds.
//
// The real ActiveDs COM interop library cannot load under WASI (no COM runtime,
// no IADs registration). SharpView references three types:
//   * ADS_NAME_TYPE_ENUM — used in enums/ADSNameType.cs
//   * ADS_GROUP_TYPE_ENUM — used in enums/GroupType.cs
//   * NameTranslate — used in PowerView.cs Convert-ADName
//
// The enum values are mirrored from the published IADsNameTranslate /
// IADsGroupType IDL so SharpView's enum-cast paths compile and produce
// recognizable integer values when serialized.
//
// NameTranslate is a no-op shell: methods exist but throw NotImplementedException
// at runtime. This is the correct failure mode — Convert-ADName is a corner-case
// SharpView verb not in the parity baseline, so the throw will surface only if
// a user invokes it directly.

using System;

namespace ActiveDs
{
    public enum ADS_NAME_TYPE_ENUM
    {
        ADS_NAME_TYPE_1779                       = 1,
        ADS_NAME_TYPE_CANONICAL                  = 2,
        ADS_NAME_TYPE_NT4                        = 3,
        ADS_NAME_TYPE_DISPLAY                    = 4,
        ADS_NAME_TYPE_DOMAIN_SIMPLE              = 5,
        ADS_NAME_TYPE_ENTERPRISE_SIMPLE          = 6,
        ADS_NAME_TYPE_GUID                       = 7,
        ADS_NAME_TYPE_UNKNOWN                    = 8,
        ADS_NAME_TYPE_USER_PRINCIPAL_NAME        = 9,
        ADS_NAME_TYPE_CANONICAL_EX               = 10,
        ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME     = 11,
        ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME    = 12
    }

    [Flags]
    public enum ADS_GROUP_TYPE_ENUM
    {
        ADS_GROUP_TYPE_GLOBAL_GROUP        = 0x00000002,
        ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP  = 0x00000004,
        ADS_GROUP_TYPE_LOCAL_GROUP         = 0x00000004,
        ADS_GROUP_TYPE_UNIVERSAL_GROUP     = 0x00000008,
        ADS_GROUP_TYPE_SECURITY_ENABLED    = unchecked((int)0x80000000)
    }

    public enum ADS_NAME_INITTYPE_ENUM
    {
        ADS_NAME_INITTYPE_DOMAIN = 1,
        ADS_NAME_INITTYPE_SERVER = 2,
        ADS_NAME_INITTYPE_GC     = 3
    }

    public class NameTranslate
    {
        public int ChaseReferral { get; set; }

        public void Init(int lnSetType, string bstrADsPath)
            => throw new NotImplementedException(
                "ActiveDs.NameTranslate.Init is not available under NativeAOT-WASI");

        public void InitEx(int lnSetType, string bstrADsPath,
                           string lpszUserID, string lpszDomain, string lpszPassword)
            => throw new NotImplementedException(
                "ActiveDs.NameTranslate.InitEx is not available under NativeAOT-WASI");

        public void Set(int lnSetType, string bstrADsPath)
            => throw new NotImplementedException(
                "ActiveDs.NameTranslate.Set is not available under NativeAOT-WASI");

        public string Get(int lnFormatType)
            => throw new NotImplementedException(
                "ActiveDs.NameTranslate.Get is not available under NativeAOT-WASI");
    }
}
