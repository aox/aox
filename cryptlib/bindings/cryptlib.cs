using System;
using System.Runtime.InteropServices;
using System.Text;

namespace cryptlib
{

public class crypt
{
    
	
	/****************************************************************************
	*																			*
	*							Algorithm and Object Types						*
	*																			*
	****************************************************************************/
	
	/* Algorithm and mode types */
	
	// CRYPT_ALGO_TYPE
	public const int ALGO_NONE               = 0  ; // No encryption
	public const int ALGO_DES                = 1  ; // DES
	public const int ALGO_3DES               = 2  ; // Triple DES
	public const int ALGO_IDEA               = 3  ; // IDEA
	public const int ALGO_CAST               = 4  ; // CAST-128
	public const int ALGO_RC2                = 5  ; // RC2
	public const int ALGO_RC4                = 6  ; // RC4
	public const int ALGO_RC5                = 7  ; // RC5
	public const int ALGO_AES                = 8  ; // AES
	public const int ALGO_BLOWFISH           = 9  ; // Blowfish
	public const int ALGO_SKIPJACK           = 10 ; // Skipjack
	public const int ALGO_DH                 = 100; // Diffie-Hellman
	public const int ALGO_RSA                = 101; // RSA
	public const int ALGO_DSA                = 102; // DSA
	public const int ALGO_ELGAMAL            = 103; // ElGamal
	public const int ALGO_KEA                = 104; // KEA
	public const int ALGO_MD2                = 200; // MD2
	public const int ALGO_MD4                = 201; // MD4
	public const int ALGO_MD5                = 202; // MD5
	public const int ALGO_SHA                = 203; // SHA/SHA1
	public const int ALGO_RIPEMD160          = 204; // RIPE-MD 160
	public const int ALGO_HMAC_MD5           = 300; // HMAC-MD5
	public const int ALGO_HMAC_SHA           = 301; // HMAC-SHA
	public const int ALGO_HMAC_RIPEMD160     = 302; // HMAC-RIPEMD-160
	public const int ALGO_LAST               = 303; // Last possible crypt algo value
	public const int ALGO_FIRST_CONVENTIONAL = 1  ;
	public const int ALGO_LAST_CONVENTIONAL  = 99 ;
	public const int ALGO_FIRST_PKC          = 100;
	public const int ALGO_LAST_PKC           = 199;
	public const int ALGO_FIRST_HASH         = 200;
	public const int ALGO_LAST_HASH          = 299;
	public const int ALGO_FIRST_MAC          = 300;
	public const int ALGO_LAST_MAC           = 399; // End of mac algo.range
	
	// CRYPT_MODE_TYPE
	public const int MODE_NONE = 0; // No encryption mode
	public const int MODE_ECB  = 1; // ECB
	public const int MODE_CBC  = 2; // CBC
	public const int MODE_CFB  = 3; // CFB
	public const int MODE_OFB  = 4; // OFB
	public const int MODE_LAST = 5; // Last possible crypt mode value
	
	
	/* Keyset subtypes */
	
	// CRYPT_KEYSET_TYPE
	public const int KEYSET_NONE           = 0 ; // No keyset type
	public const int KEYSET_FILE           = 1 ; // Generic flat file keyset
	public const int KEYSET_HTTP           = 2 ; // Web page containing cert/CRL
	public const int KEYSET_LDAP           = 3 ; // LDAP directory service
	public const int KEYSET_ODBC           = 4 ; // Generic ODBC interface
	public const int KEYSET_DATABASE       = 5 ; // Generic RDBMS interface
	public const int KEYSET_PLUGIN         = 6 ; // Generic database plugin
	public const int KEYSET_ODBC_STORE     = 7 ; // ODBC certificate store
	public const int KEYSET_DATABASE_STORE = 8 ; // Database certificate store
	public const int KEYSET_PLUGIN_STORE   = 9 ; // Database plugin certificate store
	public const int KEYSET_LAST           = 10; // Last possible keyset type
	
	/* Device subtypes */
	
	// CRYPT_DEVICE_TYPE
	public const int DEVICE_NONE      = 0; // No crypto device
	public const int DEVICE_FORTEZZA  = 1; // Fortezza card
	public const int DEVICE_PKCS11    = 2; // PKCS #11 crypto token
	public const int DEVICE_CRYPTOAPI = 3; // Microsoft CryptoAPI
	public const int DEVICE_LAST      = 4; // Last possible crypto device type
	
	/* Certificate subtypes */
	
	// CRYPT_CERTTYPE_TYPE
	public const int CERTTYPE_NONE               = 0 ; // No certificate type
	public const int CERTTYPE_CERTIFICATE        = 1 ; // Certificate
	public const int CERTTYPE_ATTRIBUTE_CERT     = 2 ; // Attribute certificate
	public const int CERTTYPE_CERTCHAIN          = 3 ; // PKCS #7 certificate chain
	public const int CERTTYPE_CERTREQUEST        = 4 ; // PKCS #10 certification request
	public const int CERTTYPE_REQUEST_CERT       = 5 ; // CRMF certification request
	public const int CERTTYPE_REQUEST_REVOCATION = 6 ; // CRMF revocation request
	public const int CERTTYPE_CRL                = 7 ; // CRL
	public const int CERTTYPE_CMS_ATTRIBUTES     = 8 ; // CMS attributes
	public const int CERTTYPE_RTCS_REQUEST       = 9 ; // RTCS request
	public const int CERTTYPE_RTCS_RESPONSE      = 10; // RTCS response
	public const int CERTTYPE_OCSP_REQUEST       = 11; // OCSP request
	public const int CERTTYPE_OCSP_RESPONSE      = 12; // OCSP response
	public const int CERTTYPE_PKIUSER            = 13; // PKI user information
	public const int CERTTYPE_LAST               = 14; // Last possible cert.type
	
	/* Envelope/data format subtypes */
	
	// CRYPT_FORMAT_TYPE
	public const int FORMAT_NONE     = 0; // No format type
	public const int FORMAT_AUTO     = 1; // Deenv, auto-determine type
	public const int FORMAT_CRYPTLIB = 2; // cryptlib native format
	public const int FORMAT_CMS      = 3; // PKCS #7 / CMS / S/MIME fmt.
	public const int FORMAT_PKCS7    = 3;
	public const int FORMAT_SMIME    = 4; // As CMS with MSG-style behaviour
	public const int FORMAT_PGP      = 5; // PGP format
	public const int FORMAT_LAST     = 6; // Last possible format type
	
	/* Session subtypes */
	
	// CRYPT_SESSION_TYPE
	public const int SESSION_NONE             = 0 ; // No session type
	public const int SESSION_SSH              = 1 ; // SSH
	public const int SESSION_SSH_SERVER       = 2 ; // SSH server
	public const int SESSION_SSL              = 3 ; // SSL/TLS
	public const int SESSION_SSL_SERVER       = 4 ; // SSL/TLS server
	public const int SESSION_RTCS             = 5 ; // RTCS
	public const int SESSION_RTCS_SERVER      = 6 ; // RTCS server
	public const int SESSION_OCSP             = 7 ; // OCSP
	public const int SESSION_OCSP_SERVER      = 8 ; // OCSP server
	public const int SESSION_TSP              = 9 ; // TSP
	public const int SESSION_TSP_SERVER       = 10; // TSP server
	public const int SESSION_CMP              = 11; // CMP
	public const int SESSION_CMP_SERVER       = 12; // CMP server
	public const int SESSION_SCEP             = 13; // SCEP
	public const int SESSION_SCEP_SERVER      = 14; // SCEP server
	public const int SESSION_CERTSTORE_SERVER = 15; // HTTP cert store interface
	public const int SESSION_LAST             = 16; // Last possible session type
	
	/* User subtypes */
	
	// CRYPT_USER_TYPE
	public const int USER_NONE   = 0; // No user type
	public const int USER_NORMAL = 1; // Normal user
	public const int USER_SO     = 2; // Security officer
	public const int USER_CA     = 3; // CA user
	public const int USER_LAST   = 4; // Last possible user type
	
	/****************************************************************************
	*																			*
	*								Attribute Types								*
	*																			*
	****************************************************************************/
	
	/* Attribute types.  These are arranged in the following order:
	
		PROPERTY	- Object property
		ATTRIBUTE	- Generic attributes
		OPTION		- Global or object-specific config.option
		CTXINFO		- Context-specific attribute
		CERTINFO	- Certificate-specific attribute
		KEYINFO		- Keyset-specific attribute
		DEVINFO		- Device-specific attribute
		ENVINFO		- Envelope-specific attribute
		SESSINFO	- Session-specific attribute
		USERINFO	- User-specific attribute */
	
	// CRYPT_ATTRIBUTE_TYPE
	public const int ATTRIBUTE_NONE                              = 0   ; // Non-value
	public const int PROPERTY_FIRST                              = 1   ; // *******************
	public const int PROPERTY_HIGHSECURITY                       = 2   ; // Owned+non-forwardcount+locked
	public const int PROPERTY_OWNER                              = 3   ; // Object owner
	public const int PROPERTY_FORWARDCOUNT                       = 4   ; // No.of times object can be forwarded
	public const int PROPERTY_LOCKED                             = 5   ; // Whether properties can be chged/read
	public const int PROPERTY_USAGECOUNT                         = 6   ; // Usage count before object expires
	public const int PROPERTY_NONEXPORTABLE                      = 7   ; // Whether key is nonexp.from context
	public const int PROPERTY_LAST                               = 8   ;
	public const int GENERIC_FIRST                               = 9   ; // Extended error information
	public const int ATTRIBUTE_ERRORTYPE                         = 10  ; // Type of last error
	public const int ATTRIBUTE_ERRORLOCUS                        = 11  ; // Locus of last error
	public const int ATTRIBUTE_INT_ERRORCODE                     = 12  ; // Low-level software-specific
	public const int ATTRIBUTE_INT_ERRORMESSAGE                  = 13  ; // error code and message
	public const int ATTRIBUTE_CURRENT_GROUP                     = 14  ; // Cursor mgt: Group in attribute list
	public const int ATTRIBUTE_CURRENT                           = 15  ; // Cursor mgt: Entry in attribute list
	public const int ATTRIBUTE_CURRENT_INSTANCE                  = 16  ; // Cursor mgt: Instance in attribute list
	public const int ATTRIBUTE_BUFFERSIZE                        = 17  ; // Internal data buffer size
	public const int GENERIC_LAST                                = 18  ;
	public const int OPTION_FIRST                                = 100 ; // **************************
	public const int OPTION_INFO_DESCRIPTION                     = 101 ; // Text description
	public const int OPTION_INFO_COPYRIGHT                       = 102 ; // Copyright notice
	public const int OPTION_INFO_MAJORVERSION                    = 103 ; // Major release version
	public const int OPTION_INFO_MINORVERSION                    = 104 ; // Minor release version
	public const int OPTION_INFO_STEPPING                        = 105 ; // Release stepping
	public const int OPTION_ENCR_ALGO                            = 106 ; // Encryption algorithm
	public const int OPTION_ENCR_HASH                            = 107 ; // Hash algorithm
	public const int OPTION_ENCR_MAC                             = 108 ; // MAC algorithm
	public const int OPTION_PKC_ALGO                             = 109 ; // Public-key encryption algorithm
	public const int OPTION_PKC_KEYSIZE                          = 110 ; // Public-key encryption key size
	public const int OPTION_SIG_ALGO                             = 111 ; // Signature algorithm
	public const int OPTION_SIG_KEYSIZE                          = 112 ; // Signature keysize
	public const int OPTION_KEYING_ALGO                          = 113 ; // Key processing algorithm
	public const int OPTION_KEYING_ITERATIONS                    = 114 ; // Key processing iterations
	public const int OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES      = 115 ; // Whether to sign unrecog.attrs
	public const int OPTION_CERT_VALIDITY                        = 116 ; // Certificate validity period
	public const int OPTION_CERT_UPDATEINTERVAL                  = 117 ; // CRL update interval
	public const int OPTION_CERT_COMPLIANCELEVEL                 = 118 ; // PKIX compliance level for cert chks.
	public const int OPTION_CERT_REQUIREPOLICY                   = 119 ; // Whether explicit policy req'd for certs
	public const int OPTION_CMS_DEFAULTATTRIBUTES                = 120 ; // Add default CMS attributes
	public const int OPTION_SMIME_DEFAULTATTRIBUTES              = 120 ; // LDAP keyset options
	public const int OPTION_KEYS_LDAP_OBJECTCLASS                = 121 ; // Object class
	public const int OPTION_KEYS_LDAP_OBJECTTYPE                 = 122 ; // Object type to fetch
	public const int OPTION_KEYS_LDAP_FILTER                     = 123 ; // Query filter
	public const int OPTION_KEYS_LDAP_CACERTNAME                 = 124 ; // CA certificate attribute name
	public const int OPTION_KEYS_LDAP_CERTNAME                   = 125 ; // Certificate attribute name
	public const int OPTION_KEYS_LDAP_CRLNAME                    = 126 ; // CRL attribute name
	public const int OPTION_KEYS_LDAP_EMAILNAME                  = 127 ; // Email attribute name
	public const int OPTION_DEVICE_PKCS11_DVR01                  = 128 ; // Name of first PKCS #11 driver
	public const int OPTION_DEVICE_PKCS11_DVR02                  = 129 ; // Name of second PKCS #11 driver
	public const int OPTION_DEVICE_PKCS11_DVR03                  = 130 ; // Name of third PKCS #11 driver
	public const int OPTION_DEVICE_PKCS11_DVR04                  = 131 ; // Name of fourth PKCS #11 driver
	public const int OPTION_DEVICE_PKCS11_DVR05                  = 132 ; // Name of fifth PKCS #11 driver
	public const int OPTION_DEVICE_PKCS11_HARDWAREONLY           = 133 ; // Use only hardware mechanisms
	public const int OPTION_NET_SOCKS_SERVER                     = 134 ; // Socks server name
	public const int OPTION_NET_SOCKS_USERNAME                   = 135 ; // Socks user name
	public const int OPTION_NET_HTTP_PROXY                       = 136 ; // Web proxy server
	public const int OPTION_NET_CONNECTTIMEOUT                   = 137 ; // Timeout for network connection setup
	public const int OPTION_NET_READTIMEOUT                      = 138 ; // Timeout for network reads
	public const int OPTION_NET_WRITETIMEOUT                     = 139 ; // Timeout for network writes
	public const int OPTION_MISC_ASYNCINIT                       = 140 ; // Whether to init cryptlib async'ly
	public const int OPTION_MISC_SIDECHANNELPROTECTION           = 141 ; // Protect against side-channel attacks
	public const int OPTION_CONFIGCHANGED                        = 142 ; // Whether in-mem.opts match on-disk ones
	public const int OPTION_SELFTESTOK                           = 143 ; // Whether self-test was completed and OK
	public const int OPTION_LAST                                 = 144 ;
	public const int CTXINFO_FIRST                               = 1000; // ********************
	public const int CTXINFO_ALGO                                = 1001; // Algorithm
	public const int CTXINFO_MODE                                = 1002; // Mode
	public const int CTXINFO_NAME_ALGO                           = 1003; // Algorithm name
	public const int CTXINFO_NAME_MODE                           = 1004; // Mode name
	public const int CTXINFO_KEYSIZE                             = 1005; // Key size in bytes
	public const int CTXINFO_BLOCKSIZE                           = 1006; // Block size
	public const int CTXINFO_IVSIZE                              = 1007; // IV size
	public const int CTXINFO_KEYING_ALGO                         = 1008; // Key processing algorithm
	public const int CTXINFO_KEYING_ITERATIONS                   = 1009; // Key processing iterations
	public const int CTXINFO_KEYING_SALT                         = 1010; // Key processing salt
	public const int CTXINFO_KEYING_VALUE                        = 1011; // Value used to derive key
	public const int CTXINFO_KEY                                 = 1012; // Key
	public const int CTXINFO_KEY_COMPONENTS                      = 1013; // Public-key components
	public const int CTXINFO_IV                                  = 1014; // IV
	public const int CTXINFO_HASHVALUE                           = 1015; // Hash value
	public const int CTXINFO_LABEL                               = 1016; // Label for private/secret key
	public const int CTXINFO_LAST                                = 1017;
	public const int CERTINFO_FIRST                              = 2000; // ************************
	public const int CERTINFO_SELFSIGNED                         = 2001; // Cert is self-signed
	public const int CERTINFO_IMMUTABLE                          = 2002; // Cert is signed and immutable
	public const int CERTINFO_XYZZY                              = 2003; // Cert is a magic just-works cert
	public const int CERTINFO_CERTTYPE                           = 2004; // Certificate object type
	public const int CERTINFO_FINGERPRINT                        = 2005; // Certificate fingerprints
	public const int CERTINFO_FINGERPRINT_MD5                    = 2005;
	public const int CERTINFO_FINGERPRINT_SHA                    = 2006;
	public const int CERTINFO_CURRENT_CERTIFICATE                = 2007; // Cursor mgt: Rel.pos in chain/CRL/OCSP
	public const int CERTINFO_CURRENT_EXTENSION                  = 2008; // Cursor mgt: Rel.pos.or abs.extension
	public const int CERTINFO_CURRENT_FIELD                      = 2009; // Cursor mgt: Rel.pos.or abs.field in ext
	public const int CERTINFO_CURRENT_COMPONENT                  = 2010; // Cursor mgt: Rel.pos in multival.field
	public const int CERTINFO_TRUSTED_USAGE                      = 2011; // Usage that cert is trusted for
	public const int CERTINFO_TRUSTED_IMPLICIT                   = 2012; // Whether cert is implicitly trusted
	public const int CERTINFO_SIGNATURELEVEL                     = 2013; // Amount of detail to include in sigs.
	public const int CERTINFO_VERSION                            = 2014; // Cert.format version
	public const int CERTINFO_SERIALNUMBER                       = 2015; // Serial number
	public const int CERTINFO_SUBJECTPUBLICKEYINFO               = 2016; // Public key
	public const int CERTINFO_CERTIFICATE                        = 2017; // User certificate
	public const int CERTINFO_USERCERTIFICATE                    = 2017;
	public const int CERTINFO_CACERTIFICATE                      = 2018; // CA certificate
	public const int CERTINFO_ISSUERNAME                         = 2019; // Issuer DN
	public const int CERTINFO_VALIDFROM                          = 2020; // Cert valid-from time
	public const int CERTINFO_VALIDTO                            = 2021; // Cert valid-to time
	public const int CERTINFO_SUBJECTNAME                        = 2022; // Subject DN
	public const int CERTINFO_ISSUERUNIQUEID                     = 2023; // Issuer unique ID
	public const int CERTINFO_SUBJECTUNIQUEID                    = 2024; // Subject unique ID
	public const int CERTINFO_CERTREQUEST                        = 2025; // Cert.request (DN + public key)
	public const int CERTINFO_THISUPDATE                         = 2026; // CRL/OCSP current-update time
	public const int CERTINFO_NEXTUPDATE                         = 2027; // CRL/OCSP next-update time
	public const int CERTINFO_REVOCATIONDATE                     = 2028; // CRL/OCSP cert-revocation time
	public const int CERTINFO_REVOCATIONSTATUS                   = 2029; // OCSP revocation status
	public const int CERTINFO_CERTSTATUS                         = 2030; // RTCS certificate status
	public const int CERTINFO_DN                                 = 2031; // Currently selected DN in string form
	public const int CERTINFO_PKIUSER_ID                         = 2032; // PKI user ID
	public const int CERTINFO_PKIUSER_ISSUEPASSWORD              = 2033; // PKI user issue password
	public const int CERTINFO_PKIUSER_REVPASSWORD                = 2034; // PKI user revocation password
	public const int CERTINFO_COUNTRYNAME                        = 2100; // countryName
	public const int CERTINFO_STATEORPROVINCENAME                = 2101; // stateOrProvinceName
	public const int CERTINFO_LOCALITYNAME                       = 2102; // localityName
	public const int CERTINFO_ORGANIZATIONNAME                   = 2103; // organizationName
	public const int CERTINFO_ORGANISATIONNAME                   = 2103;
	public const int CERTINFO_ORGANIZATIONALUNITNAME             = 2104; // organizationalUnitName
	public const int CERTINFO_ORGANISATIONALUNITNAME             = 2104;
	public const int CERTINFO_COMMONNAME                         = 2105; // commonName
	public const int CERTINFO_OTHERNAME_TYPEID                   = 2106; // otherName.typeID
	public const int CERTINFO_OTHERNAME_VALUE                    = 2107; // otherName.value
	public const int CERTINFO_RFC822NAME                         = 2108; // rfc822Name
	public const int CERTINFO_EMAIL                              = 2108;
	public const int CERTINFO_DNSNAME                            = 2109; // dNSName
	public const int CERTINFO_DIRECTORYNAME                      = 2110; // directoryName
	public const int CERTINFO_EDIPARTYNAME_NAMEASSIGNER          = 2111; // ediPartyName.nameAssigner
	public const int CERTINFO_EDIPARTYNAME_PARTYNAME             = 2112; // ediPartyName.partyName
	public const int CERTINFO_UNIFORMRESOURCEIDENTIFIER          = 2113; // uniformResourceIdentifier
	public const int CERTINFO_IPADDRESS                          = 2114; // iPAddress
	public const int CERTINFO_REGISTEREDID                       = 2115; // registeredID
	public const int CERTINFO_CHALLENGEPASSWORD                  = 2200; // 1 3 6 1 4 1 3029 3 1 4 cRLExtReason
	public const int CERTINFO_CRLEXTREASON                       = 2201; // 1 3 6 1 4 1 3029 3 1 5 keyFeatures
	public const int CERTINFO_KEYFEATURES                        = 2202; // 1 3 6 1 5 5 7 1 1 authorityInfoAccess
	public const int CERTINFO_AUTHORITYINFOACCESS                = 2203;
	public const int CERTINFO_AUTHORITYINFO_RTCS                 = 2204; // accessDescription.accessLocation
	public const int CERTINFO_AUTHORITYINFO_OCSP                 = 2205; // accessDescription.accessLocation
	public const int CERTINFO_AUTHORITYINFO_CAISSUERS            = 2206; // accessDescription.accessLocation
	public const int CERTINFO_AUTHORITYINFO_CERTSTORE            = 2207; // accessDescription.accessLocation
	public const int CERTINFO_AUTHORITYINFO_CRLS                 = 2208; // accessDescription.accessLocation
	public const int CERTINFO_BIOMETRICINFO                      = 2209;
	public const int CERTINFO_BIOMETRICINFO_TYPE                 = 2210; // biometricData.typeOfData
	public const int CERTINFO_BIOMETRICINFO_HASHALGO             = 2211; // biometricData.hashAlgorithm
	public const int CERTINFO_BIOMETRICINFO_HASH                 = 2212; // biometricData.dataHash
	public const int CERTINFO_BIOMETRICINFO_URL                  = 2213; // biometricData.sourceDataUri
	public const int CERTINFO_QCSTATEMENT                        = 2214;
	public const int CERTINFO_QCSTATEMENT_SEMANTICS              = 2215; // qcStatement.statementInfo.semanticsIdentifier
	public const int CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY  = 2216; // qcStatement.statementInfo.nameRegistrationAuthorities
	public const int CERTINFO_OCSP_NONCE                         = 2217; // nonce
	public const int CERTINFO_OCSP_RESPONSE                      = 2218;
	public const int CERTINFO_OCSP_RESPONSE_OCSP                 = 2219; // OCSP standard response
	public const int CERTINFO_OCSP_NOCHECK                       = 2220; // 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff
	public const int CERTINFO_OCSP_ARCHIVECUTOFF                 = 2221; // 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess
	public const int CERTINFO_SUBJECTINFOACCESS                  = 2222;
	public const int CERTINFO_SUBJECTINFO_CAREPOSITORY           = 2223; // accessDescription.accessLocation
	public const int CERTINFO_SUBJECTINFO_TIMESTAMPING           = 2224; // accessDescription.accessLocation
	public const int CERTINFO_SIGG_DATEOFCERTGEN                 = 2225; // 1 3 36 8 3 2 siggProcuration
	public const int CERTINFO_SIGG_PROCURATION                   = 2226;
	public const int CERTINFO_SIGG_PROCURE_COUNTRY               = 2227; // country
	public const int CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION    = 2228; // typeOfSubstitution
	public const int CERTINFO_SIGG_PROCURE_SIGNINGFOR            = 2229; // signingFor.thirdPerson
	public const int CERTINFO_SIGG_MONETARYLIMIT                 = 2230;
	public const int CERTINFO_SIGG_MONETARY_CURRENCY             = 2231; // currency
	public const int CERTINFO_SIGG_MONETARY_AMOUNT               = 2232; // amount
	public const int CERTINFO_SIGG_MONETARY_EXPONENT             = 2233; // exponent
	public const int CERTINFO_SIGG_RESTRICTION                   = 2234; // 1 3 101 1 4 1 strongExtranet
	public const int CERTINFO_STRONGEXTRANET                     = 2235;
	public const int CERTINFO_STRONGEXTRANET_ZONE                = 2236; // sxNetIDList.sxNetID.zone
	public const int CERTINFO_STRONGEXTRANET_ID                  = 2237; // sxNetIDList.sxNetID.id
	public const int CERTINFO_SUBJECTDIRECTORYATTRIBUTES         = 2238;
	public const int CERTINFO_SUBJECTDIR_TYPE                    = 2239; // attribute.type
	public const int CERTINFO_SUBJECTDIR_VALUES                  = 2240; // attribute.values
	public const int CERTINFO_SUBJECTKEYIDENTIFIER               = 2241; // 2 5 29 15 keyUsage
	public const int CERTINFO_KEYUSAGE                           = 2242; // 2 5 29 16 privateKeyUsagePeriod
	public const int CERTINFO_PRIVATEKEYUSAGEPERIOD              = 2243;
	public const int CERTINFO_PRIVATEKEY_NOTBEFORE               = 2244; // notBefore
	public const int CERTINFO_PRIVATEKEY_NOTAFTER                = 2245; // notAfter
	public const int CERTINFO_SUBJECTALTNAME                     = 2246; // 2 5 29 18 issuerAltName
	public const int CERTINFO_ISSUERALTNAME                      = 2247; // 2 5 29 19 basicConstraints
	public const int CERTINFO_BASICCONSTRAINTS                   = 2248;
	public const int CERTINFO_CA                                 = 2249; // cA
	public const int CERTINFO_AUTHORITY                          = 2249;
	public const int CERTINFO_PATHLENCONSTRAINT                  = 2250; // pathLenConstraint
	public const int CERTINFO_CRLNUMBER                          = 2251; // 2 5 29 21 cRLReason
	public const int CERTINFO_CRLREASON                          = 2252; // 2 5 29 23 holdInstructionCode
	public const int CERTINFO_HOLDINSTRUCTIONCODE                = 2253; // 2 5 29 24 invalidityDate
	public const int CERTINFO_INVALIDITYDATE                     = 2254; // 2 5 29 27 deltaCRLIndicator
	public const int CERTINFO_DELTACRLINDICATOR                  = 2255; // 2 5 29 28 issuingDistributionPoint
	public const int CERTINFO_ISSUINGDISTRIBUTIONPOINT           = 2256;
	public const int CERTINFO_ISSUINGDIST_FULLNAME               = 2257; // distributionPointName.fullName
	public const int CERTINFO_ISSUINGDIST_USERCERTSONLY          = 2258; // onlyContainsUserCerts
	public const int CERTINFO_ISSUINGDIST_CACERTSONLY            = 2259; // onlyContainsCACerts
	public const int CERTINFO_ISSUINGDIST_SOMEREASONSONLY        = 2260; // onlySomeReasons
	public const int CERTINFO_ISSUINGDIST_INDIRECTCRL            = 2261; // indirectCRL
	public const int CERTINFO_CERTIFICATEISSUER                  = 2262; // 2 5 29 30 nameConstraints
	public const int CERTINFO_NAMECONSTRAINTS                    = 2263;
	public const int CERTINFO_PERMITTEDSUBTREES                  = 2264; // permittedSubtrees
	public const int CERTINFO_EXCLUDEDSUBTREES                   = 2265; // excludedSubtrees
	public const int CERTINFO_CRLDISTRIBUTIONPOINT               = 2266;
	public const int CERTINFO_CRLDIST_FULLNAME                   = 2267; // distributionPointName.fullName
	public const int CERTINFO_CRLDIST_REASONS                    = 2268; // reasons
	public const int CERTINFO_CRLDIST_CRLISSUER                  = 2269; // cRLIssuer
	public const int CERTINFO_CERTIFICATEPOLICIES                = 2270;
	public const int CERTINFO_CERTPOLICYID                       = 2271; // policyInformation.policyIdentifier
	public const int CERTINFO_CERTPOLICY_CPSURI                  = 2272; // policyInformation.policyQualifiers.qualifier.cPSuri
	public const int CERTINFO_CERTPOLICY_ORGANIZATION            = 2273; // policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization
	public const int CERTINFO_CERTPOLICY_NOTICENUMBERS           = 2274; // policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers
	public const int CERTINFO_CERTPOLICY_EXPLICITTEXT            = 2275; // policyInformation.policyQualifiers.qualifier.userNotice.explicitText
	public const int CERTINFO_POLICYMAPPINGS                     = 2276;
	public const int CERTINFO_ISSUERDOMAINPOLICY                 = 2277; // policyMappings.issuerDomainPolicy
	public const int CERTINFO_SUBJECTDOMAINPOLICY                = 2278; // policyMappings.subjectDomainPolicy
	public const int CERTINFO_AUTHORITYKEYIDENTIFIER             = 2279;
	public const int CERTINFO_AUTHORITY_KEYIDENTIFIER            = 2280; // keyIdentifier
	public const int CERTINFO_AUTHORITY_CERTISSUER               = 2281; // authorityCertIssuer
	public const int CERTINFO_AUTHORITY_CERTSERIALNUMBER         = 2282; // authorityCertSerialNumber
	public const int CERTINFO_POLICYCONSTRAINTS                  = 2283;
	public const int CERTINFO_REQUIREEXPLICITPOLICY              = 2284; // policyConstraints.requireExplicitPolicy
	public const int CERTINFO_INHIBITPOLICYMAPPING               = 2285; // policyConstraints.inhibitPolicyMapping
	public const int CERTINFO_EXTKEYUSAGE                        = 2286;
	public const int CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING    = 2287; // individualCodeSigning
	public const int CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING    = 2288; // commercialCodeSigning
	public const int CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING     = 2289; // certTrustListSigning
	public const int CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING         = 2290; // timeStampSigning
	public const int CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO        = 2291; // serverGatedCrypto
	public const int CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM      = 2292; // encrypedFileSystem
	public const int CERTINFO_EXTKEY_SERVERAUTH                  = 2293; // serverAuth
	public const int CERTINFO_EXTKEY_CLIENTAUTH                  = 2294; // clientAuth
	public const int CERTINFO_EXTKEY_CODESIGNING                 = 2295; // codeSigning
	public const int CERTINFO_EXTKEY_EMAILPROTECTION             = 2296; // emailProtection
	public const int CERTINFO_EXTKEY_IPSECENDSYSTEM              = 2297; // ipsecEndSystem
	public const int CERTINFO_EXTKEY_IPSECTUNNEL                 = 2298; // ipsecTunnel
	public const int CERTINFO_EXTKEY_IPSECUSER                   = 2299; // ipsecUser
	public const int CERTINFO_EXTKEY_TIMESTAMPING                = 2300; // timeStamping
	public const int CERTINFO_EXTKEY_OCSPSIGNING                 = 2301; // ocspSigning
	public const int CERTINFO_EXTKEY_DIRECTORYSERVICE            = 2302; // directoryService
	public const int CERTINFO_EXTKEY_ANYKEYUSAGE                 = 2303; // anyExtendedKeyUsage
	public const int CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO        = 2304; // serverGatedCrypto
	public const int CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA     = 2305; // serverGatedCrypto CA
	public const int CERTINFO_FRESHESTCRL                        = 2306;
	public const int CERTINFO_FRESHESTCRL_FULLNAME               = 2307; // distributionPointName.fullName
	public const int CERTINFO_FRESHESTCRL_REASONS                = 2308; // reasons
	public const int CERTINFO_FRESHESTCRL_CRLISSUER              = 2309; // cRLIssuer
	public const int CERTINFO_INHIBITANYPOLICY                   = 2310; // 2 16 840 1 113730 1 x Netscape extensions
	public const int CERTINFO_NS_CERTTYPE                        = 2311; // netscape-cert-type
	public const int CERTINFO_NS_BASEURL                         = 2312; // netscape-base-url
	public const int CERTINFO_NS_REVOCATIONURL                   = 2313; // netscape-revocation-url
	public const int CERTINFO_NS_CAREVOCATIONURL                 = 2314; // netscape-ca-revocation-url
	public const int CERTINFO_NS_CERTRENEWALURL                  = 2315; // netscape-cert-renewal-url
	public const int CERTINFO_NS_CAPOLICYURL                     = 2316; // netscape-ca-policy-url
	public const int CERTINFO_NS_SSLSERVERNAME                   = 2317; // netscape-ssl-server-name
	public const int CERTINFO_NS_COMMENT                         = 2318; // netscape-comment
	public const int CERTINFO_SET_HASHEDROOTKEY                  = 2319;
	public const int CERTINFO_SET_ROOTKEYTHUMBPRINT              = 2320; // rootKeyThumbPrint
	public const int CERTINFO_SET_CERTIFICATETYPE                = 2321; // 2 23 42 7 2 SET merchantData
	public const int CERTINFO_SET_MERCHANTDATA                   = 2322;
	public const int CERTINFO_SET_MERID                          = 2323; // merID
	public const int CERTINFO_SET_MERACQUIRERBIN                 = 2324; // merAcquirerBIN
	public const int CERTINFO_SET_MERCHANTLANGUAGE               = 2325; // merNames.language
	public const int CERTINFO_SET_MERCHANTNAME                   = 2326; // merNames.name
	public const int CERTINFO_SET_MERCHANTCITY                   = 2327; // merNames.city
	public const int CERTINFO_SET_MERCHANTSTATEPROVINCE          = 2328; // merNames.stateProvince
	public const int CERTINFO_SET_MERCHANTPOSTALCODE             = 2329; // merNames.postalCode
	public const int CERTINFO_SET_MERCHANTCOUNTRYNAME            = 2330; // merNames.countryName
	public const int CERTINFO_SET_MERCOUNTRY                     = 2331; // merCountry
	public const int CERTINFO_SET_MERAUTHFLAG                    = 2332; // merAuthFlag
	public const int CERTINFO_SET_CERTCARDREQUIRED               = 2333; // 2 23 42 7 4 SET tunneling
	public const int CERTINFO_SET_TUNNELING                      = 2334;
	public const int CERTINFO_SET_TUNNELLING                     = 2334;
	public const int CERTINFO_SET_TUNNELINGFLAG                  = 2335; // tunneling
	public const int CERTINFO_SET_TUNNELLINGFLAG                 = 2335;
	public const int CERTINFO_SET_TUNNELINGALGID                 = 2336; // tunnelingAlgID
	public const int CERTINFO_SET_TUNNELLINGALGID                = 2336; // S/MIME attributes
	public const int CERTINFO_CMS_CONTENTTYPE                    = 2500; // 1 2 840 113549 1 9 4 messageDigest
	public const int CERTINFO_CMS_MESSAGEDIGEST                  = 2501; // 1 2 840 113549 1 9 5 signingTime
	public const int CERTINFO_CMS_SIGNINGTIME                    = 2502; // 1 2 840 113549 1 9 6 counterSignature
	public const int CERTINFO_CMS_COUNTERSIGNATURE               = 2503; // counterSignature
	public const int CERTINFO_CMS_SMIMECAPABILITIES              = 2504;
	public const int CERTINFO_CMS_SMIMECAP_3DES                  = 2505; // 3DES encryption
	public const int CERTINFO_CMS_SMIMECAP_AES                   = 2506; // AES encryption
	public const int CERTINFO_CMS_SMIMECAP_CAST128               = 2507; // CAST-128 encryption
	public const int CERTINFO_CMS_SMIMECAP_IDEA                  = 2508; // IDEA encryption
	public const int CERTINFO_CMS_SMIMECAP_RC2                   = 2509; // RC2 encryption (w.128 key)
	public const int CERTINFO_CMS_SMIMECAP_RC5                   = 2510; // RC5 encryption (w.128 key)
	public const int CERTINFO_CMS_SMIMECAP_SKIPJACK              = 2511; // Skipjack encryption
	public const int CERTINFO_CMS_SMIMECAP_DES                   = 2512; // DES encryption
	public const int CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA      = 2513; // preferSignedData
	public const int CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY      = 2514; // canNotDecryptAny
	public const int CERTINFO_CMS_RECEIPTREQUEST                 = 2515;
	public const int CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER      = 2516; // contentIdentifier
	public const int CERTINFO_CMS_RECEIPT_FROM                   = 2517; // receiptsFrom
	public const int CERTINFO_CMS_RECEIPT_TO                     = 2518; // receiptsTo
	public const int CERTINFO_CMS_SECURITYLABEL                  = 2519;
	public const int CERTINFO_CMS_SECLABEL_CLASSIFICATION        = 2520; // securityClassification
	public const int CERTINFO_CMS_SECLABEL_POLICY                = 2521; // securityPolicyIdentifier
	public const int CERTINFO_CMS_SECLABEL_PRIVACYMARK           = 2522; // privacyMark
	public const int CERTINFO_CMS_SECLABEL_CATTYPE               = 2523; // securityCategories.securityCategory.type
	public const int CERTINFO_CMS_SECLABEL_CATVALUE              = 2524; // securityCategories.securityCategory.value
	public const int CERTINFO_CMS_MLEXPANSIONHISTORY             = 2525;
	public const int CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER         = 2526; // mlData.mailListIdentifier.issuerAndSerialNumber
	public const int CERTINFO_CMS_MLEXP_TIME                     = 2527; // mlData.expansionTime
	public const int CERTINFO_CMS_MLEXP_NONE                     = 2528; // mlData.mlReceiptPolicy.none
	public const int CERTINFO_CMS_MLEXP_INSTEADOF                = 2529; // mlData.mlReceiptPolicy.insteadOf.generalNames.generalName
	public const int CERTINFO_CMS_MLEXP_INADDITIONTO             = 2530; // mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName
	public const int CERTINFO_CMS_CONTENTHINTS                   = 2531;
	public const int CERTINFO_CMS_CONTENTHINT_DESCRIPTION        = 2532; // contentDescription
	public const int CERTINFO_CMS_CONTENTHINT_TYPE               = 2533; // contentType
	public const int CERTINFO_CMS_EQUIVALENTLABEL                = 2534;
	public const int CERTINFO_CMS_EQVLABEL_POLICY                = 2535; // securityPolicyIdentifier
	public const int CERTINFO_CMS_EQVLABEL_CLASSIFICATION        = 2536; // securityClassification
	public const int CERTINFO_CMS_EQVLABEL_PRIVACYMARK           = 2537; // privacyMark
	public const int CERTINFO_CMS_EQVLABEL_CATTYPE               = 2538; // securityCategories.securityCategory.type
	public const int CERTINFO_CMS_EQVLABEL_CATVALUE              = 2539; // securityCategories.securityCategory.value
	public const int CERTINFO_CMS_SIGNINGCERTIFICATE             = 2540;
	public const int CERTINFO_CMS_SIGNINGCERT_ESSCERTID          = 2541; // certs.essCertID
	public const int CERTINFO_CMS_SIGNINGCERT_POLICIES           = 2542; // policies.policyInformation.policyIdentifier
	public const int CERTINFO_CMS_SIGNATUREPOLICYID              = 2543;
	public const int CERTINFO_CMS_SIGPOLICYID                    = 2544; // sigPolicyID
	public const int CERTINFO_CMS_SIGPOLICYHASH                  = 2545; // sigPolicyHash
	public const int CERTINFO_CMS_SIGPOLICY_CPSURI               = 2546; // sigPolicyQualifiers.sigPolicyQualifier.cPSuri
	public const int CERTINFO_CMS_SIGPOLICY_ORGANIZATION         = 2547; // sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization
	public const int CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS        = 2548; // sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers
	public const int CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT         = 2549; // sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText
	public const int CERTINFO_CMS_SIGTYPEIDENTIFIER              = 2550;
	public const int CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG        = 2551; // originatorSig
	public const int CERTINFO_CMS_SIGTYPEID_DOMAINSIG            = 2552; // domainSig
	public const int CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES = 2553; // additionalAttributesSig
	public const int CERTINFO_CMS_SIGTYPEID_REVIEWSIG            = 2554; // reviewSig
	public const int CERTINFO_CMS_NONCE                          = 2555; // randomNonce
	public const int CERTINFO_SCEP_MESSAGETYPE                   = 2556; // messageType
	public const int CERTINFO_SCEP_PKISTATUS                     = 2557; // pkiStatus
	public const int CERTINFO_SCEP_FAILINFO                      = 2558; // failInfo
	public const int CERTINFO_SCEP_SENDERNONCE                   = 2559; // senderNonce
	public const int CERTINFO_SCEP_RECIPIENTNONCE                = 2560; // recipientNonce
	public const int CERTINFO_SCEP_TRANSACTIONID                 = 2561; // transID
	public const int CERTINFO_CMS_SPCAGENCYINFO                  = 2562;
	public const int CERTINFO_CMS_SPCAGENCYURL                   = 2563; // spcAgencyInfo.url
	public const int CERTINFO_CMS_SPCSTATEMENTTYPE               = 2564;
	public const int CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING  = 2565; // individualCodeSigning
	public const int CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING  = 2566; // commercialCodeSigning
	public const int CERTINFO_CMS_SPCOPUSINFO                    = 2567;
	public const int CERTINFO_CMS_SPCOPUSINFO_NAME               = 2568; // spcOpusInfo.name
	public const int CERTINFO_CMS_SPCOPUSINFO_URL                = 2569; // spcOpusInfo.url
	public const int CERTINFO_LAST                               = 2570;
	public const int KEYINFO_FIRST                               = 3000; // *******************
	public const int KEYINFO_QUERY                               = 3001; // Keyset query
	public const int KEYINFO_QUERY_REQUESTS                      = 3002; // Query of requests in cert store
	public const int KEYINFO_LAST                                = 3003;
	public const int DEVINFO_FIRST                               = 4000; // *******************
	public const int DEVINFO_INITIALISE                          = 4001; // Initialise device for use
	public const int DEVINFO_INITIALIZE                          = 4001;
	public const int DEVINFO_AUTHENT_USER                        = 4002; // Authenticate user to device
	public const int DEVINFO_AUTHENT_SUPERVISOR                  = 4003; // Authenticate supervisor to dev.
	public const int DEVINFO_SET_AUTHENT_USER                    = 4004; // Set user authent.value
	public const int DEVINFO_SET_AUTHENT_SUPERVISOR              = 4005; // Set supervisor auth.val.
	public const int DEVINFO_ZEROISE                             = 4006; // Zeroise device
	public const int DEVINFO_ZEROIZE                             = 4006;
	public const int DEVINFO_LOGGEDIN                            = 4007; // Whether user is logged in
	public const int DEVINFO_LABEL                               = 4008; // Device/token label
	public const int DEVINFO_LAST                                = 4009;
	public const int ENVINFO_FIRST                               = 5000; // *********************
	public const int ENVINFO_DATASIZE                            = 5001; // Data size information
	public const int ENVINFO_COMPRESSION                         = 5002; // Compression information
	public const int ENVINFO_CONTENTTYPE                         = 5003; // Inner CMS content type
	public const int ENVINFO_DETACHEDSIGNATURE                   = 5004; // Generate CMS detached signature
	public const int ENVINFO_SIGNATURE_RESULT                    = 5005; // Signature check result
	public const int ENVINFO_MAC                                 = 5006; // Use MAC instead of encrypting
	public const int ENVINFO_PASSWORD                            = 5007; // User password
	public const int ENVINFO_KEY                                 = 5008; // Conventional encryption key
	public const int ENVINFO_SIGNATURE                           = 5009; // Signature/signature check key
	public const int ENVINFO_SIGNATURE_EXTRADATA                 = 5010; // Extra information added to CMS sigs
	public const int ENVINFO_RECIPIENT                           = 5011; // Recipient email address
	public const int ENVINFO_PUBLICKEY                           = 5012; // PKC encryption key
	public const int ENVINFO_PRIVATEKEY                          = 5013; // PKC decryption key
	public const int ENVINFO_PRIVATEKEY_LABEL                    = 5014; // Label of PKC decryption key
	public const int ENVINFO_ORIGINATOR                          = 5015; // Originator info/key
	public const int ENVINFO_SESSIONKEY                          = 5016; // Session key
	public const int ENVINFO_HASH                                = 5017; // Hash value
	public const int ENVINFO_TIMESTAMP                           = 5018; // Timestamp information
	public const int ENVINFO_KEYSET_SIGCHECK                     = 5019; // Signature check keyset
	public const int ENVINFO_KEYSET_ENCRYPT                      = 5020; // PKC encryption keyset
	public const int ENVINFO_KEYSET_DECRYPT                      = 5021; // PKC decryption keyset
	public const int ENVINFO_LAST                                = 5022;
	public const int SESSINFO_FIRST                              = 6000; // ********************
	public const int SESSINFO_ACTIVE                             = 6001; // Whether session is active
	public const int SESSINFO_CONNECTIONACTIVE                   = 6002; // Whether network connection is active
	public const int SESSINFO_USERNAME                           = 6003; // User name
	public const int SESSINFO_PASSWORD                           = 6004; // Password
	public const int SESSINFO_PRIVATEKEY                         = 6005; // Server/client private key
	public const int SESSINFO_KEYSET                             = 6006; // Certificate store
	public const int SESSINFO_AUTHRESPONSE                       = 6007; // Session authorisation OK
	public const int SESSINFO_SERVER_NAME                        = 6008; // Server name
	public const int SESSINFO_SERVER_PORT                        = 6009; // Server port number
	public const int SESSINFO_SERVER_FINGERPRINT                 = 6010; // Server key fingerprint
	public const int SESSINFO_CLIENT_NAME                        = 6011; // Client name
	public const int SESSINFO_CLIENT_PORT                        = 6012; // Client port number
	public const int SESSINFO_SESSION                            = 6013; // Transport mechanism
	public const int SESSINFO_NETWORKSOCKET                      = 6014; // User-supplied network socket
	public const int SESSINFO_VERSION                            = 6015; // Protocol version
	public const int SESSINFO_REQUEST                            = 6016; // Cert.request object
	public const int SESSINFO_RESPONSE                           = 6017; // Cert.response object
	public const int SESSINFO_CACERTIFICATE                      = 6018; // Issuing CA certificate
	public const int SESSINFO_TSP_MSGIMPRINT                     = 6019; // TSP message imprint
	public const int SESSINFO_CMP_REQUESTTYPE                    = 6020; // Request type
	public const int SESSINFO_CMP_PKIBOOT                        = 6021; // Enable PKIBoot facility
	public const int SESSINFO_CMP_PRIVKEYSET                     = 6022; // Private-key keyset
	public const int SESSINFO_SSH_CHANNEL                        = 6023; // SSH current channel
	public const int SESSINFO_SSH_CHANNEL_TYPE                   = 6024; // SSH channel type
	public const int SESSINFO_SSH_CHANNEL_ARG1                   = 6025; // SSH channel argument 1
	public const int SESSINFO_SSH_CHANNEL_ARG2                   = 6026; // SSH channel argument 2
	public const int SESSINFO_SSH_CHANNEL_ACTIVE                 = 6027; // SSH channel active
	public const int SESSINFO_LAST                               = 6028;
	public const int USERINFO_FIRST                              = 7000; // ********************
	public const int USERINFO_PASSWORD                           = 7001; // Password
	public const int USERINFO_CAKEY_CERTSIGN                     = 7002; // CA cert signing key
	public const int USERINFO_CAKEY_CRLSIGN                      = 7003; // CA CRL signing key
	public const int USERINFO_CAKEY_RTCSSIGN                     = 7004; // CA RTCS signing key
	public const int USERINFO_CAKEY_OCSPSIGN                     = 7005; // CA OCSP signing key
	public const int USERINFO_LAST                               = 7006;
	public const int ATTRIBUTE_LAST                              = 7006;
	
	/****************************************************************************
	*																			*
	*						Attribute Subtypes and Related Values				*
	*																			*
	****************************************************************************/
	
	/* Flags for the X.509 keyUsage extension */
	
	public const int KEYUSAGE_NONE                            = 0x000;
	public const int KEYUSAGE_DIGITALSIGNATURE                = 0x001;
	public const int KEYUSAGE_NONREPUDIATION                  = 0x002;
	public const int KEYUSAGE_KEYENCIPHERMENT                 = 0x004;
	public const int KEYUSAGE_DATAENCIPHERMENT                = 0x008;
	public const int KEYUSAGE_KEYAGREEMENT                    = 0x010;
	public const int KEYUSAGE_KEYCERTSIGN                     = 0x020;
	public const int KEYUSAGE_CRLSIGN                         = 0x040;
	public const int KEYUSAGE_ENCIPHERONLY                    = 0x080;
	public const int KEYUSAGE_DECIPHERONLY                    = 0x100;
	public const int KEYUSAGE_LAST                            = 0x200; // Last possible value
	
	/* X.509 cRLReason and cryptlib cRLExtReason codes */
	
	public const int CRLREASON_UNSPECIFIED          = 0 ;
	public const int CRLREASON_KEYCOMPROMISE        = 1 ;
	public const int CRLREASON_CACOMPROMISE         = 2 ;
	public const int CRLREASON_AFFILIATIONCHANGED   = 3 ;
	public const int CRLREASON_SUPERSEDED           = 4 ;
	public const int CRLREASON_CESSATIONOFOPERATION = 5 ;
	public const int CRLREASON_CERTIFICATEHOLD      = 6 ;
	public const int CRLREASON_REMOVEFROMCRL        = 8 ;
	public const int CRLREASON_PRIVILEGEWITHDRAWN   = 9 ;
	public const int CRLREASON_AACOMPROMISE         = 10;
	public const int CRLREASON_LAST                 = 11; // End of standard CRL reasons
	public const int CRLREASON_NEVERVALID           = 20;
	public const int CRLEXTREASON_LAST              = 21;
	
	/* X.509 CRL reason flags.  These identify the same thing as the cRLReason
	   codes but allow for multiple reasons to be specified.  Note that these
	   don't follow the X.509 naming since in that scheme the enumerated types
	   and bitflags have the same names */
	
	public const int CRLREASONFLAG_UNUSED                     = 0x001;
	public const int CRLREASONFLAG_KEYCOMPROMISE              = 0x002;
	public const int CRLREASONFLAG_CACOMPROMISE               = 0x004;
	public const int CRLREASONFLAG_AFFILIATIONCHANGED         = 0x008;
	public const int CRLREASONFLAG_SUPERSEDED                 = 0x010;
	public const int CRLREASONFLAG_CESSATIONOFOPERATION       = 0x020;
	public const int CRLREASONFLAG_CERTIFICATEHOLD            = 0x040;
	public const int CRLREASONFLAG_LAST                       = 0x080; // Last poss.value
	
	/* X.509 CRL holdInstruction codes */
	
	public const int HOLDINSTRUCTION_NONE        = 0;
	public const int HOLDINSTRUCTION_CALLISSUER  = 1;
	public const int HOLDINSTRUCTION_REJECT      = 2;
	public const int HOLDINSTRUCTION_PICKUPTOKEN = 3;
	public const int HOLDINSTRUCTION_LAST        = 4;
	
	/* Certificate checking compliance levels */
	
	public const int COMPLIANCELEVEL_OBLIVIOUS    = 0;
	public const int COMPLIANCELEVEL_REDUCED      = 1;
	public const int COMPLIANCELEVEL_STANDARD     = 2;
	public const int COMPLIANCELEVEL_PKIX_PARTIAL = 3;
	public const int COMPLIANCELEVEL_PKIX_FULL    = 4;
	public const int COMPLIANCELEVEL_LAST         = 5;
	
	/* Flags for the Netscape netscape-cert-type extension */
	
	public const int NS_CERTTYPE_SSLCLIENT                    = 0x001;
	public const int NS_CERTTYPE_SSLSERVER                    = 0x002;
	public const int NS_CERTTYPE_SMIME                        = 0x004;
	public const int NS_CERTTYPE_OBJECTSIGNING                = 0x008;
	public const int NS_CERTTYPE_RESERVED                     = 0x010;
	public const int NS_CERTTYPE_SSLCA                        = 0x020;
	public const int NS_CERTTYPE_SMIMECA                      = 0x040;
	public const int NS_CERTTYPE_OBJECTSIGNINGCA              = 0x080;
	public const int NS_CERTTYPE_LAST                         = 0x100; // Last possible value
	
	/* Flags for the SET certificate-type extension */
	
	public const int SET_CERTTYPE_CARD                        = 0x001;
	public const int SET_CERTTYPE_MER                         = 0x002;
	public const int SET_CERTTYPE_PGWY                        = 0x004;
	public const int SET_CERTTYPE_CCA                         = 0x008;
	public const int SET_CERTTYPE_MCA                         = 0x010;
	public const int SET_CERTTYPE_PCA                         = 0x020;
	public const int SET_CERTTYPE_GCA                         = 0x040;
	public const int SET_CERTTYPE_BCA                         = 0x080;
	public const int SET_CERTTYPE_RCA                         = 0x100;
	public const int SET_CERTTYPE_ACQ                         = 0x200;
	public const int SET_CERTTYPE_LAST                        = 0x400; // Last possible value
	
	/* CMS contentType values */
	
	// CRYPT_CONTENT_TYPE
	public const int CONTENT_NONE                   = 0 ;
	public const int CONTENT_DATA                   = 1 ;
	public const int CONTENT_SIGNEDDATA             = 2 ;
	public const int CONTENT_ENVELOPEDDATA          = 3 ;
	public const int CONTENT_SIGNEDANDENVELOPEDDATA = 4 ;
	public const int CONTENT_DIGESTEDDATA           = 5 ;
	public const int CONTENT_ENCRYPTEDDATA          = 6 ;
	public const int CONTENT_COMPRESSEDDATA         = 7 ;
	public const int CONTENT_TSTINFO                = 8 ;
	public const int CONTENT_SPCINDIRECTDATACONTEXT = 9 ;
	public const int CONTENT_RTCSREQUEST            = 10;
	public const int CONTENT_RTCSRESPONSE           = 11;
	public const int CONTENT_RTCSRESPONSE_EXT       = 12;
	public const int CONTENT_LAST                   = 13;
	
	/* ESS securityClassification codes */
	
	public const int CLASSIFICATION_UNMARKED     = 0  ;
	public const int CLASSIFICATION_UNCLASSIFIED = 1  ;
	public const int CLASSIFICATION_RESTRICTED   = 2  ;
	public const int CLASSIFICATION_CONFIDENTIAL = 3  ;
	public const int CLASSIFICATION_SECRET       = 4  ;
	public const int CLASSIFICATION_TOP_SECRET   = 5  ;
	public const int CLASSIFICATION_LAST         = 255;
	
	/* RTCS certificate status */
	
	public const int CERTSTATUS_VALID            = 0;
	public const int CERTSTATUS_NOTVALID         = 1;
	public const int CERTSTATUS_NONAUTHORITATIVE = 2;
	public const int CERTSTATUS_UNKNOWN          = 3;
	
	/* OCSP revocation status */
	
	public const int OCSPSTATUS_NOTREVOKED = 0;
	public const int OCSPSTATUS_REVOKED    = 1;
	public const int OCSPSTATUS_UNKNOWN    = 2;
	
	/* The amount of detail to include in signatures when signing certificate
	   objects */
	
	// CRYPT_SIGNATURELEVEL_TYPE
	public const int SIGNATURELEVEL_NONE       = 0; // Include only signature
	public const int SIGNATURELEVEL_SIGNERCERT = 1; // Include signer cert
	public const int SIGNATURELEVEL_ALL        = 2; // Include all relevant info
	public const int SIGNATURELEVEL_LAST       = 3; // Last possible sig.level type
	
	/* The certificate export format type, which defines the format in which a
	   certificate object is exported */
	
	// CRYPT_CERTFORMAT_TYPE
	public const int CERTFORMAT_NONE             = 0; // No certificate format
	public const int CERTFORMAT_CERTIFICATE      = 1; // DER-encoded certificate
	public const int CERTFORMAT_CERTCHAIN        = 2; // PKCS #7 certificate chain
	public const int CERTFORMAT_TEXT_CERTIFICATE = 3; // base-64 wrapped cert
	public const int CERTFORMAT_TEXT_CERTCHAIN   = 4; // base-64 wrapped cert chain
	public const int CERTFORMAT_XML_CERTIFICATE  = 5; // XML wrapped cert
	public const int CERTFORMAT_XML_CERTCHAIN    = 6; // XML wrapped cert chain
	public const int CERTFORMAT_LAST             = 7; // Last possible cert.format type
	
	/* CMP request types */
	
	// CRYPT_REQUESTTYPE_TYPE
	public const int REQUESTTYPE_NONE           = 0; // No request type
	public const int REQUESTTYPE_INITIALISATION = 1; // Initialisation request
	public const int REQUESTTYPE_INITIALIZATION = 1;
	public const int REQUESTTYPE_CERTIFICATE    = 2; // Certification request
	public const int REQUESTTYPE_KEYUPDATE      = 3; // Key update request
	public const int REQUESTTYPE_REVOCATION     = 4; // Cert revocation request
	public const int REQUESTTYPE_PKIBOOT        = 5; // PKIBoot request
	public const int REQUESTTYPE_LAST           = 6; // Last possible request type
	
	/* Key ID types */
	
	// CRYPT_KEYID_TYPE
	public const int KEYID_NONE  = 0; // No key ID type
	public const int KEYID_NAME  = 1; // Key owner name
	public const int KEYID_URI   = 2; // Key owner URI
	public const int KEYID_EMAIL = 2; // Synonym: owner email addr.
	public const int KEYID_LAST  = 3; // Last possible key ID type
	
	/* The encryption object types */
	
	// CRYPT_OBJECT_TYPE
	public const int OBJECT_NONE             = 0; // No object type
	public const int OBJECT_ENCRYPTED_KEY    = 1; // Conventionally encrypted key
	public const int OBJECT_PKCENCRYPTED_KEY = 2; // PKC-encrypted key
	public const int OBJECT_KEYAGREEMENT     = 3; // Key agreement information
	public const int OBJECT_SIGNATURE        = 4; // Signature
	public const int OBJECT_LAST             = 5; // Last possible object type
	
	/* Object/attribute error type information */
	
	// CRYPT_ERRTYPE_TYPE
	public const int ERRTYPE_NONE             = 0; // No error information
	public const int ERRTYPE_ATTR_SIZE        = 1; // Attribute data too small or large
	public const int ERRTYPE_ATTR_VALUE       = 2; // Attribute value is invalid
	public const int ERRTYPE_ATTR_ABSENT      = 3; // Required attribute missing
	public const int ERRTYPE_ATTR_PRESENT     = 4; // Non-allowed attribute present
	public const int ERRTYPE_CONSTRAINT       = 5; // Cert: Constraint violation in object
	public const int ERRTYPE_ISSUERCONSTRAINT = 6; // Cert: Constraint viol.in issuing cert
	public const int ERRTYPE_LAST             = 7; // Last possible error info type
	
	/* Cert store management action type */
	
	// CRYPT_CERTACTION_TYPE
	public const int CERTACTION_NONE                   = 0 ; // No cert management action
	public const int CERTACTION_CREATE                 = 1 ; // Create cert store
	public const int CERTACTION_CONNECT                = 2 ; // Connect to cert store
	public const int CERTACTION_DISCONNECT             = 3 ; // Disconnect from cert store
	public const int CERTACTION_ERROR                  = 4 ; // Error information
	public const int CERTACTION_ADDUSER                = 5 ; // Add PKI user
	public const int CERTACTION_DELETEUSER             = 6 ; // Delete PKI user
	public const int CERTACTION_REQUEST_CERT           = 7 ; // Cert request
	public const int CERTACTION_REQUEST_RENEWAL        = 8 ; // Cert renewal request
	public const int CERTACTION_REQUEST_REVOCATION     = 9 ; // Cert revocation request
	public const int CERTACTION_CERT_CREATION          = 10; // Cert creation
	public const int CERTACTION_CERT_CREATION_COMPLETE = 11; // Confirmation of cert creation
	public const int CERTACTION_CERT_CREATION_DROP     = 12; // Cancellation of cert creation
	public const int CERTACTION_CERT_CREATION_REVERSE  = 13; // Cancel of creation w.revocation
	public const int CERTACTION_RESTART_CLEANUP        = 14; // Delete reqs after restart
	public const int CERTACTION_RESTART_REVOKE_CERT    = 15; // Complete revocation after restart
	public const int CERTACTION_ISSUE_CERT             = 16; // Cert issue
	public const int CERTACTION_ISSUE_CRL              = 17; // CRL issue
	public const int CERTACTION_REVOKE_CERT            = 18; // Cert revocation
	public const int CERTACTION_EXPIRE_CERT            = 19; // Cert expiry
	public const int CERTACTION_CLEANUP                = 20; // Clean up on restart
	public const int CERTACTION_LAST                   = 21; // Last possible cert store log action
	
	/****************************************************************************
	*																			*
	*								General Constants							*
	*																			*
	****************************************************************************/
	
	/* The maximum user key size - 2048 bits */
	
	public const int MAX_KEYSIZE                              = 256 ;
	
	/* The maximum IV size - 256 bits */
	
	public const int MAX_IVSIZE                               = 32  ;
	
	/* The maximum public-key component size - 4096 bits */
	
	public const int MAX_PKCSIZE                              = 512 ;
	
	/* The maximum hash size - 256 bits */
	
	public const int MAX_HASHSIZE                             = 32  ;
	
	/* The maximum size of a text string (e.g.key owner name) */
	
	public const int MAX_TEXTSIZE                             = 64  ;
	
	/* A magic value indicating that the default setting for this parameter
	   should be used */
	
	public const int USE_DEFAULT                              = -10 ;
	
	/* A magic value for unused parameters */
	
	public const int UNUSED                                   = -11 ;
	
	/* Whether the PKC key is a public or private key */
	
	public const int KEYTYPE_PRIVATE                          = 0   ;
	public const int KEYTYPE_PUBLIC                           = 1   ;
	
	/* The type of information polling to perform to get random seed information */
	
	public const int RANDOM_FASTPOLL                          = -10 ;
	public const int RANDOM_SLOWPOLL                          = -11 ;
	
	/* Cursor positioning codes for certificate/CRL extensions */
	
	public const int CURSOR_FIRST                             = -20 ;
	public const int CURSOR_PREVIOUS                          = -21 ;
	public const int CURSOR_NEXT                              = -22 ;
	public const int CURSOR_LAST                              = -23 ;
	
	/* Keyset open options */
	
	// CRYPT_KEYOPT_TYPE
	public const int KEYOPT_NONE     = 0; // No options
	public const int KEYOPT_READONLY = 1; // Open keyset in read-only mode
	public const int KEYOPT_CREATE   = 2; // Create a new keyset
	public const int KEYOPT_LAST     = 3; // Last possible key option type
	
	/* The various cryptlib objects - these are just integer handles */
	
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_CERTIFICATE;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_CONTEXT;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_DEVICE;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_ENVELOPE;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_KEYSET;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_SESSION;
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_USER;
	
	/* Sometimes we don't know the exact type of a cryptlib object, so we use a
	   generic handle type to identify it */
	
	//CRYPTLIBCONVERTER - NOT NEEDED: typedef int CRYPT_HANDLE;
	
	/****************************************************************************
	*																			*
	*							Encryption Data Structures						*
	*																			*
	****************************************************************************/
	
	/* Results returned from the capability query */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//typedef struct {
	//	/* Algorithm information */
	//	C_CHR algoName[ CRYPT_MAX_TEXTSIZE ];/* Algorithm name */
	//	int blockSize;					/* Block size of the algorithm */
	//	int minKeySize;					/* Minimum key size in bytes */
	//	int keySize;					/* Recommended key size in bytes */
	//	int maxKeySize;					/* Maximum key size in bytes */
	//	} CRYPT_QUERY_INFO;
	
	/* Results returned from the encoded object query.  These provide
	   information on the objects created by cryptExportKey()/
	   cryptCreateSignature() */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//typedef struct {
	//	/* The object type */
	//	CRYPT_OBJECT_TYPE objectType;
	//
	//	/* The encryption algorithm and mode */
	//	CRYPT_ALGO_TYPE cryptAlgo;
	//	CRYPT_MODE_TYPE cryptMode;
	//
	//	/* The hash algorithm for Signature objects */
	//	CRYPT_ALGO_TYPE hashAlgo;
	//
	//	/* The salt for derived keys */
	//	unsigned char salt[ CRYPT_MAX_HASHSIZE ];
	//	int saltSize;
	//	} CRYPT_OBJECT_INFO;
	
	/* Key information for the public-key encryption algorithms.  These fields
	   are not accessed directly, but can be manipulated with the init/set/
	   destroyComponents() macros */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//typedef struct {
	//	/* Status information */
	//	int isPublicKey;			/* Whether this is a public or private key */
	//
	//	/* Public components */
	//	unsigned char n[ CRYPT_MAX_PKCSIZE ];	/* Modulus */
	//	int nLen;					/* Length of modulus in bits */
	//	unsigned char e[ CRYPT_MAX_PKCSIZE ];	/* Public exponent */
	//	int eLen;					/* Length of public exponent in bits */
	//
	//	/* Private components */
	//	unsigned char d[ CRYPT_MAX_PKCSIZE ];	/* Private exponent */
	//	int dLen;					/* Length of private exponent in bits */
	//	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 1 */
	//	int pLen;					/* Length of prime factor 1 in bits */
	//	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 2 */
	//	int qLen;					/* Length of prime factor 2 in bits */
	//	unsigned char u[ CRYPT_MAX_PKCSIZE ];	/* Mult.inverse of q, mod p */
	//	int uLen;					/* Length of private exponent in bits */
	//	unsigned char e1[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 1 (PKCS) */
	//	int e1Len;					/* Length of private exponent in bits */
	//	unsigned char e2[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 2 (PKCS) */
	//	int e2Len;					/* Length of private exponent in bits */
	//	} CRYPT_PKCINFO_RSA;
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//typedef struct {
	//	/* Status information */
	//	int isPublicKey;			/* Whether this is a public or private key */
	//
	//	/* Public components */
	//	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime modulus */
	//	int pLen;					/* Length of prime modulus in bits */
	//	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime divisor */
	//	int qLen;					/* Length of prime divisor in bits */
	//	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* h^( ( p - 1 ) / q ) mod p */
	//	int gLen;					/* Length of g in bits */
	//	unsigned char y[ CRYPT_MAX_PKCSIZE ];	/* Public random integer */
	//	int yLen;					/* Length of public integer in bits */
	//
	//	/* Private components */
	//	unsigned char x[ CRYPT_MAX_PKCSIZE ];	/* Private random integer */
	//	int xLen;					/* Length of private integer in bits */
	//	} CRYPT_PKCINFO_DLP;
	
	/* Macros to initialise and destroy the structure that stores the components
	   of a public key */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//#define cryptInitComponents( componentInfo, componentKeyType ) \
	//	{ memset( ( componentInfo ), 0, sizeof( *componentInfo ) ); \
	//	  ( componentInfo )->isPublicKey = ( ( componentKeyType ) ? 1 : 0 ); }
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//#define cryptDestroyComponents( componentInfo ) \
	//	memset( ( componentInfo ), 0, sizeof( *componentInfo ) )
	
	/* Macros to set a component of a public key */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//#define cryptSetComponent( destination, source, length ) \
	//	{ memcpy( ( destination ), ( source ), ( ( length ) + 7 ) >> 3 ); \
	//	  ( destination##Len ) = length; }
	
	/****************************************************************************
	*																			*
	*								Status Codes								*
	*																			*
	****************************************************************************/
	
	/* No error in function call */
	
	public const int OK                                       = 0   ; // No error
	
	/* Error in parameters passed to function */
	
	public const int ERROR_PARAM1                             = -1  ; // Bad argument, parameter 1
	public const int ERROR_PARAM2                             = -2  ; // Bad argument, parameter 2
	public const int ERROR_PARAM3                             = -3  ; // Bad argument, parameter 3
	public const int ERROR_PARAM4                             = -4  ; // Bad argument, parameter 4
	public const int ERROR_PARAM5                             = -5  ; // Bad argument, parameter 5
	public const int ERROR_PARAM6                             = -6  ; // Bad argument, parameter 6
	public const int ERROR_PARAM7                             = -7  ; // Bad argument, parameter 7
	
	/* Errors due to insufficient resources */
	
	public const int ERROR_MEMORY                             = -10 ; // Out of memory
	public const int ERROR_NOTINITED                          = -11 ; // Data has not been initialised
	public const int ERROR_INITED                             = -12 ; // Data has already been init'd
	public const int ERROR_NOSECURE                           = -13 ; // Opn.not avail.at requested sec.level
	public const int ERROR_RANDOM                             = -14 ; // No reliable random data available
	public const int ERROR_FAILED                             = -15 ; // Operation failed
	
	/* Security violations */
	
	public const int ERROR_NOTAVAIL                           = -20 ; // This type of opn.not available
	public const int ERROR_PERMISSION                         = -21 ; // No permiss.to perform this operation
	public const int ERROR_WRONGKEY                           = -22 ; // Incorrect key used to decrypt data
	public const int ERROR_INCOMPLETE                         = -23 ; // Operation incomplete/still in progress
	public const int ERROR_COMPLETE                           = -24 ; // Operation complete/can't continue
	public const int ERROR_TIMEOUT                            = -25 ; // Operation timed out before completion
	public const int ERROR_INVALID                            = -26 ; // Invalid/inconsistent information
	public const int ERROR_SIGNALLED                          = -27 ; // Resource destroyed by extnl.event
	
	/* High-level function errors */
	
	public const int ERROR_OVERFLOW                           = -30 ; // Resources/space exhausted
	public const int ERROR_UNDERFLOW                          = -31 ; // Not enough data available
	public const int ERROR_BADDATA                            = -32 ; // Bad/unrecognised data format
	public const int ERROR_SIGNATURE                          = -33 ; // Signature/integrity check failed
	
	/* Data access function errors */
	
	public const int ERROR_OPEN                               = -40 ; // Cannot open object
	public const int ERROR_READ                               = -41 ; // Cannot read item from object
	public const int ERROR_WRITE                              = -42 ; // Cannot write item to object
	public const int ERROR_NOTFOUND                           = -43 ; // Requested item not found in object
	public const int ERROR_DUPLICATE                          = -44 ; // Item already present in object
	
	/* Data enveloping errors */
	
	public const int ENVELOPE_RESOURCE                        = -50 ; // Need resource to proceed
	
	/* Macros to examine return values */
	
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//#define cryptStatusError( status )	( ( status ) < CRYPT_OK )
	//CRYPTLIBCONVERTER - NOT SUPPORTED:
	//#define cryptStatusOK( status )		( ( status ) == CRYPT_OK )
	
	/****************************************************************************
	*																			*
	*									General Functions						*
	*																			*
	****************************************************************************/
	
	/* The following is necessary to stop C++ name mangling */
	
	
	/* Initialise and shut down cryptlib */
	
	public static void Init()
	{
		processStatus(wrapped_Init());
	}
	
	public static void End()
	{
		processStatus(wrapped_End());
	}
	
	/* Query cryptlibs capabilities */
	
	public static CRYPT_QUERY_INFO QueryCapability(
								int cryptAlgo // CRYPT_ALGO_TYPE
								)
	{
		IntPtr cryptQueryInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
		CRYPT_QUERY_INFO cryptQueryInfo = new CRYPT_QUERY_INFO();
		try
		{
			processStatus(wrapped_QueryCapability(cryptAlgo, cryptQueryInfoPtr));
			Marshal.PtrToStructure(cryptQueryInfoPtr, cryptQueryInfo);
			return cryptQueryInfo;
		}
		finally
		{
			Marshal.FreeHGlobal(cryptQueryInfoPtr);
		}
	}
	
	/* Create and destroy an encryption context */
	
	public static int CreateContext(
								int cryptUser, // CRYPT_USER
								int cryptAlgo // CRYPT_ALGO_TYPE
								)
	{
		IntPtr cryptContextPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateContext(cryptContextPtr, cryptUser, cryptAlgo));
			return Marshal.ReadInt32(cryptContextPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(cryptContextPtr);
		}
	}
	
	public static void DestroyContext(
								int cryptContext // CRYPT_CONTEXT
								)
	{
		processStatus(wrapped_DestroyContext(cryptContext));
	}
	
	/* Generic "destroy an object" function */
	
	public static void DestroyObject(
								int cryptObject // CRYPT_HANDLE
								)
	{
		processStatus(wrapped_DestroyObject(cryptObject));
	}
	
	/* Generate a key into a context */
	
	public static void GenerateKey(
								int cryptContext // CRYPT_CONTEXT
								)
	{
		processStatus(wrapped_GenerateKey(cryptContext));
	}
	
	public static void GenerateKeyAsync(
								int cryptContext // CRYPT_CONTEXT
								)
	{
		processStatus(wrapped_GenerateKeyAsync(cryptContext));
	}
	
	public static void AsyncQuery(
								int cryptObject // CRYPT_HANDLE
								)
	{
		processStatus(wrapped_AsyncQuery(cryptObject));
	}
	
	public static void AsyncCancel(
								int cryptObject // CRYPT_HANDLE
								)
	{
		processStatus(wrapped_AsyncCancel(cryptObject));
	}
	
	/* Encrypt/decrypt/hash a block of memory */
	
	public static void Encrypt(
								int cryptContext, // CRYPT_CONTEXT
								byte[] buffer,
								int bufferOffset,
								int length
								)
	{
		GCHandle bufferHandle = new GCHandle();
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_Encrypt(cryptContext, bufferPtr, length));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}
	public static void Encrypt(
							int cryptContext, // CRYPT_CONTEXT
							byte[] buffer
							) { Encrypt(cryptContext, buffer, 0, buffer == null ? 0 : buffer.Length); }
	
	public static void Decrypt(
								int cryptContext, // CRYPT_CONTEXT
								byte[] buffer,
								int bufferOffset,
								int length
								)
	{
		GCHandle bufferHandle = new GCHandle();
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_Decrypt(cryptContext, bufferPtr, length));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}
	public static void Decrypt(
							int cryptContext, // CRYPT_CONTEXT
							byte[] buffer
							) { Decrypt(cryptContext, buffer, 0, buffer == null ? 0 : buffer.Length); }
	
	/* Get/set/delete attribute functions */
	
	public static void SetAttribute(
								int cryptHandle, // CRYPT_HANDLE
								int attributeType, // CRYPT_ATTRIBUTE_TYPE
								int value
								)
	{
		processStatus(wrapped_SetAttribute(cryptHandle, attributeType, value));
	}
	
	public static void SetAttributeString(
								int cryptHandle, // CRYPT_HANDLE
								int attributeType, // CRYPT_ATTRIBUTE_TYPE
								byte[] value,
								int valueOffset,
								int valueLength
								)
	{
		GCHandle valueHandle = new GCHandle();
		IntPtr valuePtr = IntPtr.Zero;
		try
		{
			checkIndices(value, valueOffset, valueLength);
			getPointer(value, valueOffset, ref valueHandle, ref valuePtr);
			processStatus(wrapped_SetAttributeString(cryptHandle, attributeType, valuePtr, valueLength));
		}
		finally
		{
			releasePointer(valueHandle);
		}
	}
	public static void SetAttributeString(
							int cryptHandle, // CRYPT_HANDLE
							int attributeType, // CRYPT_ATTRIBUTE_TYPE
							byte[] value
							) { SetAttributeString(cryptHandle, attributeType, value, 0, value == null ? 0 : value.Length); }
	public static void SetAttributeString(
							int cryptHandle, // CRYPT_HANDLE
							int attributeType, // CRYPT_ATTRIBUTE_TYPE
							String value
							) { SetAttributeString(cryptHandle, attributeType, value == null ? null : new UTF8Encoding().GetBytes(value), 0, value == null ? 0 : new UTF8Encoding().GetByteCount(value)); }
	
	public static int GetAttribute(
								int cryptHandle, // CRYPT_HANDLE
								int attributeType // CRYPT_ATTRIBUTE_TYPE
								)
	{
		IntPtr valuePtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_GetAttribute(cryptHandle, attributeType, valuePtr));
			return Marshal.ReadInt32(valuePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(valuePtr);
		}
	}
	
	public static int GetAttributeString(
								int cryptHandle, // CRYPT_HANDLE
								int attributeType, // CRYPT_ATTRIBUTE_TYPE
								byte[] value,
								int valueOffset
								)
	{
		IntPtr valueLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle valueHandle = new GCHandle();
		IntPtr valuePtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, valuePtr, valueLengthPtr));
			int valueLength = Marshal.ReadInt32(valueLengthPtr);
			checkIndices(value, valueOffset, valueLength);
			getPointer(value, valueOffset, ref valueHandle, ref valuePtr);
			processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, valuePtr, valueLengthPtr));
			return Marshal.ReadInt32(valueLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(valueLengthPtr);
			releasePointer(valueHandle);
		}
	}
	public static int GetAttributeString(
							int cryptHandle, // CRYPT_HANDLE
							int attributeType, // CRYPT_ATTRIBUTE_TYPE
							byte[] value
							) { return GetAttributeString(cryptHandle, attributeType, value, 0); }
	public static String GetAttributeString(
	                    int cryptHandle, // CRYPT_HANDLE
	                    int attributeType // CRYPT_ATTRIBUTE_TYPE
	                    )
	                    {
	                        int length = GetAttributeString(cryptHandle, attributeType, null);
	                        byte[] bytes = new byte[length];
	                        length = GetAttributeString(cryptHandle, attributeType, bytes);
	                        return new UTF8Encoding().GetString(bytes, 0, length);
	                    }
	
	
	public static void DeleteAttribute(
								int cryptHandle, // CRYPT_HANDLE
								int attributeType // CRYPT_ATTRIBUTE_TYPE
								)
	{
		processStatus(wrapped_DeleteAttribute(cryptHandle, attributeType));
	}
	
	/* Oddball functions: Add random data to the pool, query an encoded signature
	   or key data.  These are due to be replaced once a suitable alternative can
	   be found */
	
	public static void AddRandom(
								byte[] randomData,
								int randomDataOffset,
								int randomDataLength
								)
	{
		GCHandle randomDataHandle = new GCHandle();
		IntPtr randomDataPtr = IntPtr.Zero;
		try
		{
			checkIndices(randomData, randomDataOffset, randomDataLength);
			getPointer(randomData, randomDataOffset, ref randomDataHandle, ref randomDataPtr);
			processStatus(wrapped_AddRandom(randomDataPtr, randomDataLength));
		}
		finally
		{
			releasePointer(randomDataHandle);
		}
	}
	public static void AddRandom(
							byte[] randomData
							) { AddRandom(randomData, 0, randomData == null ? 0 : randomData.Length); }
	public static void AddRandom(
							String randomData
							) { AddRandom(randomData == null ? null : new UTF8Encoding().GetBytes(randomData), 0, randomData == null ? 0 : new UTF8Encoding().GetByteCount(randomData)); }
	public static void AddRandom(
		                    int pollType
		                    )
	{
		processStatus(wrapped_AddRandom(IntPtr.Zero, pollType));
	}
	
	
	public static CRYPT_OBJECT_INFO QueryObject(
								byte[] objectData,
								int objectDataOffset,
								int objectDataLength
								)
	{
		IntPtr cryptObjectInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_OBJECT_INFO)));
		CRYPT_OBJECT_INFO cryptObjectInfo = new CRYPT_OBJECT_INFO();
		GCHandle objectDataHandle = new GCHandle();
		IntPtr objectDataPtr = IntPtr.Zero;
		try
		{
			checkIndices(objectData, objectDataOffset, objectDataLength);
			getPointer(objectData, objectDataOffset, ref objectDataHandle, ref objectDataPtr);
			processStatus(wrapped_QueryObject(objectDataPtr, objectDataLength, cryptObjectInfoPtr));
			Marshal.PtrToStructure(cryptObjectInfoPtr, cryptObjectInfo);
			return cryptObjectInfo;
		}
		finally
		{
			Marshal.FreeHGlobal(cryptObjectInfoPtr);
			releasePointer(objectDataHandle);
		}
	}
	public static CRYPT_OBJECT_INFO QueryObject(
							byte[] objectData
							) { return QueryObject(objectData, 0, objectData == null ? 0 : objectData.Length); }
	public static CRYPT_OBJECT_INFO QueryObject(
							String objectData
							) { return QueryObject(objectData == null ? null : new UTF8Encoding().GetBytes(objectData), 0, objectData == null ? 0 : new UTF8Encoding().GetByteCount(objectData)); }
	
	/****************************************************************************
	*																			*
	*							Mid-level Encryption Functions					*
	*																			*
	****************************************************************************/
	
	/* Export and import an encrypted session key */
	
	public static int ExportKey(
								byte[] encryptedKey,
								int encryptedKeyOffset,
								int encryptedKeyMaxLength,
								int exportKey, // CRYPT_HANDLE
								int sessionKeyContext // CRYPT_CONTEXT
								)
	{
		IntPtr encryptedKeyLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle encryptedKeyHandle = new GCHandle();
		IntPtr encryptedKeyPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportKey(encryptedKeyPtr, encryptedKeyMaxLength, encryptedKeyLengthPtr, exportKey, sessionKeyContext));
			int encryptedKeyLength = Marshal.ReadInt32(encryptedKeyLengthPtr);
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref encryptedKeyHandle, ref encryptedKeyPtr);
			processStatus(wrapped_ExportKey(encryptedKeyPtr, encryptedKeyMaxLength, encryptedKeyLengthPtr, exportKey, sessionKeyContext));
			return Marshal.ReadInt32(encryptedKeyLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(encryptedKeyLengthPtr);
			releasePointer(encryptedKeyHandle);
		}
	}
	public static int ExportKey(
							byte[] encryptedKey,
							int encryptedKeyMaxLength,
							int exportKey, // CRYPT_HANDLE
							int sessionKeyContext // CRYPT_CONTEXT
							) { return ExportKey(encryptedKey, 0, encryptedKeyMaxLength, exportKey, sessionKeyContext); }
	
	public static int ExportKeyEx(
								byte[] encryptedKey,
								int encryptedKeyOffset,
								int encryptedKeyMaxLength,
								int formatType, // CRYPT_FORMAT_TYPE
								int exportKey, // CRYPT_HANDLE
								int sessionKeyContext // CRYPT_CONTEXT
								)
	{
		IntPtr encryptedKeyLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle encryptedKeyHandle = new GCHandle();
		IntPtr encryptedKeyPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportKeyEx(encryptedKeyPtr, encryptedKeyMaxLength, encryptedKeyLengthPtr, formatType, exportKey, sessionKeyContext));
			int encryptedKeyLength = Marshal.ReadInt32(encryptedKeyLengthPtr);
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref encryptedKeyHandle, ref encryptedKeyPtr);
			processStatus(wrapped_ExportKeyEx(encryptedKeyPtr, encryptedKeyMaxLength, encryptedKeyLengthPtr, formatType, exportKey, sessionKeyContext));
			return Marshal.ReadInt32(encryptedKeyLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(encryptedKeyLengthPtr);
			releasePointer(encryptedKeyHandle);
		}
	}
	public static int ExportKeyEx(
							byte[] encryptedKey,
							int encryptedKeyMaxLength,
							int formatType, // CRYPT_FORMAT_TYPE
							int exportKey, // CRYPT_HANDLE
							int sessionKeyContext // CRYPT_CONTEXT
							) { return ExportKeyEx(encryptedKey, 0, encryptedKeyMaxLength, formatType, exportKey, sessionKeyContext); }
	
	public static void ImportKey(
								byte[] encryptedKey,
								int encryptedKeyOffset,
								int encryptedKeyLength,
								int importKey, // CRYPT_CONTEXT
								int sessionKeyContext // CRYPT_CONTEXT
								)
	{
		GCHandle encryptedKeyHandle = new GCHandle();
		IntPtr encryptedKeyPtr = IntPtr.Zero;
		try
		{
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref encryptedKeyHandle, ref encryptedKeyPtr);
			processStatus(wrapped_ImportKey(encryptedKeyPtr, encryptedKeyLength, importKey, sessionKeyContext));
		}
		finally
		{
			releasePointer(encryptedKeyHandle);
		}
	}
	public static void ImportKey(
							byte[] encryptedKey,
							int importKey, // CRYPT_CONTEXT
							int sessionKeyContext // CRYPT_CONTEXT
							) { ImportKey(encryptedKey, 0, encryptedKey == null ? 0 : encryptedKey.Length, importKey, sessionKeyContext); }
	public static void ImportKey(
							String encryptedKey,
							int importKey, // CRYPT_CONTEXT
							int sessionKeyContext // CRYPT_CONTEXT
							) { ImportKey(encryptedKey == null ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, encryptedKey == null ? 0 : new UTF8Encoding().GetByteCount(encryptedKey), importKey, sessionKeyContext); }
	
	public static int ImportKeyEx(
								byte[] encryptedKey,
								int encryptedKeyOffset,
								int encryptedKeyLength,
								int importKey, // CRYPT_CONTEXT
								int sessionKeyContext // CRYPT_CONTEXT
								)
	{
		IntPtr returnedContextPtr = Marshal.AllocHGlobal(4);
		GCHandle encryptedKeyHandle = new GCHandle();
		IntPtr encryptedKeyPtr = IntPtr.Zero;
		try
		{
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref encryptedKeyHandle, ref encryptedKeyPtr);
			processStatus(wrapped_ImportKeyEx(encryptedKeyPtr, encryptedKeyLength, importKey, sessionKeyContext, returnedContextPtr));
			return Marshal.ReadInt32(returnedContextPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(returnedContextPtr);
			releasePointer(encryptedKeyHandle);
		}
	}
	public static int ImportKeyEx(
							byte[] encryptedKey,
							int importKey, // CRYPT_CONTEXT
							int sessionKeyContext // CRYPT_CONTEXT
							) { return ImportKeyEx(encryptedKey, 0, encryptedKey == null ? 0 : encryptedKey.Length, importKey, sessionKeyContext); }
	public static int ImportKeyEx(
							String encryptedKey,
							int importKey, // CRYPT_CONTEXT
							int sessionKeyContext // CRYPT_CONTEXT
							) { return ImportKeyEx(encryptedKey == null ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, encryptedKey == null ? 0 : new UTF8Encoding().GetByteCount(encryptedKey), importKey, sessionKeyContext); }
	
	/* Create and check a digital signature */
	
	public static int CreateSignature(
								byte[] signature,
								int signatureOffset,
								int signatureMaxLength,
								int signContext, // CRYPT_CONTEXT
								int hashContext // CRYPT_CONTEXT
								)
	{
		IntPtr signatureLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle signatureHandle = new GCHandle();
		IntPtr signaturePtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_CreateSignature(signaturePtr, signatureMaxLength, signatureLengthPtr, signContext, hashContext));
			int signatureLength = Marshal.ReadInt32(signatureLengthPtr);
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref signatureHandle, ref signaturePtr);
			processStatus(wrapped_CreateSignature(signaturePtr, signatureMaxLength, signatureLengthPtr, signContext, hashContext));
			return Marshal.ReadInt32(signatureLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(signatureLengthPtr);
			releasePointer(signatureHandle);
		}
	}
	public static int CreateSignature(
							byte[] signature,
							int signatureMaxLength,
							int signContext, // CRYPT_CONTEXT
							int hashContext // CRYPT_CONTEXT
							) { return CreateSignature(signature, 0, signatureMaxLength, signContext, hashContext); }
	
	public static int CreateSignatureEx(
								byte[] signature,
								int signatureOffset,
								int signatureMaxLength,
								int formatType, // CRYPT_FORMAT_TYPE
								int signContext, // CRYPT_CONTEXT
								int hashContext, // CRYPT_CONTEXT
								int extraData // CRYPT_CERTIFICATE
								)
	{
		IntPtr signatureLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle signatureHandle = new GCHandle();
		IntPtr signaturePtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_CreateSignatureEx(signaturePtr, signatureMaxLength, signatureLengthPtr, formatType, signContext, hashContext, extraData));
			int signatureLength = Marshal.ReadInt32(signatureLengthPtr);
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref signatureHandle, ref signaturePtr);
			processStatus(wrapped_CreateSignatureEx(signaturePtr, signatureMaxLength, signatureLengthPtr, formatType, signContext, hashContext, extraData));
			return Marshal.ReadInt32(signatureLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(signatureLengthPtr);
			releasePointer(signatureHandle);
		}
	}
	public static int CreateSignatureEx(
							byte[] signature,
							int signatureMaxLength,
							int formatType, // CRYPT_FORMAT_TYPE
							int signContext, // CRYPT_CONTEXT
							int hashContext, // CRYPT_CONTEXT
							int extraData // CRYPT_CERTIFICATE
							) { return CreateSignatureEx(signature, 0, signatureMaxLength, formatType, signContext, hashContext, extraData); }
	
	public static void CheckSignature(
								byte[] signature,
								int signatureOffset,
								int signatureLength,
								int sigCheckKey, // CRYPT_HANDLE
								int hashContext // CRYPT_CONTEXT
								)
	{
		GCHandle signatureHandle = new GCHandle();
		IntPtr signaturePtr = IntPtr.Zero;
		try
		{
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref signatureHandle, ref signaturePtr);
			processStatus(wrapped_CheckSignature(signaturePtr, signatureLength, sigCheckKey, hashContext));
		}
		finally
		{
			releasePointer(signatureHandle);
		}
	}
	public static void CheckSignature(
							byte[] signature,
							int sigCheckKey, // CRYPT_HANDLE
							int hashContext // CRYPT_CONTEXT
							) { CheckSignature(signature, 0, signature == null ? 0 : signature.Length, sigCheckKey, hashContext); }
	public static void CheckSignature(
							String signature,
							int sigCheckKey, // CRYPT_HANDLE
							int hashContext // CRYPT_CONTEXT
							) { CheckSignature(signature == null ? null : new UTF8Encoding().GetBytes(signature), 0, signature == null ? 0 : new UTF8Encoding().GetByteCount(signature), sigCheckKey, hashContext); }
	
	public static int CheckSignatureEx(
								byte[] signature,
								int signatureOffset,
								int signatureLength,
								int sigCheckKey, // CRYPT_HANDLE
								int hashContext // CRYPT_CONTEXT
								)
	{
		IntPtr extraDataPtr = Marshal.AllocHGlobal(4);
		GCHandle signatureHandle = new GCHandle();
		IntPtr signaturePtr = IntPtr.Zero;
		try
		{
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref signatureHandle, ref signaturePtr);
			processStatus(wrapped_CheckSignatureEx(signaturePtr, signatureLength, sigCheckKey, hashContext, extraDataPtr));
			return Marshal.ReadInt32(extraDataPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(extraDataPtr);
			releasePointer(signatureHandle);
		}
	}
	public static int CheckSignatureEx(
							byte[] signature,
							int sigCheckKey, // CRYPT_HANDLE
							int hashContext // CRYPT_CONTEXT
							) { return CheckSignatureEx(signature, 0, signature == null ? 0 : signature.Length, sigCheckKey, hashContext); }
	public static int CheckSignatureEx(
							String signature,
							int sigCheckKey, // CRYPT_HANDLE
							int hashContext // CRYPT_CONTEXT
							) { return CheckSignatureEx(signature == null ? null : new UTF8Encoding().GetBytes(signature), 0, signature == null ? 0 : new UTF8Encoding().GetByteCount(signature), sigCheckKey, hashContext); }
	
	/****************************************************************************
	*																			*
	*									Keyset Functions						*
	*																			*
	****************************************************************************/
	
	/* Open and close a keyset */
	
	public static int KeysetOpen(
								int cryptUser, // CRYPT_USER
								int keysetType, // CRYPT_KEYSET_TYPE
								String name,
								int options // CRYPT_KEYOPT_TYPE
								)
	{
		IntPtr keysetPtr = Marshal.AllocHGlobal(4);
		GCHandle nameHandle = new GCHandle();
		IntPtr namePtr = IntPtr.Zero;
		byte[] nameArray = new UTF8Encoding().GetBytes(name);
		try
		{
			getPointer(nameArray, 0, ref nameHandle, ref namePtr);
			processStatus(wrapped_KeysetOpen(keysetPtr, cryptUser, keysetType, namePtr, options));
			return Marshal.ReadInt32(keysetPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(keysetPtr);
			releasePointer(nameHandle);
		}
	}
	
	public static void KeysetClose(
								int keyset // CRYPT_KEYSET
								)
	{
		processStatus(wrapped_KeysetClose(keyset));
	}
	
	/* Get a key from a keyset */
	
	public static int GetPublicKey(
								int keyset, // CRYPT_KEYSET
								int keyIDtype, // CRYPT_KEYID_TYPE
								String keyID
								)
	{
		IntPtr cryptContextPtr = Marshal.AllocHGlobal(4);
		GCHandle keyIDHandle = new GCHandle();
		IntPtr keyIDPtr = IntPtr.Zero;
		byte[] keyIDArray = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(keyIDArray, 0, ref keyIDHandle, ref keyIDPtr);
			processStatus(wrapped_GetPublicKey(keyset, cryptContextPtr, keyIDtype, keyIDPtr));
			return Marshal.ReadInt32(cryptContextPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(cryptContextPtr);
			releasePointer(keyIDHandle);
		}
	}
	
	public static int GetPrivateKey(
								int keyset, // CRYPT_KEYSET
								int keyIDtype, // CRYPT_KEYID_TYPE
								String keyID,
								String password
								)
	{
		IntPtr cryptContextPtr = Marshal.AllocHGlobal(4);
		GCHandle keyIDHandle = new GCHandle();
		IntPtr keyIDPtr = IntPtr.Zero;
		byte[] keyIDArray = new UTF8Encoding().GetBytes(keyID);
		GCHandle passwordHandle = new GCHandle();
		IntPtr passwordPtr = IntPtr.Zero;
		byte[] passwordArray = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(keyIDArray, 0, ref keyIDHandle, ref keyIDPtr);
			getPointer(passwordArray, 0, ref passwordHandle, ref passwordPtr);
			processStatus(wrapped_GetPrivateKey(keyset, cryptContextPtr, keyIDtype, keyIDPtr, passwordPtr));
			return Marshal.ReadInt32(cryptContextPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(cryptContextPtr);
			releasePointer(keyIDHandle);
			releasePointer(passwordHandle);
		}
	}
	
	/* Add/delete a key to/from a keyset */
	
	public static void AddPublicKey(
								int keyset, // CRYPT_KEYSET
								int certificate // CRYPT_CERTIFICATE
								)
	{
		processStatus(wrapped_AddPublicKey(keyset, certificate));
	}
	
	public static void AddPrivateKey(
								int keyset, // CRYPT_KEYSET
								int cryptKey, // CRYPT_HANDLE
								String password
								)
	{
		GCHandle passwordHandle = new GCHandle();
		IntPtr passwordPtr = IntPtr.Zero;
		byte[] passwordArray = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(passwordArray, 0, ref passwordHandle, ref passwordPtr);
			processStatus(wrapped_AddPrivateKey(keyset, cryptKey, passwordPtr));
		}
		finally
		{
			releasePointer(passwordHandle);
		}
	}
	
	public static void DeleteKey(
								int keyset, // CRYPT_KEYSET
								int keyIDtype, // CRYPT_KEYID_TYPE
								String keyID
								)
	{
		GCHandle keyIDHandle = new GCHandle();
		IntPtr keyIDPtr = IntPtr.Zero;
		byte[] keyIDArray = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(keyIDArray, 0, ref keyIDHandle, ref keyIDPtr);
			processStatus(wrapped_DeleteKey(keyset, keyIDtype, keyIDPtr));
		}
		finally
		{
			releasePointer(keyIDHandle);
		}
	}
	
	/****************************************************************************
	*																			*
	*								Certificate Functions						*
	*																			*
	****************************************************************************/
	
	/* Create/destroy a certificate */
	
	public static int CreateCert(
								int cryptUser, // CRYPT_USER
								int certType // CRYPT_CERTTYPE_TYPE
								)
	{
		IntPtr certificatePtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateCert(certificatePtr, cryptUser, certType));
			return Marshal.ReadInt32(certificatePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(certificatePtr);
		}
	}
	
	public static void DestroyCert(
								int certificate // CRYPT_CERTIFICATE
								)
	{
		processStatus(wrapped_DestroyCert(certificate));
	}
	
	/* Get/add/delete certificate extensions.  These are direct data insertion 
	   functions whose use is discouraged, so they fix the string at char *
	   rather than C_STR */
	
	public static int GetCertExtension(
								int certificate, // CRYPT_CERTIFICATE
								String oid,
								byte[] extension,
								int extensionOffset,
								int extensionMaxLength
								)
	{
		IntPtr extensionLengthPtr = Marshal.AllocHGlobal(4);
		IntPtr criticalFlagPtr = Marshal.AllocHGlobal(4);
		GCHandle oidHandle = new GCHandle();
		IntPtr oidPtr = IntPtr.Zero;
		byte[] oidArray = new UTF8Encoding().GetBytes(oid);
		GCHandle extensionHandle = new GCHandle();
		IntPtr extensionPtr = IntPtr.Zero;
		try
		{
			getPointer(oidArray, 0, ref oidHandle, ref oidPtr);
			processStatus(wrapped_GetCertExtension(certificate, oidPtr, criticalFlagPtr, extensionPtr, extensionMaxLength, extensionLengthPtr));
			int extensionLength = Marshal.ReadInt32(extensionLengthPtr);
			checkIndices(extension, extensionOffset, extensionLength);
			getPointer(extension, extensionOffset, ref extensionHandle, ref extensionPtr);
			processStatus(wrapped_GetCertExtension(certificate, oidPtr, criticalFlagPtr, extensionPtr, extensionMaxLength, extensionLengthPtr));
			return Marshal.ReadInt32(extensionLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(extensionLengthPtr);
			releasePointer(extensionHandle);
			releasePointer(oidHandle);
		}
	}
	public static int GetCertExtension(
							int certificate, // CRYPT_CERTIFICATE
							String oid,
							byte[] extension,
							int extensionMaxLength
							) { return GetCertExtension(certificate, oid, extension, 0, extensionMaxLength); }
	
	public static void AddCertExtension(
								int certificate, // CRYPT_CERTIFICATE
								String oid,
								int criticalFlag,
								byte[] extension,
								int extensionOffset,
								int extensionLength
								)
	{
		GCHandle oidHandle = new GCHandle();
		IntPtr oidPtr = IntPtr.Zero;
		byte[] oidArray = new UTF8Encoding().GetBytes(oid);
		GCHandle extensionHandle = new GCHandle();
		IntPtr extensionPtr = IntPtr.Zero;
		try
		{
			getPointer(oidArray, 0, ref oidHandle, ref oidPtr);
			checkIndices(extension, extensionOffset, extensionLength);
			getPointer(extension, extensionOffset, ref extensionHandle, ref extensionPtr);
			processStatus(wrapped_AddCertExtension(certificate, oidPtr, criticalFlag, extensionPtr, extensionLength));
		}
		finally
		{
			releasePointer(extensionHandle);
			releasePointer(oidHandle);
		}
	}
	public static void AddCertExtension(
							int certificate, // CRYPT_CERTIFICATE
							String oid,
							int criticalFlag,
							byte[] extension
							) { AddCertExtension(certificate, oid, criticalFlag, extension, 0, extension == null ? 0 : extension.Length); }
	public static void AddCertExtension(
							int certificate, // CRYPT_CERTIFICATE
							String oid,
							int criticalFlag,
							String extension
							) { AddCertExtension(certificate, oid, criticalFlag, extension == null ? null : new UTF8Encoding().GetBytes(extension), 0, extension == null ? 0 : new UTF8Encoding().GetByteCount(extension)); }
	
	public static void DeleteCertExtension(
								int certificate, // CRYPT_CERTIFICATE
								String oid
								)
	{
		GCHandle oidHandle = new GCHandle();
		IntPtr oidPtr = IntPtr.Zero;
		byte[] oidArray = new UTF8Encoding().GetBytes(oid);
		try
		{
			getPointer(oidArray, 0, ref oidHandle, ref oidPtr);
			processStatus(wrapped_DeleteCertExtension(certificate, oidPtr));
		}
		finally
		{
			releasePointer(oidHandle);
		}
	}
	
	/* Sign/sig.check a certificate/certification request */
	
	public static void SignCert(
								int certificate, // CRYPT_CERTIFICATE
								int signContext // CRYPT_CONTEXT
								)
	{
		processStatus(wrapped_SignCert(certificate, signContext));
	}
	
	public static void CheckCert(
								int certificate, // CRYPT_CERTIFICATE
								int sigCheckKey // CRYPT_HANDLE
								)
	{
		processStatus(wrapped_CheckCert(certificate, sigCheckKey));
	}
	
	/* Import/export a certificate/certification request */
	
	public static int ImportCert(
								byte[] certObject,
								int certObjectOffset,
								int certObjectLength,
								int cryptUser // CRYPT_USER
								)
	{
		IntPtr certificatePtr = Marshal.AllocHGlobal(4);
		GCHandle certObjectHandle = new GCHandle();
		IntPtr certObjectPtr = IntPtr.Zero;
		try
		{
			checkIndices(certObject, certObjectOffset, certObjectLength);
			getPointer(certObject, certObjectOffset, ref certObjectHandle, ref certObjectPtr);
			processStatus(wrapped_ImportCert(certObjectPtr, certObjectLength, cryptUser, certificatePtr));
			return Marshal.ReadInt32(certificatePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(certificatePtr);
			releasePointer(certObjectHandle);
		}
	}
	public static int ImportCert(
							byte[] certObject,
							int cryptUser // CRYPT_USER
							) { return ImportCert(certObject, 0, certObject == null ? 0 : certObject.Length, cryptUser); }
	public static int ImportCert(
							String certObject,
							int cryptUser // CRYPT_USER
							) { return ImportCert(certObject == null ? null : new UTF8Encoding().GetBytes(certObject), 0, certObject == null ? 0 : new UTF8Encoding().GetByteCount(certObject), cryptUser); }
	
	public static int ExportCert(
								byte[] certObject,
								int certObjectOffset,
								int certObjectMaxLength,
								int certFormatType, // CRYPT_CERTFORMAT_TYPE
								int certificate // CRYPT_CERTIFICATE
								)
	{
		IntPtr certObjectLengthPtr = Marshal.AllocHGlobal(4);
		GCHandle certObjectHandle = new GCHandle();
		IntPtr certObjectPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportCert(certObjectPtr, certObjectMaxLength, certObjectLengthPtr, certFormatType, certificate));
			int certObjectLength = Marshal.ReadInt32(certObjectLengthPtr);
			checkIndices(certObject, certObjectOffset, certObjectLength);
			getPointer(certObject, certObjectOffset, ref certObjectHandle, ref certObjectPtr);
			processStatus(wrapped_ExportCert(certObjectPtr, certObjectMaxLength, certObjectLengthPtr, certFormatType, certificate));
			return Marshal.ReadInt32(certObjectLengthPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(certObjectLengthPtr);
			releasePointer(certObjectHandle);
		}
	}
	public static int ExportCert(
							byte[] certObject,
							int certObjectMaxLength,
							int certFormatType, // CRYPT_CERTFORMAT_TYPE
							int certificate // CRYPT_CERTIFICATE
							) { return ExportCert(certObject, 0, certObjectMaxLength, certFormatType, certificate); }
	
	/* CA management functions */
	
	public static void CAAddItem(
								int keyset, // CRYPT_KEYSET
								int certificate // CRYPT_CERTIFICATE
								)
	{
		processStatus(wrapped_CAAddItem(keyset, certificate));
	}
	
	public static int CAGetItem(
								int keyset, // CRYPT_KEYSET
								int certType, // CRYPT_CERTTYPE_TYPE
								int keyIDtype, // CRYPT_KEYID_TYPE
								String keyID
								)
	{
		IntPtr certificatePtr = Marshal.AllocHGlobal(4);
		GCHandle keyIDHandle = new GCHandle();
		IntPtr keyIDPtr = IntPtr.Zero;
		byte[] keyIDArray = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(keyIDArray, 0, ref keyIDHandle, ref keyIDPtr);
			processStatus(wrapped_CAGetItem(keyset, certificatePtr, certType, keyIDtype, keyIDPtr));
			return Marshal.ReadInt32(certificatePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(certificatePtr);
			releasePointer(keyIDHandle);
		}
	}
	
	public static void CADeleteItem(
								int keyset, // CRYPT_KEYSET
								int certType, // CRYPT_CERTTYPE_TYPE
								int keyIDtype, // CRYPT_KEYID_TYPE
								String keyID
								)
	{
		GCHandle keyIDHandle = new GCHandle();
		IntPtr keyIDPtr = IntPtr.Zero;
		byte[] keyIDArray = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(keyIDArray, 0, ref keyIDHandle, ref keyIDPtr);
			processStatus(wrapped_CADeleteItem(keyset, certType, keyIDtype, keyIDPtr));
		}
		finally
		{
			releasePointer(keyIDHandle);
		}
	}
	
	public static int CACertManagement(
								int action, // CRYPT_CERTACTION_TYPE
								int keyset, // CRYPT_KEYSET
								int caKey, // CRYPT_CONTEXT
								int certRequest // CRYPT_CERTIFICATE
								)
	{
		IntPtr certificatePtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CACertManagement(certificatePtr, action, keyset, caKey, certRequest));
			return Marshal.ReadInt32(certificatePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(certificatePtr);
		}
	}
	
	/****************************************************************************
	*																			*
	*							Envelope and Session Functions					*
	*																			*
	****************************************************************************/
	
	/* Create/destroy an envelope */
	
	public static int CreateEnvelope(
								int cryptUser, // CRYPT_USER
								int formatType // CRYPT_FORMAT_TYPE
								)
	{
		IntPtr envelopePtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateEnvelope(envelopePtr, cryptUser, formatType));
			return Marshal.ReadInt32(envelopePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(envelopePtr);
		}
	}
	
	public static void DestroyEnvelope(
								int envelope // CRYPT_ENVELOPE
								)
	{
		processStatus(wrapped_DestroyEnvelope(envelope));
	}
	
	/* Create/destroy a session */
	
	public static int CreateSession(
								int cryptUser, // CRYPT_USER
								int formatType // CRYPT_SESSION_TYPE
								)
	{
		IntPtr sessionPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateSession(sessionPtr, cryptUser, formatType));
			return Marshal.ReadInt32(sessionPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(sessionPtr);
		}
	}
	
	public static void DestroySession(
								int session // CRYPT_SESSION
								)
	{
		processStatus(wrapped_DestroySession(session));
	}
	
	/* Add/remove data to/from and envelope or session */
	
	public static int PushData(
								int envelope, // CRYPT_HANDLE
								byte[] buffer,
								int bufferOffset,
								int length
								)
	{
		IntPtr bytesCopiedPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = new GCHandle();
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_PushData(envelope, bufferPtr, length, bytesCopiedPtr));
			return Marshal.ReadInt32(bytesCopiedPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(bytesCopiedPtr);
			releasePointer(bufferHandle);
		}
	}
	public static int PushData(
							int envelope, // CRYPT_HANDLE
							byte[] buffer
							) { return PushData(envelope, buffer, 0, buffer == null ? 0 : buffer.Length); }
	public static int PushData(
							int envelope, // CRYPT_HANDLE
							String buffer
							) { return PushData(envelope, buffer == null ? null : new UTF8Encoding().GetBytes(buffer), 0, buffer == null ? 0 : new UTF8Encoding().GetByteCount(buffer)); }
	
	public static void FlushData(
								int envelope // CRYPT_HANDLE
								)
	{
		processStatus(wrapped_FlushData(envelope));
	}
	
	public static int PopData(
								int envelope, // CRYPT_HANDLE
								byte[] buffer,
								int bufferOffset,
								int length
								)
	{
		IntPtr bytesCopiedPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = new GCHandle();
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			//CryptPopData is a special case that doesn't have the length querying call
			int bytesCopied = 0;
			checkIndices(buffer, bufferOffset, bytesCopied);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_PopData(envelope, bufferPtr, length, bytesCopiedPtr));
			return Marshal.ReadInt32(bytesCopiedPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(bytesCopiedPtr);
			releasePointer(bufferHandle);
		}
	}
	public static int PopData(
							int envelope, // CRYPT_HANDLE
							byte[] buffer,
							int length
							) { return PopData(envelope, buffer, 0, length); }
	
	/****************************************************************************
	*																			*
	*								Device Functions							*
	*																			*
	****************************************************************************/
	
	/* Open and close a device */
	
	public static int DeviceOpen(
								int cryptUser, // CRYPT_USER
								int deviceType, // CRYPT_DEVICE_TYPE
								String name
								)
	{
		IntPtr devicePtr = Marshal.AllocHGlobal(4);
		GCHandle nameHandle = new GCHandle();
		IntPtr namePtr = IntPtr.Zero;
		byte[] nameArray = new UTF8Encoding().GetBytes(name);
		try
		{
			getPointer(nameArray, 0, ref nameHandle, ref namePtr);
			processStatus(wrapped_DeviceOpen(devicePtr, cryptUser, deviceType, namePtr));
			return Marshal.ReadInt32(devicePtr);
		}
		finally
		{
			Marshal.FreeHGlobal(devicePtr);
			releasePointer(nameHandle);
		}
	}
	
	public static void DeviceClose(
								int device // CRYPT_DEVICE
								)
	{
		processStatus(wrapped_DeviceClose(device));
	}
	
	/* Query a devices capabilities */
	
	public static CRYPT_QUERY_INFO DeviceQueryCapability(
								int device, // CRYPT_DEVICE
								int cryptAlgo // CRYPT_ALGO_TYPE
								)
	{
		IntPtr cryptQueryInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
		CRYPT_QUERY_INFO cryptQueryInfo = new CRYPT_QUERY_INFO();
		try
		{
			processStatus(wrapped_DeviceQueryCapability(device, cryptAlgo, cryptQueryInfoPtr));
			Marshal.PtrToStructure(cryptQueryInfoPtr, cryptQueryInfo);
			return cryptQueryInfo;
		}
		finally
		{
			Marshal.FreeHGlobal(cryptQueryInfoPtr);
		}
	}
	
	/* Create an encryption context via the device */
	
	public static int DeviceCreateContext(
								int device, // CRYPT_DEVICE
								int cryptAlgo // CRYPT_ALGO_TYPE
								)
	{
		IntPtr cryptContextPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_DeviceCreateContext(device, cryptContextPtr, cryptAlgo));
			return Marshal.ReadInt32(cryptContextPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(cryptContextPtr);
		}
	}
	
	/****************************************************************************
	*																			*
	*							User Management Functions						*
	*																			*
	****************************************************************************/
	
	/* Log on and off (create/destroy a user object) */
	
	public static int Login(
								String name,
								String password
								)
	{
		IntPtr userPtr = Marshal.AllocHGlobal(4);
		GCHandle nameHandle = new GCHandle();
		IntPtr namePtr = IntPtr.Zero;
		byte[] nameArray = new UTF8Encoding().GetBytes(name);
		GCHandle passwordHandle = new GCHandle();
		IntPtr passwordPtr = IntPtr.Zero;
		byte[] passwordArray = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(nameArray, 0, ref nameHandle, ref namePtr);
			getPointer(passwordArray, 0, ref passwordHandle, ref passwordPtr);
			processStatus(wrapped_Login(userPtr, namePtr, passwordPtr));
			return Marshal.ReadInt32(userPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(userPtr);
			releasePointer(nameHandle);
			releasePointer(passwordHandle);
		}
	}
	
	public static void Logout(
								int user // CRYPT_USER
								)
	{
		processStatus(wrapped_Logout(user));
	}
	
	
		[DllImport("cl32.dll", EntryPoint="cryptInit")]
	private static extern int wrapped_Init();

	[DllImport("cl32.dll", EntryPoint="cryptEnd")]
	private static extern int wrapped_End();

	[DllImport("cl32.dll", EntryPoint="cryptQueryCapability")]
	private static extern int wrapped_QueryCapability(int cryptAlgo, IntPtr cryptQueryInfo);

	[DllImport("cl32.dll", EntryPoint="cryptCreateContext")]
	private static extern int wrapped_CreateContext(IntPtr cryptContext, int cryptUser, int cryptAlgo);

	[DllImport("cl32.dll", EntryPoint="cryptDestroyContext")]
	private static extern int wrapped_DestroyContext(int cryptContext);

	[DllImport("cl32.dll", EntryPoint="cryptDestroyObject")]
	private static extern int wrapped_DestroyObject(int cryptObject);

	[DllImport("cl32.dll", EntryPoint="cryptGenerateKey")]
	private static extern int wrapped_GenerateKey(int cryptContext);

	[DllImport("cl32.dll", EntryPoint="cryptGenerateKeyAsync")]
	private static extern int wrapped_GenerateKeyAsync(int cryptContext);

	[DllImport("cl32.dll", EntryPoint="cryptAsyncQuery")]
	private static extern int wrapped_AsyncQuery(int cryptObject);

	[DllImport("cl32.dll", EntryPoint="cryptAsyncCancel")]
	private static extern int wrapped_AsyncCancel(int cryptObject);

	[DllImport("cl32.dll", EntryPoint="cryptEncrypt")]
	private static extern int wrapped_Encrypt(int cryptContext, IntPtr buffer, int length);

	[DllImport("cl32.dll", EntryPoint="cryptDecrypt")]
	private static extern int wrapped_Decrypt(int cryptContext, IntPtr buffer, int length);

	[DllImport("cl32.dll", EntryPoint="cryptSetAttribute")]
	private static extern int wrapped_SetAttribute(int cryptHandle, int attributeType, int value);

	[DllImport("cl32.dll", EntryPoint="cryptSetAttributeString")]
	private static extern int wrapped_SetAttributeString(int cryptHandle, int attributeType, IntPtr value, int valueLength);

	[DllImport("cl32.dll", EntryPoint="cryptGetAttribute")]
	private static extern int wrapped_GetAttribute(int cryptHandle, int attributeType, IntPtr value);

	[DllImport("cl32.dll", EntryPoint="cryptGetAttributeString")]
	private static extern int wrapped_GetAttributeString(int cryptHandle, int attributeType, IntPtr value, IntPtr valueLength);

	[DllImport("cl32.dll", EntryPoint="cryptDeleteAttribute")]
	private static extern int wrapped_DeleteAttribute(int cryptHandle, int attributeType);

	[DllImport("cl32.dll", EntryPoint="cryptAddRandom")]
	private static extern int wrapped_AddRandom(IntPtr randomData, int randomDataLength);

	[DllImport("cl32.dll", EntryPoint="cryptQueryObject")]
	private static extern int wrapped_QueryObject(IntPtr objectData, int objectDataLength, IntPtr cryptObjectInfo);

	[DllImport("cl32.dll", EntryPoint="cryptExportKey")]
	private static extern int wrapped_ExportKey(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int exportKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint="cryptExportKeyEx")]
	private static extern int wrapped_ExportKeyEx(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int formatType, int exportKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint="cryptImportKey")]
	private static extern int wrapped_ImportKey(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint="cryptImportKeyEx")]
	private static extern int wrapped_ImportKeyEx(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext, IntPtr returnedContext);

	[DllImport("cl32.dll", EntryPoint="cryptCreateSignature")]
	private static extern int wrapped_CreateSignature(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int signContext, int hashContext);

	[DllImport("cl32.dll", EntryPoint="cryptCreateSignatureEx")]
	private static extern int wrapped_CreateSignatureEx(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int formatType, int signContext, int hashContext, int extraData);

	[DllImport("cl32.dll", EntryPoint="cryptCheckSignature")]
	private static extern int wrapped_CheckSignature(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext);

	[DllImport("cl32.dll", EntryPoint="cryptCheckSignatureEx")]
	private static extern int wrapped_CheckSignatureEx(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext, IntPtr extraData);

	[DllImport("cl32.dll", EntryPoint="cryptKeysetOpen")]
	private static extern int wrapped_KeysetOpen(IntPtr keyset, int cryptUser, int keysetType, IntPtr name, int options);

	[DllImport("cl32.dll", EntryPoint="cryptKeysetClose")]
	private static extern int wrapped_KeysetClose(int keyset);

	[DllImport("cl32.dll", EntryPoint="cryptGetPublicKey")]
	private static extern int wrapped_GetPublicKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint="cryptGetPrivateKey")]
	private static extern int wrapped_GetPrivateKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID, IntPtr password);

	[DllImport("cl32.dll", EntryPoint="cryptAddPublicKey")]
	private static extern int wrapped_AddPublicKey(int keyset, int certificate);

	[DllImport("cl32.dll", EntryPoint="cryptAddPrivateKey")]
	private static extern int wrapped_AddPrivateKey(int keyset, int cryptKey, IntPtr password);

	[DllImport("cl32.dll", EntryPoint="cryptDeleteKey")]
	private static extern int wrapped_DeleteKey(int keyset, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint="cryptCreateCert")]
	private static extern int wrapped_CreateCert(IntPtr certificate, int cryptUser, int certType);

	[DllImport("cl32.dll", EntryPoint="cryptDestroyCert")]
	private static extern int wrapped_DestroyCert(int certificate);

	[DllImport("cl32.dll", EntryPoint="cryptGetCertExtension")]
	private static extern int wrapped_GetCertExtension(int certificate, IntPtr oid, IntPtr criticalFlag, IntPtr extension, int extensionMaxLength, IntPtr extensionLength);

	[DllImport("cl32.dll", EntryPoint="cryptAddCertExtension")]
	private static extern int wrapped_AddCertExtension(int certificate, IntPtr oid, int criticalFlag, IntPtr extension, int extensionLength);

	[DllImport("cl32.dll", EntryPoint="cryptDeleteCertExtension")]
	private static extern int wrapped_DeleteCertExtension(int certificate, IntPtr oid);

	[DllImport("cl32.dll", EntryPoint="cryptSignCert")]
	private static extern int wrapped_SignCert(int certificate, int signContext);

	[DllImport("cl32.dll", EntryPoint="cryptCheckCert")]
	private static extern int wrapped_CheckCert(int certificate, int sigCheckKey);

	[DllImport("cl32.dll", EntryPoint="cryptImportCert")]
	private static extern int wrapped_ImportCert(IntPtr certObject, int certObjectLength, int cryptUser, IntPtr certificate);

	[DllImport("cl32.dll", EntryPoint="cryptExportCert")]
	private static extern int wrapped_ExportCert(IntPtr certObject, int certObjectMaxLength, IntPtr certObjectLength, int certFormatType, int certificate);

	[DllImport("cl32.dll", EntryPoint="cryptCAAddItem")]
	private static extern int wrapped_CAAddItem(int keyset, int certificate);

	[DllImport("cl32.dll", EntryPoint="cryptCAGetItem")]
	private static extern int wrapped_CAGetItem(int keyset, IntPtr certificate, int certType, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint="cryptCADeleteItem")]
	private static extern int wrapped_CADeleteItem(int keyset, int certType, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint="cryptCACertManagement")]
	private static extern int wrapped_CACertManagement(IntPtr certificate, int action, int keyset, int caKey, int certRequest);

	[DllImport("cl32.dll", EntryPoint="cryptCreateEnvelope")]
	private static extern int wrapped_CreateEnvelope(IntPtr envelope, int cryptUser, int formatType);

	[DllImport("cl32.dll", EntryPoint="cryptDestroyEnvelope")]
	private static extern int wrapped_DestroyEnvelope(int envelope);

	[DllImport("cl32.dll", EntryPoint="cryptCreateSession")]
	private static extern int wrapped_CreateSession(IntPtr session, int cryptUser, int formatType);

	[DllImport("cl32.dll", EntryPoint="cryptDestroySession")]
	private static extern int wrapped_DestroySession(int session);

	[DllImport("cl32.dll", EntryPoint="cryptPushData")]
	private static extern int wrapped_PushData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);

	[DllImport("cl32.dll", EntryPoint="cryptFlushData")]
	private static extern int wrapped_FlushData(int envelope);

	[DllImport("cl32.dll", EntryPoint="cryptPopData")]
	private static extern int wrapped_PopData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);

	[DllImport("cl32.dll", EntryPoint="cryptDeviceOpen")]
	private static extern int wrapped_DeviceOpen(IntPtr device, int cryptUser, int deviceType, IntPtr name);

	[DllImport("cl32.dll", EntryPoint="cryptDeviceClose")]
	private static extern int wrapped_DeviceClose(int device);

	[DllImport("cl32.dll", EntryPoint="cryptDeviceQueryCapability")]
	private static extern int wrapped_DeviceQueryCapability(int device, int cryptAlgo, IntPtr cryptQueryInfo);

	[DllImport("cl32.dll", EntryPoint="cryptDeviceCreateContext")]
	private static extern int wrapped_DeviceCreateContext(int device, IntPtr cryptContext, int cryptAlgo);

	[DllImport("cl32.dll", EntryPoint="cryptLogin")]
	private static extern int wrapped_Login(IntPtr user, IntPtr name, IntPtr password);

	[DllImport("cl32.dll", EntryPoint="cryptLogout")]
	private static extern int wrapped_Logout(int user);


    /* Helper Functions */

    private static void processStatus(int status)
    {
        if (status < crypt.OK)
            throw new CryptException(status);
    }

    private static void checkIndices(byte[] array, int sequenceOffset, int sequenceLength)
    {
        if (array == null)
        {
            if (sequenceOffset == 0)
                return;
            else
                throw new IndexOutOfRangeException();
        }

        int arrayLength = array.Length;

        if (sequenceOffset < 0 ||
            sequenceOffset >= arrayLength ||
            sequenceOffset + sequenceLength > arrayLength)
            throw new IndexOutOfRangeException();
    }

    private static void getPointer(byte[] buffer, int bufferOffset, ref GCHandle bufferHandle, ref IntPtr bufferPtr)
    {
        if (buffer == null)
            return;
        bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        bufferPtr = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, bufferOffset);
    }

    private static void releasePointer(GCHandle bufferHandle)
    {
        if (bufferHandle.IsAllocated)
            bufferHandle.Free();
    }
}

[StructLayout(LayoutKind.Sequential, Pack=0, CharSet=CharSet.Ansi)]
public class CRYPT_QUERY_INFO
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)]public String algoName;
    public int blockSize;
    public int minKeySize;
    public int keySize;
    public int maxKeySize;

    public CRYPT_QUERY_INFO(){}

    public CRYPT_QUERY_INFO(String newAlgoName, int newBlockSize, int newMinKeySize, int newKeySize, int newMaxKeySize)
    {
        algoName = newAlgoName;
        blockSize = newBlockSize;
        minKeySize = newMinKeySize;
        keySize = newKeySize;
        maxKeySize = newMaxKeySize;
    }
}

[StructLayout(LayoutKind.Sequential, Pack=0, CharSet=CharSet.Ansi)]
public class CRYPT_OBJECT_INFO
{
    public int objectType;
    public int cryptAlgo;
    public int cryptMode;
    public int hashAlgo;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)]public byte[] salt;
    public int saltSize;

    public CRYPT_OBJECT_INFO()
    {
        salt = new byte[64];
        saltSize = 64;
    }

    public CRYPT_OBJECT_INFO(int newObjectType, int newCryptAlgo, int newCryptMode, int newHashAlgo, byte[] newSalt)
    {
        objectType = newObjectType;
        cryptAlgo = newCryptAlgo;
        cryptMode = newCryptMode;
        hashAlgo = newHashAlgo;
    }
}

public class CryptException : ApplicationException
{
    private int m_status;
    private String m_message;
    public int Status { get {return m_status;} }
    public override String Message { get {return m_message;} }

    public CryptException(int status)
    {
        m_status = status;
        String prefix = Convert.ToString(status) + ": ";

        if (m_status == crypt.ERROR_PARAM1) {
            m_message = prefix + "Bad argument, parameter 1";
            return; }
        if (m_status == crypt.ERROR_PARAM2) {
            m_message = prefix + "Bad argument, parameter 2";
            return; }
        if (m_status == crypt.ERROR_PARAM3) {
            m_message = prefix + "Bad argument, parameter 3";
            return; }
        if (m_status == crypt.ERROR_PARAM4) {
            m_message = prefix + "Bad argument, parameter 4";
            return; }
        if (m_status == crypt.ERROR_PARAM5) {
            m_message = prefix + "Bad argument, parameter 5";
            return; }
        if (m_status == crypt.ERROR_PARAM6) {
            m_message = prefix + "Bad argument, parameter 6";
            return; }
        if (m_status == crypt.ERROR_PARAM7) {
            m_message = prefix + "Bad argument, parameter 7";
            return; }
        if (m_status == crypt.ERROR_MEMORY) {
            m_message = prefix + "Out of memory";
            return; }
        if (m_status == crypt.ERROR_NOTINITED) {
            m_message = prefix + "Data has not been initialised";
            return; }
        if (m_status == crypt.ERROR_INITED) {
            m_message = prefix + "Data has already been init'd";
            return; }
        if (m_status == crypt.ERROR_NOSECURE) {
            m_message = prefix + "Opn.not avail.at requested sec.level";
            return; }
        if (m_status == crypt.ERROR_RANDOM) {
            m_message = prefix + "No reliable random data available";
            return; }
        if (m_status == crypt.ERROR_FAILED) {
            m_message = prefix + "Operation failed";
            return; }
        if (m_status == crypt.ERROR_NOTAVAIL) {
            m_message = prefix + "This type of opn.not available";
            return; }
        if (m_status == crypt.ERROR_PERMISSION) {
            m_message = prefix + "No permiss.to perform this operation";
            return; }
        if (m_status == crypt.ERROR_WRONGKEY) {
            m_message = prefix + "Incorrect key used to decrypt data";
            return; }
        if (m_status == crypt.ERROR_INCOMPLETE) {
            m_message = prefix + "Operation incomplete/still in progress";
            return; }
        if (m_status == crypt.ERROR_COMPLETE) {
            m_message = prefix + "Operation complete/can't continue";
            return; }
        if (m_status == crypt.ERROR_TIMEOUT) {
            m_message = prefix + "Operation timed out before completion";
            return; }
        if (m_status == crypt.ERROR_INVALID) {
            m_message = prefix + "Invalid/inconsistent information";
            return; }
        if (m_status == crypt.ERROR_SIGNALLED) {
            m_message = prefix + "Resource destroyed by extnl.event";
            return; }
        if (m_status == crypt.ERROR_OVERFLOW) {
            m_message = prefix + "Resources/space exhausted";
            return; }
        if (m_status == crypt.ERROR_UNDERFLOW) {
            m_message = prefix + "Not enough data available";
            return; }
        if (m_status == crypt.ERROR_BADDATA) {
            m_message = prefix + "Bad/unrecognised data format";
            return; }
        if (m_status == crypt.ERROR_SIGNATURE) {
            m_message = prefix + "Signature/integrity check failed";
            return; }
        if (m_status == crypt.ERROR_OPEN) {
            m_message = prefix + "Cannot open object";
            return; }
        if (m_status == crypt.ERROR_READ) {
            m_message = prefix + "Cannot read item from object";
            return; }
        if (m_status == crypt.ERROR_WRITE) {
            m_message = prefix + "Cannot write item to object";
            return; }
        if (m_status == crypt.ERROR_NOTFOUND) {
            m_message = prefix + "Requested item not found in object";
            return; }
        if (m_status == crypt.ERROR_DUPLICATE) {
            m_message = prefix + "Item already present in object";
            return; }
        if (m_status == crypt.ENVELOPE_RESOURCE) {
            m_message = prefix + "Need resource to proceed";
            return; }
        m_message = prefix + "Unknown Exception ?!?!";
    }
}

}