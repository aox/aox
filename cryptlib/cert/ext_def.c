/****************************************************************************
*																			*
*						Certificate Attribute Definitions					*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The following certificate extensions are currently supported.  If 
   'Enforced' is set to 'Yes', this means that they are constraint extensions
   that are enforced by the cert checking code; if set to '-', they are
   informational extensions for which enforcement doesn't apply; if set to
   'No', they need to be handled by the user (this only applies for
   certificate policies, where the user has to decide whether a given cert
   policy is acceptable or not).  The Yes/No in policyConstraints means that 
   everything except the policy mapping constraint is enforced (because 
   policyMappings itself isn't enforced).

									Enforced
									--------
	authorityInfoAccess				   -
	authorityKeyIdentifier			   -
	basicConstraints				  Yes
	biometricInfo (QualifiedCert)	  -
	certCardRequired (SET)			  -
	certificateIssuer				   -
	certificatePolicies				  Yes
	certificateType (SET)			   -
	challengePassword (SCEP)		   -
	cRLDistributionPoints			   -
	cRLNumber						   -
	cRLReason						   -
	cRLExtReason					   -
	dateOfCertGen (SigG)			   -
	deltaCRLIndicator				   -
	extKeyUsage						  Yes
	freshestCRL						   -
	hashedRootKey (SET)				   -
	holdInstructionCode				   -
	inhibitAnyPolicy				  Yes
	invalidityDate					   -
	issuerAltName					   -
	issuingDistributionPoint		   -
	keyFeatures						   -
	keyUsage						  Yes
	monetaryLimit (SigG)			   -
	nameConstraints					  Yes
	netscape-cert-type				  Yes
	netscape-base-url				   -
	netscape-revocation-url			   -
	netscape-ca-revocation-url		   -
	netscape-cert-renewal-url		   -
	netscape-ca-policy-url			   -
	netscape-ssl-server-name		   -
	netscape-comment				   -
	merchantData (SET)				   -
	ocspAcceptableResponse (OCSP)	  -
	ocspArchiveCutoff (OCSP)		   -
	ocspNoCheck (OCSP)				   -
	ocspNonce (OCSP)				   -
	policyConstraints				 Yes/No
	policyMappings					  No
	privateKeyUsagePeriod			  Yes
	procuration (SigG)				   -
	qcStatements (QualifiedCert)	   -
	restriction (SigG)				   -
	strongExtranet (Thawte)			   -
	subjectAltName					   -
	subjectDirectoryAttributes		   -
	subjectInfoAccess				   -
	subjectKeyIdentifier			   -
	tunneling (SET)					   -

   Some extensions are specified as a SEQUENCE OF thing, to make it possible
   to process these automatically we rewrite them as a SEQUENCE OF
   thingInstance1 OPTIONAL, thingInstance2 OPTIONAL, ... thingInstanceN
   OPTIONAL.  Examples of this are extKeyUsage and the altNames.

   Since some extensions fields are tagged, the fields as encoded differ from
   the fields as defined by the tagging, the following macro is used to turn
   a small integer into a context-specific tag.  By default the tag is
   implicit as per X.509v3, to make it an explicit tag we need to set the
   FL_EXPLICIT flag for the field */

#define CTAG( x )		( x | BER_CONTEXT_SPECIFIC )

/* Extended checking functions */

static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr );
static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr );
static int checkURL( const ATTRIBUTE_LIST *attributeListPtr );
static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr );
static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr );

/* Forward declarations for alternative encoding tables used by the main
   tables.  These are declared in a somewhat peculiar manner because there's
   no clean way in C to forward declare a static array */

#if __GNUC__ > 3
static const ATTRIBUTE_INFO FAR_BSS generalNameInfo[];
static const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[];
static const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[];
#else
extern const ATTRIBUTE_INFO FAR_BSS generalNameInfo[];
extern const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[];
extern const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[];
#endif

/****************************************************************************
*																			*
*						Certificate Extension Definitions					*
*																			*
****************************************************************************/

/* Certificate extensions are encoded using the following table */

static const FAR_BSS ATTRIBUTE_INFO extensionInfo[] = {
	/* challengePassword.  This is here even though it's a CMS attribute 
	   because SCEP stuffs it into PKCS #10 requests:

		OID = 1 2 840 113549 1 9 7 
		PrintableString */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x07" ), CRYPT_CERTINFO_CHALLENGEPASSWORD,
	  MKDESC( "challengePassword" )
	  BER_STRING_PRINTABLE, 0,
	  FL_LEVEL_STANDARD | FL_NOCOPY | FL_VALID_CERTREQ, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },

	/* cRLExtReason:

		OID = 1 3 6 1 4 1 3029 3 1 4
		ENUMERATED */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x04" ), CRYPT_CERTINFO_CRLEXTREASON,
	  MKDESC( "cRLExtReason" )
	  BER_ENUMERATED, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, 0, CRYPT_CRLEXTREASON_LAST, 0, NULL },

	/* keyFeatures:

		OID = 1 3 6 1 4 1 3029 3 1 5
		BITSTRING */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x05" ), CRYPT_CERTINFO_KEYFEATURES,
	  MKDESC( "keyFeatures" )
	  BER_BITSTRING, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_CERTREQ, 0, 7, 0, NULL },

	/* authorityInfoAccess:

		OID = 1 3 6 1 5 5 7 1 1
		SEQUENCE SIZE (1...MAX) OF {
			SEQUENCE {
				accessMethod	OBJECT IDENTIFIER,
				accessLocation	GeneralName
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x01" ), CRYPT_CERTINFO_AUTHORITYINFOACCESS,
	  MKDESC( "authorityInfoAccess" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (rtcs)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x07" ), 0,
	  MKDESC( "authorityInfoAccess.rtcs (1 3 6 1 4 1 3029 3 1 7)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_RTCS,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (rtcs)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (ocsp)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x01" ), 0,
	  MKDESC( "authorityInfoAccess.ocsp (1 3 6 1 5 5 7 48 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_OCSP,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (ocsp)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (caIssuers)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x02" ), 0,
	  MKDESC( "authorityInfoAccess.caIssuers (1 3 6 1 5 5 7 48 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (caIssuers)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (httpCerts)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x06" ), 0,
	  MKDESC( "authorityInfoAccess.httpCerts (1 3 6 1 5 5 7 48 6)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE, 
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (httpCerts)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (httpCRLs)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x07" ), 0,
	  MKDESC( "authorityInfoAccess.httpCRLs (1 3 6 1 5 5 7 48 7)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CRLS, 
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (httpCRLs)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (catchAll)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.catchAll" )
	  FIELDTYPE_BLOB, 0,		/* Match anything and ignore it */
	  FL_OPTIONAL | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },

	/* biometricInfo

		OID = 1 3 6 1 5 5 7 1 2
		SEQUENCE OF {
			SEQUENCE {
				typeOfData		INTEGER,
				hashAlgorithm	OBJECT IDENTIFIER,
				dataHash		OCTET STRING,
				sourceDataUri	IA5String OPTIONAL
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x02" ), CRYPT_CERTINFO_BIOMETRICINFO, 
	  MKDESC( "biometricInfo" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "biometricInfo.biometricData" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_TYPE, 
	  MKDESC( "biometricInfo.biometricData.typeOfData" )
	  BER_INTEGER, 0,
	  FL_MORE | FL_MULTIVALUED, 0, 1, 0, NULL },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO, 
	  MKDESC( "biometricInfo.biometricData.hashAlgorithm" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_HASH, 
	  MKDESC( "biometricInfo.biometricData.dataHash" )
	  BER_OCTETSTRING, 0,
	  FL_MORE | FL_MULTIVALUED, 16, CRYPT_MAX_HASHSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_URL, 
	  MKDESC( "biometricInfo.biometricData.sourceDataUri" )
	  BER_STRING_IA5, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkURL },

	/* qcStatements

		OID = 1 3 6 1 5 5 7 1 3
		critical = TRUE
		SEQUENCE OF {
			SEQUENCE {
				statementID		OBJECT IDENTIFIER,
				statementInfo	SEQUENCE {
					semanticsIdentifier	OBJECT IDENTIFIER OPTIONAL,
					nameRegistrationAuthorities SEQUENCE OF GeneralName
				}
			}
		There are two versions of the statementID OID, one for RFC 3039 and 
		the other for RFC 3739 (which are actually identical except where 
		they're not).  To handle this we preferentially encode the RFC 3739 
		(v2) OID, but allow the v1 OID as a fallback by marking both as 
		optional */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x03" ), CRYPT_CERTINFO_QCSTATEMENT,
	  MKDESC( "qcStatements" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_CRITICAL | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement (statementID)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0B\x02" ), 0,
	  MKDESC( "qcStatements.qcStatement.statementID (1 3 6 1 5 5 7 11 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0B\x01" ), 0,
	  MKDESC( "qcStatements.qcStatement.statementID (Backwards-compat.) (1 3 6 1 5 5 7 11 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement.statementInfo (statementID)" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS, 
	  MKDESC( "qcStatements.qcStatement.statementInfo.semanticsIdentifier (statementID)" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement.statementInfo.nameRegistrationAuthorities (statementID)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY, 
	  MKDESC( "qcStatements.qcStatement.statementInfo.nameRegistrationAuthorities.generalNames" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED | FL_SEQEND_3, 0, 0, 0, ( void * ) generalNameInfo },

	/* subjectInfoAccess:

		OID = 1 3 6 1 5 5 7 1 11
		SEQUENCE SIZE (1...MAX) OF {
			SEQUENCE {
				accessMethod	OBJECT IDENTIFIER,
				accessLocation	GeneralName
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x0B" ), CRYPT_CERTINFO_SUBJECTINFOACCESS,
	  MKDESC( "subjectInfoAccess" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (timeStamping)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x03" ), 0,
	  MKDESC( "subjectInfoAccess.timeStamping (1 3 6 1 5 5 7 48 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
	  MKDESC( "subjectInfoAccess.accessDescription.accessLocation (timeStamping)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (caRepository)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x05" ), 0,
	  MKDESC( "subjectInfoAccess.caRepository (1 3 6 1 5 5 7 48 5)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
	  MKDESC( "subjectInfoAccess.accessDescription.accessLocation (timeStamping)" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (catchAll)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.catchAll" )
	  FIELDTYPE_BLOB, 0,		/* Match anything and ignore it */
	  FL_OPTIONAL | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },

	/* ocspNonce:

		OID = 1 3 6 1 5 5 7 48 1 2
		nonce		INTEGER

	   This value was supposed to be an INTEGER, however alongside a million 
	   other pieces of braindamage OCSP forgot to actually define this 
	   anywhere in the spec.  Because of this it's possible to get other 
	   stuff here as well, the worst-case being OpenSSL 0.9.6/0.9.7a-c which 
	   just dump a raw blob (not any valid ASN.1 data) in here.  We can't do 
	   anything with this since we need at least something DER-encoded to be 
	   able to read it.  OpenSSL 0.9.7d and later used an OCTET STRING, so we
	   use the same trick as we do for the certPolicy IA5String/VisibleString
	   duality where we define the field as if it were a CHOICE { INTEGER,
	   OCTET STRING }, with the INTEGER first to make sure that we encode that
	   preferentially.  In addition although the nonce should be an INTEGER 
	   data value, it's really an INTEGER equivalent of an OCTET STRING hole 
	   so we call it an octet string to make sure that it gets handled 
	   appropriately */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x02" ), CRYPT_CERTINFO_OCSP_NONCE,
	  MKDESC( "ocspNonce" )
	  BER_OCTETSTRING, BER_INTEGER,	/* Actually an INTEGER hole */
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_OCSPREQ | FL_VALID_OCSPRESP | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_OCSP_NONCE,
	  MKDESC( "ocspNonce (Kludge)" )
	  BER_OCTETSTRING, 0,
	  FL_OPTIONAL, 1, 64, 0, NULL },

	/* ocspAcceptableResponses:

		OID = 1 3 6 1 5 5 7 48 1 4
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x04" ), CRYPT_CERTINFO_OCSP_RESPONSE,
	  MKDESC( "ocspAcceptableResponses" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" ), CRYPT_CERTINFO_OCSP_RESPONSE_OCSP,
	  MKDESC( "ocspAcceptableResponses.ocsp (1 3 6 1 5 5 7 48 1 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* ocspNoCheck:
		OID = 1 3 6 1 5 5 7 48 1 5
		critical = FALSE
		NULL
	   This value is treated as a pseudo-numeric value that must be 
	   CRYPT_UNUSED when written and is explicitly set to CRYPT_UNUSED when 
	   read */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x05" ), CRYPT_CERTINFO_OCSP_NOCHECK,
	  MKDESC( "ocspNoCheck" )
	  BER_NULL, 0,
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_VALID_CERTREQ | FL_NONENCODING, CRYPT_UNUSED, CRYPT_UNUSED, 0, NULL },

	/* ocspArchiveCutoff:
		OID = 1 3 6 1 5 5 7 48 1 6
		archiveCutoff	GeneralizedTime */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x06" ), CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF,
	  MKDESC( "ocspArchiveCutoff" )
	  BER_TIME_GENERALIZED, 0,
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_OCSPRESP, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* dateOfCertGen
		OID = 1 3 36 8 3 1
		dateOfCertGen	GeneralizedTime */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x01" ), CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,
	  MKDESC( "dateOfCertGen" )
	  BER_TIME_GENERALIZED, 0,
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* procuration
		OID = 1 3 36 8 3 2
		SEQUENCE OF {
			country					PrintableString SIZE(2) OPTIONAL,
			typeOfSubstitution  [0]	PrintableString OPTIONAL,
			signingFor				GeneralName
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x02" ), CRYPT_CERTINFO_SIGG_PROCURATION,
	  MKDESC( "procuration" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,
	  MKDESC( "procuration.country" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 2, 2, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,
	  MKDESC( "procuration.typeOfSubstitution" )
	  BER_STRING_PRINTABLE, CTAG( 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 128, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,
	  MKDESC( "procuration.signingFor.thirdPerson" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED, 0, 0, 0, ( void * ) generalNameInfo },

	/* monetaryLimit
		OID = 1 3 36 8 3 4
		SEQUENCE {
			currency	PrintableString SIZE(3),
			amount		INTEGER,
			exponent	INTEGER
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x04" ), CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
	  MKDESC( "monetaryLimit" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,
	  MKDESC( "monetaryLimit.currency" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE, 3, 3, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,
	  MKDESC( "monetaryLimit.amount" )
	  BER_INTEGER, 0,
	  FL_MORE, 1, 255, 0, NULL },	/* That's what the spec says */
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,
	  MKDESC( "monetaryLimit.exponent" )
	  BER_INTEGER, 0,
	  0, 0, 255, 0, NULL },

	/* restriction
		OID = 1 3 36 8 3 8
		restriction		PrintableString */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x08" ), CRYPT_CERTINFO_SIGG_RESTRICTION,
	  MKDESC( "restriction" )
	  BER_STRING_PRINTABLE, 0,
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, 1, 128, 0, NULL },

	/* strongExtranet:
		OID = 1 3 101 1 4 1
		SEQUENCE {
			version		INTEGER (0),
			SEQUENCE OF {
				SEQUENCE {
					zone	INTEGER,
					id		OCTET STRING (SIZE(1..64))
					}
				}
			} */
	{ MKOID( "\x06\x05\x2B\x65\x01\x04\x01" ), CRYPT_CERTINFO_STRONGEXTRANET,
	  MKDESC( "strongExtranet" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "strongExtranet.version" )
	  FIELDTYPE_BLOB, 0,				/* Always 0 */
	  FL_MORE | FL_NONENCODING, 0, 0, 3, "\x02\x01\x00" },
	{ NULL, 0,
	  MKDESC( "strongExtranet.sxNetIDList" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "strongExtranet.sxNetIDList.sxNetID" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ZONE,
	  MKDESC( "strongExtranet.sxNetIDList.sxNetID.zone" )
	  BER_INTEGER, 0,
	  FL_MORE, 0, INT_MAX, 0, NULL },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ID,
	  MKDESC( "strongExtranet.sxNetIDList.sxnetID.id" )
	  BER_OCTETSTRING, 0,
	  FL_SEQEND_2, 1, 64, 0, NULL },

	/* subjectDirectoryAttributes:
		OID = 2 5 29 9
		SEQUENCE SIZE (1..MAX) OF {
			SEQUENCE {
				type	OBJECT IDENTIFIER,
				values	SET OF ANY					-- SIZE (1)
				} */
	{ MKOID( "\x06\x03\x55\x1D\x09" ), CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
	  MKDESC( "subjectDirectoryAttributes" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "subjectDirectoryAttributes.attribute" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_TYPE,
	  MKDESC( "subjectDirectoryAttributes.attribute.type" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED, 3, 32, 0, NULL },
	{ NULL, 0,
	  MKDESC( "subjectDirectoryAttributes.attribute.values" )
	  BER_SET, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_VALUES,
	  MKDESC( "subjectDirectoryAttributes.attribute.values.value" )
	  FIELDTYPE_BLOB, 0,
	  FL_MULTIVALUED | FL_SEQEND, 1, 1024, 0, NULL },

	/* subjectKeyIdentifier:
		OID = 2 5 29 14
		OCTET STRING */
	{ MKOID( "\x06\x03\x55\x1D\x0E" ), CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
	  MKDESC( "subjectKeyIdentifier" )
	  BER_OCTETSTRING, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, 1, 64, 0, NULL },

	/* keyUsage:
		OID = 2 5 29 15
		critical = TRUE
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x0F" ), CRYPT_CERTINFO_KEYUSAGE,
	  MKDESC( "keyUsage" )
	  BER_BITSTRING, 0,
	  FL_CRITICAL | FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT, 0, CRYPT_KEYUSAGE_LAST, 0, NULL },

	/* privateKeyUsagePeriod:
		OID = 2 5 29 16
		SEQUENCE {
			notBefore	  [ 0 ]	GeneralizedTime OPTIONAL,
			notAfter	  [ 1 ]	GeneralizedTime OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x10" ), CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
	  MKDESC( "privateKeyUsagePeriod" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
	  MKDESC( "privateKeyUsagePeriod.notBefore" )
	  BER_TIME_GENERALIZED, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, sizeof( time_t ), sizeof( time_t ), 0, NULL },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
	  MKDESC( "privateKeyUsagePeriod.notAfter" )
	  BER_TIME_GENERALIZED, CTAG( 1 ),
	  FL_OPTIONAL, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* subjectAltName:
		OID = 2 5 29 17
		SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x11" ), FIELDID_FOLLOWS,
	  MKDESC( "subjectAltName" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTALTNAME,
	  MKDESC( "subjectAltName.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED, 0, 0, 0, ( void * ) generalNameInfo },

	/* issuerAltName:
		OID = 2 5 29 18
		SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x12" ), FIELDID_FOLLOWS,
	  MKDESC( "issuerAltName" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_CRL | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUERALTNAME,
	  MKDESC( "issuerAltName.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED, 0, 0, 0, ( void * ) generalNameInfo },

	/* basicConstraints:
		OID = 2 5 29 19
		critical = TRUE
		SEQUENCE {
			cA					BOOLEAN DEFAULT FALSE,
			pathLenConstraint	INTEGER (0..64) OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x13" ), CRYPT_CERTINFO_BASICCONSTRAINTS,
	  MKDESC( "basicConstraints" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT | FL_VALID_ATTRCERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CA,
	  MKDESC( "basicConstraints.cA" )
	  BER_BOOLEAN, 0,
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_PATHLENCONSTRAINT,
	  MKDESC( "basicConstraints.pathLenConstraint" )
	  BER_INTEGER, 0,
	  FL_OPTIONAL, 0, 64, 0, NULL },

	/* cRLNumber:
		OID = 2 5 29 20
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x14" ), CRYPT_CERTINFO_CRLNUMBER,
	  MKDESC( "cRLNumber" )
	  BER_INTEGER, 0,
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, 0, INT_MAX, 0, NULL },

	/* cRLReason:
		OID = 2 5 29 21
		ENUMERATED */
	{ MKOID( "\x06\x03\x55\x1D\x15" ), CRYPT_CERTINFO_CRLREASON,
	  MKDESC( "cRLReason" )
	  BER_ENUMERATED, 0,
	  FL_LEVEL_REDUCED | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, 0, CRYPT_CRLREASON_LAST, 0, NULL },

	/* holdInstructionCode:
		OID = 2 5 29 23
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x03\x55\x1D\x17" ), CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
	  MKDESC( "holdInstructionCode" )
	  FIELDTYPE_CHOICE, 0,
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, CRYPT_HOLDINSTRUCTION_NONE, CRYPT_HOLDINSTRUCTION_LAST, 0, ( void * ) holdInstructionInfo },

	/* invalidityDate:
		OID = 2 5 29 24
		GeneralizedTime */
	{ MKOID( "\x06\x03\x55\x1D\x18" ), CRYPT_CERTINFO_INVALIDITYDATE,
	  MKDESC( "invalidityDate" )
	  BER_TIME_GENERALIZED, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* deltaCRLIndicator:
		OID = 2 5 29 27
		critical = TRUE
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x1B" ), CRYPT_CERTINFO_DELTACRLINDICATOR,
	  MKDESC( "deltaCRLIndicator" )
	  BER_INTEGER, 0,
	  FL_CRITICAL | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, 0, INT_MAX, 0, NULL },

	/* issuingDistributionPoint:
		OID = 2 5 29 28
		critical = TRUE
		SEQUENCE {
			distributionPoint [ 0 ]	{
				fullName	  [ 0 ]	{				-- CHOICE { ... }
					SEQUENCE OF GeneralName			-- GeneralNames
					}
				} OPTIONAL,
			onlyContainsUserCerts
							  [ 1 ]	BOOLEAN DEFAULT FALSE,
			onlyContainsCACerts
							  [ 2 ]	BOOLEAN DEFAULT FALSE,
			onlySomeReasons	  [ 3 ]	BITSTRING OPTIONAL,
			indirectCRL		  [ 4 ]	BOOLEAN DEFAULT FALSE
		} */
	{ MKOID( "\x06\x03\x55\x1D\x1C" ), CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
	  MKDESC( "issuingDistributionPoint" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName.generalNames" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName.generalNames.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_3, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,
	  MKDESC( "issuingDistributionPoint.onlyContainsUserCerts" )
	  BER_BOOLEAN, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,
	  MKDESC( "issuingDistributionPoint.onlyContainsCACerts" )
	  BER_BOOLEAN, CTAG( 2 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,
	  MKDESC( "issuingDistributionPoint.onlySomeReasons" )
	  BER_BITSTRING, CTAG( 3 ),
	  FL_MORE | FL_OPTIONAL, 0, CRYPT_CRLREASONFLAG_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,
	  MKDESC( "issuingDistributionPoint.indirectCRL" )
	  BER_BOOLEAN, CTAG( 4 ),
	  FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },

	/* certificateIssuer:
		OID = 2 5 29 29
		critical = TRUE
		certificateIssuer SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x1D" ), FIELDID_FOLLOWS,
	  MKDESC( "certificateIssuer" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTIFICATEISSUER,
	  MKDESC( "certificateIssuer.generalNames" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED, 0, 0, 0, ( void * ) generalNameInfo },

	/* nameConstraints
		OID = 2 5 29 30
		critical = TRUE
		SEQUENCE {
			permittedSubtrees [ 0 ]	SEQUENCE OF {
				SEQUENCE { GeneralName }
				} OPTIONAL,
			excludedSubtrees  [ 1 ]	SEQUENCE OF {
				SEQUENCE { GeneralName }
				} OPTIONAL,
			}

		RFC 3280 extended this by adding two additional fields after the 
		GeneralName (probably from X.509v4), but mitigated it by requiring
		that they never be used, so we leave the definition as is */
	{ MKOID( "\x06\x03\x55\x1D\x1E" ), CRYPT_CERTINFO_NAMECONSTRAINTS,
	  MKDESC( "nameConstraints" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_ATTRCERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "nameConstraints.permittedSubtrees" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "nameConstraints.permittedSubtrees.sequenceOf" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_PERMITTEDSUBTREES,
	  MKDESC( "nameConstraints.permittedSubtrees.sequenceOf.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "nameConstraints.excludedSubtrees" )
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "nameConstraints.excludedSubtrees.sequenceOf" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EXCLUDEDSUBTREES,
	  MKDESC( "nameConstraints.excludedSubtrees.sequenceOf.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* cRLDistributionPoints:
		OID = 2 5 29 31
		SEQUENCE OF {
			SEQUENCE {
				distributionPoint
							  [ 0 ]	{				-- CHOICE { ... }
					fullName  [ 0 ]	SEQUENCE OF GeneralName
					} OPTIONAL,
				reasons		  [ 1 ]	BIT STRING OPTIONAL,
				cRLIssuer	  [ 2 ]	SEQUENCE OF GeneralName OPTIONAL
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x1F" ), CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
	  MKDESC( "cRLDistributionPoints" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_ATTRCERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distributionPoint" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distributionPoint.distributionPoint" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distributionPoint.distributionPoint.fullName" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CRLDIST_FULLNAME,
	  MKDESC( "cRLDistributionPoints.distributionPoint.distributionPoint.fullName.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_CRLDIST_REASONS,
	  MKDESC( "cRLDistributionPoints.distributionPoint.reasons" )
	  BER_BITSTRING, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED, 0, CRYPT_CRLREASONFLAG_LAST, 0, NULL },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distributionPoint.cRLIssuer" )
	  BER_SEQUENCE, CTAG( 2 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CRLDIST_CRLISSUER,
	  MKDESC( "cRLDistributionPoints.distributionPoint.cRLIssuer.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* certificatePolicies:
		OID = 2 5 29 32
		SEQUENCE SIZE (1..64) OF {
			SEQUENCE {
				policyIdentifier	OBJECT IDENTIFIER,
				policyQualifiers	SEQUENCE SIZE (1..64) OF {
									SEQUENCE {
					policyQualifierId
									OBJECT IDENTIFIER,
					qualifier		ANY DEFINED BY policyQualifierID
						} OPTIONAL
					}
				}
			}

		CPSuri ::= IA5String						-- OID = cps

		UserNotice ::= SEQUENCE {					-- OID = unotice
			noticeRef		SEQUENCE {
				organization	VisibleString,
				noticeNumbers	SEQUENCE OF INTEGER	-- SIZE (1)
				} OPTIONAL,
			explicitText	VisibleString OPTIONAL
			}
	   All draft versions of the PKIX profile (RFC 2459) had the 
	   organisation as an IA5String, but the final RFC changed it to a 
	   VisibleString, in order to kludge around this for the certs that use 
	   an IA5String (which in practice means only Verisign, since no-one 
	   else uses policy qualifiers), we allow both types but put the 
	   VisibleString option first which means that it'll get used 
	   preferentially when encoding */
	{ MKOID( "\x06\x03\x55\x1D\x20" ), CRYPT_CERTINFO_CERTIFICATEPOLICIES,
	  MKDESC( "certificatePolicies" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICYID,
	  MKDESC( "certificatePolicies.policyInformation.policyIdentifier" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED, 3, 32, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x01" ), 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifier.cps (1 3 6 1 5 5 7 2 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_CPSURI,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.qualifier.cPSuri" )
	  BER_STRING_IA5, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkURL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x02" ), 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifier.unotice (1 3 6 1 5 5 7 2 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifier.userNotice" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.noticeRef" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.noticeRef.organization" )
	  BER_STRING_ISO646, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,	/* Backwards-compat.kludge */
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.noticeRef.organization (Kludge)" )
	  BER_STRING_IA5, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, 0,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.noticeRef.noticeNumbers" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.noticeRef.noticeNumbers" )
	  BER_INTEGER, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, 1, 1024, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
	  MKDESC( "certificatePolicies.policyInformation.policyQualifiers.userNotice.explicitText" )
	  BER_STRING_ISO646, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 1, 200, 0, NULL },

	/* policyMappings:
		OID = 2 5 29 33
		SEQUENCE SIZE (1..MAX) OF {
			SEQUENCE {
				issuerDomainPolicy	OBJECT IDENTIFIER,
				subjectDomainPolicy	OBJECT IDENTIFIER
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x21" ), CRYPT_CERTINFO_POLICYMAPPINGS,
	  MKDESC( "policyMappings" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "policyMappings.sequenceOf" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUERDOMAINPOLICY,
	  MKDESC( "policyMappings.sequenceOf.issuerDomainPolicy" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,
	  MKDESC( "policyMappings.sequenceOf.subjectDomainPolicy" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MULTIVALUED | FL_SEQEND_3, 3, 32, 0, NULL },

	/* authorityKeyIdentifier:
		OID = 2 5 29 35
		SEQUENCE {
			keyIdentifier [ 0 ]	OCTET STRING OPTIONAL,
			authorityCertIssuer						-- Neither or both
						  [ 1 ] SEQUENCE OF GeneralName OPTIONAL
			authorityCertSerialNumber				-- of these must
						  [ 2 ] INTEGER OPTIONAL	-- be present
			}
	   Although the serialNumber should be an integer, it's really an
	   integer equivalent of an octet string hole so we call it an octet
	   string to make sure it gets handled appropriately */
	{ MKOID( "\x06\x03\x55\x1D\x23" ), CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
	  MKDESC( "authorityKeyIdentifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
	  MKDESC( "authorityKeyIdentifier.keyIdentifier" )
	  BER_OCTETSTRING, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, 0,
	  MKDESC( "authorityKeyIdentifier.authorityCertIssuer" )
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTISSUER,
	  MKDESC( "authorityKeyIdentifier.authorityCertIssuer.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,
	  MKDESC( "authorityKeyIdentifier.authorityCertSerialNumber" )
	  BER_OCTETSTRING, CTAG( 2 ),	/* Actually an INTEGER hole */
	  FL_OPTIONAL, 1, 64, 0, NULL },

	/* policyConstraints:
		OID = 2 5 29 36
		SEQUENCE {
			requireExplicitPolicy [ 0 ]	INTEGER OPTIONAL,
			inhibitPolicyMapping  [ 1 ]	INTEGER OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x24" ), CRYPT_CERTINFO_POLICYCONSTRAINTS,
	  MKDESC( "policyConstraints" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
	  MKDESC( "policyConstraints.requireExplicitPolicy" )
	  BER_INTEGER, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_INHIBITPOLICYMAPPING,
	  MKDESC( "policyConstraints.inhibitPolicyMapping" )
	  BER_INTEGER, CTAG( 1 ),
	  FL_OPTIONAL, 0, 64, 0, NULL },

	/* extKeyUsage:
		OID = 2 5 29 37
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x25" ), CRYPT_CERTINFO_EXTKEYUSAGE,
	  MKDESC( "extKeyUsage" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,
	  MKDESC( "extKeyUsage.individualCodeSigning (1 3 6 1 4 1 311 2 1 21)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,
	  MKDESC( "extKeyUsage.commercialCodeSigning (1 3 6 1 4 1 311 2 1 22)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x01" ), CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
	  MKDESC( "extKeyUsage.certTrustListSigning (1 3 6 1 4 1 311 10 3 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x02" ), CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,
	  MKDESC( "extKeyUsage.timeStampSigning (1 3 6 1 4 1 311 10 3 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x03" ), CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,
	  MKDESC( "extKeyUsage.serverGatedCrypto (1 3 6 1 4 1 311 10 3 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x04" ), CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,
	  MKDESC( "extKeyUsage.encrypedFileSystem (1 3 6 1 4 1 311 10 3 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x01" ), CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
	  MKDESC( "extKeyUsage.serverAuth (1 3 6 1 5 5 7 3 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x02" ), CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
	  MKDESC( "extKeyUsage.clientAuth (1 3 6 1 5 5 7 3 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x03" ), CRYPT_CERTINFO_EXTKEY_CODESIGNING,
	  MKDESC( "extKeyUsage.codeSigning (1 3 6 1 5 5 7 3 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x04" ), CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
	  MKDESC( "extKeyUsage.emailProtection (1 3 6 1 5 5 7 3 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x05" ), CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,
	  MKDESC( "extKeyUsage.ipsecEndSystem (1 3 6 1 5 5 7 3 5)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x06" ), CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,
	  MKDESC( "extKeyUsage.ipsecTunnel (1 3 6 1 5 5 7 3 6)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x07" ), CRYPT_CERTINFO_EXTKEY_IPSECUSER,
	  MKDESC( "extKeyUsage.ipsecUser (1 3 6 1 5 5 7 3 7)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x08" ), CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
	  MKDESC( "extKeyUsage.timeStamping (1 3 6 1 5 5 7 3 8)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x09" ), CRYPT_CERTINFO_EXTKEY_OCSPSIGNING,
	  MKDESC( "extKeyUsage.ocspSigning (1 3 6 1 5 5 7 3 9)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x05\x2B\x24\x08\x02\x01" ), CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,
	  MKDESC( "extKeyUsage.directoryService (1 3 36 8 2 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x04\x55\x1D\x25\x00" ), CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE,
	  MKDESC( "extKeyUsage.anyExtendedKeyUsage(2 5 29 37 0)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x04\x01" ), CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,
	  MKDESC( "extKeyUsage.serverGatedCrypto (2 16 840 1 113730 4 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x08\x01" ), CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
	  MKDESC( "extKeyUsage.serverGatedCryptoCA (2 16 840 1 113733 1 8 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* freshestCRL:
		OID = 2 5 29 46
		SEQUENCE OF {
			SEQUENCE {
				distributionPoint
							  [ 0 ]	{				-- CHOICE { ... }
					fullName  [ 0 ]	SEQUENCE OF GeneralName
					} OPTIONAL,
				reasons		  [ 1 ]	BIT STRING OPTIONAL,
				cRLIssuer	  [ 2 ]	SEQUENCE OF GeneralName OPTIONAL
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x2E" ), CRYPT_CERTINFO_FRESHESTCRL,
	  MKDESC( "freshestCRL" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_ATTRCERT | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint.fullName" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_FULLNAME,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint.fullName.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_REASONS,
	  MKDESC( "freshestCRL.distributionPoint.reasons" )
	  BER_BITSTRING, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED, 0, CRYPT_CRLREASONFLAG_LAST, 0, NULL },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.cRLIssuer" )
	  BER_SEQUENCE, CTAG( 2 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER,
	  MKDESC( "freshestCRL.distributionPoint.cRLIssuer.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* inhibitAnyPolicy:
		OID = 2 5 29 54
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x36" ), CRYPT_CERTINFO_INHIBITANYPOLICY,
	  MKDESC( "inhibitAnyPolicy" )
	  BER_INTEGER, 0,
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 64, 0, NULL },

	/* netscape-cert-type:
		OID = 2 16 840 1 113730 1 1
		BITSTRING */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x01" ), CRYPT_CERTINFO_NS_CERTTYPE,
	  MKDESC( "netscape-cert-type" )
	  BER_BITSTRING, 0,
	  FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT, 0, CRYPT_NS_CERTTYPE_LAST, 0, NULL },

	/* netscape-base-url:
		OID = 2 16 840 1 113730 1 2
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x02" ), CRYPT_CERTINFO_NS_BASEURL,
	  MKDESC( "netscape-base-url" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x03" ), CRYPT_CERTINFO_NS_REVOCATIONURL,
	  MKDESC( "netscape-revocation-url" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ca-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x04" ), CRYPT_CERTINFO_NS_CAREVOCATIONURL,
	  MKDESC( "netscape-ca-revocation-url" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ca-revocation-url:
		OID = 2 16 840 1 113730 11 7
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x07" ), CRYPT_CERTINFO_NS_CERTRENEWALURL,
	  MKDESC( "netscape-ca-revocation-url" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ca-policy-url:
		OID = 2 16 840 1 113730 1 8
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x08" ), CRYPT_CERTINFO_NS_CAPOLICYURL,
	  MKDESC( "netscape-ca-policy-url" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ssl-server-name:
		OID = 2 16 840 1 113730 1 12
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0C" ), CRYPT_CERTINFO_NS_SSLSERVERNAME,
	  MKDESC( "netscape-ssl-server-name" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkDNS },

	/* netscape-comment:
		OID = 2 16 840 1 113730 1 13
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0D" ), CRYPT_CERTINFO_NS_COMMENT,
	  MKDESC( "netscape-comment" )
	  BER_STRING_IA5, 0,
	  FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, 1, 1024, 0, NULL },

	/* hashedRootKey:
		OID = 2 23 42 7 0
		critical = TRUE
		SEQUENCE {
			rootKeyThumbprint	DigestedData		-- PKCS #7-type wrapper
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x00" ), CRYPT_CERTINFO_SET_HASHEDROOTKEY,
	  MKDESC( "hashedRootKey" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "hashedRootKey.rootKeyThumbprint" )
	  FIELDTYPE_BLOB, 0,				/* PKCS #7-type wrapper */
	  FL_MORE | FL_NONENCODING, 0, 0, 25,
	  "\x30\x2D\x02\x01\x00\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x30\x07\x06\x05\x67\x2A\x03\x00\x00" },
	{ NULL, CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,
	  MKDESC( "hashedRootKey.rootKeyThumbprint.hashData" )
	  BER_OCTETSTRING, 0,
	  0, 20, 20, 0, NULL },

	/* certificateType:
		OID = 2 23 42 7 1
		critical = TRUE
		BIT STRING */
	{ MKOID( "\x06\x04\x67\x2A\x07\x01" ), CRYPT_CERTINFO_SET_CERTIFICATETYPE,
	  MKDESC( "certificateType" )
	  BER_BITSTRING, 0,
	  FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_CERTREQ, 0, CRYPT_SET_CERTTYPE_LAST, 0, NULL },

	/* merchantData:
		OID = 2 23 42 7 2
		SEQUENCE {
			merID				SETString SIZE(1..30),
			merAcquirerBIN		NumericString SIZE(6),
			merNameSeq			SEQUENCE OF MerNames,
			merCountry			INTEGER (1..999),
			merAuthFlag			BOOLEAN DEFAULT TRUE
			}

		MerNames ::= SEQUENCE {
			language	  [ 0 ] VisibleString SIZE(1..35),
			name		  [ 1 ]	EXPLICIT SETString SIZE(1..50),
			city		  [ 2 ]	EXPLICIT SETString SIZE(1..50),
			stateProvince [ 3 ] EXPLICIT SETString SIZE(1..50) OPTIONAL,
			postalCode	  [ 4 ] EXPLICIT SETString SIZE(1..14) OPTIONAL,
			countryName	  [ 5 ]	EXPLICIT SETString SIZE(1..50)
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x02" ), CRYPT_CERTINFO_SET_MERCHANTDATA,
	  MKDESC( "merchantData" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERID,
	  MKDESC( "merchantData.merID" )
	  BER_STRING_ISO646, 0,
	  FL_MORE, 1, 30, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERACQUIRERBIN,
	  MKDESC( "merchantData.merAcquirerBIN" )
	  BER_STRING_NUMERIC, 0,
	  FL_MORE,  6, 6, 0, NULL },
	{ NULL, 0,
	  MKDESC( "merchantData.merNameSeq" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "merchantData.merNameSeq.merNames" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,
	  MKDESC( "merchantData.merNameSeq.merNames.language" )
	  BER_STRING_ISO646, CTAG( 0 ),
	  FL_MORE | FL_MULTIVALUED, 1, 35, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTNAME,
	  MKDESC( "merchantData.merNameSeq.merNames.name" )
	  BER_STRING_ISO646, CTAG( 1 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCITY,
	  MKDESC( "merchantData.merNameSeq.merNames.city" )
	  BER_STRING_ISO646, CTAG( 2 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,
	  MKDESC( "merchantData.merNameSeq.merNames.stateProvince" )
	  BER_STRING_ISO646, CTAG( 3 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_OPTIONAL, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,
	  MKDESC( "merchantData.merNameSeq.merNames.postalCode" )
	  BER_STRING_ISO646, CTAG( 4 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_OPTIONAL, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,
	  MKDESC( "merchantData.merNameSeq.merNames.countryName" )
	  BER_STRING_ISO646, CTAG( 5 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_SEQEND_2, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCOUNTRY,
	  MKDESC( "merchantData.merCountry" )
	  BER_INTEGER, 0,
	  FL_MORE, 1, 999, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERAUTHFLAG,
	  MKDESC( "merchantData.merAuthFlag" )
	  BER_BOOLEAN, 0,
	  FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },

	/* certCardRequired
		OID = 2 23 42 7 3
		BOOLEAN */
	{ MKOID( "\x06\x04\x67\x2A\x07\x03" ), CRYPT_CERTINFO_SET_CERTCARDREQUIRED,
	  MKDESC( "certCardRequired" )
	  BER_BOOLEAN, 0,
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, FALSE, TRUE, 0, NULL },

	/* tunneling:
		OID = 2 23 42 7 4
		SEQUENCE {
			tunneling 		DEFAULT TRUE,
			tunnelAlgIDs	SEQUENCE OF OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x04" ), CRYPT_CERTINFO_SET_TUNNELING,
	  MKDESC( "tunneling" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_CERTREQ, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGFLAG,
	  MKDESC( "tunneling.tunneling" )
	  BER_BOOLEAN, 0,
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, TRUE, NULL },
	{ NULL, 0,
	  MKDESC( "tunneling.tunnelingAlgIDs" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGALGID,
	  MKDESC( "tunneling.tunnelingAlgIDs.tunnelingAlgID" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MULTIVALUED | FL_SEQEND, 3, 32, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the holdInstructionCode */

STATIC_DATA const FAR_BSS ATTRIBUTE_INFO holdInstructionInfo[] = {
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x01" ), CRYPT_HOLDINSTRUCTION_NONE,
	  MKDESC( "holdInstructionCode.holdinstruction-none (1 2 840 10040 2 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x02" ), CRYPT_HOLDINSTRUCTION_CALLISSUER,
	  MKDESC( "holdInstructionCode.holdinstruction-callissuer (1 2 840 10040 2 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x03" ), CRYPT_HOLDINSTRUCTION_REJECT,
	  MKDESC( "holdInstructionCode.holdinstruction-reject (1 2 840 10040 2 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x04" ), CRYPT_HOLDINSTRUCTION_PICKUPTOKEN,
	  MKDESC( "holdInstructionCode.holdinstruction-pickupToken (1 2 840 10040 2 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*								GeneralName Definition						*
*																			*
****************************************************************************/

/* Encoding and decoding of GeneralNames is performed with the following
   subtable:

	otherName		  [ 0 ]	SEQUENCE {
		type-id				OBJECT IDENTIFIER,
		value		  [ 0 ]	EXPLICIT ANY DEFINED BY type-id
		} OPTIONAL,
	rfc822Name		  [ 1 ]	IA5String OPTIONAL,
	dNSName			  [ 2 ]	IA5String OPTIONAL,
	x400Address		  [ 3 ] ITU-BrainDamage OPTIONAL
	directoryName	  [ 4 ]	EXPLICIT Name OPTIONAL,
	ediPartyName 	  [ 5 ]	SEQUENCE {
		nameAssigner  [ 0 ]	EXPLICIT DirectoryString OPTIONAL,
		partyName	  [ 1 ]	EXPLICIT DirectoryString
		} OPTIONAL,
	uniformResourceIdentifier
					  [ 6 ]	IA5String OPTIONAL,
	iPAddress		  [ 7 ]	OCTET STRING OPTIONAL,
	registeredID	  [ 8 ]	OBJECT IDENTIFIER OPTIONAL

	ITU-Braindamge ::= SEQUENCE {
		built-in-standard-attributes		SEQUENCE {
			country-name  [ APPLICATION 1 ]	CHOICE {
				x121-dcc-code				NumericString,
				iso-3166-alpha2-code		PrintableString
				},
			administration-domain-name
						  [ APPLICATION 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				},
			network-address			  [ 0 ]	NumericString OPTIONAL,
			terminal-identifier		  [ 1 ]	PrintableString OPTIONAL,
			private-domain-name		  [ 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				} OPTIONAL,
			organization-name		  [ 3 ]	PrintableString OPTIONAL,
			numeric-use-identifier	  [ 4 ]	NumericString OPTIONAL,
			personal-name			  [ 5 ]	SET {
				surname				  [ 0 ]	PrintableString,
				given-name			  [ 1 ]	PrintableString,
				initials			  [ 2 ]	PrintableString,
				generation-qualifier  [ 3 ]	PrintableString
				} OPTIONAL,
			organizational-unit-name  [ 6 ]	PrintableString OPTIONAL,
			}
		built-in-domain-defined-attributes	SEQUENCE OF {
			type							PrintableString SIZE(1..64),
			value							PrintableString SIZE(1..64)
			} OPTIONAL
		extensionAttributes					SET OF SEQUENCE {
			extension-attribute-type  [ 0 ]	INTEGER,
			extension-attribute-value [ 1 ]	ANY DEFINED BY extension-attribute-type
			} OPTIONAL
		}

   Needless to say, X.400 addresses aren't supported (for readers who've
   never seen one before, now you know why they've been so enormously
   successful).

   Note the special-case encoding of the DirectoryName and EDIPartyName.  
   This is required because (for the DirectoryName) a Name is actually a 
   CHOICE { RDNSequence }, and if the tagging were implicit then there'd be 
   no way to tell which of the CHOICE options was being used:

	directoryName	  [ 4 ]	Name OPTIONAL

   becomes:

	directoryName	  [ 4 ]	CHOICE { RDNSequence } OPTIONAL

   which, if implicit tagging is used, would replace the RDNSequence tag with
   the [4] tag, making it impossible to determine which of the Name choices
   was used (actually there's only one possibility and it's unlikely that
   there'll ever be more, but that's what the encoding rules require - X.208,
   section 26.7c).
   
   The same applies to the EDIPartyName, this is a DirectoryString which is 
   a CHOICE of several possible string types.  The end result is that:

	[ 0 ] DirectoryString

   ends up looking like:

	[ 0 ] SEQUENCE {
		option1				PrintableString	OPTIONAL,
		option2				T61String OPTIONAL,
		option3				UTF8String OPTIONAL,
		option4				BMPString OPTIONAL
		} 

   Newer versions of the PKIX core RFC allow the use of 8- and 32-byte CIDR 
   forms for 4- and 16-byte IP addresses in some instances when they're 
   being used as constraints.  We'll add support for this if anyone ever 
   asks for it */

STATIC_DATA const FAR_BSS ATTRIBUTE_INFO generalNameInfo[] = {
	{ NULL, 0,
	  MKDESC( "generalName.otherName" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_TYPEID,
	  MKDESC( "generalName.otherName.type-id" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_VALUE,
	  MKDESC( "generalName.otherName.value" )
	  FIELDTYPE_BLOB, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL | FL_EXPLICIT | FL_SEQEND, 3, 512, 0, NULL },
	{ NULL, CRYPT_CERTINFO_RFC822NAME,
	  MKDESC( "generalName.rfc822Name" )
	  BER_STRING_IA5, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, MIN_RFC822_SIZE, MAX_RFC822_SIZE, 0, ( void * ) checkRFC822 },
	{ NULL, CRYPT_CERTINFO_DNSNAME,
	  MKDESC( "generalName.dNSName" )
	  BER_STRING_IA5, CTAG( 2 ),
	  FL_MORE | FL_OPTIONAL, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkDNS },
	{ NULL, 0,
	  MKDESC( "generalName.directoryName" )
	  BER_SEQUENCE, CTAG( 4 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_DIRECTORYNAME,
	  MKDESC( "generalName.directoryName.name" )
	  FIELDTYPE_DN, BER_SEQUENCE,
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_1, 0, 0, 0, ( void * ) checkDirectoryName },
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName" )
	  BER_SEQUENCE, CTAG( 5 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName.nameAssigner" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
	  MKDESC( "generalName.ediPartyName.nameAssigner.directoryName" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE | FL_OPTIONAL, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
	  MKDESC( "generalName.ediPartyName.nameAssigner.directoryName" )
	  BER_STRING_T61, 0,
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName.partyName" )
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
	  MKDESC( "generalName.ediPartyName.partyName.directoryName" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE | FL_OPTIONAL, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
	  MKDESC( "generalName.ediPartyName.partyName.directoryName" )
	  BER_STRING_T61, 0,
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_2, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
	  MKDESC( "generalName.uniformResourceIdentifier" )
	  BER_STRING_IA5, CTAG( 6 ),
	  FL_MORE | FL_OPTIONAL, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkURL },
	{ NULL, CRYPT_CERTINFO_IPADDRESS,
	  MKDESC( "generalName.iPAddress" )
	  BER_OCTETSTRING, CTAG( 7 ),
	  FL_MORE | FL_OPTIONAL, 4, 16, 0, NULL },
	{ NULL, CRYPT_CERTINFO_REGISTEREDID,
	  MKDESC( "generalName.registeredID" )
	  BER_OBJECT_IDENTIFIER, CTAG( 8 ),
	  FL_OPTIONAL, 3, 32, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*							CMS Attribute Definitions						*
*																			*
****************************************************************************/

/* CMS attributes are encoded using the following table */

static const FAR_BSS ATTRIBUTE_INFO cmsAttributeInfo[] = {
	/* contentType:
		OID = 1 2 840 113549 1 9 3
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03" ), CRYPT_CERTINFO_CMS_CONTENTTYPE,
	  MKDESC( "contentType" )
	  FIELDTYPE_CHOICE, 0,
	  0, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* messageDigest:
		OID = 1 2 840 113549 1 9 4
		OCTET STRING */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04" ), CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
	  MKDESC( "messageDigest" )
	  BER_OCTETSTRING, 0,
	  0, 16, CRYPT_MAX_HASHSIZE, 0, NULL },

	/* signingTime:
		OID = 1 2 840 113549 1 9 5
		CHOICE {
			utcTime			UTCTime,				-- Up to 2049
			generalizedTime	GeneralizedTime
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05" ), CRYPT_CERTINFO_CMS_SIGNINGTIME,
	  MKDESC( "signingTime" )
	  BER_TIME_UTC, 0,
	  0, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* counterSignature:
		OID = 1 2 840 113549 1 9 6
		CHOICE {
			utcTime			UTCTime,				-- Up to 2049
			generalizedTime	GeneralizedTime
			}
	   This field isn't an authenticated attribute so it isn't used */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x06" ), CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,
	  MKDESC( "counterSignature" )
	  -1, 0,
	  0, 0, 0, 0, NULL },

  	/* signingDescription:
		OID = 1 2 840 113549 1 9 13
		UTF8String */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0D" ), CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION,
	  MKDESC( "signingDescription" )
	  BER_STRING_UTF8, 0,
	  0, 1, MAX_ATTRIBUTE_SIZE, 0, NULL },

	/* sMIMECapabilities:
		OID = 1 2 840 113549 1 9 15
		SEQUENCE OF {
			SEQUENCE {
				capabilityID	OBJECT IDENTIFIER,
				parameters		ANY DEFINED BY capabilityID
				}
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F" ), CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
	  MKDESC( "sMIMECapabilities" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (des-EDE3-CBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_3DES,
	  MKDESC( "sMIMECapabilities.capability.des-EDE3-CBC" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (aes128-CBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_AES,
	  MKDESC( "sMIMECapabilities.capability.aes128-CBC" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (cast5CBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0A" ), CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,
	  MKDESC( "sMIMECapabilities.capability.cast5CBC" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.cast5CBC.parameter" )
	  FIELDTYPE_BLOB, 0,		/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (ideaCBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_IDEA,
	  MKDESC( "sMIMECapabilities.capability.ideaCBC (Ascom Tech variant)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (rc2CBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC2,
	  MKDESC( "sMIMECapabilities.capability.rc2CBC" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.rc2CBC.parameters" )
	  FIELDTYPE_BLOB, 0,		/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (rC5-CBCPad)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x09" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC5,
	  MKDESC( "sMIMECapabilities.capability.rC5-CBCPad" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.rC5-CBCPad.parameters" )
	  FIELDTYPE_BLOB, 0,		/* 16-byte key, 12 rounds, 64-bit blocks */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 11, "\x30\x09\x02\x01\x10\x02\x01\x0C\x02\x01\x40" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (fortezzaConfidentialityAlgorithm)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x04" ), CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK,
	  MKDESC( "sMIMECapabilities.capability.fortezzaConfidentialityAlgorithm" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (desCBC)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x05\x2B\x0E\x03\x02\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_DES,
	  MKDESC( "sMIMECapabilities.capability.desCBC" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (preferSignedData)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x01" ), CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,
	  MKDESC( "sMIMECapabilities.capability.preferSignedData" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (canNotDecryptAny)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,
	  MKDESC( "sMIMECapabilities.capability.canNotDecryptAny" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (catchAll)" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ NULL, 10000,
	  MKDESC( "sMIMECapabilities.capability.catchAll" )
	  FIELDTYPE_BLOB, 0,		/* Match anything and ignore it */
	  FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },

	/* receiptRequest:
		OID = 1 2 840 113549 1 9 16 2 1
		SEQUENCE {
			contentIdentifier	OCTET STRING,
			receiptsFrom  [ 0 ]	INTEGER (0..1),
			receiptsTo			SEQUENCE {
				SEQUENCE OF GeneralName
				}
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x01" ), CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
	  MKDESC( "receiptRequest" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER,
	  MKDESC( "receiptRequest.contentIdentifier" )
	  BER_OCTETSTRING, 0,
	  FL_MORE, 16, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_FROM,
	  MKDESC( "receiptRequest.receiptsFrom" )
	  BER_INTEGER, CTAG( 0 ),
	  FL_MORE, 0, 1, 0, NULL },
	{ NULL, 0,
	  MKDESC( "receiptRequest.receiptsTo" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "receiptRequest.receiptsTo.generalNames" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_TO,
	  MKDESC( "receiptRequest.receiptsTo.generalNames.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MULTIVALUED | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* essSecurityLabel:
		OID = 1 2 840 113549 1 9 16 2 2
		SET {
			policyIdentifier	OBJECT IDENTIFIER,
			classification		INTEGER (0..5+6..255) OPTIONAL,
			privacyMark			PrintableString OPTIONAL,
			categories			SET OF {
				SEQUENCE {
					type  [ 0 ]	OBJECT IDENTIFIER,
					value [ 1 ]	ANY DEFINED BY type
					}
				} OPTIONAL
			}
		Because this is a SET, we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x02" ), CRYPT_CERTINFO_CMS_SECURITYLABEL,
	  MKDESC( "essSecurityLabel" )
	  BER_SET, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
	  MKDESC( "essSecurityLabel.securityClassification" )
	  BER_INTEGER, 0,
	  FL_MORE | FL_OPTIONAL, CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
	  MKDESC( "essSecurityLabel.securityPolicyIdentifier" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,
	  MKDESC( "essSecurityLabel.privacyMark" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, 0,
	  MKDESC( "essSecurityLabel.securityCategories" )
	  BER_SET, 0,
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory.type" )
	  BER_OBJECT_IDENTIFIER, CTAG( 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory.type" )
	  FIELDTYPE_BLOB, CTAG( 1 ),
	  FL_MULTIVALUED | FL_SEQEND_2 | FL_OPTIONAL, 1, 512, 0, NULL },

	/* mlExpansionHistory:
		OID = 1 2 840 113549 1 9 16 2 3
		SEQUENCE OF {
			SEQUENCE {
				entityIdentifier IssuerAndSerialNumber (blob),
				expansionTime	GeneralizedTime,
				mlReceiptPolicy	CHOICE {
					none		  [ 0 ]	NULL,
					insteadOf	  [ 1 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName		-- GeneralNames
						}
					inAdditionTo  [ 2 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName		-- GeneralNames
						}
					}
				} OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x03" ), CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
	  MKDESC( "mlExpansionHistory" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER,
	  MKDESC( "mlExpansionHistory.mlData.mailListIdentifier.issuerAndSerialNumber" )
	  FIELDTYPE_BLOB, 0,
	  FL_MORE | FL_MULTIVALUED, 1, 512, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_TIME,
	  MKDESC( "mlExpansionHistory.mlData.expansionTime" )
	  BER_TIME_GENERALIZED, 0,
	  FL_MORE | FL_MULTIVALUED, sizeof( time_t ), sizeof( time_t ), 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_NONE,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.none" )
	  BER_NULL, CTAG( 0 ),
	  FL_MORE | FL_MULTIVALUED, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf" )
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf.generalNames" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf.generalNames.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_SEQEND_2 | FL_MULTIVALUED | FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo" )
	  BER_SEQUENCE, CTAG( 2 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo.generalNames" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName" )
	  FIELDTYPE_SUBTYPED, 0,
	  FL_SEQEND_3 | FL_MULTIVALUED | FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },

	/* contentHints:
		OID = 1 2 840 113549 1 9 16 2 4
		SEQUENCE {
			contentDescription	UTF8String,
			contentType			OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x04" ), CRYPT_CERTINFO_CMS_CONTENTHINTS,
	  MKDESC( "contentHints" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,
	  MKDESC( "contentHints.contentDescription" )
	  BER_STRING_UTF8, 0,
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,
	  MKDESC( "contentHints.contentType" )
	  FIELDTYPE_CHOICE, 0,
	  0, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* equivalentLabels:
		OID = 1 2 840 113549 1 9 16 2 9
		SEQUENCE OF {
			SET {
				policyIdentifier OBJECT IDENTIFIER,
				classification	INTEGER (0..5) OPTIONAL,
				privacyMark		PrintableString OPTIONAL,
				categories		SET OF {
					SEQUENCE {
						type  [ 0 ]	OBJECT IDENTIFIER,
						value [ 1 ]	ANY DEFINED BY type
						}
					} OPTIONAL
				}
			}
		Because this is a SET, we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x09" ), CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
	  MKDESC( "equivalentLabels" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set" )
	  BER_SET, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION,
	  MKDESC( "equivalentLabels.set.securityClassification" )
	  BER_INTEGER, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,
	  MKDESC( "equivalentLabels.set.securityPolicyIdentifier" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_MULTIVALUED, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,
	  MKDESC( "equivalentLabels.set.privacyMark" )
	  BER_STRING_PRINTABLE, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set.securityCategories" )
	  BER_SET, 0,
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory.type" )
	  BER_OBJECT_IDENTIFIER, CTAG( 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory.value" )
	  FIELDTYPE_BLOB, CTAG( 1 ),
	  FL_MULTIVALUED | FL_SEQEND_3 | FL_OPTIONAL, 1, 512, 0, NULL },

	/* signingCertificate:
		OID = 1 2 840 113549 1 9 16 2 12
		SEQUENCE {
			SEQUENCE OF ESSCertID
			SEQUENCE OF {
				SEQUENCE {
					policyIdentifier	OBJECT IDENTIFIER
					}
				} OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" ), CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
	  MKDESC( "signingCertificate" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signingCertificate.certs" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID,
	  MKDESC( "signingCertificate.certs.essCertID" )
	  FIELDTYPE_BLOB, 0,
	  FL_MORE | FL_MULTIVALUED | FL_SEQEND, 32, MAX_ATTRIBUTE_SIZE, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signingCertificate.policies" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signingCertificate.policies.policyInformation" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,
	  MKDESC( "signingCertificate.policies.policyInformation.policyIdentifier" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, 3, 32, 0, NULL },

	/* signaturePolicyID:
		OID = 1 2 840 113549 1 9 16 2 15
		SEQUENCE {
			sigPolicyID					OBJECT IDENTIFIER,
			sigPolicyHash				OtherHashAlgAndValue,
			sigPolicyQualifiers			SEQUENCE OF {
										SEQUENCE {
				sigPolicyQualifierID	OBJECT IDENTIFIER,
				sigPolicyQualifier		ANY DEFINED BY sigPolicyQualifierID
					}
				} OPTIONAL
			}

		CPSuri ::= IA5String						-- OID = cps

		UserNotice ::= SEQUENCE {					-- OID = unotice
			noticeRef		SEQUENCE {
				organization	UTF8String,
				noticeNumbers	SEQUENCE OF INTEGER	-- SIZE (1)
				} OPTIONAL,
			explicitText	UTF8String OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0F" ), CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID,
	  MKDESC( "signaturePolicyID" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICYID,
	  MKDESC( "signaturePolicyID.sigPolicyID" )
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICYHASH,
	  MKDESC( "signaturePolicyID.sigPolicyHash" )
	  FIELDTYPE_BLOB, 0,
	  FL_MORE, 32, MAX_ATTRIBUTE_SIZE, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x05\x01" ), 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cps (1 2 840 113549 1 9 16 5 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cPSuri" )
	  BER_STRING_IA5, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkURL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x05\x02" ), 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.unotice (1 2 840 113549 1 9 16 5 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization" )
	  BER_STRING_UTF8, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,	/* Backwards-compat.handling for VisibleString */
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization" )
	  BER_STRING_ISO646, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers" )
	  BER_INTEGER, 0,
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, 1, 1024, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText" )
	  BER_STRING_UTF8, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 1, 200, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,	/* Backwards-compat.handling for VisibleString */
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText" )
	  BER_STRING_ISO646, 0,
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, 1, 200, 0, NULL },

	/* signatureTypeIdentifier:
		OID = 1 2 840 113549 1 9 16 9
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09" ), CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER,
	  MKDESC( "signatureTypeIdentifier" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x01" ), CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG,
	  MKDESC( "signatureTypeIdentifier.originatorSig (1 2 840 113549 1 9 16 9 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x02" ), CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG,
	  MKDESC( "signatureTypeIdentifier.domainSig (1 2 840 113549 1 9 16 9 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x03" ), CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES,
	  MKDESC( "signatureTypeIdentifier.additionalAttributesSig (1 2 840 113549 1 9 16 9 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x04" ), CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG,
	  MKDESC( "signatureTypeIdentifier.reviewSig (1 2 840 113549 1 9 16 9 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* randomNonce:
		OID = 1 2 840 113549 1 9 25 3
		OCTET STRING */
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x19\x03" ), CRYPT_CERTINFO_CMS_NONCE,
	  MKDESC( "randomNonce" )
	  BER_OCTETSTRING, 0,
	  0, 4, CRYPT_MAX_HASHSIZE, 0, NULL },

	/* SCEP attributes:
		messageType:
			OID = 2 16 840 1 113733 1 9 2
			PrintableString
		pkiStatus
			OID = 2 16 840 1 113733 1 9 3
			PrintableString
		failInfo
			OID = 2 16 840 1 113733 1 9 4 
			PrintableString
		senderNonce
			OID = 2 16 840 1 113733 1 9 5
			OCTET STRING
		recipientNonce
			OID = 2 16 840 1 113733 1 9 6
			OCTET STRING
		transID
			OID = 2 16 840 1 113733 1 9 7
			PrintableString */
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x02" ), CRYPT_CERTINFO_SCEP_MESSAGETYPE,
	  MKDESC( "messageType" )
	  BER_STRING_PRINTABLE, 0,
	  0, 1, 2, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x03" ), CRYPT_CERTINFO_SCEP_PKISTATUS,
	  MKDESC( "pkiStatus" )
	  BER_STRING_PRINTABLE, 0,
	  0, 1, 1, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x04" ), CRYPT_CERTINFO_SCEP_FAILINFO,
	  MKDESC( "failInfo" )
	  BER_STRING_PRINTABLE, 0,
	  0, 1, 1, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x05" ), CRYPT_CERTINFO_SCEP_SENDERNONCE,
	  MKDESC( "senderNonce" )
	  BER_OCTETSTRING, 0,
	  0, 8, CRYPT_MAX_HASHSIZE, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x06" ), CRYPT_CERTINFO_SCEP_RECIPIENTNONCE,
	  MKDESC( "recipientNonce" )
	  BER_OCTETSTRING, 0,
	  0, 8, CRYPT_MAX_HASHSIZE, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x07" ), CRYPT_CERTINFO_SCEP_TRANSACTIONID,
	  MKDESC( "transID" )
	  BER_STRING_PRINTABLE, 0,
	  0, 2, CRYPT_MAX_TEXTSIZE, 0, NULL },

	/* spcAgencyInfo:
		OID = 1 3 6 1 4 1 311 2 1 10
		SEQUENCE {
			[ 0 ] {
				??? (= [ 0 ] IA5String )
				}
			}
	   The format for this attribute is unknown but it seems to be an 
	   unnecessarily nested URL which is probably an IA5String */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0A" ), CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
	  MKDESC( "spcAgencyInfo" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "spcAgencyInfo.vendorInfo" )
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SPCAGENCYURL,
	  MKDESC( "spcAgencyInfo..vendorInfo.url" )
	  BER_STRING_IA5, CTAG( 0 ),
	  0, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* spcStatementType:
		OID = 1 3 6 1 4 1 311 2 1 11
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0B" ), CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
	  MKDESC( "spcStatementType" )
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,
	  MKDESC( "spcStatementType.individualCodeSigning (1 3 6 1 4 1 311 2 1 21)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,
	  MKDESC( "spcStatementType.commercialCodeSigning (1 3 6 1 4 1 311 2 1 22)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* spcOpusInfo:
		OID = 1 3 6 1 4 1 311 2 1 12
		SEQUENCE {
			[ 0 ] {
				??? (= [ 0 ] BMPString )
				}
			[ 1 ] {
				??? (= [ 0 ] IA5String )
				}
			}
	   The format for this attribute is unknown but it seems to be either an 
	   empty sequence or some nested set of tagged fields that eventually 
	   end up as text strings */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0C" ), CRYPT_CERTINFO_CMS_SPCOPUSINFO,
	  MKDESC( "spcOpusInfo" )
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  MKDESC( "spcOpusInfo.programInfo" )
	  BER_SEQUENCE, MAKE_CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME,
	  MKDESC( "spcOpusInfo.programInfo.name" )
	  BER_STRING_BMP, MAKE_CTAG_PRIMITIVE( 0 ),
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, 2, 128, 0, NULL },
	{ NULL, 0,
	  MKDESC( "spcOpusInfo.vendorInfo" )
	  BER_SEQUENCE, MAKE_CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL,
	  MKDESC( "spcOpusInfo.vendorInfo.url" )
	  BER_STRING_IA5, MAKE_CTAG_PRIMITIVE( 0 ),
	  FL_OPTIONAL | FL_SEQEND, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	{ NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the contentType */

STATIC_DATA const FAR_BSS ATTRIBUTE_INFO contentTypeInfo[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA,
	  MKDESC( "contentType.data (1 2 840 113549 1 7 1)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA,
	  MKDESC( "contentType.signedData (1 2 840 113549 1 7 2)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA,
	  MKDESC( "contentType.envelopedData (1 2 840 113549 1 7 3)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04" ), CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
	  MKDESC( "contentType.signedAndEnvelopedData (1 2 840 113549 1 7 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_DIGESTEDDATA, CRYPT_CONTENT_DIGESTEDDATA,
	  MKDESC( "contentType.digestedData (1 2 840 113549 1 7 5)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA,
	  MKDESC( "contentType.encryptedData (1 2 840 113549 1 7 6)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA,
	  MKDESC( "contentType.compressedData (1 2 840 113549 1 9 16 1 9)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CMS_TSTOKEN, CRYPT_CONTENT_TSTINFO,
	  MKDESC( "contentType.tstInfo (1 2 840 113549 1 9 16 1 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT,
	  MKDESC( "contentType.spcIndirectDataContext (1 3 6 1 4 1 311 2 1 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST,
	  MKDESC( "contentType.rtcsRequest (1 3 6 1 4 1 3029 4 1 4)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE,
	  MKDESC( "contentType.rtcsResponse (1 3 6 1 4 1 3029 4 1 5)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT,
	  MKDESC( "contentType.rtcsResponseExt (1 3 6 1 4 1 3029 4 1 6)" )
	  FIELDTYPE_IDENTIFIER, 0,
	  FL_OPTIONAL, 0, 0, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/* Select the appropriate attribute info table for encoding/type checking */

const ATTRIBUTE_INFO *selectAttributeInfo( const ATTRIBUTE_TYPE attributeType )
	{
	assert( attributeType == ATTRIBUTE_CERTIFICATE || \
			attributeType == ATTRIBUTE_CMS );

	/* Sanity checks on various encoded attribute info flags. This isn't a
	   particularly optimal place to put this, but it's better than any 
	   other */
	assert( decodeNestingLevel( FL_SEQEND ) == 1 );
	assert( decodeNestingLevel( FL_SEQEND_1 ) == 1 );
	assert( decodeNestingLevel( FL_SEQEND_2 ) == 2 );
	assert( decodeNestingLevel( FL_SEQEND_3 ) == 3 );
	assert( decodeComplianceLevel( FL_LEVEL_OBLIVIOUS ) == CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
	assert( decodeComplianceLevel( FL_LEVEL_REDUCED ) == CRYPT_COMPLIANCELEVEL_REDUCED );
	assert( decodeComplianceLevel( FL_LEVEL_STANDARD ) == CRYPT_COMPLIANCELEVEL_STANDARD );
	assert( decodeComplianceLevel( FL_LEVEL_PKIX_PARTIAL ) == CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL );
	assert( decodeComplianceLevel( FL_LEVEL_PKIX_FULL ) == CRYPT_COMPLIANCELEVEL_PKIX_FULL );

	return( ( attributeType == ATTRIBUTE_CMS ) ? \
			cmsAttributeInfo : extensionInfo );
	}

/****************************************************************************
*																			*
*						Extended Validity Checking Functions				*
*																			*
****************************************************************************/

/* Determine whether a variety of URIs are valid.  The PKIX RFC refers to a 
   pile of complex parsing rules for various URI forms, since cryptlib is 
   neither a resolver nor an MTA nor a web browser it leaves it up to the
   calling application to decide whether a particular form is acceptable to 
   it or not.  We do however perform a few basic checks to weed out 
   obviously-incorrect forms here */

typedef enum { 
	URL_NONE,				/* No URL */
	URL_RFC822,				/* Email address */
	URL_DNS,				/* FQDN */
	URL_HTTP,				/* HTTP URL */
	URL_ANY,				/* Generic URL */
	URL_LAST				/* Last possible URL type */
	} URL_CHECK_TYPE;

static int checkURLString( const char *url, const int urlLength, 
						   const URL_CHECK_TYPE urlType )
	{
	const char *schemaPtr;
	int length = urlLength, i;

	/* Check for a schema separator */
	schemaPtr = strstr( url, "://" );
	if( schemaPtr != NULL )
		{
		const char *urlStart = url;

		url = schemaPtr + 3;	/* Skip "://" */
		schemaPtr = urlStart;
		length = schemaPtr - urlStart;
		}

	/* Make sure that the start of the URL looks valid */
	switch( urlType )
		{
		case URL_DNS:
			if( schemaPtr != NULL || \
				( isDigit( url[ 0 ] && isDigit( url[ 1 ] ) ) ) )
				/* Catch erroneous use of URL or IP address */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			if( !strCompare( url, "*.", 2 ) )
				url += 2;	/* Skip wildcard */
			break;

		case URL_RFC822:
			if( schemaPtr != NULL )
				/* Catch erroneous use of URL */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			if( !strCompare( url, "*@", 2 ) )
				url += 2;	/* Skip wildcard */
			break;

		case URL_HTTP:
			if( schemaPtr == NULL || urlLength < 8 || \
				( strCompare( schemaPtr, "http://", 7 ) && \
				  strCompare( schemaPtr, "https://", 8 ) ) )
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			if( !strCompare( url, "*.", 2 ) )
				url += 2;	/* Skip wildcard */
			break;

		case URL_ANY:
			if( schemaPtr == NULL || urlLength < 7 )
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}

	/* Make sure that the string follows the RFC 1738 rules for valid characters */
	for( i = 0; i < length; i++ )
		{
		const int ch = url[ i ];

		if( !isPrint( ch ) || ch == ' ' || ch == '<' || ch == '>' || \
			ch == '"' || ch == '{' || ch == '}' || ch == '|' || \
			ch == '\\' || ch == '^' || ch == '[' || ch == ']' || \
			ch == '`' || ch == '*' )
			return( CRYPT_ERRTYPE_ATTR_VALUE );
		}

	return( CRYPT_OK );
	}

static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( attributeListPtr->value, 
							attributeListPtr->valueLength, URL_RFC822 ) );
	}

static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( attributeListPtr->value, 
							attributeListPtr->valueLength, URL_DNS ) );
	}

static int checkURL( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( attributeListPtr->value, 
							attributeListPtr->valueLength, URL_ANY ) );
	}

static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( attributeListPtr->value, 
							attributeListPtr->valueLength, URL_HTTP ) );
	}

/* Determine whether a DN (either a complete DN or a DN subtree) is valid.
   Most attribute fields require a full DN, but some fields (which act as
   filters) are allowed a partial DN */

static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE dummy;
	const BOOLEAN checkFullDN = \
			( attributeListPtr->fieldID == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
			  attributeListPtr->fieldID == CRYPT_CERTINFO_PERMITTEDSUBTREES ) ? \
			FALSE : TRUE;
	CRYPT_ERRTYPE_TYPE errorType;

	if( cryptStatusError( checkDN( attributeListPtr->value, checkFullDN, TRUE,
								   &dummy, &errorType ) ) )
		return( errorType );
	return( CRYPT_OK );
	}
