/****************************************************************************
*																			*
*						  Certificate Checking Routines						*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						ExtKeyUsage to Key Usage Routines					*
*																			*
****************************************************************************/

/* The following keyUsage settings are used based on extendedKeyUsage and
   Netscape key usage extensions.  In the following 'Y' = required, 'w' =
   written but apparently not required, S = for signature keys only, E = for
   encryption keys only, KA = for key agreement keys only.

						dig	non	key	dat	key	cer	crl	enc	dec
						sig	rep	enc	enc	agt	sig	sig	onl	onl
   PKIX:				-----------------------------------
	serverAuth			 S		 E		KA
	clientAuth			 S
	codeSign			 Y
	email				 Y	 Y	 E
	ipsecEndSys			 S		 E		KA
	ipsecTunnel			 S		 E		KA
	ipsecUser			 S		 E		KA
	timeStamping		 Y	 Y
	ocsp				 Y
	directoryService	 ?
   MS:					-----------------------------------
	individualCodeSign	 Y
	commercialCodeSign	 Y
	ctlSign				 Y
	tsa					 Y
	sgc							 E
	encryptedFS					 E
   NS:					-----------------------------------
	sgc							 E
   NS extensions:		-----------------------------------
	sslClient			 Y
	sslServer					 Y
	sMime				 S		 E
	objectSign			 Y
	sslCA                               	 Y	 w
	sMimeCA									 Y	 w
	objectSignCA							 Y	 w
						-----------------------------------
						dig	non	key	dat	key	cer	crl	enc	dec
						sig	rep	enc	enc	agt	sig	sig	onl	onl */

/* Masks for various key usage types */

#define USAGE_SIGN_MASK			( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								  CRYPT_KEYUSAGE_NONREPUDIATION | \
								  CRYPT_KEYUSAGE_KEYCERTSIGN | \
								  CRYPT_KEYUSAGE_CRLSIGN )
#define USAGE_CRYPT_MASK		( CRYPT_KEYUSAGE_KEYENCIPHERMENT | \
								  CRYPT_KEYUSAGE_DATAENCIPHERMENT )
#define USAGE_KEYAGREEMENT_MASK	( CRYPT_KEYUSAGE_KEYAGREEMENT | \
								  CRYPT_KEYUSAGE_ENCIPHERONLY | \
								  CRYPT_KEYUSAGE_DECIPHERONLY )

/* Mask for key usage types that we don't check for consistency against
   extended key usages.  The two CA usages don't occur in extended key usage,
   and non-repudiation has a somewhat peculiar status where no-one's quite
   sure what it means and it can (in some interpretations) be transparently
   replaced with the meaning of digitalSignature even if the two values are 
   dissimilar, so we don't check for consistency with this one */

#define USAGE_MASK_NONRELEVANT	( CRYPT_KEYUSAGE_NONREPUDIATION | \
								  CRYPT_KEYUSAGE_KEYCERTSIGN | \
								  CRYPT_KEYUSAGE_CRLSIGN )

/* Flags to denote the algorithm type */

#define ALGO_TYPE_SIGN			1
#define ALGO_TYPE_CRYPT			2
#define ALGO_TYPE_KEYAGREEMENT	4

/* Table mapping extended key usage values to key usage flags */

static const FAR_BSS struct {
	const CRYPT_ATTRIBUTE_TYPE usageType;
	const int keyUsageFlags;
	} extendedUsageInfo[] = {
	{ CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,	/* individualCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,	/* commercialCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,	/* certTrustListSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,	/* timeStampSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	  CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,	/* encrypedFileSystem */
	  CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH,				/* serverAuth */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,				/* clientAuth */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_CODESIGNING,			/* codeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,		/* emailProtection */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,			/* ipsecEndSystem */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,			/* ipsecTunnel */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_IPSECUSER,				/* ipsecUser */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,			/* timeStamping */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_CERTINFO_EXTKEY_OCSPSIGNING,			/* ocspSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,		/* directoryService */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	  CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_ATTRIBUTE_NONE, 0 }
	};

/* Table mapping Netscape cert-type flags to extended key usage flags */

static const FAR_BSS struct {
	const int certType;
	const int keyUsageFlags;
	} certTypeInfo[] = {
	{ CRYPT_NS_CERTTYPE_SSLCLIENT,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_NS_CERTTYPE_SSLSERVER,
	  CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_NS_CERTTYPE_SMIME,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_NS_CERTTYPE_OBJECTSIGNING,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_NS_CERTTYPE_RESERVED, 0 },
	{ CRYPT_NS_CERTTYPE_SSLCA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_NS_CERTTYPE_SMIMECA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ 0, 0 }
	};

/* Build up key usage flags consistent with the extended key usage purpose */

static int getExtendedKeyUsageFlags( const ATTRIBUTE_LIST *attributes,
									 const int algorithmType,
									 CRYPT_ATTRIBUTE_TYPE *errorLocus )
	{
	int keyUsage = 0, i;

	for( i = 0; extendedUsageInfo[ i ].usageType != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		const ATTRIBUTE_LIST *attributeListPtr = \
					findAttributeField( attributes, extendedUsageInfo[ i ].usageType, 
										CRYPT_ATTRIBUTE_NONE );
		int extendedUsage = 0;

		/* If this usage isn't present, continue */
		if( attributeListPtr == NULL )
			continue;

		/* If the usage is consistent with the algorithm type, add it */
		if( algorithmType & ALGO_TYPE_SIGN )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_SIGN_MASK;
		if( algorithmType & ALGO_TYPE_CRYPT )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_CRYPT_MASK;
		if( algorithmType & ALGO_TYPE_KEYAGREEMENT )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_KEYAGREEMENT_MASK;

		/* If there's no key usage consistent with the extended usage and the
		   extended usage isn't some special-case usage, return an error */
		if( !extendedUsage && extendedUsageInfo[ i ].keyUsageFlags )
			{
			*errorLocus = extendedUsageInfo[ i ].usageType;
			return( CRYPT_ERROR_INVALID );
			}

		keyUsage |= extendedUsage;
		}

	return( keyUsage );
	}

/* Build up key usage flags consistent with the Netscape cert-type purpose */

static int getNetscapeCertTypeFlags( const ATTRIBUTE_LIST *attributes,
									 const int algorithmType,
									 CRYPT_ATTRIBUTE_TYPE *errorLocus )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findAttributeField( attributes, CRYPT_CERTINFO_NS_CERTTYPE, 
									CRYPT_ATTRIBUTE_NONE );
	int nsCertType, keyUsage = 0, i;

	/* If there isn't a Netscape cert-type extension present, exit */
	if( attributeListPtr == NULL )
		return( 0 );
	nsCertType = ( int ) attributeListPtr->intValue;

	/* The Netscape cert-type value is a bitfield containing the different
	   cert types.  For each cert-type flag which is set, we set the
	   corresponding keyUsage flags */
	for( i = 0; certTypeInfo[ i ].certType; i++ )
		{
		int nsUsage = 0;

		/* If this isn't the currently-selected cert-type, continue */
		if( !( nsCertType & certTypeInfo[ i ].certType ) )
			continue;

		/* If the usage is consistent with the algorithm type, add it */
		if( algorithmType & ALGO_TYPE_SIGN )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_SIGN_MASK;
		if( algorithmType & ALGO_TYPE_CRYPT )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_CRYPT_MASK;
		if( algorithmType & ALGO_TYPE_KEYAGREEMENT )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_KEYAGREEMENT_MASK;

		/* If there's no key usage consistent with the Netscape cert-type,
		   return an error */
		if( !nsUsage )
			{
			*errorLocus = CRYPT_CERTINFO_NS_CERTTYPE;
			return( CRYPT_ERROR_INVALID );
			}

		keyUsage |= nsUsage;
		}

	return( keyUsage );
	}

/* Get key usage flags for a cert based on its extended key usage/Netscape 
   cert-type.  Returns 0 if no extKeyUsage/cert-type values present */

int getKeyUsageFromExtKeyUsage( const CERT_INFO *certInfoPtr,
								CRYPT_ATTRIBUTE_TYPE *errorLocus, 
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	int algorithmType = 0, keyUsage;

	/* Determine the possible algorithm usage type(s) */
	if( isCryptAlgo( certInfoPtr->publicKeyAlgo ) )
		algorithmType |= ALGO_TYPE_CRYPT;
	if( isSigAlgo( certInfoPtr->publicKeyAlgo ) )
		algorithmType |= ALGO_TYPE_SIGN;
	if( isKeyxAlgo( certInfoPtr->publicKeyAlgo ) )
		algorithmType |= ALGO_TYPE_KEYAGREEMENT;

	/* Get the key usage flags for the given extended/Netscape usage type(s)
	   and algorithm type */
	keyUsage = getExtendedKeyUsageFlags( certInfoPtr->attributes,
										 algorithmType, errorLocus );
	keyUsage |= getNetscapeCertTypeFlags( certInfoPtr->attributes, 
										  algorithmType, errorLocus );
	if( cryptStatusError( keyUsage ) )
		{
		*errorType = CRYPT_ERRTYPE_CONSTRAINT;
		return( CRYPT_ERROR_INVALID );
		}

	return( keyUsage );
	}

/****************************************************************************
*																			*
*								Key Usage Routines							*
*																			*
****************************************************************************/

/* Check that the key usage flags are consistent, checked if complianceLevel
   >= CRYPT_COMPLIANCELEVEL_STANDARD */

static int checkKeyUsageFlags( const CERT_INFO *certInfoPtr,
							   const int complianceLevel,
							   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							   CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN keyUsageCritical = 0;
	BOOLEAN isCA = FALSE;
	int extKeyUsage, keyUsage;

	assert( isReadPtr( certInfoPtr, CERT_INFO ) );
	assert( complianceLevel >= CRYPT_COMPLIANCELEVEL_STANDARD );

	/* Obtain assorted cert information */
	attributeListPtr = findAttributeField( certInfoPtr->attributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		isCA = attributeListPtr->intValue;

	/* Get the key usage information.  We recognise two distinct usage types, 
	   the explicit (or implicit for v1 certs) keyUsage, and the extKeyUsage 
	   based on any extended key usage extensions that may be present */
	extKeyUsage = getKeyUsageFromExtKeyUsage( certInfoPtr, errorLocus, 
											  errorType );
	if( cryptStatusError( extKeyUsage ) )
		return( extKeyUsage );
	if( certInfoPtr->version == 1 && ( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
		/* It's a v1 self-signed cert with no keyUsage present, any (normal) 
		   key usage is permitted */
		keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
				   CRYPT_KEYUSAGE_NONREPUDIATION | \
				   CRYPT_KEYUSAGE_KEYENCIPHERMENT;
	else
		{
		/* It's not a v1 self-signed cert, get its keyUsage */
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_KEYUSAGE, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			keyUsage = attributeListPtr->intValue;
			keyUsageCritical = \
					( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ? \
					TRUE : FALSE;
			}
		else
			{
			int algorithmType = 0, netscapeUsage;

			/* If we're doing a PKIX-compliant check, we need a keyUsage
			   (PKIX section 4.2.1.3) */
			if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
				{
				setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_INVALID );
				}

			/* Some broken certs don't have any keyUsage present, if there's
			   nothing there allow at least some minimal usage.  Note that 
			   this is a non-CA usage, so setting it doesn't interfere with 
			   the CA keyUsage checks below */
			keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE;
			
			/* Some even more broken certs indicate their usage via a 
			   Netscape key usage (even though they use X.509 flags 
			   everywhere else), which means that we fail them if we're 
			   strictly applying the PKIX requirements at a higher compliance
			   level.  At this lower level we try for Netscape usage if we 
			   can't find anything else, and if there's one present, use the 
			   translated values as if they were the X.509 usage */
			if( isCryptAlgo( certInfoPtr->publicKeyAlgo ) )
				algorithmType = ALGO_TYPE_CRYPT;
			if( isSigAlgo( certInfoPtr->publicKeyAlgo ) )
				algorithmType |= ALGO_TYPE_SIGN;
			if( isKeyxAlgo( certInfoPtr->publicKeyAlgo ) )
				algorithmType |= ALGO_TYPE_KEYAGREEMENT;
			netscapeUsage = getNetscapeCertTypeFlags( certInfoPtr->attributes,
													  algorithmType, errorLocus );
			if( netscapeUsage > 0 )
				keyUsage = netscapeUsage;
			}
		}

	/* If the CA flag is set, make sure that there's a keyUsage with one of 
	   the CA usages present.  Conversely, if there are CA key usages 
	   present, make sure that the CA flag is set.  The CA flag is actually a 
	   leftover from an early v3 cert concept and is made entirely redundant 
	   by the keyUsage flags, but we have to check it regardless */
	if( isCA )
		{
		if( !( ( extKeyUsage | keyUsage ) & \
			   ( CRYPT_KEYUSAGE_CRLSIGN | CRYPT_KEYUSAGE_KEYCERTSIGN ) ) )
			{
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}	
	else
		if( ( extKeyUsage | keyUsage ) & \
			( CRYPT_KEYUSAGE_CRLSIGN | CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		
	/* Make sure that mutually exclusive flags aren't set */
	if( ( keyUsage & CRYPT_KEYUSAGE_ENCIPHERONLY ) && \
		( keyUsage & CRYPT_KEYUSAGE_DECIPHERONLY ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}

	/* Make sure that the keyUsage flags represent capabilities that the 
	   algorithm is actually capable of */
	if( ( ( keyUsage & USAGE_CRYPT_MASK ) && \
			!isCryptAlgo( certInfoPtr->publicKeyAlgo ) ) || \
		( ( keyUsage & USAGE_SIGN_MASK ) && \
			!isSigAlgo( certInfoPtr->publicKeyAlgo ) ) || \
		( ( keyUsage & USAGE_KEYAGREEMENT_MASK ) && \
			!isKeyxAlgo( certInfoPtr->publicKeyAlgo ) ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}

	/* Mask out any non-relevant usages (e.g. cert signing, which doesn't 
	   occur in extended key usages and has already been checked above) */
	extKeyUsage &= ~USAGE_MASK_NONRELEVANT;
	keyUsage &= ~USAGE_MASK_NONRELEVANT;

	/* If there's no key usage based on extended key usage present or we're 
	   not doing a PKIX-compliant check, there's nothing further to check */
	if( !extKeyUsage || complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If the usage and extended usage are critical (but only if both are 
	   critical, because PKIX says so) make sure that the given usage is 
	   consistent with the required usage.  Checking whether the extended 
	   usage is critical is a bit nontrivial, we have to check each possible
	   extended usage since only one of them may be present, so we check the
	   criticality of the basic key usage first to allow quick short-circuit
	   evaluation.
	   
	   In addition to the explicit criticality checks, we also perform an
	   implicit check based on whether this is a freshly-generated, as-yet-
	   unsigned cryptlib cert.  This is done for two reasons, firstly because 
	   an unsigned cert won't have had the criticality flag set by the
	   signing/encoding process so the extension always appears non-critical, 
	   and secondly because we don't want cryptlib to generate inconsistent 
	   certs, whether the extensions are marked critical or not (cryptlib
	   always makes the keyUsage critical, so at least for key usage it's
	   no change from the standard behaviour) */
	if( certInfoPtr->certificate != NULL )
		{
		int attributeID;

		if( !keyUsageCritical )
			/* No critical key usage, return */
			return( CRYPT_OK );
		for( attributeID = CRYPT_CERTINFO_EXTKEYUSAGE + 1; 
			 attributeID < CRYPT_CERTINFO_NS_CERTTYPE; attributeID++ )
			{
			attributeListPtr = findAttributeField( certInfoPtr->attributes,
										attributeID, CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr != NULL && \
				!( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) )
				/* We found an extended key usage and it's non-critical 
				   (which means that all extended usages are non-critical), 
				   return */
				return( CRYPT_OK );
			}
		}

	/* Make sure that the extended key usage-based key usage is consistent 
	   with the actual key usage */
	if( ( keyUsage & extKeyUsage ) != extKeyUsage )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Name Comparison Routines						*
*																			*
****************************************************************************/

/* Compare two attribute components */

static BOOLEAN compareAttributeComponents( const ATTRIBUTE_LIST *attribute1ptr,
										   const ATTRIBUTE_LIST *attribute2ptr )
	{
	/* Make sure either both are absent or present */
	if( attribute1ptr != NULL )
		{
		if( attribute2ptr == NULL )
			return( FALSE );	/* Both must be present or absent */
		}
	else
		{
		if( attribute2ptr != NULL )
			return( FALSE );	/* Both must be present or absent */
		return( TRUE );
		}

	/* If it's an attribute containing a composite field, use a special-case
	   compare */
	if( attribute1ptr->fieldType == FIELDTYPE_DN )
		return( compareDN( attribute1ptr->value, attribute2ptr->value, FALSE ) );

	/* Compare the data values */
	if( attribute1ptr->valueLength != attribute2ptr->valueLength || \
		memcmp( attribute1ptr->value, attribute2ptr->value, 
				attribute1ptr->valueLength ) )
		return( FALSE );

	return( TRUE );
	}

/* Compare two altNames component by component */

static CRYPT_ATTRIBUTE_TYPE compareAltNames( const ATTRIBUTE_LIST *subjectAttributes,
											 const ATTRIBUTE_LIST *issuerAttributes )
	{
	ATTRIBUTE_LIST *subjectAttributeListPtr, *issuerAttributeListPtr;

	/* Check the otherName */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_OTHERNAME_TYPEID );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_OTHERNAME_TYPEID );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_OTHERNAME_TYPEID );
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_OTHERNAME_VALUE );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_OTHERNAME_VALUE );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_OTHERNAME_VALUE );

	/* Check the email address */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_RFC822NAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_RFC822NAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_RFC822NAME );

	/* Check the DNS name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_DNSNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DNSNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_DNSNAME );

	/* Check the directory name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_DIRECTORYNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DIRECTORYNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_DIRECTORYNAME );

	/* Check the EDI party name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );

	/* Check the URI */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );

	/* Check the IP address */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_IPADDRESS );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_IPADDRESS );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_IPADDRESS );

	/* Check the registered ID */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_REGISTEREDID );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_REGISTEREDID );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_REGISTEREDID );

	return( CRYPT_ATTRIBUTE_NONE );
	}

/* Perform a wildcarded compare of two strings in attributes */

static BOOLEAN wildcardStringMatch( const char *wildcardString, 
									const char *string )
	{
	while( *wildcardString && *string )
		{
		/* Match a wildcard */
		if( *wildcardString == '*' )
			{
			BOOLEAN isMatch = FALSE;

			/* Skip '*'s and exit if we've reached the end of the pattern */
			while( *wildcardString == '*' )
				wildcardString++;
			if( !*wildcardString )
				return( TRUE );

			/* Match to the next literal, then match the next section with
			   backtracking in case of a mismatch */
			while( *string && *wildcardString != *string )
				string++;
			while( *string && !isMatch )
				{
				isMatch = wildcardStringMatch( wildcardString, string );
				if( !isMatch )
					string++;
				}

			return( isMatch );
			}
		else
			if( *wildcardString != *string )
				return( FALSE );

		wildcardString++;
		string++;
		}

	/* If there are literals left in the wildcard or text string, we haven't
	   found a match yet */
	if( *wildcardString && ( *wildcardString != '*' || *++wildcardString ) )
		return( FALSE );
	return( *string ? FALSE : TRUE );
	}

static BOOLEAN wildcardMatch( const ATTRIBUTE_LIST *constrainedAttribute,
							  const ATTRIBUTE_LIST *attribute,
							  const BOOLEAN errorStatus )
	{
	const char *string = attribute->value;
	int count = 0, i;

	/* Perform a quick damage-control check to prevent excessive recursion:
	   There shouldn't be more than ten wildcard chars present (realistically
	   there shouldn't be more than one) */
	for( i = 0; string[ i ]; i++ )
		if( string[ i ] == '*' )
			count++;
	if( count > 10 )
		return( errorStatus );

	/* Pass the call on to the string matcher (this is recursive so we can't
	   do the match in this function) */
	return( wildcardStringMatch( string, constrainedAttribute->value ) );
	}

/* Check name constraints placed by an issuer, checked if complianceLevel >=
   CRYPT_COMPLIANCELEVEL_PKIX_FULL.  matchValue = TRUE for excluded subtrees 
   (fail on a match), FALSE for included subtrees (fail on a mismatch) */

int checkNameConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN matchValue,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const CRYPT_ATTRIBUTE_TYPE constraintType = matchValue ? \
		CRYPT_CERTINFO_EXCLUDEDSUBTREES : CRYPT_CERTINFO_PERMITTEDSUBTREES;
	ATTRIBUTE_LIST *attributeListPtr, *constrainedAttributeListPtr;
	int status = CRYPT_OK;

	assert( isReadPtr( subjectCertInfoPtr, CERT_INFO ) );
	assert( isReadPtr( issuerAttributes, ATTRIBUTE_LIST ) );

	/* Compare the DN if a constraint exists */
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_DIRECTORYNAME );
	if( compareDN( subjectCertInfoPtr->subjectName,
				   attributeListPtr->value, TRUE ) == matchValue )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Compare the Internet-related names if constraints exist */
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_RFC822NAME );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_RFC822NAME );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_DNSNAME );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DNSNAME );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	if( cryptStatusError( status ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Check policy constraints placed by an issuer, checked if complianceLevel 
   >= CRYPT_COMPLIANCELEVEL_PKIX_FULL */

int checkPolicyConstraints( const CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes,
							CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr, *constrainedAttributeListPtr;

	assert( isReadPtr( subjectCertInfoPtr, CERT_INFO ) );
	assert( isReadPtr( issuerAttributes, ATTRIBUTE_LIST ) );

	/* Compare the issuer and subject policies if constraints exist */
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_CERTPOLICYID, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL )
		return( CRYPT_OK );
	constrainedAttributeListPtr = \
				findAttributeField( subjectCertInfoPtr->attributes,
									CRYPT_CERTINFO_CERTPOLICYID, 
									CRYPT_ATTRIBUTE_NONE );
	if( constrainedAttributeListPtr == NULL )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( attributeListPtr->valueLength != \
								constrainedAttributeListPtr->valueLength || \
		memcmp( attributeListPtr->value, constrainedAttributeListPtr->value, 
				attributeListPtr->valueLength ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Check for Constraint Violations						*
*																			*
****************************************************************************/

/* Check the validity of a CRL based on an issuer cert */

static int checkCRL( const CERT_INFO *crlInfoPtr,
					 const CERT_INFO *issuerCertInfoPtr,
					 const int complianceLevel,
					 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					 CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* If it's a delta CRL, make sure that the CRL numbers make sense (that 
	   is, that the delta CRL was issued after the full CRL) */
	attributeListPtr = findAttributeField( crlInfoPtr->attributes,
										   CRYPT_CERTINFO_DELTACRLINDICATOR, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		const int deltaCRLindicator = ( int ) attributeListPtr->intValue;

		attributeListPtr = findAttributeField( crlInfoPtr->attributes,
											   CRYPT_CERTINFO_CRLNUMBER, 
											   CRYPT_ATTRIBUTE_NONE  );
		if( attributeListPtr != NULL && \
			attributeListPtr->intValue >= deltaCRLindicator )
			{
			setErrorValues( CRYPT_CERTINFO_DELTACRLINDICATOR,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If it's a standalone CRL entry used purely as a container for 
	   revocation data, don't try and perform any issuer-based checking */
	if( issuerCertInfoPtr == NULL )
		return( CRYPT_OK );

	/* There is one universal case in which a cert is regarded as an invalid 
	   issuer cert regardless of any special-case considerations for self-
	   signed/v1 certs, and that's when the cert is explicitly not trusted 
	   for this purpose */
	if( issuerCertInfoPtr->trustedUsage != CRYPT_ERROR && \
		!( issuerCertInfoPtr->trustedUsage & CRYPT_KEYUSAGE_CRLSIGN ) )
		{
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If the issuer is a v1 cert, we can't do any checking of issuer 
	   attributes/capabilities */
	if( issuerCertInfoPtr->version <= 2 )
		return( CRYPT_OK );

	/* If it's an oblivious check, we're done */
	if( complianceLevel <= CRYPT_COMPLIANCELEVEL_OBLIVIOUS )
		return( CRYPT_OK );

	/* Make sure that the issuer has a key usage attribute present and can 
	   sign certs (PKIX section 4.2.1.3) */
	attributeListPtr = findAttributeField( issuerCertInfoPtr->attributes,
										   CRYPT_CERTINFO_KEYUSAGE, 
										   CRYPT_ATTRIBUTE_NONE  );
	if( attributeListPtr == NULL || \
		!( attributeListPtr->intValue & CRYPT_KEYUSAGE_CRLSIGN ) )
		{
		/* The issuer can't sign CRLs */
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Make sure that there's a basicConstraints attribute present and that 
	   the issuer is a CA (PKIX section 4.2.1.10) */
	attributeListPtr = findAttributeField( issuerCertInfoPtr->attributes,
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL || !attributeListPtr->intValue )
		{
		setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/* Check the validity of a subject cert based on an issuer cert, with the 
   level of checking performed depending on the complianceLevel setting */

int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr,
			   const BOOLEAN shortCircuitCheck,
			   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			   CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const ATTRIBUTE_LIST *issuerAttributes = \
			( issuerCertInfoPtr != NULL ) ? issuerCertInfoPtr->attributes : NULL;
	ATTRIBUTE_LIST *attributeListPtr;
	const BOOLEAN selfSigned = ( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED );
	BOOLEAN subjectIsCA = FALSE, issuerIsCA = FALSE;
	const time_t currentTime = getTime();
	int complianceLevel, status;

	assert( isReadPtr( subjectCertInfoPtr, CERT_INFO ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* If it's some form of certificate request or an OCSP object (which means
	   it isn't signed by an issuer in the normal sense), there's nothing to 
	   check (yet) */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		return( CRYPT_OK );

	/* It's an issuer-signed object, there must be an issuer cert present
	   unless its a standalone single CRL entry that acts purely as a 
	   container for revocation data */
	assert( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			isReadPtr( issuerCertInfoPtr, CERT_INFO ) );

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( subjectCertInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're checking a CRL, call the special-case routine for this */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CRL )
		return( checkCRL( subjectCertInfoPtr, issuerCertInfoPtr, 
						  complianceLevel, errorLocus, errorType ) );

	/* There is one universal case in which a cert is regarded as an invalid 
	   issuer cert regardless of any special-case considerations for self-
	   signed/v1 certs, and that's when the cert is explicitly not trusted 
	   for this purpose */
	if( issuerCertInfoPtr->trustedUsage != CRYPT_ERROR && \
		!( issuerCertInfoPtr->trustedUsage & CRYPT_KEYUSAGE_KEYCERTSIGN ) )
		{
		/* The issuer can sign certs but is explicitly not trusted to do 
		   so */
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( selfSigned )
		{
		/* Check whether the issuer (== subject) is explicitly not trusted 
		   to sign itself */
		if( subjectCertInfoPtr->trustedUsage != CRYPT_ERROR && \
			!( subjectCertInfoPtr->trustedUsage & CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If we're not running in oblivious mode, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		return( CRYPT_OK );

	/* Check that the validity period is in order.  If we're checking an 
	   existing cert then the start time has to be valid, if we're creating
	   a new cert then it doesn't have to be valid since the cert could be
	   created for use in the future */
	if( currentTime < MIN_TIME_VALUE )
		{
		/* Time is broken, we can't reliably check for expiry times */
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( subjectCertInfoPtr->startTime >= subjectCertInfoPtr->endTime || \
		( subjectCertInfoPtr->certificate != NULL && \
		  currentTime < subjectCertInfoPtr->startTime ) )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( currentTime > subjectCertInfoPtr->endTime )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDTO, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If it's a self-signed cert or we're doing a short-circuit check of a 
	   cert in a chain that has already been checked, and we've already 
	   checked it at the appropriate level, there's no need to perform any 
	   further checks */
	if( ( selfSigned || shortCircuitCheck ) && \
		( subjectCertInfoPtr->maxCheckLevel >= complianceLevel ) )
		return( CRYPT_OK );

	/* If the cert isn't self-signed, check name chaining */
	if( !selfSigned )
		{
		/* Check that the subject issuer and issuer subject names chain
		   properly.  If the DNs are present in pre-encoded form, we do
		   a binary comparison, which is faster than calling compareDN() */
		if( subjectCertInfoPtr->certificate != NULL )
			{
			if( subjectCertInfoPtr->issuerDNsize != \
									issuerCertInfoPtr->subjectDNsize || \
				memcmp( subjectCertInfoPtr->issuerDNptr, 
						issuerCertInfoPtr->subjectDNptr, 
						subjectCertInfoPtr->issuerDNsize ) )
				{
				setErrorValues( CRYPT_CERTINFO_ISSUERNAME, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		else
			if( !compareDN( subjectCertInfoPtr->issuerName,
							issuerCertInfoPtr->subjectName, FALSE ) )
				{
				setErrorValues( CRYPT_CERTINFO_ISSUERNAME, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
		}

	/* Determine whether the subject or issuer are CA certs */
	attributeListPtr = findAttributeField( subjectAttributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		subjectIsCA = attributeListPtr->intValue;
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		issuerIsCA = attributeListPtr->intValue;

	/* If the issuer is a non self-signed v3 cert, check the issuer 
	   attributes/capabilities.  Note that this means that a self-signed 
	   cert has an implicitly permitted usage of keyCertSign for itself even 
	   if it's a non-CA cert (a Smith and Wesson beats four aces) */
	if( !selfSigned && issuerCertInfoPtr->version > 2 )
		{
		/* Make sure that the issuer has a key usage attribute present and 
		   can sign certs (PKIX section 4.2.1.3) */
		attributeListPtr = findAttributeField( issuerAttributes,
											   CRYPT_CERTINFO_KEYUSAGE, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr == NULL || \
			!( attributeListPtr->intValue & CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			/* The issuer can't sign certs */
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

		/* Make sure that there's a basicConstraints attribute present/the
		   issuer is a CA (PKIX section 4.2.1.10) */
		if( !issuerIsCA )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If we're doing a reduced level of checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		if( subjectCertInfoPtr->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* Check that the cert usage flags are present and consistent.  The key 
	   usage checking level ranges from CRYPT_COMPLIANCELEVEL_STANDARD to
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL so we re-do the check even if it's
	   already been done at a lower level */
	if( subjectCertInfoPtr->maxCheckLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
		subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		status = checkKeyUsageFlags( subjectCertInfoPtr, complianceLevel,
									 errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
        }

	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		{
		if( subjectCertInfoPtr->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* Check various CA vs. non-CA restrictions: Name, policy, and path-
	   length constraints can only be present in CA certs */
	if( !subjectIsCA )
		{
		if( checkAttributePresent( subjectAttributes, \
								   CRYPT_CERTINFO_NAMECONSTRAINTS ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( checkAttributePresent( subjectAttributes, \
								   CRYPT_CERTINFO_POLICYCONSTRAINTS ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( findAttributeField( subjectAttributes,
								CRYPT_CERTINFO_PATHLENCONSTRAINT, 
								CRYPT_ATTRIBUTE_NONE ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}
	if( !issuerIsCA )
		{
		if( checkAttributePresent( issuerAttributes, \
								   CRYPT_CERTINFO_NAMECONSTRAINTS ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( checkAttributePresent( issuerAttributes, \
								   CRYPT_CERTINFO_POLICYCONSTRAINTS ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, 
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( findAttributeField( issuerAttributes,
								CRYPT_CERTINFO_PATHLENCONSTRAINT, 
								CRYPT_ATTRIBUTE_NONE ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If there's a path length constraint present and set to zero, make 
	   sure that the subject is a non-CA cert */
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_PATHLENCONSTRAINT, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue <= 0 && \
		!selfSigned && subjectIsCA )
		{
		setErrorValues( CRYPT_CERTINFO_PATHLENCONSTRAINT,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're not doing full PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		{
		if( subjectCertInfoPtr->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* If the cert isn't self-signed and an issuer altname is present, check 
	   that it chains correctly.  No-one can quite agree on how chaining of 
	   altNames is really supposed to work, it's only their rarity that 
	   prevents this from being much of a problem */
	if( !selfSigned && \
		subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		const BOOLEAN boolean1 = checkAttributePresent( issuerAttributes,
											CRYPT_CERTINFO_SUBJECTALTNAME );
		const BOOLEAN boolean2 = checkAttributePresent( subjectAttributes,
											CRYPT_CERTINFO_ISSUERALTNAME );

		/* If present, the attribute must be present and match in both 
		   certs */
		if( boolean1 && !boolean2 )
			{ 
			setErrorValues( CRYPT_CERTINFO_ISSUERALTNAME, 
							CRYPT_ERRTYPE_CONSTRAINT ); 
			return( CRYPT_ERROR_INVALID );
			}
		if( boolean2 && !boolean1 )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( boolean1 && boolean2 )
			{
			const CRYPT_ATTRIBUTE_TYPE altNameComponent = \
										compareAltNames( subjectAttributes, 
														 issuerAttributes );
			if( altNameComponent != CRYPT_ATTRIBUTE_NONE )
				{
				setErrorValues( altNameComponent, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		}

	/* If the issuing cert has name constraints and isn't self-signed, make 
	   sure that the subject name and altName falls within the constrained 
	   subtrees.  Since excluded subtrees override permitted subtrees, we 
	   check these first */
	if( !selfSigned )
		{
		attributeListPtr = findAttributeField( issuerAttributes, 
											   CRYPT_CERTINFO_EXCLUDEDSUBTREES,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			if( cryptStatusError( \
				checkNameConstraints( subjectCertInfoPtr, attributeListPtr, 
									  TRUE, errorLocus, errorType ) ) )
				return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = findAttributeField( issuerAttributes, 
											   CRYPT_CERTINFO_PERMITTEDSUBTREES,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			if( cryptStatusError( \
				checkNameConstraints( subjectCertInfoPtr, attributeListPtr, 
									  FALSE, errorLocus, errorType ) ) )
				return( CRYPT_ERROR_INVALID );
			}
		}

	/* If there's a policy constraint present and the skip count is set to 
	   zero (i.e. the constraint applies to the current cert), check the 
	   issuer constraints against the subject */
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue <= 0 )
		{
		status = checkPolicyConstraints( subjectCertInfoPtr,
										 issuerAttributes,
										 errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	if( subjectCertInfoPtr->maxCheckLevel < complianceLevel )
		subjectCertInfoPtr->maxCheckLevel = complianceLevel;
	return( CRYPT_OK );
	}

/* Check that a certificate is valid for a particular purpose.  This is used
   mainly to check that contexts and certs are valid for key exchange/sig.
   generation/cert signing, and isn't as rigorous as the cert/issuer cert 
   check in checkCert().  In some instances we need to check for specific 
   types of usage that are dependant on the peculiarities of object types, 
   so if it's available we pass in the exact requested cryptlib-level usage 
   as well */

int checkCertUsage( const CERT_INFO *certInfoPtr, const int keyUsage,
					const MESSAGE_CHECK_TYPE exactUsage,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	const BOOLEAN isV1selfSigned = \
		( certInfoPtr->version == 1 && \
		  ( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ) ? TRUE : FALSE;
	int complianceLevel, status;

	assert( isReadPtr( certInfoPtr, CERT_INFO ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* PKCS #10 cert requests are special-case objects in that the key they 
	   contain is usable only for signature checking of the self-signature 
	   on the object (it can't be used for general-purpose usages, which 
	   would make it equivalent to a trusted self-signed cert).  This is 
	   problematic because the keyUsage may indicate that the key is valid 
	   for other things as well, or not valid for signature checking.  To 
	   get around this, we indicate that the key has a single trusted usage, 
	   signature checking, and disallow any other usage regardless of what 
	   the keyUsage says.  The actual keyUsage usage is only valid once the 
	   request has been converted into a cert */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		if( exactUsage == MESSAGE_CHECK_PKC_SIGCHECK )
			return( CRYPT_OK );
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE,
							  &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're looking for a CA cert, make sure that either the 
	   basicConstraints CA flag is set and the keyUsage indicates a CA usage,
	   or if there's no basicConstraints/keyUsage present that it's a v1 
	   self-signed cert (PKIX sections 4.2.1.3 and 4.2.1.10) */
	if( exactUsage == MESSAGE_CHECK_CA && \
		complianceLevel >= CRYPT_COMPLIANCELEVEL_REDUCED && \
		!isV1selfSigned )
		{
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_CA, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr == NULL || !attributeListPtr->intValue )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_KEYUSAGE, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr == NULL || \
			!( attributeListPtr->intValue & certInfoPtr->trustedUsage & \
				( CRYPT_KEYUSAGE_CRLSIGN | CRYPT_KEYUSAGE_KEYCERTSIGN ) ) )
			{
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Check and enforce the keyUsage if required */
	if( keyUsage != CRYPT_UNUSED )
		{
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_KEYUSAGE, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			const int trustedUsage = \
						attributeListPtr->intValue & certInfoPtr->trustedUsage;
			BOOLEAN usageOK = FALSE;

			/* If it's a key agreement usage the checking gets a bit complex, 
			   we have to make sure it's both a permitted usage and not an 
			   excluded usage */
			if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
				( keyUsage == CRYPT_KEYUSAGE_ENCIPHERONLY || \
				  keyUsage == CRYPT_KEYUSAGE_DECIPHERONLY ) )
				{
				const int excludedUsage = \
					( keyUsage == CRYPT_KEYUSAGE_ENCIPHERONLY ) ? \
					CRYPT_KEYUSAGE_DECIPHERONLY : CRYPT_KEYUSAGE_ENCIPHERONLY;

				if( ( trustedUsage & keyUsage ) && \
					!( trustedUsage & excludedUsage ) )
					usageOK = TRUE;
				}
			else
				/* Conventional usage flag, do a straight check */
				if( trustedUsage & keyUsage )
					usageOK = TRUE;
			if( !usageOK )
				{
				setErrorValues( ( attributeListPtr->intValue & keyUsage ) ? \
									CRYPT_CERTINFO_TRUSTED_USAGE : \
									CRYPT_CERTINFO_KEYUSAGE,
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		else
			{
			/* There is one special case in which a cert with no explicit 
			   key usage can't be used for a particular purpose and that's 
			   when the cert is explicitly not trusted for the purpose */
			if( !( certInfoPtr->trustedUsage & keyUsage ) )
				{
				setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		}

	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If we're being asked for a private-key op, check and enforce the 
	   privateKeyUsage attribute if there's one present */
	if( ( exactUsage == MESSAGE_CHECK_PKC_PRIVATE || \
		  exactUsage == MESSAGE_CHECK_PKC_DECRYPT || \
		  exactUsage == MESSAGE_CHECK_PKC_SIGN ) && \
		findAttributeField( certInfoPtr->attributes,
							CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD, 
							CRYPT_ATTRIBUTE_NONE ) != NULL )
		{
		const time_t currentTime = getTime();

		if( currentTime < MIN_TIME_VALUE )
			{
			/* Time is broken, we can't reliably check for expiry times */
			setErrorValues( CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			currentTime < *( ( time_t * ) attributeListPtr->value ) )
			{
			setErrorValues( CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			currentTime > *( ( time_t * ) attributeListPtr->value ) )
			{
			setErrorValues( CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	return( CRYPT_OK );
	}
