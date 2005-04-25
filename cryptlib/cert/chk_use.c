/****************************************************************************
*																			*
*						Certificate Usage Checking Routines					*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
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
	serverAuth			 S		 E		KA					[1]
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
	sslServer			 S		 E							[1]
	sMime				 S		 E
	objectSign			 Y
	sslCA                               	 Y	 w
	sMimeCA									 Y	 w
	objectSignCA							 Y	 w
						-----------------------------------
						dig	non	key	dat	key	cer	crl	enc	dec
						sig	rep	enc	enc	agt	sig	sig	onl	onl

   [1] These keys need to potentially perform both decryption for RSA key 
       transport and signing for (authenticating) DH key agreement */

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
   and no-one can agree on what non-repudiation is supposed to mean */

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
	{ CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,/* individualCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,/* commercialCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,/* certTrustListSigning */
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
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_KEYENCIPHERMENT },
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

/* Build up key usage flags consistent with the extended key usage purpose.  
   We don't have to perform any special-case handling for 
   anyExtendedKeyUsage (added in RFC 3280, section 4.2.1.13) since it's a 
   no-op extension whose presence is the equivalent of adding "|| TRUE" to 
   an expression */

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

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

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
		/* We only have to set the error type at this point since the error
		   locus was set when we got the key usage flags */
		*errorType = CRYPT_ERRTYPE_CONSTRAINT;
		return( CRYPT_ERROR_INVALID );
		}

	return( keyUsage );
	}

/****************************************************************************
*																			*
*								Check Key/Cert Usage						*
*																			*
****************************************************************************/

/* Check that a certificate/key is valid for a particular purpose.  This is 
   used both to check that contexts/certs are valid for key exchange/sig.
   generation/cert signing, and as a part of the chk_cert.c checking 
   process */

int checkKeyUsage( const CERT_INFO *certInfoPtr,
				   const int flags, const int specificUsage, 
				   const int complianceLevel, 
				   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
				   CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN keyUsageCritical = 0;
	BOOLEAN isCA = FALSE;
	const int trustedUsage = \
				( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? \
				certInfoPtr->cCertCert->trustedUsage : CRYPT_ERROR;
	int keyUsage, rawKeyUsage, extKeyUsage, rawExtKeyUsage;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( ( flags & CHECKKEY_FLAG_CA ) && \
			  ( specificUsage & ( CRYPT_KEYUSAGE_KEYCERTSIGN | \
								  CRYPT_KEYUSAGE_CRLSIGN ) ) ) || \
			( !( flags & CHECKKEY_FLAG_CA ) && \
			  ( ( specificUsage & ( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
									CRYPT_KEYUSAGE_KEYENCIPHERMENT | \
									CRYPT_KEYUSAGE_KEYAGREEMENT ) ) || \
				( specificUsage == CRYPT_UNUSED ) ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* There is one universal case in which a key is regarded as invalid for
	   the requested use and that's when it's explicitly not trusted for the 
	   purpose.  Note that this check (in oblivious mode) differs slightly
	   from the later check (in reduced mode or higher) in that in oblivious
	   mode we ignore the cert's actual key usage and check only the 
	   requested against trusted usage */
	if( specificUsage != CRYPT_UNUSED && trustedUsage != CRYPT_ERROR && \
		!( trustedUsage & specificUsage ) )
		{
		/* The issuer is explicitly not trusted to perform the requested 
		   operation */
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're running in oblivious mode, there's nothing else to check */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		return( CRYPT_OK );

	/* Obtain assorted cert information */
	attributeListPtr = findAttributeField( certInfoPtr->attributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		isCA = attributeListPtr->intValue;
	extKeyUsage = getKeyUsageFromExtKeyUsage( certInfoPtr, errorLocus, 
											  errorType );
	if( cryptStatusError( extKeyUsage ) )
		return( extKeyUsage );

	/* If it's a v1 self-signed cert the CA status and key usage is 
	   implicit/undefined */
	if( certInfoPtr->version == 1 && \
		( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
		{
		/* If it's claiming to be a CA cert by virtue of being a v1 self-
		   signed cert, there can't be any v3 CA attributes (or any v3
		   attributes for that matter) present.  Unfortunately we can't just 
		   check for the complete non-presence of attributes because the 
		   cert-import code will have converted an email address in the DN
		   into the appropriate altName component, creating at least one
		   valid (in this case) attribute */
		if( checkAttributePresent( certInfoPtr->attributes, 
								   CRYPT_CERTINFO_BASICCONSTRAINTS ) || \
			checkAttributePresent( certInfoPtr->attributes, 
								   CRYPT_CERTINFO_KEYUSAGE ) || \
			extKeyUsage != 0 )
			{
			setErrorValues( CRYPT_CERTINFO_VERSION, 
							CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INVALID );
			}

		/* It's a v1 self-signed cert with no keyUsage present, don't
		   perform any usage-specific checks */
		return( CRYPT_OK );
		}

	/* Get the cert's keyUsage */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_KEYUSAGE, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		keyUsage = attributeListPtr->intValue;
		keyUsageCritical = \
			( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ? TRUE : FALSE;
		}
	else
		{
		/* If we're doing a PKIX-compliant check, we need a keyUsage (PKIX 
		   section 4.2.1.3).  RFC 2459 left this optional, RC 3280 made it
		   mandatory for CA certs, we always require it at this level of
		   checking (no doubt the next PKIX revision will make it mandatory
		   in EE certs as well) */
		if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
			{
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_INVALID );
			}

		/* Some broken certs don't have any keyUsage present, if there's
		   nothing there allow at least some minimal usage.  Note that this 
		   is a non-CA usage, so setting it doesn't interfere with the CA 
		   keyUsage checks below.
		
		   Some even more broken certs indicate their usage via a Netscape 
		   key usage (even though they use X.509 flags everywhere else), 
		   which means that we fail them if we're strictly applying the PKIX 
		   requirements at a higher compliance level.  At this lower level,
		   fixAttributes() will have mapped the Netscape usage to the
		   equivalent X.509 usage, so there's always a keyUsage present */
		keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE;
		}

	/* Apply the trusted-usage restrictions if necessary */
	rawKeyUsage = keyUsage;
	rawExtKeyUsage = extKeyUsage;
	if( trustedUsage != CRYPT_ERROR )
		{
		keyUsage &= trustedUsage;
		extKeyUsage &= trustedUsage;
		}

	/* If we're looking for a CA cert, make sure that the basicConstraints 
	   CA flag is set and the keyUsage indicates a CA usage (PKIX sections 
	   4.2.1.3 and 4.2.1.10).  RFC 2459 left this open, it was made explicit 
	   in RFC 3280 */
	if( flags & CHECKKEY_FLAG_CA )
		{
		if( !isCA )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( !( keyUsage & specificUsage & ( CRYPT_KEYUSAGE_CRLSIGN | \
											CRYPT_KEYUSAGE_KEYCERTSIGN ) ) )
			{
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* There is one universal case in which a key is regarded as invalid for
	   the requested use and that's when it's explicitly not trusted for the 
	   purpose */
	if( specificUsage != CRYPT_UNUSED && trustedUsage != CRYPT_ERROR && \
		!( specificUsage & keyUsage ) )
		{
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE,
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're doing a reduced level of checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_STANDARD )
		return( CRYPT_OK );

	/* If the CA flag is set, make sure that there's a keyUsage with one of 
	   the CA usages present.  Conversely, if there are CA key usages 
	   present, make sure that the CA flag is set.  The CA flag is actually a 
	   leftover from an early v3 cert concept and is made entirely redundant 
	   by the keyUsage flags, but we have to check it regardless (PKIX 
	   section 4.2.1.10).  RFC 2459 left this open, it was made explicit in
	   RFC 3280 */
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
		if( ( extKeyUsage | keyUsage ) & ( CRYPT_KEYUSAGE_CRLSIGN | \
										   CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			setErrorValues( CRYPT_CERTINFO_CA, CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

	/* Check and enforce the keyUsage if required (PKIX section 4.2.1.3).  
	   RFC 2459 included some waffly text about critical vs. non-critical 
	   usage, RFC 3280 made this explicit regardless of criticality */
	if( specificUsage != CRYPT_UNUSED )
		{
		BOOLEAN usageOK = FALSE;

		/* If it's a key agreement usage the checking gets a bit complex, we 
		   have to make sure that it's both a permitted usage and not an 
		   excluded usage */
		if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
			( specificUsage & ( CRYPT_KEYUSAGE_ENCIPHERONLY | \
								CRYPT_KEYUSAGE_DECIPHERONLY ) ) )
			{
			const int excludedUsage = \
					( specificUsage & CRYPT_KEYUSAGE_ENCIPHERONLY ) ? \
					CRYPT_KEYUSAGE_DECIPHERONLY : CRYPT_KEYUSAGE_ENCIPHERONLY;

			if( ( keyUsage & specificUsage ) && !( keyUsage & excludedUsage ) )
				usageOK = TRUE;
			}
		else
			/* Conventional usage flag, do a straight check */
			if( keyUsage & specificUsage )
				usageOK = TRUE;
		if( !usageOK )
			{
			setErrorValues( ( rawKeyUsage & specificUsage ) ? \
								CRYPT_CERTINFO_TRUSTED_USAGE : \
								CRYPT_CERTINFO_KEYUSAGE,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Switch back to the original usage values (before adjustment by 
	   trusted-usage values) because after this point we're performing 
	   consistency checks on the values and need to check all of the bits */
	keyUsage = rawKeyUsage;
	extKeyUsage = rawExtKeyUsage;
	   		
	/* Make sure that mutually exclusive flags aren't set */
	if( ( keyUsage & CRYPT_KEYUSAGE_ENCIPHERONLY ) && \
		( keyUsage & CRYPT_KEYUSAGE_DECIPHERONLY ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}

	/* Make sure that the keyUsage flags represent capabilities that the 
	   algorithm is actually capable of.  RFC 2459 included some waffly text
	   about critical vs. non-critical usage, RFC 3280 made this explicit
	   regardless of criticality */
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
	keyUsage &= ~USAGE_MASK_NONRELEVANT;
	extKeyUsage &= ~USAGE_MASK_NONRELEVANT;

	/* If there's no key usage based on extended key usage present, there's 
	   nothing further to check */
	if( !extKeyUsage || complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If the usage and extended usage are critical (but only if both are 
	   critical, because PKIX says so) make sure that the given usage is 
	   consistent with the required usage (PKIX section 4.2.1.13).  To 
	   perform this check we first check for situations where we *don't* 
	   have to perform the check, and only if none of these occur do we 
	   perform the actual check.
	   
	   Checking whether the extended usage is critical is a bit nontrivial, 
	   we have to check each possible extended usage since only one of them 
	   may be present, so we check the criticality of the basic key usage 
	   first to allow quick short-circuit evaluation.
	   
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

		/* If there's no critical key usage present we can exit without
		   performing further checks */
		if( !keyUsageCritical )
			return( CRYPT_OK );

		/* If we find an extended key usage and it's non-critical (which 
		   means that all extended usages are non-critical since they're
		   all in the same extension), return */
		for( attributeID = CRYPT_CERTINFO_EXTKEYUSAGE + 1; 
			 attributeID < CRYPT_CERTINFO_NS_CERTTYPE; attributeID++ )
			{
			attributeListPtr = findAttributeField( certInfoPtr->attributes,
										attributeID, CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr != NULL && \
				!( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) )
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

	/* If the encipherOnly or decipherOnly bits are set, the keyAgreement 
	   bit most also be set (PKIX section 4.2.1.3).  Actually the spec 
	   merely says "undefined", but we interpret this to mean that they 
	   should be consistent.  This situation occurs because the encipher/
	   decipher-only usages were tacked on as modifiers long after 
	   keyAgreement was defined and make it entirely redundant, in the same 
	   way that the CA keyUsages make the basicConstraints CA flag 
	   redundant */
	if( ( keyUsage & ( CRYPT_KEYUSAGE_ENCIPHERONLY | \
					   CRYPT_KEYUSAGE_DECIPHERONLY ) ) && \
		!( keyUsage & CRYPT_KEYUSAGE_KEYAGREEMENT ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're being asked to check for private-key constraints, check and 
	   enforce the privateKeyUsage attribute if there's one present */
	if( ( flags & CHECKKEY_FLAG_PRIVATEKEY ) && \
		checkAttributePresent( certInfoPtr->attributes,
							   CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD ) )
		{
		const time_t currentTime = getTime();

		if( currentTime < MIN_TIME_VALUE )
			{
			/* Time is broken, we can't reliably check for expiry times */
			setErrorValues( CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = \
					findAttributeField( certInfoPtr->attributes,
										CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, 
										CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			currentTime < *( ( time_t * ) attributeListPtr->value ) )
			{
			setErrorValues( CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = \
					findAttributeField( certInfoPtr->attributes,
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
