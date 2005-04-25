/****************************************************************************
*																			*
*							Message ACLs Handlers							*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* A pointer to the kernel data block */

static KERNEL_DATA *krnlData = NULL;

/****************************************************************************
*																			*
*									Message ACLs							*
*																			*
****************************************************************************/

/* Compare ACL for compare messages */

static const FAR_BSS COMPARE_ACL compareACLTbl[] = {
	/* Hash/MAC value */
	{ MESSAGE_COMPARE_HASH,
	  MK_CMPACL_S( ST_CTX_HASH | ST_CTX_MAC, 
				   16, CRYPT_MAX_HASHSIZE ) },

	/* PKC keyID */
	{ MESSAGE_COMPARE_KEYID,
	  MK_CMPACL_S( ST_CTX_PKC, 
				   2, 128 ) },

	/* PGP keyID */
	{ MESSAGE_COMPARE_KEYID_PGP,
	  MK_CMPACL_S( ST_CTX_PKC, 
				   PGP_KEYID_SIZE, PGP_KEYID_SIZE ) },

	/* OpenPGP keyID */
	{ MESSAGE_COMPARE_KEYID_OPENPGP,
	  MK_CMPACL_S( ST_CTX_PKC, 
				   PGP_KEYID_SIZE, PGP_KEYID_SIZE ) },

	/* X.509 subject DN */
	{ MESSAGE_COMPARE_SUBJECT,
	  MK_CMPACL_S( ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN, 
				   2, MAX_ATTRIBUTE_SIZE ) },

	/* PKCS #7 issuerAndSerialNumber */
	{ MESSAGE_COMPARE_ISSUERANDSERIALNUMBER,
	  MK_CMPACL_S( ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN, 
				   2, MAX_ATTRIBUTE_SIZE ) },

	/* Cert SHA-1 fingerprint */
	{ MESSAGE_COMPARE_FINGERPRINT,
	  MK_CMPACL_S( ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN, 
				   20, 20 ) },

	/* Certificate object */
	{ MESSAGE_COMPARE_CERTOBJ,
	  MK_CMPACL_O( ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN, 
				   ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN ) },

	/* End-of-ACL marker */
	{ MESSAGE_COMPARE_NONE,
	  MK_CMPACL_END() }
	};

/* Check ACL for check messages */

#define PUBKEY_CERT_OBJECT		( ST_CERT_CERT | ST_CERT_ATTRCERT | \
								  ST_CERT_CERTCHAIN | ST_CERT_CERTREQ | \
								  ST_CERT_REQ_CERT )
#define PUBKEY_KEYSET_OBJECT	( ST_KEYSET_FILE | ST_KEYSET_FILE_PARTIAL | \
								  ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE | \
								  ST_KEYSET_HTTP | ST_KEYSET_LDAP | \
								  ST_DEV_FORT | ST_DEV_P11 | ST_DEV_CAPI )
#define PRIVKEY_KEYSET_OBJECT	( ST_KEYSET_FILE | ST_KEYSET_FILE_PARTIAL | \
								  ST_DEV_FORT | ST_DEV_P11 | ST_DEV_CAPI )

static const FAR_BSS CHECK_ACL checkACLTbl[] = {
	/* PKC actions.  These get somewhat complex to check because the primary
	   message target may be a context or cert object with an associated 
	   public key, so we have to allow both object types */
	{ MESSAGE_CHECK_PKC,			/* Public or private key context */
	  MK_CHKACL( MESSAGE_NONE, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_PRIVATE,	/* Private key context */
	  MK_CHKACL( MESSAGE_NONE, 
				 ST_CTX_PKC | ST_CERT_CERT | ST_CERT_CERTCHAIN ) },

	{ MESSAGE_CHECK_PKC_ENCRYPT,	/* Public encryption context */
	  MK_CHKACL( MESSAGE_CTX_ENCRYPT, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_DECRYPT,	/* Private decryption context */
	  MK_CHKACL( MESSAGE_CTX_DECRYPT, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_SIGCHECK,	/* Public signature check context */
	  MK_CHKACL( MESSAGE_CTX_SIGCHECK, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_SIGN,		/* Private signature context */
	  MK_CHKACL( MESSAGE_CTX_SIGN, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_KA_EXPORT,	/* Key agreement - export context */
	  MK_CHKACL( MESSAGE_NONE, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	{ MESSAGE_CHECK_PKC_KA_IMPORT,	/* Key agreement - import context */
	  MK_CHKACL( MESSAGE_NONE, 
				 ST_CTX_PKC | PUBKEY_CERT_OBJECT ) },

	/* Conventional encryption/hash/MAC actions */
	{ MESSAGE_CHECK_CRYPT,			/* Conventional encryption capability */
	  MK_CHKACL( MESSAGE_CTX_ENCRYPT, 
				 ST_CTX_CONV ) },

	{ MESSAGE_CHECK_HASH,			/* Hash capability */
	  MK_CHKACL( MESSAGE_CTX_HASH, 
				 ST_CTX_HASH ) },

	{ MESSAGE_CHECK_MAC,			/* MAC capability */
	  MK_CHKACL( MESSAGE_CTX_HASH, 
				 ST_CTX_MAC ) },

	/* Checks that an object is ready to be initialised to perform this
	   operation */
	{ MESSAGE_CHECK_CRYPT_READY,	/* Ready for init for conv.encr.*/
	  MK_CHKACL_EX( MESSAGE_CTX_ENCRYPT, 
					ST_CTX_CONV, ACL_FLAG_LOW_STATE ) },

	{ MESSAGE_CHECK_MAC_READY,		/* Ready for init for MAC */
	  MK_CHKACL_EX( MESSAGE_CTX_HASH, 
					ST_CTX_MAC, ACL_FLAG_LOW_STATE ) },

	{ MESSAGE_CHECK_KEYGEN_READY,	/* Ready for init key generation */
	  MK_CHKACL_EX( MESSAGE_CTX_GENKEY, 
					ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ACL_FLAG_LOW_STATE ) },

	/* Checks on purely passive container objects that constrain action 
	   objects (for example a cert being attached to a context) for which 
	   the state isn't important in this instance.  Usually we check to make 
	   sure that the cert is in the high state, but when a cert is being 
	   created/imported it may not be in the high state yet at the time the 
	   check is being carried out.
	   
	   In addition to certs the message can be sent to a keyset to check 
	   whether it contains keys capable of performing the required action */
	{ MESSAGE_CHECK_PKC_ENCRYPT_AVAIL,	/* Encryption available */
	  MK_CHKACL_EX( MESSAGE_CTX_ENCRYPT, 
					PUBKEY_CERT_OBJECT | PUBKEY_KEYSET_OBJECT, 
					ACL_FLAG_ANY_STATE ) },

	{ MESSAGE_CHECK_PKC_DECRYPT_AVAIL,	/* Decryption available */
	  MK_CHKACL_EX( MESSAGE_CTX_DECRYPT, 
					PUBKEY_CERT_OBJECT | PRIVKEY_KEYSET_OBJECT,
					ACL_FLAG_ANY_STATE ) },

	{ MESSAGE_CHECK_PKC_SIGCHECK_AVAIL,	/* Signature check available */
	  MK_CHKACL_EX( MESSAGE_CTX_SIGCHECK, 
					PUBKEY_CERT_OBJECT | PUBKEY_KEYSET_OBJECT,
					ACL_FLAG_ANY_STATE ) },
	
	{ MESSAGE_CHECK_PKC_SIGN_AVAIL,		/* Signature available */
	  MK_CHKACL_EX( MESSAGE_CTX_SIGN, 
					PUBKEY_CERT_OBJECT | PRIVKEY_KEYSET_OBJECT,
					ACL_FLAG_ANY_STATE ) },

	{ MESSAGE_CHECK_PKC_KA_EXPORT_AVAIL,/* Key agreement - export available */
	  MK_CHKACL_EX( MESSAGE_NONE, 
					PUBKEY_CERT_OBJECT, ACL_FLAG_ANY_STATE ) },

	{ MESSAGE_CHECK_PKC_KA_IMPORT_AVAIL,/* Key agreement - import available */
	  MK_CHKACL_EX( MESSAGE_NONE, 
					PUBKEY_CERT_OBJECT, ACL_FLAG_ANY_STATE ) },

	/* Misc.actions.  The CA capability is spread across certs (the CA flag) 
	   and contexts (the signing capability) */
	{ MESSAGE_CHECK_CA,				/* Cert signing capability */
	  MK_CHKACL_ALT( MESSAGE_CTX_SIGN, MESSAGE_CTX_SIGCHECK, 
					 ST_CTX_PKC | ST_CERT_CERT | ST_CERT_ATTRCERT | ST_CERT_CERTCHAIN ) },

	/* End-of-ACL marker */
	{ MESSAGE_CHECK_NONE,
	  MK_CHKACL_END() }
	};

/* When we export a cert the easiest way to handle the export check is via
   a pseudo-ACL that's checked via the standard attribute ACL-checking
   function.  The following ACL handles cert exports */

static const FAR_BSS ATTRIBUTE_ACL_ALT formatPseudoACL[] = {
	/* Encoded cert data */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* Encoded cert.chain */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* Base64-encoded certificate */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_TEXT_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* Base64-encoded cert.chain */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_TEXT_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	
	/* XML-encoded certificate */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_XML_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* XML-encoded cert.chain */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_XML_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* SET OF cert in chain */
	MKACL_S_ALT(
		CRYPT_ICERTFORMAT_CERTSET,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),

	/* SEQUENCE OF cert in chain */
	MKACL_S_ALT(
		CRYPT_ICERTFORMAT_CERTSEQUENCE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),

	/* SSL certificate chain */
	MKACL_S_ALT(
		CRYPT_ICERTFORMAT_SSL_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),

	/* Encoded non-signed object data.  We allow this attribute to be read 
	   for objects in the high as well as the low state even though in 
	   theory it's only present for low (non-signed) objects because the 
	   object can be in the high state if it was imported from its external 
	   encoded form */
	MKACL_S_ALT(	
		CRYPT_ICERTFORMAT_DATA,
		ST_CERT_CMSATTR | ST_CERT_REQ_REV | ST_CERT_RTCS_REQ | \
			ST_CERT_RTCS_RESP | ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),

	/* End-of-ACL marker */
	MKACL_S_ALT(
		CRYPT_CERTFORMAT_NONE, ST_NONE, ST_NONE, ACCESS_xxx_xxx, 
		ROUTE( OBJECT_TYPE_NONE ), RANGE( 0, 0 ) ),
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check whether a numeric value falls within a range */

static BOOLEAN checkNumericRange( const int value, const int lowRange, 
								  const int highRange )
	{
	/* Precondition: The range values are either both negative or both 
	   positive.  This is needed for the range comparison to work */
	PRE( ( lowRange < 0 && highRange < 0 ) || \
		 ( lowRange >= 0 && highRange >= 0 ) );

	/* Check whether the value is within the allowed range.  Since some 
	   values can be negative (e.g. cursor movement codes) we have to 
	   reverse the range check for negative values */
	if( lowRange >= 0 )
		{
		/* Positive, it's a standard comparison */
		if( value >= lowRange && value <= highRange )
			return( TRUE );
		}
	else
		{
		PRE( highRange <= lowRange );

		/* Negative, reverse the comparison */
		if( value >= highRange && value <= lowRange )
			return( TRUE );
		}

	return( FALSE );
	}

/* Check whether a numeric value falls within a special-case range type */

static BOOLEAN checkAttributeRangeSpecial( const RANGEVAL_TYPE rangeType,
										   const void *rangeInfo,
										   const int value )
	{
	/* Precondition: The range checking information is valid */
	PRE( rangeType > RANGEVAL_NONE && rangeType < RANGEVAL_LAST );
	PRE( rangeInfo != NULL );

	/* RANGEVAL_ALLOWEDVALUES contains an int [] of permitted values,
	   terminated by CRYPT_ERROR */
	if( rangeType == RANGEVAL_ALLOWEDVALUES )
		{
		const int *allowedValuesInfo = rangeInfo;
		int i;

		for( i = 0; allowedValuesInfo[ i ] != CRYPT_ERROR; i++ )
			{
			INV( i < 5 );
			if( value == allowedValuesInfo[ i ] )
				return( TRUE );
			}
		return( FALSE );
		}

	/* RANGEVAL_SUBRANGES contains a SUBRANGE [] of allowed subranges,
	   terminated by { CRYPT_ERROR, CRYPT_ERROR } */
	if( rangeType == RANGEVAL_SUBRANGES )
		{
		const RANGE_SUBRANGE_TYPE *allowedValuesInfo = rangeInfo;
		int i;

		for( i = 0; allowedValuesInfo[ i ].lowRange != CRYPT_ERROR; i++ )
			{
			INV( i < 5 );
			if( checkNumericRange( value, allowedValuesInfo[ i ].lowRange, 
								   allowedValuesInfo[ i ].highRange ) )
				return( TRUE );
			}
		return( FALSE );
		}

	assert( NOTREACHED );
	return( FALSE );		/* Get rid of compiler warning */
	}

/* Check whether a string value falls within the given limits, with special
   handling for widechar strings.  This sort of thing really shouldn't be
   in the kernel, but not having it here makes correct string length range 
   checking difficult */

static BOOLEAN checkAttributeRangeWidechar( const void *value,
											const int valueLength,
											const int minLength,
											const int maxLength )
	{
#ifdef USE_WIDECHARS
	const wchar_t *wcString = value;

	/* If it's not a multiple of wchar_t in size or smaller than a
	   wchar_t, it can't be a widechar string */
	if( ( valueLength % WCSIZE ) || ( valueLength < WCSIZE ) )
		return( ( valueLength < minLength || valueLength > maxLength ) ? \
				FALSE : TRUE );

	/* If wchar_t is > 16 bits and the bits above 16 are all zero, it's
	   definitely a widechar string */
#if INT_MAX > 0xFFFFL
	if( WCSIZE > 2 && *wcString < 0xFFFF )
		return( ( valueLength < ( minLength * WCSIZE ) || \
				  valueLength > ( maxLength * WCSIZE ) ) ? \
				FALSE : TRUE );
#endif /* > 16-bit machines */

	/* Now it gets tricky.  The only thing that we can still safely check
	   for is something that's been bloated out into widechars from ASCII */
	if( ( valueLength > WCSIZE * 2 ) && \
		( wcString[ 0 ] < 0xFF && wcString[ 1 ] < 0xFF ) )
		return( ( valueLength < ( minLength * WCSIZE ) || \
				  valueLength > ( maxLength * WCSIZE ) ) ? \
				FALSE : TRUE );
#endif /* USE_WIDECHARS */

	/* It's not a widechar string or we can't handle these, perform a
	   straight range check */
	return( ( valueLength < minLength || valueLength > maxLength ) ? \
			FALSE : TRUE );
	}

/* Check whether a given action is permitted for an object */

static int checkActionPermitted( const OBJECT_INFO *objectInfoPtr,
								 const MESSAGE_TYPE message )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	int requiredLevel, actualLevel;

	/* Determine the required level for access.  Like protection rings, the
	   lower the value, the higher the privilege level.  Level 3 is all-access,
	   level 2 is internal-access only, level 1 is no access, and level 0 is
	   not-available (e.g. encryption for hash contexts) */
	requiredLevel = objectInfoPtr->actionFlags & \
					MK_ACTION_PERM( localMessage, ACTION_PERM_MASK );

	/* Make sure that the action is enabled at the required level */
	if( message & MESSAGE_FLAG_INTERNAL )
		/* It's an internal message, the minimal permissions will do */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_NONE_EXTERNAL );
	else
		/* It's an external message, we need full permissions for access */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_ALL );
	if( requiredLevel < actualLevel )
		{
		/* The required level is less than the actual level (e.g. level 2 
		   access attempted from level 3), return more detailed information 
		   about the problem */
		return( ( ( requiredLevel >> ACTION_PERM_SHIFT( localMessage ) ) == ACTION_PERM_NOTAVAIL ) ? \
				CRYPT_ERROR_NOTAVAIL : CRYPT_ERROR_PERMISSION );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

int initMessageACL( KERNEL_DATA *krnlDataPtr )
	{
	int i;

	/* Perform a consistency check on the compare ACL */
	for( i = 0; compareACLTbl[ i ].compareType != MESSAGE_COMPARE_NONE; i++ )
		{
		const COMPARE_ACL *compareACL = &compareACLTbl[ i ];

		if( compareACL->compareType <= MESSAGE_COMPARE_NONE || \
			compareACL->compareType >= MESSAGE_COMPARE_LAST || \
			compareACL->compareType != i + 1 )
			return( CRYPT_ERROR_FAILED );
		if( ( compareACL->objectACL.subTypeA & ~( SUBTYPE_CLASS_A | \
												  ST_CTX_ANY | ST_CERT_ANY ) ) || \
			compareACL->objectACL.subTypeB != ST_NONE )
			return( CRYPT_ERROR_FAILED );
		if( ( compareACL->objectACL.flags != 0 ) && \
			( compareACL->objectACL.flags != ACL_FLAG_HIGH_STATE ) )
			return( CRYPT_ERROR_FAILED );
		if( paramInfo( compareACL, 0 ).valueType == PARAM_VALUE_STRING )
			{
			if( paramInfo( compareACL, 0 ).lowRange < 2 || \
				paramInfo( compareACL, 0 ).lowRange > \
					paramInfo( compareACL, 0 ).highRange || \
				paramInfo( compareACL, 0 ).highRange > MAX_ATTRIBUTE_SIZE ) 
				return( CRYPT_ERROR_FAILED );
			}
		else
			{
			if( paramInfo( compareACL, 0 ).valueType != PARAM_VALUE_OBJECT )
				return( CRYPT_ERROR_FAILED );
			if( ( paramInfo( compareACL, 0 ).subTypeA & ~( SUBTYPE_CLASS_A | \
														   ST_CERT_ANY ) ) || \
				paramInfo( compareACL, 0 ).subTypeB != ST_NONE )
				return( CRYPT_ERROR_FAILED );
			}
		}

	/* Perform a consistency check on the check ACL */
	for( i = 0; checkACLTbl[ i ].checkType != MESSAGE_CHECK_NONE; i++ )
		{
		const CHECK_ACL *checkACL = &checkACLTbl[ i ];
		int actionIndex;

		if( checkACL->checkType <= MESSAGE_CHECK_NONE || \
			checkACL->checkType >= MESSAGE_CHECK_LAST || \
			checkACL->checkType != i + 1 )
			return( CRYPT_ERROR_FAILED );
		for( actionIndex = 0; \
			 checkACL->actionType[ actionIndex ] != MESSAGE_NONE; \
			 actionIndex++ )
			{
			if( actionIndex >= 2 )
				return( CRYPT_ERROR_FAILED );
			if( checkACL->actionType[ actionIndex ] != MESSAGE_NONE && \
				( checkACL->actionType[ actionIndex ] < MESSAGE_CTX_ENCRYPT || \
				  checkACL->actionType[ actionIndex ] > MESSAGE_CRT_SIGCHECK ) )
				return( CRYPT_ERROR_FAILED );
			}
		if( ( checkACL->objectACL.subTypeA & \
					~( SUBTYPE_CLASS_A | ST_CTX_ANY | ST_CERT_ANY | \
										 ST_KEYSET_ANY | ST_DEV_ANY ) ) || \
			checkACL->objectACL.subTypeB != ST_NONE )
			return( CRYPT_ERROR_FAILED );
		if( checkACL->objectACL.flags & ~ACL_FLAG_ANY_STATE )
			return( CRYPT_ERROR_FAILED );
		}

	/* Perform a consistency check on the cert export pseudo-ACL */
	for( i = 0; formatPseudoACL[ i ].attribute != CRYPT_CERTFORMAT_NONE; i++ )
		{
		const ATTRIBUTE_ACL_ALT *formatACL = &formatPseudoACL[ i ];

		if( formatACL->attribute <= CRYPT_CERTTYPE_NONE || \
			formatACL->attribute >= CRYPT_CERTTYPE_LAST )
			return( CRYPT_ERROR_FAILED );
		if( ( formatACL->subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_ANY ) ) || \
			formatACL->subTypeB != ST_NONE )
			return( CRYPT_ERROR_FAILED );
		if( formatACL->attribute < CRYPT_CERTFORMAT_LAST_EXTERNAL )
			{
			if( formatACL->access != ACCESS_Rxx_xxx )
				return( CRYPT_ERROR_FAILED );
			}
		else
			{
			if( formatACL->access != ACCESS_INT_Rxx_xxx && \
				formatACL->access != ACCESS_INT_Rxx_Rxx )
				return( CRYPT_ERROR_FAILED );
			}
		if( formatACL->valueType != ATTRIBUTE_VALUE_STRING || \
			formatACL->lowRange < 16 || \
			formatACL->lowRange >= formatACL->highRange || \
			formatACL->highRange > 8192 || \
			formatACL->extendedInfo != NULL )
			return( CRYPT_ERROR_FAILED );
		}

	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	return( CRYPT_OK );
	}

void endMessageACL( void )
	{
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*							Message Pre-dispatch Handlers					*
*																			*
****************************************************************************/

/* If it's a destroy object message, adjust the reference counts of any
   dependent objects and set the object's state to signalled.  We do this 
   before we send the destroy message to the object in order that any 
   further attempts to access it will fail.  This is handled anyway by the
   message dispatcher, but setting the status to signalled now means that
   it's rejected immediately rather than being enqueued and then dequeued
   again once the destroy message has been processed */

int preDispatchSignalDependentObjects( const int objectHandle,
									   const MESSAGE_TYPE message,
									   const void *messageDataPtr,
									   const int messageValue,
									   const void *dummy )
	{
	OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];

	/* Precondition */
	PRE( isValidObject( objectHandle ) && \
		 objectHandle >= NO_SYSTEM_OBJECTS );

	if( isValidObject( objectInfoPtr->dependentDevice ) )
		/* Velisurmaaja */
		decRefCount( objectInfoPtr->dependentDevice, 0, NULL, TRUE );
	if( isValidObject( objectInfoPtr->dependentObject ) )
		decRefCount( objectInfoPtr->dependentObject, 0, NULL, TRUE );
	objectInfoPtr->flags |= OBJECT_FLAG_SIGNALLED;

	/* Postcondition: The object is now in the destroyed state as far as
	   other objects are concerned */
	POST( isInvalidObjectState( objectHandle ) );

	return( CRYPT_OK );
	}

/* If it's an attribute get/set/delete, check the access conditions for the
   object and the message parameters */

int preDispatchCheckAttributeAccess( const int objectHandle,
									 const MESSAGE_TYPE message,
									 const void *messageDataPtr,
									 const int messageValue,
									 const void *auxInfo )
	{
	static const int accessTypeTbl[ 5 ][ 2 ] = {
		/* MESSAGE_GETATTRIBUTE */			/* MESSAGE_GETATTRIBUTE_S */
		{ ACCESS_FLAG_R, ACCESS_FLAG_H_R }, { ACCESS_FLAG_R, ACCESS_FLAG_H_R },
		/* MESSAGE_SETATTRIBUTE */			/* MESSAGE_SETATTRIBUTE_S */
		{ ACCESS_FLAG_W, ACCESS_FLAG_H_W }, { ACCESS_FLAG_W, ACCESS_FLAG_H_W },
		/* MESSAGE_DELETEATTRIBUTE */
		{ ACCESS_FLAG_D, ACCESS_FLAG_H_D }
		};
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	const OBJECT_INFO *objectInfo = &objectTable[ objectHandle ];
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const int subType = objectInfo->subType;
	int accessType = \
			accessTypeTbl[ localMessage - MESSAGE_GETATTRIBUTE ]\
						 [ ( objectInfo->flags & OBJECT_FLAG_HIGH ) ? 1 : 0 ];
	const BOOLEAN isInternalMessage = \
			( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;

	/* Preconditions */
	PRE( isValidType( objectInfo->type ) );
	PRE( isAttributeMessage( localMessage ) );
	PRE( isAttribute( messageValue ) || isInternalAttribute( messageValue ) );
	PRE( localMessage == MESSAGE_DELETEATTRIBUTE || messageDataPtr != NULL );
	PRE( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) && \
		 attributeACL->attribute == messageValue );

	/* If it's an internal message, use the internal access permssions */
	if( isInternalMessage )
		accessType = MK_ACCESS_INTERNAL( accessType );

	/* Make sure that the attribute is valid for this object subtype */
	if( !isValidSubtype( attributeACL->subTypeA, subType ) && \
		!isValidSubtype( attributeACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that this type of access is valid for this attribute */
	if( !( attributeACL->access & accessType ) )
		{
		/* If it's an internal-only attribute being accessed through an
		   external message, it isn't visible to the user so we return
		   an attribute value error */
		if( !( attributeACL->access & ACCESS_MASK_EXTERNAL ) && \
			!isInternalMessage )
			return( CRYPT_ARGERROR_VALUE );

		/* It is visible, return a standard permission error */
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Inner precondition: The attribute is valid for this subtype and is
	   externally visible or it's an internal message, and this type of
	   access is allowed */
	PRE( isValidSubtype( attributeACL->subTypeA, subType ) || \
		 isValidSubtype( attributeACL->subTypeB, subType ) );
	PRE( ( attributeACL->access & ACCESS_MASK_EXTERNAL ) || \
		 isInternalMessage );
	PRE( attributeACL->access & accessType );

	/* If it's a delete attribute message, there's no attribute data being
	   communicated so we can exit now */
	if( localMessage == MESSAGE_DELETEATTRIBUTE )
		{
		assert( messageDataPtr == NULL );
		return( CRYPT_OK );
		}

	/* Inner precondition: We're getting or setting the value of an attribute */
	PRE( localMessage == MESSAGE_GETATTRIBUTE || \
		 localMessage == MESSAGE_GETATTRIBUTE_S || \
		 localMessage == MESSAGE_SETATTRIBUTE || \
		 localMessage == MESSAGE_SETATTRIBUTE_S );

	/* Safety check for invalid pointers passed from an internal function */
	if( attributeACL->valueType != ATTRIBUTE_VALUE_SPECIAL && \
		!isReadPtr( messageDataPtr, \
					( attributeACL->valueType == ATTRIBUTE_VALUE_STRING || \
					  attributeACL->valueType == ATTRIBUTE_VALUE_WCSTRING || \
					  attributeACL->valueType == ATTRIBUTE_VALUE_TIME ) ? \
						sizeof( RESOURCE_DATA ) : sizeof( int ) ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Make sure that the attribute type matches the supplied value type.
	   We assert the preconditions for internal messages before the general
	   check to ensure that we throw an exception rather than just returning
	   an error code for internal programming errors */
	switch( attributeACL->valueType )
		{
		case ATTRIBUTE_VALUE_BOOLEAN:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );
			PRE( isReadPtr( messageDataPtr, sizeof( int ) ) );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, the only thing 
			   that we can check is the presence of a writeable output 
			   buffer */
			if( localMessage == MESSAGE_GETATTRIBUTE )
				{
				if( !isWritePtr( ( void * ) messageDataPtr, sizeof( int ) ) )
					return( CRYPT_ARGERROR_STR1 );
				}
			break;

		case ATTRIBUTE_VALUE_NUMERIC:
			{
			const int *valuePtr = messageDataPtr;

			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );
			PRE( isReadPtr( messageDataPtr, sizeof( int ) ) );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, the only thing 
			   that we can check is the presence of a writeable output 
			   buffer */
			if( localMessage == MESSAGE_GETATTRIBUTE )
				{
				if( !isWritePtr( ( void * ) messageDataPtr, sizeof( int ) ) )
					return( CRYPT_ARGERROR_STR1 );
				break;
				}

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE );

			/* If it's a standard range check, make sure that the attribute 
			   value is within the allowed range */
			if( !isSpecialRange( attributeACL ) )
				{
				if( !checkNumericRange( *valuePtr, attributeACL->lowRange, 
										attributeACL->highRange ) )
					return( CRYPT_ARGERROR_NUM1 );
				break;
				}

			/* It's a special-case range check */
			assert( isSpecialRange( attributeACL ) );
			switch( getSpecialRangeType( attributeACL ) )
				{
				case RANGEVAL_ANY:
					break;

				case RANGEVAL_SELECTVALUE:
					if( *valuePtr != CRYPT_UNUSED )
						return( CRYPT_ARGERROR_NUM1 );
					break;

				case RANGEVAL_ALLOWEDVALUES:
					if( !checkAttributeRangeSpecial( RANGEVAL_ALLOWEDVALUES, 
											getSpecialRangeInfo( attributeACL ),
											*valuePtr ) )
						return( CRYPT_ARGERROR_NUM1 );
					break;

				case RANGEVAL_SUBRANGES:
					if( !checkAttributeRangeSpecial( RANGEVAL_SUBRANGES, 
											getSpecialRangeInfo( attributeACL ),
											*valuePtr ) )
						return( CRYPT_ARGERROR_NUM1 );
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ARGERROR_NUM1 );
				}
			break;
			}

		case ATTRIBUTE_VALUE_OBJECT:
			{
			const OBJECT_ACL *objectACL = attributeACL->extendedInfo;
			const int *valuePtr = messageDataPtr;
			int objectParamHandle, objectParamSubType;

			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );
			PRE( isReadPtr( messageDataPtr, sizeof( int ) ) );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, the only thing 
			   that we can check is the presence of a writeable output 
			   buffer */
			if( localMessage == MESSAGE_GETATTRIBUTE )
				{
				if( !isWritePtr( ( void * ) messageDataPtr, sizeof( int ) ) )
					return( CRYPT_ARGERROR_STR1 );
				break;
				}

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE );

			/* Must contain a valid object handle */
			if( !fullObjectCheck( *valuePtr, message ) || \
				!isSameOwningObject( objectHandle, *valuePtr ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Object must be of the correct type */
			if( objectACL->flags & ACL_FLAG_ROUTE_TO_CTX )
				objectParamHandle = findTargetType( *valuePtr,
													OBJECT_TYPE_CONTEXT );
			else
				if( objectACL->flags & ACL_FLAG_ROUTE_TO_CERT )
					objectParamHandle = findTargetType( *valuePtr,
														OBJECT_TYPE_CERTIFICATE );
				else
					objectParamHandle = *valuePtr;
			if( cryptStatusError( objectParamHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			objectParamSubType = objectTable[ objectParamHandle ].subType;
			if( !isValidSubtype( objectACL->subTypeA, objectParamSubType ) && \
				!isValidSubtype( objectACL->subTypeB, objectParamSubType ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( ( objectACL->flags & ACL_FLAG_STATE_MASK ) && \
				!checkObjectState( objectACL->flags, objectParamHandle ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Postcondition: Object parameter is valid and accessible,
			   object is of the correct type and state */
			POST( fullObjectCheck( *valuePtr, message ) && \
				  isSameOwningObject( objectHandle, *valuePtr ) );
			POST( isValidSubtype( objectACL->subTypeA, objectParamSubType ) || \
				  isValidSubtype( objectACL->subTypeB, objectParamSubType ) );
			POST( !( objectACL->flags & ACL_FLAG_STATE_MASK ) || \
				  checkObjectState( objectACL->flags, objectParamHandle ) );
			break;
			}

		case ATTRIBUTE_VALUE_STRING:
		case ATTRIBUTE_VALUE_WCSTRING:
			{
			const RESOURCE_DATA *msgData = messageDataPtr;

			/* Inner precondition: If it's an internal message, it must be
			   a valid string value or a null value if we're obtaining a
			   length.  Polled entropy data can be arbitrarily large so we
			   don't check its length */
			PRE( isReadPtr( messageDataPtr, sizeof( RESOURCE_DATA ) ) );
			PRE( !isInternalMessage || \
				 ( ( localMessage == MESSAGE_GETATTRIBUTE_S && \
					 ( ( msgData->data == NULL && msgData->length == 0 ) || \
					   ( msgData->length >= 1 && \
						 isWritePtr( msgData->data, msgData->length ) ) ) ) || \
				   ( localMessage == MESSAGE_SETATTRIBUTE_S && \
					 isReadPtr( msgData->data, msgData->length ) && \
					 ( msgData->length < 16384 || \
					   messageValue == CRYPT_IATTRIBUTE_ENTROPY ) ) ) );

			/* Must be a string value */
			if( localMessage != MESSAGE_GETATTRIBUTE_S && \
				localMessage != MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, the only thing 
			   that we can check is the presence of a writeable output 
			   buffer.  We return a string arg error for both the buffer and
			   length, since the length isn't explicitly specified by an 
			   external caller */
			if( localMessage == MESSAGE_GETATTRIBUTE_S )
				{
				if( !( ( msgData->data == NULL && msgData->length == 0 ) || \
					   ( msgData->length > 0 && \
						 isWritePtr( msgData->data, msgData->length ) ) ) )
					return( CRYPT_ARGERROR_STR1 );
				break;
				}

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE_S );

			/* Make sure that the string length is within the allowed
			   range */
			if( isSpecialRange( attributeACL ) )
				{
				if( !checkAttributeRangeSpecial( \
									getSpecialRangeType( attributeACL ),
									getSpecialRangeInfo( attributeACL ),
									msgData->length ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			else
				if( attributeACL->valueType == ATTRIBUTE_VALUE_WCSTRING )
					{
					if( !checkAttributeRangeWidechar( msgData->data,
													  msgData->length,
													  attributeACL->lowRange,
													  attributeACL->highRange ) )
						return( CRYPT_ARGERROR_NUM1 );
					}
				else
					if( msgData->length < attributeACL->lowRange || \
						msgData->length > attributeACL->highRange )
						return( CRYPT_ARGERROR_NUM1 );
			if( msgData->length > 0 && \
				!isReadPtr( msgData->data, msgData->length ) )
				return( CRYPT_ARGERROR_STR1 );
			break;
			}

		case ATTRIBUTE_VALUE_TIME:
			{
			const RESOURCE_DATA *msgData = messageDataPtr;

			/* Inner precondition: If it's an internal message, it must be
			   a string value corresponding to a time_t */
			PRE( isReadPtr( messageDataPtr, sizeof( RESOURCE_DATA ) ) );
			PRE( !isInternalMessage || \
				 ( ( localMessage == MESSAGE_GETATTRIBUTE_S || \
					 localMessage == MESSAGE_SETATTRIBUTE_S ) && \
				   isReadPtr( msgData->data, msgData->length ) && \
				   msgData->length == sizeof( time_t ) ) );

			/* Must be a string value */
			if( localMessage != MESSAGE_GETATTRIBUTE_S && \
				localMessage != MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, the only thing 
			   that we can check is the presence of a writeable output 
			   buffer.  We return a string arg error for both the buffer and
			   length, since the length isn't explicitly specified by an 
			   external caller */
			if( localMessage == MESSAGE_GETATTRIBUTE_S )
				{
				if( !( ( msgData->data == NULL && msgData->length == 0 ) || \
					   ( msgData->length > 0 && \
						 isWritePtr( msgData->data, msgData->length ) ) ) )
					return( CRYPT_ARGERROR_STR1 );
				break;
				}

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == MESSAGE_GETATTRIBUTE_S )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE_S );

			/* Must contain a time_t in a sensible range */
			if( !isReadPtr( msgData->data, sizeof( time_t ) ) || \
				*( ( time_t * ) msgData->data ) < MIN_TIME_VALUE )
				return( CRYPT_ARGERROR_STR1 );
			if( msgData->length != sizeof( time_t ) )
				return( CRYPT_ARGERROR_NUM1 );
			break;
			}

		case ATTRIBUTE_VALUE_SPECIAL:
			/* It's an ACL with an object-subtype-specific sub-ACL, find the
			   precise ACL for this object subtype */
			for( attributeACL = getSpecialRangeInfo( attributeACL ); \
				 attributeACL->valueType != ATTRIBUTE_VALUE_NONE; \
				 attributeACL++ )
				if( isValidSubtype( attributeACL->subTypeA, subType ) || \
					isValidSubtype( attributeACL->subTypeB, subType ) )
					break;
			if( attributeACL->valueType == ATTRIBUTE_VALUE_NONE )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_PERMISSION );
				}

			/* Recursively check the message against the sub-ACL */
			return( preDispatchCheckAttributeAccess( objectHandle, message,
							messageDataPtr, messageValue, attributeACL ) );

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_PERMISSION );
		}

	return( CRYPT_OK );
	}

/* It's a compare message, make sure that the parameters are OK */

int preDispatchCheckCompareParam( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy )
	{
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const COMPARE_ACL *compareACL = NULL;

	/* Precondition: It's a valid compare message type */
	PRE( fullObjectCheck( objectHandle, message ) );
	PRE( messageValue > MESSAGE_COMPARE_NONE && \
		 messageValue < MESSAGE_COMPARE_LAST );

	/* Find the appropriate ACL for this compare type */
	if( messageValue > MESSAGE_COMPARE_NONE && \
		messageValue < MESSAGE_COMPARE_LAST )
		compareACL = &compareACLTbl[ messageValue - 1 ];
	if( compareACL == NULL )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_VALUE );
		}

	/* Inner precondition: We have the correct ACL, and the full object 
	   check has been performed by the kernel */
	PRE( compareACL->compareType == messageValue );

	/* Check the message target.  The full object check has already been
	   performed by the message dispatcher so all we need to check is the
	   compare-specific subtype.  We throw an exception if we find an 
	   invalid parameter, both because this is an internal message and this 
	   situation shouldn't occur, and because an error return from a compare
	   message is perfectly valid (it denotes a non-match) so parameter
	   errors won't otherwise be caught by the caller */
	if( !( isValidSubtype( compareACL->objectACL.subTypeA, \
						   objectInfoPtr->subType ) ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_OBJECT );
		}
	if( ( compareACL->objectACL.flags & ACL_FLAG_STATE_MASK ) && \
		!checkObjectState( compareACL->objectACL.flags, objectHandle ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Check the message parameters.  We throw an exception if we find an
	   invalid parameter for the reason given above */
	if( paramInfo( compareACL, 0 ).valueType == PARAM_VALUE_OBJECT )
		{
		const CRYPT_HANDLE iCryptHandle = *( ( CRYPT_HANDLE * ) messageDataPtr );

		PRE( fullObjectCheck( iCryptHandle, message ) && \
			 isSameOwningObject( objectHandle, iCryptHandle ) );
		PRE( checkParamObject( paramInfo( compareACL, 0 ), iCryptHandle ) );
		}
	else
		{
		const RESOURCE_DATA *msgData = messageDataPtr;

		PRE( checkParamString( paramInfo( compareACL, 0 ),
							   msgData->data, msgData->length ) );
		}

	/* Postconditions: The compare parameters are valid, either an object
	   handle or a string value at least as big as a minimal-length DN */
	POST( ( messageValue == MESSAGE_COMPARE_CERTOBJ && \
			isValidHandle( *( ( CRYPT_HANDLE * ) messageDataPtr ) ) ) || \
		  ( messageValue != MESSAGE_COMPARE_CERTOBJ && \
			isReadPtr( messageDataPtr, sizeof( RESOURCE_DATA ) ) && \
			( ( RESOURCE_DATA * ) messageDataPtr )->length >= 2 && \
			isReadPtr( ( ( RESOURCE_DATA * ) messageDataPtr )->data, \
					   ( ( RESOURCE_DATA * ) messageDataPtr )->length ) ) );

	return( CRYPT_OK );
	}

/* It's a check message, make sure that the parameters are OK */

int preDispatchCheckCheckParam( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *messageDataPtr,
								const int messageValue,
								const void *dummy )
	{
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const CHECK_ACL *checkACL = NULL;

	/* Precondition: It's a valid check message type */
	PRE( fullObjectCheck( objectHandle, message ) );
	PRE( messageValue > MESSAGE_CHECK_NONE && \
		 messageValue < MESSAGE_CHECK_LAST );

	/* Find the appropriate ACL for this check type */
	if( messageValue > MESSAGE_CHECK_NONE && \
		messageValue < MESSAGE_CHECK_LAST )
		checkACL = &checkACLTbl[ messageValue - 1 ];
	if( checkACL == NULL )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_VALUE );
		}

	/* Inner precondition: We have the correct ACL */
	PRE( checkACL->checkType == messageValue );

	/* Check the message target.  The full object check has already been
	   performed by the message dispatcher so all we need to check is the
	   compare-specific subtype */
	if( !( isValidSubtype( checkACL->objectACL.subTypeA, \
						   objectInfoPtr->subType ) ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( ( checkACL->objectACL.flags & ACL_FLAG_STATE_MASK ) && \
		!checkObjectState( checkACL->objectACL.flags, objectHandle ) )
		/* The object is in the wrong state, meaning that it's inited when
		   it shouldn't be or not inited when it should be, return a more
		   specific error message */
		return( isInHighState( objectHandle ) ? \
				CRYPT_ERROR_INITED : CRYPT_ERROR_NOTINITED );

	/* Make sure that the object's usage count is still valid.  The usage
	   count is a type of meta-capability that overrides all other
	   capabilities in that an object with an expired usage count isn't
	   valid for anything no matter what the available capabilities are */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED && \
		objectInfoPtr->usageCount <= 0 )
		return( CRYPT_ARGERROR_OBJECT );

	/* If this is a context and there's an action associated with this 
	   check, make sure that the requested action is permitted for this 
	   object */
	if( objectInfoPtr->type == OBJECT_TYPE_CONTEXT && \
		checkACL->actionType[ 0 ] != MESSAGE_NONE )
		{
		const BOOLEAN isInternalMessage = \
				( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;
		int i, status = CRYPT_ERROR;

		/* Step through the list of permitted actions checking to see
		   whether one of them matches.  We convert the return status to 
		   CRYPT_ERROR_NOTAVAIL since this is more appropriate than a 
		   generic object error */
		for( i = 0; cryptStatusError( status ) && \
					checkACL->actionType[ i ] != MESSAGE_NONE; i++ )
			{
			status = checkActionPermitted( objectInfoPtr, 
							isInternalMessage ? \
								MKINTERNAL( checkACL->actionType[ i ] ) : \
								checkACL->actionType[ i ] );
			}
		if( cryptStatusError( status ) )
			/* We went through all of the permitted actions without finding 
			   one that was OK for this context */
			return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Postconditions: The object being checked is valid */
	POST( fullObjectCheck( objectHandle, message ) && \
		  ( isValidSubtype( checkACL->objectACL.subTypeA, \
						    objectInfoPtr->subType ) ) );

	return( CRYPT_OK );
	}

/* It's a context action message, check the access conditions for the object */

int preDispatchCheckActionAccess( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy )
	{
	const OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	int status;

	/* Precondition: It's a valid access */
	PRE( isValidObject( objectHandle ) );
	PRE( isActionMessage( localMessage ) );

	/* If the object is in the low state, it can't be used for any action */
	if( !isInHighState( objectHandle ) )
		return( CRYPT_ERROR_NOTINITED );

	/* If the object is in the high state, it can't receive another message
	   of the kind that causes the state change */
	if( localMessage == MESSAGE_CTX_GENKEY )
		return( CRYPT_ERROR_INITED );

	/* If there's a usage count set for the object and it's gone to zero, it
	   can't be used any more */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED && \
		objectInfoPtr->usageCount <= 0 )
		return( CRYPT_ERROR_PERMISSION );

	/* Inner precondition: Object is in the high state and can process the
	   action message */
	PRE( isInHighState( objectHandle ) );
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount > 0 );

	/* Check that the requested action is permitted for this object */
	status = checkActionPermitted( objectInfoPtr, message );
	if( cryptStatusError( status ) )
		return( status );

	/* Postcondition */
	POST( localMessage != MESSAGE_CTX_GENKEY );
	POST( isInHighState( objectHandle ) );
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount > 0 );
	POST( cryptStatusOK( checkActionPermitted( objectInfoPtr, message ) ) );

	return( CRYPT_OK );
	}

/* If it's a state change trigger message, make sure that the object isn't
   already in the high state */

int preDispatchCheckState( const int objectHandle,
						   const MESSAGE_TYPE message,
						   const void *messageDataPtr,
						   const int messageValue, const void *dummy )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;

	/* Precondition: It's a valid access */
	PRE( isValidObject( objectHandle ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* If it's a keygen message, perform a secondary check to ensure that key
	   generation is permitted for this object */
	if( localMessage == MESSAGE_CTX_GENKEY )
		{
		int status;

		/* Check that the requested action is permitted for this object */
		status = checkActionPermitted( &krnlData->objectTable[ objectHandle ], 
									   message );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Postcondition: Object is in the low state so a state change message
	   is valid */
	POST( !isInHighState( objectHandle ) );

	return( CRYPT_OK );
	}

/* Check the access conditions for a message containing an optional handle
   as the message parameter */

int preDispatchCheckParamHandleOpt( const int objectHandle,
									const MESSAGE_TYPE message,
									const void *messageDataPtr,
									const int messageValue,
									const void *auxInfo )
	{
	const MESSAGE_ACL *messageACL = ( MESSAGE_ACL * ) auxInfo;
	const OBJECT_ACL *objectACL = &messageACL->objectACL;
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	int subType;

	/* Preconditions: The access is valid and we've been supplied a valid 
	   check ACL */
	PRE( isValidObject( objectHandle ) );
	PRE( isReadPtr( messageACL, sizeof( MESSAGE_ACL ) ) && \
		 messageACL->type == ( message & MESSAGE_MASK ) );

	/* If the object parameter is CRYPT_UNUSED (for example for a self-signed
	   cert), we're OK */
	if( messageValue == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Make sure that the object parameter is valid and accessible */
	if( !fullObjectCheck( messageValue, message ) || \
		!isSameOwningObject( objectHandle, messageValue ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the object parameter subtype is correct */
	subType = objectTable[ messageValue ].subType;
	if( !isValidSubtype( objectACL->subTypeA, subType ) && \
		!isValidSubtype( objectACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Postcondition: Object parameter is valid, accessible, and of the
	   correct type */
	POST( fullObjectCheck( messageValue, message ) && \
		  isSameOwningObject( objectHandle, messageValue ) );
	POST( isValidSubtype( objectACL->subTypeA, subType ) || \
		  isValidSubtype( objectACL->subTypeB, subType ) );

	return( CRYPT_OK );
	}

/* Perform a combined check of the object and the handle */

int preDispatchCheckStateParamHandle( const int objectHandle,
									  const MESSAGE_TYPE message,
									  const void *messageDataPtr,
									  const int messageValue,
									  const void *auxInfo )
	{
	const MESSAGE_ACL *messageACL = ( MESSAGE_ACL * ) auxInfo;
	const OBJECT_ACL *objectACL = &messageACL->objectACL;
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	int subType;

	/* Preconditions: The access is valid and we've been supplied a valid 
	   check ACL */
	PRE( fullObjectCheck( objectHandle, message ) );
	PRE( isReadPtr( messageACL, sizeof( MESSAGE_ACL ) ) && \
		 messageACL->type == ( message & MESSAGE_MASK ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Make sure that the object parameter is valid and accessible */
	if( !fullObjectCheck( messageValue, message ) || \
		!isSameOwningObject( objectHandle, messageValue ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the object parameter subtype is correct */
	subType = objectTable[ messageValue ].subType;
	if( !isValidSubtype( objectACL->subTypeA, subType ) && \
		!isValidSubtype( objectACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Postcondition: Object is in the low state so a state change message
	   is valid and the object parameter is valid, accessible, and of the
	   correct type */
	POST( !isInHighState( objectHandle ) );
	POST( fullObjectCheck( messageValue, message ) && \
		  isSameOwningObject( objectHandle, messageValue ) );
	POST( isValidSubtype( objectACL->subTypeA, subType ) || \
		  isValidSubtype( objectACL->subTypeB, subType ) );

	return( CRYPT_OK );
	}

/* We're exporting a certificate, make sure that the format is valid for
   this cert type */

int preDispatchCheckExportAccess( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy )
	{
	const ATTRIBUTE_ACL *formatACL;
	int i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( messageDataPtr != NULL );
	PRE( messageValue > CRYPT_CERTFORMAT_NONE && \
		 messageValue < CRYPT_CERTFORMAT_LAST );

	/* Make sure that the export format is valid */
	if( messageValue <= CRYPT_CERTFORMAT_NONE || \
		messageValue >= CRYPT_CERTFORMAT_LAST )
		return( CRYPT_ARGERROR_VALUE );

	/* Find the appropriate ACL for this export type */
	for( i = 0; formatPseudoACL[ i ].attribute != messageValue && \
				formatPseudoACL[ i ].attribute != CRYPT_CERTFORMAT_NONE; \
		 i++ );
	if( formatPseudoACL[ i ].attribute == CRYPT_CERTFORMAT_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_VALUE );
		}
	formatACL = ( ATTRIBUTE_ACL * ) &formatPseudoACL[ i ];

	/* The easiest way to handle this check is to use an ACL, treating the
	   format type as a pseudo-attribute type */
	POST( formatACL->attribute == messageValue );

	return( preDispatchCheckAttributeAccess( objectHandle,
							( message & MESSAGE_FLAG_INTERNAL ) ? \
							IMESSAGE_GETATTRIBUTE_S : MESSAGE_GETATTRIBUTE_S,
							messageDataPtr, messageValue, formatACL ) );
	}

/* It's data being pushed or popped, make sure that it's a valid data
   quantity */

int preDispatchCheckData( const int objectHandle,
						  const MESSAGE_TYPE message,
						  const void *messageDataPtr,
						  const int messageValue,
						  const void *dummy )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const RESOURCE_DATA *msgData = messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( isReadPtr( messageDataPtr, sizeof( RESOURCE_DATA ) ) );
	PRE( messageValue == 0 );

	/* Make sure that it's either a flush (buffer = NULL, length = 0)
	   or valid data */
	if( msgData->data == NULL )
		{
		if( localMessage != MESSAGE_ENV_PUSHDATA )
			return( CRYPT_ARGERROR_STR1 );
		if( msgData->length != 0 )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		{
		if( msgData->length <= 0 )
			return( CRYPT_ARGERROR_NUM1 );
		if( !isReadPtr( msgData->data, msgData->length ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Postcondition: It's a flush or it's valid data */
	POST( ( localMessage == MESSAGE_ENV_PUSHDATA && \
			msgData->data == NULL && msgData->length == 0 ) || \
		  ( msgData->data != NULL && msgData->length > 0 ) );

	return( CRYPT_OK );
	}

/* We're creating a new object, set its owner to the owner of the object 
   that it's being created through */

int preDispatchSetObjectOwner( const int objectHandle,
							   const MESSAGE_TYPE message,
							   const void *messageDataPtr,
							   const int messageValue,
							   const void *dummy )
	{
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	MESSAGE_CREATEOBJECT_INFO *createInfo = \
					( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr;

	/* Precondition */
	PRE( fullObjectCheck( objectHandle, message ) && \
		 objectTable[ objectHandle ].type == OBJECT_TYPE_DEVICE );
	PRE( messageDataPtr != NULL );
	PRE( isValidType( messageValue ) );
	PRE( createInfo->cryptOwner == CRYPT_ERROR );

	/* Set the new object's owner to the owner of the object that it's being
	   created through.  If it's being created through the system device
	   object (which has no owner), we set the owner to the default user
	   object */
	if( objectHandle == SYSTEM_OBJECT_HANDLE )
		createInfo->cryptOwner = DEFAULTUSER_OBJECT_HANDLE;
	else
		{
		const int ownerObject = objectTable[ objectHandle ].owner;

		/* Inner precondition: The owner is a valid user object */
		PRE( isValidObject( ownerObject ) && \
			 objectTable[ ownerObject ].type == OBJECT_TYPE_USER );

		createInfo->cryptOwner = ownerObject;
		}

	/* Postcondition: The new object's owner will be the user object it's
	   being created through or the default user if it's being done via the
	   system object */
	POST( ( objectHandle == SYSTEM_OBJECT_HANDLE && \
			createInfo->cryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
		  ( objectHandle != SYSTEM_OBJECT_HANDLE && \
			createInfo->cryptOwner == objectTable[ objectHandle ].owner ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Message Post-Dispatch Handlers					*
*																			*
****************************************************************************/

/* If we're fetching or creating an object, it won't be visible to an
   outside caller.  If it's an external message, we have to make the object
   externally visible before we return it */

int postDispatchMakeObjectExternal( const int dummy,
									const MESSAGE_TYPE message,
									const void *messageDataPtr,
									const int messageValue,
									const void *auxInfo )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const BOOLEAN isInternalMessage = \
					( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;
	CRYPT_HANDLE objectHandle;
	int status;

	/* Preconditions */
	PRE( localMessage == MESSAGE_GETATTRIBUTE || \
		 localMessage == MESSAGE_DEV_CREATEOBJECT || \
		 localMessage == MESSAGE_DEV_CREATEOBJECT_INDIRECT || \
		 localMessage == MESSAGE_KEY_GETKEY || \
		 localMessage == MESSAGE_KEY_GETNEXTCERT || \
		 localMessage == MESSAGE_KEY_CERTMGMT );
	PRE( messageDataPtr != NULL );

	/* If it's an internal message, there are no problems with object
	   visibility.  In addition most messages are internal, so performing
	   this check before anything else quickly weeds out the majority of
	   cases */
	if( isInternalMessage )
		return( CRYPT_OK );

	switch( localMessage )
		{
		case MESSAGE_GETATTRIBUTE:
			{
			const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;

			/* Inner precondition: Since it's an external message, we must
			   be reading a standard attribute */
			PRE( isAttribute( messageValue ) );
			PRE( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) || \
				 attributeACL->attribute == messageValue );

			/* If it's not an object attribute read, we're done */
			if( attributeACL->valueType == ATTRIBUTE_VALUE_SPECIAL )
				{
				attributeACL = getSpecialRangeInfo( attributeACL );
				POST( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) );
				}
			if( attributeACL->valueType != ATTRIBUTE_VALUE_OBJECT )
				return( CRYPT_OK );

			/* Inner precondition: We're reading an object attribute and
			   sending the response to an external caller */
			PRE( attributeACL->valueType == ATTRIBUTE_VALUE_OBJECT );
			PRE( isValidObject( *( ( int * ) messageDataPtr ) ) );
			PRE( !isInternalMessage );

			objectHandle = *( ( int * ) messageDataPtr );
			break;
			}

		case MESSAGE_DEV_CREATEOBJECT:
		case MESSAGE_DEV_CREATEOBJECT_INDIRECT:
			{
			MESSAGE_CREATEOBJECT_INFO *createInfo = \
							( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr;

			PRE( isReadPtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );

			objectHandle = createInfo->cryptHandle;
			break;
			}

		case MESSAGE_KEY_GETKEY:
		case MESSAGE_KEY_GETNEXTCERT:
			{
			MESSAGE_KEYMGMT_INFO *getkeyInfo = \
							( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

			PRE( isReadPtr( getkeyInfo, sizeof( MESSAGE_KEYMGMT_INFO ) ) );

			objectHandle = getkeyInfo->cryptHandle;
			break;
			}

		case MESSAGE_KEY_CERTMGMT:
			{
			MESSAGE_CERTMGMT_INFO *certMgmtInfo = \
							( MESSAGE_CERTMGMT_INFO * ) messageDataPtr;

			PRE( isReadPtr( certMgmtInfo, sizeof( MESSAGE_CERTMGMT_INFO ) ) );

			/* If it's not a cert management action that can return an
			   object, there's no object to make visible */
			if( messageValue != CRYPT_CERTACTION_ISSUE_CERT && \
				messageValue != CRYPT_CERTACTION_CERT_CREATION && \
				messageValue != CRYPT_CERTACTION_ISSUE_CRL )
				return( CRYPT_OK );

			/* If the caller has indicated that they're not interested in the
			   newly-created object, it won't be present so we can't make it
			   externally visible */
			if( certMgmtInfo->cryptCert == CRYPT_UNUSED )
				return( CRYPT_OK );

			/* Inner precondition: It's an action that can return an object,
			   and there's an object present */
			PRE( messageValue == CRYPT_CERTACTION_ISSUE_CERT || \
				 messageValue == CRYPT_CERTACTION_CERT_CREATION || \
				 messageValue == CRYPT_CERTACTION_ISSUE_CRL );
			PRE( certMgmtInfo->cryptCert != CRYPT_UNUSED );

			objectHandle = certMgmtInfo->cryptCert;
			break;
			}

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Postcondition: We've got a valid internal object to make externally
	   visible */
	POST( isValidObject( objectHandle ) && \
		  isInternalObject( objectHandle ) );

	/* Make the object externally visible.  In theory we should make this 
	   attribute read-only, but it's currently still needed in init.c (the
	   kernel self-test, which checks for internal vs. external 
	   accessibility), keyex.c (to make PGP imported contexts visible), 
	   sign.c (to make CMS signing attributes externally visible), and
	   cryptapi.c when creating objects (to make them externally visible) 
	   and destroying objects (to make the appear destroyed if a dec-
	   refcount leaves it still active) */
	status = krnlSendMessage( objectHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE,
							  CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) )
		return( status );

	/* Postcondition: The object is now externally visible */
	POST( isValidObject( objectHandle ) && \
		  !isInternalObject( objectHandle ) );

	return( CRYPT_OK );
	}

/* If there's a dependent object with a given relationship to the controlling
   object, forward the message.  In practice the only dependencies are those
   of PKC contexts paired with certs, for which a message sent to one (e.g. a
   check message such as "is this suitable for signing?") needs to be
   forwarded to the other */

int postDispatchForwardToDependentObject( const int objectHandle,
										  const MESSAGE_TYPE message,
										  const void *dummy1,
										  const int messageValue,
										  const void *dummy2 )
	{
	const OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];
	const int dependentObject = objectInfoPtr->dependentObject;
	const OBJECT_TYPE objectType = objectInfoPtr->type;
	const OBJECT_TYPE dependentType = isValidObject( dependentObject ) ? \
					krnlData->objectTable[ dependentObject ].type : CRYPT_ERROR;
	int status;
	TEMP_VAR( const MESSAGE_TYPE localMessage = message & MESSAGE_MASK );

	/* Precondition: It's an appropriate message type being forwarded to a
	   dependent object */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == MESSAGE_CHECK );
	PRE( messageValue > MESSAGE_CHECK_NONE && \
		 messageValue < MESSAGE_CHECK_LAST );
	PRE( isValidObject( dependentObject ) || dependentObject == CRYPT_ERROR );

	/* If there's no context : cert relationship between the objects, don't 
	   do anything */
	if( !isValidObject( dependentObject ) || \
		!( objectType == OBJECT_TYPE_CONTEXT && \
		   dependentType == OBJECT_TYPE_CERTIFICATE ) && \
		!( objectType == OBJECT_TYPE_CERTIFICATE && \
		   dependentType == OBJECT_TYPE_CONTEXT ) )
		return( CRYPT_OK );

	/* Postcondition */
	POST( isValidObject( dependentObject ) );
	POST( isSameOwningObject( objectHandle, dependentObject ) );

	/* Forward the message to the dependent object.  We have to make the
	   message internal since the dependent object may be internal-only.
	   In addition we have to unlock the object table since the dependent
	   object may currently be owned by another thread */
	MUTEX_UNLOCK( objectTable );
	status = krnlSendMessage( dependentObject, IMESSAGE_CHECK, NULL,
							  messageValue );
	MUTEX_LOCK( objectTable );
	return( status );
	}

/* Some objects can only perform given number of actions before they self-
   destruct, so if there's a usage count set we update it */

int postDispatchUpdateUsageCount( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *dummy1,
								  const int messageValue,
								  const void *dummy2 )
	{
	OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];
	ORIGINAL_INT_VAR( usageCt, objectInfoPtr->usageCount );

	/* Precondition: It's a context with a nonzero usage count */
	PRE( isValidObject( objectHandle ) && \
		 objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		 objectInfoPtr->usageCount > 0 );

	/* If there's an active usage count present, update it */
	if( objectInfoPtr->usageCount > 0 )
		objectInfoPtr->usageCount--;

	/* Postcondition: If there was a usage count it's been decremented and
	   is >= 0 (the ground state) */
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  ( objectInfoPtr->usageCount == ORIGINAL_VALUE( usageCt ) - 1 && \
			objectInfoPtr->usageCount >= 0 ) );
	return( CRYPT_OK );
	}

/* Certain messages can trigger changes in the object state from the low to
   the high state.  Once one of these messages is successfully processed, we 
   change the object's state so that further accesses are handled by the 
   kernel based on the new state established by the message having been 
   processed successfully.  Since the object is still marked as busy at this 
   stage, other messages arriving before the following state change can't 
   bypass the kernel checks since they won't be processed until the object 
   is marked as non-busy later on */

int postDispatchChangeState( const int objectHandle,
							 const MESSAGE_TYPE message,
							 const void *dummy1,
							 const int messageValue,
							 const void *dummy2 )
	{
	/* Precondition: Object is in the low state so a state change message is
	   valid */
	PRE( isValidObject( objectHandle ) );
	PRE( !isInHighState( objectHandle ) );

	/* The state change message was successfully processed, the object is now
	   in the high state */
	krnlData->objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;

	/* Postcondition: Object is in the high state */
	POST( isInHighState( objectHandle ) );
	return( CRYPT_OK );
	}

int postDispatchChangeStateOpt( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *dummy1,
								const int messageValue,
								const void *auxInfo )
	{
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) );

	/* If it's an attribute that triggers a state change, change the state */
	if( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER )
		{
		/* Inner precondition: Object is in the low state so a state change
		   message is valid, or it's a retriggerable attribute that can be
		   added multiple times (in other words, it can be added in both
		   the low and high state, with the first add in the low state
		   triggering a transition into the high state and subsequent
		   additions augmenting the existing data) */
		PRE( !isInHighState( objectHandle ) || \
			 ( ( attributeACL->access & ACCESS_INT_xWx_xWx ) == ACCESS_INT_xWx_xWx ) );

		krnlData->objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;

		/* Postcondition: Object is in the high state */
		POST( isInHighState( objectHandle ) );
		return( CRYPT_OK );
		}

	/* Postcondition: It wasn't a trigger message */
	POST( !( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER ) );
	return( CRYPT_OK );
	}
