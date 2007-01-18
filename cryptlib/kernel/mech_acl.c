/****************************************************************************
*																			*
*								Mechanism ACLs								*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
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
*								Mechanism ACLs								*
*																			*
****************************************************************************/

/* The ACL tables for each mechanism class */

static const MECHANISM_ACL FAR_BSS mechanismWrapACL[] = {
	/* PKCS #1 encrypt */
	{ MECHANISM_ENC_PKCS1,
	  { MKACP_S_OPT( 64, MAX_PKCENCRYPTED_SIZE ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* PKCS #1 encrypt using PGP formatting */
	{ MECHANISM_ENC_PKCS1_PGP,
	  { MKACP_S_OPT( 64, MAX_PKCENCRYPTED_SIZE ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV,				/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* PKCS #1 encrypt of raw data */
	{ MECHANISM_ENC_PKCS1_RAW,
	  { MKACP_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Wrapped raw data */
		MKACP_S( 8, CRYPT_MAX_KEYSIZE ),	/* Raw data */
		MKACP_UNUSED(),
		MKACP_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* CMS key wrap */
	{ MECHANISM_ENC_CMS,
	  { MKACP_S_OPT( 8 + 8, CRYPT_MAX_KEYSIZE + 16 ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	/* KEA key agreement */
	{ MECHANISM_ENC_KEA,
	  { MKACP_S( 140, 140 ),				/* sizeof( TEK( MEK ) + Ra ) */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV,				/* Skipjack session key */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Recipient KEA pubkey */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_O( ST_CTX_PKC,				/* Sender KEA privkey */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Private key wrap */
	{ MECHANISM_PRIVATEKEYWRAP,
	  { MKACP_S_OPT( 16, MAX_PRIVATE_KEYSIZE ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_PKC,				/* Ctx containing private key */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	/* Private key wrap */
	{ MECHANISM_PRIVATEKEYWRAP_PKCS8,
	  { MKACP_S_OPT( 16, MAX_PRIVATE_KEYSIZE ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_PKC,				/* Ctx containing private key */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	{ MECHANISM_NONE,
	  { MKACP_END() } },
	{ MECHANISM_NONE,
	  { MKACP_END() } }
	};

static const MECHANISM_ACL FAR_BSS mechanismUnwrapACL[] = {
	/* PKCS #1 decrypt */
	{ MECHANISM_ENC_PKCS1,
	  { MKACP_S_OPT( 60, CRYPT_MAX_PKCSIZE ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx to contain key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* PKCS #1 decrypt using PGP formatting */
	{ MECHANISM_ENC_PKCS1_PGP,
	  { MKACP_S_OPT( 60, 4 + ( 2 * CRYPT_MAX_PKCSIZE ) ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_UNUSED(),						/* Placeholder for ctx to contain key */
		MKACP_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* PKCS #1 decrypt of raw data */
	{ MECHANISM_ENC_PKCS1_RAW,
	  { MKACP_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Wrapped raw data */
		MKACP_S( 8, CRYPT_MAX_PKCSIZE ),	/* Raw data */
		MKACP_UNUSED(),
		MKACP_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACP_UNUSED() } },

	/* CMS key unwrap */
	{ MECHANISM_ENC_CMS,
	  { MKACP_S( 8 + 8, CRYPT_MAX_KEYSIZE + 16 ),/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx to contain key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	/* KEA key agreement */
	{ MECHANISM_ENC_KEA,
	  { MKACP_S( 140, 140 ),				/* sizeof( TEK( MEK ) + Ra ) */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_CONV,				/* Skipjack session key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Recipient KEA privkey */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Sender KEA pubkey */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },

	/* Private key unwrap */
	{ MECHANISM_PRIVATEKEYWRAP,
	  { MKACP_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	/* Private key unwrap */
	{ MECHANISM_PRIVATEKEYWRAP_PGP,
	  { MKACP_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	/* Private key unwrap */
	{ MECHANISM_PRIVATEKEYWRAP_OPENPGP,
	  { MKACP_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACP_S_NONE(),
		MKACP_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACP_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED() } },

	{ MECHANISM_NONE,
	  { MKACP_END() } },
	{ MECHANISM_NONE,
	  { MKACP_END() } }
	};

static const MECHANISM_ACL FAR_BSS mechanismSignACL[] = {
	/* PKCS #1 sign */
	{ MECHANISM_SIG_PKCS1,
	  { MKACP_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Signature */
		MKACP_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED(),						/* Secondary hash context */
		MKACP_O( ST_CTX_PKC,				/* Signing context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },

	/* SSL sign with dual hashes */
	{ MECHANISM_SIG_SSL,
	  { MKACP_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Signature */
		MKACP_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_HASH,				/* Secondary hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Signing context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },

	{ MECHANISM_NONE,
	  { MKACP_END() } },
	{ MECHANISM_NONE,
	  { MKACP_END() } }
	};

static const MECHANISM_ACL FAR_BSS mechanismSigCheckACL[] = {
	/* PKCS #1 sig check */
	{ MECHANISM_SIG_PKCS1,
	  { MKACP_S( 60, CRYPT_MAX_PKCSIZE ),	/* Signature */
		MKACP_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_UNUSED(),						/* Secondary hash context */
		MKACP_O( ST_CTX_PKC,				/* Sig.check context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },

	/* SSL sign with dual hashes */
	{ MECHANISM_SIG_SSL,
	  { MKACP_S( 60, CRYPT_MAX_PKCSIZE ),	/* Signature */
		MKACP_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_HASH,				/* Secondary hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CTX_PKC,				/* Sig.check context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },

	{ MECHANISM_NONE,
	  { MKACP_END() } },
	{ MECHANISM_NONE,
	  { MKACP_END() } }
	};

static const MECHANISM_ACL FAR_BSS mechanismDeriveACL[] = {
	/* PKCS #5 derive */
	{ MECHANISM_DERIVE_PKCS5,
	  { MKACP_S( 1, CRYPT_MAX_KEYSIZE ),	/* Key data */
		MKACP_S( 2, MAX_ATTRIBUTE_SIZE ),	/* Keying material */
		MKACP_N( CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_SHA ),/* Hash algo */
		MKACP_S( 4, 512 ),					/* Salt */
		MKACP_N( 1, INT_MAX ) } },			/* Iterations */

	/* SSL derive */
	{ MECHANISM_DERIVE_SSL,
	  { MKACP_S( 48, 512 ),					/* Master secret/key data */
		MKACP_S( 48, CRYPT_MAX_PKCSIZE ),	/* Premaster secret/master secret */
		MKACP_N( CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT ),/* SSL uses dual hash */
		MKACP_S( 64, 64 ),					/* Salt */
		MKACP_N( 1, 1 ) } },				/* Iterations */

	/* TLS derive.  The odd lower bounds on the output and salt are needed
	   when generating the TLS hashed MAC and (for the salt and output) and
	   when generating a master secret from a fixed shared key (for the
	   input) */
	{ MECHANISM_DERIVE_TLS,
	  { MKACP_S( 12, 512 ),					/* Master secret/key data (usually 48) */
		MKACP_S( 6, CRYPT_MAX_PKCSIZE ),	/* Premaster secret/master secret (us'ly 48) */
		MKACP_N( CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT ),/* TLS uses dual hash */
		MKACP_S( 13, 512 ),					/* Salt (usually 64) */
		MKACP_N( 1, 1 ) } },				/* Iterations */

	/* CMP/Entrust derive */
	{ MECHANISM_DERIVE_CMP,
	  { MKACP_S( 20, 20 ),					/* HMAC-SHA key */
		MKACP_S( 1, 512 ),					/* Key data */
		MKACP_N( CRYPT_ALGO_SHA, CRYPT_ALGO_SHA ),/* Hash algo */
		MKACP_S( 1, 512 ),					/* Salt */
		MKACP_N( 1, INT_MAX ) } },			/* Iterations */

	/* OpenPGP S2K derive */
	{ MECHANISM_DERIVE_PGP,
	  { MKACP_S( 16, CRYPT_MAX_KEYSIZE ),	/* Key data */
		MKACP_S( 2, MAX_ATTRIBUTE_SIZE ),	/* Keying material */
		MKACP_N( CRYPT_ALGO_MD5, CRYPT_ALGO_RIPEMD160 ),/* Hash algo */
		MKACP_S( 8, 8 ),					/* Salt */
		MKACP_N( 0, INT_MAX ) } },			/* Iterations (0 = don't iterate) */

	/* PKCS #12 derive */
	{ MECHANISM_DERIVE_PKCS12,
	  { MKACP_S( 20, 20 ),					/* Key data */
		MKACP_S( 2, CRYPT_MAX_TEXTSIZE ),	/* Keying material */
		MKACP_N( CRYPT_ALGO_SHA, CRYPT_ALGO_SHA ),/* Hash algo */
		MKACP_S( 9, 9 ),					/* Salt (+ ID byte) */
		MKACP_N( 1, INT_MAX ) } },			/* Iterations */

	{ MECHANISM_NONE,
	  { MKACP_END() } },
	{ MECHANISM_NONE,
	  { MKACP_END() } }
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

int initMechanismACL( KERNEL_DATA *krnlDataPtr )
	{
	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	return( CRYPT_OK );
	}

void endMechanismACL( void )
	{
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*							Mechanism ACL Check Functions					*
*																			*
****************************************************************************/

/* Functions to implement the checks in the mechanism ACL tables */

int preDispatchCheckMechanismWrapAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	const MECHANISM_WRAP_INFO *mechanismInfo = \
				( MECHANISM_WRAP_INFO * ) messageDataPtr;
	const MECHANISM_ACL *mechanismACL = \
				( ( message & MESSAGE_MASK ) == MESSAGE_DEV_EXPORT ) ? \
				mechanismWrapACL : mechanismUnwrapACL;
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	const int mechanismAclSize = \
				( ( message & MESSAGE_MASK ) == MESSAGE_DEV_EXPORT ) ? \
				FAILSAFE_ARRAYSIZE( mechanismWrapACL, MECHANISM_ACL ) : \
				FAILSAFE_ARRAYSIZE( mechanismUnwrapACL, MECHANISM_ACL );
	BOOLEAN isRawMechanism;
	int contextHandle, i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( message == MESSAGE_DEV_EXPORT || message == IMESSAGE_DEV_EXPORT || \
		 message == MESSAGE_DEV_IMPORT || message == IMESSAGE_DEV_IMPORT );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_ENC_PKCS1 || \
		 messageValue == MECHANISM_ENC_PKCS1_PGP || \
		 messageValue == MECHANISM_ENC_PKCS1_RAW || \
		 messageValue == MECHANISM_ENC_CMS || \
		 messageValue == MECHANISM_ENC_KEA || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_PKCS8 || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_PGP || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_OPENPGP );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE && \
				i < mechanismAclSize; i++ );
	if( i >= mechanismAclSize )
		retIntError();
	if( mechanismACL[ i ].type == MECHANISM_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	mechanismACL = &mechanismACL[ i ];
	isRawMechanism = \
		( paramInfo( mechanismACL, 2 ).valueType == PARAM_VALUE_UNUSED ) ? \
		TRUE : FALSE;

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkParamString( paramInfo( mechanismACL, 0 ),
						   mechanismInfo->wrappedData,
						   mechanismInfo->wrappedDataLength ) );
	PRE( checkParamString( paramInfo( mechanismACL, 1 ),
						   mechanismInfo->keyData,
						   mechanismInfo->keyDataLength ) );
	PRE( checkParamObject( paramInfo( mechanismACL, 4 ),
						   mechanismInfo->auxContext ) );

	/* Make sure that the user-supplied parameters are in order, part 1: The
	   session key is a valid object of the correct type, and there's a key
	   loaded/not loaded as appropriate */
	if( !isRawMechanism )
		{
		if( !fullObjectCheck( mechanismInfo->keyContext, message ) )
			return( CRYPT_ARGERROR_NUM1 );
		if( paramInfo( mechanismACL, 2 ).flags & ACL_FLAG_ROUTE_TO_CTX )
			{
			/* The key being wrapped may be accessed via an object such as a
			   certificate that isn't the required object type, in order to
			   perform the following check on it we have to first find the
			   ultimate target object */
			contextHandle = findTargetType( mechanismInfo->keyContext,
											OBJECT_TYPE_CONTEXT );
			if( cryptStatusError( contextHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			}
		else
			contextHandle = mechanismInfo->keyContext;
		if( !checkParamObject( paramInfo( mechanismACL, 2 ), contextHandle ) )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* For raw wrap/unwrap mechanisms the data is supplied as string
		   data.  In theory this would be somewhat risky since it allows
		   bypassing of object ownership checks, however these mechanisms
		   are only accessed from deep within cryptlib (e.g. by the SSH and
		   SSL/TLS session code, which needs to handle protocol-specific
		   secret data in special ways) so there's no chance for problems
		   since the contexts it ends up in are cryptlib-internal,
		   automatically-created ones belonging to the owner of the session
		   object */
		PRE( checkParamObject( paramInfo( mechanismACL, 2 ),
							   mechanismInfo->keyContext ) );

	/* Make sure that the user-supplied parameters are in order, part 2: The
	   wrapping key is a valid object of the correct type with a key loaded */
	if( !fullObjectCheck( mechanismInfo->wrapContext, message ) )
		return( CRYPT_ARGERROR_NUM2 );
	if( paramInfo( mechanismACL, 3 ).flags & ACL_FLAG_ROUTE_TO_CTX )
		{
		/* The wrapping key may be accessed via an object such as a
		   certificate that isn't the required object type, in order to
		   perform the following check on it we have to first find the
		   ultimate target object */
		contextHandle = findTargetType( mechanismInfo->wrapContext,
										OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( contextHandle ) )
			return( CRYPT_ARGERROR_NUM2 );
		}
	else
		contextHandle = mechanismInfo->wrapContext;
	if( !checkParamObject( paramInfo( mechanismACL, 3 ), contextHandle ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Postcondition: The wrapping key and session key are of the appropriate
	   type, there are keys loaded/not loaded as appropriate, and the access
	   is valid.  We don't explicitly state this since it's just
	   regurgitating the checks already performed above */

	/* Make sure that all of the objects have the same owner */
	if( isRawMechanism )
		{
		if( !isSameOwningObject( objectHandle, mechanismInfo->wrapContext ) )
			return( CRYPT_ARGERROR_NUM2 );
		}
	else
		{
		if( !isSameOwningObject( objectHandle, mechanismInfo->keyContext ) )
			return( CRYPT_ARGERROR_NUM1 );
		if( !isSameOwningObject( mechanismInfo->keyContext,
								 mechanismInfo->wrapContext ) )
			return( CRYPT_ARGERROR_NUM2 );
		}

	/* Postcondition: All the objects have the same owner */
#ifndef __WINCE__	/* String too long for compiler */
	POST( ( isRawMechanism && \
			isSameOwningObject( objectHandle, mechanismInfo->wrapContext ) ) || \
		  ( !isRawMechanism && \
			isSameOwningObject( objectHandle, mechanismInfo->keyContext ) && \
			isSameOwningObject( mechanismInfo->keyContext, \
								mechanismInfo->wrapContext ) ) );
#endif /* !__WINCE__ */

	return( CRYPT_OK );
	}

int preDispatchCheckMechanismSignAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	const MECHANISM_SIGN_INFO *mechanismInfo = \
				( MECHANISM_SIGN_INFO * ) messageDataPtr;
	const MECHANISM_ACL *mechanismACL = \
				( ( message & MESSAGE_MASK ) == MESSAGE_DEV_SIGN ) ? \
				mechanismSignACL : mechanismSigCheckACL;
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	const int mechanismAclSize = \
				( ( message & MESSAGE_MASK ) == MESSAGE_DEV_SIGN ) ? \
				FAILSAFE_ARRAYSIZE( mechanismSignACL, MECHANISM_ACL ) : \
				FAILSAFE_ARRAYSIZE( mechanismSigCheckACL, MECHANISM_ACL );
	int contextHandle, i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( message == MESSAGE_DEV_SIGN || message == IMESSAGE_DEV_SIGN || \
		 message == MESSAGE_DEV_SIGCHECK || message == IMESSAGE_DEV_SIGCHECK );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_SIG_PKCS1 || \
		 messageValue == MECHANISM_SIG_SSL );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE && \
				i < mechanismAclSize; i++ );
	if( i >= mechanismAclSize )
		retIntError();
	if( mechanismACL[ i ].type == MECHANISM_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	mechanismACL = &mechanismACL[ i ];

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkParamString( paramInfo( mechanismACL, 0 ),
						   mechanismInfo->signature,
						   mechanismInfo->signatureLength ) );

	/* Make sure that the user-supplied parameters are in order, part 1: The
	   hash contexts are valid objects of the correct type.  If there's a
	   secondary hash context present we report problems with it as a problem
	   with the (logical) single hash context */
	if( !fullObjectCheck( mechanismInfo->hashContext, message ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !checkParamObject( paramInfo( mechanismACL, 1 ),
						   mechanismInfo->hashContext ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( paramInfo( mechanismACL, 2 ).valueType != PARAM_VALUE_UNUSED && \
		!fullObjectCheck( mechanismInfo->hashContext2, message ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !checkParamObject( paramInfo( mechanismACL, 2 ),
						   mechanismInfo->hashContext2 ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Make sure that the user-supplied parameters are in order, part 2: The
	   sig/sig check context is a valid object of the correct type, and
	   there's a key loaded */
	if( !fullObjectCheck( mechanismInfo->signContext, message ) )
		return( CRYPT_ARGERROR_NUM2 );
	if( paramInfo( mechanismACL, 3 ).flags & ACL_FLAG_ROUTE_TO_CTX )
		{
		/* The sig.check key may be accessed via an object such as a
		   certificate that isn't the required object type, in order to
		   perform the following check on it we have to first find the
		   ultimate target object */
		contextHandle = findTargetType( mechanismInfo->signContext,
										OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( contextHandle ) )
			return( CRYPT_ARGERROR_NUM2 );
		}
	else
		contextHandle = mechanismInfo->signContext;
	if( !checkParamObject( paramInfo( mechanismACL, 3 ), contextHandle ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Postcondition: The hash and sig/sig check contexts are of the
	   appropriate type, there's a key loaded in the sig/sig check context,
	   and the access is valid.  We don't explicitly state this since it's
	   just regurgitating the checks already performed above */

	/* Make sure that all of the objects have the same owner */
	if( !isSameOwningObject( objectHandle, mechanismInfo->hashContext ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isSameOwningObject( mechanismInfo->hashContext, \
							 mechanismInfo->signContext ) )
		return( CRYPT_ARGERROR_NUM2 );
	if( paramInfo( mechanismACL, 2 ).valueType != PARAM_VALUE_UNUSED )
		{
		if( !isSameOwningObject( objectHandle, mechanismInfo->hashContext2 ) )
			return( CRYPT_ARGERROR_NUM1 );
		if( !isSameOwningObject( mechanismInfo->hashContext, \
								 mechanismInfo->signContext ) )
			return( CRYPT_ARGERROR_NUM2 );
		}

	/* Postcondition: All of the objects have the same owner */
	POST( isSameOwningObject( objectHandle, mechanismInfo->hashContext ) && \
		  isSameOwningObject( mechanismInfo->hashContext, \
							  mechanismInfo->signContext ) );

	return( CRYPT_OK );
	}

int preDispatchCheckMechanismDeriveAccess( const int objectHandle,
										   const MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue,
										   const void *dummy )
	{
	const MECHANISM_ACL *mechanismACL = mechanismDeriveACL;
	int i;
	TEMP_VAR( const MECHANISM_DERIVE_INFO *mechanismInfo = \
					( MECHANISM_DERIVE_INFO * ) messageDataPtr );

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( message == MESSAGE_DEV_DERIVE || message == IMESSAGE_DEV_DERIVE );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_DERIVE_PKCS5 || \
		 messageValue == MECHANISM_DERIVE_PKCS12 || \
		 messageValue == MECHANISM_DERIVE_SSL || \
		 messageValue == MECHANISM_DERIVE_TLS || \
		 messageValue == MECHANISM_DERIVE_CMP || \
		 messageValue == MECHANISM_DERIVE_PGP );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE && \
				i < FAILSAFE_ARRAYSIZE( mechanismDeriveACL, MECHANISM_ACL ); 
		 i++ );
	if( i >= FAILSAFE_ARRAYSIZE( mechanismDeriveACL, MECHANISM_ACL ) )
		retIntError();
	if( mechanismACL[ i ].type == MECHANISM_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	mechanismACL = &mechanismACL[ i ];

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkParamString( paramInfo( mechanismACL, 0 ),
						   mechanismInfo->dataOut,
						   mechanismInfo->dataOutLength ) );
	PRE( checkParamString( paramInfo( mechanismACL, 1 ),
						   mechanismInfo->dataIn,
						   mechanismInfo->dataInLength ) );
	PRE( checkParamNumeric( paramInfo( mechanismACL, 2 ),
							mechanismInfo->hashAlgo ) );
	PRE( checkParamString( paramInfo( mechanismACL, 3 ),
						   mechanismInfo->salt,
						   mechanismInfo->saltLength ) );
	PRE( checkParamNumeric( paramInfo( mechanismACL, 4 ),
							mechanismInfo->iterations ) );

	/* This is a pure data-transformation mechanism, there are no objects
	   used so there are no further checks to perform */

	return( CRYPT_OK );
	}
