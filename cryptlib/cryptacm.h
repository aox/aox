/****************************************************************************
*																			*
*								Mechanism ACLs								*
*						Copyright Peter Gutmann 1999-2003					*
*																			*
****************************************************************************/

#ifndef _CRYPTACM_DEFINED

#define _CRYPTACM_DEFINED

/* The ACL tables for each mechanism class */

static const FAR_BSS MECHANISM_ACL mechanismWrapACL[] = {
	{ MECHANISM_PKCS1,				/* PKCS #1 encrypt */
	  { MKACM_S_OPT( 64, MAX_PKCENCRYPTED_SIZE ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_PKCS1_PGP,			/* PKCS #1 encrypt using PGP formatting */
	  { MKACM_S_OPT( 64, MAX_PKCENCRYPTED_SIZE ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV,				/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_PKCS1_RAW,			/* PKCS #1 encrypt of raw data */
	  { MKACM_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Wrapped raw data */
		MKACM_S( 8, CRYPT_MAX_KEYSIZE ),	/* Raw data */
		MKACM_UNUSED(),
		MKACM_O( ST_CTX_PKC,				/* Wrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_CMS,				/* CMS key wrap */
	  { MKACM_S_OPT( 8 + 8, CRYPT_MAX_KEYSIZE + 16 ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx containing key */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_KEA,				/* KEA key agreement */
	  { MKACM_S( 140, 140 ),				/* sizeof( TEK( MEK ) + Ra ) */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV,				/* Skipjack session key */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Recipient KEA pubkey */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_O( ST_CTX_PKC,				/* Sender KEA privkey */
				 ACL_FLAG_HIGH_STATE ) } },
	{ MECHANISM_PRIVATEKEYWRAP,		/* Private key wrap */
	  { MKACM_S_OPT( 16, MAX_PRIVATE_KEYSIZE ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_PKC,				/* Ctx containing private key */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_PRIVATEKEYWRAP_PKCS8,/* Private key wrap */
	  { MKACM_S_OPT( 16, MAX_PRIVATE_KEYSIZE ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_PKC,				/* Ctx containing private key */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_O( ST_CTX_CONV,				/* Wrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_NONE,
	  { MKACM_END() } }
	};

static const FAR_BSS MECHANISM_ACL mechanismUnwrapACL[] = {
	{ MECHANISM_PKCS1,				/* PKCS #1 decrypt */
	  { MKACM_S_OPT( 60, CRYPT_MAX_PKCSIZE ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx to contain key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_PKCS1_PGP,			/* PKCS #1 decrypt using PGP formatting */
	  { MKACM_S_OPT( 60, 4 + ( 2 * CRYPT_MAX_PKCSIZE ) ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_UNUSED(),						/* Placeholder for ctx to contain key */
		MKACM_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_PKCS1_RAW,			/* PKCS #1 decrypt of raw data */
	  { MKACM_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Wrapped raw data */
		MKACM_S( 8, CRYPT_MAX_PKCSIZE ),	/* Raw data */
		MKACM_UNUSED(),
		MKACM_O( ST_CTX_PKC,				/* Unwrap PKC context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ),
		MKACM_UNUSED() } },
	{ MECHANISM_CMS,				/* CMS key unwrap */
	  { MKACM_S( 8 + 8, CRYPT_MAX_KEYSIZE + 16 ),/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV | ST_CTX_MAC,	/* Ctx to contain key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_KEA,				/* KEA key agreement */
	  { MKACM_S( 140, 140 ),				/* sizeof( TEK( MEK ) + Ra ) */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_CONV,				/* Skipjack session key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Recipient KEA privkey */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Sender KEA pubkey */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },
	{ MECHANISM_PRIVATEKEYWRAP,		/* Private key unwrap */
	  { MKACM_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_PRIVATEKEYWRAP_PGP,	/* Private key unwrap */
	  { MKACM_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_PRIVATEKEYWRAP_OPENPGP,	/* Private key unwrap */
	  { MKACM_S( 16, MAX_PRIVATE_KEYSIZE ),	/* Wrapped key */
		MKACM_S_NONE(),
		MKACM_O( ST_CTX_PKC,				/* Ctx to contain private key */
				 ACL_FLAG_LOW_STATE ),
		MKACM_O( ST_CTX_CONV,				/* Unwrap context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_UNUSED() } },
	{ MECHANISM_NONE,
	  { MKACM_END() } }
	};

static const FAR_BSS MECHANISM_ACL mechanismSignACL[] = {
	{ MECHANISM_PKCS1,				/* PKCS #1 sign */
	  { MKACM_S_OPT( 64, CRYPT_MAX_PKCSIZE ),/* Signature */
		MKACM_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Signing context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },
	{ MECHANISM_NONE,
	  { MKACM_END() } }
	};

static const FAR_BSS MECHANISM_ACL mechanismSigCheckACL[] = {
	{ MECHANISM_PKCS1,				/* PKCS #1 sig check */
	  { MKACM_S( 60, CRYPT_MAX_PKCSIZE ),	/* Signature */
		MKACM_O( ST_CTX_HASH,				/* Hash context */
				 ACL_FLAG_HIGH_STATE ),
		MKACM_O( ST_CTX_PKC,				/* Sig.check context */
				 ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX ) } },
	{ MECHANISM_NONE,
	  { MKACM_END() } }
	};

static const FAR_BSS MECHANISM_ACL mechanismDeriveACL[] = {
	{ MECHANISM_PKCS5,				/* PKCS #5 derive */
	  { MKACM_S( 1, CRYPT_MAX_KEYSIZE ),	/* Key data */
		MKACM_S( 2, MAX_ATTRIBUTE_SIZE ),	/* Keying material */
		MKACM_N( CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_SHA ),/* Hash algo */
		MKACM_S( 4, 512 ),					/* Salt */
		MKACM_N( 1, INT_MAX ) } },			/* Iterations */
	{ MECHANISM_SSL,				/* SSL derive */
	  { MKACM_S( 48, 512 ),					/* Master secret/key data */
		MKACM_S( 48, 512 ),					/* Premaster secret/master secret */
		MKACM_N( CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT ),/* SSL uses dual hash */
		MKACM_S( 64, 64 ),					/* Salt */
		MKACM_N( 1, 1 ) } },				/* Iterations */
	{ MECHANISM_TLS,				/* TLS derive (the odd lower bounds on the output
											   and salt are needed when generating
											   the TLS hashed MAC and (for the salt)
											   when generating a master secret from
											   a fixed shared key) */
	  { MKACM_S( 12, 512 ),					/* Master secret/key data (usually 48) */
		MKACM_S( 48, 512 ),					/* Premaster secret/master secret */
		MKACM_N( CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT ),/* TLS uses dual hash */
		MKACM_S( 13, 512 ),					/* Salt (usually 64) */
		MKACM_N( 1, 1 ) } },				/* Iterations */
	{ MECHANISM_CMP,				/* CMP/Entrust derive */
	  { MKACM_S( 20, 20 ),					/* HMAC-SHA key */
		MKACM_S( 1, 512 ),					/* Key data */
		MKACM_N( CRYPT_ALGO_SHA, CRYPT_ALGO_SHA ),/* Hash algo */
		MKACM_S( 1, 512 ),					/* Salt */
		MKACM_N( 1, INT_MAX ) } },			/* Iterations */
	{ MECHANISM_PGP,				/* OpenPGP S2K derive */
	  { MKACM_S( 16, CRYPT_MAX_KEYSIZE ),	/* Key data */
		MKACM_S( 2, MAX_ATTRIBUTE_SIZE ),	/* Keying material */
		MKACM_N( CRYPT_ALGO_MD5, CRYPT_ALGO_RIPEMD160 ),/* Hash algo */
		MKACM_S( 8, 8 ),					/* Salt */
		MKACM_N( 0, INT_MAX ) } },			/* Iterations (0 = don't iterate) */
	{ MECHANISM_PKCS12,				/* PKCS #12 derive */
	  { MKACM_S( 20, 20 ),					/* Key data */
		MKACM_S( 2, CRYPT_MAX_TEXTSIZE ),	/* Keying material */
		MKACM_N( CRYPT_ALGO_SHA, CRYPT_ALGO_SHA ),/* Hash algo */
		MKACM_S( 9, 9 ),					/* Salt (+ ID byte) */
		MKACM_N( 1, INT_MAX ) } },			/* Iterations */
	{ MECHANISM_NONE,
	  { MKACM_END() } }
	};

/* Functions to implement the checks in the mechanism ACL tables */

static int preDispatchCheckMechanismWrapAccess( const int objectHandle,
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
	BOOLEAN isRawMechanism;
	int contextHandle, i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( message == MESSAGE_DEV_EXPORT || message == IMESSAGE_DEV_EXPORT || \
		 message == MESSAGE_DEV_IMPORT || message == IMESSAGE_DEV_IMPORT );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_PKCS1 || \
		 messageValue == MECHANISM_PKCS1_PGP || \
		 messageValue == MECHANISM_PKCS1_RAW || \
		 messageValue == MECHANISM_CMS || \
		 messageValue == MECHANISM_KEA || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_PKCS8 || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_PGP || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP_OPENPGP );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE; i++ );
	mechanismACL = &mechanismACL[ i ];
	isRawMechanism = \
		( paramInfo( mechanismACL, 2 ).valueType == MECHPARAM_VALUE_UNUSED ) ? \
		TRUE : FALSE;

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkMechParamString( paramInfo( mechanismACL, 0 ),
							   mechanismInfo->wrappedData,
							   mechanismInfo->wrappedDataLength ) );
	PRE( checkMechParamString( paramInfo( mechanismACL, 1 ),
							   mechanismInfo->keyData,
							   mechanismInfo->keyDataLength ) );
	PRE( checkMechParamObject( paramInfo( mechanismACL, 4 ),
							   mechanismInfo->auxContext ) );

	/* Make sure the user-supplied parameters are in order, part 1: The
	   session key is a valid object of the correct type, and there's a key
	   loaded/not loaded as appropriate */
	if( !isRawMechanism )
		{
		if( !isValidObject( mechanismInfo->keyContext ) || \
			!isObjectAccessValid( mechanismInfo->keyContext, message ) || \
			!checkObjectOwnership( objectTable[ mechanismInfo->keyContext ] ) )
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
		if( !checkMechParamObject( paramInfo( mechanismACL, 2 ), contextHandle ) )
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
		PRE( checkMechParamObject( paramInfo( mechanismACL, 2 ),
								   mechanismInfo->keyContext ) );

	/* Make sure the user-supplied parameters are in order, part 2: The
	   wrapping key is a valid object of the correct type with a key loaded */
	if( !isValidObject( mechanismInfo->wrapContext ) || \
		!isObjectAccessValid( mechanismInfo->wrapContext, message ) || \
		!checkObjectOwnership( objectTable[ mechanismInfo->wrapContext ] ) )
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
	if( !checkMechParamObject( paramInfo( mechanismACL, 3 ), contextHandle ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Postcondition: The wrapping key and session key are of the appropriate
	   type, there are keys loaded/not loaded as appropriate, and the access
	   is valid.  We don't explicitly state this since it's just
	   regurgitating the checks already performed above */

	/* Make sure all the objects have the same owner */
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

	/* Postcondition: All objects have the same owner */
	POST( ( isRawMechanism && \
			isSameOwningObject( objectHandle, mechanismInfo->wrapContext ) ) || \
		  ( !isRawMechanism && \
			isSameOwningObject( objectHandle, mechanismInfo->keyContext ) && \
			isSameOwningObject( mechanismInfo->keyContext, \
								mechanismInfo->wrapContext ) ) );

	return( CRYPT_OK );
	}

static int preDispatchCheckMechanismSignAccess( const int objectHandle,
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
	int contextHandle, i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( message == MESSAGE_DEV_SIGN || message == IMESSAGE_DEV_SIGN || \
		 message == MESSAGE_DEV_SIGCHECK || message == IMESSAGE_DEV_SIGCHECK );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_PKCS1 );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE; i++ );
	mechanismACL = &mechanismACL[ i ];

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkMechParamString( paramInfo( mechanismACL, 0 ),
							   mechanismInfo->signature,
							   mechanismInfo->signatureLength ) );

	/* Make sure the user-supplied parameters are in order, part 1: The
	   hash context is a valid object of the correct type */
	if( !isValidObject( mechanismInfo->hashContext ) || \
		!isObjectAccessValid( mechanismInfo->hashContext, message ) || \
		!checkObjectOwnership( objectTable[ mechanismInfo->hashContext ] ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !checkMechParamObject( paramInfo( mechanismACL, 1 ),
							   mechanismInfo->hashContext ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Make sure the user-supplied parameters are in order, part 2: The
	   sig/sig check context is a valid object of the correct type, and
	   there's a key loaded */
	if( !isValidObject( mechanismInfo->signContext ) || \
		!isObjectAccessValid( mechanismInfo->signContext, message ) || \
		!checkObjectOwnership( objectTable[ mechanismInfo->signContext ] ) )
		return( CRYPT_ARGERROR_NUM2 );
	if( paramInfo( mechanismACL, 2 ).flags & ACL_FLAG_ROUTE_TO_CTX )
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
	if( !checkMechParamObject( paramInfo( mechanismACL, 2 ), contextHandle ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Postcondition: The hash and sig/sig check contexts are of the
	   appropriate type, there's a key loaded in the sig/sig check context,
	   and the access is valid.  We don't explicitly state this since it's
	   just regurgitating the checks already performed above */

	/* Make sure all the objects have the same owner */
	if( !isSameOwningObject( objectHandle, mechanismInfo->hashContext ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isSameOwningObject( mechanismInfo->hashContext, \
							 mechanismInfo->signContext ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Postcondition: All the objects have the same owner */
	POST( isSameOwningObject( objectHandle, mechanismInfo->hashContext ) && \
		  isSameOwningObject( mechanismInfo->hashContext, \
							  mechanismInfo->signContext ) );

	return( CRYPT_OK );
	}

static int preDispatchCheckMechanismDeriveAccess( const int objectHandle,
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
	PRE( messageValue == MECHANISM_PKCS5 || \
		 messageValue == MECHANISM_PKCS12 || \
		 messageValue == MECHANISM_SSL || \
		 messageValue == MECHANISM_TLS || \
		 messageValue == MECHANISM_CMP || \
		 messageValue == MECHANISM_PGP );

	/* Find the appropriate ACL for this mechanism */
	for( i = 0; mechanismACL[ i ].type != messageValue && \
				mechanismACL[ i ].type != MECHANISM_NONE; i++ );
	mechanismACL = &mechanismACL[ i ];

	/* Inner precondition: We have an ACL for this mechanism, and the non-
	   user-supplied parameters (the ones supplied by cryptlib that must
	   be OK) are in order */
	PRE( mechanismACL->type != MECHANISM_NONE );
	PRE( checkMechParamString( paramInfo( mechanismACL, 0 ),
							   mechanismInfo->dataOut,
							   mechanismInfo->dataOutLength ) );
	PRE( checkMechParamString( paramInfo( mechanismACL, 1 ),
							   mechanismInfo->dataIn,
							   mechanismInfo->dataInLength ) );
	PRE( checkMechParamNumeric( paramInfo( mechanismACL, 2 ),
								mechanismInfo->hashAlgo ) );
	PRE( checkMechParamString( paramInfo( mechanismACL, 3 ),
							   mechanismInfo->salt,
							   mechanismInfo->saltLength ) );
	PRE( checkMechParamNumeric( paramInfo( mechanismACL, 4 ),
								mechanismInfo->iterations ) );

	/* This is a pure data-transformation mechanism, there are no objects
	   used so there are no further checks to perform */

	return( CRYPT_OK );
	}
#endif /* _CRYPTACM_DEFINED */
