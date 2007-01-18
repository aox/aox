/****************************************************************************
*																			*
*					cryptlib Enveloping Information Management				*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "pgp.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#ifdef USE_FORTEZZA

/* Check that an object being added is suitable for use with Fortezza data */

static int checkFortezzaUsage( const CRYPT_HANDLE cryptHandle,
							   const ENVELOPE_INFO *envelopeInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE envInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	int device1, device2, status;

	assert( isHandleRangeValid( cryptHandle ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envInfo == CRYPT_ENVINFO_ORIGINATOR || \
			envInfo == CRYPT_ENVINFO_SESSIONKEY );

	/* Make sure that the new session key being added (if there's existing
	   originator info) or the existing one (if it's originator info being
	   added) is a Skipjack context */
	status = krnlSendMessage( ( envInfo == CRYPT_ENVINFO_ORIGINATOR ) ? \
							  envelopeInfoPtr->iCryptContext : cryptHandle,
							  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) || cryptAlgo != CRYPT_ALGO_SKIPJACK )
		return( CRYPT_ARGERROR_NUM1 );

	/* Make sure that both objects are present in the same device */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT, &device1,
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( envelopeInfoPtr->iCryptContext,
								  IMESSAGE_GETDEPENDENT, &device2,
								  OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) && ( device1 != device2 ) )
		status = CRYPT_ARGERROR_NUM1;

	return( status );
	}
#endif /* USE_FORTEZZA */

/****************************************************************************
*																			*
*					Misc.Enveloping Info Management Functions				*
*																			*
****************************************************************************/

/* Set up the encryption for an envelope */

int initEnvelopeEncryption( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_CONTEXT cryptContext,
							const CRYPT_ALGO_TYPE algorithm,
							const CRYPT_MODE_TYPE mode,
							const BYTE *iv, const int ivLength,
							const BOOLEAN copyContext )
	{
	CRYPT_CONTEXT iCryptContext = cryptContext;
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_MODE_TYPE cryptMode;
	int blockSize, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isHandleRangeValid( cryptContext ) );
	assert( ( algorithm == CRYPT_ALGO_NONE && mode == CRYPT_MODE_NONE ) || \
			( algorithm >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			  algorithm <= CRYPT_ALGO_LAST_CONVENTIONAL ) );
	assert( ( algorithm == CRYPT_ALGO_NONE && mode == CRYPT_MODE_NONE ) || \
			( mode > CRYPT_MODE_NONE && mode < CRYPT_MODE_LAST ) );
	assert( ( iv == NULL && ivLength == 0 ) || \
			isReadPtr( iv, ivLength ) );

	/* Extract the information that we need to process data */
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
								  &blockSize, CRYPT_CTXINFO_BLOCKSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the context is what's required */
	if( algorithm != CRYPT_ALGO_NONE && \
		( cryptAlgo != algorithm || cryptMode != mode ) )
		/* This can only happen on de-enveloping if the data is corrupted or
		   if the user is asked for a KEK and tries to supply a session key
		   instead */
		return( CRYPT_ERROR_WRONGKEY );

	/* If it's a user-supplied context, take a copy for our own use.  This is
	   only done for non-idempotent user-supplied contexts, for everything
	   else we either use cryptlib's object management to handle things for
	   us or the context is a internal one created specifically for our own
	   use */
	if( copyContext )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		setMessageCreateObjectInfo( &createInfo, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CLONE, NULL,
								  createInfo.cryptHandle );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iCryptContext = createInfo.cryptHandle;
		}

	/* Load the IV into the context and set up the encryption information for
	   the envelope */
	if( !isStreamCipher( cryptAlgo ) )
		{
		if( iv != NULL )
			{
			MESSAGE_DATA msgData;
			int ivSize;

			status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
									  &ivSize, CRYPT_CTXINFO_IVSIZE );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( void * ) iv, min( ivLength, ivSize ) );
				status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
										  &msgData, CRYPT_CTXINFO_IV );
				}
			}
		else
			/* There's no IV specified, generate a new one */
			status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
		if( cryptStatusError( status ) )
			{
			if( copyContext )
				/* Destroy the copy that we created earlier */
				krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	envelopeInfoPtr->iCryptContext = iCryptContext;
	envelopeInfoPtr->blockSize = blockSize;
	envelopeInfoPtr->blockSizeMask = ~( blockSize - 1 );

	return( CRYPT_OK );
	}

/* Check the consistency of enveloping resources before we begin enveloping,
   returning the ID of any missing attributes */

static CRYPT_ATTRIBUTE_TYPE checkMissingInfo( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	BOOLEAN signingKeyPresent = FALSE;
	int iterationCount;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Make sure that we have the minimum requirements for each usage type
	   present */
	switch( envelopeInfoPtr->usage )
		{
		case ACTION_COMPRESS:
			assert( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED );
			break;

		case ACTION_HASH:
			assert( NOTREACHED );
			break;

		case ACTION_MAC:
			/* It's a MAC envelope, there must be at least one key exchange 
			   action present.  A few obscure operation sequences may 
			   however set the usage without setting a key exchange action.  
			   For example making the envelope a MAC envelope simply 
			   indicates that any future key exchange actions should be used 
			   for MAC'ing rather than encryption, but this is indicative of
			   a logic error in the calling app so we report an error even 
			   if, strictly speaking, we could ignore it and continue */
			if( findAction( envelopeInfoPtr->preActionList, \
							ACTION_KEYEXCHANGE_PKC ) == NULL && \
				findAction( envelopeInfoPtr->preActionList, \
							ACTION_KEYEXCHANGE ) == NULL )
				/* We return the most generic CRYPT_ENVINFO_KEY error code, 
				   since there are several possible missing attribute types 
				   that could be required */
				return( CRYPT_ENVINFO_KEY );

		case ACTION_CRYPT:
			/* It's an encryption envelope, there must be a key present at 
			   some level.  This situation doesn't normally occur since the 
			   higher-level code will only set the usage to encryption once 
			   a key exchange action has been added, but we check anyway 
			   just to be safe */
			if( findAction( envelopeInfoPtr->preActionList, \
							ACTION_KEYEXCHANGE_PKC ) == NULL && \
				findAction( envelopeInfoPtr->preActionList, \
							ACTION_KEYEXCHANGE ) == NULL && \
				findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) == NULL )
				return( CRYPT_ENVINFO_KEY );

			/* If there's an originator present, there must be a matching 
			   public-key action present */
#ifdef USE_FORTEZZA
			if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR && \
				findAction( envelopeInfoPtr->preActionList,
							ACTION_KEYEXCHANGE_PKC ) == NULL )
				return( CRYPT_ENVINFO_PUBLICKEY );
#endif /* USE_FORTEZZA */

			break;

		case ACTION_SIGN:
			/* It's a signing envelope, there must be a signature key
			   present */
			if( findAction( envelopeInfoPtr->postActionList, \
							ACTION_SIGN ) == NULL )
				return( CRYPT_ENVINFO_SIGNATURE );
			signingKeyPresent = TRUE;
		}

	assert( signingKeyPresent || \
			!( ( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) || \
			   findAction( envelopeInfoPtr->actionList, ACTION_HASH ) ) );

	/* If there are signature-related options present (signature envelope,
	   detached-sig flag set, hash context present, or CMS attributes or a
	   TSA session present), there must be a signing key also present */
	iterationCount = 0;
	for( actionListPtr = envelopeInfoPtr->postActionList;
		 actionListPtr != NULL && iterationCount++ < FAILSAFE_ITERATIONS_MAX; 
		 actionListPtr = actionListPtr->next )
		{
		if( actionListPtr->iExtraData != CRYPT_ERROR || \
			actionListPtr->iTspSession != CRYPT_ERROR )
			{
			if( !signingKeyPresent || \
				actionListPtr->iCryptHandle == CRYPT_ERROR )
				return( CRYPT_ENVINFO_SIGNATURE );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	return( CRYPT_ATTRIBUTE_NONE );
	}

/****************************************************************************
*																			*
*							Add Enveloping Information 						*
*																			*
****************************************************************************/

/* Add keyset information (this function is also used by the de-enveloping 
   routines) */

int addKeysetInfo( ENVELOPE_INFO *envelopeInfoPtr,
				   const CRYPT_ATTRIBUTE_TYPE keysetFunction,
				   const CRYPT_KEYSET keyset )
	{
	CRYPT_KEYSET *iKeysetPtr;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( keysetFunction == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
			keysetFunction == CRYPT_ENVINFO_KEYSET_DECRYPT || \
			keysetFunction == CRYPT_ENVINFO_KEYSET_SIGCHECK );
	assert( isHandleRangeValid( keyset ) );

	/* Figure out which keyset we want to set */
	switch( keysetFunction )
		{
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			iKeysetPtr = &envelopeInfoPtr->iEncryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			iKeysetPtr = &envelopeInfoPtr->iDecryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			iKeysetPtr = &envelopeInfoPtr->iSigCheckKeyset;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_INTERNAL );
		}

	/* Make sure that the keyset hasn't already been set */
	if( *iKeysetPtr != CRYPT_ERROR )
		{
		setErrorInfo( envelopeInfoPtr, keysetFunction,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Remember the new keyset and increment its reference count */
	*iKeysetPtr = keyset;
	return( krnlSendNotifier( keyset, IMESSAGE_INCREFCOUNT ) );
	}

/* Add an encryption password */

static int addPasswordInfo( ENVELOPE_INFO *envelopeInfoPtr,
							const void *password, const int passwordLength )
	{
	CRYPT_ALGO_TYPE cryptAlgo = envelopeInfoPtr->defaultAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( password, passwordLength ) );

	/* PGP doesn't support both PKC and conventional key exchange actions or 
	   multiple conventional key exchange actions in the same envelope since 
	   the session key is encrypted for the PKC action but derived from the 
	   password for the conventional action */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
		( findAction( envelopeInfoPtr->preActionList,
					  ACTION_KEYEXCHANGE_PKC ) != NULL || \
		  envelopeInfoPtr->actionList != NULL ) )
		{
		setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_PUBLICKEY,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Create the appropriate encryption context.  We have to be careful to 
	   ensure that we use an algorithm which is compatible with the wrapping 
	   mechanism.  We don't have to perform this check if the format type is 
	   PGP since PGP wrapping always uses CFB mode (so there are no modes 
	   that need to be avoided) and the higher-level code has constrained 
	   the algorithm type to something which is encodable using the PGP data 
	   format */
	if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP && \
		( isStreamCipher( cryptAlgo ) || \
		  cryptStatusError( sizeofAlgoIDex( cryptAlgo,
		  									CRYPT_MODE_CBC, 0 ) ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT, 
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Derive the key into the context and add it to the action list */
#ifdef USE_PGP
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		MESSAGE_DATA msgData;
		BYTE salt[ PGP_SALTSIZE + 8 ];
		static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;

		/* PGP uses CFB mode for everything so we change the mode from the 
		   default of CBC to CFB */
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( void * ) &mode, CRYPT_CTXINFO_MODE );
		if( cryptStatusError( status ) )
			return( status );

		/* Generate a salt, derive the key into the context, and insert it 
		   into the action list.  Since PGP doesn't perform a key exchange 
		   of a session key, we insert the password-derived context directly 
		   into the main action list */
		setMessageData( &msgData, salt, PGP_SALTSIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			status = pgpPasswordToKey( createInfo.cryptHandle, CRYPT_UNUSED, 
									   password, passwordLength,
									   envelopeInfoPtr->defaultHash,
									   salt, PGP_ITERATIONS );
		if( cryptStatusOK( status ) && \
			addAction( &envelopeInfoPtr->actionList,
					   envelopeInfoPtr->memPoolState, ACTION_CRYPT,
					   createInfo.cryptHandle ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	else
#endif /* USE_PGP */
		{
		MESSAGE_DATA msgData;
		ACTION_RESULT actionResult;

		setMessageData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEYING_VALUE );
		if( cryptStatusOK( status ) )
			{
			/* Make sure that this key exchange action isn't already present 
			   and insert it into the list */
			actionResult = checkAction( envelopeInfoPtr->preActionList,
										ACTION_KEYEXCHANGE,
										createInfo.cryptHandle );
			if( actionResult == ACTION_RESULT_ERROR || \
				actionResult == ACTION_RESULT_INITED )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_PASSWORD,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				status = CRYPT_ERROR_INITED;
				}
			else
				if( addAction( &envelopeInfoPtr->preActionList,
							   envelopeInfoPtr->memPoolState,
							   ACTION_KEYEXCHANGE,
							   createInfo.cryptHandle ) == NULL )
					status = CRYPT_ERROR_MEMORY;
			}
		}
	if( cryptStatusError( status ) )
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Add a context to an envelope */

static int addContextInfo( ENVELOPE_INFO *envelopeInfoPtr,
						   const CRYPT_HANDLE cryptHandle,
						   ACTION_LIST **actionListHeadPtrPtr,
						   const ACTION_TYPE actionType )
	{
	CRYPT_ALGO_TYPE cryptAlgo, certHashAlgo;
	CRYPT_MODE_TYPE cryptMode = CRYPT_MODE_NONE;
	CRYPT_HANDLE iCryptHandle = cryptHandle;
	ACTION_LIST *actionListPtr, *hashActionPtr;
	ACTION_RESULT actionResult;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( isWritePtr( actionListHeadPtrPtr, sizeof( ACTION_LIST * ) ) );
	assert( actionType > ACTION_NONE && actionType < ACTION_LAST );

	/* Make sure that the algorithm information is encodable using the 
	   selected envelope format.  This should already have been checked by
	   the calling function, but we double-check here because this provides 
	   a convenient centralised location */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && \
		( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) )
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( status );
	if( !envelopeInfoPtr->checkAlgo( cryptAlgo, cryptMode ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Find the insertion point for this action and make sure that it isn't
	   already present.  The difference between an ACTION_RESULT_INITED and 
	   an ACTION_RESULT_PRESENT is that an inited response indicates that 
	   the user explicitly added the action and can't add it again while a 
	   present response indicates that the action was added automatically by 
	   cryptlib in response to the user adding some other action and 
	   shouldn't be reported as an error, to the user it doesn't make any 
	   difference whether the same action was added automatically by 
	   cryptlib or explicitly */
	actionResult = checkAction( *actionListHeadPtrPtr, actionType, iCryptHandle );
	switch( actionResult )
		{
		case ACTION_RESULT_OK:
		case ACTION_RESULT_EMPTY:
			break;

		case ACTION_RESULT_INITED:
			return( CRYPT_ERROR_INITED );
	
		case ACTION_RESULT_PRESENT:
			return( CRYPT_OK );

		case ACTION_RESULT_ERROR:
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Insert the action into the list.  If it's a non-idempotent context
	   (i.e. one whose state can change based on user actions), we clone it
	   for our own use, otherwise we just increment its reference count */
	if( actionType == ACTION_HASH || actionType == ACTION_CRYPT )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		setMessageCreateObjectInfo( &createInfo, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_CLONE, NULL,
								  createInfo.cryptHandle );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iCryptHandle = createInfo.cryptHandle;
		}
	else
		{
		status = krnlSendNotifier( iCryptHandle, IMESSAGE_INCREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		}
	actionListPtr = addAction( actionListHeadPtrPtr,
							   envelopeInfoPtr->memPoolState, actionType,
							   iCryptHandle );
	if( actionListPtr == NULL )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( CRYPT_ERROR_MEMORY );
		}
	if( actionType == ACTION_HASH )
		/* Remember that we need to hook the hash action up to a signature
		   action before we start enveloping data */
		actionListPtr->flags |= ACTION_NEEDSCONTROLLER;

	/* If the newly-inserted action isn't a controlling action, we're done */
	if( actionType != ACTION_SIGN )
		return( status );

	/* Check whether the hash algorithm used in the cert is stronger than the
	   one that's set for the envelope as a whole, and if it is, upgrade the
	   envelope hash algo.  This is based on the fact that anyone who's able
	   to verify the cert using a stronger hash algorithm must also be able
	   to verify the envelope using the stronger algorithm.  This allows a
	   transparent upgrade to stronger hash algorithms as they become
	   available */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
							  &certHashAlgo, CRYPT_IATTRIBUTE_CERTHASHALGO );
	if( cryptStatusOK( status ) && \
		isStrongerHash( certHashAlgo, envelopeInfoPtr->defaultHash ) )
		envelopeInfoPtr->defaultHash = certHashAlgo;

	/* If there's no subject hash action available, create one so that we
	   can connect it to the signature action */
	if( envelopeInfoPtr->actionList == NULL )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Create a default hash action */
		setMessageCreateObjectInfo( &createInfo, envelopeInfoPtr->defaultHash );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );

		/* Add the hash action to the list */
		hashActionPtr = addAction( &envelopeInfoPtr->actionList,
								   envelopeInfoPtr->memPoolState, ACTION_HASH,
								   createInfo.cryptHandle );
		if( hashActionPtr == NULL )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( CRYPT_ERROR_MEMORY );
			}

		/* Remember that the action was added invisibly to the caller so that
		   we don't return an error if they add it explicitly later on */
		hashActionPtr->flags |= ACTION_ADDEDAUTOMATICALLY;
		}
	else
		{
		/* Find the last hash action that was added */
		hashActionPtr = findLastAction( envelopeInfoPtr->actionList,
										ACTION_HASH );
		if( hashActionPtr == NULL )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_HASH,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}

	/* Connect the signature action to the last hash action that was added
	   and remember that this action now has a controlling action */
	actionListPtr->associatedAction = hashActionPtr;
	hashActionPtr->flags &= ~ACTION_NEEDSCONTROLLER;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Enveloping Information Management Functions				*
*																			*
****************************************************************************/

/* Add enveloping information to an envelope */

static int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE envInfo,
							const void *value, const int valueLength )
	{
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value );
	ACTION_LIST *actionListPtr;
	const int intValue = *( ( int * ) value );

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( ( envInfo == CRYPT_IATTRIBUTE_INCLUDESIGCERT ) || \
			( envInfo == CRYPT_IATTRIBUTE_ATTRONLY ) || \
			( envInfo > CRYPT_ENVINFO_FIRST && \
			  envInfo < CRYPT_ENVINFO_LAST ) );

	/* If it's a generic "add a context" action for a PGP envelope, check 
	   that everything is valid.  This is necessary because the PGP format 
	   doesn't support the full range of enveloping capabilities */
#ifdef USE_PGP
	if( ( envelopeInfoPtr->type == CRYPT_FORMAT_PGP ) && \
		( envInfo == CRYPT_ENVINFO_PUBLICKEY || \
		  envInfo == CRYPT_ENVINFO_PRIVATEKEY || \
		  envInfo == CRYPT_ENVINFO_KEY || \
		  envInfo == CRYPT_ENVINFO_SESSIONKEY || \
		  envInfo == CRYPT_ENVINFO_HASH || \
		  envInfo == CRYPT_ENVINFO_SIGNATURE ) )
		{
		/* PGP doesn't support both PKC and conventional key exchange
		   actions in the same envelope since the session key is encrypted
		   for the PKC action but derived from the password for the
		   conventional action */
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE ) != NULL )
			{
			setErrorInfo( envelopeInfoPtr, envInfo,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* PGP handles multiple signers by nesting signed data rather than
		   attaching multiple signatures, so we can only apply a single
		   signature per envelope */
		if( envInfo == CRYPT_ENVINFO_SIGNATURE && \
			envelopeInfoPtr->postActionList != NULL )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_SIGNATURE,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* PGP doesn't allow multiple hash algorithms to be used when signing
		   data (a follow-on from the way nested sigs are handled) */
		if( envInfo == CRYPT_ENVINFO_HASH && \
			envelopeInfoPtr->actionList != NULL )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_HASH,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}
		}
#endif /* USE_PGP */

	/* If it's meta-information, remember the value */
	switch( envInfo )
		{
		case CRYPT_IATTRIBUTE_INCLUDESIGCERT:
			/* This is on by default so we should only be turning it off */
			assert( intValue == FALSE );

			envelopeInfoPtr->flags |= ENVELOPE_NOSIGNINGCERTS;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_ATTRONLY:
			/* This is off by default so we should only be turning it on */
			assert( intValue == TRUE );

			if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
				{
				/* Detached-sig and attribute-only messages are mutually
				   exclusive */
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_DETACHEDSIGNATURE,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			envelopeInfoPtr->flags |= ENVELOPE_ATTRONLY;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_DATASIZE:
			envelopeInfoPtr->payloadSize = intValue;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_CONTENTTYPE:
			envelopeInfoPtr->contentType = intValue;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			if( intValue )
				{
				if( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY )
					/* Detached-sig and attribute-only messages are mutually
					   exclusive.  Since the attribute-only message attribute
					   is internal, we can't set extended error information
					   for this one */
					return( CRYPT_ERROR_INITED );
				envelopeInfoPtr->flags |= ENVELOPE_DETACHED_SIG;
				}
			else
				envelopeInfoPtr->flags &= ~ENVELOPE_DETACHED_SIG;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_MAC:
			{
			/* The MAC flag is somewhat different from the detached-signature
			   one in that the latter is a modifier for an existing envelope
			   usage while the former changes the usage itself.  Because of
			   this it can only be set to TRUE (if it could be reset the
			   caller could set non-MAC-compatible options by clearing the
			   flag and then setting it again afterwards), since the envelope
			   usage change occurs at a higher level all we do here is make
			   sure that the flag isn't being cleared */
			if( !intValue )
				return( CRYPT_ARGERROR_NUM1 );

			/* There are no known implementations of this content-type, so
			   for now we disallow any attempts to use it */
			return( CRYPT_ERROR_NOTAVAIL );
			}

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			/* It's keyset information, just keep a record of it for later 
			   use */
			return( addKeysetInfo( envelopeInfoPtr, envInfo, cryptHandle ) );

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
		case CRYPT_ENVINFO_TIMESTAMP:
			{
			CRYPT_HANDLE *iCryptHandlePtr;

			/* Find the last signature action that was added and make sure
			   that it doesn't already have an action of this type attached 
			   to it */
			actionListPtr = findLastAction( envelopeInfoPtr->postActionList,
											ACTION_SIGN );
			if( actionListPtr == NULL )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_SIGNATURE,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			iCryptHandlePtr = ( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) ? \
							  &actionListPtr->iExtraData : \
							  &actionListPtr->iTspSession;
			if( *iCryptHandlePtr != CRYPT_ERROR )
				{
				setErrorInfo( envelopeInfoPtr, envInfo,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			/* Increment its reference count and add it to the action */
			krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
			*iCryptHandlePtr = cryptHandle;
			return( CRYPT_OK );
			}

		case CRYPT_ENVINFO_ORIGINATOR:
#ifdef USE_FORTEZZA
			/* If there's a session key present, make sure that it's 
			   consistent with the originator info */
			if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
				{
				int status;

				status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr,
											 CRYPT_ENVINFO_ORIGINATOR );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Increment its reference count and add it to the action */
			krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
			envelopeInfoPtr->iExtraCertChain = cryptHandle;

			/* Since we're using Fortezza key management, we have to use 
			   Skipjack as the data encryption algorithm */
			envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_SKIPJACK;

			return( CRYPT_OK );
#else
			return( CRYPT_ARGERROR_NUM1 );
#endif /* USE_FORTEZZA */

		case CRYPT_ENVINFO_COMPRESSION:
#ifdef USE_COMPRESSION
			/* Make sure that we don't try and initialise the compression
			   multiple times */
			if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_COMPRESSION,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			/* Initialize the compression */
			if( deflateInit( &envelopeInfoPtr->zStream, \
							 Z_DEFAULT_COMPRESSION ) != Z_OK )
				return( CRYPT_ERROR_MEMORY );
			envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;

			return( CRYPT_OK );
#else
			return( CRYPT_ARGERROR_NUM1 );
#endif /* USE_COMPRESSION */

		case CRYPT_ENVINFO_PASSWORD:
			return( addPasswordInfo( envelopeInfoPtr, value, valueLength ) );

		case CRYPT_ENVINFO_PUBLICKEY:
		case CRYPT_ENVINFO_PRIVATEKEY:
			return( addContextInfo( envelopeInfoPtr, cryptHandle,
									&envelopeInfoPtr->preActionList,
									ACTION_KEYEXCHANGE_PKC ) );

		case CRYPT_ENVINFO_KEY:
			/* PGP doesn't allow KEK-based encryption, so if it's a PGP
			   envelope we drop through and treat it as a session key */
			if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
				return( addContextInfo( envelopeInfoPtr, cryptHandle, 
										&envelopeInfoPtr->preActionList,
										ACTION_KEYEXCHANGE ) );
			/* Fall through */

		case CRYPT_ENVINFO_SESSIONKEY:
			/* We can't add more than one session key */
			if( envelopeInfoPtr->actionList != NULL )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_SESSIONKEY,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

#ifdef USE_FORTEZZA
			/* If there's originator info present, make sure that it's
			   consistent with the new session key */
			if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
				{
				int status;

				status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr,
											 CRYPT_ENVINFO_SESSIONKEY );
				if( cryptStatusError( status ) )
					return( status );
				}
#endif /* USE_FORTEZZA */

			return( addContextInfo( envelopeInfoPtr, cryptHandle, 
									&envelopeInfoPtr->actionList,
									ACTION_CRYPT ) );

		case CRYPT_ENVINFO_HASH:
			return( addContextInfo( envelopeInfoPtr, cryptHandle, 
									&envelopeInfoPtr->actionList, 
									ACTION_HASH ) );

		case CRYPT_ENVINFO_SIGNATURE:
			return( addContextInfo( envelopeInfoPtr, cryptHandle, 
									&envelopeInfoPtr->postActionList, 
									ACTION_SIGN ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ARGERROR_NUM1 );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initEnvResourceHandling( ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) && \
			!( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) );

	/* Set the access method pointers */
	envelopeInfoPtr->addInfo = addEnvelopeInfo;
	envelopeInfoPtr->checkMissingInfo = checkMissingInfo;
	}
#endif /* USE_ENVELOPES */
