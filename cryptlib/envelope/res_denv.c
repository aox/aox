/****************************************************************************
*																			*
*					cryptlib De-enveloping Information Management			*
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
*						Content List Management Functions					*
*																			*
****************************************************************************/

/* Create a content list item */

CONTENT_LIST *createContentListItem( MEMPOOL_STATE memPoolState,
									 const CRYPT_FORMAT_TYPE formatType,
									 const void *object, const int objectSize,
									 const BOOLEAN isSigObject )
	{
	CONTENT_LIST *contentListItem;

	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( ( object == NULL && objectSize == 0 ) || \
			isReadPtr( object, objectSize ) );

	if( ( contentListItem = getMemPool( memPoolState,
										sizeof( CONTENT_LIST ) ) ) == NULL )
		return( NULL );
	memset( contentListItem, 0, sizeof( CONTENT_LIST ) );
	contentListItem->formatType = formatType;
	contentListItem->object = object;
	contentListItem->objectSize = objectSize;
	if( isSigObject )
		{
		contentListItem->flags = CONTENTLIST_ISSIGOBJ;
		contentListItem->clSigInfo.iSigCheckKey = CRYPT_ERROR;
		contentListItem->clSigInfo.iExtraData = CRYPT_ERROR;
		contentListItem->clSigInfo.iTimestamp = CRYPT_ERROR;
		}

	return( contentListItem );
	}

/* Add an item to the content list */

void appendContentListItem( ENVELOPE_INFO *envelopeInfoPtr,
							CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( contentListPtr == NULL || \
			isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );

	/* Find the end of the list and add the new item */
	if( contentListPtr != NULL )
		{
		int iterationCount = 0;
		
		while( contentListPtr->next != NULL && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			contentListPtr = contentListPtr->next;
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Void();
		}
	insertDoubleListElements( &envelopeInfoPtr->contentList, contentListPtr,
							  contentListItem, contentListItem );
	}

/* Delete a content list */

void deleteContentList( MEMPOOL_STATE memPoolState,
						CONTENT_LIST **contentListHeadPtr )
	{
	CONTENT_LIST *contentListCursor = *contentListHeadPtr;
	int iterationCount = 0;

	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( contentListHeadPtr, sizeof( CONTENT_LIST * ) ) );

	while( contentListCursor != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		CONTENT_LIST *contentListItem = contentListCursor;

		contentListCursor = contentListCursor->next;

		/* Destroy any attached objects if necessary */
		if( contentListItem->flags & CONTENTLIST_ISSIGOBJ )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			if( sigInfo->iSigCheckKey != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_DECREFCOUNT );
			if( sigInfo->iExtraData != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iExtraData, IMESSAGE_DECREFCOUNT );
			if( sigInfo->iTimestamp != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iTimestamp, IMESSAGE_DECREFCOUNT );
			}

		/* Erase and free the object buffer if necessary */
		deleteDoubleListElement( contentListHeadPtr, contentListItem );
		if( contentListItem->object != NULL )
			{
			/* Clear the object.  We have to cheat a bit here with pointer
			   casting, the 'const' indicates that the object data is never 
			   modified while it's in the content list, but it has to be
			   modified at the end when we delete it */
			zeroise( ( void * ) contentListItem->object, 
					 contentListItem->objectSize );
			clFree( "deleteContentList", ( void * ) contentListItem->object );
			}
		zeroise( contentListItem, sizeof( CONTENT_LIST ) );
		freeMemPool( memPoolState, contentListItem );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();
	}

/****************************************************************************
*																			*
*						Process Additional Envelope Information 			*
*																			*
****************************************************************************/

/* Process timestamps */

static int processTimestamp( CONTENT_LIST *contentListPtr, 
							 const void *timestamp, 
							 const int timestampLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int bufSize = max( timestampLength + 128, MIN_BUFFER_SIZE );
	int status;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( timestamp, timestampLength ) );

	/* Create an envelope to contain the timestamp data */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &bufSize, CRYPT_ATTRIBUTE_BUFFERSIZE );

	/* Push in the timestamp data */
	setMessageData( &msgData, ( void * ) timestamp, timestampLength );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* We've got the timestamp info in a sub-envelope, remember it for
	   later */
	contentListPtr->clSigInfo.iTimestamp = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Process CMS unauthenticated attributes.  We can't handle these as
   standard CMS attributes since the only thing that we're likely to see 
   here is a countersignature, which isn't an attribute in the normal 
   sense */

static int processUnauthAttributes( CONTENT_LIST *contentListPtr,
									const void *unauthAttr,
									const int unauthAttrLength )
	{
	STREAM stream;
	int iterationCount = 0, status;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( unauthAttr, unauthAttrLength ) );

	/* Make sure that the unauthenticated attributes are OK.  Normally this
	   is done when we import the attributes, but since we can't import
	   them we have to perform the check explicitly here */
	status = checkObjectEncoding( unauthAttr, unauthAttrLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Process each attribute */
	sMemConnect( &stream, unauthAttr, unauthAttrLength );
	status = readConstructed( &stream, NULL, 1 );
	while( cryptStatusOK( status ) && \
		   sMemDataLeft( &stream ) > MIN_CRYPT_OBJECTSIZE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		BYTE oid[ MAX_OID_SIZE + 8 ];
		int oidLength, length;

		/* See what we've got */
		readSequence( &stream, NULL );
		status = readEncodedOID( &stream, oid, &oidLength, MAX_OID_SIZE,
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusOK( status ) )
			status = readSet( &stream, &length );
		if( cryptStatusError( status ) )
			break;
		if( length < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_UNDERFLOW );
		if( length > sMemDataLeft( &stream ) )
			return( CRYPT_ERROR_OVERFLOW );
		if( oidLength == sizeofOID( OID_TSP_TSTOKEN ) && \
			!memcmp( oid, OID_TSP_TSTOKEN, oidLength ) )
			{
			/* We've got a timestamp.  We can't really do much with this at
			   the moment since although it quacks like a countersignature,
			   in the PKIX tradition it's subtly (and gratuitously)
			   incompatible in various ways so that it can't be verified as
			   a standard countersignature.  Amusingly, the RFC actually
			   states that this is a stupid way to do things.  Specifically,
			   instead of using the normal MUST/SHOULD it first states that
			   the sensible solution to the problem is to use a
			   countersignature, and then goes on to mandate something that
			   isn't a countersignature.  Since this isn't the sensible
			   solution, it's obviously the stupid one.  QED */
			status = processTimestamp( contentListPtr, sMemBufPtr( &stream ), 
									   length );
			if( cryptStatusError( status ) )
				break;

			/* Drop through */
			}

		/* It's something that we don't recognise, skip it and continue */
		status = readUniversal( &stream );
		continue;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	sMemDisconnect( &stream );

	return( status );
	}

/* Import a wrapped session key */

static int importSessionKey( ENVELOPE_INFO *envelopeInfoPtr,
							 const CONTENT_LIST *contentListPtr,
							 const CRYPT_CONTEXT iImportContext,
							 CRYPT_CONTEXT *iSessionKeyContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	CONTENT_LIST *sessionKeyInfoPtr;
	int iterationCount = 0, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isHandleRangeValid( iImportContext ) );
	assert( isWritePtr( iSessionKeyContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear the return value */
	*iSessionKeyContext = CRYPT_ERROR;

	/* PGP doesn't provide separate session key information with the
	   encrypted data but wraps it up alongside the encrypted key, so we
	   can't import the wrapped key into a context via the standard key
	   import functions but instead have to create the context as part of
	   the unwrap process */
	if( contentListPtr->formatType == CRYPT_FORMAT_PGP )
		return( iCryptImportKeyEx( contentListPtr->object,
								   contentListPtr->objectSize,
								   CRYPT_FORMAT_PGP, iImportContext,
								   CRYPT_UNUSED, iSessionKeyContext ) );

	/* Look for the information required to recreate the session key context */
	for( sessionKeyInfoPtr = envelopeInfoPtr->contentList;
		 sessionKeyInfoPtr != NULL && \
			sessionKeyInfoPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 sessionKeyInfoPtr = sessionKeyInfoPtr->next );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();
	if( sessionKeyInfoPtr == NULL )
		/* We need to read more data before we can recreate the session key */
		return( CRYPT_ERROR_UNDERFLOW );

	/* Create the session key context and import the encrypted session key */
	setMessageCreateObjectInfo( &createInfo,
								sessionKeyInfoPtr->clEncrInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionKeyInfoPtr->clEncrInfo.cryptMode,
							  CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = iCryptImportKeyEx( contentListPtr->object,
									contentListPtr->objectSize,
									contentListPtr->formatType,
									iImportContext, createInfo.cryptHandle,
									NULL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iSessionKeyContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Add De-enveloping Information 					*
*																			*
****************************************************************************/

/* Add signature verification information */

static int addSignatureInfo( ENVELOPE_INFO *envelopeInfoPtr,
							 CONTENT_LIST *contentListPtr,
							 const CRYPT_HANDLE sigCheckContext,
							 const BOOLEAN isExternalKey )
	{
	CONTENT_SIG_INFO *sigInfo = &contentListPtr->clSigInfo;
	ACTION_LIST *actionListPtr;
	int iterationCount = 0, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isHandleRangeValid( sigCheckContext ) );

	/* If we've already processed this entry, return the cached processing 
	   result */
	if( contentListPtr->flags & CONTENTLIST_PROCESSED )
		return( sigInfo->processingResult );

	/* Find the hash action that we need to check this signature */
	for( actionListPtr = envelopeInfoPtr->actionList;
		 actionListPtr != NULL && iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 actionListPtr = actionListPtr->next )
		{
		int cryptAlgo;

		/* Check to see if it's the one that we want */
		if( cryptStatusOK( \
				krnlSendMessage( actionListPtr->iCryptHandle,
								 IMESSAGE_GETATTRIBUTE, &cryptAlgo,
								 CRYPT_CTXINFO_ALGO ) ) && \
			cryptAlgo == sigInfo->hashAlgo )
			break;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* If we can't find a hash action to match this signature, return a bad 
	   signature error since something must have altered the algorithm ID 
	   for the hash */
	if( actionListPtr == NULL || actionListPtr->action != ACTION_HASH )
		{
		contentListPtr->flags |= CONTENTLIST_PROCESSED;
		sigInfo->processingResult = CRYPT_ERROR_SIGNATURE;
		return( CRYPT_ERROR_SIGNATURE );
		}

	/* Check the signature */
	if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
		{
		/* If it's CMS signed data then the sig.check key should be included 
		   with the signed data as a cert chain, however it's possible 
		   (though unlikely) that the certs may be unrelated to the 
		   signature, in which case the caller will have provided the sig.
		   check key from an external source */
		status = iCryptCheckSignatureEx( contentListPtr->object,
								contentListPtr->objectSize, CRYPT_FORMAT_CMS,
								( sigInfo->iSigCheckKey == CRYPT_ERROR ) ? \
									sigCheckContext : sigInfo->iSigCheckKey,
								actionListPtr->iCryptHandle,
								&sigInfo->iExtraData );

		/* If there are authenticated attributes present we have to perform 
		   an extra check here to make sure that the content-type specified 
		   in the authenticated attributes matches the actual data content 
		   type */
		if( cryptStatusOK( status ) && sigInfo->iExtraData != CRYPT_ERROR )
			{
			int contentType;

			status = krnlSendMessage( sigInfo->iExtraData,
									  IMESSAGE_GETATTRIBUTE, &contentType,
									  CRYPT_CERTINFO_CMS_CONTENTTYPE );
			if( cryptStatusError( status ) || \
				envelopeInfoPtr->contentType != contentType )
				status = CRYPT_ERROR_SIGNATURE;
			}

		/* If there are unauthenticated attributes present, process them.  
		   We don't record the processing status for these to ensure that 
		   some random error in the non signature-related attributes doesn't 
		   invalidate an otherwise OK signature */
		if( cryptStatusOK( status ) && sigInfo->extraData2 != NULL )
			processUnauthAttributes( contentListPtr, sigInfo->extraData2,
									 sigInfo->extraData2Length );
		}
	else
		{
		status = iCryptCheckSignatureEx( contentListPtr->object,
								contentListPtr->objectSize,
								contentListPtr->formatType, sigCheckContext,
								actionListPtr->iCryptHandle, NULL );

		/* If it's a format that includes signing key info, remember the key 
		   that was used to check the signature in case the user wants to 
		   query it later */
		if( contentListPtr->formatType != CRYPT_FORMAT_PGP )
			{
			krnlSendNotifier( sigCheckContext, IMESSAGE_INCREFCOUNT );
			sigInfo->iSigCheckKey = sigCheckContext;
			if( isExternalKey )
				contentListPtr->flags |= CONTENTLIST_EXTERNALKEY;
			}
		}

	/* Remember the processing result so that we don't have to repeat the 
	   processing if queried again.  Since we don't need the encoded 
	   signature data any more after this point, we free it to make the 
	   memory available for reuse */
	clFree( "addSignatureInfo", ( void * ) contentListPtr->object );
	contentListPtr->object = NULL;
	contentListPtr->objectSize = 0;
	contentListPtr->flags |= CONTENTLIST_PROCESSED;
	sigInfo->processingResult = cryptArgError( status ) ? \
								CRYPT_ERROR_SIGNATURE : status;
	return( status );
	}

/* Add a password for decryption of a private key */

static int addPrivkeyPasswordInfo( ENVELOPE_INFO *envelopeInfoPtr,
								   const CONTENT_LIST *contentListPtr,
								   const void *password, 
								   const int passwordLength )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( password, passwordLength ) );

	/* Make sure that there's a keyset available to pull the key from */
	if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
		{
		setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_DECRYPT,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Try and get the key information */
	if( contentListPtr->issuerAndSerialNumber == NULL )
		{
		setMessageKeymgmtInfo( &getkeyInfo,
				( contentListPtr->formatType == CRYPT_FORMAT_PGP ) ? \
				CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID,
				contentListPtr->keyID, contentListPtr->keyIDsize,
				( void * ) password, passwordLength, 
				KEYMGMT_FLAG_USAGE_CRYPT );
		}
	else
		{
		setMessageKeymgmtInfo( &getkeyInfo,
				CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
				contentListPtr->issuerAndSerialNumber,
				contentListPtr->issuerAndSerialNumberSize,
				( void * ) password, passwordLength, 
				KEYMGMT_FLAG_USAGE_CRYPT );
		}
	status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo,
							  KEYMGMT_ITEM_PRIVATEKEY );
	if( cryptStatusError( status ) )
		return( status );

	/* We managed to get the private key, push it into the envelope.  If the
	   call succeeds, this will import the session key and delete the 
	   required-information list */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY,
									   &getkeyInfo.cryptHandle, 0 );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Add a decryption password */

static int addPasswordInfo( ENVELOPE_INFO *envelopeInfoPtr,
							const CONTENT_LIST *contentListPtr,
							const void *password, const int passwordLength,
							CRYPT_CONTEXT *iNewContext )
	{
	const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( password, passwordLength ) );
	assert( isWritePtr( iNewContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Create the appropriate encryption context and derive the key into it */
	setMessageCreateObjectInfo( &createInfo, encrInfo->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT, 
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &encrInfo->cryptMode,
							  CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		{
#ifdef USE_PGP
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			{
			status = pgpPasswordToKey( createInfo.cryptHandle, CRYPT_UNUSED,
							password, passwordLength, encrInfo->keySetupAlgo,
							encrInfo->saltOrIVsize > 0 ? encrInfo->saltOrIV : NULL,
							encrInfo->keySetupIterations );
			}
		else
#endif /* USE_PGP */
			{
			MESSAGE_DATA msgData;

			/* Load the derivation information into the context */
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE,
									  ( void * ) &encrInfo->keySetupIterations,
									  CRYPT_CTXINFO_KEYING_ITERATIONS );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( void * ) encrInfo->saltOrIV,
								encrInfo->saltOrIVsize );
				status = krnlSendMessage( createInfo.cryptHandle,
									IMESSAGE_SETATTRIBUTE_S, &msgData,
									CRYPT_CTXINFO_KEYING_SALT );
				}
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( void * ) password, 
								passwordLength );
				status = krnlSendMessage( createInfo.cryptHandle,
									IMESSAGE_SETATTRIBUTE_S, &msgData,
									CRYPT_CTXINFO_KEYING_VALUE );
				}
			}
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Recover the session key using the password context and destroy it 
	   when we're done with it */
	if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
		{
		status = importSessionKey( envelopeInfoPtr, contentListPtr,
								   createInfo.cryptHandle, iNewContext );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* In PGP there isn't any encrypted session key, so the context 
		   created from the password becomes the bulk encryption context */
		*iNewContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					De-enveloping Information Management Functions			*
*																			*
****************************************************************************/

/* Add de-enveloping information to an envelope */

static int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE envInfo,
							  const void *value, const int valueLength )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentListCurrent;
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value ), iNewContext;
	ACTION_RESULT actionResult;
	int status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envInfo == CRYPT_IATTRIBUTE_ATTRONLY || \
			( envInfo > CRYPT_ENVINFO_FIRST && \
			  envInfo < CRYPT_ENVINFO_LAST ) );

	/* Perform any final checking and setup */
	if( envInfo != CRYPT_IATTRIBUTE_ATTRONLY && \
		envInfo != CRYPT_ENVINFO_KEYSET_SIGCHECK && \
		envInfo != CRYPT_ENVINFO_KEYSET_ENCRYPT && \
		envInfo != CRYPT_ENVINFO_KEYSET_DECRYPT && \
		envInfo != CRYPT_ENVINFO_HASH )
		{
		/* Since we can add one of a multitude of necessary information 
		   types, we need to check to make sure that what we're adding is 
		   appropriate.  If the caller hasn't tried to read the required 
		   resource information yet, we try to match what's being added to 
		   the first information object of the correct type */
		if( contentListPtr == NULL )
			{
			int iterationCount = 0;
			
			/* Look for the first information object matching the supplied
			   information */
			for( contentListPtr = envelopeInfoPtr->contentList;
				 contentListPtr != NULL && \
					contentListPtr->envInfo != envInfo && \
					iterationCount++ < FAILSAFE_ITERATIONS_MAX;
				 contentListPtr = contentListPtr->next );
			if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
				retIntError();
			if( contentListPtr == NULL && \
				envInfo == CRYPT_ENVINFO_PASSWORD && \
				envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
				{
				/* If we didn't find a direct match and we've been given a 
				   password, check for a private key that can (potentially)
				   be decrypted using the password.  This requires both a
				   keyset/device to fetch the key from and a private key as a
				   required info type */
				iterationCount = 0;
				for( contentListPtr = envelopeInfoPtr->contentList;
					 contentListPtr != NULL && \
						contentListPtr->envInfo != CRYPT_ENVINFO_PRIVATEKEY && \
						iterationCount++ < FAILSAFE_ITERATIONS_MAX;
					 contentListPtr = contentListPtr->next );
				if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
					retIntError();
				}
			if( contentListPtr == NULL )
				return( CRYPT_ARGERROR_VALUE );
			}
		else
			{
			/* Make sure that the information that we're adding matches the 
			   currently required information object.  The one exception to 
			   this is that we can be passed password information when we 
			   require a private key if the private key is encrypted */
			if( contentListPtr->envInfo != envInfo && \
				!( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
				   envInfo == CRYPT_ENVINFO_PASSWORD && \
				   envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR ) )
				return( CRYPT_ARGERROR_VALUE );
			}
		
		}

	switch( envInfo )
		{
		case CRYPT_IATTRIBUTE_ATTRONLY:
			/* This is off by default so we should only be turning it on */
			assert( ( *( int * ) value ) == TRUE );

			envelopeInfoPtr->flags |= ENVELOPE_ATTRONLY;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			/* It's keyset information, keep a record of it for later use */
			return( addKeysetInfo( envelopeInfoPtr, envInfo, cryptHandle ) );

		case CRYPT_ENVINFO_HASH:
			{
			ACTION_LIST *actionListItem;

			/* The user is checking a detached signature, remember the hash 
			   for later.  In theory we should also check the state of the 
			   hash context, however PGP requires that it not be completed 
			   (since it needs to hash further data) and everything else 
			   requires that it be completed, but we don't know at this 
			   point whether we're processing PGP or non-PGP data, so we 
			   can't perform any checking here */
			if( envelopeInfoPtr->actionList != NULL )
				{
				/* There's already a hash action present, we can't add 
				   anything further */
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_HASH,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			/* Add the hash as an action list item */
			actionListItem = addAction( &envelopeInfoPtr->actionList,
										envelopeInfoPtr->memPoolState,
										ACTION_HASH, cryptHandle );
			if( actionListItem == NULL )
				return( CRYPT_ERROR_MEMORY );
			return( krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT ) );
			}

		case CRYPT_ENVINFO_SIGNATURE:
			/* It's a signature object, check the signature and exit */
			return( addSignatureInfo( envelopeInfoPtr, contentListPtr,
									  cryptHandle, !valueLength ) );

		case CRYPT_ENVINFO_PASSWORD:
			/* If we've been given a password and we need private key 
			   information, it's the password required to decrypt the key 
			   so we treat this specially.  This action recursively calls
			   addDeenvelopeInfo() with the processed private key, so we
			   don't have to fall through to the session-key processing
			   code below like the other key-handling actions */
			if( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY )
				return( addPrivkeyPasswordInfo( envelopeInfoPtr, contentListPtr,
												value, valueLength ) );

			/* We've been given a standard decryption password, create the 
			   appropriate encryption context for it and derive the key from 
			   the password */
			status = addPasswordInfo( envelopeInfoPtr, contentListPtr,
									  value, valueLength, &iNewContext );
			break;


		case CRYPT_ENVINFO_PRIVATEKEY:
		case CRYPT_ENVINFO_KEY:
			/* Import the session key using the KEK */
			status = importSessionKey( envelopeInfoPtr, contentListPtr,
									   cryptHandle, &iNewContext );
			break;

		case CRYPT_ENVINFO_SESSIONKEY:
			{
			/* If we've been given the session key directly then we must 
			   have reached the encrypted data so we take a copy and set 
			   up the decryption with it */
			const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;

			status = initEnvelopeEncryption( envelopeInfoPtr, cryptHandle,
							encrInfo->cryptAlgo, encrInfo->cryptMode,
							encrInfo->saltOrIV, encrInfo->saltOrIVsize, TRUE );
			if( cryptStatusOK( status ) )
				/* The session key context is the newly-created internal 
				   one */
				iNewContext = envelopeInfoPtr->iCryptContext;
			break;
			}

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've now got the session key, if we recovered it from a key exchange
	   action (rather than having it passed directly to us by the user), try
	   and set up the decryption */
	assert( isHandleRangeValid( iNewContext ) );
	if( envInfo != CRYPT_ENVINFO_SESSIONKEY )
		{
		int iterationCount = 0;
		
		/* If we got as far as the encrypted data (indicated by the fact 
		   that there's content info present), we can set up the decryption.  
		   If we didn't get this far, it'll be set up by the de-enveloping 
		   code when we reach it */
		for( contentListPtr = envelopeInfoPtr->contentList;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX;
			 contentListPtr = contentListPtr->next );
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError();
		if( contentListPtr != NULL )
			{
			const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;

			/* We got to the encrypted data, set up the decryption */
			status = initEnvelopeEncryption( envelopeInfoPtr, iNewContext,
						encrInfo->cryptAlgo, encrInfo->cryptMode,
						encrInfo->saltOrIV, encrInfo->saltOrIVsize, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Add the recovered session encryption action to the action list */
	actionResult = checkAction( envelopeInfoPtr->actionList, ACTION_CRYPT,
								iNewContext );
	if( actionResult == ACTION_RESULT_ERROR || \
		actionResult == ACTION_RESULT_INITED )
		{
		setErrorInfo( envelopeInfoPtr, envInfo,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}
	if( addAction( &envelopeInfoPtr->actionList,
				   envelopeInfoPtr->memPoolState, ACTION_CRYPT,
				   iNewContext ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Notify the kernel that the session key context is attached to the
	   envelope.  This is an internal object used only by the envelope so we
	   tell the kernel not to increment its reference count when it attaches
	   it */
	krnlSendMessage( envelopeInfoPtr->objectHandle, IMESSAGE_SETDEPENDENT,
					 &iNewContext, SETDEP_OPTION_NOINCREF );

	/* Destroy the content list, which at this point will contain only (now-
	   irrelevant) key exchange items */
	deleteContentList( envelopeInfoPtr->memPoolState,
					   &envelopeInfoPtr->contentList );
	envelopeInfoPtr->contentList = envelopeInfoPtr->contentListCurrent = NULL;

	/* If the only error was an information required error, we've now
	   resolved the problem and can continue */
	if( envelopeInfoPtr->errorState == CRYPT_ENVELOPE_RESOURCE )
		envelopeInfoPtr->errorState = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initDenvResourceHandling( ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) && \
			( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) );

	/* Set the access method pointers */
	envelopeInfoPtr->addInfo = addDeenvelopeInfo;
	}
#endif /* USE_ENVELOPES */
