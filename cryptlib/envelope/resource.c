/****************************************************************************
*																			*
*					cryptlib Enveloping Information Management				*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "pgp.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "pgp.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "envelope/envelope.h"
  #include "envelope/pgp.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Action List Management Functions					*
*																			*
****************************************************************************/

/* Create a new action */

static ACTION_LIST *createAction( MEMPOOL_STATE memPoolState,
								  const ACTION_TYPE actionType,
								  const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListItem;

	/* Create the new action list item */
	if( ( actionListItem = getMemPool( memPoolState,
									   sizeof( ACTION_LIST ) ) ) == NULL )
		return( NULL );
	memset( actionListItem, 0, sizeof( ACTION_LIST ) );
	actionListItem->action = actionType;
	actionListItem->iCryptHandle = cryptHandle;
	actionListItem->iExtraData = CRYPT_ERROR;
	actionListItem->iTspSession = CRYPT_ERROR;

	return( actionListItem );
	}

/* Find an action of a given type and the last action of a given type.  
   Since the lists are sorted by action type, the generic findAction()
   finds the start of an action group */

ACTION_LIST *findAction( ACTION_LIST *actionListPtr,
						 const ACTION_TYPE actionType )
	{
	while( actionListPtr != NULL )
		{
		if( actionListPtr->action == actionType )
			return( actionListPtr );
		actionListPtr = actionListPtr->next;
		}

	return( NULL );
	}

ACTION_LIST *findLastAction( ACTION_LIST *actionListPtr,
							 const ACTION_TYPE actionType )
	{
	/* Find the start of the action group */
	actionListPtr = findAction( actionListPtr, actionType );
	if( actionListPtr == NULL )
		return( NULL );

	/* Find the end of the action group */
	while( actionListPtr->next != NULL && \
		   actionListPtr->next->action == actionType )
		actionListPtr = actionListPtr->next;
	return( actionListPtr );
	}

/* Check a new action to make sure that it isn't already present in the 
   action list, producing one of the following outcomes.  The two 'action 
   present' results are for the case where the action is already present 
   and shouldn't be added again, and where the action is present from being 
   added as an (invisible to the user) side-effect of another action being 
   added, so that this attempt to add it should be reported as CRYPT_OK 
   rather than CRYPT_INITED */

typedef enum {
	ACTION_RESULT_OK,				/* Action not present, can be added */
	ACTION_RESULT_EMPTY,			/* Action list is empty */
	ACTION_RESULT_INITED,			/* Action present (CRYPT_INITED) */
	ACTION_RESULT_PRESENT			/* Action present (CRYPT_OK) */
	} ACTION_RESULT;

static ACTION_RESULT checkAction( const ACTION_LIST *actionListStart,
								  const ACTION_TYPE actionType, 
								  const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = ( ACTION_LIST * ) actionListStart;
	BYTE keyID[ KEYID_SIZE ];
	int cryptAlgo, status = CRYPT_OK;

	assert( actionType == ACTION_KEYEXCHANGE || \
			actionType == ACTION_KEYEXCHANGE_PKC || \
			actionType == ACTION_CRYPT || \
			actionType == ACTION_HASH || actionType == ACTION_MAC || \
			actionType == ACTION_SIGN );

	/* If the action list is empty, there's nothing to check */
	if( actionListPtr == NULL )
		return( ACTION_RESULT_EMPTY );

	/* Get identification information for the action object.  For a hash/
	   MAC/session key object we get the algorithm, for a PKC object 
	   (signature or key exchange) we get the key ID */
	if( actionType == ACTION_HASH || actionType == ACTION_MAC || \
		actionType == ACTION_CRYPT )
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	else
		if( actionType != ACTION_KEYEXCHANGE )
			{
			RESOURCE_DATA msgData;

			assert( actionType == ACTION_KEYEXCHANGE_PKC || \
					actionType == ACTION_SIGN );

			setMessageData( &msgData, keyID, KEYID_SIZE );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S, 
									  &msgData, CRYPT_IATTRIBUTE_KEYID );
			}
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Walk down the list from the first to the last action in the action 
	   group, checking each in turn */
	for( actionListPtr = findAction( actionListPtr, actionType );
		 actionListPtr != NULL && actionListPtr->action == actionType;
		 actionListPtr = actionListPtr->next )
		{
		RESOURCE_DATA msgData;
		BOOLEAN isDuplicate = FALSE;

		/* Make sure that we haven't added this action already.  This can 
		   get a bit tricky both because detecting some types of duplicates 
		   is rather hard and because the definition of what's an invalid
		   duplicate varies somewhat.  For a hash, MAC, and encryption
		   action, we only allow one action of a given algorithm type to
		   be added.  For a PKC key exchange or signature action we only 
		   allow one action for a given key to be added.  For a conventional
		   key exchange action we should in theory check for duplicates in
		   some form but it's not certain what constitutes a duplicate (for
		   example are two otherwise identical actions with a different 
		   number of key setup iterations considered duplicates or not?) so 
		   for now we assume the user won't do anything silly (in any case 
		   for any key exchange action the only thing a duplicate will do is 
		   result in unnecessary bloating of the envelope header) */
		if( actionType == ACTION_HASH || actionType == ACTION_MAC || \
			actionType == ACTION_CRYPT )
			{
			int actionAlgo;

			/* It's a hash/MAC or session key object, compare the two
			   objects by comparing their algorithms */
			if( cryptStatusOK( \
					krnlSendMessage( actionListPtr->iCryptHandle, 
									 IMESSAGE_GETATTRIBUTE, &actionAlgo, 
									 CRYPT_CTXINFO_ALGO ) ) && \
				actionAlgo == cryptAlgo )
				isDuplicate = TRUE;
			}
		else
			{
			/* It's a PKC key exchange or signature action, compare the two 
			   objects by comparing their keys */
			setMessageData( &msgData, keyID, KEYID_SIZE );
			if( cryptStatusOK( \
					krnlSendMessage( actionListPtr->iCryptHandle, 
									 IMESSAGE_COMPARE, &msgData, 
									 MESSAGE_COMPARE_KEYID ) ) )
				isDuplicate = TRUE;
			}
		if( isDuplicate )
			{
			/* If the action was added automatically as the result of adding 
			   another action then the first attempt to add it by the caller 
			   isn't an error */
			if( actionListPtr->flags & ACTION_ADDEDAUTOMATICALLY )
				{
				actionListPtr->flags &= ~ACTION_ADDEDAUTOMATICALLY;
				return( ACTION_RESULT_PRESENT );
				}

			return( ACTION_RESULT_INITED );
			}
		}

	return( ACTION_RESULT_OK );
	}

/* Add a new action to the end of an action list */

ACTION_LIST *addAction( ACTION_LIST **actionListHeadPtrPtr,
						MEMPOOL_STATE memPoolState,
						const ACTION_TYPE actionType,
						const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = *actionListHeadPtrPtr, *prevActionPtr = NULL;
	ACTION_LIST *actionListItem;

	/* Create a new action */
	actionListItem = createAction( memPoolState, actionType, 
								   ( cryptHandle == CRYPT_UNUSED ) ? \
								   CRYPT_ERROR : cryptHandle );
	if( actionListItem == NULL )
		return( NULL );

	/* Find the last action in the action group and append the new action */
	while( actionListPtr != NULL && actionListPtr->action <= actionType )
		{
		prevActionPtr = actionListPtr;
		actionListPtr = actionListPtr->next;
		}
	if( prevActionPtr == NULL )
		*actionListHeadPtrPtr = actionListItem;
	else
		prevActionPtr->next = actionListItem;
	actionListItem->next = actionListPtr;

	return( actionListItem );
	}

/* Delete an action from an action list */

static void deleteActionListItem( MEMPOOL_STATE memPoolState,
								  ACTION_LIST *actionListItem )
	{
	/* Destroy any attached objects and information if necessary and 
	   clear the list item memory */
	if( actionListItem->iCryptHandle != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iCryptHandle, IMESSAGE_DECREFCOUNT );
	if( actionListItem->iExtraData != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iExtraData, IMESSAGE_DECREFCOUNT );
	if( actionListItem->iTspSession != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iTspSession, IMESSAGE_DECREFCOUNT );
	zeroise( actionListItem, sizeof( ACTION_LIST ) );
	freeMemPool( memPoolState, actionListItem );
	}

void deleteAction( ACTION_LIST **actionListHead, 
				   MEMPOOL_STATE memPoolState,	
				   ACTION_LIST *actionListItem )
	{
	ACTION_LIST *listPrevPtr;

	for( listPrevPtr = *actionListHead; 
		 listPrevPtr != NULL && listPrevPtr->next != actionListItem; 
		 listPrevPtr = listPrevPtr->next );

	/* Remove the item from the list */
	if( actionListItem == *actionListHead )
		/* Delete from start */
		*actionListHead = actionListItem->next;
	else
		/* Delete from middle or end */
		listPrevPtr->next = actionListItem->next;

	/* Clear all data in the list item and free the memory */
	deleteActionListItem( memPoolState, actionListItem );
	}

/* Delete an action list */

void deleteActionList( MEMPOOL_STATE memPoolState,
					   ACTION_LIST *actionListPtr )
	{
	while( actionListPtr != NULL )
		{
		ACTION_LIST *actionListItem = actionListPtr;

		actionListPtr = actionListPtr->next;
		deleteActionListItem( memPoolState, actionListItem );
		}
	}

/* Delete any orphaned actions, for example automatically-added hash actions 
   that were overridden by user-supplied alternate actions */

void deleteUnusedActions( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr = envelopeInfoPtr->actionList;

	/* Check for unattached hash/MAC or encryption actions and delete them */
	while( actionListPtr != NULL )
		{
		ACTION_LIST *actionListCurrent = actionListPtr;

		actionListPtr = actionListPtr->next;
		if( ( actionListCurrent->action == ACTION_HASH || \
			  actionListCurrent->action == ACTION_MAC || \
			  actionListCurrent->action == ACTION_CRYPT ) && \
			( actionListCurrent->flags & ACTION_NEEDSCONTROLLER ) )
			deleteAction( &envelopeInfoPtr->actionList, 
						  envelopeInfoPtr->memPoolState, actionListCurrent );
		}
	}

/* Check that the actions in an envelope are consistent.  This is a complex
   function which is called from an assert() macro, so we only need to define
   it when we're building a debug version */

#ifndef NDEBUG

BOOLEAN actionsOK( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr = envelopeInfoPtr->actionList;

	/* The permitted action combinations are key exchange + crypt/MAC, 
	   sign + hash, crypt, or none, make sure that this is the case */
	if( envelopeInfoPtr->preActionList != NULL )
		{
		/* Key exchange must be followed by crypt or MAC action */
		if( actionListPtr == NULL )
			return( FALSE );
		while( actionListPtr != NULL )
			{
			if( actionListPtr->action != ACTION_CRYPT && \
				actionListPtr->action != ACTION_MAC )
				return( FALSE );
			actionListPtr = actionListPtr->next;
			}
		if( envelopeInfoPtr->postActionList != NULL )
			return( FALSE );
		}
	else
		if( envelopeInfoPtr->postActionList != NULL )
			{
			/* Signature must be preceded by hash action */
			if( actionListPtr == NULL )
				return( FALSE );
			while( actionListPtr != NULL )
				{
				if( actionListPtr->action != ACTION_HASH )
					return( FALSE );
				actionListPtr = actionListPtr->next;
				}
			if( envelopeInfoPtr->preActionList != NULL )
				return( FALSE );
			}
		else
			if( actionListPtr != NULL )
				/* A standalone action can only be (session-key based) 
				   encryption except for de-enveloping a signed envelope,
				   where we can have standalone hash actions before we get 
				   to the signature data and add post-actions */
				if( !( ( actionListPtr->action == ACTION_CRYPT ) || \
					   ( ( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
					     actionListPtr->action == ACTION_HASH ) ) )
					return( FALSE );

	/* Pre-actions can only be key exchange actions, and have to be sorted
	   by action group */
	if( envelopeInfoPtr->preActionList != NULL )
		{
		actionListPtr = envelopeInfoPtr->preActionList;

		while( actionListPtr != NULL && \
			   actionListPtr->action == ACTION_KEYEXCHANGE_PKC )
			actionListPtr = actionListPtr->next;
		while( actionListPtr != NULL && \
			   actionListPtr->action == ACTION_KEYEXCHANGE )
			actionListPtr = actionListPtr->next;

		return( ( actionListPtr == NULL ) ? TRUE : FALSE );
		}

	/* Post-actions can only be signature actions */
	if( envelopeInfoPtr->postActionList != NULL )
		{
		for( actionListPtr = envelopeInfoPtr->postActionList;
			 actionListPtr != NULL; actionListPtr = actionListPtr->next )
			if( actionListPtr->action != ACTION_SIGN )
				return( FALSE );

		return( TRUE );
		}

	/* A standalone action can be either a single crypt, one or more hashes,
	   or nothing */
	if( envelopeInfoPtr->actionList == NULL )
		return( TRUE );
	if( envelopeInfoPtr->actionList->action == ACTION_CRYPT )
		return( envelopeInfoPtr->actionList->next == NULL ? TRUE : FALSE );
	for( actionListPtr = envelopeInfoPtr->preActionList;
		 actionListPtr != NULL; actionListPtr = actionListPtr->next )
		if( actionListPtr->action != ACTION_HASH )
			return( FALSE );

	return( TRUE );
	}
#endif /* !NDEBUG */

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

	if( ( contentListItem = getMemPool( memPoolState,
										sizeof( CONTENT_LIST ) ) ) == NULL )
		return( NULL );
	memset( contentListItem, 0, sizeof( CONTENT_LIST ) );
	contentListItem->formatType = formatType;
	contentListItem->object = ( void * ) object;
	contentListItem->objectSize = objectSize;
	if( isSigObject )
		{
		contentListItem->flags = CONTENTLIST_ISSIGOBJ;
		contentListItem->clSigInfo.iSigCheckKey = CRYPT_ERROR;
		contentListItem->clSigInfo.iExtraData = CRYPT_ERROR;
		}

	return( contentListItem );
	}

/* Add an item to the content list */

void appendContentListItem( ENVELOPE_INFO *envelopeInfoPtr,
							const CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

	if( envelopeInfoPtr->contentList == NULL )
		{
		envelopeInfoPtr->contentList = ( CONTENT_LIST * ) contentListItem;
		return;
		}

	/* Find the end of the list and add the new item */
	while( contentListPtr->next != NULL )
		contentListPtr = contentListPtr->next;
	contentListPtr->next = ( CONTENT_LIST * ) contentListItem;
	}

/* Delete a content list */

void deleteContentList( MEMPOOL_STATE memPoolState,
						CONTENT_LIST *contentListPtr )
	{
	while( contentListPtr != NULL )
		{
		CONTENT_LIST *contentListItem = contentListPtr;

		/* Destroy any attached objects if necessary */
		if( contentListItem->flags & CONTENTLIST_ISSIGOBJ )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			if( sigInfo->iSigCheckKey != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_DECREFCOUNT );
			if( sigInfo->iExtraData != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iExtraData, IMESSAGE_DECREFCOUNT );
			}

		/* Erase and free the object buffer if necessary */
		contentListPtr = contentListPtr->next;
		if( contentListItem->object != NULL )
			{
			zeroise( contentListItem->object, contentListItem->objectSize );
			clFree( "deleteContentList", contentListItem->object );
			}
		zeroise( contentListItem, sizeof( CONTENT_LIST ) );
		freeMemPool( memPoolState, contentListItem );
		}
	}

/****************************************************************************
*																			*
*						Misc.Enveloping Info Management Functions			*
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
	RESOURCE_DATA msgData;
	int blockSize, status;

	/* Extract the information we need to process data */
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
	if( algorithm != CRYPT_UNUSED && \
		( cryptAlgo != algorithm || cryptMode != mode ) )
		/* This can only happen on deenveloping if the data is corrupted or 
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
			int ivSize;

			status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, 
									  &ivSize, CRYPT_CTXINFO_IVSIZE );
			setMessageData( &msgData, ( void * ) iv, min( ivLength, ivSize ) );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
										  &msgData, CRYPT_CTXINFO_IV );
			}
		else
			/* There's no IV specified, generate a new one */
			status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
		if( cryptStatusError( status ) )
			{
			if( copyContext )
				/* Destroy the copy we created earlier */
				krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	envelopeInfoPtr->iCryptContext = iCryptContext;
	envelopeInfoPtr->blockSize = blockSize;
	envelopeInfoPtr->blockSizeMask = ~( blockSize - 1 );

	return( CRYPT_OK );
	}

/* Add keyset information */

static int addKeyset( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE keysetFunction,
					  const CRYPT_KEYSET keyset )
	{
	CRYPT_KEYSET *iKeysetPtr;

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
			return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Make sure that the keyset hasn't already been set */
	if( *iKeysetPtr != CRYPT_ERROR )
		return( CRYPT_ERROR_INITED );

	/* Remember the new keyset and increment its reference count */
	*iKeysetPtr = keyset;
	return( krnlSendNotifier( keyset, IMESSAGE_INCREFCOUNT ) );
	}

/****************************************************************************
*																			*
*					Deenveloping Information Management Functions			*
*																			*
****************************************************************************/

/* Process CMS unauthenticated attributes.  We can't handle these as 
   standard CMS attributes since the only thing we're likely to see here is 
   a countersignature, which isn't an attribute in the normal sense */

static int processUnauthAttributes( CONTENT_LIST *contentListPtr,
									const void *unauthAttr, 
									const int unauthAttrLength )
	{
	STREAM stream;
	int status;

	UNUSED( contentListPtr );

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
		   sMemDataLeft( &stream ) > MIN_CRYPT_OBJECTSIZE )
		{
		BYTE oid[ MAX_OID_SIZE ];
		int oidLength;

		/* See what we've got */
		readSequence( &stream, NULL );
		status = readRawObject( &stream, oid, &oidLength, MAX_OID_SIZE, 
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusOK( status ) )
			status = readSet( &stream, NULL );
		if( cryptStatusError( status ) )
			break;
		if( oidLength != sizeofOID( OID_TSP_TSTOKEN ) || \
			memcmp( oid, OID_TSP_TSTOKEN, oidLength ) )
			{
			/* It's not a timestamp, skip it and continue */
			readUniversal( &stream );
			continue;
			}

		/* We've got a timestamp.  We can't really do much with this at the 
		   moment since although it quacks like a countersignature, in the 
		   PKIX tradition it's subtly (and gratuitously) incompatible in 
		   various ways, so it can't be verified as a standard 
		   countersignature.  Amusingly, the RFC actually states that this 
		   is a stupid way to do things.  Specifically, instead of using the 
		   normal MUST/SHOULD it first states that the sensible solution to 
		   the problem is to use a countersignature, and then goes on to 
		   describe something that isn't a countersignature.  Since this 
		   isn't the sensible solution, it's obviously the stupid one.  QED */
#if 1
		readUniversal( &stream );
#else	/* Alternatively, if we're being asked to return the timestamp data,
		   we could proceed as follows */
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		RESOURCE_DATA msgData;
		int dataSize, bufSize;

		/* Find out how much data we've got */
		dataSize = getStreamObjectLength( &stream );
		if( cryptStatusError( dataSize ) )
			return( dataSize );
		if( dataSize > sMemDataLeft( &stream ) )
			return( CRYPT_ERROR_OVERFLOW );
		bufSize = max( dataSize + 128, MIN_BUFFER_SIZE );

		/* Create a second envelope to contain the timestamp */
		setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_ENVELOPE );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
						 ( void * ) &bufSize, CRYPT_ATTRIBUTE_BUFFERSIZE );

		/* Push in the timestamp data */
		setMessageData( &msgData, sMemBufPtr( &stream ), dataSize );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_ENV_PUSHDATA, 
								  &msgData, 0 );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
			}
		if( cryptStatusError( status ) )
			return( status );
		/* contentListPtr->iTimestamp = createInfo.cryptHandle; */
		}
#endif /* 0 */
		}
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
	int status;

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
			sessionKeyInfoPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
		 sessionKeyInfoPtr = sessionKeyInfoPtr->next );
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

/* Add de-enveloping information to an envelope */

static int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE envInfo, 
							  const void *value, const int valueLength )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentListCurrent;
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value ), iNewContext;
	ACTION_LIST *actionListPtr;
	int status = CRYPT_OK;

	/* If it's meta-information, remember the value */
	if( envInfo == CRYPT_IATTRIBUTE_ATTRONLY )
		{
		/* This is off by default so we should only be turning it on */
		assert( ( *( int * ) value ) == TRUE );

		envelopeInfoPtr->flags |= ENVELOPE_ATTRONLY;
		return( CRYPT_OK );
		}

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle ) );

	/* If it's a hash action, the user is checking a detached sig, remember
	   the hash for later.  In theory we should check the state of the hash 
	   context, however PGP requires that it not be completed (since it
	   needs to hash further data) and everything else requires that it be
	   completed, but we don't know at this point whether we're processing
	   PGP or non-PGP data, so we can't perform any checking here */
	if( envInfo == CRYPT_ENVINFO_HASH )
		{
		ACTION_LIST *actionListItem;

		/* If there's already an action present, we can't add anything 
		   further */
		if( envelopeInfoPtr->actionList != NULL )
			return( CRYPT_ERROR_INITED );

		/* Add the hash as an action list item */
		actionListItem = createAction( envelopeInfoPtr->memPoolState, 
									   ACTION_HASH, cryptHandle );
		if( actionListItem == NULL )
			return( CRYPT_ERROR_MEMORY );
		envelopeInfoPtr->actionList = actionListItem;
		return( krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT ) );
		}

	/* Since we can add one of a multitude of necessary information types, we
	   need to check to make sure that what we're adding is appropriate.  If 
	   the caller hasn't tried to read the required resource information yet, 
	   we try to match what's being added to the first information object of 
	   the correct type */
	if( contentListPtr == NULL )
		{
		/* Look for the first information object matching the supplied
		   information */
		for( contentListPtr = envelopeInfoPtr->contentList;
			 contentListPtr != NULL && contentListPtr->envInfo != envInfo;
			 contentListPtr = contentListPtr->next );
		if( contentListPtr == NULL )
			return( CRYPT_ARGERROR_VALUE );
		}

	/* Make sure that the information we're adding matches the currently 
	   required information object.  The one exception to this is that we 
	   can be passed password information when we require a private key if 
	   the private key is encrypted */
	if( contentListPtr->envInfo != envInfo && \
		!( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
		   envInfo == CRYPT_ENVINFO_PASSWORD ) )
		return( CRYPT_ARGERROR_VALUE );

	/* If it's a signature object, check the signature and exit.  Anything
	   left after this point is a keying object */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE )
		{
		CONTENT_SIG_INFO *sigInfo = &contentListPtr->clSigInfo;

		/* If we've already processed this entry, return the saved processing
		   result */
		if( contentListPtr->flags & CONTENTLIST_PROCESSED )
			return( sigInfo->processingResult );

		/* Find the hash action we need to check this signature */
		for( actionListPtr = envelopeInfoPtr->actionList;
			 actionListPtr != NULL; actionListPtr = actionListPtr->next )
			{
			int cryptAlgo;

			/* Check to see if it's the one we want */
			if( cryptStatusOK( \
					krnlSendMessage( actionListPtr->iCryptHandle, 
									 IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
									 CRYPT_CTXINFO_ALGO ) ) && \
				cryptAlgo == sigInfo->hashAlgo )
				break;
			}

		/* If we can't find a hash action to match this signature, return a
		   bad signature error since something must have altered the
		   algorithm ID for the hash */
		if( actionListPtr == NULL || actionListPtr->action != ACTION_HASH )
			{
			contentListPtr->flags |= CONTENTLIST_PROCESSED;
			sigInfo->processingResult = CRYPT_ERROR_SIGNATURE;
			return( CRYPT_ERROR_SIGNATURE );
			}

		/* Check the signature */
		if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
			{
			/* If it's CMS signed data then the sig.check key should be 
			   included with the signed data as a cert chain, however it's
			   possible (though unlikely) that the certs may be unrelated to
			   the signature, in which case the caller will have provided
			   the sig.check key from an external source */
			status = iCryptCheckSignatureEx( contentListPtr->object,
								contentListPtr->objectSize, CRYPT_FORMAT_CMS,
								( sigInfo->iSigCheckKey == CRYPT_ERROR ) ? \
									cryptHandle : sigInfo->iSigCheckKey,
								actionListPtr->iCryptHandle, 
								&sigInfo->iExtraData );

			/* If there are authenticated attributes present we have to
			   perform an extra check here to make sure that the content-type
			   specified in the authenticated attributes matches the actual
			   data content type */
			if( cryptStatusOK( status ) && \
				sigInfo->iExtraData != CRYPT_ERROR )
				{
				int contentType;

				status = krnlSendMessage( sigInfo->iExtraData, 
										  IMESSAGE_GETATTRIBUTE, &contentType, 
										  CRYPT_CERTINFO_CMS_CONTENTTYPE );
				if( cryptStatusError( status ) || \
					envelopeInfoPtr->contentType != contentType )
					status = CRYPT_ERROR_SIGNATURE;
				}

			/* If there are unauthenticated attributes present, process 
			   them */
			if( cryptStatusOK( status ) && \
				sigInfo->extraData2 != NULL )
				status = processUnauthAttributes( contentListPtr,
												  sigInfo->extraData2,
												  sigInfo->extraData2Length );
			}
		else
			{
			status = iCryptCheckSignatureEx( contentListPtr->object,
								contentListPtr->objectSize, 
								contentListPtr->formatType, cryptHandle, 
								actionListPtr->iCryptHandle, NULL );

			/* If it's a format that includes signing key info, remember the 
			   key that was used to check the signature in case the user 
			   wants to query it later */
			if( contentListPtr->formatType != CRYPT_FORMAT_PGP )
				{
				krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
				sigInfo->iSigCheckKey = cryptHandle;
				if( !valueLength )
					contentListPtr->flags |= CONTENTLIST_EXTERNALKEY;
				}
			}

		/* Remember the processing result so that we don't have to repeat the
		   processing if queried again.  Since we don't need the encoded
		   signature data any more after this point, we free it to make the
		   memory available for reuse */
		clFree( "addDeenvelopeInfo", contentListPtr->object );
		contentListPtr->object = NULL;
		contentListPtr->objectSize = 0;
		contentListPtr->flags |= CONTENTLIST_PROCESSED;
		sigInfo->processingResult = cryptArgError( status ) ? \
									CRYPT_ERROR_SIGNATURE : status;
		return( status );
		}

	/* If we need private key information and we've been given a password,
	   it's the password required to decrypt the key so we treat this
	   specially */
	if( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
		envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;

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
					( void * ) value, valueLength, KEYMGMT_FLAG_USAGE_CRYPT );
			}
		else
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
					CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
					contentListPtr->issuerAndSerialNumber,
					contentListPtr->issuerAndSerialNumberSize,
					( void * ) value, valueLength, KEYMGMT_FLAG_USAGE_CRYPT );
			}
		status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PRIVATEKEY );

		/* If we managed to get the private key, push it into the envelope.  
		   If the call succeeds, this will import the session key and delete 
		   the required-information list */
		if( status == CRYPT_OK )
			{
			status = addDeenvelopeInfo( envelopeInfoPtr,
										CRYPT_ENVINFO_PRIVATEKEY,
										&getkeyInfo.cryptHandle, 0 );
			krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			}

		return( status );
		}

	/* If we've been given a password, create the appropriate encryption
	   context for it and derive the key from the password */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Create the appropriate encryption context and derive the key into 
		   it */
		setMessageCreateObjectInfo( &createInfo, encrInfo->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
								  ( void * ) &encrInfo->cryptMode, 
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			{
#ifdef USE_PGP
			if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
				status = pgpPasswordToKey( createInfo.cryptHandle, value, 
									valueLength, encrInfo->keySetupAlgo, 
									encrInfo->saltOrIVsize > 0 ? \
										encrInfo->saltOrIV : NULL,
									encrInfo->keySetupIterations );
			else
#endif /* USE_PGP */
				{
				RESOURCE_DATA msgData;

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
					setMessageData( &msgData, ( void * ) value, valueLength );
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
									   createInfo.cryptHandle, &iNewContext );
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			/* In PGP there isn't any encrypted session key, so the context
			   created from the password becomes the bulk encryption
			   context */
			iNewContext = createInfo.cryptHandle;
		}

	/* If we've been given a KEK (symmetric or asymmetric), recreate the 
	   session key by importing it using the KEK */
	if( envInfo == CRYPT_ENVINFO_PRIVATEKEY || \
		envInfo == CRYPT_ENVINFO_KEY )
		{
		/* Import the session key using the KEK */
		status = importSessionKey( envelopeInfoPtr, contentListPtr, 
								   cryptHandle, &iNewContext );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* At this point we have the session key, either by recovering it from a
	   key exchange action or by having it passed to us directly.  If we've
	   been given it directly then we must have reached the encrypted data 
	   so we take a copy and set up the decryption with it */
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;

		status = initEnvelopeEncryption( envelopeInfoPtr, cryptHandle,
						encrInfo->cryptAlgo, encrInfo->cryptMode,
						encrInfo->saltOrIV, encrInfo->saltOrIVsize, TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* The session key context is the newly-created internal one */
		iNewContext = envelopeInfoPtr->iCryptContext;
		}
	else
		{
		/* We've recovered the session key from a key exchange action.  If 
		   we got as far as the encrypted data (indicated by the fact that
		   there's content info present), we set up the decryption.  If we 
		   didn't get this far, it'll be set up by the deenveloping code 
		   when we reach it */
		for( contentListPtr = envelopeInfoPtr->contentList;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
			 contentListPtr = contentListPtr->next );
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
	if( checkAction( envelopeInfoPtr->actionList, ACTION_CRYPT, 
					 iNewContext ) == ACTION_RESULT_INITED )
		return( CRYPT_ERROR_INITED );
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
					   envelopeInfoPtr->contentList );
	envelopeInfoPtr->contentList = envelopeInfoPtr->contentListCurrent = NULL;

	/* If the only error was an information required error, we've now
	   resolved the problem and can continue */
	if( envelopeInfoPtr->errorState == CRYPT_ENVELOPE_RESOURCE )
		envelopeInfoPtr->errorState = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*					Enveloping Information Management Functions				*
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

/* Add enveloping information to an envelope */

static int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE envInfo, 
							const void *value, const int valueLength )
	{
	CRYPT_HANDLE cryptHandle = *( CRYPT_HANDLE * ) value;
	ACTION_LIST *actionListPtr, **actionListHeadPtrPtr, *hashActionPtr;
	ACTION_RESULT actionResult;
	ACTION_TYPE actionType;
	int status;

	/* If it's meta-information, remember the value */
	if( envInfo == CRYPT_ENVINFO_DATASIZE )
		{
		envelopeInfoPtr->payloadSize = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_CONTENTTYPE )
		{
		envelopeInfoPtr->contentType = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_DETACHEDSIGNATURE || \
		envInfo == CRYPT_ENVINFO_MAC )
		{
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		const BOOLEAN flag = ( *( int * ) value ) ? TRUE : FALSE;

		if( envInfo == CRYPT_ENVINFO_DETACHEDSIGNATURE )
			{
			if( flag )
				{
				if( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY )
					/* Detached-sig and attribute-only messages are mutually
					   exclusive */
					return( CRYPT_ERROR_INITED );
				envelopeInfoPtr->flags |= ENVELOPE_DETACHED_SIG;
				}
			else
				envelopeInfoPtr->flags &= ~ENVELOPE_DETACHED_SIG;
			}
		else
			{
			/* The MAC flag is somewhat different from the detached-signature
			   one in that the latter is a modifier for an existing envelope
			   usage while the former changes the usage itself.  Because of
			   this it can only be set to TRUE (if it could be reset the 
			   caller could set non-MAC-compatible options by clearing the
			   flag and then setting it again afterwards), since the envelope
			   usage change occurs at a higher level all we do here is make
			   sure that the flag isn't being cleared */
			if( !flag )
				return( CRYPT_ARGERROR_NUM1 );

			/* There are no known implementations of this content-type, so 
			   for now we disallow any attempts to use it */
			return( CRYPT_ERROR_NOTAVAIL );
			}
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_IATTRIBUTE_INCLUDESIGCERT )
		{
		/* This is on by default so we should only be turning it off */
		assert( ( *( int * ) value ) == FALSE );

		envelopeInfoPtr->flags |= ENVELOPE_NOSIGNINGCERTS;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_IATTRIBUTE_ATTRONLY )
		{
		/* This is off by default so we should only be turning it on */
		assert( ( *( int * ) value ) == TRUE );

		if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
			/* Detached-sig and attribute-only messages are mutually 
			   exclusive */
			return( CRYPT_ERROR_INITED );
		envelopeInfoPtr->flags |= ENVELOPE_ATTRONLY;
		return( CRYPT_OK );
		}

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle ) );

	/* If it's an extra action for the signature, record it with the main
	   signature action */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA || \
		envInfo == CRYPT_ENVINFO_TIMESTAMP_AUTHORITY )
		{
		CRYPT_HANDLE *iCryptHandlePtr;

		/* Find the last signature action that was added and make sure 
		   that it doesn't already have an action of this type attached to 
		   it */
		actionListPtr = envelopeInfoPtr->postActionList;
		if( actionListPtr == NULL )
			return( CRYPT_ERROR_NOTINITED );
		while( actionListPtr->next != NULL && \
			   actionListPtr->next->action == ACTION_SIGN )
			actionListPtr = actionListPtr->next;
		iCryptHandlePtr = ( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) ? \
						  &actionListPtr->iExtraData : \
						  &actionListPtr->iTspSession;
		if( *iCryptHandlePtr != CRYPT_ERROR )
			return( CRYPT_ERROR_INITED );

		/* Increment its reference count and add it to the action */
		krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
		*iCryptHandlePtr = cryptHandle;
		return( CRYPT_OK );
		}

	/* If it's originator information, record it for the enveloped data 
	   header */
	if( envInfo == CRYPT_ENVINFO_ORIGINATOR )
		{
#ifdef USE_FORTEZZA
		/* If there's a session key present, make sure that it's consistent 
		   with the originator info */
		if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
			{
			status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr, 
										 CRYPT_ENVINFO_ORIGINATOR );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Increment its reference count and add it to the action */
		krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
		envelopeInfoPtr->iExtraCertChain = cryptHandle;

		/* Since we're using Fortezza key management, we have to use Skipjack 
		   as the data encryption algorithm */
		envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_SKIPJACK;

		return( CRYPT_OK );
#else
		return( CRYPT_ARGERROR_NUM1 );
#endif /* USE_FORTEZZA */
		}

	/* If it's compression information, set up the compression structures */
	if( envInfo == CRYPT_ENVINFO_COMPRESSION )
		{
#ifdef USE_COMPRESSION
		assert( !( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED ) );

		/* Initialize the compression */
		if( deflateInit( &envelopeInfoPtr->zStream, \
						 Z_DEFAULT_COMPRESSION ) != Z_OK )
			return( CRYPT_ERROR_MEMORY );
		envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;

		return( CRYPT_OK );
#else
		return( CRYPT_ARGERROR_NUM1 );
#endif /* USE_COMPRESSION */
		}

	/* If it's a password, derive a session key encryption context from it */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		CRYPT_ALGO_TYPE cryptAlgo = envelopeInfoPtr->defaultAlgo;

		/* PGP doesn't support both PKC and conventional key exchange 
		   actions or multiple conventional key exchange actions in the same 
		   envelope since the session key is encrypted for the PKC action 
		   but derived from the password for the conventional action */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			( findAction( envelopeInfoPtr->preActionList,
						  ACTION_KEYEXCHANGE_PKC ) != NULL || \
			  envelopeInfoPtr->actionList != NULL ) )
			  return( CRYPT_ERROR_INITED );

		/* Create the appropriate encryption context.  We have to be careful 
		   to ensure that we use an algorithm which is compatible with the 
		   wrapping mechanism.  We don't have to perform this check if the
		   format type is PGP since PGP wrapping always uses CFB mode (so
		   there are no modes that need to be avoided) and the higher-level
		   code has constrained the algorithm type to something which is 
		   encodable using the PGP data format */
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP && \
			( isStreamCipher( cryptAlgo ) || \
			  cryptStatusError( sizeofAlgoIDex( cryptAlgo,
									( CRYPT_ALGO_TYPE ) CRYPT_MODE_CBC, 0 ) ) ) )
			cryptAlgo = CRYPT_ALGO_3DES;
		setMessageCreateObjectInfo( &createInfo, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );

		/* Derive the key into the context and add it to the action list */
#ifdef USE_PGP
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			{
			RESOURCE_DATA msgData;
			BYTE salt[ PGP_SALTSIZE ];
			static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;

			/* PGP uses CFB mode for everything so we change the mode from 
			   the default of CBC to CFB */
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
							 ( void * ) &mode, CRYPT_CTXINFO_MODE );

			/* Generate a salt, derive the key into the context, and insert 
			   it into the action list.  Since PGP doesn't perform a key 
			   exchange of a session key, we insert the password-derived 
			   context directly into the main action list */
			setMessageData( &msgData, salt, PGP_SALTSIZE );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				status = pgpPasswordToKey( createInfo.cryptHandle, 
										   value, valueLength, 
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
			RESOURCE_DATA msgData;

			setMessageData( &msgData, ( void * ) value, valueLength );
			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_KEYING_VALUE );
			if( cryptStatusOK( status ) )
				{
				/* Make sure that this key exchange action isn't already 
				   present and insert it into the list */
				if( checkAction( envelopeInfoPtr->preActionList, 
								 ACTION_KEYEXCHANGE, 
								 createInfo.cryptHandle ) == ACTION_RESULT_INITED )
					status = CRYPT_ERROR_INITED;
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

	/* It's a generic "add a context" action, check that everything is valid.  
	   This is necessary because the PGP format doesn't support the full 
	   range of enveloping capabilities */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		/* PGP doesn't support both PKC and conventional key exchange 
		   actions in the same envelope since the session key is encrypted
		   for the PKC action but derived from the password for the 
		   conventional action */
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE ) != NULL )
			return( CRYPT_ERROR_INITED );

		/* PGP handles multiple signers by nesting signed data rather than
		   attaching multiple signatures, so we can only apply a single
		   signature per envelope */
		if( envInfo == CRYPT_ENVINFO_SIGNATURE && \
			envelopeInfoPtr->postActionList != NULL )
			return( CRYPT_ERROR_INITED );

		/* PGP doesn't allow multiple hash algorithms to be used when signing
		   data (a follow-on from the way nested sigs are handled) */
		if( envInfo == CRYPT_ENVINFO_HASH && \
			envelopeInfoPtr->actionList != NULL )
			return( CRYPT_ERROR_INITED );
		}
	switch( envInfo )
		{
		case CRYPT_ENVINFO_PUBLICKEY:
		case CRYPT_ENVINFO_PRIVATEKEY:
			actionListHeadPtrPtr = &envelopeInfoPtr->preActionList;
			actionType = ACTION_KEYEXCHANGE_PKC;
			break;

		case CRYPT_ENVINFO_KEY:
			/* PGP doesn't allow KEK-based encryption, so if it's a PGP 
			   envelope we drop through and treat it as a session key */
			if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
				{
				actionListHeadPtrPtr = &envelopeInfoPtr->preActionList;
				actionType = ACTION_KEYEXCHANGE;
				break;
				}

		case CRYPT_ENVINFO_SESSIONKEY:
			/* We can't add more than one session key */
			if( envelopeInfoPtr->actionList != NULL )
				return( CRYPT_ERROR_INITED );
			actionListHeadPtrPtr = &envelopeInfoPtr->actionList;
			actionType = ACTION_CRYPT;

#ifdef USE_FORTEZZA
			/* If there's originator info present, make sure that it's 
			   consistent with the new session key */
			if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
				{
				status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr, 
											 CRYPT_ENVINFO_SESSIONKEY );
				if( cryptStatusError( status ) )
					return( status );
				}
#endif /* USE_FORTEZZA */
			break;

		case CRYPT_ENVINFO_HASH:
			actionListHeadPtrPtr = &envelopeInfoPtr->actionList;
			actionType = ACTION_HASH;
			break;

		case CRYPT_ENVINFO_SIGNATURE:
			actionListHeadPtrPtr = &envelopeInfoPtr->postActionList;
			actionType = ACTION_SIGN;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Find the insertion point for this action and make sure that it isn't
	   already present.  The difference between an inited and present return
	   code is that an inited response indicates that the user explicitly 
	   added the action and can't add it again while a present response
	   indicates that the action was added automatically by cryptlib in
	   response to the user adding some other action and shouldn't be 
	   reported as an error, to the user it doesn't make any difference
	   whether the same action was added automatically by cryptlib or
	   explicitly */
	actionResult = checkAction( *actionListHeadPtrPtr, actionType, cryptHandle );
	if( actionResult == ACTION_RESULT_INITED )
		return( CRYPT_ERROR_INITED );
	if( actionResult == ACTION_RESULT_PRESENT )
		return( CRYPT_OK );

	/* Insert the action into the list.  If it's a non-idempotent context 
	   (i.e. one whose state can change based on user actions), we clone it 
	   for our own use, otherwise we just increment its reference count */
	if( actionType == ACTION_HASH || actionType == ACTION_CRYPT )
		{
		CRYPT_ALGO_TYPE cryptAlgo;
		MESSAGE_CREATEOBJECT_INFO createInfo;

		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, 
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			{
			setMessageCreateObjectInfo( &createInfo, cryptAlgo );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( cryptHandle, IMESSAGE_CLONE, NULL, 
								  createInfo.cryptHandle );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		cryptHandle = createInfo.cryptHandle;
		}
	else
		status = krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT );
	actionListPtr = addAction( actionListHeadPtrPtr, 
							   envelopeInfoPtr->memPoolState, actionType, 
							   cryptHandle );
	if( actionListPtr == NULL )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( CRYPT_ERROR_MEMORY );
		}
	if( actionType == ACTION_HASH )
		/* Remember that we need to hook the hash action up to a signature
		   action before we start enveloping data */
		actionListPtr->flags |= ACTION_NEEDSCONTROLLER;

	/* If the newly-inserted action isn't a controlling action, we're done */
	if( actionType != ACTION_SIGN )
		return( status );

	/* If there's no subject hash action available, create one so we can 
	   connect it to the signature action */
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
		   we don't return an error if they add it as well */
		hashActionPtr->flags |= ACTION_ADDEDAUTOMATICALLY;
		}
	else
		/* Find the last hash action that was added */
		hashActionPtr = findLastAction( envelopeInfoPtr->actionList, 
										ACTION_HASH );

	/* Connect the signature action to the last hash action that was added 
	   and remember that this action now has a controlling action */
	actionListPtr->associatedAction = hashActionPtr;
	hashActionPtr->flags &= ~ACTION_NEEDSCONTROLLER;

	return( CRYPT_OK );
	}

/* Check the consistency of envelope resources */

static CRYPT_ATTRIBUTE_TYPE checkMissingInfo( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	BOOLEAN needsSigAction = FALSE;

	/* If there are signature-related options present (signature envelope,
	   detached-sig flag set, hash context present, or CMS attributes or a 
	   TSA session present), there must be a signing key also present */
	for( actionListPtr = envelopeInfoPtr->postActionList;
		 actionListPtr != NULL; actionListPtr = actionListPtr->next )
		if( actionListPtr->iExtraData != CRYPT_ERROR || \
			actionListPtr->iTspSession != CRYPT_ERROR )
			{
			needsSigAction = TRUE;
			break;
			}
	if( ( envelopeInfoPtr->usage == ACTION_SIGN || \
		  envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG || \
		  findAction( envelopeInfoPtr->actionList, ACTION_HASH ) != NULL || \
		  needsSigAction ) && \
		findAction( envelopeInfoPtr->postActionList, ACTION_SIGN ) == NULL )
		return( CRYPT_ENVINFO_SIGNATURE );

	/* If it's a MAC envelope, there must be at least one key exchange action 
	   present.  A few obscure operations may set the usage without setting a 
	   key exchange action, for example making the envelope a MAC envelope 
	   simply indicates that any future key exchange actions should be used 
	   for MAC'ing rather than encryption */
	if( envelopeInfoPtr->usage == ACTION_MAC && \
		findAction( envelopeInfoPtr->preActionList, \
					ACTION_KEYEXCHANGE_PKC ) == NULL && \
		findAction( envelopeInfoPtr->preActionList, \
					ACTION_KEYEXCHANGE ) == NULL )
		/* We return the most generic CRYPT_ENVINFO_KEY error code, since 
		   there are several possible missing attribute types that could
		   be required */
		return( CRYPT_ENVINFO_KEY );

	/* If it's an encryption envelope, there must be a key present at some 
	   level.  This situation doesn't normally occur since the higher-level 
	   code will only set the usage to encryption once a key exchange action 
	   has been added, but we check anyway just to be safe */
	if( envelopeInfoPtr->usage == ACTION_CRYPT && \
		findAction( envelopeInfoPtr->preActionList, \
					ACTION_KEYEXCHANGE_PKC ) == NULL && \
		findAction( envelopeInfoPtr->preActionList, \
					ACTION_KEYEXCHANGE ) == NULL && \
		findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) == NULL )
		return( CRYPT_ENVINFO_KEY );

	/* If there's an originator present, there must be a matching public-key
	   action present */
	if( envelopeInfoPtr->usage == ACTION_CRYPT && \
		envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR && \
		findAction( envelopeInfoPtr->preActionList, 
					ACTION_KEYEXCHANGE_PKC ) == NULL )
		return( CRYPT_ENVINFO_PUBLICKEY );

	return( CRYPT_ATTRIBUTE_NONE );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initResourceHandling( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
		envelopeInfoPtr->addInfo = addDeenvelopeInfo;
	else
		{
		envelopeInfoPtr->addInfo = addEnvelopeInfo;
		envelopeInfoPtr->checkMissingInfo = checkMissingInfo;
		}
	}

