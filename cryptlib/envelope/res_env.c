/****************************************************************************
*																			*
*					cryptlib Enveloping Information Management				*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "pgp.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "pgp.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "envelope/envelope.h"
  #include "envelope/pgp.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Action List Management Functions					*
*																			*
****************************************************************************/

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
   action list, producing an ACTION_RESULT outcome */

ACTION_RESULT checkAction( const ACTION_LIST *actionListStart,
						   const ACTION_TYPE actionType, 
						   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = ( ACTION_LIST * ) actionListStart;
	RESOURCE_DATA msgData;
	BYTE keyID[ KEYID_SIZE ];
	int cryptAlgo, status = CRYPT_OK;

	/* If the action list is empty, there's nothing to check */
	if( actionListPtr == NULL )
		return( ACTION_RESULT_EMPTY );

	/* Get identification information for the action object */
	switch( actionType )
		{
		case ACTION_KEYEXCHANGE:
			/* For conventional key wrap we can't really do much, for raw
			   action objects we'd check the algorithm for duplicates but
			   it's perfectly valid to wrap a single session/MAC key using
			   multiple key wrap objects with the same algorithm */
			break;

		case ACTION_KEYEXCHANGE_PKC:
		case ACTION_SIGN:
			/* It's a PKC object, get the key ID */
			setMessageData( &msgData, keyID, KEYID_SIZE );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S, 
									  &msgData, CRYPT_IATTRIBUTE_KEYID );
			break;

		case ACTION_HASH:
		case ACTION_MAC:
		case ACTION_CRYPT:
			/* It's a raw action object, get the algorithm */
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
									  &cryptAlgo, CRYPT_CTXINFO_ALGO );
			break;

		default:
			assert( NOTREACHED );
			return( ACTION_RESULT_ERROR );
		}
	if( cryptStatusError( status ) )
		return( ACTION_RESULT_ERROR );

	/* Walk down the list from the first to the last action in the action 
	   group, checking each in turn */
	for( actionListPtr = findAction( actionListPtr, actionType );
		 actionListPtr != NULL && actionListPtr->action == actionType;
		 actionListPtr = actionListPtr->next )
		{
		BOOLEAN isDuplicate = FALSE;
		int actionAlgo;

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
		switch( actionType )
			{
			case ACTION_KEYEXCHANGE:
				/* It's a conventional key exchange, there's not much that
				   we can check */
				break;

			case ACTION_KEYEXCHANGE_PKC:
			case ACTION_SIGN:
				/* It's a PKC key exchange or signature action, compare the 
				   two objects by comparing their keys */
				setMessageData( &msgData, keyID, KEYID_SIZE );
				if( cryptStatusOK( \
						krnlSendMessage( actionListPtr->iCryptHandle, 
										 IMESSAGE_COMPARE, &msgData, 
										 MESSAGE_COMPARE_KEYID ) ) )
					isDuplicate = TRUE;
				break;

			case ACTION_HASH:
			case ACTION_MAC:
			case ACTION_CRYPT:
				/* It's a hash/MAC or session key object, compare the two
				   objects by comparing their algorithms */
				if( cryptStatusOK( \
					krnlSendMessage( actionListPtr->iCryptHandle, 
									 IMESSAGE_GETATTRIBUTE, &actionAlgo, 
									 CRYPT_CTXINFO_ALGO ) ) && \
					actionAlgo == cryptAlgo )
					isDuplicate = TRUE;
				break;

			}
		if( isDuplicate )
			{
			/* If the action was added automatically/implicitly as the 
			   result of adding another action then the first attempt to add 
			   it explicitly by the caller isn't an error, with the 
			   ACTION_RESULT_PRESENT code being translated to CRYPT_OK */
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

	/* Create the new action list item */
	if( ( actionListItem = getMemPool( memPoolState,
									   sizeof( ACTION_LIST ) ) ) == NULL )
		return( NULL );
	memset( actionListItem, 0, sizeof( ACTION_LIST ) );
	actionListItem->action = actionType;
	actionListItem->iCryptHandle = ( cryptHandle == CRYPT_UNUSED ) ? \
								   CRYPT_ERROR : cryptHandle;
	actionListItem->iExtraData = CRYPT_ERROR;
	actionListItem->iTspSession = CRYPT_ERROR;

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
	deleteSingleListElement( actionListHead, listPrevPtr, actionListItem );

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
	if( algorithm != CRYPT_ALGO_NONE && \
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

int addKeyset( ENVELOPE_INFO *envelopeInfoPtr,
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
		envInfo == CRYPT_ENVINFO_TIMESTAMP )
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
										   CRYPT_UNUSED, value, valueLength, 
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
				actionResult = checkAction( envelopeInfoPtr->preActionList, 
											ACTION_KEYEXCHANGE, 
											createInfo.cryptHandle );
				if( actionResult == ACTION_RESULT_ERROR || \
					actionResult == ACTION_RESULT_INITED )
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
	if( actionResult == ACTION_RESULT_ERROR )
		return( CRYPT_ARGERROR_NUM1 );
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

void initEnvResourceHandling( ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) );

	/* Set the access method pointers */
	envelopeInfoPtr->addInfo = addEnvelopeInfo;
	envelopeInfoPtr->checkMissingInfo = checkMissingInfo;
	}
