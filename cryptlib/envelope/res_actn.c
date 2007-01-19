/****************************************************************************
*																			*
*						cryptlib Envelope Action Management					*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Find an Action								*
*																			*
****************************************************************************/

/* Find an action of a given type and the last action of a given type.
   Since the lists are sorted by action type, the generic findAction()
   finds the start of an action group */

ACTION_LIST *findAction( ACTION_LIST *actionListPtr,
						 const ACTION_TYPE actionType )
	{
	int iterationCount = 0;
	
	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );
	assert( actionType == ACTION_KEYEXCHANGE || \
			actionType == ACTION_KEYEXCHANGE_PKC || \
			actionType == ACTION_SIGN || \
			actionType == ACTION_HASH || \
			actionType == ACTION_MAC || \
			actionType == ACTION_CRYPT );

	while( actionListPtr != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		if( actionListPtr->action == actionType )
			return( actionListPtr );
		actionListPtr = actionListPtr->next;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( NULL );
	}

ACTION_LIST *findLastAction( ACTION_LIST *actionListPtr,
							 const ACTION_TYPE actionType )
	{
	int iterationCount = 0;

	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );
	assert( actionType == ACTION_KEYEXCHANGE || \
			actionType == ACTION_KEYEXCHANGE_PKC || \
			actionType == ACTION_SIGN || \
			actionType == ACTION_HASH || \
			actionType == ACTION_MAC || \
			actionType == ACTION_CRYPT );

	/* Find the start of the action group */
	actionListPtr = findAction( actionListPtr, actionType );
	if( actionListPtr == NULL )
		return( NULL );

	/* Find the end of the action group */
	while( actionListPtr->next != NULL && \
		   actionListPtr->next->action == actionType && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		actionListPtr = actionListPtr->next;
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();
	return( actionListPtr );
	}

/****************************************************************************
*																			*
*								Add/Delete an Action						*
*																			*
****************************************************************************/

/* Add a new action to the end of an action list */

ACTION_LIST *addAction( ACTION_LIST **actionListHeadPtrPtr,
						MEMPOOL_STATE memPoolState,
						const ACTION_TYPE actionType,
						const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = *actionListHeadPtrPtr, *prevActionPtr = NULL;
	ACTION_LIST *actionListItem;
	int iterationCount = 0;

	assert( isWritePtr( actionListHeadPtrPtr, sizeof( ACTION_LIST * ) ) );
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( actionType == ACTION_KEYEXCHANGE || \
			actionType == ACTION_KEYEXCHANGE_PKC || \
			actionType == ACTION_SIGN || \
			actionType == ACTION_HASH || \
			actionType == ACTION_MAC || \
			actionType == ACTION_CRYPT );
	assert( ( cryptHandle == CRYPT_UNUSED ) || \
			isHandleRangeValid( cryptHandle ) );

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
	while( actionListPtr != NULL && actionListPtr->action <= actionType && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		prevActionPtr = actionListPtr;
		actionListPtr = actionListPtr->next;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();
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
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( actionListItem, sizeof( ACTION_LIST ) ) );

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
	int iterationCount = 0;

	assert( isWritePtr( actionListHead, sizeof( ACTION_LIST * ) ) );
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( actionListItem, sizeof( ACTION_LIST ) ) );

	/* Find the previons entry in the list */
	for( listPrevPtr = *actionListHead;
		 listPrevPtr != NULL && listPrevPtr->next != actionListItem && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 listPrevPtr = listPrevPtr->next );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();

	/* Remove the item from the list */
	deleteSingleListElement( actionListHead, listPrevPtr, actionListItem );

	/* Clear all data in the list item and free the memory */
	deleteActionListItem( memPoolState, actionListItem );
	}

/* Delete an action list */

void deleteActionList( MEMPOOL_STATE memPoolState,
					   ACTION_LIST *actionListPtr )
	{
	int iterationCount = 0;

	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	while( actionListPtr != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		ACTION_LIST *actionListItem = actionListPtr;

		actionListPtr = actionListPtr->next;
		deleteActionListItem( memPoolState, actionListItem );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();
	}

/* Delete any orphaned actions, for example automatically-added hash actions
   that were overridden by user-supplied alternate actions */

void deleteUnusedActions( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr = envelopeInfoPtr->actionList;
	int iterationCount = 0;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Check for unattached hash/MAC or encryption actions and delete them */
	while( actionListPtr != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
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
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();
	}

/****************************************************************************
*																			*
*								Check an Action								*
*																			*
****************************************************************************/

/* Check a new action to make sure that it isn't already present in the
   action list, producing an ACTION_RESULT outcome */

ACTION_RESULT checkAction( const ACTION_LIST *actionListStart,
						   const ACTION_TYPE actionType,
						   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = ( ACTION_LIST * ) actionListStart;
	MESSAGE_DATA msgData;
	BYTE keyID[ KEYID_SIZE + 8 ];
	int cryptAlgo, iterationCount, status = CRYPT_OK;

	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );
	assert( ( actionType == ACTION_KEYEXCHANGE ) || \
			isHandleRangeValid( cryptHandle ) );

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
	iterationCount = 0;
	for( actionListPtr = findAction( actionListPtr, actionType );
		 actionListPtr != NULL && actionListPtr->action == actionType && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
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
		   for now we assume that the user won't do anything silly (in any 
		   case for any key exchange action the only thing that a duplicate 
		   will do is result in unnecessary bloating of the envelope 
		   header) */
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
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	return( ACTION_RESULT_OK );
	}

/* Perform a sanity-check to ensure that the actions in an envelope are
   consistent.  There are two approaches to this, take the envelope usage 
   and check that everything is consistent with it, or take the actions
   and make sure that they're consistent with the usage (and each other).  
   We perform the latter type of check, which is somewhat simpler.  The
   requirements that we enforce are:

			|	Pre		|	In		|	Post	|
	--------+-----------+-----------+-----------+-----
	   SIG	|	  -		|	Hash	|	 Sig	| CMS
			|	  -		| 1x Hash	|  1x Sig	| PGP
	--------+-----------+-----------+-----------+-----
	   MAC	| Keyex,PKC	|	Hash	|	  -		| CMS
			|	  -		|	  -		|	  -		| PGP
	--------+-----------+-----------+-----------+-----
	  COPR	|	  -		|	  -		|	  -		| CMS
			|	  -		|	  -		|	  -		| PGP
	--------+-----------+-----------+-----------+-----
	  ENCR	| Keyex,PKC	|	Crypt	|	  -		| CMS
			|	 PKC	| 1x Crypt	|	  -		| PGP

   In the case of ENCR, the pre-actions can be absent if we're using raw 
   session-key encryption */

int checkActions( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* If there are no pre-, post-, or main actions (i.e. it's a compressed
	   or data-only envelope), we're done */
	if( envelopeInfoPtr->actionList == NULL )
		{
		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_COMPRESS && \
			envelopeInfoPtr->usage != ACTION_NONE )
			return( FALSE );

		/* There can be no pre- or post-actions present for this usage */
		if( envelopeInfoPtr->preActionList != NULL || \
			envelopeInfoPtr->postActionList != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If there are pre-actions, it has to be a key exchange + encryption or
	   MAC actions */
	if( envelopeInfoPtr->preActionList != NULL )
		{
		int actionCount = 0, iterationCount;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			return( FALSE );

		/* Pre-actions can only be key exchange actions, and have to be sorted
		   by action group */
		for( actionListPtr = envelopeInfoPtr->preActionList;
			 actionListPtr != NULL && \
				actionListPtr->action == ACTION_KEYEXCHANGE_PKC;
			actionListPtr = actionListPtr->next );
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			actionListPtr != NULL )
			/* PGP can't have any conventional keyex actions, since the 
			   password is used to directly derive the session key */
			return( FALSE );
		iterationCount = 0;
		while( actionListPtr != NULL && \
			   actionListPtr->action == ACTION_KEYEXCHANGE && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
				actionListPtr = actionListPtr->next;
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Boolean();
		if( actionListPtr != NULL )
			return( FALSE );

		/* Key exchange must be followed by a single crypt or one or more
		   MAC actions */
		assert( envelopeInfoPtr->actionList != NULL );
		iterationCount = 0;
		for( actionListPtr = envelopeInfoPtr->actionList;
			 actionListPtr != NULL && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX; 
			 actionListPtr = actionListPtr->next )
			{
			if( actionListPtr->action == ACTION_CRYPT )
				actionCount++;
			else
				{
				if( actionListPtr->action != ACTION_MAC )
					return( FALSE );
				if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
					/* PGP doesn't support MAC'd envelopes */
					return( FALSE );
				}
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Boolean();
		if( actionCount > 1 )
			return( FALSE );

		/* There can't be any post-actions */
		if( envelopeInfoPtr->postActionList != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If there are post-actions, it has to be a hash + signature actions */
	if( envelopeInfoPtr->postActionList != NULL )
		{
		int hashActionCount = 0, sigActionCount = 0, iterationCount;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_SIGN )
			return( FALSE );

		/* There can't be any pre-actions */
		if( envelopeInfoPtr->preActionList != NULL )
			return( FALSE );

		/* Signature must be preceded by one or more hash actions */
		if( envelopeInfoPtr->actionList == NULL )
			return( FALSE );
		iterationCount = 0;
		for( actionListPtr = envelopeInfoPtr->actionList;
			 actionListPtr != NULL && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX; 
			 actionListPtr = actionListPtr->next )
			{
			if( actionListPtr->action != ACTION_HASH )
				return( FALSE );
			hashActionCount++;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Boolean();

		/* PGP can only have a single hash per signed envelope */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && hashActionCount > 1 )
			return( FALSE );

		/* Hash actions must be followed by one or more signature actions */
		iterationCount = 0;
		for( actionListPtr = envelopeInfoPtr->postActionList;
			 actionListPtr != NULL && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX; 
			 actionListPtr = actionListPtr->next )
			{
			if( actionListPtr->action != ACTION_SIGN )
				return( FALSE );
			sigActionCount++;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Boolean();

		/* PGP can only have a single signature, multiple signatures are 
		   handled by nesting envelopes */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && sigActionCount > 1 )
			return( FALSE );

		return( TRUE );
		}

	/* If there's a standalone session-key encryption action, it has to be
	   the only action present */
	actionListPtr = envelopeInfoPtr->actionList;
	if( actionListPtr->action == ACTION_CRYPT )
		{
		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			return( FALSE );

		/* There can only be one encryption action present */
		if( actionListPtr->next != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If we're processing PGP-encrypted data with an MDC at the end of the 
	   encrypted data then it's possible to have an encryption envelope with
	   a hash action (which must be followed by an encryption action) */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
		actionListPtr->action == ACTION_HASH && \
		actionListPtr->next != NULL && \
		actionListPtr->next->action == ACTION_CRYPT )
		{
		ACTION_LIST *nextActionPtr = actionListPtr->next;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			return( FALSE );

		/* Make sure that the encryption action is the only other action */
		if( nextActionPtr->action != ACTION_CRYPT || \
			nextActionPtr->next != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* Anything else has to be a signing envelope */
	if( envelopeInfoPtr->usage != ACTION_SIGN )
		return( FALSE );

	/* When we're de-enveloping a signed envelope, we can have standalone
	   hash actions before we get to the signature data and add post-
	   actions */
	if( ( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
		actionListPtr->action == ACTION_HASH )
		{
		int iterationCount = 0;
		
		while( actionListPtr != NULL && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			if( actionListPtr->action != ACTION_HASH )
				return( FALSE );
			actionListPtr = actionListPtr->next;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Boolean();
		return( TRUE );
		}

	/* Everything else is an error */
	return( FALSE );
	}
#endif /* USE_ENVELOPES */
