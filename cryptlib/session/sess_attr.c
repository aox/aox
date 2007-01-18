/****************************************************************************
*																			*
*				cryptlib Session Attribute Support Routines					*
*					  Copyright Peter Gutmann 1998-2005						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Reset the internal virtual cursor in a attribute-list item after we've 
   moved the attribute cursor */

#define resetVirtualCursor( attributeListPtr ) \
		if( attributeListPtr != NULL ) \
			attributeListPtr->flags |= ATTR_FLAG_CURSORMOVED

/* Helper function used to access internal attributes within an attribute 
   group */

#if 0	/* Currently unused, will be enabled in 3.3 with the move to 
		   composite attributes for host/client info */

static int accessFunction( ATTRIBUTE_LIST *attributeListPtr,
						   const ATTR_TYPE attrGetType )
	{
	static const CRYPT_ATTRIBUTE_TYPE attributeOrderList[] = {
				CRYPT_SESSINFO_NAME, CRYPT_SESSINFO_PASSWORD,
				CRYPT_SESSINFO_KEY, CRYPT_ATTRIBUTE_NONE, 
				CRYPT_ATTRIBUTE_NONE };
	USER_INFO *userInfoPtr = attributeListPtr->value;
	CRYPT_ATTRIBUTE_TYPE attributeID = userInfoPtr->cursorPos;
	BOOLEAN doContinue;
	int iterationCount = 0;

	/* If we've just moved the cursor onto this attribute, reset the 
	   position to the first internal attribute */
	if( attributeListPtr->flags & ATTR_FLAG_CURSORMOVED )
		{
		attributeID = userInfoPtr->cursorPos = \
						CRYPT_ENVINFO_SIGNATURE_RESULT;
		attributeListPtr->flags &= ~ATTR_FLAG_CURSORMOVED;
		}

	/* If it's an info fetch, return the currently-selected attribute */
	if( attrGetType == ATTR_NONE )
		return( attributeID );

	do
		{
		int i;

		/* Find the position of the current sub-attribute in the attribute 
		   order list and use that to get its successor/predecessor sub-
		   attribute */
		for( i = 0; 
			 attributeOrderList[ i ] != attributeID && \
				attributeOrderList[ i ] != CRYPT_ATTRIBUTE_NONE && \
				i < FAILSAFE_ARRAYSIZE( attributeOrderList, CRYPT_ATTRIBUTE_TYPE ); 
			 i++ );
		if( i >= FAILSAFE_ARRAYSIZE( attributeOrderList, CRYPT_ATTRIBUTE_TYPE ) )
			retIntError_False();
		if( attributeOrderList[ i ] == CRYPT_ATTRIBUTE_NONE )
			attributeID = CRYPT_ATTRIBUTE_NONE;
		else
			if( attrGetType == ATTR_PREV )
				attributeID = ( i < 1 ) ? CRYPT_ATTRIBUTE_NONE : \
										  attributeOrderList[ i - 1 ];
			else
				attributeID = attributeOrderList[ i + 1 ];
		if( attributeID == CRYPT_ATTRIBUTE_NONE )
			/* We've reached the first/last sub-attribute within the current 
			   item/group, tell the caller that there are no more sub-
			   attributes present and they have to move on to the next 
			   group */
			return( FALSE );

		/* Check whether the required sub-attribute is present.  If not, we
		   continue and try the next one */
		doContinue = FALSE;
		switch( attributeID )
			{
			case CRYPT_SESSINFO_NAME:
				break;	/* Always present */
				
			case CRYPT_SESSINFO_PASSWORD:
				if( userInfoPtr->passwordLen <= 0 )
					doContinue = TRUE;
				break;
	
			case CRYPT_SESSINFO_KEY:
				if( userInfoPtr->key == CRYPT_ERROR )
					doContinue = TRUE;
				break;

			default:
				assert( NOTREACHED );
				return( FALSE );
			}
		}
	while( doContinue && iterationCount++ < FAILSAFE_ITERATIONS_SMALL );
	if( iterationCount >= FAILSAFE_ITERATIONS_SMALL )
		retIntError_False();
	attributeListPtr->attributeCursorEntry = attributeID;
	
	return( TRUE );
	}
#endif /* 0 */

/* Callback function used to provide external access to attribute list-
   internal fields */

static const void *getAttrFunction( const void *attributePtr, 
									CRYPT_ATTRIBUTE_TYPE *groupID, 
									CRYPT_ATTRIBUTE_TYPE *attributeID, 
									CRYPT_ATTRIBUTE_TYPE *instanceID,
									const ATTR_TYPE attrGetType )
	{
	ATTRIBUTE_LIST *attributeListPtr = ( ATTRIBUTE_LIST * ) attributePtr;
	BOOLEAN subGroupMove;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Clear return values */
	if( groupID != NULL )
		*groupID = CRYPT_ATTRIBUTE_NONE;
	if( attributeID != NULL )
		*attributeID = CRYPT_ATTRIBUTE_NONE;
	if( instanceID != NULL )
		*instanceID = CRYPT_ATTRIBUTE_NONE;

	/* Move to the next or previous attribute if required.  This isn't just a
	   case of following the prev/next links because some attribute-list 
	   items contain an entire attribute group, so positioning by attribute 
	   merely changes the current selection within the group (== attribute-
	   list item) rather than moving to the previous/next entry.  Because of 
	   this we have to special-case the code for composite items and allow 
	   virtual positioning within the item */
	if( attributeListPtr == NULL )
		return( NULL );
	subGroupMove = ( attrGetType == ATTR_PREV || \
					 attrGetType == ATTR_NEXT ) && \
				   ( attributeListPtr->flags & ATTR_FLAG_COMPOSITE );
	if( subGroupMove )
		{
		assert( attrGetType == ATTR_NEXT || attrGetType == ATTR_PREV );
		assert( attributeListPtr->flags & ATTR_FLAG_COMPOSITE );
		assert( attributeListPtr->accessFunction != NULL );

		subGroupMove = attributeListPtr->accessFunction( attributeListPtr, 
														 attrGetType );
		}

	/* If we're moving by group, move to the next/previous attribute list
	   item and reset the internal virtual cursor.  Note that we always 
	   advance the cursor to the next/prev attribute, it's up to the calling 
	   code to manage attribute by attribute vs.group by group moves */
	if( !subGroupMove && attrGetType != ATTR_CURRENT )
		{
		attributeListPtr = ( attrGetType == ATTR_PREV ) ? \
						   attributeListPtr->prev : attributeListPtr->next;
		resetVirtualCursor( attributeListPtr );
		}
	if( attributeListPtr == NULL )
		return( NULL );

	/* Return ID information to the caller.  We only return the group ID if
	   we've moved within the attribute group, if we've moved from one group
	   to another we leave it cleared because sessions can contain multiple
	   groups with the same ID, and returning an ID identical to the one from
	   the group that we've moved out of would make it look as if we're still 
	   within the same group.  Note that this relies on the behaviour of the
	   attribute-move functions, which first get the current group using 
	   ATTR_CURRENT and then move to the next or previous using ATTR_NEXT/
	   PREV */
	if( groupID != NULL && ( attrGetType == ATTR_CURRENT || subGroupMove ) )
		*groupID = attributeListPtr->groupID;
	if( attributeID != NULL )
		{
		if( attributeListPtr->flags & ATTR_FLAG_COMPOSITE )
			*attributeID = attributeListPtr->accessFunction( attributeListPtr, 
															 ATTR_NONE );
		else
			*attributeID = attributeListPtr->attributeID;
		}

	return( attributeListPtr );
	}

/* Check that a set of attributes is well-formed.  We can perform most of 
   the checking as the attributes are added, but some checks (for example
   whether each username has a corresponding password) aren't possible 
   until all of the attributes are present */

CRYPT_ATTRIBUTE_TYPE checkMissingInfo( const ATTRIBUTE_LIST *attributeListHead,
									   const BOOLEAN isServer )
	{
	const ATTRIBUTE_LIST *attributeListPtr = attributeListHead;

	if( attributeListPtr == NULL )
		return( CRYPT_ATTRIBUTE_NONE );

	/* Make sure that every username attribute is paired up with a 
	   corresponding authentication attribute.  This only applies to 
	   servers, because clients can also use private keys for 
	   authentication, and the presence of a key or password is checked
	   elsewhere */
	if( isServer )
		{
		int iterationCount = 0;

		while( ( attributeListPtr = \
					attributeFind( attributeListPtr, getAttrFunction, 
								   CRYPT_SESSINFO_USERNAME, 
								   CRYPT_ATTRIBUTE_NONE ) ) != NULL && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			/* Make sure that there's a matching authentication attribute */
			if( ( attributeListPtr = attributeListPtr->next ) == NULL )
				return( CRYPT_SESSINFO_PASSWORD );

			/* The authentication attribute is currently a password, but in
			   future versions could also be a public key used for 
			   authentication */
			if( attributeListPtr->attributeID != CRYPT_SESSINFO_PASSWORD )
				return( CRYPT_SESSINFO_PASSWORD );

			/* Move on to the next attribute */
			attributeListPtr = attributeListPtr->next;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Ext( CRYPT_SESSINFO_ACTIVE );
		}

	return( CRYPT_ATTRIBUTE_NONE );
	}

/****************************************************************************
*																			*
*					Attribute Cursor Management Routines					*
*																			*
****************************************************************************/

/* Get/set the attribute cursor */

int getSessionAttributeCursor( ATTRIBUTE_LIST *attributeListHead,
							   ATTRIBUTE_LIST *attributeListCursor, 
							   const CRYPT_ATTRIBUTE_TYPE sessionInfoType,
							   int *valuePtr )
	{
	BOOLEAN initAttributeList = FALSE;

	assert( attributeListHead == NULL || \
			isWritePtr( attributeListHead, sizeof( ATTRIBUTE_LIST ) ) );
	assert( attributeListCursor == NULL || \
			isWritePtr( attributeListCursor, sizeof( ATTRIBUTE_LIST ) ) );
	assert( ( sessionInfoType == CRYPT_ATTRIBUTE_CURRENT ) || \
			( sessionInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP ) || \
			( sessionInfoType > CRYPT_SESSINFO_FIRST && \
			  sessionInfoType < CRYPT_SESSINFO_LAST ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	/* Clear return value */
	*valuePtr = CRYPT_ATTRIBUTE_NONE;

	/* We're querying something that resides in the attribute list, make 
	   sure that there's an attribute list present.  If it's present but 
	   nothing is selected, select the first entry */
	if( attributeListCursor == NULL )
		{
		if( attributeListHead == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		attributeListCursor = attributeListHead;
		resetVirtualCursor( attributeListCursor );
		initAttributeList = TRUE;
		}

	/* If we're reading the group, return the group type */
	if( sessionInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP ) 
		*valuePtr = attributeListCursor->groupID;
	else
		/* If it's a single-attribute group, return the attribute type */
		if( !( attributeListCursor->flags & ATTR_FLAG_COMPOSITE ) )
			*valuePtr = attributeListCursor->groupID;
		else
			/* It's a composite type, get the currently-selected sub-attribute */
			*valuePtr = attributeListCursor->accessFunction( attributeListCursor, 
														 ATTR_NONE );
	return( initAttributeList ? OK_SPECIAL : CRYPT_OK );
	}

int setSessionAttributeCursor( ATTRIBUTE_LIST *attributeListHead,
							   ATTRIBUTE_LIST **attributeListCursorPtr, 
							   const CRYPT_ATTRIBUTE_TYPE sessionInfoType,
							   const int position )
	{
	ATTRIBUTE_LIST *attributeListPtr = *attributeListCursorPtr;

	assert( attributeListHead == NULL || \
			isWritePtr( attributeListHead, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( attributeListCursorPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( sessionInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			sessionInfoType == CRYPT_ATTRIBUTE_CURRENT || \
			sessionInfoType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	assert( position <= CRYPT_CURSOR_FIRST && \
			position >= CRYPT_CURSOR_LAST );

	/* If it's an absolute positioning code, pre-set the attribute cursor if 
	   required */
	if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_LAST )
		{
		if( attributeListHead == NULL )
			return( CRYPT_ERROR_NOTFOUND );

		/* If it's an absolute attribute positioning code, reset the 
		   attribute cursor to the start of the list before we try to move 
		   it, and if it's an attribute positioning code, initialise the 
		   attribute cursor if necessary */
		if( sessionInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			attributeListPtr == NULL )
			{
			attributeListPtr = attributeListHead;
			resetVirtualCursor( attributeListPtr );
			}

		/* If there are no attributes present, return the appropriate error 
		   code */
		if( attributeListPtr == NULL )
			return( ( position == CRYPT_CURSOR_FIRST || \
					  position == CRYPT_CURSOR_LAST ) ? \
					 CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_NOTINITED );
		}
	else
		/* It's a relative positioning code, return a not-inited error 
		   rather than a not-found error if the cursor isn't set since there 
		   may be attributes present but the cursor hasn't been initialised 
		   yet by selecting the first or last absolute attribute */
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTINITED );

	/* Move the cursor */
	attributeListPtr = ( ATTRIBUTE_LIST * ) \
					   attributeMoveCursor( attributeListPtr, getAttrFunction, 
											sessionInfoType, position );
	if( attributeListPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	*attributeListCursorPtr = attributeListPtr;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Find an Attribute							*
*																			*
****************************************************************************/

/* Find a session attribute by type */

const ATTRIBUTE_LIST *findSessionAttribute( const ATTRIBUTE_LIST *attributeListPtr,
								const CRYPT_ATTRIBUTE_TYPE attributeID )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFind( attributeListPtr, getAttrFunction, 
						   attributeID, CRYPT_ATTRIBUTE_NONE ) );
	}

/* Find a session attribute by type and content */

const ATTRIBUTE_LIST *findSessionAttributeEx( const ATTRIBUTE_LIST *attributeListPtr,
								const CRYPT_ATTRIBUTE_TYPE attributeID,
								const void *value, const int valueLength )
	{
	const ATTRIBUTE_LIST *attributeListCursor;
	int iterationCount = 0;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Find the first attribute of this type */
	attributeListCursor = attributeFind( attributeListPtr, getAttrFunction, 
										 attributeID, CRYPT_ATTRIBUTE_NONE );
	if( attributeListCursor == NULL )
		return( NULL );

	/* Walk down the rest of the list looking for an attribute entry whose 
	   contents match the requested contents.  Unfortunately we can't use 
	   attributeFindNextInstance() to help us because that finds the next 
	   instance of the current attribute in an attribute group, not the next 
	   instance in an interleaved set of attributes */
	while( attributeListCursor != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		if( attributeListCursor->attributeID == attributeID && \
			attributeListCursor->valueLength == valueLength && \
			!memcmp( attributeListCursor->value, value, valueLength ) )
			break;
		attributeListCursor = attributeListCursor->next;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( attributeListCursor );
	}

/****************************************************************************
*																			*
*								Add an Attribute							*
*																			*
****************************************************************************/

/* Add a session attribute.  There are two versions of this function, the
   standard version and an extended version that allows the caller to 
   specify an access function to access session subtype-specific internal
   attributes when the data being added is structured session-type-specific
   data, and a set of ATTR_FLAG_xxx flags to provide precise control over
   the attribute handling */

static int addAttribute( ATTRIBUTE_LIST **listHeadPtr,
						 const CRYPT_ATTRIBUTE_TYPE groupID,
						 const CRYPT_ATTRIBUTE_TYPE attributeID,
						 const void *data, const int dataLength, 
						 const int dataMaxLength, 
						 const ATTRACCESSFUNCTION accessFunction, 
						 const int flags )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint = NULL;

	assert( isWritePtr( listHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( groupID > CRYPT_SESSINFO_FIRST && \
			groupID < CRYPT_SESSINFO_LAST );
	assert( attributeID > CRYPT_SESSINFO_FIRST && \
			attributeID < CRYPT_SESSINFO_LAST );
	assert( ( data == NULL ) || \
			( isReadPtr( data, dataLength ) && \
			  dataLength <= dataMaxLength ) );
	assert( dataMaxLength >= 0 );
	assert( !( flags & ATTR_FLAG_COMPOSITE ) || \
			accessFunction != NULL );

	/* Find the correct insertion point and make sure that the attribute 
	   isn't already present */
	if( *listHeadPtr != NULL )
		{
		ATTRIBUTE_LIST *prevElement = NULL;
		int iterationCount = 0;

		for( insertPoint = *listHeadPtr; 
			 insertPoint != NULL && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX;
			 insertPoint = insertPoint->next )
			{
			/* If this is a non-multivalued attribute, make sure that it
			   isn't already present */
			if( !( flags & ATTR_FLAG_MULTIVALUED ) && \
				insertPoint->attributeID == attributeID )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError();
		insertPoint = prevElement;
		}

	/* Allocate memory for the new element and copy the information across.  
	   The data is stored in storage ... storage + dataLength, with storage
	   reserved up to dataMaxLength (if it's greater than dataLength) to
	   allow the contents to be replaced with a new fixed-length value  */
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addSessionAttribute", sizeof( ATTRIBUTE_LIST ) + \
													   dataMaxLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, dataMaxLength );
	newElement->groupID = groupID;
	newElement->attributeID = attributeID;
	newElement->accessFunction = accessFunction;
	newElement->flags = flags;
	if( data == NULL )
		newElement->intValue = dataLength;
	else
		{
		assert( isReadPtr( data, dataLength ) );

		memcpy( newElement->value, data, dataLength );
		newElement->valueLength = dataLength;
		}
	insertDoubleListElement( listHeadPtr, insertPoint, newElement );

	return( CRYPT_OK );
	}

int addSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
						 const CRYPT_ATTRIBUTE_TYPE attributeID,
						 const void *data, const int dataLength )
	{
	/* Pre-3.3 kludge: Set the groupID to the attributeID since groups 
	   aren't defined yet */
	return( addAttribute( listHeadPtr, attributeID, attributeID, data, 
						  dataLength, dataLength, NULL, ATTR_FLAG_NONE ) );
	}

int addSessionAttributeEx( ATTRIBUTE_LIST **listHeadPtr,
						   const CRYPT_ATTRIBUTE_TYPE attributeID,
						   const void *data, const int dataLength, 
						   const int flags )
	{
	/* Pre-3.3 kludge: Set the groupID to the attributeID since groups 
	   aren't defined yet */
	return( addAttribute( listHeadPtr, attributeID, attributeID, data, 
						  dataLength, dataLength, NULL, flags ) );
	}

int addSessionAttributeComposite( ATTRIBUTE_LIST **listHeadPtr,
								  const CRYPT_ATTRIBUTE_TYPE attributeID,
								  const ATTRACCESSFUNCTION accessFunction, 
								  const void *data, const int dataLength,
								  const int flags )
	{
	/* For composite attributes the groupID is the attributeID, with the
	   actual attributeID being returned by the accessFunction */
	return( addAttribute( listHeadPtr, attributeID, attributeID, data, 
						  dataLength, dataLength, accessFunction, flags ) );
	}

/* Update a session attribute, either by replacing an existing entry if it
   already exists or by adding a new entry */

int updateSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeID,
							const void *data, const int dataLength,
							const int dataMaxLength, const int flags )
	{
	ATTRIBUTE_LIST *attributeListPtr = *listHeadPtr;

	assert( !( flags & ATTR_FLAG_MULTIVALUED ) );

	/* Find the first attribute of this type */
	attributeListPtr = attributeFind( attributeListPtr, getAttrFunction, 
									  attributeID, CRYPT_ATTRIBUTE_NONE );

	/* If the attribute is already present, update the value */
	if( attributeListPtr != NULL )
		{
		assert( attributeListPtr->attributeID == attributeID );
		assert( ( attributeListPtr->valueLength == 0 && \
				  !memcmp( attributeListPtr->value, \
						   "\x00\x00\x00\x00", 4 ) ) || \
				attributeListPtr->valueLength > 0 );
		assert( isReadPtr( data, dataLength ) && \
				dataLength <= dataMaxLength );

		zeroise( attributeListPtr->value, attributeListPtr->valueLength );
		memcpy( attributeListPtr->value, data, dataLength );
		attributeListPtr->valueLength = dataLength;
		return( CRYPT_OK );
		}

	/* The attribute isn't already present, it's a straight add */
	return( addAttribute( listHeadPtr, attributeID, attributeID, data, 
						  dataLength, dataMaxLength, NULL, flags ) );
	}

/****************************************************************************
*																			*
*								Delete an Attribute							*
*																			*
****************************************************************************/

/* Reset a session attribute.  This is used to clear the data in attributes
   such as passwords that can be updated over different runs of a session */

void resetSessionAttribute( ATTRIBUTE_LIST *attributeListPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeID )
	{
	/* Find the attribute to reset */
	attributeListPtr = ( ATTRIBUTE_LIST * ) \
				findSessionAttribute( attributeListPtr, attributeID );
	if( attributeListPtr == NULL )
		return;

	zeroise( attributeListPtr->value, attributeListPtr->valueLength );
	attributeListPtr->valueLength = 0;
	}

/* Delete a complete set of session attributes */

void deleteSessionAttribute( ATTRIBUTE_LIST **attributeListHead,
							 ATTRIBUTE_LIST **attributeListCurrent,
							 ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isWritePtr( attributeListHead, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( attributeListCurrent, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* If we're about to delete the attribute that's pointed to by the 
	   current-attribute pointer, advance it to the next attribute.  If 
	   there's no next attribute, move it to the previous attribute.  This 
	   behaviour is the most logically consistent, it means that we can do 
	   things like deleting an entire attribute list by repeatedly deleting 
	   a single attribute */
	if( *attributeListCurrent == attributeListPtr )
		*attributeListCurrent = ( attributeListPtr->next != NULL ) ? \
								attributeListPtr->next : \
								attributeListPtr->prev;

	/* Remove the item from the list */
	deleteDoubleListElement( attributeListHead, attributeListPtr );

	/* Clear all data in the list item and free the memory */
	endVarStruct( attributeListPtr, ATTRIBUTE_LIST );
	clFree( "deleteSessionAttribute", attributeListPtr );
	}

void deleteSessionAttributes( ATTRIBUTE_LIST **attributeListHead,
							  ATTRIBUTE_LIST **attributeListCurrent )
	{
	ATTRIBUTE_LIST *attributeListCursor = *attributeListHead;
	int iterationCount = 0;

	assert( isWritePtr( attributeListHead, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( attributeListCurrent, sizeof( ATTRIBUTE_LIST * ) ) );

	/* If the list was empty, return now */
	if( attributeListCursor == NULL )
		{
		assert( *attributeListCurrent == NULL );
		return;
		}

	/* Destroy any remaining list items */
	while( attributeListCursor != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;

		attributeListCursor = attributeListCursor->next;
		deleteSessionAttribute( attributeListHead, attributeListCurrent, 
								itemToFree );
		}
	*attributeListCurrent = NULL;

	assert( *attributeListHead == NULL );
	}

#endif /* USE_SESSIONS */
