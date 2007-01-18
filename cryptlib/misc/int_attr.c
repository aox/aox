/****************************************************************************
*																			*
*						cryptlib Internal Attribute API						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Attribute Location Routines						*
*																			*
****************************************************************************/

/* Find the start and end of an attribute group from an attribute within
   the group */

void *attributeFindStart( const void *attributePtr,
						  GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID;
	int iterationCount;

	if( attributePtr == NULL )
		return( NULL );

	/* Move backwards until we find the start of the attribute */
	if( getAttrFunction( attributePtr, &groupID, NULL, NULL, 
						 ATTR_CURRENT ) == NULL )
		return( NULL );
	assert( groupID != CRYPT_ATTRIBUTE_NONE );
	for( iterationCount = 0; iterationCount < FAILSAFE_ITERATIONS_MAX; 
		 iterationCount++ )
		{
		CRYPT_ATTRIBUTE_TYPE prevGroupID;
		const void *prevPtr;

		prevPtr = getAttrFunction( attributePtr, &prevGroupID, NULL, NULL,
								   ATTR_PREV );
		if( prevPtr == NULL || prevGroupID != groupID )
			/* We've reached the start of the list or a different attribute
			   group, this is the start of the current group */
			break;
		attributePtr = prevPtr;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( ( void * ) attributePtr );
	}

void *attributeFindEnd( const void *attributePtr,
						GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID;
	int iterationCount;

	if( attributePtr == NULL )
		return( NULL );

	/* Move forwards until we're just before the start of the next
	   attribute */
	if( getAttrFunction( attributePtr, &groupID, NULL, NULL, 
						 ATTR_CURRENT ) == NULL )
		return( NULL );
	assert( groupID != CRYPT_ATTRIBUTE_NONE );
	for( iterationCount = 0; iterationCount < FAILSAFE_ITERATIONS_MAX; 
		 iterationCount++ )
		{
		CRYPT_ATTRIBUTE_TYPE nextGroupID;
		const void *nextPtr;

		nextPtr = getAttrFunction( attributePtr, &nextGroupID, NULL, NULL,
								   ATTR_NEXT );
		if( nextPtr == NULL || nextGroupID != groupID )
			/* We've reached the end of the list or a different attribute
			   group, this is the end of the current group */
			break;
		attributePtr = nextPtr;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( ( void * ) attributePtr );
	}

/* Find an attribute in a list of attributes */

void *attributeFind( const void *attributePtr,
					 GETATTRFUNCTION getAttrFunction,
					 const CRYPT_ATTRIBUTE_TYPE attributeID,
					 const CRYPT_ATTRIBUTE_TYPE instanceID )
	{
	CRYPT_ATTRIBUTE_TYPE currAttributeID, currInstanceID;
	int iterationCount = 0;

	assert( isAttribute( attributeID ) || isInternalAttribute( attributeID ) );
	assert( instanceID == CRYPT_ATTRIBUTE_NONE || \
			isAttribute( attributeID ) || isInternalAttribute( attributeID ) );

	if( attributePtr == NULL )
		return( NULL );

	/* Find the attribute in the list */
	attributePtr = getAttrFunction( attributePtr, NULL, &currAttributeID, 
									NULL, ATTR_CURRENT );
	assert( attributePtr == NULL || currAttributeID != CRYPT_ATTRIBUTE_NONE );
	while( attributePtr != NULL && currAttributeID != attributeID && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )	
		attributePtr = getAttrFunction( attributePtr, NULL,
										&currAttributeID, NULL,
										ATTR_NEXT );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();
	if( attributePtr == NULL || instanceID == CRYPT_ATTRIBUTE_NONE )
		/* If the attribute isn't present or we're not looking for a 
		   particular instance, we're done */
		return( ( void * ) attributePtr );

	/* Find the attribute instance */
	attributePtr = getAttrFunction( attributePtr, NULL, &currAttributeID, 
									&currInstanceID, ATTR_CURRENT );
	assert( currAttributeID != CRYPT_ATTRIBUTE_NONE );
	iterationCount = 0;
	while( attributePtr != NULL && currAttributeID == attributeID && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )	
		{
		if( currInstanceID == instanceID )
			return( ( void * ) attributePtr );
		attributePtr = getAttrFunction( attributePtr, NULL,
										&currAttributeID, &currInstanceID,
										ATTR_NEXT );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();
	return( NULL );
	}

/* Find the next instance of an attribute in an attribute group.  This is
   used to step through multiple instances of an attribute, for example in
   a cert extension containing a SEQUENCE OF <attribute> */

void *attributeFindNextInstance( const void *attributePtr,
								 GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID, attributeID;
	CRYPT_ATTRIBUTE_TYPE currGroupID, currAttributeID;
	int iterationCount = 0;

	if( attributePtr == NULL )
		return( NULL );

	/* Skip the current field */
	attributePtr = getAttrFunction( attributePtr, &groupID, &attributeID, 
									NULL, ATTR_CURRENT );
	assert( groupID != CRYPT_ATTRIBUTE_NONE && \
			attributeID != CRYPT_ATTRIBUTE_NONE );
	if( attributePtr != NULL )
		attributePtr = getAttrFunction( attributePtr, &currGroupID,
										&currAttributeID, NULL,
										ATTR_NEXT );

	/* Step through the remaining attributes in the group looking for
	   another occurrence of the current attribute */
	while( attributePtr != NULL && currGroupID == groupID && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		if( currAttributeID == attributeID )
			return( ( void * ) attributePtr );
		attributePtr = getAttrFunction( attributePtr, &currGroupID,
										&currAttributeID, NULL,
										ATTR_NEXT );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	/* We couldn't find another instance of the attribute in this group */
	return( NULL );
	}

/****************************************************************************
*																			*
*						Attribute Cursor Movement Routines					*
*																			*
****************************************************************************/

/* Moving the cursor by attribute group is a bit more complex than just 
   stepping forwards or backwards along the attribute list.  First we have 
   to find the start or end of the current group.  Then we move to the start 
   of the previous (via ATTR_PREV and attributeFindStart()), or start of the
   next (via ATTR_NEXT) group beyond that.  This has the effect of moving us 
   from anywhere in the current group to the start of the preceding or 
   following group.  Finally, we repeat this as required */

static const void *moveCursorByGroup( const void *currentCursor,
									  GETATTRFUNCTION getAttrFunction,
									  const int cursorMoveType, 
									  int count, const BOOLEAN absMove )
	{
	const void *newCursor = currentCursor, *lastCursor = NULL;
	int iterationCount = 0;

	while( count-- > 0 && newCursor != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		lastCursor = newCursor;
		if( cursorMoveType == CRYPT_CURSOR_FIRST || \
			cursorMoveType == CRYPT_CURSOR_PREVIOUS )
			{
			/* Move from the start of the current group to the start of the
			   preceding group */
			newCursor = attributeFindStart( newCursor, getAttrFunction );
			if( newCursor != NULL )
				newCursor = getAttrFunction( newCursor, NULL, NULL, NULL,
											 ATTR_PREV );
			if( newCursor != NULL )
				newCursor = attributeFindStart( newCursor, getAttrFunction );
			}
		else
			{
			/* Move from the end of the current group to the start of the
			   next group */
			newCursor = attributeFindEnd( newCursor, getAttrFunction );
			if( newCursor != NULL )
				newCursor = getAttrFunction( newCursor, NULL, NULL, NULL,
											 ATTR_NEXT );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();
	assert( lastCursor != NULL );	/* We went through the loop at least once */

	/* If the new cursor is NULL, we've reached the start or end of the
	   attribute list */
	if( newCursor == NULL )
		{
		/* If it's an absolute move we've reached our destination, otherwise
		   there's nowhere left to move to.  We move to the start of the
		   first or last attribute that we got to before we ran out of
		   attributes to make sure that we don't fall off the start/end of
		   the list */
		return( absMove ? \
				attributeFindStart( lastCursor, getAttrFunction ) : NULL );
		}

	/* We've found what we were looking for */
	return( newCursor );
	}

/* Moving by attribute or attribute instance is rather simpler than moving by
   group.  For attributes we move backwards or forwards until we either run 
   out of attributes or the next attribute belongs to a different group.  For 
   attribute instances we move similarly, except that we stop when we reach 
   an attribute whose group type, attribute type, and instance type don't 
   match the current one.  We have to explicitly keep track of whether the 
   cursor was successfully moved rather than checking that it's value has 
   changed because some object types implement composite attributes that 
   maintain an attribute-internal virtual cursor, which can return the same 
   attribute pointer multiple times if the move is internal to the 
   (composite) attribute */

static const void *moveCursorByAttribute( const void *currentCursor,
										  GETATTRFUNCTION getAttrFunction,
										  const int cursorMoveType, 
										  int count, const BOOLEAN absMove )
	{
	CRYPT_ATTRIBUTE_TYPE groupID;
	BOOLEAN cursorMoved = FALSE;
	const void *newCursor = currentCursor;
	int iterationCount = 0;

	if( getAttrFunction( currentCursor, &groupID, NULL, NULL, 
						 ATTR_CURRENT ) == NULL )
		return( NULL );
	assert( groupID != CRYPT_ATTRIBUTE_NONE );
	if( cursorMoveType == CRYPT_CURSOR_FIRST || \
		cursorMoveType == CRYPT_CURSOR_PREVIOUS )
		{
		CRYPT_ATTRIBUTE_TYPE prevGroupID;
		const void *prevCursor;

		prevCursor = getAttrFunction( newCursor, &prevGroupID, NULL, 
									  NULL, ATTR_PREV );
		while( prevCursor != NULL && count-- > 0 && \
			   prevGroupID == groupID && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			newCursor = prevCursor;
			prevCursor = getAttrFunction( newCursor, &prevGroupID, NULL, 
										  NULL, ATTR_PREV );
			cursorMoved = TRUE;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Null();
		}
	else
		{
		CRYPT_ATTRIBUTE_TYPE nextGroupID;
		const void *nextCursor;

		nextCursor = getAttrFunction( newCursor, &nextGroupID, NULL,
									  NULL, ATTR_NEXT );
		while( nextCursor != NULL && count-- > 0 && \
			   nextGroupID == groupID && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			newCursor = nextCursor;
			nextCursor = getAttrFunction( newCursor, &nextGroupID, NULL,
										  NULL, ATTR_NEXT );
			cursorMoved = TRUE;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Null();
		}

	if( !absMove && !cursorMoved )
		return( NULL );
	return( newCursor );
	}

static const void *moveCursorByInstance( const void *currentCursor,
										 GETATTRFUNCTION getAttrFunction,
										 const int cursorMoveType, 
										 int count, const BOOLEAN absMove )
	{
	CRYPT_ATTRIBUTE_TYPE groupID, attributeID, instanceID;
	BOOLEAN cursorMoved = FALSE;
	const void *newCursor = currentCursor;
	int iterationCount = 0;

	if( getAttrFunction( currentCursor, &groupID, &attributeID, 
						 &instanceID, ATTR_CURRENT ) == NULL )
		return( NULL );
	assert( groupID != CRYPT_ATTRIBUTE_NONE && \
			attributeID != CRYPT_ATTRIBUTE_NONE );
	if( cursorMoveType == CRYPT_CURSOR_FIRST || \
		cursorMoveType == CRYPT_CURSOR_PREVIOUS )
		{
		CRYPT_ATTRIBUTE_TYPE prevGroupID, prevAttrID, prevInstID;
		const void *prevCursor;

		prevCursor = getAttrFunction( newCursor, &prevGroupID,
									  &prevAttrID, &prevInstID,
									  ATTR_PREV );
		while( prevCursor != NULL && count-- > 0 && \
			   prevGroupID == groupID && prevAttrID == attributeID && \
			   prevInstID == instanceID && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			newCursor = prevCursor;
			prevCursor = getAttrFunction( newCursor, &prevGroupID,
										  &prevAttrID, &prevInstID,
										  ATTR_PREV );
			cursorMoved = TRUE;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Null();
		}
	else
		{
		CRYPT_ATTRIBUTE_TYPE nextGroupID, nextAttrID, nextInstID;
		const void *nextCursor;

		nextCursor = getAttrFunction( newCursor, &nextGroupID,
									  &nextAttrID, &nextInstID,
									  ATTR_NEXT );
		while( nextCursor != NULL && count-- > 0 && \
			   nextGroupID == groupID && nextAttrID == attributeID && \
			   nextInstID == instanceID && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			{
			newCursor = nextCursor;
			nextCursor = getAttrFunction( newCursor, &nextGroupID,
										  &nextAttrID, &nextInstID,
										  ATTR_NEXT );
			cursorMoved = TRUE;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
			retIntError_Null();
		}

	if( !absMove && !cursorMoved )
		return( NULL );
	return( newCursor );
	}

/* Move the attribute cursor relative to the current cursor position */

const void *attributeMoveCursor( const void *currentCursor,
								 GETATTRFUNCTION getAttrFunction,
								 const CRYPT_ATTRIBUTE_TYPE attributeMoveType,
								 const int cursorMoveType )
	{
	const BOOLEAN absMove = ( cursorMoveType == CRYPT_CURSOR_FIRST || \
							  cursorMoveType == CRYPT_CURSOR_LAST ) ? \
							TRUE : FALSE;
	int count;

	assert( attributeMoveType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			attributeMoveType == CRYPT_ATTRIBUTE_CURRENT || \
			attributeMoveType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	assert( cursorMoveType <= CRYPT_CURSOR_FIRST && \
			cursorMoveType >= CRYPT_CURSOR_LAST );

	/* Positioning in null attribute lists is always unsuccessful */
	if( currentCursor == NULL )
		return( NULL );

	/* Set the amount that we want to move by based on the position code.
	   This means that we can handle the movement in a simple while loop
	   instead of having to special-case it for moves by one item */
	count = absMove ? INT_MAX : 1;

	/* Perform the appropriate attribute move type */
	switch( attributeMoveType )
		{
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			return( moveCursorByGroup( currentCursor, getAttrFunction, 
									   cursorMoveType, count, absMove ) );

		case CRYPT_ATTRIBUTE_CURRENT:
			return( moveCursorByAttribute( currentCursor, getAttrFunction,
										   cursorMoveType, count, absMove ) );

		case CRYPT_ATTRIBUTE_CURRENT_INSTANCE:
			return( moveCursorByInstance( currentCursor, getAttrFunction,
										  cursorMoveType, count, absMove ) );
		}

	/* Everything else is an error */
	assert( NOTREACHED );
	return( NULL );
	}
