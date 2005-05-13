/****************************************************************************
*																			*
*						cryptlib Secure Session Routines					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "stream.h"
  #include "session.h"
#else
  #include "misc/asn1.h"
  #include "io/stream.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( SESSION_INFO *sessionInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( sessionInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( SESSION_INFO *sessionInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotInited( SESSION_INFO *sessionInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTINITED ) );
	}

static int exitErrorNotFound( SESSION_INFO *sessionInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Exit after saving a detailed error message.  This is used by lower-level 
   session code to provide more information to the caller than a basic error 
   code */

int retExtFnSession( SESSION_INFO *sessionInfoPtr, const int status, 
					 const char *format, ... )
	{
	va_list argPtr;

	va_start( argPtr, format );
	vsnprintf( sessionInfoPtr->errorMessage, MAX_ERRMSG_SIZE, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/* Reset the internal virtual cursor in a attribute-list item after we've 
   moved the attribute cursor */

#define resetVirtualCursor( attributeListPtr ) \
		if( attributeListPtr != NULL ) \
			attributeListPtr->flags |= ATTR_FLAG_CURSORMOVED

/* Helper function used to access internal attributes within an attribute 
   group */

static int accessFunction( ATTRIBUTE_LIST *attributeListPtr,
						   const ATTR_TYPE attrGetType )
	{
#if 0	/* Currently unused, will be enabled in 3.2 with the move to 
		   composite attributes for host/client info */
	static const CRYPT_ATTRIBUTE_TYPE attributeOrderList[] = {
				CRYPT_SESSINFO_NAME, CRYPT_SESSINFO_PASSWORD,
				CRYPT_SESSINFO_KEY, CRYPT_ATTRIBUTE_NONE, 
				CRYPT_ATTRIBUTE_NONE };
	USER_INFO *userInfoPtr = attributeListPtr->value;
	CRYPT_ATTRIBUTE_TYPE attributeType = userInfoPtr->cursorPos;
	BOOLEAN doContinue;

	/* If we've just moved the cursor onto this attribute, reset the 
	   position to the first internal attribute */
	if( attributeListPtr->flags & ATTR_FLAG_CURSORMOVED )
		{
		attributeType = userInfoPtr->cursorPos = \
						CRYPT_ENVINFO_SIGNATURE_RESULT;
		attributeListPtr->flags &= ~ATTR_FLAG_CURSORMOVED;
		}

	/* If it's an info fetch, return the currently-selected attribute */
	if( attrGetType == ATTR_NONE )
		return( attributeType );

	do
		{
		int i;

		/* Find the position of the current sub-attribute in the attribute 
		   order list and use that to get its successor/predecessor sub-
		   attribute */
		for( i = 0; \
			 attributeOrderList[ i ] != attributeType && \
			 attributeOrderList[ i ] != CRYPT_ATTRIBUTE_NONE; i++ );
		if( attributeOrderList[ i ] == CRYPT_ATTRIBUTE_NONE )
			attributeType = CRYPT_ATTRIBUTE_NONE;
		else
			if( attrGetType == ATTR_PREV )
				attributeType = ( i < 1 ) ? CRYPT_ATTRIBUTE_NONE : \
											attributeOrderList[ i - 1 ];
			else
				attributeType = attributeOrderList[ i + 1 ];
		if( attributeType == CRYPT_ATTRIBUTE_NONE )
			/* We've reached the first/last sub-attribute within the current 
			   item/group, tell the caller that there are no more sub-
			   attributes present and they have to move on to the next 
			   group */
			return( FALSE );

		/* Check whether the required sub-attribute is present.  If not, we
		   continue and try the next one */
		doContinue = FALSE;
		switch( attributeType )
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
	while( doContinue );
	attributeListPtr->attributeCursorEntry = attributeType;
#endif /* 0 */
	
	return( TRUE );
	}

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
		*groupID = attributeListPtr->attribute;
	if( attributeID != NULL && \
		( attributeListPtr->flags & ATTR_FLAG_COMPOSITE ) )
		*attributeID = attributeListPtr->accessFunction( attributeListPtr, 
														 ATTR_NONE );
	return( attributeListPtr );
	}

/* Add a session attribute */

static int insertSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
								   const CRYPT_ATTRIBUTE_TYPE attributeType,
								   const void *data, const int dataLength,
								   const int dataMaxLength, 
								   const ATTRACCESSFUNCTION accessFunction,
								   const int flags )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint = NULL;

	assert( isWritePtr( listHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( attributeType > CRYPT_SESSINFO_FIRST && \
			attributeType < CRYPT_SESSINFO_LAST );
	assert( ( data == NULL ) || \
			( isReadPtr( data, dataLength ) && \
			  dataLength <= dataMaxLength ) );
	assert( dataMaxLength >= 0 );
	assert( !( flags & ATTR_FLAG_COMPOSITE ) || \
			accessFunction != NULL );

	/* Make sure that this attribute isn't already present */
	if( *listHeadPtr != NULL )
		{
		ATTRIBUTE_LIST *prevElement = NULL;

		for( insertPoint = *listHeadPtr; insertPoint != NULL;
			 insertPoint = insertPoint->next )
			{
			/* If this is a non-multivalued attribute, make sure that it
			   attribute isn't already present */
			if( !( flags & ATTR_FLAG_MULTIVALUED ) && \
				insertPoint->attribute == attributeType )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
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
	newElement->attribute = attributeType;
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
						 const CRYPT_ATTRIBUTE_TYPE attributeType,
						 const void *data, const int dataLength )
	{
	return( insertSessionAttribute( listHeadPtr, attributeType, data, 
								    dataLength, dataLength, NULL,
									ATTR_FLAG_NONE ) );
	}

int addSessionAttributeEx( ATTRIBUTE_LIST **listHeadPtr,
						   const CRYPT_ATTRIBUTE_TYPE attributeType,
						   const void *data, const int dataLength,
						   const ATTRACCESSFUNCTION accessFunction, 
						   const int flags )
	{
	return( insertSessionAttribute( listHeadPtr, attributeType, data, 
								    dataLength, dataLength, 
									accessFunction, flags ) );
	}

/* Update a session attribute, either by replacing an existing entry if it
   already exists or by adding a new entry */

int updateSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeType,
							const void *data, const int dataLength,
							const int dataMaxLength, const int flags )
	{
	ATTRIBUTE_LIST *attributeListPtr = *listHeadPtr;

	assert( !( flags & ATTR_FLAG_MULTIVALUED ) );

	/* Try and find the attribute */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attribute != attributeType )
		attributeListPtr = attributeListPtr->next;

	/* If the attribute is already present, update the value */
	if( attributeListPtr != NULL )
		{
		assert( attributeListPtr->attribute == attributeType );
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
	return( insertSessionAttribute( listHeadPtr, attributeType, data, 
								    dataLength, dataMaxLength, NULL,
								    flags ) );
	}

/* Find a session attribute */

const ATTRIBUTE_LIST *findSessionAttribute( const ATTRIBUTE_LIST *attributeListPtr,
											const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	while( attributeListPtr != NULL && \
		   attributeListPtr->attribute != attributeType )
		attributeListPtr = attributeListPtr->next;
	return( attributeListPtr );
	}

/* Reset a session attribute.  This is used to clear the data in attributes
   such as passwords that can be updated over different runs of a session */

void resetSessionAttribute( ATTRIBUTE_LIST *attributeListPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	/* Find the attribute to reset */
	attributeListPtr = ( ATTRIBUTE_LIST * ) \
				findSessionAttribute( attributeListPtr, attributeType );
	if( attributeListPtr == NULL )
		return;

	zeroise( attributeListPtr->value, attributeListPtr->valueLength );
	attributeListPtr->valueLength = 0;
	}

/* Delete a complete set of session attributes */

void deleteSessionAttribute( ATTRIBUTE_LIST **attributeListHead,
							 ATTRIBUTE_LIST *attributeListPtr )
	{
	/* Remove the item from the list */
	deleteDoubleListElement( attributeListHead, attributeListPtr );

	/* Clear all data in the list item and free the memory */
	endVarStruct( attributeListPtr, ATTRIBUTE_LIST );
	clFree( "deleteSessionAttribute", attributeListPtr );
	}

void deleteSessionAttributes( ATTRIBUTE_LIST **attributeListHead )
	{
	ATTRIBUTE_LIST *attributeListCursor = *attributeListHead;

	assert( isWritePtr( attributeListHead, sizeof( ATTRIBUTE_LIST * ) ) );

	/* If the list was empty, return now */
	if( attributeListCursor == NULL )
		return;

	/* Destroy any remaining list items */
	while( attributeListCursor != NULL )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;

		attributeListCursor = attributeListCursor->next;
		deleteSessionAttribute( attributeListHead, itemToFree );
		}

	assert( *attributeListHead == NULL );
	}

/****************************************************************************
*																			*
*						Session Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a session object */

static int processGetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			ATTRIBUTE_LIST *attributeListPtr = \
								sessionInfoPtr->attributeListCurrent;

			/* We're querying something that resides in the attribute list, 
			   make sure that there's an attribute list present.  If it's 
			   present but nothing is selected, select the first entry */
			if( attributeListPtr == NULL )
				{
				if( sessionInfoPtr->attributeList == NULL )
					return( exitErrorNotFound( sessionInfoPtr, 
											   messageValue ) );
				attributeListPtr = sessionInfoPtr->attributeListCurrent = \
								   sessionInfoPtr->attributeList;
				resetVirtualCursor( attributeListPtr );
				}

			/* If we're reading the group type or it's a single-attribute 
			   group, return the overall attribute type */
			if( ( messageValue == CRYPT_ATTRIBUTE_CURRENT_GROUP ) || \
				!( attributeListPtr->flags & ATTR_FLAG_COMPOSITE ) )
				*valuePtr = attributeListPtr->attribute;
			else
				/* It's a composite type, get the currently-selected sub-
				   attribute */
				*valuePtr = attributeListPtr->accessFunction( attributeListPtr, 
															  ATTR_NONE );
			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->connectTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->readTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->writeTimeout;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = sessionInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = sessionInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->receiveBufSize;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:
			*valuePtr = sessionInfoPtr->errorCode;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Only secure transport sessions can be persistently active,
			   request/response sessions are only active while the 
			   transaction is in progress.  Note that this differs from the
			   connection-active state, which records the fact that there's 
			   a network-level connection established but no messages or
			   secure session active across it.  See the comment in 
			   processSetAttribute() for more on this */
			*valuePtr = sessionInfoPtr->iCryptInContext != CRYPT_ERROR && \
						( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CONNECTIONACTIVE:
			*valuePtr = ( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
		case CRYPT_SESSINFO_CLIENT_PORT:
			{
			const ATTRIBUTE_LIST *attributeListPtr = \
						findSessionAttribute( sessionInfoPtr->attributeList,
											  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = attributeListPtr->intValue;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_VERSION:
			*valuePtr = sessionInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_AUTHRESPONSE:
			*valuePtr = sessionInfoPtr->authResponse;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const int value = *( int * ) messageDataPtr;
	int status;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			const ATTRIBUTE_LIST *attributeListCursor;

			/* If it's an absolute positioning code, pre-set the attribute
			   cursor if required */
			if( value == CRYPT_CURSOR_FIRST || value == CRYPT_CURSOR_LAST )
				{
				if( sessionInfoPtr->attributeList == NULL )
					return( CRYPT_ERROR_NOTFOUND );

				/* If it's an absolute attribute positioning code, reset the
				   attribute cursor to the start of the list before we try 
				   to move it, and if it's an attribute positioning code, 
				   initialise the attribute cursor if necessary */
				if( messageValue == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
					sessionInfoPtr->attributeListCurrent == NULL )
					{
					sessionInfoPtr->attributeListCurrent = \
										sessionInfoPtr->attributeList;
					resetVirtualCursor( sessionInfoPtr->attributeListCurrent );
					}

				/* If there are no attributes present, return the 
				   appropriate error code */
				if( sessionInfoPtr->attributeListCurrent == NULL )
					return( ( value == CRYPT_CURSOR_FIRST || \
							  value == CRYPT_CURSOR_LAST ) ? \
							 CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_NOTINITED );
				}
			else
				/* It's a relative positioning code, return a not-inited 
				   error rather than a not-found error if the cursor isn't 
				   set since there may be attributes present but the cursor 
				   hasn't been initialised yet by selecting the first or 
				   last absolute attribute */
				if( sessionInfoPtr->attributeListCurrent == NULL )
					return( CRYPT_ERROR_NOTINITED );

			/* Move the cursor */
			attributeListCursor = \
				attributeMoveCursor( sessionInfoPtr->attributeListCurrent, 
									 getAttrFunction, messageValue, value );
			if( attributeListCursor == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			sessionInfoPtr->attributeListCurrent = \
							( ATTRIBUTE_LIST * ) attributeListCursor;
			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			sessionInfoPtr->connectTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			sessionInfoPtr->readTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			sessionInfoPtr->writeTimeout = value;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			assert( !( sessionInfoPtr->flags & SESSION_ISOPEN ) );
			sessionInfoPtr->receiveBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Session state and persistent sessions are handled as follows:
			   The CRYPT_SESSINFO_ACTIVE attribute records the active state
			   of the session as a whole, and the CRYPT_SESSINFO_-
			   CONNECTIONACTIVE attribute records the state of the 
			   underlying comms session.  Setting CRYPT_SESSINFO_ACTIVE for 
			   the first time activates the comms session, and leaves it 
			   active if the underlying mechanism (e.g. HTTP 1.1 persistent 
			   connections) supports it.  The CRYPT_SESSINFO_ACTIVE 
			   attribute is reset once the transaction completes, and 
			   further transactions can be initiated as long as 
			   CRYPT_SESSINFO_CONNECTIONACTIVE is set:

										Obj.state	_active		_connactive
										---------	-------		-----------
				create						0			0			0
				setattr						0			0			0
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
				setattr						1			0			1
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
					(peer closes conn)		1			0			0
				setattr							CRYPT_ERROR_COMPLETE */
			if( value == FALSE )
				return( CRYPT_OK );	/* No-op */

			/* If the session is in the partially-open state while we wait 
			   for the caller to allow or disallow the session 
			   authentication, they have to provide a clear yes or no 
			   indication if they try to continue the session activation */
			if( ( sessionInfoPtr->flags & SESSION_PARTIALOPEN ) && \
				sessionInfoPtr->authResponse == CRYPT_UNUSED )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_AUTHRESPONSE ) );

			status = activateSession( sessionInfoPtr );
			if( cryptArgError( status ) )
				{
				/* Catch leaked low-level status values.  The session 
				   management code does a large amount of work involving 
				   other cryptlib objects, so it's possible that an 
				   unexpected failure at some point will leak through an 
				   inappropriate status value */
				assert( NOTREACHED );
				status = CRYPT_ERROR_FAILED;
				}
			return( status );

		case CRYPT_SESSINFO_SERVER_PORT:
			/* If there's already a transport session or network socket 
			   specified, we can't set a port as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			return( addSessionAttribute( &sessionInfoPtr->attributeList,
										 CRYPT_SESSINFO_SERVER_PORT, NULL,
										 value ) );

		case CRYPT_SESSINFO_VERSION:
			if( value < sessionInfoPtr->protocolInfo->minVersion || \
				value > sessionInfoPtr->protocolInfo->maxVersion )
				return( CRYPT_ARGERROR_VALUE );
			sessionInfoPtr->version = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PRIVATEKEY:
			{
			const int requiredAttributeFlags = \
					( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
						sessionInfoPtr->serverReqAttrFlags : \
						sessionInfoPtr->clientReqAttrFlags;

			/* Make sure that it's a private key */
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusError( status ) )
				{
				if( sessionInfoPtr->type != CRYPT_SESSION_SSL )
					return( CRYPT_ARGERROR_NUM1 );

				/* SSL can also do key agreement-based key exchange, so we
				   fall back to this if key transport-based exchange isn't
				   possible */
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_KA_EXPORT );
				if( cryptStatusError( status ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* If we need a private key with certain capabilities, make sure 
			   that it has these capabilities.  This is a more specific check 
			   than that allowed by the kernel ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYSIGN )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_SIGN );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCRYPT )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_DECRYPT );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}

			/* If we need a private key with a cert, make sure that the
			   appropriate type of initialised cert object is present.  This
			   is a more specific check than that allowed by the kernel 
			   ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCERT )
				{
				int attrValue;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_IMMUTABLE );
				if( cryptStatusError( status ) || !attrValue )
					return( CRYPT_ARGERROR_NUM1 );
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) ||
					( attrValue != CRYPT_CERTTYPE_CERTIFICATE && \
					  attrValue != CRYPT_CERTTYPE_CERTCHAIN ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( ( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCACERT ) && \
				cryptStatusError( \
					krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
					return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key meets the mininum height requirements.  
			   We only perform this check if we're explicitly being asked to
			   perform the check and it's a server session (which has certain
			   minimum length requirements for private keys), for client
			   sessions the permitted length/security level is controlled by
			   the server so we can't really perform much checking */
			if( sessionInfoPtr->protocolInfo->requiredPrivateKeySize && \
				( sessionInfoPtr->flags & SESSION_ISSERVER ) )
				{
				int length;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &length, CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) || \
					length < sessionInfoPtr->protocolInfo->requiredPrivateKeySize )
					return( exitError( sessionInfoPtr,
									   CRYPT_SESSINFO_PRIVATEKEY,
									   CRYPT_ERRTYPE_ATTR_SIZE,
									   CRYPT_ARGERROR_NUM1 ) );
				}

			/* Perform any protocol-specific checks if necessary */
			if( sessionInfoPtr->checkAttributeFunction != NULL )
				{
				status = sessionInfoPtr->checkAttributeFunction( sessionInfoPtr,
											value, CRYPT_SESSINFO_PRIVATEKEY );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Add the private key and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->privateKey = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_KEYSET:
			{
			int type;

			/* Make sure that it's either a cert store (rather than just a 
			   generic keyset) or a read-only cert source (and specifically 
			   not a cert store) if required */
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSTORE )
				{
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &type, CRYPT_IATTRIBUTE_SUBTYPE );
				if( cryptStatusError( status ) || \
					( type != SUBTYPE_KEYSET_DBMS_STORE ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSOURCE )
				{
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &type, CRYPT_IATTRIBUTE_SUBTYPE );
				if( cryptStatusError( status ) || \
					( type == SUBTYPE_KEYSET_DBMS_STORE ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* Add the keyset and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->cryptKeyset = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_AUTHRESPONSE:
			sessionInfoPtr->authResponse = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SESSION:
			/* If there's already a host or network socket specified, we 
			   can't set a transport session as well */
			if( findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Add the transport mechanism and increment its reference
			   count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->transportSession = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_NETWORKSOCKET:
			{
			NET_CONNECT_INFO connectInfo;
			STREAM stream;

			/* If there's already a host or session specified, we can't set 
			   a network socket as well */
			if( findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );

			/* Create a dummy network stream to make sure that the network 
			   socket is OK */
			initNetConnectInfo( &connectInfo, sessionInfoPtr->ownerHandle, 
								sessionInfoPtr->readTimeout, 
								sessionInfoPtr->connectTimeout,
								NET_OPTION_NETWORKSOCKET_DUMMY );
			connectInfo.networkSocket = value;
			status = sNetConnect( &stream, STREAM_PROTOCOL_TCPIP, 
								  &connectInfo, sessionInfoPtr->errorMessage, 
								  &sessionInfoPtr->errorCode );
			if( cryptStatusError( status ) )
				return( status );
			sNetDisconnect( &stream );

			/* Add the network socket */
			sessionInfoPtr->networkSocket = value;
			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	const ATTRIBUTE_LIST *attributeListPtr;
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( exitErrorNotFound( sessionInfoPtr,
									   messageValue ) );

		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			if( !*sessionInfoPtr->errorMessage )
				/* We don't set extended error information for this atribute
				   because it's usually read in response to an existing error, 
				   which would overwrite the existing error information */
				return( CRYPT_ERROR_NOTFOUND );
			return( attributeCopy( msgData, sessionInfoPtr->errorMessage,
								   strlen( sessionInfoPtr->errorMessage ) ) );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_CLIENT_NAME:
			attributeListPtr = \
					findSessionAttribute( sessionInfoPtr->attributeList,
										  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			return( attributeCopy( msgData, attributeListPtr->value,
								   attributeListPtr->valueLength ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int status;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never used */
			return( CRYPT_ARGERROR_VALUE );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
			{
			int flags = 0;

			assert( msgData->length > 0 && \
					msgData->length <= CRYPT_MAX_TEXTSIZE );

			/* If this attribute is already set, we can't add it again */
			if( findSessionAttribute( sessionInfoPtr->attributeList, 
									  messageValue ) != NULL && \
				!( sessionInfoPtr->type == CRYPT_SESSION_SSL && \
				   sessionInfoPtr->flags & SESSION_ISSERVER ) )
				return( exitErrorInited( sessionInfoPtr, messageValue ) );

			/* If it could be an encoded PKI value, check its validity */
			if( ( messageValue == CRYPT_SESSINFO_USERNAME || \
				  messageValue == CRYPT_SESSINFO_PASSWORD ) && \
				isPKIUserValue( msgData->data, msgData->length ) )
				{
				BYTE decodedValue[ CRYPT_MAX_TEXTSIZE ];
				int status;

				/* It's an encoded value, make sure that it's in order */
				status = decodePKIUserValue( decodedValue, msgData->data, 
											 msgData->length );
				zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
				if( cryptStatusError( status ) )
					return( status );
				flags = ATTR_FLAG_ENCODEDVALUE;
				}

			/* Remember the value.  SSL server sessions maintain multiple 
			   username/password entries possible so we perform a 
			   (potential) update rather than a new add */
			if( sessionInfoPtr->type == CRYPT_SESSION_SSL && \
				sessionInfoPtr->flags & SESSION_ISSERVER )
				status = updateSessionAttribute( &sessionInfoPtr->attributeList,
												 messageValue, msgData->data, 
												 msgData->length, 
												 CRYPT_MAX_TEXTSIZE, flags );
			else
				status = insertSessionAttribute( &sessionInfoPtr->attributeList,
												 messageValue, msgData->data, 
												 msgData->length, 
												 CRYPT_MAX_TEXTSIZE, NULL, 
												 flags );
			return( status );
			}

		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
			/* If this attribute is already set, we can't add it again */
			if( findSessionAttribute( sessionInfoPtr->attributeList, 
									  messageValue ) != NULL )
				return( exitErrorInited( sessionInfoPtr, messageValue ) );

			/* Remember the value */
			return( addSessionAttribute( &sessionInfoPtr->attributeList,
										 messageValue, msgData->data, 
										 msgData->length ) );

		case CRYPT_SESSINFO_SERVER_NAME:
			{
			const PROTOCOL_INFO *protocolInfoPtr = \
										sessionInfoPtr->protocolInfo;
			URL_INFO urlInfo;
			int status;

			assert( msgData->length > 0 && msgData->length < MAX_URL_SIZE );
			if( findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );

			/* If there's already a transport session or network socket 
			   specified, we can't set a server name as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Parse the server name */
			status = sNetParseURL( &urlInfo, msgData->data, 
								   msgData->length );
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* We can only use autodetection with PKI services */
			if( !strCompare( msgData->data, "[Autodetect]", 
							 msgData->length ) && \
				!protocolInfoPtr->isReqResp )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* If there's a port or user name specified in the URL, set the 
			   appropriate attributes */
			if( urlInfo.userInfoLen > 0 )
				{
				RESOURCE_DATA userInfoMsgData;

				krnlSendMessage( sessionInfoPtr->objectHandle, 
								 IMESSAGE_DELETEATTRIBUTE, NULL,
								 CRYPT_SESSINFO_USERNAME );
				setMessageData( &userInfoMsgData, ( void * ) urlInfo.userInfo, 
								urlInfo.userInfoLen );
				status = krnlSendMessage( sessionInfoPtr->objectHandle, 
										  IMESSAGE_SETATTRIBUTE_S, 
										  &userInfoMsgData,
										  CRYPT_SESSINFO_USERNAME );
				}
			if( cryptStatusOK( status ) && urlInfo.port > 0 )
				{
				krnlSendMessage( sessionInfoPtr->objectHandle, 
								 IMESSAGE_DELETEATTRIBUTE, NULL,
								 CRYPT_SESSINFO_SERVER_PORT );
				status = krnlSendMessage( sessionInfoPtr->objectHandle, 
										  IMESSAGE_SETATTRIBUTE, &urlInfo.port,
										  CRYPT_SESSINFO_SERVER_PORT );
				}
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* Remember the server name */
			if( urlInfo.hostLen + urlInfo.locationLen + 1 > MAX_URL_SIZE )
				{
				/* This should never happen since the overall URL size has 
				   to be less than MAX_URL_SIZE */
				assert( NOTREACHED );
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );
				}
			if( urlInfo.locationLen <= 0 )
				status = addSessionAttribute( &sessionInfoPtr->attributeList,
											  CRYPT_SESSINFO_SERVER_NAME, 
											  urlInfo.host, urlInfo.hostLen );
			else
				{
				char urlBuffer[ MAX_URL_SIZE ];

				memcpy( urlBuffer, urlInfo.host, urlInfo.hostLen );
				memcpy( urlBuffer + urlInfo.hostLen, 
						urlInfo.location, urlInfo.locationLen );
				status = addSessionAttribute( &sessionInfoPtr->attributeList,
									CRYPT_SESSINFO_SERVER_NAME, urlBuffer, 
									urlInfo.hostLen + urlInfo.locationLen );
				}
			if( cryptStatusError( status ) )
				return( status );

			/* Remember the transport type */
			if( protocolInfoPtr->altProtocolInfo != NULL && \
				urlInfo.schemaLen == \
						strlen( protocolInfoPtr->altProtocolInfo->uriType ) && \
				!strCompare( urlInfo.schema, 
							 protocolInfoPtr->altProtocolInfo->uriType,
							 strlen( protocolInfoPtr->altProtocolInfo->uriType ) ) )
				{
				/* The caller has specified the use of the altnernate 
				   transport protocol type, switch to that instead of HTTP */
				sessionInfoPtr->flags &= ~SESSION_ISHTTPTRANSPORT;
				sessionInfoPtr->flags |= SESSION_USEALTTRANSPORT;
				}
			else
				if( sessionInfoPtr->protocolInfo->flags & SESSION_ISHTTPTRANSPORT )
					{
					sessionInfoPtr->flags &= ~SESSION_USEALTTRANSPORT;
					sessionInfoPtr->flags |= SESSION_ISHTTPTRANSPORT;
					}
			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processDeleteAttribute( SESSION_INFO *sessionInfoPtr,
								   const int messageValue )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->readTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->writeTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_SERVER_PORT:
			/* Make sure that the attribute to delete is actually present */
			attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotFound( sessionInfoPtr, messageValue ) );

			/* Delete the attribute */
			deleteSessionAttribute( &sessionInfoPtr->attributeList,
									( ATTRIBUTE_LIST * ) attributeListPtr );
			return( CRYPT_OK );

		case CRYPT_SESSINFO_REQUEST:
			if( sessionInfoPtr->iCertRequest == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_REQUEST ) );
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCertRequest = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_TSP_MSGIMPRINT:
			if( sessionInfoPtr->sessionTSP->imprintAlgo == CRYPT_ALGO_NONE || \
				sessionInfoPtr->sessionTSP->imprintSize <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_TSP_MSGIMPRINT ) );
			sessionInfoPtr->sessionTSP->imprintAlgo = CRYPT_ALGO_NONE;
			sessionInfoPtr->sessionTSP->imprintSize = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Session Message Handler						*
*																			*
****************************************************************************/

/* Handle a message sent to a session object */

static int sessionMessageFunction( const void *objectInfoPtr,
								   const MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	SESSION_INFO *sessionInfoPtr = ( SESSION_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the session if required.  Nemo nisi mors */
		if( sessionInfoPtr->flags & SESSION_ISOPEN )
			sessionInfoPtr->shutdownFunction( sessionInfoPtr );

		/* Clear and free session state information if necessary */
		if( sessionInfoPtr->sendBuffer != NULL )
			{
			zeroise( sessionInfoPtr->sendBuffer,
					 sessionInfoPtr->sendBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->sendBuffer );
			}
		if( sessionInfoPtr->receiveBuffer != NULL )
			{
			zeroise( sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->receiveBuffer );
			}

		/* Clear session attributes if necessary */
		if( sessionInfoPtr->attributeList != NULL )
			deleteSessionAttributes( &sessionInfoPtr->attributeList );

		/* Clean up any session-related objects if necessary */
		if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertRequest != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertResponse,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privateKey != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privateKey,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->transportSession != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->transportSession,
							  IMESSAGE_DECREFCOUNT );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		/* If it's a protocol-specific attribute, forward it directly to
		   the low-level code */
		if( message != MESSAGE_DELETEATTRIBUTE && \
			( ( messageValue >= CRYPT_SESSINFO_FIRST_SPECIFIC && \
				messageValue <= CRYPT_SESSINFO_LAST_SPECIFIC ) || \
			  messageValue == CRYPT_IATTRIBUTE_ENC_TIMESTAMP ) )
			{
			int status;

			if( message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S )
				{
				assert( sessionInfoPtr->setAttributeFunction != NULL );

				status = sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_INITED )
					return( exitErrorInited( sessionInfoPtr, 
											 messageValue ) );
				}
			else
				{
				assert( message == MESSAGE_GETATTRIBUTE || \
						message == MESSAGE_GETATTRIBUTE_S );
				assert( sessionInfoPtr->getAttributeFunction != NULL );

				status = sessionInfoPtr->getAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_NOTFOUND )
					return( exitErrorNotFound( sessionInfoPtr, 
											   messageValue ) );
				}
			return( status );
			}

		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_DELETEATTRIBUTE )
			return( processDeleteAttribute( sessionInfoPtr, messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_ENV_PUSHDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		const int length = msgData->length;
		int bytesCopied, status;

		/* Unless we're told otherwise, we've copied zero bytes */
		msgData->length = 0;

		/* If the session isn't open yet, perform an implicit open */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			{
			status = krnlSendMessage( sessionInfoPtr->objectHandle, 
									  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
									  CRYPT_SESSINFO_ACTIVE );
			if( cryptStatusError( status ) )
				return( status );

			/* The session is ready to process data, move it into the high
			   state */
			krnlSendMessage( sessionInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED );
			}
		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->sendBuffer != NULL );
		assert( sessionInfoPtr->preparePacketFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->flags & SESSION_SENDCLOSED )
			/* If the other side has closed its receive channel (which is 
			   our send channel), we can't send any more data, although we 
			   can still get data on our receive channel if we haven't closed
			   it as well.  The closing of the other side's send channel is 
			   detected during a read and isn't a write error but a normal 
			   state change in the channel, so we don't treat it as an error 
			   when it's seen at the read stage until the caller actually 
			   tries to write data to the closed channel */
			sessionInfoPtr->writeErrorState = CRYPT_ERROR_COMPLETE;
		if( sessionInfoPtr->writeErrorState != CRYPT_OK )
			return( sessionInfoPtr->writeErrorState );

		/* Write the data */
		clearErrorInfo( sessionInfoPtr );
		status = putSessionData( sessionInfoPtr, msgData->data, length, 
								 &bytesCopied );
		if( cryptStatusOK( status ) )
			msgData->length = bytesCopied;
		assert( ( cryptStatusError( status ) && bytesCopied == 0 ) || \
				( cryptStatusOK( status ) && bytesCopied >= 0 ) );
		return( status );
		}
	if( message == MESSAGE_ENV_POPDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		const int length = msgData->length;
		int bytesCopied, status;

		/* Unless we're told otherwise, we've copied zero bytes */
		msgData->length = 0;

		/* If the session isn't open, there's nothing to pop */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			return( CRYPT_ERROR_NOTINITED );

		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->receiveBuffer != NULL );
		assert( sessionInfoPtr->readHeaderFunction != NULL );
		assert( sessionInfoPtr->processBodyFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->readErrorState != CRYPT_OK )
			return( sessionInfoPtr->readErrorState );

		/* Read the data */
		clearErrorInfo( sessionInfoPtr );
		status = getSessionData( sessionInfoPtr, msgData->data, length,
								 &bytesCopied );
		if( cryptStatusOK( status ) )
			msgData->length = bytesCopied;
		assert( ( cryptStatusError( status ) && bytesCopied == 0 ) || \
				( cryptStatusOK( status ) && bytesCopied >= 0 ) );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a session.  This is a low-level function encapsulated by createSession()
   and used to manage error exits */

static int openSession( CRYPT_SESSION *iCryptSession,
						const CRYPT_USER cryptOwner,
						const CRYPT_SESSION_TYPE sessionType,
						SESSION_INFO **sessionInfoPtrPtr )
	{
	SESSION_INFO *sessionInfoPtr;
	const PROTOCOL_INFO *protocolInfoPtr;
	static const struct {
		const CRYPT_SESSION_TYPE sessionType;
		const CRYPT_SESSION_TYPE baseSessionType;
		const int subType;
		} sessionTypes[] = {
	{ CRYPT_SESSION_SSH, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH },
	{ CRYPT_SESSION_SSH_SERVER, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH_SVR },
	{ CRYPT_SESSION_SSL, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL },
	{ CRYPT_SESSION_SSL_SERVER, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL_SVR },
	{ CRYPT_SESSION_RTCS, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS },
	{ CRYPT_SESSION_RTCS_SERVER, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS_SVR },
	{ CRYPT_SESSION_OCSP, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP },
	{ CRYPT_SESSION_OCSP_SERVER, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP_SVR },
	{ CRYPT_SESSION_TSP, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP },
	{ CRYPT_SESSION_TSP_SERVER, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP_SVR },
	{ CRYPT_SESSION_CMP, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP },
	{ CRYPT_SESSION_CMP_SERVER, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP_SVR },
	{ CRYPT_SESSION_SCEP, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP },
	{ CRYPT_SESSION_SCEP_SERVER, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP_SVR },
	{ CRYPT_SESSION_CERTSTORE_SERVER, CRYPT_SESSION_CERTSTORE_SERVER, SUBTYPE_SESSION_CERT_SVR },
	{ CRYPT_SESSION_NONE, CRYPT_SESSION_NONE, CRYPT_ERROR }
	};
	int storageSize = 0, i, status;

	assert( sessionInfoPtrPtr != NULL );

	/* Clear the return values */
	*iCryptSession = CRYPT_ERROR;
	*sessionInfoPtrPtr = NULL;

	/* Map the external session type to a base type and internal object
	   subtype */
	for( i = 0; sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE; i++ )
		if( sessionTypes[ i ].sessionType == sessionType )
			break;
	assert( sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE );

	/* Set up subtype-specific information */
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_SSH:
			storageSize = sizeof( SSH_INFO );
			break;

		case CRYPT_SESSION_SSL:
			storageSize = sizeof( SSL_INFO );
			break;

		case CRYPT_SESSION_TSP:
			storageSize = sizeof( TSP_INFO );
			break;

		case CRYPT_SESSION_CMP:
			storageSize = sizeof( CMP_INFO );
			break;
		}

	/* Create the session object */
	status = krnlCreateObject( ( void ** ) &sessionInfoPtr, 
							   sizeof( SESSION_INFO ) + storageSize, 
							   OBJECT_TYPE_SESSION, sessionTypes[ i ].subType,
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, sessionMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*sessionInfoPtrPtr = sessionInfoPtr;
	*iCryptSession = sessionInfoPtr->objectHandle = status;
	sessionInfoPtr->ownerHandle = cryptOwner;
	sessionInfoPtr->type = sessionTypes[ i ].baseSessionType;
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_SSH:
			sessionInfoPtr->sessionSSH = ( SSH_INFO * ) sessionInfoPtr->storage;
			break;

		case CRYPT_SESSION_SSL:
			sessionInfoPtr->sessionSSL = ( SSL_INFO * ) sessionInfoPtr->storage;
			break;

		case CRYPT_SESSION_TSP:
			sessionInfoPtr->sessionTSP = ( TSP_INFO * ) sessionInfoPtr->storage;
			break;

		case CRYPT_SESSION_CMP:
			sessionInfoPtr->sessionCMP = ( CMP_INFO * ) sessionInfoPtr->storage;
			break;
		}
	sessionInfoPtr->storageSize = storageSize;

	/* If it's a server session, mark it as such.  An HTTP certstore session 
	   is a special case in that it's always a server session */
	if( ( sessionTypes[ i ].sessionType != \
		  sessionTypes[ i ].baseSessionType ) || \
		( sessionTypes[ i ].sessionType == CRYPT_SESSION_CERTSTORE_SERVER ) )
		sessionInfoPtr->flags = SESSION_ISSERVER;

	/* Set up any internal objects to contain invalid handles */
	sessionInfoPtr->iKeyexCryptContext = \
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
	sessionInfoPtr->iCryptInContext = \
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
	sessionInfoPtr->iAuthInContext = \
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
	sessionInfoPtr->iCertRequest = \
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	sessionInfoPtr->privateKey = CRYPT_ERROR;
	sessionInfoPtr->cryptKeyset = CRYPT_ERROR;
	sessionInfoPtr->privKeyset =  CRYPT_ERROR;
	sessionInfoPtr->transportSession = CRYPT_ERROR;
	sessionInfoPtr->networkSocket = CRYPT_ERROR;
	sessionInfoPtr->readTimeout = \
		sessionInfoPtr->writeTimeout = \
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;

	/* Set up any additinal values */
	sessionInfoPtr->authResponse = CRYPT_UNUSED;

	/* Set up the access information for the session and initialise it */
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_CERTSTORE_SERVER:
			status = setAccessMethodCertstore( sessionInfoPtr );
			break;

		case CRYPT_SESSION_CMP:
			status = setAccessMethodCMP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_RTCS:
			status = setAccessMethodRTCS( sessionInfoPtr );
			break;

		case CRYPT_SESSION_OCSP:
			status = setAccessMethodOCSP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SCEP:
			status = setAccessMethodSCEP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSH:
			status = setAccessMethodSSH( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSL:
			status = setAccessMethodSSL( sessionInfoPtr );
			break;

		case CRYPT_SESSION_TSP:
			status = setAccessMethodTSP( sessionInfoPtr );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the protocol info is OK */
	protocolInfoPtr = sessionInfoPtr->protocolInfo;
	assert( ( protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->bufSize == 0 && \
			  protocolInfoPtr->sendBufStartOfs == 0 && \
			  protocolInfoPtr->maxPacketSize == 0 ) || 
			( !protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->bufSize >= MIN_BUFFER_SIZE && \
			  protocolInfoPtr->sendBufStartOfs >= 5 && \
			  protocolInfoPtr->maxPacketSize <= protocolInfoPtr->bufSize ) );
	assert( ( ( protocolInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) && \
			  protocolInfoPtr->port == 80 ) || \
			( protocolInfoPtr->port != 80 ) );
	assert( protocolInfoPtr->port > 21 );
	assert( protocolInfoPtr->version >= 0 );
	assert( ( protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->clientContentType != NULL && \
			  protocolInfoPtr->serverContentType != NULL ) || 
			( !protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->clientContentType == NULL && \
			  protocolInfoPtr->serverContentType == NULL ) );

	/* Copy mutable protocol-specific information into the session info */
	sessionInfoPtr->flags |= protocolInfoPtr->flags;
	sessionInfoPtr->clientReqAttrFlags = protocolInfoPtr->clientReqAttrFlags;
	sessionInfoPtr->serverReqAttrFlags = protocolInfoPtr->serverReqAttrFlags;
	sessionInfoPtr->version = protocolInfoPtr->version;
	if( protocolInfoPtr->isReqResp )
		{
		sessionInfoPtr->sendBufSize = CRYPT_UNUSED;
		sessionInfoPtr->receiveBufSize = MIN_BUFFER_SIZE;
		}
	else
		{
		sessionInfoPtr->sendBufSize = sessionInfoPtr->receiveBufSize = \
				protocolInfoPtr->bufSize;
		sessionInfoPtr->sendBufStartOfs = sessionInfoPtr->receiveBufStartOfs = \
				protocolInfoPtr->sendBufStartOfs;
		sessionInfoPtr->maxPacketSize = protocolInfoPtr->maxPacketSize;
		}

	/* Install default handlers if no session-specific ones are provided */
	initSessionIO( sessionInfoPtr );

	/* Check that the handlers are all OK */
	assert( sessionInfoPtr->connectFunction != NULL );
	assert( sessionInfoPtr->transactFunction != NULL );
	assert( ( protocolInfoPtr->isReqResp && \
			  sessionInfoPtr->readHeaderFunction == NULL && \
			  sessionInfoPtr->processBodyFunction == NULL && \
			  sessionInfoPtr->preparePacketFunction == NULL ) || \
			( !protocolInfoPtr->isReqResp && \
			  sessionInfoPtr->readHeaderFunction != NULL && \
			  sessionInfoPtr->processBodyFunction != NULL && \
			  sessionInfoPtr->preparePacketFunction != NULL ) );

	return( CRYPT_OK );
	}

int createSession( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_SESSION iCryptSession;
	SESSION_INFO *sessionInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_SESSION_NONE || \
		createInfo->arg1 >= CRYPT_SESSION_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = openSession( &iCryptSession, createInfo->cryptOwner,
							  createInfo->arg1, &sessionInfoPtr );
	if( sessionInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptSession, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptSession, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptSession;
	return( CRYPT_OK );
	}

/* Generic management function for this class of object */

int sessionManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	static int initLevel = 0;
	int status;

	assert( action == MANAGEMENT_ACTION_INIT || \
			action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			action == MANAGEMENT_ACTION_SHUTDOWN );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			status = netInitTCP();
			if( cryptStatusOK( status ) )
				{
				initLevel++;
				status = initSessionCache();
				}
			if( cryptStatusOK( status ) )
				initLevel++;
			return( status );

		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* We have to wait for the driver binding to complete before we
			   can start the shutdown process */
			krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );
			if( initLevel > 0 )
				netSignalShutdown();
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_SHUTDOWN:
			if( initLevel > 1 )
				endSessionCache();
			if( initLevel > 0 )
				netEndTCP();
			initLevel = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
#endif /* USE_SESSIONS */
