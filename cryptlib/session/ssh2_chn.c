/****************************************************************************
*																			*
*						cryptlib SSHv2 Channel Management					*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

/* Channel flags */

#define CHANNEL_FLAG_NONE		0x00	/* No channel flag */
#define CHANNEL_FLAG_ACTIVE		0x01	/* Channel is active */
#define CHANNEL_FLAG_WRITECLOSED 0x02	/* Write-side of ch.closed */

/* Per-channel information.  SSH channel IDs are 32-bit/4 byte data values
   and can be reused during sessions so we provide our own guaranteed-unique
   short int ID for users to identify a particular channel.  Since each
   channel can have its own distinct characteristics, we have to record
   information like the window size and count and packet size info on a per-
   channel basis.  In addition if the channel is tied to a forwarded port
   we also record port-forwarding information (recorded in the generic
   channel-type and channel-type-argument strings) */

typedef struct {
	/* General channel info.  The read and write channel numbers are the
	   same for everything but Cisco software */
	int channelID;						/* cryptlib-level channel ID */
	long readChannelNo, writeChannelNo;	/* SSH-level channel ID */
	int flags;							/* Channel flags */

	/* External interface information */
	CRYPT_ATTRIBUTE_TYPE cursorPos;		/* Virtual cursor position */

	/* Channel parameters */
	long windowCount;					/* Current window usage */
	int maxPacketSize;					/* Max allowed packet size */

	/* Channel naming information */
	char type[ CRYPT_MAX_TEXTSIZE + 8 ], arg1[ CRYPT_MAX_TEXTSIZE + 8 ];
	char arg2[ CRYPT_MAX_TEXTSIZE + 8 ];
	int typeLen, arg1Len, arg2Len;

	/* Channel extra data.  This contains encoded oddball protocol-specific
	   SSH packets to be sent or having been received */
	BYTE extraData[ ( UINT_SIZE + CRYPT_MAX_TEXTSIZE ) + \
					( UINT_SIZE * 4 ) + 8 ];
	} SSH_CHANNEL_INFO;

/* Check whether a channel corresponds to a null channel (a placeholder used
   when there's currently no channel active) and whether a channel is
   currently active */

#define isNullChannel( channelInfoPtr ) \
		( ( channelInfoPtr )->readChannelNo == UNUSED_CHANNEL_NO )
#define isActiveChannel( channelInfoPtr ) \
		( channelInfoPtr->flags & CHANNEL_FLAG_ACTIVE )

/* The maximum allowed number of channels */

#define SSH_MAX_CHANNELS	4

#ifdef USE_SSH

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check whether there are any active channels still present.  Since a
   channel can be half-closed (we've closed it for write but the other
   side hasn't acknowledged the close yet), we allow the caller to specify
   an excluded channel ID that's treated as logically closed for active
   channel-check purposes even if a channel entry is still present for it.
   In addition we allow a count parameter to allow checking for whether
   a set of channels is still open */

static BOOLEAN isChannelActive( const SESSION_INFO *sessionInfoPtr,
								const int excludedChannelID,
								const int channelCount )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int count = channelCount, iterationCount = 0;

	for( attributeListPtr = sessionInfoPtr->attributeList;
		 attributeListPtr != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next )
		{
		const SSH_CHANNEL_INFO *channelInfoPtr;

		/* If it's not an SSH channel. continue */
		if( attributeListPtr->attributeID != CRYPT_SESSINFO_SSH_CHANNEL )
			continue;

		/* It's an SSH channel, check whether it's the one that we're
		   after */
		assert( attributeListPtr->valueLength == sizeof( SSH_CHANNEL_INFO ) );
		channelInfoPtr = attributeListPtr->value;
		if( isActiveChannel( channelInfoPtr ) && \
			channelInfoPtr->channelID != excludedChannelID )
			{
			/* It's the one that we're after, if a sufficient number of
			   matches have been found, we're done */
			count--;
			if( count <= 0 )
				return( TRUE );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Boolean();

	return( FALSE );
	}

/* Helper function used to access SSH-specific internal attributes within
   an attribute group */

static int accessFunction( ATTRIBUTE_LIST *attributeListPtr,
						   const ATTR_TYPE attrGetType )
	{
	static const CRYPT_ATTRIBUTE_TYPE attributeOrderList[] = {
			CRYPT_SESSINFO_SSH_CHANNEL, CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
			CRYPT_SESSINFO_SSH_CHANNEL_ARG1, CRYPT_SESSINFO_SSH_CHANNEL_ARG2,
			CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE, CRYPT_ATTRIBUTE_NONE,
			CRYPT_ATTRIBUTE_NONE };
	SSH_CHANNEL_INFO *channelInfoPtr = attributeListPtr->value;
	CRYPT_ATTRIBUTE_TYPE attributeType = channelInfoPtr->cursorPos;
	BOOLEAN doContinue;
	int iterationCount = 0;

	/* If we've just moved the cursor onto this attribute, reset the
	   position to the first internal attribute */
	if( attributeListPtr->flags & ATTR_FLAG_CURSORMOVED )
		{
		attributeType = channelInfoPtr->cursorPos = \
						CRYPT_SESSINFO_SSH_CHANNEL;
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
		for( i = 0; 
			 attributeOrderList[ i ] != attributeType && \
				attributeOrderList[ i ] != CRYPT_ATTRIBUTE_NONE && \
				i < FAILSAFE_ARRAYSIZE( attributeOrderList, CRYPT_ATTRIBUTE_TYPE ); 
			 i++ );
		if( i >= FAILSAFE_ARRAYSIZE( attributeOrderList, CRYPT_ATTRIBUTE_TYPE ) )
			retIntError_Boolean();
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
			case CRYPT_SESSINFO_SSH_CHANNEL:
			case CRYPT_SESSINFO_SSH_CHANNEL_TYPE:
			case CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE:
				break;	/* Always present */

			case CRYPT_SESSINFO_SSH_CHANNEL_ARG1:
				if( channelInfoPtr->arg1Len <= 0 )
					doContinue = TRUE;
				break;

			case CRYPT_SESSINFO_SSH_CHANNEL_ARG2:
				if( channelInfoPtr->arg2Len <= 0 )
					doContinue = TRUE;
				break;

			default:
				assert( NOTREACHED );
				return( FALSE );
			}
		}
	while( doContinue && iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError_Boolean();
	channelInfoPtr->cursorPos = attributeType;

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Find Channel Information						*
*																			*
****************************************************************************/

/* Find the attribute entry for a channel */

static ATTRIBUTE_LIST *findChannelAttr( const SESSION_INFO *sessionInfoPtr,
										const long channelNo )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int iterationCount = 0;

	for( attributeListPtr = sessionInfoPtr->attributeList;
		 attributeListPtr != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next )
		{
		const SSH_CHANNEL_INFO *channelInfoPtr;

		/* If it's not an SSH channel. continue */
		if( attributeListPtr->attributeID != CRYPT_SESSINFO_SSH_CHANNEL )
			continue;

		/* It's an SSH channel, check whether it's the one that we're
		   after */
		assert( attributeListPtr->valueLength == sizeof( SSH_CHANNEL_INFO ) );
		channelInfoPtr = attributeListPtr->value;
		if( channelNo == CRYPT_USE_DEFAULT )
			{
			/* We're looking for any open channel channel, return the first
			   match */
			if( channelInfoPtr->flags & CHANNEL_FLAG_WRITECLOSED )
				continue;
			return( attributeListPtr );
			}
		if( channelInfoPtr->readChannelNo == channelNo || \
			channelInfoPtr->writeChannelNo == channelNo )
			return( attributeListPtr );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( NULL );
	}

/* Find the channel info for a channel, matching by channel number, channel
   ID, and channel host + port information */

static SSH_CHANNEL_INFO *findChannelInfo( const SESSION_INFO *sessionInfoPtr,
										  const long channelNo )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
							findChannelAttr( sessionInfoPtr, channelNo );

	return( ( attributeListPtr == NULL ) ? NULL : attributeListPtr->value );
	}

static SSH_CHANNEL_INFO *findChannelInfoID( const SESSION_INFO *sessionInfoPtr,
											const int channelID )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int iterationCount = 0;

	assert( channelID != UNUSED_CHANNEL_ID );

	for( attributeListPtr = sessionInfoPtr->attributeList;
		 attributeListPtr != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next )
		{
		const SSH_CHANNEL_INFO *channelInfoPtr;

		/* If it's not an SSH channel. continue */
		if( attributeListPtr->attributeID != CRYPT_SESSINFO_SSH_CHANNEL )
			continue;

		/* It's an SSH channel, check whether it's the that one we're
		   after */
		assert( attributeListPtr->valueLength == sizeof( SSH_CHANNEL_INFO ) );
		channelInfoPtr = attributeListPtr->value;
		if( channelInfoPtr->channelID == channelID )
			return( ( SSH_CHANNEL_INFO * ) channelInfoPtr );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( NULL );
	}

static SSH_CHANNEL_INFO *findChannelInfoAddr( const SESSION_INFO *sessionInfoPtr,
											  const char *addrInfo,
											  const int addrInfoLen )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int iterationCount = 0;

	assert( isReadPtr( addrInfo, addrInfoLen ) );

	for( attributeListPtr = sessionInfoPtr->attributeList;
		 attributeListPtr != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next )
		{
		const SSH_CHANNEL_INFO *channelInfoPtr;

		/* If it's not an SSH channel. continue */
		if( attributeListPtr->attributeID != CRYPT_SESSINFO_SSH_CHANNEL )
			continue;

		/* It's an SSH channel, check whether it's the one that we're
		   after */
		assert( attributeListPtr->valueLength == sizeof( SSH_CHANNEL_INFO ) );
		channelInfoPtr = attributeListPtr->value;
		if( channelInfoPtr->arg1Len == addrInfoLen && \
			!memcmp( channelInfoPtr->arg1, addrInfo, addrInfoLen ) )
			return( ( SSH_CHANNEL_INFO * ) channelInfoPtr );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Null();

	return( NULL );
	}

static const SSH_CHANNEL_INFO *getCurrentChannelInfo( const SESSION_INFO *sessionInfoPtr,
													  const CHANNEL_TYPE channelType )
	{
	static const SSH_CHANNEL_INFO nullChannel = \
			{ UNUSED_CHANNEL_ID, UNUSED_CHANNEL_NO, CHANNEL_FLAG_NONE, \
			  0, 0 /*...*/ };
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const SSH_CHANNEL_INFO *channelInfoPtr;
	const int channelID = ( channelType == CHANNEL_READ ) ? \
							sshInfo->currReadChannel : \
							sshInfo->currWriteChannel;

	/* If there's no channel open yet, return the null channel */
	if( channelID == UNUSED_CHANNEL_ID )
		return( ( SSH_CHANNEL_INFO * ) &nullChannel );

	channelInfoPtr = findChannelInfoID( sessionInfoPtr,
										( channelType == CHANNEL_READ ) ? \
											sshInfo->currReadChannel : \
											sshInfo->currWriteChannel );
	return( ( channelInfoPtr == NULL ) ? \
			( SSH_CHANNEL_INFO * ) &nullChannel : channelInfoPtr );
	}

/****************************************************************************
*																			*
*								Get/Set Channel Info						*
*																			*
****************************************************************************/

/* Get the currently active channel */

int getCurrentChannelNo( const SESSION_INFO *sessionInfoPtr,
						 const CHANNEL_TYPE channelType )
	{
	const SSH_CHANNEL_INFO *channelInfoPtr = \
				getCurrentChannelInfo( sessionInfoPtr, channelType );

	assert( channelType == CHANNEL_READ || channelType == CHANNEL_WRITE );

	return( ( channelType == CHANNEL_READ ) ? \
			channelInfoPtr->readChannelNo : channelInfoPtr->writeChannelNo );
	}

/* Get/set an attribute or SSH-specific internal attribute from the current
   channel */

static int copyAttributeData( void *dest, int *destLen, const void *src,
							  const int srcLen, const BOOLEAN copyIn )
	{
	if( !copyIn && srcLen <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( srcLen <= 0 || srcLen > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_BADDATA );
	*destLen = srcLen;
	if( dest != NULL )
		memcpy( dest, src, srcLen );
	return( CRYPT_OK );
	}

int getChannelAttribute( const SESSION_INFO *sessionInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE attribute,
						 void *data, int *dataLength )
	{
	const SSH_CHANNEL_INFO *channelInfoPtr = \
				getCurrentChannelInfo( sessionInfoPtr, CHANNEL_READ );

	/* Clear return values */
	if( data != NULL )
		memset( data, 0, 8 );
	*dataLength = 0;

	if( isNullChannel( channelInfoPtr ) )
		return( CRYPT_ERROR_NOTFOUND );

	switch( attribute )
		{
		case CRYPT_SESSINFO_SSH_CHANNEL:
			*dataLength = channelInfoPtr->channelID;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SSH_CHANNEL_TYPE:
			return( copyAttributeData( data, dataLength,
									   channelInfoPtr->type,
									   channelInfoPtr->typeLen, FALSE ) );

		case CRYPT_SESSINFO_SSH_CHANNEL_ARG1:
			return( copyAttributeData( data, dataLength,
									   channelInfoPtr->arg1,
									   channelInfoPtr->arg1Len, FALSE ) );

		case CRYPT_SESSINFO_SSH_CHANNEL_ARG2:
			return( copyAttributeData( data, dataLength,
									   channelInfoPtr->arg2,
									   channelInfoPtr->arg2Len, FALSE ) );

		case CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE:
			*dataLength = isActiveChannel( channelInfoPtr ) ? TRUE : FALSE;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

int setChannelAttribute( SESSION_INFO *sessionInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE attribute,
						 const void *data, const int dataLength )
	{
	SSH_CHANNEL_INFO *channelInfoPtr;

	/* If we're setting the channel ID this doesn't change any channel
	   attribute but selects the one with the given ID */
	if( attribute == CRYPT_SESSINFO_SSH_CHANNEL )
		{
		channelInfoPtr = findChannelInfoID( sessionInfoPtr, dataLength );
		if( channelInfoPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		return( selectChannel( sessionInfoPtr, channelInfoPtr->writeChannelNo,
							   CHANNEL_WRITE ) );
		}

	/* Set the attribute for the currently-active channel */
	channelInfoPtr = ( SSH_CHANNEL_INFO * ) \
				getCurrentChannelInfo( sessionInfoPtr, CHANNEL_READ );
	if( isNullChannel( channelInfoPtr ) )
		return( CRYPT_ERROR_NOTFOUND );
	switch( attribute )
		{
		case CRYPT_SESSINFO_SSH_CHANNEL_TYPE:
			return( copyAttributeData( channelInfoPtr->type,
									   &channelInfoPtr->typeLen,
									   data, dataLength, TRUE ) );

		case CRYPT_SESSINFO_SSH_CHANNEL_ARG1:
			return( copyAttributeData( channelInfoPtr->arg1,
									   &channelInfoPtr->arg1Len,
									   data, dataLength, TRUE ) );

		case CRYPT_SESSINFO_SSH_CHANNEL_ARG2:
			return( copyAttributeData( channelInfoPtr->arg2,
									   &channelInfoPtr->arg2Len,
									   data, dataLength, TRUE ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

int getChannelExtAttribute( const SESSION_INFO *sessionInfoPtr,
							const SSH_ATTRIBUTE_TYPE attribute,
							void *data, int *dataLength )
	{
	const SSH_CHANNEL_INFO *channelInfoPtr = \
				getCurrentChannelInfo( sessionInfoPtr, CHANNEL_READ );

	if( isNullChannel( channelInfoPtr ) )
		return( CRYPT_ERROR_NOTFOUND );

	switch( attribute )
		{
		case SSH_ATTRIBUTE_WINDOWCOUNT:
			*dataLength = channelInfoPtr->windowCount;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

int setChannelExtAttribute( const SESSION_INFO *sessionInfoPtr,
							const SSH_ATTRIBUTE_TYPE attribute,
							const void *data, const int dataLength )
	{
	SSH_CHANNEL_INFO *channelInfoPtr = ( SSH_CHANNEL_INFO * ) \
				getCurrentChannelInfo( sessionInfoPtr, CHANNEL_READ );

	if( isNullChannel( channelInfoPtr ) )
		return( CRYPT_ERROR_NOTFOUND );

	switch( attribute )
		{
		case SSH_ATTRIBUTE_ACTIVE:
			channelInfoPtr->flags |= CHANNEL_FLAG_ACTIVE;
			return( CRYPT_OK );

		case SSH_ATTRIBUTE_WINDOWCOUNT:
			channelInfoPtr->windowCount = dataLength;
			return( CRYPT_OK );

		case SSH_ATTRIBUTE_ALTCHANNELNO:
			channelInfoPtr->writeChannelNo = dataLength;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Get the status of a channel: Not open, write-side closed, open */

CHANNEL_TYPE getChannelStatus( const SESSION_INFO *sessionInfoPtr,
							   const long channelNo )
	{
	SSH_CHANNEL_INFO *channelInfoPtr;

	channelInfoPtr = findChannelInfo( sessionInfoPtr, channelNo );
	return( ( channelInfoPtr == NULL ) ? CHANNEL_NONE : \
			( channelInfoPtr->flags & CHANNEL_FLAG_WRITECLOSED ) ? \
				CHANNEL_READ : CHANNEL_BOTH );
	}

CHANNEL_TYPE getChannelStatusAddr( const SESSION_INFO *sessionInfoPtr,
								   const char *addrInfo,
								   const int addrInfoLen )
	{
	const SSH_CHANNEL_INFO *channelInfoPtr;

	channelInfoPtr = findChannelInfoAddr( sessionInfoPtr, addrInfo,
										  addrInfoLen );
	return( ( channelInfoPtr == NULL ) ? CHANNEL_NONE : \
			( channelInfoPtr->flags & CHANNEL_FLAG_WRITECLOSED ) ? \
				CHANNEL_READ : CHANNEL_BOTH );
	}

/****************************************************************************
*																			*
*							Channel Management Functions					*
*																			*
****************************************************************************/

/* Select a channel */

int selectChannel( SESSION_INFO *sessionInfoPtr, const long channelNo,
				   const CHANNEL_TYPE channelType )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	SSH_CHANNEL_INFO *channelInfoPtr;

	/* Locate the channel and update the current channel info.  We allow a
	   special channel-type indicator of CHANNEL_NONE to allow the selection
	   of not-yet-activated channels.  Since it's possible to have per-
	   channel packet sizes, we also update the overall packet size value */
	channelInfoPtr = findChannelInfo( sessionInfoPtr, channelNo );
	if( channelInfoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	if( !isActiveChannel( channelInfoPtr ) && channelType != CHANNEL_NONE )
		return( CRYPT_ERROR_NOTINITED );
	switch( channelType )
		{
		case CHANNEL_READ:
			sshInfo->currReadChannel = channelInfoPtr->channelID;
			break;

		case CHANNEL_WRITE:
			sshInfo->currWriteChannel = channelInfoPtr->channelID;
			break;

		case CHANNEL_BOTH:
		case CHANNEL_NONE:
			sshInfo->currReadChannel = \
				sshInfo->currWriteChannel = channelInfoPtr->channelID;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTINITED );
		}
	sessionInfoPtr->maxPacketSize = channelInfoPtr->maxPacketSize;

	return( CRYPT_OK );
	}

/* Add/create/delete a channel */

int addChannel( SESSION_INFO *sessionInfoPtr, const long channelNo,
				const int maxPacketSize, const void *type,
				const int typeLen, const void *arg1, const int arg1Len )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	SSH_CHANNEL_INFO channelInfo;
	int channelCount = 0, iterationCount = 0, status;

	assert( channelNo >= 0 );
	assert( maxPacketSize >= 1024 && maxPacketSize <= 0x100000L );
	assert( isReadPtr( type, typeLen ) );

	/* Make sure that this channel doesn't already exist */
	if( findChannelInfo( sessionInfoPtr, channelNo ) != NULL )
		retExt( sessionInfoPtr, CRYPT_ERROR_DUPLICATE,
				"Attempt to add duplicate channel %ld", channelNo );

	/* SSH channels are allocated unique IDs for tracking by cryptlib,
	   since (at least in theory) the SSH-level channel IDs may repeat.
	   If the initial (not-yet-initialised) channel ID matches the
	   UNUSED_CHANNEL_ID magic value, we initialise it to one past that
	   value */
	if( sshInfo->channelIndex <= UNUSED_CHANNEL_ID )
		sshInfo->channelIndex = UNUSED_CHANNEL_ID + 1;

	/* Make sure that we haven't exceeded the maximum number of channels */
	for( attributeListPtr = sessionInfoPtr->attributeList;
		 attributeListPtr != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next )
		{
		if( attributeListPtr->attributeID == CRYPT_SESSINFO_SSH_CHANNEL )
			channelCount++;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();
	if( channelCount > SSH_MAX_CHANNELS )
		retExt( sessionInfoPtr, CRYPT_ERROR_OVERFLOW,
				"Maximum number (%d) of SSH channels reached",
				SSH_MAX_CHANNELS );

	/* Initialise the info for the new channel and create it */
	memset( &channelInfo, 0, sizeof( SSH_CHANNEL_INFO ) );
	channelInfo.channelID = sshInfo->channelIndex++;
	channelInfo.readChannelNo = channelInfo.writeChannelNo = channelNo;
	channelInfo.maxPacketSize = maxPacketSize;
	copyAttributeData( channelInfo.type, &channelInfo.typeLen,
					   type, typeLen, TRUE );
	if( arg1 != NULL )
		copyAttributeData( channelInfo.arg1, &channelInfo.arg1Len,
						   arg1, arg1Len, TRUE );
	status = addSessionAttributeComposite( &sessionInfoPtr->attributeList,
							CRYPT_SESSINFO_SSH_CHANNEL, accessFunction,
							&channelInfo, sizeof( SSH_CHANNEL_INFO ),
							ATTR_FLAG_MULTIVALUED | ATTR_FLAG_COMPOSITE );
	if( cryptStatusError( status ) )
		return( status );

	/* Select the newly-created channel.  We have to select it using the
	   special-case indicator of CHANNEL_NONE since we can't normally
	   select an inactive channel */
	return( selectChannel( sessionInfoPtr, channelNo, CHANNEL_NONE ) );
	}

int createChannel( SESSION_INFO *sessionInfoPtr )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	int iterationCount = 0;

	/* Find an unused channel number.  Since the peer can request the
	   creation of arbitrary-numbered channels, we have to be careful to
	   ensure that we don't clash with any existing peer-requested channel
	   numbers when we create our own channel */
	while( findChannelInfo( sessionInfoPtr, \
							sshInfo->nextChannelNo ) != NULL && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		sshInfo->nextChannelNo++;
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	/* Create a channel with the new channel number */
	return( addChannel( sessionInfoPtr, sshInfo->nextChannelNo++,
						sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE,
						"session", 7, NULL, 0 ) );
	}

int deleteChannel( SESSION_INFO *sessionInfoPtr, const long channelNo,
				   const CHANNEL_TYPE channelType,
				   const BOOLEAN deleteLastChannel )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	SSH_CHANNEL_INFO *channelInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	int channelID;

	/* If we can't delete the last remaining channel (it has to be done
	   explicitly via a session close) and there are less than two active
	   channels left, we can't do anything */
	if( !deleteLastChannel && \
		!isChannelActive( sessionInfoPtr, UNUSED_CHANNEL_ID, 2 ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Locate the channel info */
	attributeListPtr = findChannelAttr( sessionInfoPtr, channelNo );
	if( attributeListPtr == NULL )
		return( isChannelActive( sessionInfoPtr, UNUSED_CHANNEL_ID, 1 ) ? \
				CRYPT_ERROR_NOTFOUND : OK_SPECIAL );
	channelInfoPtr = attributeListPtr->value;
	channelID = channelInfoPtr->channelID;

	/* Delete the channel entry.  If we're only closing the write side we
	   mark the channel as closed for write but leave the overall channel
	   open */
	if( channelType == CHANNEL_WRITE )
		{
		assert( !( channelInfoPtr->flags & CHANNEL_FLAG_WRITECLOSED ) );
		channelInfoPtr->flags |= CHANNEL_FLAG_WRITECLOSED;
		if( channelID == sshInfo->currWriteChannel )
			sshInfo->currWriteChannel = UNUSED_CHANNEL_ID;
		return( isChannelActive( sessionInfoPtr, \
								 channelInfoPtr->channelID, 1 ) ? \
				CRYPT_OK : OK_SPECIAL );
		}
	deleteSessionAttribute( &sessionInfoPtr->attributeList,
							&sessionInfoPtr->attributeListCurrent,
							attributeListPtr );

	/* If we've deleted the current channel, select a null channel until a
	   new one is created/selected */
	if( channelID == sshInfo->currReadChannel )
		sshInfo->currReadChannel = UNUSED_CHANNEL_ID;
	if( channelID == sshInfo->currWriteChannel )
		sshInfo->currWriteChannel = UNUSED_CHANNEL_ID;

	/* We've deleted an open channel, check if there are any channels left
	   and if not let the caller know */
	return( isChannelActive( sessionInfoPtr, UNUSED_CHANNEL_ID, 1 ) ? \
			CRYPT_OK : OK_SPECIAL );
	}

#if 0

int deleteChannelAddr( SESSION_INFO *sessionInfoPtr, const char *addrInfo,
					   const int addrInfoLen )
	{
	const SSH_CHANNEL_INFO *channelInfoPtr;

	channelInfoPtr = findChannelInfoAddr( sessionInfoPtr, addrInfo,
										  addrInfoLen );
	if( channelInfoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* We've found the entry that it corresponds to, clear it.  This doesn't
	   actually delete the entire channel, but merely deletes the forwarding.
	   See the note in ssh2_msg.c for why this is currently unused */
	memset( channelInfoPtr->arg1, 0, CRYPT_MAX_TEXTSIZE );
	channelInfoPtr->arg1Len = 0;
	return( CRYPT_OK );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Enqueue/Send Channel Messages					*
*																			*
****************************************************************************/

/* Enqueue a response to a request, to be sent at the next available
   opportunity.  This is required because we may be in the middle of
   assembling or sending a data packet when we need to send the response,
   so the response has to be deferred until after the data packet has been
   completed and sent */

int enqueueResponse( SESSION_INFO *sessionInfoPtr, const int type,
					 const int noParams, const long channelNo,
					 const int param1, const int param2, const int param3 )
	{
	SSH_RESPONSE_INFO *respPtr = &sessionInfoPtr->sessionSSH->response;
	STREAM stream;

	/* If there's already a response enqueued, we can't enqueue another one
	   until it's been sent */
	if( respPtr->type != 0 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}

	respPtr->type = type;
	sMemOpen( &stream, respPtr->data, SSH_MAX_RESPONSESIZE );
	if( noParams > 0 )
		writeUint32( &stream, channelNo );
	if( noParams > 1 )
		writeUint32( &stream, param1 );
	if( noParams > 2 )
		writeUint32( &stream, param2 );
	if( noParams > 3 )
		writeUint32( &stream, param3 );
	assert( sStatusOK( &stream ) );
	respPtr->dataLen = stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Assemble a packet for and send a previously enqueued response */

int sendEnqueuedResponse( SESSION_INFO *sessionInfoPtr, const int offset )
	{
	SSH_RESPONSE_INFO *respPtr = &sessionInfoPtr->sessionSSH->response;
	STREAM stream;
	int sendBufOffset = ( offset == CRYPT_UNUSED ) ? \
						sessionInfoPtr->sendBufPos : offset;
	int status;

	assert( sendBufOffset >= 0 );

	/* If there's an incomplete packet in the process of being assembled in
	   the send buffer, we can't do anything */
	if( !sessionInfoPtr->partialWrite && \
		( sendBufOffset > sessionInfoPtr->sendBufStartOfs ) )
		return( CRYPT_OK );

	/* Either the send buffer's empty or it contains a completed packet in
	   the process of being written, if there's not enough room for the
	   enqueued response we can't do anything */
	if( sendBufOffset + ( 32 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_IVSIZE ) > \
		sessionInfoPtr->sendBufSize )
		return( CRYPT_OK );

	assert( ( sendBufOffset <= sessionInfoPtr->sendBufStartOfs ) || \
			( sessionInfoPtr->partialWrite && \
			  sendBufOffset + ( 32 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_IVSIZE ) < \
			  sessionInfoPtr->sendBufSize ) );

	/* If there's nothing in the send buffer, set the start offset to zero.
	   We have to do this because it's pre-adjusted to accomodate the header
	   for a payload data packet, since we're assembling our own packet in
	   the buffer there's no need for this additional header room */
	if( sendBufOffset == sessionInfoPtr->sendBufStartOfs )
		sessionInfoPtr->sendBufPos = sendBufOffset = 0;

	/* Assemble the response as a new packet at the end of any existing
	   data */
	sMemOpen( &stream, sessionInfoPtr->sendBuffer + sendBufOffset,
			  sessionInfoPtr->sendBufSize - sendBufOffset );
	swrite( &stream, "\x00\x00\x00\x00\x00", SSH2_HEADER_SIZE );
	status = sputc( &stream, respPtr->type );
	if( respPtr->dataLen > 0 )
		/* Some responses can consist purely of an ID byte */
		status = swrite( &stream, respPtr->data, respPtr->dataLen );
	if( cryptStatusOK( status ) )
		status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* If we're only assembling the data and the caller is taking care of
	   sending the assembled packet, we're done */
	if( offset != CRYPT_UNUSED )
		return( CRYPT_OK );

	/* We've sent (or at least assembled) the response, clear the enqueued
	   data */
	memset( respPtr, 0, sizeof( SSH_RESPONSE_INFO ) );

	/* Try and write the response */
	if( sessionInfoPtr->flags & SESSION_ISOPEN )
		{
		int dummy;

		/* We're in the data transfer phase, use the standard data-flush
		   mechanism to try and get the data out.  We set the partial-write
		   flag because what we've just added is pre-packaged data that
		   doesn't have to go through the data-payload encoding process */
		sessionInfoPtr->sendBufPos += stell( &stream );
		sessionInfoPtr->partialWrite = TRUE;
		status = putSessionData( sessionInfoPtr, NULL, 0, &dummy );
		}
	else
		/* We're still in the handshake phase, we can send the packet
		   directly */
		status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );

	return( status );
	}

/* Enqueue channel control data ready to be sent, and try and send it if
   possible */

int enqueueChannelData( SESSION_INFO *sessionInfoPtr, const int type,
						const long channelNo, const int param )
	{
	int status;

	status = enqueueResponse( sessionInfoPtr, type, 2, channelNo, param,
							  CRYPT_UNUSED, CRYPT_UNUSED );
	return( cryptStatusOK( status ) ? \
			sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED ) : status );
	}

/* Append enqueued channel control data to existing channel payload data
   without trying to send it (the data send is being piggybacked on a
   payload data send and will be handled by the caller) */

int appendChannelData( SESSION_INFO *sessionInfoPtr, const int offset )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( offset >= 0 && offset < sessionInfoPtr->sendBufSize );

	return( sendEnqueuedResponse( sessionInfoPtr, offset ) );
	}
#endif /* USE_SSH */
