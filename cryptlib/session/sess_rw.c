/****************************************************************************
*																			*
*				cryptlib Session Read/Write Support Routines				*
*					  Copyright Peter Gutmann 1998-2006						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/* Common code to read and write data over the secure connection.  This
   is called by the protocol-specific handlers, which supply three functions:

	readHeaderFunction()	- Reads the header for a packet and sets up
							  length information.
	processBodyFunction()	- Processes the body of a packet.
	preparePacketFunction()	- Wraps a packet in preparation for sending it.

   The behaviour of the network-level stream handlers is as follows:

	Timeout		byteCount		Result
	-------		---------		------
		  - error -				error
	  0			  0				0
	  0			> 0				byteCount
	> 0			  0				CRYPT_ERROR_TIMEOUT
	> 0			> 0				byteCount

   Errors in the processBodyFunction() and preparePacketFunction() are 
   always fatal.  In theory we could try to recover, however the functions 
   update assorted crypto state such as packet sequence numbers and IVs that 
   would be tricky to roll back, and in practice recoverable errors are 
   likely to be extremely rare (at best perhaps a CRYPT_ERROR_TIMEOUT for a 
   context tied to a device, however even this won't occur since the 
   conventional encryption and MAC contexts are all internal native 
   contexts), so there's little point in trying to make the functions 
   recoverable */

/****************************************************************************
*																			*
*						Secure Session Data Read Functions					*
*																			*
****************************************************************************/

/* The read data code uses a helper function tryRead() that either reads
   everything which is available or to the end of the current packet.  In
   other words it's an atomic, all-or-nothing function that can be used by
   higher-level code to handle network-level packetisation.  Buffer
   management is handled as follows: The bPos index always points to the end
   of the decoded data (i.e. data that can be used by the user), if there's
   no partial packet present this index is the same as bEnd:

	----+------------------------
	////|
	----+------------------------
		^
		|
	bEnd/bPos

   If there's a partial packet present, pendingPacketRemaining contains the
   number of bytes required to complete the packet and bEnd points to the
   end of the received data, and is advanced as more data is read:

							<----> pPR
	----+-------------------+----+----
	////|///////////////////|....|
	----+-------------------+----+----
		^					^
		|					|
	  bPos				  bEnd

   Once the complete packet is read (pPR reaches 0), it's decrypted, and
   bPos and bEnd are adjusted to point to the end of the new data:

	----+------------------------+----
	////|////////////////////////|
	----+------------------------+----
								 ^
								 |
							 bEnd/bPos

   The handling of any header data present at the start of the packet
   depends on the packet format, if the header is independent of the
   encrypted data it's handled entirely by the readHeaderFunction() and 
   there's no need to provide special-case handling.  If the header is part 
   of the encrypted data, decryption is a two-stage operation in which
   readHeaderFunction() decrypts just enough of the packet to extract and
   process the header (depositing any leftover non-header data at the start
   of the buffer) and processBodyFunction() processes the rest of the data.

   Errors in the readHeaderFunction() are fatal if they come from the session
   protocol level (e.g. a MAC failure or bad packet) and nonfatal if they
   come from the network layer below the session (the stream-level code has
   its own handling of fatal vs. nonfatal errors, so we don't try and get
   down to that level) */

static int tryRead( SESSION_INFO *sessionInfoPtr, READSTATE_INFO *readInfo )
	{
	int bytesLeft, status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* If there's no pending packet information present, try and read it.
	   This can return one of four classes of values:

		1. An error code.
		2. Zero, to indicate that nothing was read.
		3. OK_SPECIAL and read info READINFO_NOOP to indicate that header
		   data but no payload data was read.
		4. A byte count and read info READINFO_HEADERPAYLOAD to indicate
		   that some payload data was read as part of the header */
	if( sessionInfoPtr->pendingPacketLength <= 0 )
		{
		status = sessionInfoPtr->readHeaderFunction( sessionInfoPtr, readInfo );
		if( status <= 0 && status != OK_SPECIAL )
			return( status );
		assert( ( status == OK_SPECIAL && *readInfo == READINFO_NOOP ) || \
				( status > 0 && *readInfo == READINFO_HEADERPAYLOAD ) );
		if( *readInfo == READINFO_HEADERPAYLOAD )
			{
			/* Some protocols treat the header information for a secured
			   data packet as part of the data, so when we read the header we
			   can get part of the payload included in the read.  When the
			   protocol-specific header read code obtained some payload data
			   alongside the header, it returns READINFO_HEADERPAYLOAD to
			   indicate that the packet info needs to be adjusted for the
			   packet header data that was just read */
			sessionInfoPtr->receiveBufEnd += status;
			sessionInfoPtr->pendingPacketPartialLength = status;
			sessionInfoPtr->pendingPacketRemaining -= status;
			}
		}
	bytesLeft = sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd;

	assert( sessionInfoPtr->partialHeaderLength == 0 );

	/* Sanity-check the read state */
	if( sessionInfoPtr->receiveBufEnd < 0 || \
		sessionInfoPtr->receiveBufEnd > sessionInfoPtr->receiveBufSize || \
		sessionInfoPtr->receiveBufPos < 0 || \
		sessionInfoPtr->receiveBufPos > sessionInfoPtr->receiveBufEnd || \
		sessionInfoPtr->pendingPacketLength < 0 || \
		sessionInfoPtr->pendingPacketRemaining <= 0 || \
		sessionInfoPtr->pendingPacketPartialLength < 0 )
		{
		assert( NOTREACHED );
		retExt( sessionInfoPtr, CRYPT_ERROR_FAILED,
				"Internal error: Inconsistent state detected in session "
				"read stream" );
		}

	/* If there's not enough room in the receive buffer to read at least 1K
	   of packet data, don't try anything until the user has emptied more
	   data from the buffer */
	if( bytesLeft < min( sessionInfoPtr->pendingPacketRemaining, 1024 ) )
		return( 0 );

	/* Try and read more of the packet */
	status = sread( &sessionInfoPtr->stream,
					sessionInfoPtr->receiveBuffer + sessionInfoPtr->receiveBufEnd,
					min( sessionInfoPtr->pendingPacketRemaining, bytesLeft ) );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status <= 0 )
		/* Nothing read, try again later.  This happens only if we're using
		   non-blocking reads (i.e. polled I/O), if any kind of timeout is
		   specified we'll get a timeout error if no data is read */
		return( 0 );
	sessionInfoPtr->receiveBufEnd += status;
	sessionInfoPtr->pendingPacketRemaining -= status;
	if( sessionInfoPtr->pendingPacketRemaining > 0 )
		{
		/* We got some but not all of the data, try again later */
		*readInfo = READINFO_PARTIAL;
		return( OK_SPECIAL );
		}
	assert( sessionInfoPtr->pendingPacketRemaining == 0 );

	/* We've got a complete packet in the buffer, process it */
	return( sessionInfoPtr->processBodyFunction( sessionInfoPtr, readInfo ) );
	}

/* Get data from the remote system */

static int getData( SESSION_INFO *sessionInfoPtr, 
					BYTE *buffer, const int length, int *bytesCopied )
	{
	const int bytesToCopy = min( length, sessionInfoPtr->receiveBufPos );
	READSTATE_INFO readInfo;
	int remainder, status;

	assert( bytesToCopy >= 0 );

	/* Clear return value */
	*bytesCopied = 0;

	/* Sanity-check the read state */
	if( sessionInfoPtr->receiveBufPos < 0 || \
		sessionInfoPtr->receiveBufPos > sessionInfoPtr->receiveBufEnd || \
		sessionInfoPtr->receiveBufEnd < 0 || \
		sessionInfoPtr->receiveBufEnd > sessionInfoPtr->receiveBufSize )
		{
		assert( NOTREACHED );
		retExt( sessionInfoPtr, CRYPT_ERROR_FAILED,
				"Internal error: Inconsistent state detected in session "
				"read stream" );
		}

	/* Copy as much data as we can across and move any remaining data down
	   to the start of the receive buffer.  We copy out up to receiveBufPos,
	   the end of the decoded data, but move up to receiveBufEnd, the 
	   combined decoded data and any as-yet-undecoded partial data that
	   follows the decoded data */
	if( bytesToCopy > 0 )
		{
		memcpy( buffer, sessionInfoPtr->receiveBuffer, bytesToCopy );
		remainder = sessionInfoPtr->receiveBufEnd - bytesToCopy;
		assert( remainder >= 0 );
		if( remainder > 0 )
			{
			/* There's decoded and/or non-decoded data left, move it down to
			   the start of the buffer */
			memmove( sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBuffer + bytesToCopy, remainder );
			sessionInfoPtr->receiveBufPos -= bytesToCopy;
			sessionInfoPtr->receiveBufEnd = remainder;
			}
		else
			/* We've consumed all of the data in the buffer, reset the buffer
			   info */
			sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd = 0;
		assert( sessionInfoPtr->receiveBufPos >= 0 );

		/* Remember how much we've copied and, if we've satisfied the 
		   request, exit */
		*bytesCopied = bytesToCopy;
		if( bytesToCopy >= length )
			return( CRYPT_OK );
		}
	assert( sessionInfoPtr->receiveBufPos == 0 );

	/* Try and read a complete packet.  This can return one of four classes 
	   of values:

		1. An error code.
		2. Zero to indicate that nothing was read (only happens on non-
		   blocking reads (polled I/O), a blocking read will return a 
		   timeout error) or that there isn't enough room left in the read 
		   buffer to read any more.
		3a.OK_SPECIAL and read info READINFO_PARTIAL to indicate that a
		   partial packet (not enough to process) was read.
		3b.OK_SPECIAL and read info READINFO_NOOP to indicate that a no-op 
		   packet was read and the caller should try again without changing 
		   the read timeout value.
		4. A byte count if a complete packet was read and processed */
	status = tryRead( sessionInfoPtr, &readInfo );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		{
		/* If there's an error reading data, only return an error status if 
		   we haven't already returned existing/earlier data.  This ensures 
		   that the caller can drain out any remaining data from the session 
		   buffer before they start getting error returns */
		if( *bytesCopied <= 0 )
			{
			if( readInfo == READINFO_FATAL )
				sessionInfoPtr->readErrorState = status;
			return( status );
			}

		/* We got some data before encountering the error, if it's fatal 
		   save the pending error state for later while returning the read 
		   byte count to the caller.  Note that this results in non-fatal 
		   errors being quietly dropped if data is otherwise available, the 
		   alternative would be to save it as a pending (specially-marked) 
		   non-fatal error, however since this error type by definition can 
		   be resumed it may already have resolved itself by the next time 
		   that we're called, so this is safe to do */
		if( readInfo == READINFO_FATAL )
			sessionInfoPtr->pendingReadErrorState = status;
		return( OK_SPECIAL );
		}

	/* If we got nothing, exit */
	if( status == 0 )
		return( OK_SPECIAL );

	/* If we read a partial packet and there's room for the rest of the 
	   packet in the buffer, set a minimum timeout to try and get the rest 
	   of the packet.  This is safe because tryRead() could have behaved in 
	   only one of two ways:

		1. Blocking read, in which case we waited for the full timeout 
		   period anyway and a small additional timeout won't be noticed.
		2. Nonblocking read, in which case waiting for a nonzero time could 
		   potentially have retrieved more data */
	if( status == OK_SPECIAL )
		{
		assert( readInfo == READINFO_PARTIAL || \
				readInfo == READINFO_NOOP );
		if( readInfo == READINFO_PARTIAL && \
			sessionInfoPtr->pendingPacketRemaining <= \
			sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd )
			sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_READTIMEOUT, NULL, 1 );
		return( CRYPT_OK );
		}

	/* Make the stream nonblocking if it was blocking before.  This is 
	   necessary to avoid having the stream always block for the set timeout 
	   value on the last read */
	assert( status > 0 );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_READTIMEOUT, NULL, 0 );

	return( CRYPT_OK );
	}

int getSessionData( SESSION_INFO *sessionInfoPtr, void *data, 
					const int length, int *bytesCopied )
	{
	BYTE *dataPtr = data;
	int dataLength = length, iterationCount = 0, status = CRYPT_OK;

	/* Clear return value */
	*bytesCopied = 0;

	/* If there's an error pending (which will always be fatal, see the
	   comment after the tryRead() call in getData()), set the current error 
	   state to the pending state and return */
	if( cryptStatusError( sessionInfoPtr->pendingReadErrorState ) )
		{
		assert( sessionInfoPtr->receiveBufPos == 0 );

		status = sessionInfoPtr->readErrorState = \
						sessionInfoPtr->pendingReadErrorState;
		sessionInfoPtr->pendingReadErrorState = CRYPT_OK;
		return( status );
		}

	/* Update the stream read timeout to the current user-selected read 
	   timeout in case the user has changed the timeout setting */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_READTIMEOUT, NULL,
			sessionInfoPtr->readTimeout );

	while( cryptStatusOK( status ) && dataLength > 0 && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
		{
		int count;

		/* Get the next packets-worth of data.  This can return one of three
		   classes of values:

			1. An error code.
			2. OK_SPECIAL to indicate that some data was read but no more is
			   available.
			3. CRYPT_OK to indicate that data was read and more may be 
			   available.
		
		   Note that we can have data available even if an error status is 
		   returned since it can successfully read data before encountering 
		   the error, so we update the byte count no matter what the return 
		   status */
		status = getData( sessionInfoPtr, dataPtr, dataLength, &count );
		if( count > 0 )
			{
			*bytesCopied += count;
			dataPtr += count;
			dataLength -= count;
			}

		assert( sessionInfoPtr->receiveBufEnd <= \
				sessionInfoPtr->receiveBufSize );
		assert( sessionInfoPtr->receiveBufPos <= \
				sessionInfoPtr->receiveBufEnd );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* If we got at least some data or encountered a soft timeout, the 
	   operation was (nominally) successful, otherwise it's an error */
	return( ( *bytesCopied > 0 || status == OK_SPECIAL ) ? \
			CRYPT_OK : status );
	}

/* Read a fixed-size packet header, called by the secure data session
   routines to read the fixed header on a data packet.  This is an atomic
   read of out-of-band data that isn't part of the packet payload, so we
   have to make sure that we've got the entire header before we can
   continue:

		| <- hdrSize ->	|
	----+---------------+--------
	////|				|
	----+---------------+--------
		^		^
		|		|
	  bEnd	partialHdr

   The data is read into the read buffer starting at the end of the last
   payload packet bEnd, this is safe because this function causes a
   pipeline stall so no more data can be read until the header has been
   read.  The function then returns CRYPT_ERROR_TIMEOUT until partialHdr 
   reaches the full header size */

int readFixedHeader( SESSION_INFO *sessionInfoPtr, const int headerSize )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	int status;

	/* If it's the first attempt at reading the header, set the total byte
	   count */
	if( sessionInfoPtr->partialHeaderLength <= 0 )
		sessionInfoPtr->partialHeaderLength = headerSize;
	else
		bufPtr += headerSize - sessionInfoPtr->partialHeaderLength;

	assert( sessionInfoPtr->partialHeaderLength > 0 && \
			sessionInfoPtr->partialHeaderLength <= headerSize );

	/* Clear the first few bytes of returned data to make sure that the
	   higher-level code always bails out if the read fails for some reason
	   without returning an error status */
	memset( bufPtr, 0, min( headerSize, \
							sessionInfoPtr->partialHeaderLength ) );

	/* Try and read the remaining header bytes */
	status = sread( &sessionInfoPtr->stream, bufPtr,
					sessionInfoPtr->partialHeaderLength );
	if( cryptStatusError( status ) )
		{
		/* We could be trying to read an ack for a close packet sent in 
		   response to an earlier error, in which case we don't want the
		   already-present error information overwritten by network
		   error info, so if the no-report-error flag is set we don't
		   update the extended error info */
		if( sessionInfoPtr->flags & SESSION_NOREPORTERROR )
			return( status );

		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}

	/* If we didn't get the whole header, treat it as a timeout error */
	if( status < sessionInfoPtr->partialHeaderLength )
		{
		/* If we timed out during the handshake phase, treat it as a hard
		   timeout error */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			{
			if( sessionInfoPtr->flags & SESSION_NOREPORTERROR )
				return( status );
			retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
					"Timeout during packet header read, only got %d of %d "
					"bytes", status, headerSize );
			}

		/* We're in the data-processing stage, it's a soft timeout error */
		sessionInfoPtr->partialHeaderLength -= status;
		return( 0 );
		}

	/* We've got the whole header ready to process */
	assert( sessionInfoPtr->partialHeaderLength == status );
	sessionInfoPtr->partialHeaderLength = 0;
	return( headerSize );
	}

/****************************************************************************
*																			*
*						Secure Session Data Write Functions					*
*																			*
****************************************************************************/

/* Send data to the remote system.  There are two strategies for handling 
   buffer filling and partial writes, either to fill the buffer as full as 
   possible and write it all at once, or to write complete packets as soon 
   as they're available.  We use the latter strategy here, both because it 
   considerably simplifies buffer management and because interleaving 
   (asynchronous) writes and packet processing increases the chances that 
   the current packet will be successfully dispatched across the network 
   while the next one is being encrypted - trying to asynchronously write a 
   large amount of data in one go practically guarantees that the write 
   won't complete.

   Session buffer management is handled as follows: The startOfs index 
   points to the start of the payload space in the buffer (everything before 
   this is header data).  The maxPacketSize value indicates the end of the 
   payload space relative to the startOfs:

	<- hdr->|<-- payload -->|
	+-------+---------------+---+
	|		|///////////////|	|
	+-------+---------------+---+
			^				^
			|				|
		startOfs	  maxPacketSize

   The bPos index moves from startsOfs to maxPacketSize, after which the 
   data is wrapped up by the protocol-specific code.  At this point bPos
   usually points past the end of maxPacketSize due to the addition of
   trailer data such as encryption block padding and a MAC.  Once the
   packet is assembled, the data is flushed and the bPos index reset:

		startOfs	  maxPacketSize
			|				|
			v				v
	+-------+-------+-------+---+
	|.......|.......|///////|///|
	+-------+-------+-------+---+
					^<--- to -->^
					|	write	|
			  partialBufPos	  bufPos

   As with reads, writes can be non-atomic, although on a more restrictive 
   scale than reads: Once an encrypted packet has been assembled in the 
   write buffer, the entire contents must be written before a new packet can 
   be assembled.  This guarantees that when the caller flushes data through 
   to the other side, all of the data will be sent (and the other side will 
   have a chance to react to it) before the next load of data can be flushed 
   through.

   Once we have partial data in the send buffer, all further attempts to
   add more data fail until the remainder of the partially-written data
   has been flushed.  This is handled by setting sendBufPartialBufPos to
   point to the first byte of unwritten data, so that 
   sendBufPartialBufPos ... sendBufPos remains to be written */

static int flushData( SESSION_INFO *sessionInfoPtr )
	{
	int length, status;

	/* If there's no data to flush, exit */
	if( sessionInfoPtr->sendBufPos <= sessionInfoPtr->sendBufStartOfs )
		return( CRYPT_OK );	

	/* If there's no unwritten data from a previous write attempt still 
	   present, prepare to send the new data */
	if( !sessionInfoPtr->partialWrite )
		{
		assert( sessionInfoPtr->sendBufPartialBufPos == 0 );

		status = length = \
			sessionInfoPtr->preparePacketFunction( sessionInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* Errors in the crypto are immediately fatal */
			sessionInfoPtr->writeErrorState = status;
			return( status );
			}

		/* Adjust the buffer position to account for the wrapped packet
		   size */
		sessionInfoPtr->sendBufPos = length;
		}
	length = sessionInfoPtr->sendBufPos - \
			 sessionInfoPtr->sendBufPartialBufPos;
	assert( length > 0 );

	/* Send the data through to the remote system */
	status = swrite( &sessionInfoPtr->stream, 
					 sessionInfoPtr->sendBuffer + \
						sessionInfoPtr->sendBufPartialBufPos,
					 length );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_TIMEOUT )
		{
		/* There was an error other than a (restartable) send timeout,
		   return the error details to the caller */
		sessionInfoPtr->writeErrorState = status;
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}

	/* If the send timed out before all of the data could be written, 
	   record how much still remains to be sent and inform the caller.  We
	   return this special-case code rather than either a timeout or
	   CRYPT_OK / 0 bytes because the caller can turn this into a situation-
	   specific status at the higher level, a timeout error for an explicit
	   flush but a CRYPT_OK / 0 for an implicit flush performed as part of a
	   write */
	if( status < length )
		{
		assert( status == CRYPT_ERROR_TIMEOUT || \
				( status >= 0 && status < length ) );

		/* If we wrote at least some part of the packet, adjust the partial-
		   write position by the amount that we wrote */
		if( status > 0 )
			sessionInfoPtr->sendBufPartialBufPos += status;

		assert( sessionInfoPtr->sendBufPartialBufPos < \
				sessionInfoPtr->sendBufPos );

		sessionInfoPtr->partialWrite = TRUE;
		return( OK_SPECIAL );
		}

	assert( status == length );

	/* We sent everything, reset the buffer status values */
	sessionInfoPtr->sendBufPos = sessionInfoPtr->sendBufStartOfs;
	sessionInfoPtr->partialWrite = FALSE;
	sessionInfoPtr->sendBufPartialBufPos = 0;

	return( CRYPT_OK );
	}

int putSessionData( SESSION_INFO *sessionInfoPtr, const void *data,
					const int length, int *bytesCopied )
	{
	BYTE *dataPtr = ( BYTE * ) data;
	int dataLength = length, iterationCount = 0, status;

	/* Clear return value */
	*bytesCopied = 0;

	/* Sanity-check the write state */
	if( sessionInfoPtr->sendBufPos < sessionInfoPtr->sendBufStartOfs || \
		sessionInfoPtr->sendBufPos >= sessionInfoPtr->sendBufSize || \
		( !sessionInfoPtr->partialWrite && \
		  sessionInfoPtr->sendBufPos > sessionInfoPtr->sendBufStartOfs + \
									   sessionInfoPtr->maxPacketSize ) || \
		sessionInfoPtr->sendBufPartialBufPos < 0 || \
		sessionInfoPtr->sendBufPartialBufPos >= sessionInfoPtr->sendBufPos )
		{
		assert( NOTREACHED );
		retExt( sessionInfoPtr, CRYPT_ERROR_FAILED,
				"Internal error: Inconsistent state detected in session "
				"write stream" );
		}

	/* If there's an error pending (which will always be fatal, see the
	   comment after the flushData() call below), set the current error state
	   to the pending state and return */
	if( cryptStatusError( sessionInfoPtr->pendingWriteErrorState ) )
		{
		assert( sessionInfoPtr->receiveBufPos == 0 );

		status = sessionInfoPtr->writeErrorState = \
						sessionInfoPtr->pendingWriteErrorState;
		sessionInfoPtr->pendingWriteErrorState = CRYPT_OK;
		return( status );
		}

	/* Update the stream write timeout to the current user-selected write 
	   timeout in case the user has changed the timeout setting */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_WRITETIMEOUT, NULL,
			sessionInfoPtr->writeTimeout );

	/* If it's a flush, send the data through to the server.  If there's a 
	   timeout error during an explicit flush (that is, some but not all of
	   the data is written, so it's a soft timeout), it's converted into an 
	   explicit hard timeout failure */
	if( dataLength <= 0 )
		{
		const int oldBufPos = sessionInfoPtr->sendBufPartialBufPos;
		int bytesWritten;

		status = flushData( sessionInfoPtr );
		if( status != OK_SPECIAL )
			return( status );

		/* Since a partial write isn't a network-level error condition (it's 
		   only treated as a problem once it gets to the putSessionData() 
		   layer), there's no extended error information set for it, so we
		   have to set the error information here when we turn the partial
		   write into a timeout error */
		bytesWritten = sessionInfoPtr->sendBufPartialBufPos - oldBufPos;
		if( bytesWritten > 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
					"Timeout during flush, only %d bytes were written "
					"before the timeout of %d seconds expired",
					sessionInfoPtr->sendBufPartialBufPos, 
					sessionInfoPtr->writeTimeout );
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
				"Timeout during flush, no data could be written before the "
				"timeout of %d seconds expired", 
				sessionInfoPtr->writeTimeout );
		}

	/* If there's unwritten data from a previous write still in the buffer, 
	   flush that through first.  Since this isn't an explicit flush by the
	   caller we convert a soft timeout indicator into CRYPT_OK / 0 bytes */
	if( sessionInfoPtr->partialWrite )
		{
		status = flushData( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
		}

	/* If there's too much data to fit in the buffer, send it through to the
	   host */
	while( ( sessionInfoPtr->sendBufPos - \
			 sessionInfoPtr->sendBufStartOfs ) + dataLength >= \
		   sessionInfoPtr->maxPacketSize && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		const int bytesToCopy = sessionInfoPtr->maxPacketSize - \
								( sessionInfoPtr->sendBufPos + \
								  sessionInfoPtr->sendBufStartOfs );

		assert( bytesToCopy >= 0 && bytesToCopy <= dataLength );

		/* Copy in as much data as we have room for and send it through.  The
		   flush can return one of three classes of values:

			1. An error code, but not CRYPT_ERROR_TIMEOUT, which is handled
			   as case (2) below.
			2. OK_SPECIAL to indicate that some of the requested data 
			   (possibly 0 bytes) was written.
			3. CRYPT_OK to indicate that all of the requested data was
			   written and more can be written if necessary */
		if( bytesToCopy > 0 )
			{
			memcpy( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufPos,
					dataPtr, bytesToCopy );
			sessionInfoPtr->sendBufPos += bytesToCopy;
			dataPtr += bytesToCopy;
			dataLength -= bytesToCopy;
			*bytesCopied += bytesToCopy;
			}
		status = flushData( sessionInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* If it's a soft timeout indicator, convert it to a CRYPT_OK / 
			   0 bytes written */
			if( status == OK_SPECIAL )
				return( CRYPT_OK );

			/* There was a problem flushing the data through, if we managed 
			   to copy anything into the buffer we've made some progress so 
			   we defer it until the next call */
			if( *bytesCopied > 0 )
				{
				sessionInfoPtr->pendingWriteErrorState = status;
				return( CRYPT_OK );
				}

			/* Nothing was copied before the error occurred, it's 
			   immediately fatal */
			return( status );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();

	/* If there's anything left, it'll fit completely into the send buffer, 
	   just copy it in */
	if( dataLength > 0 )
		{
		assert( ( sessionInfoPtr->sendBufPos - \
				  sessionInfoPtr->sendBufStartOfs ) + dataLength < \
				sessionInfoPtr->maxPacketSize );

		memcpy( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufPos,
				dataPtr, dataLength );
		sessionInfoPtr->sendBufPos += dataLength;
		*bytesCopied += dataLength;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*				Request/response Session Data Handling Functions			*
*																			*
****************************************************************************/

/* Read/write a PKI (i.e. ASN.1-encoded) datagram */

int readPkiDatagram( SESSION_INFO *sessionInfoPtr )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Read the datagram */
	sessionInfoPtr->receiveBufEnd = 0;
	status = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < 4 )
		/* Perform a sanity check on the length.  This avoids some
		   assertions in the debug build, and provides somewhat more
		   specific information for the caller than the invalid-encoding
		   error that we'd get later */
		retExt( sessionInfoPtr, CRYPT_ERROR_UNDERFLOW,
				"Invalid PKI message length %d", status );

	/* Find out how much data we got and perform a firewall check that
	   everything is OK.  We rely on this rather than the read byte count
	   since checking the ASN.1, which is the data that will actually be
	   processed, avoids any vagaries of server implementation oddities */
	length = checkObjectEncoding( sessionInfoPtr->receiveBuffer, status );
	if( cryptStatusError( length ) )
		retExt( sessionInfoPtr, length, "Invalid PKI message encoding" );
	sessionInfoPtr->receiveBufEnd = length;
	return( CRYPT_OK );
	}

int writePkiDatagram( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( sessionInfoPtr->receiveBufEnd > 4 );

	/* Write the datagram */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );
	if( cryptStatusError( status ) )
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
	sessionInfoPtr->receiveBufEnd = 0;

	return( CRYPT_OK );	/* swrite() returns a byte count */
	}
#endif /* USE_SESSIONS */
