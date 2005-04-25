/****************************************************************************
*																			*
*					  cryptlib Datagram Decoding Routines					*
*						Copyright Peter Gutmann 1996-2005					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "../misc/asn1.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/*			 .... NO! ...				   ... MNO! ...
		   ..... MNO!! ...................... MNNOO! ...
		 ..... MMNO! ......................... MNNOO!! .
		.... MNOONNOO!	 MMMMMMMMMMPPPOII!	 MNNO!!!! .
		 ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....
			...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...
		   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....
		   ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...
			....... MMMMM..	   OPPMMP	 .,OMI! ....
			 ...... MMMM::	 o.,OPMP,.o	  ::I!! ...
				 .... NNM:::.,,OOPM!P,.::::!! ....
				  .. MMNNNNNOOOOPMO!!IIPPO!!O! .....
				 ... MMMMMNNNNOO:!!:!!IPPPPOO! ....
				   .. MMMMMNNOOMMNNIIIPPPOO!! ......
				  ...... MMMONNMMNNNIIIOO!..........
			   ....... MN MOMMMNNNIIIIIO! OO ..........
			......... MNO! IiiiiiiiiiiiI OOOO ...........
		  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........
		   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........
		   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........
			  ...... OO! ................. ON! .......
				 ................................

   Be very careful when modifying this code, the data manipulation it
   performs is somewhat tricky */

/****************************************************************************
*																			*
*							Header Processing Routines						*
*																			*
****************************************************************************/

/* Handle the EOC and PKCS #5 block padding if necessary:

			   pad
	+-------+-------+-------+
	|		|		|		|
	+-------+-------+-------+
			^		^
			|		|
		 padPtr	  bPos */

static int processEOC( ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );

	/* If we're using a block cipher, undo the PKCS #5 padding which is
	   present at the end of the block */
	if( envelopeInfoPtr->blockSize > 1 )
		{
		const BYTE *padPtr = envelopeInfoPtr->buffer + \
							 envelopeInfoPtr->bufPos - 1;
		const int padSize = *padPtr;
		int i;

		/* Make sure that the padding size is valid */
		if( padSize < 1 || padSize > envelopeInfoPtr->blockSize || \
			padSize > envelopeInfoPtr->bufPos )
			return( CRYPT_ERROR_BADDATA );

		/* Check the padding data */
		envelopeInfoPtr->bufPos -= padSize;
		padPtr -= padSize - 1;
		for( i = 0; i < padSize - 1; i++ )
			if( padPtr[ i ] != padSize )
				return( CRYPT_ERROR_BADDATA );
		assert( envelopeInfoPtr->bufPos >= 0 );
		}

	/* Remember that we've reached the end of the payload and where the
	   payload ends ("This was the end of the river all right") */
	envelopeInfoPtr->dataFlags |= ENVDATA_ENDOFCONTENTS;
	envelopeInfoPtr->dataLeft = envelopeInfoPtr->bufPos;

	return( CRYPT_OK );
	}

/* Decode the header for the next segment in the buffer.  Returns the number
   of bytes consumed, or an underflow error if more data is required */

static int getNextSegment( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
						   const int length )
	{
	SEGHDR_STATE state = envelopeInfoPtr->segHdrState;
	long segmentLength = envelopeInfoPtr->segHdrSegLength;
	int count = envelopeInfoPtr->segHdrCount, bufPos;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );

	/* If we've already processed the entire payload, don't do anything.  
	   This can happen when we're using the definite encoding form, since
	   the EOC flag is set elsewhere as soon as the entire payload has been
	   copied to the buffer */
	if( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS )
		return( OK_SPECIAL );

	/* If we're using the definite encoding form, there's a single segment
	   equal in length to the entire payload */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		envelopeInfoPtr->segmentSize = envelopeInfoPtr->payloadSize;
		return( OK_SPECIAL );
		}

	/* If we're using the indefinite form but it's an envelope type that 
	   doesn't segment data, the length is implicitly defined as "until we 
	   run out of input" */
	if( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT )
		{
		envelopeInfoPtr->segmentSize = CRYPT_UNUSED;
		return( OK_SPECIAL );
		}

	/* If we're starting a new sub-segment read and there's enough data 
	   present that we can try and use the ASN.1 read routines, try and get
	   the sub-segment info using the ASN.1 routines */
	if( state == SEGHDRSTATE_NONE && length >= 2 )
		{
		STREAM stream;
		int bytesRead, status;

		assert( envelopeInfoPtr->segHdrSegLength == 0L && \
				envelopeInfoPtr->segHdrCount == 0 );

		/* Get the sub-segment info */
		sMemConnect( &stream, buffer, length );
		status = checkEOC( &stream );
		if( status == FALSE )
			{
			/* It's a new sub-segment, get its length */
			status = readLongGenericHole( &stream, &segmentLength, 
										  BER_OCTETSTRING );
			if( cryptStatusOK( status ) && segmentLength == CRYPT_UNUSED )
				/* If it's an (invalid) indefinite-length encoding, we can't 
				   do anything with it */
				status = CRYPT_ERROR_BADDATA;
			}
		else
			/* If we've seen the EOC, wrap up the processing */
			if( status == TRUE )
				{
				status = processEOC( envelopeInfoPtr );
				segmentLength = 0;
				}
		bytesRead = stell( &stream );
		sMemDisconnect( &stream );

		/* If the read was successful (i.e. we didn't run out of input), 
		   return the info to the caller */
		if( status != CRYPT_ERROR_UNDERFLOW )
			{
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->segmentSize = segmentLength;
			return( bytesRead );
			}
		}

	/* We couldn't read the current sub-segment info using the ASN.1 
	   routines due to lack of input data, fall back to the FSM-based read, 
	   which is interruptible.  This read processes each data byte until 
	   we've either parsed the entire header or run out of input. It is
	   however not quite as tolerant as the ASN.1 code in terms of accepting
	   odd non-DER encodings */
	for( bufPos = 0; bufPos < length && state != SEGHDRSTATE_DONE; bufPos++ )
		{
		SEGHDR_STATE oldState = state;

		switch( state )
			{
			case SEGHDRSTATE_NONE:
				/* Check for OCTET STRING or start or end-of-contents
				   octets */
				segmentLength = 0;
				if( buffer[ bufPos ] == BER_OCTETSTRING )
					state = SEGHDRSTATE_LEN_OF_LEN;
				else
					if( buffer[ bufPos ] == BER_EOC )
						state = SEGHDRSTATE_END;
					else
						return( CRYPT_ERROR_BADDATA );
				break;

			case SEGHDRSTATE_LEN_OF_LEN:
				/* We've seen the OCTET STRING header, check for a short
				   length or length-of-length value */
				count = buffer[ bufPos ];
				if( !( count & 0x80 ) )
					{
					/* It's a short/indefinite length */
					segmentLength = count;
					state = SEGHDRSTATE_DONE;
					}
				else
					{
					/* It's a long segment, get the length-of-length
					   information */
					count &= 0x7F;
					if( count < 1 || count > 4 )
						/* "Nobody will ever need more than 640K" */
						return( CRYPT_ERROR_BADDATA );
					state = SEGHDRSTATE_LEN;
					}
				break;

			case SEGHDRSTATE_LEN:
				/* We're processing a long-format length field, get the next
				   part of the length */
				segmentLength = ( segmentLength << 8 ) | buffer[ bufPos ];
				count--;

				/* If we've got all the data, make sure that the segment 
				   length is valid and return to the initial state */
				if( count <= 0 )
					{
					if( segmentLength < 0x80 )
						/* Probably a bit pedantic, but it helps catch 
						   garbled data */
						return( CRYPT_ERROR_BADDATA );
					state = SEGHDRSTATE_DONE;
					}
				break;

			case SEGHDRSTATE_END:
				{
				int status;

				/* We've seen the first EOC octet, check for the second 
				   one */
				if( buffer[ bufPos ] )
					return( CRYPT_ERROR_BADDATA );

				/* Process the EOC octets */
				status = processEOC( envelopeInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				state = SEGHDRSTATE_DONE;
				break;
				}

			default:
				assert( NOTREACHED );
			}

		/* If the state hasn't changed when it should have, there's a
		   problem */
		if( state == oldState && state != SEGHDRSTATE_LEN )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Make sure that the length we got is valid.  These checks just 
	   duplicate the checks normally performed by the ASN.1-level code */
	if( length < 0 )
		return( CRYPT_ERROR_BADDATA );
	if( ( length & 0x80000000UL ) || length > MAX_INTLENGTH )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we got the final length, update the appropriate segment length
	   value */
	if( state == SEGHDRSTATE_DONE )
		{
		envelopeInfoPtr->segmentSize = segmentLength;
		envelopeInfoPtr->segHdrSegLength = 0L;
		envelopeInfoPtr->segHdrCount = 0;
		envelopeInfoPtr->segHdrState = SEGHDRSTATE_NONE;
		}
	else
		{
		/* Copy the local state information back into the envelope
		   structure */
		envelopeInfoPtr->segHdrSegLength = segmentLength;
		envelopeInfoPtr->segHdrCount = count;
		envelopeInfoPtr->segHdrState = state;
		}

	return( bufPos );
	}

/****************************************************************************
*																			*
*								Copy to Envelope							*
*																			*
****************************************************************************/

/* Copy possibly encrypted data into the envelope with special handling for
   block encryption modes.  Returns the number of bytes copied */

static int copyData( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
					 const int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	int bytesToCopy, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( ( envelopeInfoPtr->blockSize == 0 ) || \
			( envelopeInfoPtr->blockBufferPos >= 0 && \
			  envelopeInfoPtr->blockBufferPos < envelopeInfoPtr->blockSize ) );

	/* Figure out how much we can copy across.  First we calculate the
	   minimum of the amount of data passed in and the amount remaining in
	   the current segment.  If it's unknown-length data (which can only
	   happen for compressed data), it ends wherever the caller tells us it 
	   ends and we use it all */
	bytesToCopy = ( envelopeInfoPtr->segmentSize == CRYPT_UNUSED ) ? \
				  length : ( int ) min( envelopeInfoPtr->segmentSize, length );

	/* Now we check if this is affected by the total free space remaining in
	   the buffer.  If we're processing data blocks we can have two cases,
	   one in which the limit is the amount of buffer space available and the
	   other in which the limit is the amount of data available.  If the
	   limit is set by the available data, we don't have to worry about
	   flushing extra data out of the block buffer into the main buffer, but
	   if the limit is set by the available buffer space we have to reduce
	   the amount we can copy in based on any extra data that will be
	   flushed out of the block buffer.

	   There are two possible approaches that can be used when the block
	   buffer is involved.  The first one copies as much as we can into the
	   buffer and, if that isn't enough, maxes out the block buffer with as
	   much remaining data as possible.  The second only copies in as much as
	   can fit into the buffer, even if there's room in the block buffer for
	   a few more bytes.  The second approach is preferable because although
	   either will give the impression of a not-quite-full buffer into which
	   no more data can be copied, the second minimizes the amount of data
	   which is moved into and out of the block buffer.

	   The first approach may seem slightly more logical, but will only
	   cause confusion in the long run.  Consider copying (say) 43 bytes to
	   a 43-byte buffer.  The first time this will succeed, after which there
	   will be 40 bytes in the buffer (reported to the caller) and 3 in the
	   block buffer.  If the caller tries to copy in 3 more bytes to "fill"
	   the main buffer, they'll again vanish into the block buffer.  A second
	   call with three more bytes will copy 2 bytes and return with 1
	   uncopied.  In effect this method of using the block buffer extends the
	   blocksize-quantized main buffer by the size of the block buffer, which
	   will only cause confusion when data appears to vanish when copied in */
	bytesToCopy = min( bytesToCopy, \
					   ( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos ) - \
						 envelopeInfoPtr->blockBufferPos );
	if( bytesToCopy < 0 || envelopeInfoPtr->blockBufferPos < 0 )
		{
		/* Safety check that verifies segmentSize, length, bufPos, and
		   blockBufferPos before we start into the following code */
		assert( NOTREACHED );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If we're given a zero length, return now.  This can happen if all
	   input is consumed in processing the headers (we're passed a zero
	   length) */
	if( bytesToCopy <= 0 )
		return( 0 );

	/* If its a block encryption mode we need to provide special handling for
	   odd data lengths that don't match the block size */
	if( envelopeInfoPtr->blockSize > 1 )
		{
		int bytesCopied = 0, quantizedBytesToCopy;

		/* If the new data will fit into the block buffer, copy it in now and
		   return */
		if( envelopeInfoPtr->blockBufferPos + bytesToCopy < \
			envelopeInfoPtr->blockSize )
			{
			memcpy( envelopeInfoPtr->blockBuffer + envelopeInfoPtr->blockBufferPos,
					buffer, bytesToCopy );
			envelopeInfoPtr->blockBufferPos += bytesToCopy;

			/* Adjust the segment size based on what we've consumed */
			envelopeInfoPtr->segmentSize -= bytesToCopy;

			return( bytesToCopy );
			}

		/* If there isn't room in the main buffer for even one more block,
		   exit without doing anything.  This leads to slightly anomalous
		   behaviour where, with no room for a complete block in the main
		   buffer, copying in a data length smaller than the block buffer
		   will lead to the data being absorbed by the block buffer due to
		   the previous section of code, but copying in a length larger than
		   the block buffer will result in no data at all being absorbed,
		   even if there is still room in the block buffer */
		if( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos < \
			envelopeInfoPtr->blockSize )
			return( 0 );	/* No room for even one more block */

		/* There's room for at least one more block in the buffer.  First,
		   if there are leftover bytes in the block buffer, move them into
		   the main buffer */
		if( envelopeInfoPtr->blockBufferPos > 0 )
			{
			memcpy( bufPtr, envelopeInfoPtr->blockBuffer,
					envelopeInfoPtr->blockBufferPos );
			bytesCopied = envelopeInfoPtr->blockBufferPos;
			}
		envelopeInfoPtr->blockBufferPos = 0;

		/* Determine how many bytes we can copy into the buffer to fill it
		   to the nearest available block size */
		quantizedBytesToCopy = ( bytesToCopy + bytesCopied ) & \
							   envelopeInfoPtr->blockSizeMask;
		quantizedBytesToCopy -= bytesCopied;
		if( bytesToCopy < 0 || quantizedBytesToCopy <= 0 || \
			quantizedBytesToCopy > bytesToCopy )
			{
			/* Safety check */
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
			}

		/* Now copy across a number of bytes which is a multiple of the block
		   size and decrypt them.  Note that we have to use memmove() rather
		   than memcpy() because if we're sync'ing data in the buffer we're
		   doing a copy within the buffer rather than copying in external 
		   data */
		memmove( bufPtr + bytesCopied, buffer, quantizedBytesToCopy );
		envelopeInfoPtr->bufPos += bytesCopied + quantizedBytesToCopy;
		envelopeInfoPtr->segmentSize -= bytesToCopy;
		status = krnlSendMessage( envelopeInfoPtr->iCryptContext, 
								  IMESSAGE_CTX_DECRYPT, bufPtr, 
								  bytesCopied + quantizedBytesToCopy );
		if( cryptStatusError( status ) )
			return( status );
		assert( envelopeInfoPtr->bufPos >=0 && \
				envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
		assert( envelopeInfoPtr->segmentSize >= 0 );

		/* If the payload has a definite length and we've reached its end,
		   set the EOC flag to make sure that we don't go any further */
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
			envelopeInfoPtr->segmentSize <= 0 )
			{
			status = processEOC( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			const int blockBufferBToC = bytesToCopy - quantizedBytesToCopy;

			/* Copy any remainder (the difference between the amount to copy
			   and the blocksize-quantized amount) into the block buffer */
			if( blockBufferBToC > 0 )
				memcpy( envelopeInfoPtr->blockBuffer, buffer + quantizedBytesToCopy,
						blockBufferBToC );
			envelopeInfoPtr->blockBufferPos = blockBufferBToC;
			}

		return( bytesToCopy );
		}

	/* It's unencrypted or encrypted with a stream cipher, just copy over as
	   much of the segment as we can and decrypt it if necessary */
	memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos, buffer,
			bytesToCopy );
	envelopeInfoPtr->bufPos += bytesToCopy;
	if( envelopeInfoPtr->segmentSize != CRYPT_UNUSED )
		envelopeInfoPtr->segmentSize -= bytesToCopy;
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		status = krnlSendMessage( envelopeInfoPtr->iCryptContext, 
								  IMESSAGE_CTX_DECRYPT, bufPtr, 
								  bytesToCopy );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If the payload has a definite length and we've reached its end, set
	   the EOC flag to make sure that we don't go any further */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
		envelopeInfoPtr->segmentSize <= 0 )
		{
		status = processEOC( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( bytesToCopy );
	}

/* Copy data into the de-enveloping envelope.  Returns the number of bytes
   copied */

static int copyToDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, 
							 const BYTE *buffer, const int length )
	{
	BYTE *bufPtr = ( BYTE * ) buffer;
	int currentLength = length, bytesCopied;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );
	assert( envelopeInfoPtr->bufPos >=0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );

	/* If we're trying to copy into a full buffer, return a count of 0 bytes
	   (the calling routine may convert this to an overflow error if
	   necessary) */
	if( envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
		return( 0 );

	/* If we're verifying a detached signature, just hash the data and exit.
	   We don't have to check for problems with the context at this point
	   since they'll be detected when we complete the hashing, and we don't 
	   have to check whether hashing is active or not since it'll always be 
	   active for detached data, which is hashed and discarded */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		{
		ACTION_LIST *hashActionPtr;

		assert( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE );
		assert( envelopeInfoPtr->actionList != NULL );

		for( hashActionPtr = envelopeInfoPtr->actionList;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH; 
			 hashActionPtr = hashActionPtr->next )
			krnlSendMessage( hashActionPtr->iCryptHandle, IMESSAGE_CTX_HASH, 
							 ( void * ) buffer, currentLength );
		return( currentLength );
		}

	/* Keep processing data until either we run out of input or we can't copy
	   in any more data.  The code sequence within this loop acts as a simple
	   FSM so that if we exit at any point then the next call to this
	   function will resume where we left off */
	do
		{
		int segmentCount, status;

		/* If there's no segment information currently available, we need to
		   process a segment header before we can handle any data.  The use 
		   of a loop is necessary to handle some broken implementations that
		   emit zero-length sub-segments.  We limit the segment count to 10
		   sub-segments to make sure that we don't spend forever trying to 
		   process extremely broken data */
		for( segmentCount = 0; \
			 segmentCount < 10 && envelopeInfoPtr->segmentSize <= 0; \
			 segmentCount++ )
			{
			status = getNextSegment( envelopeInfoPtr, bufPtr, currentLength );
			if( status == OK_SPECIAL )
				/* We got the length via some other mechanism because it's a 
				   definite-length or non-segmenting encoding, no input was
				   consumed and we can exit */
				break;
			if( cryptStatusError( status ) )
				return( status );
			bufPtr += status;
			currentLength -= status;

			/* If we've reached the EOC or consumed all of the input data, 
			   exit */
			if( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) || \
				currentLength <= 0 )
				return( length - currentLength );
			}
		if( segmentCount >= 10 )
			/* We've processed ten consecutive sub-segments in a row, there's 
			   something wrong with the input data */
			return( CRYPT_ERROR_BADDATA );

		/* Copy the data into the envelope, decrypting it as we go if 
		   necessary */
		bytesCopied = copyData( envelopeInfoPtr, bufPtr, currentLength );
		if( cryptStatusError( bytesCopied ) )
			return( bytesCopied );
		bufPtr += bytesCopied;
		currentLength -= bytesCopied;

		/* Sanity check to catch copying errors */
		assert( envelopeInfoPtr->bufPos >= 0 && \
				envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
		assert( currentLength >= 0 );
		assert( ( envelopeInfoPtr->segmentSize >= 0 ) || \
				( ( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT ) && \
				  ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) && \
				  ( envelopeInfoPtr->segmentSize == CRYPT_UNUSED ) ) );
		}
	while( currentLength > 0 && bytesCopied > 0 );

	return( length - currentLength );
	}

/****************************************************************************
*																			*
*								Copy from Envelope							*
*																			*
****************************************************************************/

/* Copy data from the envelope.  Returns the number of bytes copied */

static int copyFromDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
							   int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	const BOOLEAN isLookaheadRead = ( length < 0 ) ? TRUE : FALSE;
	int bytesToCopy, bytesCopied, remainder;
	int oobBytesCopied = 0;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( envelopeInfoPtr->oobBufPos >= 0 && \
			envelopeInfoPtr->oobBufPos <= OOB_BUFFER_SIZE );

	/* Remember how much data we need to copy.  A negative length specifies 
	   that this is a speculative/lookahead read, so we turn it into a 
	   positive value if necessary */
	bytesToCopy = length = ( length < 0 ) ? -length : length;
	if( bytesToCopy < 0 )
		{
		/* Safety checks, also covers some later operations like the OOB 
		   copy */
		assert( NOTREACHED );
		return( CRYPT_ERROR_BADDATA );
		}
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );

	/* If we're verifying a detached sig, the data is communicated out-of-
	   band so there's nothing to copy out */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		return( 0 );

	/* If there's buffered out-of-band data from a lookahead read present, 
	   insert it into the output stream */
	if( envelopeInfoPtr->oobBufPos > 0 )
		{
		oobBytesCopied = min( bytesToCopy, envelopeInfoPtr->oobBufPos );
		memcpy( buffer, envelopeInfoPtr->oobBuffer, oobBytesCopied );
		if( !isLookaheadRead )
			{
			/* If we moved the data out of the OOB buffer, adjust the OOB 
			   buffer contents */
			if( envelopeInfoPtr->oobBufPos > oobBytesCopied )
				memmove( envelopeInfoPtr->oobBuffer, 
						 envelopeInfoPtr->oobBuffer + oobBytesCopied,
						 envelopeInfoPtr->oobBufPos - oobBytesCopied );
			envelopeInfoPtr->oobBufPos -= oobBytesCopied;
			}
		bytesToCopy -= oobBytesCopied;
		length -= oobBytesCopied;
		buffer += oobBytesCopied;
		if( bytesToCopy <= 0 )
			return( oobBytesCopied );
		}

	/* If we're using compression, expand the data from the buffer to the
	   output via the zStream */
#ifdef USE_COMPRESSION
	if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
		{
		const int bytesIn = \
			( envelopeInfoPtr->dataLeft > 0 && \
			  envelopeInfoPtr->dataLeft < envelopeInfoPtr->bufPos ) ? \
			envelopeInfoPtr->dataLeft : envelopeInfoPtr->bufPos;
		int status;

		/* Decompress the data into the output buffer.  Note that we use the
		   length value to determine the length of the output rather than
		   bytesToCopy since the ratio of bytes in the buffer to bytes of
		   output isn't 1:1 as it is for other content types.
		   
		   When using PGP 2.x-compatible decompression, we have to allow a
		   return status of Z_BUF_ERROR because it uses a compression format
		   from a pre-release version of InfoZip that doesn't include 
		   header or trailer information, so the decompression code can't
		   definitely tell that it's reached the end of its input data but
		   can only report that it can't go any further.
		
		   We can also get a Z_BUF_ERROR for some types of data corruption, 
		   for example if we're flushing out data still present in the 
		   zstream (avail_in == 0) and there's a problem with the data, 
		   which the zlib code reports as a buffer error since it expects 
		   more input but there's none available.  In this case we report it 
		   as an underflow, which isn't always accurate but is more useful 
		   than the generic CRYPT_ERROR_FAILED */
		envelopeInfoPtr->zStream.next_in = bufPtr;
		envelopeInfoPtr->zStream.avail_in = bytesIn;
		envelopeInfoPtr->zStream.next_out = buffer;
		envelopeInfoPtr->zStream.avail_out = length;
		status = inflate( &envelopeInfoPtr->zStream, Z_SYNC_FLUSH );
		if( status != Z_OK && status != Z_STREAM_END && \
			!( status == Z_BUF_ERROR && \
			   envelopeInfoPtr->type == CRYPT_FORMAT_PGP ) )
			{
			assert( status != Z_STREAM_ERROR );	/* Parameter error */
			return( ( status == Z_DATA_ERROR ) ? CRYPT_ERROR_BADDATA : \
					( status == Z_MEM_ERROR ) ? CRYPT_ERROR_MEMORY : \
					( status == Z_BUF_ERROR ) ? CRYPT_ERROR_UNDERFLOW : \
					CRYPT_ERROR_FAILED );
			}

		/* Adjust the status information based on the data copied from the
		   buffer into the zStream (bytesCopied) and the data flushed from
		   the zStream to the output (bytesToCopy) */
		bytesCopied = bytesIn - envelopeInfoPtr->zStream.avail_in;
		bytesToCopy = length - envelopeInfoPtr->zStream.avail_out;
		assert( bytesCopied >= 0 && bytesToCopy >= 0 );

		/* If we consumed all of the input and there's extra data left after
		   the end of the data stream, it's EOC information.  Mark that as 
		   consumed as well */
		if( envelopeInfoPtr->zStream.avail_in <= 0 && \
			envelopeInfoPtr->dataLeft > 0 && \
			envelopeInfoPtr->dataLeft < envelopeInfoPtr->bufPos )
			{
			if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP && \
				( !( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) || \
				  ( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft != 2 ) ) )
				{
				/* We should only have the EOC octets present at this 
				   point */
				assert( NOTREACHED );
				return( CRYPT_ERROR_BADDATA );
				}
			envelopeInfoPtr->dataLeft = envelopeInfoPtr->bufPos;
			}

		/* If we're doing a lookahead read, we can't just copy the data out
		   as we would for any other content type because we can't undo the
		   decompression step, so we remember the output data in a local 
		   buffer and insert it into the output stream on the next read */
		if( isLookaheadRead )
			{
			assert( envelopeInfoPtr->oobBufPos + length <= OOB_BUFFER_SIZE );
			memcpy( envelopeInfoPtr->oobBuffer + envelopeInfoPtr->oobBufPos,
					buffer, length );
			envelopeInfoPtr->oobBufPos += length;
			}
		}
	else
#endif /* USE_COMPRESSION */
		{
		ACTION_LIST *hashActionPtr;

		/* Copy out as much of the data as we can, making sure that we don't 
		   overrun into any following data */
		if( bytesToCopy > envelopeInfoPtr->bufPos )
			bytesToCopy = envelopeInfoPtr->bufPos;
		if( envelopeInfoPtr->dataLeft > 0 && \
			bytesToCopy > envelopeInfoPtr->dataLeft )
			bytesToCopy = envelopeInfoPtr->dataLeft;
		if( bytesToCopy < 0 )
			{
			/* Safety check */
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
			}

		/* If we're using a block encryption mode and we haven't seen the 
		   end-of-contents yet and there's no data waiting in the block 
		   buffer (which would mean that there's more data to come), we 
		   can't copy out the last block because it might contain padding */
		if( envelopeInfoPtr->blockSize > 1 && \
			!( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
			envelopeInfoPtr->blockBufferPos > 0 )
			{
			bytesToCopy -= envelopeInfoPtr->blockSize;
			if( bytesToCopy <= 0 )
				return( 0 );
			}

		/* If we've seen the end-of-contents octets and there's no payload 
		   left to copy out, or if we've ended up with nothing to copy (e.g. 
		   due to blocking requirements), exit */
		if( ( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
			  envelopeInfoPtr->dataLeft <= 0 ) || \
			bytesToCopy <= 0 )
			return( oobBytesCopied );
		assert( bytesToCopy > 0 );

		/* If we're doing a lookahead read, just copy the data out without 
		   adjusting the read-data values */
		if( isLookaheadRead )
			{
			memcpy( buffer, bufPtr, bytesToCopy );
			return( bytesToCopy );
			}

		/* Hash the payload data if necessary.  We don't have to check for
		   problems with the context at this point since they'll be detected
		   when we complete the hashing */
		if( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE )
			for( hashActionPtr = envelopeInfoPtr->actionList;
				 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH; 
				 hashActionPtr = hashActionPtr->next )
				krnlSendMessage( hashActionPtr->iCryptHandle,
								 IMESSAGE_CTX_HASH, bufPtr, bytesToCopy );

		/* We're not using compression, copy the data across directly */
		memcpy( buffer, bufPtr, bytesToCopy );
		bytesCopied = bytesToCopy;
		}

	/* Safety check */
	if( envelopeInfoPtr->bufPos - bytesCopied < 0 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Move any remaining data down to the start of the buffer  */
	remainder = envelopeInfoPtr->bufPos - bytesCopied;
	if( remainder > 0 && bytesCopied > 0 )
		memmove( bufPtr, bufPtr + bytesCopied, remainder );
	envelopeInfoPtr->bufPos = remainder;

	/* If there's data following the payload, adjust the end-of-payload
	   pointer to reflect the data that we've just copied out */
	if( envelopeInfoPtr->dataLeft > 0 && bytesCopied > 0 )
		envelopeInfoPtr->dataLeft -= bytesCopied;
	assert( envelopeInfoPtr->dataLeft >= 0 );

	return( oobBytesCopied + bytesToCopy );
	}

/* Synchronise the deenveloping data stream */

static int syncDeenvelopeData( ENVELOPE_INFO *envelopeInfoPtr,
							   STREAM *stream )
	{
	const int dataStartPos = stell( stream );
	const int oldBufPos = envelopeInfoPtr->bufPos;
	const int bytesLeft = sMemDataLeft( stream );
	int bytesCopied;

	/* After the envelope header has been processed, what's left is payload
	   data that requires special processing because of segmenting and
	   decryption and hashing requirements, so we feed it in via a
	   copyToDeenvelope() of the data in the buffer.  This is a rather ugly
	   hack, but it works because we're moving data backwards in the buffer 
	   so there shouldn't be any problems for the rare instances where the 
	   data overlaps.  In the worst case (PKCS #7 short definite-length OCTET
	   STRING) we only consume two bytes, the tag and one-byte length, but 
	   since we're using memmove this shouldn't be a problem.

	   Since we're in effect restarting from the payload data, we reset
	   everything that counts to point back to the start of the buffer where
	   we'll be moving the payload data.  We don't have to worry about the
	   copyToDeenvelope() overflowing the envelope since the source is the
	   envelope buffer so the data must fit within the envelope */
	envelopeInfoPtr->bufPos = 0;
	if( bytesLeft <= 0 )
		{
		/* Handle the special case of the data ending at exactly this point */
		sseek( stream, 0 );
		return( CRYPT_ERROR_UNDERFLOW );
		}
	sMemDisconnect( stream );
	sMemConnect( stream, envelopeInfoPtr->buffer, bytesLeft );
	bytesCopied = envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr,
							envelopeInfoPtr->buffer + dataStartPos, bytesLeft );
	if( cryptStatusError( bytesCopied ) )
		{
		/* Undo the buffer position reset.  This isn't 100% effective if 
		   there are multiple segments present and we hit an error after 
		   we've copied down enough data to overwrite what's at the start, 
		   but in most cases it allows us to undo the copyToEnvelope() - if 
		   the data is corrupted we won't get any further anyway */
		envelopeInfoPtr->bufPos = oldBufPos;
		return( bytesCopied );
		}
	assert( bytesCopied >= 0 );

	/* If we've reached the end of the payload, remember where the payload
	   ends.  If there's anything that followed the payload, we need to move
	   it down to the end of the decoded payload data, since
	   copyToDeenvelope() stops copying as soon as it hits the end-of-
	   contents octets */
	if( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
		bytesCopied < bytesLeft )
		{
		const int bytesToCopy = bytesLeft - bytesCopied;

		memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				envelopeInfoPtr->buffer + bytesCopied + dataStartPos,
				bytesToCopy );
		envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + bytesToCopy;
		}

	return( CRYPT_OK );
	}

/* Process additional out-of-band data that doesn't get copied into/out of
   the de-enveloping envelope */

static int processExtraData( ENVELOPE_INFO *envelopeInfoPtr, 
							 const void *buffer, const int length )
	{
	ACTION_LIST *hashActionPtr;
	int status;

	/* If the hash value was supplied externally (which means there's 
	   nothing for us to hash, since it's already been done by the caller),
	   there won't be any hash actions active and we can return immediately */
	if( !( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE ) )
		return( length ? CRYPT_ERROR_BADDATA : CRYPT_OK );

	/* The enveloping code uses a null buffer to signify a flush, but the 
	   lower-level encryption actions don't allow a null buffer.  If we're
	   given a null buffer we substitute an empty (non-null) one */
	if( buffer == NULL )
		buffer = "";

	/* Hash the data or wrap up the hashing as appropriate */
	for( hashActionPtr = envelopeInfoPtr->actionList;
		 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH; 
		 hashActionPtr = hashActionPtr->next )
		{
		status = krnlSendMessage( hashActionPtr->iCryptHandle, 
								  IMESSAGE_CTX_HASH, ( void * ) buffer, 
								  length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we've finished the hashing, clear the hashing-active flag to 
	   prevent data from being hashed again if it's processed by other 
	   code such as copyFromDeenvelope() */
	if( length <= 0 )
		envelopeInfoPtr->dataFlags &= ~ENVDATA_HASHACTIONSACTIVE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initDeenvelopeStreaming( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	envelopeInfoPtr->copyToEnvelopeFunction = copyToDeenvelope;
	envelopeInfoPtr->copyFromEnvelopeFunction = copyFromDeenvelope;
	envelopeInfoPtr->syncDeenvelopeData = syncDeenvelopeData;
	envelopeInfoPtr->processExtraData = processExtraData;
	}
