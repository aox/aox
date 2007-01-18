/****************************************************************************
*																			*
*					  cryptlib Datagram Decoding Routines					*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
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

   Be very careful when modifying this code, the data manipulation that it
   performs is somewhat tricky */

#ifdef USE_ENVELOPES

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
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize && \
			envelopeInfoPtr->bufSize >= MIN_BUFFER_SIZE );

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
   of bytes consumed, or zero if more data is required to decode the header */

typedef enum {
	SEGMENT_NONE,			/* No segment status */
	SEGMENT_FIXEDLENGTH,	/* Fixed-length segment */
	SEGMENT_ENDOFDATA,		/* No more data to process */
	SEGMENT_LAST			/* Last possible segment status */
	} SEGMENT_STATUS;

static int getNextSegment( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
						   const int length, SEGMENT_STATUS *segmentStatus )
	{
	STREAM stream;
	long segmentLength;
	int bytesRead, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );

	/* Clear return value */
	*segmentStatus = SEGMENT_NONE;

	/* If we've already processed the entire payload, don't do anything.
	   This can happen when we're using the definite encoding form, since
	   the EOC flag is set elsewhere as soon as the entire payload has been
	   copied to the buffer */
	if( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS )
		{
		assert( envelopeInfoPtr->segmentSize <= 0 );
		*segmentStatus = SEGMENT_ENDOFDATA;
		return( OK_SPECIAL );
		}

	/* If we're using the definite encoding form, there's a single segment
	   equal in length to the entire payload */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		envelopeInfoPtr->segmentSize = envelopeInfoPtr->payloadSize;
		*segmentStatus = SEGMENT_FIXEDLENGTH;
		return( OK_SPECIAL );
		}

	/* If we're using the indefinite form but it's an envelope type that
	   doesn't segment data, the length is implicitly defined as "until we
	   run out of input" */
	if( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT )
		{
		envelopeInfoPtr->segmentSize = CRYPT_UNUSED;
		*segmentStatus = SEGMENT_FIXEDLENGTH;
		return( OK_SPECIAL );
		}

	/* If there's not enough data left to contain the header for a
	   reasonable-sized segment, tell the caller to try again with more
	   data.  For a PGP envelope a partial header is a single byte, for
	   a PKCS #7/CMS envelope it's two bytes (tag + length) but most
	   segments will be longer than 256 bytes, requiring at least three
	   bytes of tag + length data.  A reasonable tradeoff seems to be to
	   require three bytes before trying to decode the length */
	if( length < 3 )
		return( 0 );

	/* Get the sub-segment info */
	sMemConnect( &stream, buffer, length );
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		status = pgpReadPartialLength( &stream, &segmentLength );
		if( cryptStatusError( status ) )
			{
			/* If we got an OK_SPECIAL return it's just an indication that
			   we got another partial length (with other segments to
			   follow), and not an actual error */
			if( status != OK_SPECIAL )
				return( status );
			}
		else
			{
			/* We've read a length that doesn't use the indefinite-length
			   encoding, it's the last data segment, shift from indefinite
			   to definite-length mode */
			envelopeInfoPtr->dataFlags |= ENVDATA_NOSEGMENT;
			if( segmentLength > 0 )
				{
				/* If this is a packet with an MDC packet tacked on, adjust
				   the data length for the length of the MDC packet */
				if( envelopeInfoPtr->dataFlags & ENVDATA_HASATTACHEDOOB )
					{
					/* If the MDC data is larger than the length of the last
					   segment, adjust its effefctive size to zero.  This is
					   rather problematic in that if the sender chooses to
					   break the MDC packet across the partial-header
					   boundary it'll include some of the MDC data with the
					   payload, but there's no easy solution to this, the
					   problem likes in the PGP spec for allowing a length
					   encoding form that makes one-pass processing
					   impossible.  Hopefully implementations will realise
					   this and never break the MDC data over a partial-
					   length header */
					segmentLength -= PGP_MDC_PACKET_SIZE;
					if( segmentLength < 0 )
						segmentLength = 0;
					}

				/* Convert the last segment into a definite-length segment.
				   When we return the calling code will immediately call
				   getNextSegment() again since we've consumed some input,
				   at that point the definite-length payload size will be
				   set and the call will return with OK_SPECIAL to tell the
				   caller that there's no more length information to fetch */
				envelopeInfoPtr->payloadSize = segmentLength;
				segmentLength = 0;
				}
			else
				/* It's a terminating zero-length segment, wrap up the
				   processing */
				status = processEOC( envelopeInfoPtr );
			}
		}
	else
		{
		/* checkEOC() can also return an error code alongside the TRUE/FALSE
		   indication, in which case we drop through to the error-handler
		   that follows this code block without doing anything else */
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
			/* If we've seen the EOC, wrap up the processing.  Any other
			   value for the return status is an error code */
			if( status == TRUE )
				{
				status = processEOC( envelopeInfoPtr );
				segmentLength = 0;
				}
		}
	bytesRead = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		/* If we got an underflow error, record it as zero bytes read so
		   that we'll retry the read next time */
		if( status == CRYPT_ERROR_UNDERFLOW )
			return( 0 );
		return( status );
		}

	/* We got the length, return the information to the caller */
	envelopeInfoPtr->segmentSize = segmentLength;
	return( bytesRead );
	}

/****************************************************************************
*																			*
*								Copy to Envelope							*
*																			*
****************************************************************************/

/* Copy encrypted data blocks into the envelope buffer, with any overflow
   held in the block buffer.  Only complete blocks are copied into the main
   envelope buffer, if there's not enough data present for a complete block
   it's temporarily held in the block buffer (see the diagram for copyData()
   below for more details) */

static int copyEncryptedDataBlocks( ENVELOPE_INFO *envelopeInfoPtr,
									const BYTE *buffer, const int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	int bytesCopied = 0, quantizedBytesToCopy, blockBufferBToC, status;

	assert( length > 0 );

	/* If the new data will fit entirely into the block buffer, copy it in
	   now and return */
	if( length < envelopeInfoPtr->blockSize - envelopeInfoPtr->blockBufferPos )
		{
		memcpy( envelopeInfoPtr->blockBuffer + envelopeInfoPtr->blockBufferPos,
				buffer, length );
		envelopeInfoPtr->blockBufferPos += length;

		/* Adjust the segment size based on what we've consumed */
		envelopeInfoPtr->segmentSize -= length;

		return( length );
		}

	/* If there isn't room in the main buffer for even one more block, exit
	   without doing anything.  This leads to slightly anomalous behaviour
	   where, with no room for a complete block in the main buffer, copying
	   in a data length smaller than the block buffer will lead to the data
	   being absorbed by the block buffer due to the previous section of
	   code, but copying in a length larger than the block buffer will
	   result in no data at all being absorbed, even if there's still room
	   in the block buffer */
	if( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos < \
		envelopeInfoPtr->blockSize )
		return( 0 );	/* No room for even one more block */

	/* There's room for at least one more block in the buffer.  First, if
	   there are leftover bytes in the block buffer, move them into the main
	   buffer */
	if( envelopeInfoPtr->blockBufferPos > 0 )
		{
		memcpy( bufPtr, envelopeInfoPtr->blockBuffer,
				envelopeInfoPtr->blockBufferPos );
		bytesCopied = envelopeInfoPtr->blockBufferPos;
		}
	envelopeInfoPtr->blockBufferPos = 0;

	/* Determine how many bytes we can copy into the buffer to fill it to
	   the nearest available block size */
	quantizedBytesToCopy = ( length + bytesCopied ) & \
						   envelopeInfoPtr->blockSizeMask;
	quantizedBytesToCopy -= bytesCopied;
	if( length < 0 || quantizedBytesToCopy <= 0 || \
		quantizedBytesToCopy > length )
		{
		/* Sanity check */
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}
	assert( !( ( bytesCopied + quantizedBytesToCopy ) & \
			   ( envelopeInfoPtr->blockSize - 1 ) ) );

	/* Now copy across a number of bytes which is a multiple of the block
	   size and decrypt them.  Note that we have to use memmove() rather
	   than memcpy() because if we're sync'ing data in the buffer we're
	   doing a copy within the buffer rather than copying in data from
	   an external source */
	memmove( bufPtr + bytesCopied, buffer, quantizedBytesToCopy );
	envelopeInfoPtr->bufPos += bytesCopied + quantizedBytesToCopy;
	envelopeInfoPtr->segmentSize -= length;
	status = krnlSendMessage( envelopeInfoPtr->iCryptContext,
							  IMESSAGE_CTX_DECRYPT, bufPtr,
							  bytesCopied + quantizedBytesToCopy );
	if( cryptStatusError( status ) )
		return( status );
	assert( envelopeInfoPtr->bufPos >=0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( envelopeInfoPtr->segmentSize >= 0 );

	/* If the payload has a definite length and we've reached its end, set
	   the EOC flag to make sure that we don't go any further */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
		envelopeInfoPtr->segmentSize <= 0 )
		{
		status = processEOC( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		return( length );
		}

	/* Copy any remainder (the difference between the amount to copy and the
	   blocksize-quantized amount) into the block buffer */
	blockBufferBToC = length - quantizedBytesToCopy;
	assert( blockBufferBToC >=0 && \
			blockBufferBToC <= envelopeInfoPtr->bufSize );
	if( blockBufferBToC > 0 )
		memcpy( envelopeInfoPtr->blockBuffer, buffer + quantizedBytesToCopy,
				blockBufferBToC );
	envelopeInfoPtr->blockBufferPos = blockBufferBToC;

	return( length );
	}

/* Copy possibly encrypted data into the envelope with special handling for
   block encryption modes.  Returns the number of bytes copied.  The buffers
   work as follows:

						  bPos			  bSize
							|				|
							v				v
	+-----------------------+---------------+
	|		|		|		|		|		|	Main buffer
	+-----------------------+---------------+

							+-------+
							|///|	|			Overflow block buffer
							+-------+
								^	^
								| bBufSize
							 bBufPos

    The main buffer only contains data amounts quantised to the encryption
	block size.  Any additional data is copied into the block buffer, a
	staging buffer used to accumulate data until it can be transferred to
	the main buffer for decryption */

static int copyData( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
					 const int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	int bytesToCopy = length, bytesLeft, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize || \
			envelopeInfoPtr->bufSize >= MIN_BUFFER_SIZE );
	assert( ( envelopeInfoPtr->blockSize == 0 ) || \
			( envelopeInfoPtr->blockBufferPos >= 0 && \
			  envelopeInfoPtr->blockBufferPos < envelopeInfoPtr->blockSize ) );

	/* Figure out how much we can copy across.  First we calculate the
	   minimum of the amount of data passed in and the amount remaining in
	   the current segment */
	if( envelopeInfoPtr->segmentSize != CRYPT_UNUSED && \
		envelopeInfoPtr->segmentSize < bytesToCopy )
		bytesToCopy = envelopeInfoPtr->segmentSize;

	/* Now we check to see if this is affected by the total free space
	   remaining in the buffer.  If we're processing data blocks we can have
	   two cases, one in which the limit is the amount of buffer space
	   available and the other in which the limit is the amount of data
	   available.  If the limit is set by the available data, we don't have
	   to worry about flushing extra data out of the block buffer into the
	   main buffer, but if the limit is set by the available buffer space we
	   have to reduce the amount that we can copy in based on any extra data
	   that will be flushed out of the block buffer.

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
	   will only cause confusion when data appears to vanish when copied in.

	   In the following length calculation, the block buffer content is
	   counted as part of the total content in order to implement the second
	   buffer-filling strategy */
	bytesLeft = envelopeInfoPtr->bufSize - \
				( envelopeInfoPtr->bufPos + envelopeInfoPtr->blockBufferPos );
	if( bytesLeft < bytesToCopy )
		bytesToCopy = bytesLeft;
	if( bytesToCopy <= 0 || envelopeInfoPtr->blockBufferPos < 0 ||
		envelopeInfoPtr->blockBufferPos > envelopeInfoPtr->blockSize )
		{
		/* Sanity check that verifies segmentSize, length, bufPos, and
		   blockBufferPos before we start into the following code */
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* If its a block encryption mode we need to provide special handling for
	   odd data lengths that don't match the block size */
	if( envelopeInfoPtr->blockSize > 1 )
		return( copyEncryptedDataBlocks( envelopeInfoPtr, buffer,
										 bytesToCopy ) );

	/* It's unencrypted or encrypted with a stream cipher, just copy over as
	   much of the segment as we can and decrypt it if necessary.  We use
	   memmove() for the same reason as given above */
	memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos, buffer,
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
	int currentLength = length, bytesCopied, iterationCount;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length > 0 );
	assert( isReadPtr( buffer, length ) );

	/* Sanity-check the envelope state */
	if( envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize || \
		envelopeInfoPtr->bufSize < MIN_BUFFER_SIZE || \
		( envelopeInfoPtr->blockSize > 0 && \
		  ( envelopeInfoPtr->blockBufferPos < 0 || \
			envelopeInfoPtr->blockBufferPos >= envelopeInfoPtr->blockSize ) ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* If we're trying to copy data into a full buffer, return a count of 0
	   bytes (the calling routine may convert this to an overflow error if
	   necessary) */
	if( envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
		return( 0 );

	/* If we're verifying a detached signature, just hash the data and exit.
	   We don't have to check whether hashing is active or not since it'll
	   always be active for detached data, which is hashed and discarded */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		{
		ACTION_LIST *hashActionPtr;
		int status;

		assert( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE );
		assert( envelopeInfoPtr->actionList != NULL );

		iterationCount = 0;
		for( hashActionPtr = envelopeInfoPtr->actionList;
			 hashActionPtr != NULL && \
				hashActionPtr->action == ACTION_HASH && \
				iterationCount++ < FAILSAFE_ITERATIONS_MED;
			 hashActionPtr = hashActionPtr->next )
			{
			status = krnlSendMessage( hashActionPtr->iCryptHandle,
									  IMESSAGE_CTX_HASH,
									  ( void * ) buffer, currentLength );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_MED )
			retIntError();
		return( currentLength );
		}

	/* Keep processing data until either we run out of input or we can't copy
	   in any more data.  The code sequence within this loop acts as a simple
	   FSM so that if we exit at any point then the next call to this
	   function will resume where we left off */
	iterationCount = 0;
	do
		{
		int segmentCount, status;

		/* If there's no segment information currently available, we need to
		   process a segment header before we can handle any data.  The use
		   of a loop is necessary to handle some broken implementations that
		   emit zero-length sub-segments (as a corollary, it also helps
		   avoid a pile of special-case code to manage PGP's strange way of
		   handling the last segment in indefinite-length encodings).  We
		   limit the segment count to 10 sub-segments to make sure that we
		   don't spend forever trying to process extremely broken data */
		for( segmentCount = 0; \
			 segmentCount < 10 && envelopeInfoPtr->segmentSize <= 0; \
			 segmentCount++ )
			{
			SEGMENT_STATUS segmentStatus;
			int bytesRead;

			bytesRead = status = \
				getNextSegment( envelopeInfoPtr, bufPtr, currentLength,
								&segmentStatus );
			if( status == OK_SPECIAL )
				{
				/* If we've reached the end of the payload, we're done */
				if( segmentStatus == SEGMENT_ENDOFDATA )
					return( length - currentLength );

				/* We got the length via some other mechanism because it's a
				   definite-length or non-segmenting encoding, no input was
				   consumed and we can exit */
				assert( segmentStatus == SEGMENT_FIXEDLENGTH );
				break;
				}
			if( cryptStatusError( status ) )
				return( status );
			if( bytesRead <= 0 )
				/* We don't have enough input data left to read the
				   information for the next segment, exit */
				return( length - currentLength );
			bufPtr += bytesRead;
			currentLength -= bytesRead;

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
		assert( currentLength > 0 );

		/* Copy the data into the envelope, decrypting it as we go if
		   necessary */
		bytesCopied = copyData( envelopeInfoPtr, bufPtr, currentLength );
		if( cryptStatusError( bytesCopied ) )
			return( bytesCopied );
		bufPtr += bytesCopied;
		currentLength -= bytesCopied;

		assert( envelopeInfoPtr->bufPos >= 0 && \
				envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize && \
				envelopeInfoPtr->bufSize >= MIN_BUFFER_SIZE );
		assert( currentLength >= 0 );
		assert( ( envelopeInfoPtr->segmentSize >= 0 ) || \
				( ( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT ) && \
				  ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) && \
				  ( envelopeInfoPtr->segmentSize == CRYPT_UNUSED ) ) );
		}
	while( currentLength > 0 && bytesCopied > 0 && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* Make sure that we've left everything in a valid state */
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize && \
			envelopeInfoPtr->bufSize >= MIN_BUFFER_SIZE );
	assert( ( envelopeInfoPtr->blockSize == 0 ) || \
			( envelopeInfoPtr->blockBufferPos >= 0 && \
			  envelopeInfoPtr->blockBufferPos < envelopeInfoPtr->blockSize ) );

	return( length - currentLength );
	}

/****************************************************************************
*																			*
*								Copy from Envelope							*
*																			*
****************************************************************************/

/* Copy data from the envelope.  Returns the number of bytes copied */

static int copyFromDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
							   const int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	const BOOLEAN isLookaheadRead = ( length < 0 ) ? TRUE : FALSE;
	int bytesToCopy, bytesCopied, oobBytesCopied = 0, remainder;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Sanity-check the envelope state */
	if( envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize || \
		envelopeInfoPtr->bufSize < MIN_BUFFER_SIZE || \
		envelopeInfoPtr->oobBufPos < 0 || \
		envelopeInfoPtr->oobBufPos > OOB_BUFFER_SIZE || \
		( envelopeInfoPtr->blockSize > 0 && \
		  ( envelopeInfoPtr->blockBufferPos < 0 || \
			envelopeInfoPtr->blockBufferPos >= envelopeInfoPtr->blockSize ) ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* Remember how much data we need to copy.  A negative length specifies
	   that this is a speculative/lookahead read, so we turn it into a
	   positive value if necessary */
	bytesToCopy = ( length < 0 ) ? -length : length;
	if( bytesToCopy <= 0 )
		{
		/* Sanity check */
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}
	assert( isReadPtr( buffer, bytesToCopy ) );
	assert( !isLookaheadRead || \
			( bytesToCopy > 0 && bytesToCopy <= OOB_BUFFER_SIZE ) );

	/* If we're verifying a detached sig, the data is communicated out-of-
	   band so there's nothing to copy out */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		return( 0 );

	/* If there's buffered out-of-band data from a lookahead read present,
	   insert it into the output stream */
	if( envelopeInfoPtr->oobBufPos > 0 )
		{
		oobBytesCopied = min( bytesToCopy, envelopeInfoPtr->oobBufPos );
		assert( oobBytesCopied > 0 );
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
		buffer += oobBytesCopied;
		if( bytesToCopy <= 0 )
			return( oobBytesCopied );
		}

	/* If we're using compression, expand the data from the buffer to the
	   output via the zStream */
#ifdef USE_COMPRESSION
	if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
		{
		const int inLength = bytesToCopy;
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

		   We can also get a Z_BUF_ERROR for some types of (non-fatal) error
		   situations, for example if we're flushing out data still present
		   in the zstream (avail_in == 0) and there's a problem such as the
		   compressor needing more data but there's none available, the zlib
		   code will report it as a Z_BUF_ERROR.  In this case we convert it
		   into a (recoverable) underflow error, which isn't always accurate
		   but is more useful than the generic CRYPT_ERROR_FAILED */
		envelopeInfoPtr->zStream.next_in = bufPtr;
		envelopeInfoPtr->zStream.avail_in = bytesIn;
		envelopeInfoPtr->zStream.next_out = buffer;
		envelopeInfoPtr->zStream.avail_out = bytesToCopy;
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
		bytesToCopy -= envelopeInfoPtr->zStream.avail_out;
		assert( bytesCopied >= 0 && bytesToCopy >= 0 );

		/* If we consumed all of the input and there's extra data left after
		   the end of the data stream, it's EOC information, mark that as
		   consumed as well */
		if( envelopeInfoPtr->zStream.avail_in <= 0 && \
			envelopeInfoPtr->dataLeft > 0 && \
			envelopeInfoPtr->dataLeft < envelopeInfoPtr->bufPos )
			{
			if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP && \
				( !( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) || \
				  ( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft != 2 ) ) )
				{
				/* We should only have the EOC octets { 0x00 0x00 } present
				   at this point */
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			envelopeInfoPtr->dataLeft = envelopeInfoPtr->bufPos;
			}

		/* If we're doing a lookahead read, we can't just copy the data out
		   as we would for any other content type because we can't undo the
		   decompression step, so we remember the output data in a local
		   buffer and insert it into the output stream on the next read */
		if( isLookaheadRead )
			{
			assert( envelopeInfoPtr->oobBufPos + inLength <= OOB_BUFFER_SIZE );
			memcpy( envelopeInfoPtr->oobBuffer + envelopeInfoPtr->oobBufPos,
					buffer, inLength );
			envelopeInfoPtr->oobBufPos += inLength;
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
			/* Sanity check */
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}

		/* If we're using a block encryption mode and we haven't seen the
		   end-of-contents yet and there's no data waiting in the block
		   buffer (which would mean that there's more data to come), we
		   can't copy out the last block because it might contain padding,
		   so we decrease the effective data amount by one block's worth */
		if( envelopeInfoPtr->blockSize > 1 && \
			!( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
			envelopeInfoPtr->blockBufferPos > 0 )
			bytesToCopy -= envelopeInfoPtr->blockSize;

		/* If we've ended up with nothing to copy (e.g. due to blocking
		   requirements), exit */
		if( bytesToCopy <= 0 )
			return( oobBytesCopied );
		assert( bytesToCopy > 0 );

		/* If we've seen the end-of-contents octets and there's no payload
		   left to copy out, exit */
		if( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
			envelopeInfoPtr->dataLeft <= 0 )
			return( oobBytesCopied );

		/* If we're doing a lookahead read, just copy the data out without
		   adjusting the read-data values */
		if( isLookaheadRead )
			{
			memcpy( buffer, bufPtr, bytesToCopy );
			return( bytesToCopy );
			}

		/* Hash the payload data if necessary */
		if( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE )
			{
			int iterationCount = 0;
			
			for( hashActionPtr = envelopeInfoPtr->actionList;
				 hashActionPtr != NULL && \
					hashActionPtr->action == ACTION_HASH && \
					iterationCount++ < FAILSAFE_ITERATIONS_MED;
				 hashActionPtr = hashActionPtr->next )
				{
				int status;

				status = krnlSendMessage( hashActionPtr->iCryptHandle,
										  IMESSAGE_CTX_HASH, bufPtr,
										  bytesToCopy );
				if( cryptStatusError( status ) )
					return( status );
				}
			if( iterationCount >= FAILSAFE_ITERATIONS_MED )
				retIntError();
			}

		/* We're not using compression, copy the data across directly */
		memcpy( buffer, bufPtr, bytesToCopy );
		bytesCopied = bytesToCopy;
		}

	/* Sanity check */
	if( envelopeInfoPtr->bufPos - bytesCopied < 0 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
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

/****************************************************************************
*																			*
*						Extra Data Management Functions						*
*																			*
****************************************************************************/

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
	   data overlaps.  In the worst case (PKCS #7/CMS short definite-length
	   OCTET STRING) we only consume two bytes, the tag and one-byte length,
	   but since we're using memmove() in copyData() this shouldn't be a
	   problem.

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
	   contents octets.  We use memmove() rather than memcpy() since we're
	   copying to/from the same buffer */
	if( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) && \
		bytesCopied < bytesLeft )
		{
		const int bytesToCopy = bytesLeft - bytesCopied;

		assert( bytesToCopy > 0 );
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
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
	int iterationCount = 0;

	assert( length >= 0 );

	/* If the hash value was supplied externally (which means that there's
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
		 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH && \
			iterationCount++ < FAILSAFE_ITERATIONS_MED;
		 hashActionPtr = hashActionPtr->next )
		{
		int status;

		status = krnlSendMessage( hashActionPtr->iCryptHandle,
								  IMESSAGE_CTX_HASH, ( void * ) buffer,
								  length );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

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
#endif /* USE_ENVELOPES */
