/****************************************************************************
*																			*
*					  cryptlib Datatgram Encoding Routines					*
*						Copyright Peter Gutmann 1996-2003					*
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

/* Determine the quantization level and length threshold for the length
   encoding of constructed indefinite-length strings.  The length encoding
   is the actual length if <= 127, or a one-byte length-of-length followed by
   the length if > 127 */

#define TAG_SIZE					1	/* Useful symbolic define */

#if INT_MAX > 32767

#define lengthOfLength( length )	( ( length < 128 ) ? 1 : \
									  ( length < 0xFF ) ? 2 : \
									  ( length < 0xFFFF ) ? 3 : \
									  ( length < 0xFFFFFF ) ? 4 : 5 )

#define findThreshold( length )		( ( length < 128 ) ? 127 : \
									  ( length < 0xFF ) ? ( 0xFF - 1 ) : \
									  ( length < 0xFFFF ) ? ( 0xFFFF - 1 ) : \
									  ( length < 0xFFFFFF ) ? ( 0xFFFFFF - 1 ) : INT_MAX )
#else

#define lengthOfLength( length )	( ( length < 128 ) ? 1 : \
									  ( length < 0xFF ) ? 2 : 3 )

#define findThreshold( length )		( ( length < 128 ) ? 127 : \
									  ( length < 0xFF ) ? ( 0xFF - 1 ) : INT_MAX )
#endif /* 32-bit ints */

/* Begin a new segment in the buffer.  The layout is:

			tag	len		 payload
	+-------+-+---+---------------------+-------+
	|		| |	  |						|		|
	+-------+-+---+---------------------+-------+
			  ^	  ^						^
			  |	  |						|
		  sStart sDataStart			sDataEnd

   The segment starts at segmentDataStart - TAG_SIZE */

static int beginSegment( ENVELOPE_INFO *envelopeInfoPtr )
	{
	const int lLen = lengthOfLength( envelopeInfoPtr->bufSize );

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( ( envelopeInfoPtr->blockSize == 0 ) || \
			( envelopeInfoPtr->blockBufferPos >= 0 && \
			  envelopeInfoPtr->blockBufferPos < envelopeInfoPtr->blockSize ) );

	/* Make sure that there's enough room in the buffer to accommodate the 
	   start of a new segment.  In the worst case this is 6 bytes (OCTET 
	   STRING tag + 5-byte length) + 15 bytes (blockBuffer contents for a 
	   128-bit block cipher).  Although in practice we could eliminate this 
	   condition, it would require tracking a lot of state information to 
	   record which data had been encoded into the buffer and whether the 
	   blockBuffer data had been copied into the buffer, so to keep it 
	   simple we require enough room to do everything at once */
	if( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos < \
		TAG_SIZE + lLen + envelopeInfoPtr->blockBufferPos )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we're encoding data with a definite length, there's no real segment
	   boundary apart from the artificial ones created by encryption
	   blocking */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		envelopeInfoPtr->segmentStart = envelopeInfoPtr->bufPos;
	else
		{
		/* Begin a new segment after the end of the current segment.  We
		   always leave enough room for the largest allowable length field
		   because we may have a short segment at the end of the buffer which
		   is moved to the start of the buffer after data is copied out,
		   turning it into a longer segment.  For this reason we rely on the
		   completeSegment() code to get the length right and move any data
		   down as required */
		envelopeInfoPtr->buffer[ envelopeInfoPtr->bufPos ] = BER_OCTETSTRING;
		envelopeInfoPtr->segmentStart = envelopeInfoPtr->bufPos + TAG_SIZE;
		envelopeInfoPtr->bufPos += TAG_SIZE + lLen;
		}
	envelopeInfoPtr->segmentDataStart = envelopeInfoPtr->bufPos;

	/* Now copy anything left in the block buffer to the start of the new
	   segment.  We know that everything will fit because we've checked 
	   earlier on that the header and blockbuffer contents will fit into 
	   the remaining space */
	if( envelopeInfoPtr->blockBufferPos > 0 )
		{
		memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
				envelopeInfoPtr->blockBuffer, envelopeInfoPtr->blockBufferPos );
		envelopeInfoPtr->bufPos += envelopeInfoPtr->blockBufferPos;
		}
	envelopeInfoPtr->blockBufferPos = 0;

	/* We've started the new segment, mark it as incomplete */
	envelopeInfoPtr->dataFlags &= ~ENVDATA_SEGMENTCOMPLETE;

	return( CRYPT_OK );
	}

/* Complete a segment of data in the buffer.  This is incredibly complicated
   because we need to take into account the indefinite-length encoding (which
   has a variable-size length field) and the quantization to the cipher block
   size.  In particular the indefinite-length encoding means that we can 
   never encode a block with a size of 130 bytes (we get tag + length + 127 = 
   129, then tag + length-of-length + length + 128 = 131), and the same for 
   the next boundary at 256 bytes */

static BOOLEAN encodeSegmentHeader( ENVELOPE_INFO *envelopeInfoPtr,
									const BOOLEAN isEncrypted )
	{
	BYTE *segmentDataPtr = envelopeInfoPtr->buffer + \
						   envelopeInfoPtr->segmentStart;
	const int oldLLen = TAG_SIZE + ( envelopeInfoPtr->segmentDataStart - \
									 envelopeInfoPtr->segmentStart );
	int dLen = envelopeInfoPtr->bufPos - envelopeInfoPtr->segmentDataStart;
	int lLen, qTot, threshold, remainder = 0;
	BOOLEAN needsPadding = envelopeInfoPtr->dataFlags & ENVDATA_NEEDSPADDING;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( envelopeInfoPtr->segmentStart >= 0 && \
			envelopeInfoPtr->segmentStart < envelopeInfoPtr->bufPos );
	assert( envelopeInfoPtr->segmentDataStart >= \
								envelopeInfoPtr->segmentStart && \
			envelopeInfoPtr->segmentDataStart < envelopeInfoPtr->bufPos );

	/* If we're adding PKCS #5 padding, try and add one block's worth of
	   pseudo-data.  This adjusted data length is then fed into the block
	   size quantisation process, after which any odd-sized remainder is
	   ignored, and the necessary padding bytes are added to account for the
	   difference between the actual and padded size */
	if( needsPadding )
		{
		/* Check whether the padding will fit onto the end of the data.  This
		   check isn't completely accurate since the length encoding might
		   shrink by one or two bytes and allow a little extra data to be
		   squeezed in, however the extra data could cause the length
		   encoding to expand again, requiring a complex adjustment process.
		   To make things easier we ignore this possibility at the expense of
		   emitting one more segment than is necessary in a few very rare
		   cases */
		if( envelopeInfoPtr->segmentDataStart + dLen + \
			envelopeInfoPtr->blockSize < envelopeInfoPtr->bufSize )
			dLen += envelopeInfoPtr->blockSize;
		else
			needsPadding = FALSE;
		}

	/* Now that we've made any necessary adjustments to the data length,
	   determine the length of the length encoding (which may have grown or
	   shrunk since we initially calculated it when we began the segment) and
	   any combined data lengths based on it */
	lLen = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
		   TAG_SIZE + lengthOfLength( dLen ) : 0;
	qTot = lLen + dLen;

	/* Quantize and adjust the length if we're encrypting in a block mode */
	if( isEncrypted )
		{
		qTot = dLen & envelopeInfoPtr->blockSizeMask;
		threshold = findThreshold( qTot );
		if( qTot <= threshold && dLen > threshold )
			/* The block-size quantisation has moved the quantised length
			   across a length-of-length encoding boundary, adjust lLen to
			   account for this */
			lLen--;
		remainder = dLen - qTot;
		dLen = qTot;	/* Data length has now shrunk to quantised size */
		}
	assert( ( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && lLen == 0 ) || \
			( envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
			  lLen > 0 && lLen <= 6 ) );
	assert( remainder >= 0 && \
			( envelopeInfoPtr->blockSize == 0 || \
			  remainder < envelopeInfoPtr->blockSize ) );

	/* If there's not enough data present to do anything, tell the caller 
	   that we couldn't do anything */
	if( qTot <= 0 )
		return( FALSE );
	assert( dLen >= 0 );

	/* If there's a header between segments and the header length encoding 
	   has shrunk (either due to the cipher block size quantization shrinking 
	   the segment or because we've wrapped up a segment at less than the 
	   original projected length), move the data down.  The complete segment 
	   starts at segmentStart - TAG_SIZE, in the worst case the shrinking can 
	   cover several bytes if we go from a > 255 byte segment to a <= 127 
	   byte one */
	if( lLen > 0 && lLen < oldLLen )
		{
		const int delta = oldLLen - lLen;

		memmove( segmentDataPtr - TAG_SIZE + lLen,
				 segmentDataPtr - TAG_SIZE + oldLLen,
				 envelopeInfoPtr->bufPos - envelopeInfoPtr->segmentDataStart );
		envelopeInfoPtr->bufPos -= delta;
		envelopeInfoPtr->segmentDataStart -= delta;
		}
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
	assert( envelopeInfoPtr->segmentDataStart >= \
								envelopeInfoPtr->segmentStart && \
			envelopeInfoPtr->segmentDataStart + dLen <= \
								envelopeInfoPtr->bufSize );

	/* If we need to add PKCS #5 block padding, try and do so now.  Since the
	   extension of the data length to allow for padding data is performed by
	   adding one block of pseudo-data and letting the block quantisation
	   system take care of any discrepancies, we can calculate the padding
	   amount as the difference between any remainder after quantisation and
	   the block size */
	if( needsPadding )
		{
		const int padSize = envelopeInfoPtr->blockSize - remainder;
		int i;

		/* Add the block padding and set the remainder to zero, since we're
		   now at an even block boundary */
		for( i = 0; i < padSize; i++ )
			envelopeInfoPtr->buffer[ envelopeInfoPtr->bufPos + i ] = padSize;
		envelopeInfoPtr->bufPos += padSize;
		envelopeInfoPtr->dataFlags &= ~ENVDATA_NEEDSPADDING;
		remainder = 0;
		}

	/* Move any leftover bytes into the block buffer */
	if( remainder > 0 )
		{
		memcpy( envelopeInfoPtr->blockBuffer,
				envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos - \
										  remainder, remainder );
		envelopeInfoPtr->blockBufferPos = remainder;
		envelopeInfoPtr->bufPos -= remainder;
		}

	/* If we're using the definite length form, exit */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		return( TRUE );

	/* If it's a short length we can encode it in a single byte */
	if( dLen < 128 )
		{
		*segmentDataPtr = dLen;
		return( TRUE );
		}

	/* It's a long length, encode it as a variable-length value */
	lLen -= 2;	/* Tag + length of length */
	*segmentDataPtr++ = 0x80 | lLen;
#if INT_MAX > 32767
	if( lLen > 3 )
		{
		*segmentDataPtr++ = dLen >> 24;
		dLen &= 0xFFFFFFL;
		}
	if( lLen > 2 )
		{
		*segmentDataPtr++ = dLen >> 16;
		dLen &= 0xFFFFL;
		}
#endif /* 32-bit ints */
	if( lLen > 1 )
		{
		*segmentDataPtr++ = dLen >> 8;
		dLen &= 0xFF;
		}
	*segmentDataPtr++ = dLen;
	return( TRUE );
	}

static int completeSegment( ENVELOPE_INFO *envelopeInfoPtr,
							const BOOLEAN forceCompletion )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->bufPos >= 0 && \
			envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );

	/* If we're enveloping data using indefinite encoding and we're not at
	   the end of the data, don't emit a sub-segment containing less then 10
	   bytes of data.  This is to protect against users who write code that
	   performs byte-at-a-time enveloping, at least we can quantize the data
	   amount to make it slightly more efficient.  As a side-effect, it
	   avoids occasional inefficiencies at boundaries where one or two bytes
	   may still be hanging around from a previous data block, since they'll
	   be coalesced into the following block */
	if( !forceCompletion && \
		!( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
		envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
		( envelopeInfoPtr->bufPos - envelopeInfoPtr->segmentDataStart ) < 10 )
		{
		/* We can't emit any of the small sub-segment, however there may be
		   (non-)data preceding this that we can hand over so we set the
		   segment data end value to the start of the segment (the complete
		   segment starts at segmentStart - TAG_SIZE) */
		envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->segmentStart - \
										  TAG_SIZE;
		return( CRYPT_OK );
		}

	/* Wrap up the segment */
	if( !( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT ) && \
		!encodeSegmentHeader( envelopeInfoPtr, 
					( envelopeInfoPtr->iCryptContext != CRYPT_ERROR ) ? \
					TRUE : FALSE ) )
		/* Not enough data to complete the segment */
		return( CRYPT_ERROR_UNDERFLOW );
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		int status;

		status = krnlSendMessage( envelopeInfoPtr->iCryptContext,
						IMESSAGE_CTX_ENCRYPT,
						envelopeInfoPtr->buffer + \
								envelopeInfoPtr->segmentDataStart,
						envelopeInfoPtr->bufPos - \
								envelopeInfoPtr->segmentDataStart );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Remember how much data is now available to be read out */
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;

	/* Mark this segment as being completed */
	envelopeInfoPtr->dataFlags |= ENVDATA_SEGMENTCOMPLETE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Copy to Envelope							*
*																			*
****************************************************************************/

/* Copy data into the envelope.  Returns the number of bytes copied, or an
   overflow error if we're trying to flush data and there isn't room to
   perform the flush (this somewhat peculiar case is because the caller
   expects to have 0 bytes copied in this case) */

static int copyToEnvelope( ENVELOPE_INFO *envelopeInfoPtr, 
						   const BYTE *buffer, const int length )
	{
	ACTION_LIST *hashActionPtr;
	BOOLEAN needCompleteSegment = FALSE;
	BYTE *bufPtr;
	int bytesToCopy, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length >= 0 );
	assert( length == 0 || isReadPtr( buffer, length ) );

	/* Perform a safety check of the envelope state */
	if( envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* If we're trying to copy into a full buffer, return a count of 0 bytes
	   unless we're trying to flush the buffer (the calling routine may
	   convert this to an overflow error if necessary) */
	if( envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
		return( length > 0 ? 0 : CRYPT_ERROR_OVERFLOW );

	/* If we're generating a detached signature, just hash the data and
	   exit */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		{
		/* Unlike CMS, PGP handles authenticated attributes by extending the 
		   hashing of the payload data to cover the additional attributes,
		   so if this is a flush and we're using the PGP format we can't 
		   wrap up the hashing yet */
		if( length <= 0 && envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			return( 0 );

		assert( envelopeInfoPtr->actionList != NULL );
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
		return( length );
		}

	/* If we're flushing data, wrap up the segment and exit */
	if( length <= 0 )
		{
		BOOLEAN needNewSegment = envelopeInfoPtr->dataFlags & \
								 ENVDATA_NEEDSPADDING;

		/* If we're using an explicit payload length, make sure that we 
		   copied in as much data as was explicitly declared */
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
			envelopeInfoPtr->segmentSize != 0 )
			return( CRYPT_ERROR_UNDERFLOW );

#ifdef USE_COMPRESSION
		/* If we're using compression, flush any remaining data out of the
		   zStream */
		if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
			{
			/* If we've just completed a segment, begin a new one.  This
			   action is slightly anomalous in that normally a flush can't
			   add more data to the envelope and so we'd never need to start
			   a new segment during a flush, however since we can have
			   arbitrarily large amounts of data trapped in subspace via zlib
			   we need to be able to handle starting new segments at this
			   point */
			if( envelopeInfoPtr->dataFlags & ENVDATA_SEGMENTCOMPLETE )
				{
				status = beginSegment( envelopeInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				if( envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
					return( CRYPT_ERROR_OVERFLOW );
				}

			/* Flush any remaining compressed data into the envelope buffer */
			bytesToCopy = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
			envelopeInfoPtr->zStream.next_in = NULL;
			envelopeInfoPtr->zStream.avail_in = 0;
			envelopeInfoPtr->zStream.next_out = envelopeInfoPtr->buffer + \
												envelopeInfoPtr->bufPos;
			envelopeInfoPtr->zStream.avail_out = bytesToCopy;
			status = deflate( &envelopeInfoPtr->zStream, Z_FINISH );
			if( status != Z_STREAM_END && status != Z_OK )
				/* There was some problem other than the output buffer being
				   full */
				return( CRYPT_ERROR_FAILED );

			/* Adjust the status information based on the data flushed out
			   of the zStream.  We don't need to check for the output buffer
			   being full because this case is already handled by the check
			   of the deflate() return value */
			envelopeInfoPtr->bufPos += bytesToCopy - \
									   envelopeInfoPtr->zStream.avail_out;
			assert( envelopeInfoPtr->bufPos >= 0 && \
					envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );

			/* If we didn't finish flushing data because the output buffer is
			   full, complete the segment and tell the caller that they need 
			   to pop some data */
			if( status == Z_OK )
				{
				status = completeSegment( envelopeInfoPtr, TRUE );
				return( cryptStatusError( status ) ? \
						status : CRYPT_ERROR_OVERFLOW );
				}
			}
#endif /* USE_COMPRESSION */

		/* If we're encrypting data with a block cipher, we need to add PKCS
		   #5 padding at the end of the last block */
		if( envelopeInfoPtr->blockSize > 1 )
			{
			envelopeInfoPtr->dataFlags |= ENVDATA_NEEDSPADDING;
			if( envelopeInfoPtr->dataFlags & ENVDATA_SEGMENTCOMPLETE )
				/* The current segment has been wrapped up, we need to begin
				   a new segment to contain the padding */
				needNewSegment = TRUE;
			}

		/* If we're carrying over the padding requirement from a previous
		   block, we need to begin a new block before we can try and add the
		   padding.  This can happen if there was data left after the 
		   previous segment was completed or if the addition of padding 
		   would have overflowed the buffer when the segment was completed, 
		   in other words if the needPadding flag is still set from the 
		   previous call */
		if( needNewSegment )
			{
			status = beginSegment( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			if( envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
				return( CRYPT_ERROR_OVERFLOW );
			}

		/* Complete the segment if necessary */
		if( !( envelopeInfoPtr->dataFlags & ENVDATA_SEGMENTCOMPLETE ) || \
			( envelopeInfoPtr->dataFlags & ENVDATA_NEEDSPADDING ) )
			{
			status = completeSegment( envelopeInfoPtr, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( envelopeInfoPtr->dataFlags & ENVDATA_NEEDSPADDING )
			return( CRYPT_ERROR_OVERFLOW );

		/* If we're completed the hashing, we're done.  In addition unlike 
		   CMS, PGP handles authenticated attributes by extending the 
		   hashing of the payload data to cover the additional attributes,
		   so if we're using the PGP format we can't wrap up the hashing
		   yet */
		if( !( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE ) || \
			envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			return( 0 );

		/* We've finished processing everything, complete each hash action if
		   necessary */
		assert( envelopeInfoPtr->actionList != NULL );
		for( hashActionPtr = envelopeInfoPtr->actionList;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH; 
			 hashActionPtr = hashActionPtr->next )
			{
			status = krnlSendMessage( hashActionPtr->iCryptHandle,
									  IMESSAGE_CTX_HASH, "", 0 );
			if( cryptStatusError( status ) )
				return( status );
			}

		return( 0 );
		}

	/* If we're using an explicit payload length, make sure that we don't 
	   try and copy in more data than has been explicitly declared */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
		length > envelopeInfoPtr->segmentSize )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we've just completed a segment, begin a new one before we add any
	   data */
	if( envelopeInfoPtr->dataFlags & ENVDATA_SEGMENTCOMPLETE )
		{
		status = beginSegment( envelopeInfoPtr );
		if( cryptStatusError( status ) || \
			envelopeInfoPtr->bufPos >= envelopeInfoPtr->bufSize )
			return( 0 );	/* 0 bytes copied */
		}

	/* Copy over as much as we can fit into the buffer */
	bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	bytesToCopy = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
	if( bytesToCopy <= 0 )
		{
		/* Safety check */
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}
#ifdef USE_COMPRESSION
	if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
		{
		/* Compress the data into the envelope buffer */
		envelopeInfoPtr->zStream.next_in = ( BYTE * ) buffer;
		envelopeInfoPtr->zStream.avail_in = length;
		envelopeInfoPtr->zStream.next_out = bufPtr;
		envelopeInfoPtr->zStream.avail_out = bytesToCopy;
		status = deflate( &envelopeInfoPtr->zStream, Z_NO_FLUSH );
		if( status != Z_OK )
			return( CRYPT_ERROR_FAILED );

		/* Adjust the status information based on the data copied into the
		   zStream and flushed from the zStream into the buffer */
		envelopeInfoPtr->bufPos += bytesToCopy - \
								   envelopeInfoPtr->zStream.avail_out;
		bytesToCopy = length - envelopeInfoPtr->zStream.avail_in;

		/* If the buffer is full (there's no more room left for further
		   input) we need to close off the segment */
		if( envelopeInfoPtr->zStream.avail_out <= 0 )
			needCompleteSegment = TRUE;
		}
	else
#endif /* USE_COMPRESSION */
		{
		/* We're not using compression */
		if( bytesToCopy > length )
			bytesToCopy = length;
		memcpy( bufPtr, buffer, bytesToCopy );
		envelopeInfoPtr->bufPos += bytesToCopy;

		/* Hash the data if necessary.  We don't have to check for problems
		   with the context at this point since they'll be detected when we
		   complete the hashing */
		if( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE )
			for( hashActionPtr = envelopeInfoPtr->actionList;
				 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH; 
				 hashActionPtr = hashActionPtr->next )
				krnlSendMessage( hashActionPtr->iCryptHandle,
								 IMESSAGE_CTX_HASH, bufPtr, bytesToCopy );

		/* If the buffer is full (i.e. we've been fed more input data than we
		   could copy into the buffer) we need to close off the segment */
		if( bytesToCopy < length )
			needCompleteSegment = TRUE;
		}
	assert( envelopeInfoPtr->bufPos >= 0 );

	/* Adjust the bytes-left counter if necessary */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		envelopeInfoPtr->segmentSize -= bytesToCopy;

	/* Close off the segment if necessary */
	if( needCompleteSegment )
		{
		status = completeSegment( envelopeInfoPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( bytesToCopy );
	}

/****************************************************************************
*																			*
*								Copy from Envelope							*
*																			*
****************************************************************************/

/* Copy data from the envelope and begin a new segment in the newly-created
   room.  If called with a zero length value this will create a new segment
   without moving any data.  Returns the number of bytes copied */

static int copyFromEnvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
							 int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	int remainder;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( length >= 0 );
	assert( length == 0 || isWritePtr( buffer, length ) );

	/* Perform a safety check of the envelope state */
	if( envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* If the caller wants more data than there is available in the set of
	   completed segments, try to wrap up the next segment to make more data
	   available */
	if( length > envelopeInfoPtr->segmentDataEnd )
		{
		/* Try and complete the segment if necessary.  This may not be
		   possible if we're using a block encryption mode and there isn't
		   enough room at the end of the buffer to encrypt a full block.  If
		   we're generating a detached sig, the data is communicated out-of-
		   band, so there's no segmenting */
		if( !( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) && \
			!( envelopeInfoPtr->dataFlags & ENVDATA_SEGMENTCOMPLETE ) )
			{
			int status = completeSegment( envelopeInfoPtr, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Return all of the data that we've got */
		length = min( length, envelopeInfoPtr->segmentDataEnd );
		}
	remainder = envelopeInfoPtr->bufPos - length;
	assert( remainder >= 0 && remainder <= envelopeInfoPtr->bufPos );

	/* Copy the data out and move any remaining data down to the start of the
	   buffer  */
	if( length > 0 )
		{
		memcpy( buffer, bufPtr, length );

		/* Move any remaining data down in the buffer */
		if( remainder > 0 )
			memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + length,
					 remainder );
		envelopeInfoPtr->bufPos = remainder;

		/* Update the segment location information.  Note that the segment 
		   start values track the start position of the last completed segment 
		   and aren't updated until we begin a new segment, so they may go 
		   negative at this point when the data from the last completed 
		   segment is moved past the start of the buffer */
		envelopeInfoPtr->segmentStart -= length;
		envelopeInfoPtr->segmentDataStart -= length;
		envelopeInfoPtr->segmentDataEnd -= length;
		assert( envelopeInfoPtr->segmentDataEnd >= 0 );
		}

	return( length );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initEnvelopeStreaming( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	envelopeInfoPtr->copyToEnvelopeFunction = copyToEnvelope;
	envelopeInfoPtr->copyFromEnvelopeFunction = copyFromEnvelope;
	}
