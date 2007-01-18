/****************************************************************************
*																			*
*				Miscellaneous (Non-ASN.1) Read/Write Routines				*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Read large integer data */

typedef enum {
	LENGTH_16U,			/* Unsigned int, 16-bit length */
	LENGTH_16U_BITS,	/* Unsigned int, 16-bit length, length in bits */
	LENGTH_32,			/* Signed int, 32-bit length */
	LENGTH_32U_BITS		/* Unsigned int, 32-bit length, length in bits */
	} LENGTH_TYPE;

static int readInteger( STREAM *stream, void *integer, int *integerLength,
						const int minLength, const int maxLength,
						const LENGTH_TYPE lengthType )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer == NULL || isWritePtr( integer, maxLength ) );
	assert( integerLength == NULL || \
			isWritePtr( integerLength, sizeof( int ) ) );

	/* Clear return values */
	if( integer != NULL )
		*( ( BYTE * ) integer ) = '\0';
	if( integerLength != NULL )
		*integerLength = 0;

	/* Read the length and make sure that it's within range, with allowance
	   for extra zero-padding */
	if( lengthType == LENGTH_16U || lengthType == LENGTH_16U_BITS )
		length = readUint16( stream );
	else
		length = readUint32( stream );
	if( cryptStatusError( length ) )
		return( length );
	if( lengthType == LENGTH_16U_BITS || lengthType == LENGTH_32U_BITS )
		length = bitsToBytes( length );
	if( length < minLength || length > maxLength + 2 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* If we're reading a signed integer, the sign bit can't be set, since
	   this would produce a negative value.  This differs from the ASN.1
	   code, where the incorrect setting of the sign bit is so common that
	   we always treat integers as unsigned */
	if( lengthType == LENGTH_32 && ( sPeek( stream ) & 0x80 ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Skip possible leading-zero padding and repeat the length check once
	   the zero-padding has been adjusted */
	while( length > 0 && sPeek( stream ) == 0 )
		{
		int status;

		status = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		length--;
		}
	if( length < minLength || length > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Read the value */
	if( integerLength != NULL )
		*integerLength = length;
	if( integer == NULL )
		return( sSkip( stream, length ) );
	return( sread( stream, integer, length ) );
	}

/****************************************************************************
*																			*
*								Data Read Routines							*
*																			*
****************************************************************************/

/* Read 16-, 32- and 64-bit integer values.  Although in theory we could do
   the 16-bit read more simply with ( sgetc( stream ) << 8 ) | sgetc( stream ),
   this will break with some compilers that reorder expressions */

int readUint16( STREAM *stream )
	{
	BYTE buffer[ UINT16_SIZE + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT16_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	return( ( ( int ) buffer[ 0 ] << 8 ) | buffer[ 1 ] );
	}

int readUint32( STREAM *stream )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( buffer[ 0 ] & 0x80 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( ( ( int ) buffer[ 0 ] << 24 ) | \
			( ( int ) buffer[ 1 ] << 16 ) | \
			( ( int ) buffer[ 2 ] << 8 ) | \
							   buffer[ 3 ] );
	}

int readUint64( STREAM *stream )
	{
	BYTE buffer[ ( UINT64_SIZE / 2 ) + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT64_SIZE / 2 );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( buffer, "\x00\x00\x00\x00", UINT64_SIZE / 2 ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint32( stream ) );
	}

/* Read 32- and 64-bit time values.  Note that we can't just call down
   directly to readUint32() for these since time_t may be unsigned or of a
   different integral size than int */

int readUint32Time( STREAM *stream, time_t *timeVal )
	{
	int value;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( timeVal, sizeof( time_t ) ) );

	value = readUint32( stream );
	if( cryptStatusError( value ) )
		return( value );
	*timeVal = ( time_t ) value;
	return( CRYPT_OK );
	}

int readUint64Time( STREAM *stream, time_t *timeVal )
	{
	int value;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( timeVal, sizeof( time_t ) ) );

	value = readUint64( stream );
	if( cryptStatusError( value ) )
		return( value );
	*timeVal = ( time_t ) value;
	return( CRYPT_OK );
	}

/* Read a string preceded by a 32-bit length */

static int readData32( STREAM *stream, void *data, int *dataLength,
					   const int maxLength, const BOOLEAN includeLengthField )
	{
	BYTE *dataPtr = data;
	const int extraSize = includeLengthField ? UINT32_SIZE : 0;
	int length;

	length = readUint32( stream );
	if( length <= 0 )
		/* Error or zero length.  If it's zero length we don't return any
		   data */
		return( length );
	if( length > maxLength - extraSize )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( includeLengthField )
		{
		dataPtr[ 0 ] = ( length >> 24 ) & 0xFF;
		dataPtr[ 1 ] = ( length >> 16 ) & 0xFF;
		dataPtr[ 2 ] = ( length >> 8 ) & 0xFF;
		dataPtr[ 3 ] = length & 0xFF;
		}
	if( data == NULL )
		return( sSkip( stream, length ) );
	*dataLength = length + extraSize;
	return( sread( stream, dataPtr + extraSize, length ) );
	}

int readString32( STREAM *stream, void *string, int *stringLength,
				  const int maxLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( string == NULL && stringLength == NULL ) || \
			( isWritePtr( string, maxLength ) && \
			  isWritePtr( stringLength, sizeof( int ) ) ) );
	assert( maxLength >= 1 );

	/* Clear return values */
	if( string != NULL )
		{
		( ( char * ) string )[ 0 ] = '\0';
		*stringLength = 0;
		}

	/* Read the string, limiting the size to the maximum buffer size */
	return( readData32( stream, string, stringLength, maxLength, FALSE ) );
	}

/* Read a raw object preceded by a 32-bit length */

int readRawObject32( STREAM *stream, void *buffer, int *bufferLength,
					 const int maxLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( buffer == NULL && bufferLength == NULL ) || \
			( isWritePtr( buffer, maxLength ) &&
			  isWritePtr( bufferLength, sizeof( int ) ) ) );
	assert( maxLength >= UINT32_SIZE + 1 );

	/* Clear return values */
	if( buffer != NULL )
		{
		memset( buffer, 0, UINT32_SIZE );
		*bufferLength = 0;
		}

	/* Read the string, limiting the size to the maximum buffer size */
	return( readData32( stream, buffer, bufferLength, maxLength, TRUE ) );
	}

/* Read a universal type and discard it, used to skip unknown or unwanted
   types */

static int readUniversal( STREAM *stream, const LENGTH_TYPE lengthType )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the length and skip the data */
	if( lengthType == LENGTH_16U )
		length = readUint16( stream );
	else
		length = readUint32( stream );
	if( length <= 0 )
		/* Error or zero length */
		return( length );
	return( sSkip( stream, length ) );
	}

int readUniversal16( STREAM *stream )
	{
	return( readUniversal( stream, LENGTH_16U ) );
	}

int readUniversal32( STREAM *stream )
	{
	return( readUniversal( stream, LENGTH_32 ) );
	}

/* Read (large) integers in various formats */

int readInteger16U( STREAM *stream, void *integer, int *integerLength,
					const int minLength, const int maxLength )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_16U ) );
	}

int readInteger16Ubits( STREAM *stream, void *integer, int *integerLength,
						const int minLength, const int maxLength )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_16U_BITS ) );
	}

int readInteger32( STREAM *stream, void *integer, int *integerLength,
				   const int minLength, const int maxLength )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_32 ) );
	}

int readInteger32Ubits( STREAM *stream, void *integer, int *integerLength,
						const int minLength, const int maxLength )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_32U_BITS ) );
	}

#ifdef USE_PKC

/* Read integers as bignums in various formats */

static int readBignumInteger( STREAM *stream, void *bignum,
							  const int minLength, const int maxLength,
							  const LENGTH_TYPE lengthType )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );
	assert( minLength >= 1 && maxLength <= CRYPT_MAX_PKCSIZE );

	/* Read the integer data */
	status = readInteger( stream, buffer, &length, minLength, maxLength,
						  lengthType );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the value to a bignum */
	if( BN_bin2bn( buffer, length, bignum ) == NULL )
		{
		sSetError( stream, CRYPT_ERROR_MEMORY );
		status = CRYPT_ERROR_MEMORY;
		}
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

int readBignumInteger16U( STREAM *stream, void *bignum, const int minLength,
						  const int maxLength )
	{
	return( readBignumInteger( stream, bignum, minLength, maxLength,
							   LENGTH_16U ) );
	}

int readBignumInteger16Ubits( STREAM *stream, void *bignum, const int minBits,
							  const int maxBits )
	{
	return( readBignumInteger( stream, bignum, bitsToBytes( minBits ),
							   bitsToBytes( maxBits ), LENGTH_16U_BITS ) );
	}

int readBignumInteger32( STREAM *stream, void *bignum, const int minLength,
						 const int maxLength )
	{
	return( readBignumInteger( stream, bignum, minLength, maxLength,
							   LENGTH_32 ) );
	}
#endif /* USE_PKC */

/****************************************************************************
*																			*
*								Data Write Routines							*
*																			*
****************************************************************************/

/* Write 16-, 32- and 64-bit integer values */

int writeUint16( STREAM *stream, const int value )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	sputc( stream, ( value >> 8 ) & 0xFF );
	return( sputc( stream, value & 0xFF ) );
	}

int writeUint32( STREAM *stream, const long value )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = ( value >> 24 ) & 0xFF;
	buffer[ 1 ] = ( value >> 16 ) & 0xFF;
	buffer[ 2 ] = ( value >> 8 ) & 0xFF;
	buffer[ 3 ] = value & 0xFF;
	return( swrite( stream, buffer, UINT32_SIZE ) );
	}

int writeUint64( STREAM *stream, const long value )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	swrite( stream, "\x00\x00\x00\x00", UINT64_SIZE / 2 );
	return( writeUint32( stream, value ) );
	}

/* Write 32- and 64-bit time values */

int writeUint32Time( STREAM *stream, const time_t timeVal )
	{
	return( writeUint32( stream, ( int ) timeVal ) );
	}

int writeUint64Time( STREAM *stream, const time_t timeVal )
	{
	return( writeUint64( stream, ( int ) timeVal ) );
	}

/* Write a string preceded by a 32-bit length */

int writeString32( STREAM *stream, const void *string,
				   const int stringLength )
	{
	const int length = ( stringLength > 0 ) ? stringLength : \
											  strlen( string );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stringLength == 0 || \
			isReadPtr( string, stringLength ) );

	writeUint32( stream, length );
	return( swrite( stream, string, length ) );
	}

/* Write large integers in various formats */

static int writeInteger( STREAM *stream, const void *integer,
						 const int integerLength ,
						 const LENGTH_TYPE lengthType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( integer, integerLength ) );

	switch( lengthType )
		{
		case LENGTH_16U:
			writeUint16( stream, integerLength );
			break;

		case LENGTH_16U_BITS:
			writeUint16( stream, bytesToBits( integerLength ) );
			break;

		case LENGTH_32:
			{
			const BOOLEAN leadingOneBit = ( ( BYTE * ) integer )[ 0 ] & 0x80;

			writeUint32( stream, integerLength + ( leadingOneBit ? 1 : 0 ) );
			if( leadingOneBit )
				sputc( stream, 0 );	/* MPIs are signed values */
			break;
			}

		case LENGTH_32U_BITS:
			writeUint32( stream, bytesToBits( integerLength ) );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	return( swrite( stream, integer, integerLength ) );
	}

int writeInteger16U( STREAM *stream, const void *integer,
					 const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_16U ) );
	}

int writeInteger16Ubits( STREAM *stream, const void *integer,
						 const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_16U_BITS ) );
	}

int writeInteger32( STREAM *stream, const void *integer,
					const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_32 ) );
	}

int writeInteger32Ubits( STREAM *stream, const void *integer,
						 const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_32U_BITS ) );
	}

#ifdef USE_PKC

/* Write integers from bignums in various formats */

int sizeofBignumInteger32( const void *bignum )
	{
	return( UINT32_SIZE + BN_num_bytes( bignum ) + \
						  BN_high_bit( ( BIGNUM * ) bignum ) );
	}

static int writeBignumInteger( STREAM *stream, const void *bignum,
							   const LENGTH_TYPE lengthType )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int bnLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	bnLength = BN_bn2bin( bignum, buffer );
	switch( lengthType )
		{
		case LENGTH_16U:
			status = writeInteger( stream, buffer, bnLength, LENGTH_16U );
			break;

		case LENGTH_16U_BITS:
			/* We can't call down to writeInteger16Ubits() from here because
			   we need to write a precise length in bits rather than a value
			   reconstructed from the byte count */
			writeUint16( stream, BN_num_bits( bignum ) );
			status = swrite( stream, buffer, bnLength );
			break;

		case LENGTH_32:
			status = writeInteger( stream, buffer, bnLength, LENGTH_32 );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_NOTAVAIL;
		}
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

int writeBignumInteger16U( STREAM *stream, const void *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_16U ) );
	}

int writeBignumInteger16Ubits( STREAM *stream, const void *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_16U_BITS ) );
	}

int writeBignumInteger32( STREAM *stream, const void *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_32 ) );
	}
#endif /* USE_PKC */

/****************************************************************************
*																			*
*							PGP Read/Write Routines							*
*																			*
****************************************************************************/

#ifdef USE_PGP

#if defined( INC_ALL )
  #include "pgp.h"
#else
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* PGP-specific read/write routines to read and write PGP variable-length
   length values.  We also have a short-length version which is used to read
   small packets such as keyrings and sigs and which ensures that the length
   is in the range 1...16K */

static int pgpReadLength( STREAM *stream, long *length, const int ctb,
						  const int minLength, const int maxLength,
						  const BOOLEAN indefOK )
	{
	BOOLEAN indefiniteLength = FALSE;
	long localLength;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( length, sizeof( long ) ) );
	assert( minLength >= 0 && minLength < maxLength && \
			maxLength <= MAX_INTLENGTH );

	/* Clear return value */
	*length = CRYPT_ERROR;

	/* If it doesn't look like PGP data, don't go any further */
	if( !pgpIsCTB( ctb ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* If it's an OpenPGP CTB, undo the hand-Huffman-coding */
	if( pgpGetPacketVersion( ctb ) == PGP_VERSION_OPENPGP )
		{
		localLength = sgetc( stream );

		if( localLength >= 192 )
			{
			if( localLength <= 223 )
				{
				const int value = sgetc( stream );

				if( !cryptStatusError( value ) )
					localLength = ( ( localLength - 192 ) << 8 ) + value + 192;
				else
					localLength = value;
				}
			else
				{
				if( localLength < 255 )
					{
					/* It's PGP's annoying interpretation of indefinite-
					   length encoding.  This is an incredible pain to
					   handle but fortunately except for McAfee's PGP
					   implementation it doesn't seem to be used by
					   anything.  The only data type that would normally
					   need indefinite lengths, compressed data, uses the
					   2.x CTB 0xA3 instead */
					if( !indefOK )
						return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

					/* Unlike ASN.1, which encodes an outer indefinite-
					   length marker and then encodes each sub-segment as
					   a data unit within it, PGP encodes a partial length
					   as a sequence of power-of-two exponent values with a
					   standard length encoding for the last sub-segment.
					   So once we're in indefinite-length mode we have to
					   record the current *type* of the length (as well as
					   its value) to determine whether more length packets
					   follow */
					localLength = 1 << ( localLength & 0x1F );
					indefiniteLength = TRUE;
					}
				else
					localLength = readUint32( stream );
				}
			}
		}
	else
		/* It's a PGP 2.x CTB, decode the length as a byte, word, or long */
		switch( ctb & 3 )
			{
			case 0:
				localLength = sgetc( stream );
				break;

			case 1:
				localLength = readUint16( stream );
				break;

			case 2:
				localLength = readUint32( stream );
				break;

			default:
				/* A length value of 3 indicates that the data length is
				   determined externally, this is a deprecated PGP 2.x value
				   that we don't handle */
				return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
			}
	if( cryptStatusError( localLength ) )
		return( localLength );
	if( localLength < minLength || localLength > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	*length = localLength;
	return( indefiniteLength ? OK_SPECIAL : CRYPT_OK );
	}

static int readPacketHeader( STREAM *stream, int *ctb, long *length,
							 const int minLength, const BOOLEAN indefOK )
	{
	long localLength;
	int localCTB, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ctb == NULL || isWritePtr( ctb, sizeof( int ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	/* Clear return values */
	if( ctb != NULL )
		*ctb = 0;
	if( length != NULL )
		*length = CRYPT_ERROR;

	/* We always need at least two more bytes to do anything */
	if( sMemDataLeft( stream ) < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Peek at the CTB and figure out whether we've got enough data left to
	   read the header */
	localCTB = sgetc( stream );
	if( !pgpIsCTB( localCTB ) )
		/* If it doesn't look like PGP data, don't go any further */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( pgpGetPacketVersion( localCTB ) == PGP_VERSION_OPENPGP )
		{
		/* OpenPGP has an awkward variable-length encoding that requires
		   that we burrow further down into the data to get the actual
		   length, to avoid problems with having to undo this we assume a
		   worst-case length of 5 bytes.  This is safe because the shortest
		   possible packet type, a conventionally-encrypted data packet with
		   a 1-byte payload, contains a minimum of 11 bytes of data (8-byte
		   IV, 2 bytes of repeated IV data, and 1 byte of payload) */
		if( sMemDataLeft( stream ) < 5 )
			return( CRYPT_ERROR_UNDERFLOW );
		}
	else
		{
		static const int lengthOfLength[ 4 ] = { 1, 2, 4, 0 };

		/* If it's a compressed data packet, there's no length present.
		   Normally we reject any indefinite-length packets since these
		   can't be processed sensibly (PGP 2.x, which used intermediate
		   files for everything, just read to EOF, OpenPGP deprecates them
		   because this doesn't exactly lead to portable implementations).
		   However, compressed-data packets can only be stored in this
		   manner but can still be processed because the user has to
		   explicitly flush the data at some point and we assume that this
		   is EOF.  This isn't anywhere near as clean as the PKCS #7/CMS/
		   SMIME equivalent where we've got an explicit end-of-data
		   indication, but it does the trick */
		if( localCTB == PGP_CTB_COMPRESSED )
			{
			if( ctb != NULL )
				*ctb = localCTB;
			if( length != NULL )
				*length = CRYPT_UNUSED;
			return( CRYPT_OK );
			}

		/* PGP 2.x has a predictable variable-length length encoding so we
		   can easily check whether there's enough data left */
		if( sMemDataLeft( stream ) < lengthOfLength[ localCTB & 3 ] )
			return( CRYPT_ERROR_UNDERFLOW );
		}

	/* Now that we know the format, get the length information */
	status = pgpReadLength( stream, &localLength, localCTB,
							minLength, MAX_INTLENGTH, indefOK );
	if( cryptStatusError( status ) )
		{
		int type;

		if( status != OK_SPECIAL )
			return( status );

		/* It's an indefinite-length encoding, this is only valid for
		   payload data packets so we make sure that we've got one of these
		   packet types present */
		assert( indefOK );
		type = pgpGetPacketType( localCTB );
		if( type != PGP_PACKET_DATA && type != PGP_PACKET_COPR && \
			type != PGP_PACKET_ENCR && type != PGP_PACKET_ENCR_MDC )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	if( ctb != NULL )
		*ctb = localCTB;
	if( length != NULL )
		*length = localLength;

	return( status );
	}

int pgpReadShortLength( STREAM *stream, const int ctb )
	{
	long length;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = pgpReadLength( stream, &length, ctb, 0, 16384, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	return( ( int ) length );
	}

int pgpWriteLength( STREAM *stream, const long length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	if( length <= 191 )
		return( sputc( stream, length ) );
	if( length <= 8383 )
		{
		const long adjustedLength = length - 192;

		sputc( stream, ( ( adjustedLength >> 8 ) & 0xFF ) + 192 );
		return( sputc( stream, ( adjustedLength & 0xFF ) ) );
		}
	sputc( stream, 0xFF );
	sputc( stream, ( length >> 24 ) & 0xFF );
	sputc( stream, ( length >> 16 ) & 0xFF );
	sputc( stream, ( length >> 8 ) & 0xFF );
	return( sputc( stream, ( length & 0xFF ) ) );
	}

int pgpReadPacketHeader( STREAM *stream, int *ctb, long *length,
						 const int minLength )
	{
	return( readPacketHeader( stream, ctb, length, minLength, FALSE ) );
	}

int pgpReadPacketHeaderI( STREAM *stream, int *ctb, long *length,
						  const int minLength )
	{
	return( readPacketHeader( stream, ctb, length, minLength, TRUE ) );
	}

int pgpReadPartialLength( STREAM *stream, long *length )
	{
	/* This is a raw length value so we have to feed in a pseudo-CTB */
	return( pgpReadLength( stream, length, PGP_CTB_OPENPGP,
						   0, MAX_INTLENGTH, TRUE ) );
	}

int pgpWritePacketHeader( STREAM *stream, const int packetType,
						  const long length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	sputc( stream, PGP_CTB_OPENPGP | packetType );
	return( pgpWriteLength( stream, length ) );
	}
#endif /* USE_PGP */
