/****************************************************************************
*																			*
*				Miscellaneous (Non-ASN.1) Read/Write Routines				*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

/* Non-ASN.1 formats use their own encoding types for integers, strings,
   and misellaneous other values, the following functions read and write
   these values */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../bn/bn.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

#if defined( USE_PGP ) || defined( USE_PGPKEYS ) || \
	defined( USE_SSH1 ) || defined( USE_SSH2 )

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Read a constrained-length data value, used by several routines */

static int readConstrainedData( STREAM *stream, void *buffer,
								int *bufferLength, const int length,
								const int maxLength )
	{
	int dataLength = length, remainder = 0;

	if( bufferLength != NULL )
		*bufferLength = length;

	/* If we don't care about the return value, skip it and exit */
	if( buffer == NULL )
		return( sSkip( stream, dataLength ) );

	/* Read in the object, limiting the size to the maximum buffer size */
	if( dataLength > maxLength )
		{
		remainder = dataLength - maxLength;
		dataLength = maxLength;
		}
	if( dataLength > 0 )
		{
		sread( stream, buffer, dataLength );
		*bufferLength = dataLength;
		}

	/* Skip any remaining data if necessary */
	if( remainder > 0 )
		sSkip( stream, remainder );

	return( sGetStatus( stream ) );
	}

/* Read large integer data */

typedef enum { LENGTH_16BITS_BITS, LENGTH_32BITS, LENGTH_32BITS_BITS } LENGTH_TYPE;

static int readIntegerData( STREAM *stream, void *integer,
							int *integerLength, const int minLength, 
							const int maxLength, 
							const LENGTH_TYPE lengthType )
	{
	BYTE *integerDataPtr = integer;
	int length, i, status;

	/* Clear return values */
	if( integer != NULL )
		*integerDataPtr = '\0';
	if( integerLength != NULL )
		*integerLength = 0;

	/* Read the integer value */
	if( lengthType == LENGTH_16BITS_BITS )
		{
		const int bitLength = ( sgetc( stream ) << 8 ) | sgetc( stream );

		length = bitsToBytes( bitLength );
		if( cryptStatusError( sGetStatus( stream ) ) )
			return( sGetStatus( stream ) );
		}
	else
		{
		length = readUint32( stream );
		if( cryptStatusError( length ) )
			return( length );
		if( lengthType == LENGTH_32BITS_BITS )
			length = bitsToBytes( length );
		}
	if( length < minLength || length > maxLength )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	if( integerLength != NULL )
		*integerLength = length;
	if( integer == NULL )
		return( sSkip( stream, length ) );
	status = sread( stream, integer, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Strip possible leading-zero padding */
	for( i = 0; integerDataPtr[ i ] == 0 && i < length; i++ );
	if( i > 0 )
		{
		if( length - i <= 0 )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		memmove( integerDataPtr, integerDataPtr + i, length - i );
		if( integerLength != NULL )
			*integerLength = length;
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Data Read/Write Routines						*
*																			*
****************************************************************************/

/* Read and write 32-bit integer values */

int readUint32( STREAM *stream )
	{
	BYTE buffer[ UINT32_SIZE ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( buffer[ 0 ] & 0x80 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	return( ( ( unsigned int ) buffer[ 0 ] << 24 ) | \
			( ( unsigned int ) buffer[ 1 ] << 16 ) | \
			( ( unsigned int ) buffer[ 2 ] << 8 ) | \
							   buffer[ 3 ] );
	}

int writeUint32( STREAM *stream, const int value )
	{
	BYTE buffer[ UINT32_SIZE ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = value >> 24;
	buffer[ 1 ] = value >> 16;
	buffer[ 2 ] = value >> 8;
	buffer[ 3 ] = value & 0xFF;
	return( swrite( stream, buffer, UINT32_SIZE ) );
	}

/* Read and write 64-bit integer values standard integer values */

int readUint64( STREAM *stream )
	{
	BYTE buffer[ UINT64_SIZE / 2 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT64_SIZE / 2 );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( buffer, "\x00\x00\x00\x00", UINT64_SIZE / 2 ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	return( readUint32( stream ) );
	}

int writeUint64( STREAM *stream, const int value )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	swrite( stream, "\x00\x00\x00\x00", UINT64_SIZE / 2 );
	return( writeUint32( stream, value ) );
	}

/* Read and write 32- and 64-bit time values.  Note that we can't call down 
   to read/writeUint32 for these since time_t may be unsigned or of a 
   different integral size than int */

int readUint32Time( STREAM *stream, time_t *timeVal )
	{
	BYTE buffer[ UINT32_SIZE ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( timeVal, sizeof( time_t ) ) );

	status = sread( stream, buffer, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( timeVal != NULL )
		*timeVal = ( ( time_t ) buffer[ 0 ] << 24 ) | \
				   ( ( time_t ) buffer[ 1 ] << 16 ) | \
				   ( ( time_t ) buffer[ 2 ] << 8 ) | \
								buffer[ 3 ];
	return( CRYPT_OK );
	}

int writeUint32Time( STREAM *stream, const time_t timeVal )
	{
	BYTE buffer[ UINT32_SIZE ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = ( int ) ( timeVal >> 24 );
	buffer[ 1 ] = ( int ) ( timeVal >> 16 );
	buffer[ 2 ] = ( int ) ( timeVal >> 8 );
	buffer[ 3 ] = ( int ) ( timeVal & 0xFF );
	return( swrite( stream, buffer, UINT32_SIZE ) );
	}

int readUint64Time( STREAM *stream, time_t *timeVal )
	{
	BYTE buffer[ UINT64_SIZE ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( timeVal, sizeof( time_t ) ) );

	status = sread( stream, buffer, UINT64_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( buffer, "\x00\x00\x00\x00", UINT64_SIZE / 2 ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	return( readUint32Time( stream, timeVal ) );
	}

int writeUint64Time( STREAM *stream, const time_t timeVal )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	swrite( stream, "\x00\x00\x00\x00", UINT64_SIZE / 2 );
	return( writeUint32Time( stream, timeVal ) );
	}

/* Read and write strings preceded by 32-bit lengths */

int readString32( STREAM *stream, void *string, int *stringLength,
				  const int maxLength )
	{
	int length;

	/* Clear return values */
	if( string != NULL )
		( ( char * ) string )[ 0 ] = '\0';
	if( stringLength != NULL )
		*stringLength = 0;

	/* Read the string, limiting the size to the maximum buffer size */
	length = readUint32( stream );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	return( readConstrainedData( stream, string, stringLength, length,
								 maxLength ) );
	}

int writeString32( STREAM *stream, const void *string,
				   const int stringLength )
	{
	const int length = ( stringLength ) ? stringLength : strlen( string );

	writeUint32( stream, length );
	return( swrite( stream, string, length ) );
	}

/* Read and write (large) integers preceded by 32-bit lengths */

int readInteger32( STREAM *stream, void *integer, int *integerLength,
				   const int maxLength )
	{
	return( readIntegerData( stream, integer, integerLength, 1, maxLength, 
							 LENGTH_32BITS ) );
	}

int writeInteger32( STREAM *stream, const void *integer,
					const int integerLength )
	{
	const BOOLEAN leadingOneBit = ( ( BYTE * ) integer )[ 0 ] & 0x80;

	writeUint32( stream, integerLength + ( leadingOneBit ? 1 : 0 ) );
	if( leadingOneBit )
		sputc( stream, 0 );	/* MPIs are signed values */
	return( swrite( stream, integer, integerLength ) );
	}

/* Read and write unsigned (large) integers preceded by 16- and 32-bit 
   lengths, lengths in bits */

int readInteger16Ubits( STREAM *stream, void *integer, int *integerLength,
						const int maxLength )
	{
	return( readIntegerData( stream, integer, integerLength, 1, maxLength,
							 LENGTH_16BITS_BITS ) );
	}

int readInteger32Ubits( STREAM *stream, void *integer, int *integerLength,
						const int maxLength )
	{
	return( readIntegerData( stream, integer, integerLength, 1, maxLength,
							 LENGTH_32BITS_BITS ) );
	}

int writeInteger16Ubits( STREAM *stream, const void *integer,
						 const int integerLength )
	{
	const int bitLength = bytesToBits( integerLength );

	sputc( stream, ( bitLength >> 8 ) & 0xFF );
	sputc( stream, bitLength & 0xFF );
	return( swrite( stream, integer, integerLength ) );
	}

int writeInteger32Ubits( STREAM *stream, const void *integer,
						 const int integerLength )
	{
	const int bitLength = bytesToBits( integerLength );

	writeUint32( stream, bitLength );
	return( swrite( stream, integer, integerLength ) );
	}

/* Read and write bignum integers preceded by 32-bit lengths */

int sizeofBignumInteger32( const void *bignum )
	{
	return( UINT32_SIZE + BN_num_bytes( bignum ) + \
						  BN_high_bit( ( BIGNUM * ) bignum ) );
	}

int readBignumInteger32( STREAM *stream, void *bignum, const int minBytes, 
						 const int maxBytes )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ], *bufPtr = buffer;
	int length = readUint32( stream ), status;

	if( cryptStatusError( length ) )
		return( length );
	if( length < minBytes || length > maxBytes + 1 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	while( !*bufPtr && length > 1 )
		{
		bufPtr++;
		length--;
		}
	if( BN_bin2bn( bufPtr, length, bignum ) == NULL )
		{
		sSetError( stream, CRYPT_ERROR_MEMORY );
		status = CRYPT_ERROR_MEMORY;
		}
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

int writeBignumInteger32( STREAM *stream, const void *bignum )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 1 ];
	const BOOLEAN highBit = BN_high_bit( ( BIGNUM * ) bignum );
	int bnLength, padOffset = 0, status;

	writeUint32( stream, BN_num_bytes( bignum ) + ( highBit ? 1 : 0 ) );
	if( highBit )
		buffer[ padOffset++ ] = '\0';
	bnLength = BN_bn2bin( bignum, buffer + padOffset ) + padOffset;
	status = swrite( stream, buffer, bnLength );
	zeroise( buffer, CRYPT_MAX_PKCSIZE + 1 );
	return( status );
	}

/* Read and write unsigned bignum integers preceded by 16-bit lengths, 
   lengths in bits.  We can't call down to writeInteger16Ubits() from 
   writeBignumInteger16Ubits() because the latter writes a precise length in
   bits while the former uses a value reconstructed from the byte count */

int readBignumInteger16Ubits( STREAM *stream, void *bignum, const int minBits, 
							  const int maxBits )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	/* Read the integer data */
	status = readIntegerData( stream, buffer, &length, bitsToBytes( minBits ), 
							  bitsToBytes( maxBits ), LENGTH_16BITS_BITS );
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

int writeBignumInteger16Ubits( STREAM *stream, const void *bignum )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int bnLength;

	bnLength = BN_num_bits( bignum );
	sputc( stream, bnLength >> 8 );
	sputc( stream, bnLength & 0xFF );
	bnLength = BN_bn2bin( bignum, buffer );
	return( swrite( stream, buffer, bnLength ) );
	}

/* PGP-specific read/write routines to read and write PGP variable-length 
   length values.  We also have a short-length version which is used to read 
   small packets such as keyrings and sigs and which ensures that the length 
   is in the range 1...16K */

#define PGP_CTB				0x80	/* PGP 2.x CTB template */
#define PGP_CTB_OPENPGP		0xC0	/* OpenPGP CTB template */
#define PGP_CTB_COMPRESSED	0xA3	/* Compressed indef-length data */

static long pgpReadLength( STREAM *stream, const int ctb )
	{
	long length;

	/* If it doesn't look like PGP data, don't go any further */
	if( !( ctb & PGP_CTB ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If it's an OpenPGP CTB, undo the hand-Huffman-coding */
	if( ( ctb & PGP_CTB_OPENPGP ) == PGP_CTB_OPENPGP )
		{
		length = sgetc( stream );

		if( length >= 192 )
			{
			if( length <= 223 )
				length = ( ( length - 192 ) << 8 ) + sgetc( stream ) + 192;
			else
				{
				if( length != 0xFF )
					{
					/* It's an indefinite-length encoding.  These are an
					   incredible pain to handle and don't seem to be
					   used by anything (the only data type that would need
					   them, compressed data, uses the 2.x CTB 0xA3 instead)
					   so we don't try and do anything with it */
					sSetError( stream, CRYPT_ERROR_BADDATA );
					return( CRYPT_ERROR_BADDATA );
					}
				length = readUint32( stream );
				}
			}
		}
	else
		/* It's a PGP 2.x CTB, decode the length as a byte, word, or long */
		switch( ctb & 3 )
			{
			case 0:
				length = sgetc( stream );
				break;

			case 1:
				length = ( sgetc( stream ) << 8 ) | sgetc( stream );
				break;

			case 2:
				length = readUint32( stream );
				break;

			default:
				/* A length value of 3 indicates that the data length is 
				   determined externally, this is a deprecated PGP 2.x value 
				   that we don't handle */
				sSetError( stream, CRYPT_ERROR_BADDATA );
				return( CRYPT_ERROR_BADDATA );
			}
	if( length < 0 || length > MAX_INTLENGTH )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	return( length );
	}

int pgpReadShortLength( STREAM *stream, const int ctb )
	{
	const long length = pgpReadLength( stream, ctb );

	if( length <= 0 || length > 16384 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	return( ( int ) length );
	}

int pgpWriteLength( STREAM *stream, const int length )
	{
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

int pgpReadPacketHeader( STREAM *stream, int *ctb, long *length )
	{
	long localLength;
	int localCTB;

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
	localCTB = sPeek( stream );
	if( !( localCTB & PGP_CTB ) )
		{
		/* If it doesn't look like PGP data, don't go any further */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	if( ( localCTB & PGP_CTB_OPENPGP ) == PGP_CTB_OPENPGP )
		{
		/* OpenPGP has an awkward variable-length encoding which requires
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
			sgetc( stream );	/* Skip CTB */
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
	sgetc( stream );			/* Skip CTB */
	localLength = pgpReadLength( stream, localCTB );
	if( cryptStatusError( localLength ) )
		return( localLength );
	if( ctb != NULL )
		*ctb = localCTB;
	if( length != NULL )
		*length = localLength;

	return( CRYPT_OK );
	}

int pgpWritePacketHeader( STREAM *stream, const int packetType,
						  const long length )
	{
	sputc( stream, PGP_CTB_OPENPGP | packetType );
	return( pgpWriteLength( stream, length ) );
	}
#endif /* USE_PGP || USE_PGPKEYS || USE_SSH1 || USE_SSH2 */
