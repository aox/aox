/****************************************************************************
*																			*
*						   ASN.1 Read/Write Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "asn1_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../bn/bn.h"
  #include "asn1_rw.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* When specifying a tag, we can use either the default tag for the object
   (given with DEFAULT_TAG) or a special-case tag.  The following macro
   selects the correct value.  Since these are all primitive objects, we
   force the tag type to a primitive tag */

#define selectTag( tag, default )	\
		( ( ( tag ) == DEFAULT_TAG ) ? ( default ) : \
									   ( MAKE_CTAG_PRIMITIVE( tag ) ) )

/* Calculate the size of the encoded length octets */

static int calculateLengthSize( const long length )
	{
	if( length < 128 )
		/* Use short form of length octets */
		return( 1 );
	else
		/* Use long form of length octets: length-of-length followed by
		   32, 24, 16, or 8-bit length */
		return( 1 + ( ( length > 0xFFFFFFL ) ? 4 : \
					  ( length > 0xFFFF ) ? 3 : ( length > 0xFF ) ? 2 : 1 ) );
	}

/* Determine the encoded size of an object given only a length.  This is
   implemented as a function rather than a macro since the macro form would
   evaluate the length argument a great many times.

   The function checks for a length < 0 since this is frequently called with
   the output of another function that may return an error code */

long sizeofObject( const long length )
	{
	return( ( length < 0 ) ? length : \
			sizeof( BYTE ) + calculateLengthSize( length ) + length );
	}

/* Determine the size of a bignum.  When we're writing these we can't use 
   sizeofObject() directly because the internal representation is unsigned 
   whereas the encoded form is signed */

int signedBignumSize( const void *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	return( BN_num_bytes( bignum ) + BN_high_bit( ( BIGNUM * ) bignum ) );
	}

/****************************************************************************
*																			*
*							ASN.1 Output Routines							*
*																			*
****************************************************************************/

/* Write the length octets for an ASN.1 data type */

int writeLength( STREAM *stream, const long length )
	{
	BYTE buffer[ 8 ];
	const int noLengthOctets = ( length > 0xFFFFFFL ) ? 4 : \
							   ( length > 0xFFFFL ) ? 3 : \
							   ( length > 0xFF ) ? 2 : 1;
	int bufPos = 1;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	/* Check if we can use the short form of length octets */
	if( length < 128 )
		return( sputc( stream, ( BYTE ) length ) );

	/* Encode the number of length octets followed by the octets themselves */
	buffer[ 0 ] = 0x80 | noLengthOctets;
	if( noLengthOctets > 3 )
		buffer[ bufPos++ ] = ( BYTE ) ( length >> 24 );
	if( noLengthOctets > 2 )
		buffer[ bufPos++ ] = ( BYTE ) ( length >> 16 );
	if( noLengthOctets > 1 )
		buffer[ bufPos++ ] = ( BYTE ) ( length >> 8 );
	buffer[ bufPos++ ] = ( BYTE ) length;
	return( swrite( stream, buffer, bufPos ) );
	}

/* Write a (non-bignum) numeric value, used by several routines */

static int writeNumeric( STREAM *stream, const long integer )
	{
	BOOLEAN needsLZ = TRUE;
	BYTE buffer[ 8 ];
	int length = 1;

	/* Determine the number of bytes necessary to encode the integer and
	   encode it into a temporary buffer */
	if( integer < 0 )
		buffer[ length++ ] = 0;
	if( integer > 0x00FFFFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 24 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00800000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x0000FFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 16 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00008000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x000000FFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 8 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00000080L && needsLZ )
		buffer[ length++ ] = 0;
	buffer[ length++ ] = ( BYTE ) integer;

	/* Write the length and numeric data */
	buffer[ 0 ] = length - 1;
	return( swrite( stream, buffer, length ) );
	}

/* Write a short integer value */

int writeShortInteger( STREAM *stream, const long integer, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer >= 0 );

	/* Write the identifier and numeric fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );
	return( writeNumeric( stream, integer ) );
	}

/* Write a large integer value */

int writeInteger( STREAM *stream, const BYTE *integer,
				  const int integerLength, const int tag )
	{
	const BOOLEAN leadingZero = integerLength && ( *integer & 0x80 ) ? 1 : 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( integer, integerLength ) );
	assert( integerLength >= 0 );

	/* Write the identifier field */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );

	/* Write it as a big-endian bignum value.  We have to be careful about 
	   how we handle values with the high bit set since the internal format 
	   is unsigned while ASN.1 values are signed */
	if( !integerLength )
		return( swrite( stream, "\x01\x00", 2 ) );
	writeLength( stream, integerLength + leadingZero );
	if( leadingZero )
		sputc( stream, 0 );
	return( swrite( stream, integer, integerLength ) );
	}

/* Write an bignum integer value */

int writeBignumTag( STREAM *stream, const void *bignum, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	/* If it's a dummy write, don't go through the full encoding process.
	   This optimisation both speeds things up and reduces unnecessary
	   writing of key data to memory */
	if( sIsNullStream( stream ) )
		{
		swrite( stream, buffer, sizeofBignum( bignum ) );
		return( CRYPT_OK );
		}

	length = BN_bn2bin( ( BIGNUM * ) bignum, buffer );
	status = writeInteger( stream, buffer, length, tag );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );

	return( status );
	}

/* Write an enumerated value */

int writeEnumerated( STREAM *stream, const int enumerated, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( enumerated >= 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_ENUMERATED : BER_CONTEXT_SPECIFIC | tag );
	return( writeNumeric( stream, ( long ) enumerated ) );
	}

/* Write a null value */

int writeNull( STREAM *stream, const int tag )
	{
	BYTE buffer[ 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? \
				  BER_NULL : BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 0;
	return( swrite( stream, buffer, 2 ) );
	}

/* Write a boolean value */

int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag )
	{
	BYTE buffer[ 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? \
				  BER_BOOLEAN : BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 1;
	buffer[ 2 ] = boolean ? 0xFF : 0;
	return( swrite( stream, buffer, 3 ) );
	}

/* Write an octet string */

int writeOctetString( STREAM *stream, const BYTE *string, const int length,
					  const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( string, length ) );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_OCTETSTRING : BER_CONTEXT_SPECIFIC | tag );
	writeLength( stream, length );
	return( swrite( stream, string, length ) );
	}

/* Write a character string.  This handles any of the myriad ASN.1 character
   string types.  The handling of the tag works somewhat differently here to
   the usual manner in that since the function is polymorphic, the tag
   defines the character string type and is always used (there's no
   DEFAULT_TAG like the other functions use) */

int writeCharacterString( STREAM *stream, const BYTE *string,
						  const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( string, length ) );
	assert( tag != DEFAULT_TAG );

	writeTag( stream, tag );
	writeLength( stream, length );
	return( swrite( stream, string, length ) );
	}

/* Write a bit string */

int writeBitString( STREAM *stream, const int bitString, const int tag )
	{
	BYTE buffer[ 16 ];
	unsigned int value = 0;
	int data = bitString, noBits = 0, i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( bitString >= 0 );

	/* ASN.1 bitstrings start at bit 0, so we need to reverse the order of
	  the bits before we write them out */
	for( i = 0; i < ( sizeof( int ) > 2 ? 32 : 16 ); i++ )
		{
		/* Update the number of significant bits */
		if( data )
			noBits++;

		/* Reverse the bits */
		value <<= 1;
		if( data & 1 )
			value |= 1;
		data >>= 1;
		}

	/* Write the data as an ASN.1 BITSTRING.  This has the potential to lose
	   some bits on 16-bit systems, but this only applies to the more obscure
	   CMP error codes and it's unlikely too many people will be running a
	   CMP server on a DOS box */
	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? BER_BITSTRING : \
				  BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 1 + ( ( noBits + 7 ) >> 3 );
	buffer[ 2 ] = ~( ( noBits - 1 ) & 7 ) & 7;
#if UINT_MAX > 0xFFFF
	buffer[ 3 ] = value >> 24;
	buffer[ 4 ] = value >> 16;
	buffer[ 5 ] = value >> 8;
	buffer[ 6 ] = value;
#else
	buffer[ 3 ] = value >> 8;
	buffer[ 4 ] = value;
#endif /* 16 vs.32-bit systems */
	return( swrite( stream, buffer, 3 + ( ( noBits + 7 ) >> 3 ) ) );
	}

/* Write a canonical UTCTime and GeneralizedTime value */

int writeUTCTime( STREAM *stream, const time_t timeVal, const int tag )
	{
	struct tm *timeInfo = gmtime( &timeVal );
	char buffer[ 20 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal > 0 );

	/* Sanity check on input data */
	if( timeInfo == NULL || timeInfo->tm_year <= 90 )
		{
		assert( NOTREACHED );
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Print the main time fields */
	sPrintf( buffer + 2, "%02d%02d%02d%02d%02d%02dZ", 
			 timeInfo->tm_year % 100, timeInfo->tm_mon + 1, 
			 timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min, 
			 timeInfo->tm_sec );

	/* Write the time string */
	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? \
				  BER_TIME_UTC : BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 13;
	return( swrite( stream, buffer, 15 ) );
	}

int writeGeneralizedTime( STREAM *stream, const time_t timeVal, const int tag )
	{
	struct tm *timeInfo = gmtime( &timeVal );
	char buffer[ 20 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal > 0 );

	/* Sanity check on input data */
	if( timeInfo == NULL || timeInfo->tm_year <= 90 )
		{
		assert( NOTREACHED );
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Print the main time fields */
	sPrintf( buffer + 2, "%04d%02d%02d%02d%02d%02dZ", 
			 timeInfo->tm_year + 1900, timeInfo->tm_mon + 1, 
			 timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min, 
			 timeInfo->tm_sec );

	/* Write the time string */
	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? \
				  BER_TIME_GENERALIZED : BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 15;
	return( swrite( stream, buffer, 17 ) );
	}

/****************************************************************************
*																			*
*							ASN.1 Input Routines							*
*																			*
****************************************************************************/

/* Check for constructed end-of-item octets */

int checkEOC( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the tag and check for an EOC octet pair */
	if( peekTag( stream ) != BER_EOC )
		return( FALSE );
	readTag( stream );
	if( sgetc( stream ) )
		{
		/* After finding an EOC tag we need to have a length of zero */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	return( TRUE );
	}

/* Read the length octets for an ASN.1 data type, with special-case handling
   for long and short lengths and how indefinite-length encodings are handled.
   The short-length read is limited to 32K, the limit for most PKI data and 
   one that doesn't cause type conversion problems on systems where 
   sizeof( int ) != sizeof( long ).  If the caller indicates that indefinite 
   lengths are OK, we return OK_SPECIAL if we encounter one.  Long length 
   reads always allow indefinite lengths since these are quite likely for 
   large objects */

typedef enum {
	READLENGTH_NONE,		/* No length read behaviour */
	READLENGTH_SHORT,		/* Short length, no indef.allowed */
	READLENGTH_SHORT_INDEF,	/* Short length, indef.to OK_SPECIAL */
	READLENGTH_LONG_INDEF,	/* Long length, indef.to OK_SPECIAL */
	READLENGTH_LAST			/* Last possible read type */
	} READLENGTH_TYPE;

static long readLengthValue( STREAM *stream, const READLENGTH_TYPE readType )
	{
	BYTE buffer[ 8 ], *bufPtr = buffer;
	BOOLEAN shortLen = ( readType == READLENGTH_SHORT || \
						 readType == READLENGTH_SHORT_INDEF );
	long length = 0;
	int noLengthOctets, status;

	/* Read the first byte of length data.  If it's a short length, we're
	   done */
	length = sgetc( stream );
	if( cryptStatusError( length ) || !( length & 0x80 ) )
		return( length );

	/* Read the actual length octets.  Since BER lengths can be encoded in
	   peculiar ways (at least one text uses a big-endian 32-bit encoding 
	   for everything) we allow up to 8 bytes of non-DER length data, but
	   only the last 2 or 4 of these can be nonzero */
	noLengthOctets = length & 0x7F;
	if( noLengthOctets <= 0 )
		{
		/* If indefinite lengths aren't allowed, signal an error */
		if( readType == READLENGTH_SHORT )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}

		/* Indefinite length encoding, warn the caller */
		assert( readType == READLENGTH_SHORT_INDEF || \
				readType == READLENGTH_LONG_INDEF );
		return( OK_SPECIAL );
		}
	if( noLengthOctets > 8 )
		status = CRYPT_ERROR_BADDATA;
	else
		status = sread( stream, buffer, noLengthOctets );
	if( cryptStatusError( status ) )
		{
		sSetError( stream, status );
		return( status );
		}
	if( !buffer[ 0 ] )
		{
		int i;

		/* Oddball length encoding with leading zero(es) */
		for( i = 0; i < noLengthOctets && !buffer[ i ]; i++ );
		if( noLengthOctets - i > ( shortLen ? 2 : 4 ) )
			{
			/* > 32-bit length, this should never happen */
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		if( i >= noLengthOctets )
			return( 0 );		/* Very broken encoding of a zero length */
		noLengthOctets -= i;
		bufPtr += i;			/* Skip leading zero(es) */
		}
	else
		{
		if( shortLen && noLengthOctets > 2 )
			{
			sSetError( stream, CRYPT_ERROR_OVERFLOW );
			return( CRYPT_ERROR_OVERFLOW );
			}
		if( noLengthOctets > 4 )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}
	length = 0;
	while( noLengthOctets-- > 0 )
		length = length << 8 | *bufPtr++;
	if( shortLen )
		{
		if( length & 0xFFFF8000UL )
			{
			/* Length must be < 32K for short lengths */
			sSetError( stream, CRYPT_ERROR_OVERFLOW );
			return( CRYPT_ERROR_OVERFLOW );
			}
		}
	else
		if( ( length & 0x80000000UL ) || length > MAX_INTLENGTH )
			{
			/* Length must be < MAX_INTLENGTH for standard data */
			sSetError( stream, CRYPT_ERROR_OVERFLOW );
			return( CRYPT_ERROR_OVERFLOW );
			}
	if( length < 0 )
		{
		/* Shouldn't happen since the above check catches it, but we check
		   again just to be safe */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	return( length );
	}

/* Read a constrained-length data value, used by several routines */

static int readConstrainedData( STREAM *stream, BYTE *buffer, 
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

/* Read a short (<= 256 bytes) raw object without decoding it.  This is used
   to read short data blocks like object identifiers, which are only ever
   handled in encoded form */

int readRawObjectTag( STREAM *stream, BYTE *buffer, int *bufferLength,
					  const int maxLength, const int expectedTag )
	{
	int length, offset = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bufferLength, sizeof( int ) ) );
	assert( maxLength > 0 );

	/* Clear return value */
	if( buffer != NULL )
		*buffer = '\0';
	*bufferLength = 0;

	/* Read the identifier field and length.  Since we need to remember each
	   byte as it's read we can't just call readLengthValue() for the length, 
	   but since we only need to handle lengths that can be encoded in one 
	   or two bytes this isn't much of a problem */
	if( expectedTag != NO_TAG )
		{
		const int tag = readTag( stream );

		if( expectedTag != CRYPT_UNUSED && expectedTag != tag )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		if( buffer != NULL )
			buffer[ offset++ ] = tag;
		}
	length = sgetc( stream );
	if( buffer != NULL )
		buffer[ offset++ ] = length;
	if( length & 0x80 )
		{
		length &= 0x7F;
		if( length <= 0 || length > 1 )
			{
			/* If the object is indefinite-length or longer than 256 bytes, 
			   we don't want to handle it */
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		length = sgetc( stream );
		if( buffer != NULL )
			buffer[ offset++ ] = length;
		}
	if( cryptStatusError( length ) )
		return( length );

	/* Read in the rest of the data, adjusting the length for the header data
	   that we've already read */
	status = readConstrainedData( stream, buffer + offset, bufferLength, 
								  length, maxLength - offset );
	if( cryptStatusOK( status ) )
		*bufferLength += offset;
	return( status );
	}

/* Read a (short) numeric value, used by several routines */

static int readNumeric( STREAM *stream, long *value )
	{
	BYTE buffer[ 8 ], *bufPtr = buffer;
	int length, status;

	/* Clear return value */
	if( value != NULL )
		*value = 0L;

	/* Read the length field and make sure that it's a short value, and read 
	   the data */
	length = sgetc( stream );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	if( length > 4 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) || value == NULL )
		return( status );
	while( length-- > 0 )
		*value = ( *value << 8 ) | *bufPtr++;

	return( CRYPT_OK );
	}

/* Read a large integer value */

int readIntegerTag( STREAM *stream, BYTE *integer, int *integerLength,
					const int maxLength, const int tag )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( maxLength > 0 );

	/* Clear return value */
	if( integer != NULL )
		*integer = '\0';
	if( integerLength != NULL )
		*integerLength = 0;

	/* Read the identifier field if necessary and the length */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_INTEGER ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */

	/* ASN.1 encoded values are signed while the internal representation is
	   unsigned, so we skip any leading zero bytes needed to encode a value
	   that has the high bit set */
	if( sPeek( stream ) == 0 )
		{
		sgetc( stream );
		length--;			/* Skip the zero byte */
		}
	if( length == 0 )
		return( CRYPT_OK );	/* Zero value */

	/* Read in the numeric value, limiting the size to the maximum buffer 
	   size.  This is safe because the only situation where this can occur 
	   is when reading some blob (whose value we don't care about) dressed 
	   up as an integer rather than for any real integer */
	return( readConstrainedData( stream, integer, integerLength, length, 
								 maxLength ) );
	}

/* Read a bignum integer value */

int readBignumTag( STREAM *stream, void *bignum, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	/* Read the identifier field if necessary and the length */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_INTEGER ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */

	/* ASN.1 encoded values are signed while the internal representation is
	   unsigned, so we skip any leading zero bytes needed to encode a value
	   that has the high bit set */
	if( sPeek( stream ) == 0 )
		{
		sgetc( stream );
		length--;			/* Skip the zero byte */
		}
	if( length == 0 )
		return( CRYPT_OK );	/* Zero value */

	/* Read the value into a fixed buffer */
	if( length > CRYPT_MAX_PKCSIZE )
		{
		sSetError( stream, CRYPT_ERROR_OVERFLOW );
		return( sGetStatus( stream ) );
		}
	status = sread( stream, buffer, length );
	if( !cryptStatusError( status ) )
		{
		if( BN_bin2bn( buffer, length, bignum ) == NULL )
			{
			sSetError( stream, CRYPT_ERROR_MEMORY );
			status = CRYPT_ERROR_MEMORY;
			}
		zeroise( buffer, CRYPT_MAX_PKCSIZE );
		}
	return( status );
	}

/* Read a universal type and discard it (used to skip unknown or unwanted
   types) */

int readUniversalData( STREAM *stream )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	return( sSkip( stream, length ) );
	}

int readUniversal( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	readTag( stream );
	return( readUniversalData( stream ) );
	}

/* Read a short integer value */

int readShortIntegerTag( STREAM *stream, long *value, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( value != NULL )
		*value = 0L;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_INTEGER ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Read the numeric field */
	return( readNumeric( stream, value ) );
	}

/* Read an enumerated value.  This is encoded like an ASN.1 integer so we
   just read it as such */

int readEnumeratedTag( STREAM *stream, int *enumeration, const int tag )
	{
	long value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( enumeration != NULL )
		*enumeration = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_ENUMERATED ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Read the numeric field */
	status = readNumeric( stream, &value );
	if( cryptStatusOK( status ) && enumeration != NULL )
		*enumeration = ( int ) value;
	return( status );
	}

/* Read a null value */

int readNullTag( STREAM *stream, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the identifier if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_NULL ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Skip the length octet */
	if( sgetc( stream ) )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	return( sGetStatus( stream ) );
	}

/* Read a boolean value */

int readBooleanTag( STREAM *stream, BOOLEAN *boolean, const int tag )
	{
	int value;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( boolean != NULL )
		*boolean = FALSE;

	/* Read the identifier if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_BOOLEAN ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Skip the length octet and read the boolean value */
	if( sgetc( stream ) != 1 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}
	value = sgetc( stream );
	if( !cryptStatusError( value ) && boolean != NULL )
		*boolean = value ? TRUE : FALSE;
	return( sGetStatus( stream ) );
	}

/* Read an octet string value */

int readOctetStringTag( STREAM *stream, BYTE *string, int *stringLength,
						const int maxLength, const int tag )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( maxLength > 0 );

	/* Clear return value */
	if( string != NULL )
		{
		*string = '\0';
		*stringLength = 0;
		}

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_OCTETSTRING ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Now read in the string, limiting the size to the maximum buffer size */
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	return( readConstrainedData( stream, string, stringLength, length, 
								 maxLength ) );
	}

/* Read a character string.  This handles any of the myriad ASN.1 character
   string types.  The handling of the tag works somewhat differently here to
   the usual manner in that since the function is polymorphic, the tag
   defines the character string type and is always used (there's no
   NO_TAG or DEFAULT_TAG like the other functions use).  This works because
   the plethora of string types means that the higher-level routines that 
   read them invariably have to sort out the valid tag types themselves */

int readCharacterString( STREAM *stream, BYTE *string, int *stringLength,
						 const int maxLength, const int tag )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( maxLength > 0 );
	assert( tag != NO_TAG && tag != DEFAULT_TAG );

	/* Clear return value */
	if( string != NULL )
		{
		*string = '\0';
		*stringLength = 0;
		}

	/* Read the identifier field if necessary */
	if( readTag( stream ) != tag )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}

	/* Now read in the string, limiting the size to the maximum buffer size */
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	return( readConstrainedData( stream, string, stringLength, length, 
								 maxLength ) );
	}

/* Read a bit string */

int readBitStringTag( STREAM *stream, int *bitString, const int tag )
	{
	unsigned int data, mask = 0x80;
	int length, flag = 1, value = 0, noBits, i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	/* Clear return value */
	if( bitString != NULL )
		*bitString = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_BITSTRING ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		}

	/* Make sure that we have a bitstring with between 0 and sizeof( int ) 
	   bits.  This isn't as machine-dependant as it seems, the only place 
	   where bit strings longer than one or two bytes are used is with the 
	   more obscure CMP error subcodes that just provide further information
	   above and beyond the main error code and text message, so we provide
	   the extra information if the machine architecture can handle it and
	   skip it otherwise */
	length = sgetc( stream ) - 1;
	noBits = sgetc( stream );
	if( length < 0 || length > sizeof( int ) || noBits < 0 || noBits > 7 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	if( length == 0 )
		return( CRYPT_OK );		/* Zero value */
	noBits = ( length * 8 ) - noBits;

	/* ASN.1 bitstrings start at bit 0, so we need to reverse the order of
	   the bits */
	data = sgetc( stream );
	for( i = noBits - 8; i > 0; i -= 8 )
		{
		data = ( data << 8 ) | sgetc( stream );
		mask <<= 8;
		}
	for( i = 0; i < noBits; i++ )
		{
		if( data & mask )
			value |= flag;
		flag <<= 1;
		data <<= 1;
		}
	if( bitString != NULL )
		*bitString = value;

	return( sGetStatus( stream ) );
	}

/* Read a UTCTime and GeneralizedTime value */

static int getDigits( const BYTE *bufPtr )
	{
	int result, ch = *bufPtr++;

	if( ch < '0' || ch > '9' )
		return( -1 );
	result = ( ch - '0' ) * 10;
	ch = *bufPtr++;
	if( ch < '0' || ch > '9' )
		return( -1 );
	return( result + ( ch - '0' ) );
	}

static int readTime( STREAM *stream, time_t *timePtr, const BOOLEAN isUTCTime )
	{
	BYTE buffer[ 32 ], *bufPtr = buffer;
	struct tm theTime,  *gm_tm;
	time_t utcTime, gmTime;
#if 0
	time_t localTime;
#endif /* 0 */
	int value = 0, length, status;

	/* Read the length field and make sure that it's of the correct size.  
	   There's only one encoding allowed although in theory the encoded 
	   value could range in length from 11 to 17 bytes for UTCTime and 13 to 
	   19 bytes for GeneralizedTime.  In practice we also have to allow 11-
	   byte UTCTimes since an obsolete encoding rule allowed the time to be 
	   encoded without seconds, and Sweden Post haven't realised that this 
	   has changed yet */
	length = sgetc( stream );
	if( ( isUTCTime && length != 13 && length != 11 ) || \
		( !isUTCTime && length != 15 ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}

	/* Read the encoded time data */
	memset( buffer, 0, 32 );
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Decode the time fields.  Ideally we should use sscanf(), but there
	   are too many dodgy versions of this around */
	memset( &theTime, 0, sizeof( struct tm ) );
	theTime.tm_isdst = -1;		/* Get the system to adjust for DST */
	if( !isUTCTime )
		{
		value = ( getDigits( bufPtr ) - 19 ) * 100;	/* Read the century */
		bufPtr += 2;
		length -= 2;
		}
	theTime.tm_year = getDigits( bufPtr ) + value;
	theTime.tm_mon = getDigits( bufPtr + 2 ) - 1;
	theTime.tm_mday = getDigits( bufPtr + 4 );
	theTime.tm_hour = getDigits( bufPtr + 6 );
	theTime.tm_min = getDigits( bufPtr + 8 );

	/* Read the seconds field if there's one present */
	if( length == 13 )
		{
		theTime.tm_sec = getDigits( bufPtr + 10 );
		if( bufPtr[ 12 ] != 'Z' )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		if( length != 11 || bufPtr[ 10 ] != 'Z' )
			status = CRYPT_ERROR_BADDATA;

	/* Make sure that there were no format errors */
	if( cryptStatusOK( status ) && \
		( theTime.tm_year | theTime.tm_mon | theTime.tm_mday | \
		  theTime.tm_hour | theTime.tm_min | theTime.tm_sec ) < 0 )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sSetError( stream, status );
		return( status );
		}

	/* Finally, convert it to the local time.  Since the UTCTime format
	   doesn't take centuries into account (and you'd think that when the ISO
	   came up with the world's least efficient time encoding format they
	   could have spared another two bytes to fully specify the year), we
	   have to adjust by one century for years < 50 (and hope there aren't
	   any Y2K bugs in mktime()) if the format is UTCTime.  Note that there
	   are some implementations that currently roll over a century from 1970
	   (the Unix/Posix epoch and sort-of ISO/ANSI C epoch although they never
	   come out and say it), but hopefully these will be fixed by 2050.

		"The time is out of joint; o cursed spite,
		 That ever I was born to set it right"	- Shakespeare, "Hamlet" */
	if( isUTCTime && theTime.tm_year < 50 )
		theTime.tm_year += 100;
	utcTime = mktime( &theTime );
	if( utcTime == -1 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Convert the UTC time to local time.  This is complicated by the fact 
	   that although the C standard library can convert from local time -> 
	   UTC, it can't convert the time back, so we calculate the local offset 
	   from UTC and adjust the time as appropriate.  Since we can't assume 
	   that time_t is signed, we have to treat a negative and positive offset 
	   separately.  An extra complication is added by daylight savings time 
	   adjustment, some systems adjust for DST by default, some don't, and 
	   some allow you to set it in the Control Panel so it varies from 
	   machine to machine (thanks Bill!), so we have to make it explicit as 
	   part of the conversion process.  Even this still isn't perfect 
	   because it displays the time adjusted for DST now rather than DST 
	   when the cert was created, however this problem is more or less 
	   undecidable, the code used here has the property that the values for 
	   Windows agree with those for Unix and everything else which is the 
	   main thing */
#if 0							/* Changed 22/10/02 */
	localTime = getTime();
	gm_tm = gmtime( &localTime );
	gm_tm->tm_isdst = -1;		/* Force correct DST adjustment */
	gmTime = mktime( gm_tm );
	if( timePtr != NULL )
		if( localTime < gmTime )
			*timePtr = utcTime - ( gmTime - localTime );
		else
			*timePtr = utcTime + ( localTime - gmTime );
#else
	/* Another attempt: Treat the UTC time as local time (gmtime() always 
	   assumes the input is local time) and covert to GMT and back, which 
	   should give the offset from GMT */
	gm_tm = gmtime( &utcTime );
	gm_tm->tm_isdst = -1;		/* Force correct DST adjustment */
	gmTime = mktime( gm_tm );
	if( timePtr != NULL )
		{
		if( utcTime < gmTime )
			*timePtr = utcTime - ( gmTime - utcTime );
		else
			*timePtr = utcTime +  ( utcTime - gmTime );

		/* This still isn't quite perfect, since it can't handle time at
		   a DST changeover.  This is really a user problem ("Don't do that,
		   then"), but if necessary can be corrected by converting back to
		   GMT as a sanity check and applying a +/- 1 hour correction if 
		   there's a mismatch */
  #if 0
		gm_tm = gmtime( timePtr );
		gm_tm->tm_isdst = -1;
		gmTime = mktime( gm_tm );
		if( gmTime != utcTime )
			{
			*timePtr = ( *timePtr ) + 3600;	/* Try +1 first */
			gm_tm = gmtime( timePtr );
			gm_tm->tm_isdst = -1;
			gmTime = mktime( gm_tm );
			if( gmTime != utcTime )
				/* Nope, use -1 instead */
				*timePtr = ( *timePtr ) -7200;
			}
  #endif /* 0 */
		}
#endif /* 0 */

	return( CRYPT_OK );
	}

int readUTCTimeTag( STREAM *stream, time_t *timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( timeVal != NULL )
		*timeVal = 0;
	
	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_TIME_UTC ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Read the time fields */
	return( readTime( stream, timeVal, TRUE ) );
	}

int readGeneralizedTimeTag( STREAM *stream, time_t *timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( timeVal != NULL )
		*timeVal = 0;
	
	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_TIME_GENERALIZED ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Read the time fields */
	return( readTime( stream, timeVal, FALSE ) );
	}

/****************************************************************************
*																			*
*					Utility Routines for Constructed Objects				*
*																			*
****************************************************************************/

/* Check that a tag for one of the hole types is valid: BIT STRING,
   primtive or constructed OCTET STRING, SEQUENCE, or SET */

#define isValidHoleTag( tag ) \
		( ( tagValue & BER_CLASS_MASK ) != BER_UNIVERSAL || \
		  ( tagValue == BER_BITSTRING || tagValue == BER_OCTETSTRING || \
			tagValue == ( BER_OCTETSTRING | BER_CONSTRUCTED ) || \
			tagValue == BER_SEQUENCE || tagValue == BER_SET ) )

/* Read an encapsulating SEQUENCE or SET or BIT STRING/OCTET STRING hole */

static int readObjectHeader( STREAM *stream, int *length, const int tag,
							 const BOOLEAN isBitString, 
							 const BOOLEAN indefOK )
	{
	int tagValue, dataLength;

	/* Clear return value */
	if( length != NULL )
		*length = 0;

	/* Read the object tag */
	tagValue = readTag( stream );
	if( cryptStatusError( tagValue ) )
		return( tagValue );
	if( tag == ANY_TAG )
		{
		/* Even if we're prepared to accept (almost) any tag, we still have 
		   to check for valid universal tags */
		if( !isValidHoleTag( tagValue ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		if( tagValue != tag )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
	
	/* Read the length.  If the indefiniteOK flag is set of the length is 
	   being ignored by the caller we allow indefinite lengths.  The latter
	   is because it makes handling of infinitely-nested SEQUENCEs and 
	   whatnot easier if we don't have to worry about definite vs. 
	   indefinite-length encoding, and if indefinite lengths really aren't 
	   OK then they'll be picked up when the caller runs into the EOC at the
	   end of the object */
	dataLength = readLengthValue( stream, ( indefOK || length == NULL ) ? \
								  READLENGTH_SHORT_INDEF : READLENGTH_SHORT );
	if( cryptStatusError( dataLength ) )
		{
		/* If we've asked for an indication of indefinite-length values and we
		   got one, convert the length to CRYPT_UNUSED */
		if( indefOK && dataLength == OK_SPECIAL )
			dataLength = CRYPT_UNUSED;
		else
			return( dataLength );
		}

	/* If it's a bit string there's an extra unused-bits count */
	if( isBitString )
		{
		if( dataLength != CRYPT_UNUSED )
			dataLength--;
		if( length != NULL )
			*length = dataLength;
		return( sgetc( stream ) );
		}

	if( length != NULL )
		*length = dataLength;
	return( CRYPT_OK );
	}

int readSequence( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, BER_SEQUENCE, FALSE, FALSE ) );
	}

int readSequenceI( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, BER_SEQUENCE, FALSE, TRUE ) );
	}

int readSet( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, BER_SET, FALSE, FALSE ) );
	}

int readSetI( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, BER_SET, FALSE, TRUE ) );
	}

int readConstructed( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
							  BER_SEQUENCE : MAKE_CTAG( tag ), FALSE, FALSE ) );
	}

int readConstructedI( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
							  BER_SEQUENCE : MAKE_CTAG( tag ), FALSE, TRUE ) );
	}

int readOctetStringHole( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
							  BER_OCTETSTRING : MAKE_CTAG_PRIMITIVE( tag ),
							  FALSE, FALSE ) );
	}

int readBitStringHole( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
							  BER_BITSTRING : MAKE_CTAG_PRIMITIVE( tag ),
							  TRUE, FALSE ) );
	}

int readGenericHole( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readObjectHeader( stream, length, 
							  ( tag == DEFAULT_TAG ) ? ANY_TAG : tag, 
							  FALSE, FALSE ) );
	}

/* Read an abnormally-long encapsulating SEQUENCE or OCTET STRING hole.  
   This is used in place of the usual read in places where potentially huge 
   data quantities would fail the sanity check enforced by standard read.
   This form always allows indefinite lengths, which are likely for large
   objects */

static int readLongObjectHeader( STREAM *stream, long *length, const int tag )
	{
	long dataLength;
	int tagValue;

	if( length != NULL )
		*length = 0;	/* Clear return value */
	tagValue = readTag( stream );
	if( cryptStatusError( tagValue ) )
		return( tagValue );
	if( tag == ANY_TAG )
		{
		/* Even if we're prepared to accept (almost) any tag, we still have 
		   to check for valid universal tags */
		if( !isValidHoleTag( tagValue ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		if( tagValue != tag )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
	dataLength = readLengthValue( stream, READLENGTH_LONG_INDEF );
	if( cryptStatusError( dataLength ) )
		{
		/* We've asked for an indication of indefinite-length values, if we
		   got one convert the length to CRYPT_UNUSED */
		if( dataLength == OK_SPECIAL )
			dataLength = CRYPT_UNUSED;
		else
			return( dataLength );
		}
	if( length != NULL )
		*length = dataLength;

	return( CRYPT_OK );
	}

long readLongSequence( STREAM *stream, long *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readLongObjectHeader( stream, length, BER_SEQUENCE ) );
	}

long readLongConstructed( STREAM *stream, long *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readLongObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
								  BER_SEQUENCE : MAKE_CTAG( tag ) ) );
	}

long readLongGenericHole( STREAM *stream, long *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( readLongObjectHeader( stream, length, 							  
								  ( tag == DEFAULT_TAG ) ? ANY_TAG : tag ) );
	}

/* Write the start of an encapsulating SEQUENCE, SET, or generic tagged
   constructed object.  The difference between writeOctet/BitStringHole() and
   writeGenericHole() is that the octet/bit-string versions create a normal
   or context-specific-tagged string while the generic version creates a 
   pure hole with no processing of tags */

int writeSequence( STREAM *stream, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, BER_SEQUENCE );
	return( writeLength( stream, length ) );
	}

int writeSet( STREAM *stream, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, BER_SET );
	return( writeLength( stream, length ) );
	}

int writeConstructed( STREAM *stream, const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_SEQUENCE : MAKE_CTAG( tag ) );
	return( writeLength( stream, length ) );
	}

int writeOctetStringHole( STREAM *stream, const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_OCTETSTRING : MAKE_CTAG_PRIMITIVE( tag ) );
	return( writeLength( stream, length ) );
	}

int writeBitStringHole( STREAM *stream, const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_BITSTRING : MAKE_CTAG_PRIMITIVE( tag ) );
	writeLength( stream, length + 1 );	/* +1 for bit count */
	return( sputc( stream, 0 ) );
	}

int writeGenericHole( STREAM *stream, const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	writeTag( stream, tag );
	return( writeLength( stream, length ) );
	}

/****************************************************************************
*																			*
*						ASN.1 Encoding/Length Checks						*
*																			*
****************************************************************************/

/* The maximum nesting level for constructed or encapsulated objects (this
   can get surprisingly high for some of the more complex attributes).  This
   value is chosen to pass all normal certs while avoiding stack overflows
   for artificial bad data */

#define MAX_NESTING_LEVEL	50

/* When we parse a nested data object encapsulated within a larger object,
   the length is initially set to a magic value which is adjusted to the
   actual length once we start parsing the object */

#define LENGTH_MAGIC		177545L

/* Current parse state.  This is used to check for potential BIT STRING and
   OCTET STRING targets for OCTET/BIT STRING holes, which are always
   preceded by an AlgorithmIdentifier.  In order to detect these without
   having to know every imaginable AlgorithmIdentifier OID, we check for the
   following sequence of events:

	checkASN1Object								-- SEQUENCE
		checkASN1
			checkASN1Object
				checkPrimitive					-- OID
			checkASN1Object
				checkPrimitive					-- opt.BOOLEAN	  OCTET STRING
				checkPrimitive					-- NULL, or		|
				checkASN1Object					-- SEQUENCE		| BIT STRING
	checkASN1Object
		checkPrimitive							-- OCTET/BIT STRING

   This type of checking is rather awkward in the (otherwise stateless) code,
   but is the only way to be sure that it's safe to try burrowing into an
   OCTET STRING or BIT STRING to try to find encapsulated data, since
   otherwise even with relatively strict checking there's still a very small
   chance that random data will look like a nested object */

typedef enum {
	/* Generic non-state */
	STATE_NONE,

	/* States corresponding to ASN.1 primitives */
	STATE_BOOLEAN, STATE_NULL, STATE_OID, STATE_SEQUENCE,

	/* States corresponding to different parts of a SEQUENCE { OID, optional,
	   OCTET/BIT STRING } sequence */
	STATE_HOLE_OID, STATE_HOLE_BITSTRING, STATE_HOLE_OCTETSTRING,

	/* Error state */
	STATE_ERROR
	} ASN1_STATE;

/* Structure to hold info on an ASN.1 item */

typedef struct {
	int tag;			/* Tag */
	long length;		/* Data length */
	BOOLEAN indefinite;	/* Item has indefinite length */
	int headerSize;		/* Size of tag+length */
	} ASN1_ITEM;

/* Get an ASN.1 object's tag and length */

static int getItem( STREAM *stream, ASN1_ITEM *item )
	{
	int length;

	memset( item, 0, sizeof( ASN1_ITEM ) );
	item->headerSize = 2;
	item->tag = sgetc( stream );
	length = sgetc( stream );
	if( cryptStatusError( length ) )
		return( STATE_ERROR );
	if( length & 0x80 )
		{
		int i;

		length &= 0x7F;
		if( length > 4 )
			/* Object has a bad length field, usually because we've lost sync
			   in the decoder or run into garbage */
			return( STATE_ERROR );
		item->headerSize += length;
		item->length = 0;
		if( !length )
			item->indefinite = TRUE;
		for( i = 0; i < length; i++ )
			item->length = ( item->length << 8 ) | sgetc( stream );
		}
	else
		item->length = length;
	if( item->headerSize < 2 || item->length < 0 )
		return( STATE_ERROR );

	return( sStatusOK( stream ) ? STATE_NONE : STATE_ERROR );
	}

/* Check whether an ASN.1 object is encapsulated inside an OCTET STRING or
   BIT STRING.  After performing the various checks we have to explicitly
   clear the stream error state since the probing for valid data could have
   set the error indicator if nothing valid was found */

static BOOLEAN checkEncapsulation( STREAM *stream, const int length,
								   const BOOLEAN isBitstring,
								   const ASN1_STATE state )
	{
	BOOLEAN isEncapsulated = TRUE;
	long streamPos = stell( stream );
	int tag = peekTag( stream ), innerLength, status;

	/* Perform a quick check to see whether an OCTET STRING or BIT STRING hole
	   is allowed at this point.  A BIT STRING must be preceded by { SEQ, OID,
	   NULL }.  An OCTET STRING must be preceded by { SEQ, OID, {BOOLEAN} } */
	if( ( isBitstring && state != STATE_HOLE_BITSTRING ) ||
		( !isBitstring && ( state != STATE_HOLE_OID && \
							state != STATE_HOLE_OCTETSTRING ) ) )
		return( FALSE );

	/* A BIT STRING that encapsulates something only ever contains
	   { SEQUENCE, sequence_length < length, INTEGER } */
	if( isBitstring )
		{
		/* Make sure that there's a SEQUENCE of a vaguely correct length
		   present */
		status = readSequence( stream, &innerLength );
		if( cryptStatusError( status ) || \
			innerLength < length - 10 || innerLength > length + 10 )
			{
			sClearError( stream );
			sseek( stream, streamPos );
			return( FALSE );
			}
		
		/* Make sure that the first thing inside the SEQUENCE is an
		   INTEGER */
		status = readInteger( stream, NULL, &innerLength, 
							  CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) || \
			innerLength < length - 12 || innerLength > length + 8 )
			isEncapsulated = FALSE;

		sClearError( stream );
		sseek( stream, streamPos );
		return( isEncapsulated );
		}

	/* An OCTET STRING is more complex.  This could encapsulate any of:
		BIT STRING: keyUsage, crlReason, Netscape certType, must be
			<= 16 bits and a valid bitstring.
		GeneralisedTime: invalidityDate: too difficult to identify
			since the obvious check for a valid length will also fail
			invalid-length encodings, missing the very thing we usually
			want to check for.
		IA5String: Netscape extensions, also checked by the context-
			aware higher-level code that knows how long and in what
			format the string should be.
		INTEGER: deltaCRLIndicator, crlNumber, must be <= 16 bits).
		OCTET STRING: keyID, a blob that we don't check.
		OID: holdInstructionCode, which is difficult to identify and
			will be checked by the context-aware extension read code
			anyway.
		SEQUENCE: most extensions, a bit difficult to check but for
			now we make sure that the length is roughly right */
	switch( tag )
		{
		case BER_BITSTRING:
			status = readBitStringHole( stream, &innerLength, DEFAULT_TAG );
			if( cryptStatusError( status ) || \
				innerLength < 0 || innerLength > 2 )
				isEncapsulated = FALSE;
			else
				{
				int ch = sgetc( stream );

				if( ch < 0 || ch > 7 )
					isEncapsulated = FALSE;
				}
			break;

		case BER_INTEGER:
			status = readInteger( stream, NULL, &innerLength, 
								  CRYPT_MAX_PKCSIZE );
			if( cryptStatusError( status ) || \
				innerLength < 0 || innerLength > 2 )
				isEncapsulated = FALSE;
			break;

		case BER_SEQUENCE:
			status = readSequence( stream, &innerLength );
			if( cryptStatusError( status ) || \
				innerLength < length - 10 || innerLength > length + 10 )
				isEncapsulated = FALSE;
			break;

		default:
			isEncapsulated = FALSE;
		}
	sClearError( stream );
	sseek( stream, streamPos );
	return( isEncapsulated );
	}

/* Check a primitive ASN.1 object */

static ASN1_STATE checkASN1( STREAM *stream, long length,
							 const int isIndefinite, const int level,
							 ASN1_STATE state, 
							 const BOOLEAN checkDataElements );

static ASN1_STATE checkPrimitive( STREAM *stream, const ASN1_ITEM *item,
								  const int level, const ASN1_STATE state )
	{
	int length = ( int ) item->length, ch, i;

	/* In theory only NULL and EOC elements are allowed to have a zero 
	   length, but some broken implementations (Netscape, Van Dyke) encode
	   numeric zero values as a zero-length element so we have to accept 
	   these as well */
	if( !item->length && item->tag != BER_NULL && \
						 item->tag != BER_RESERVED && \
						 item->tag != BER_INTEGER )
		return( STATE_ERROR );

	/* Perform a general check that everything is OK.  We don't check for 
	   invalid content except where it would impede decoding of the data in
	   order to avoid failing on all of the broken certs out there */
	switch( item->tag )
		{
		case BER_BOOLEAN:
			sgetc( stream );
			return( STATE_BOOLEAN );

		case BER_INTEGER:
		case BER_ENUMERATED:
			if( length > 0 )	/* May be encoded as a zero-length value */
				sSkip( stream, length );
			return( STATE_NONE );

		case BER_BITSTRING:
			/* Check the number of unused bits */
			ch = sgetc( stream );
			length--;
			if( ch < 0 || ch > 7 )
				/* Invalid number of unused bits */
				return( STATE_ERROR );

			/* If it's short enough to be a bit flag, it's just a sequence 
			   of bits */
			if( length <= 4 )
				{
				if( length )
					sSkip( stream, length );
				return( STATE_NONE );
				}
			/* Fall through */

		case BER_OCTETSTRING:
			/* If it's something encapsulated inside the string, handle it
			   as a constructed item */
			if( checkEncapsulation( stream, length, 
					( item->tag == BER_BITSTRING ) ? TRUE : FALSE, state ) )
				{
				ASN1_STATE octetState;

				octetState = checkASN1( stream, length, item->indefinite,
										level + 1, STATE_NONE, TRUE );
				return( ( octetState == STATE_ERROR ) ? \
						STATE_ERROR : STATE_NONE );
				}

			/* Skip the data */
			sSkip( stream, length );
			return( STATE_NONE );

		case BER_OBJECT_IDENTIFIER:
			if( length > MAX_OID_SIZE - 2 )
				/* Total OID size (including tag and length, since they're 
				   treated as a blob) should be less than a sane limit */
				return( STATE_ERROR );

			/* At this point we could check for obsolete and deprecated OIDs,
			   but this will be caught later on anyway */
			sSkip( stream, length );
			return( STATE_OID );

		case BER_RESERVED:
			break;					/* EOC */

		case BER_NULL:
			return( STATE_NULL );

		case BER_STRING_BMP:
		case BER_STRING_GENERAL:	/* Produced by Entrust software */
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_T61:
		case BER_STRING_UTF8:
			sSkip( stream, length );
			return( STATE_NONE );

		case BER_TIME_UTC:
		case BER_TIME_GENERALIZED:
			if( item->tag == BER_TIME_GENERALIZED )
				{
				if( length != 15 )
					return( STATE_ERROR );
				}
			else
				if( length != 11 && length != 13 )
					return( STATE_ERROR );
			for( i = 0; i < length; i++ )
				{
				ch = sgetc( stream );
				if( ( ch < '0' || ch > '9' ) && ch != 'Z' )
					return( STATE_ERROR );
				}
			return( STATE_NONE );

		default:
			/* Disallowed or unrecognised primitive */
			return( STATE_ERROR );
		}

	return( STATE_NONE );
	}

/* Check a single ASN.1 object */

static ASN1_STATE checkASN1object( STREAM *stream, const ASN1_ITEM *item,
								   const int level, const ASN1_STATE state,
								   const BOOLEAN checkDataElements )
	{
	ASN1_STATE newState;

	/* Perform a sanity check */
	if( ( item->tag != BER_NULL ) && ( item->length < 0 ) )
		/* Object has a bad length field, usually because we've lost sync in 
		   the decoder or run into garbage */
		return( STATE_ERROR );

	/* If we're checking data elements, check the contents for validity */
	if( checkDataElements && ( item->tag & BER_CLASS_MASK ) == BER_UNIVERSAL )
		{
		/* If it's constructed, parse the nested object(s) */
		if( ( item->tag & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			return( checkASN1( stream, item->length, item->indefinite,
							   level + 1, ( item->tag == BER_SEQUENCE ) ? \
							   STATE_SEQUENCE : STATE_NONE, TRUE ) );

		/* It's primitive, check the primitive element with optional state
		   update: SEQ + OID -> HOLE_OID; OID + NULL | BOOLEAN -> HOLE_OID */
		newState = checkPrimitive( stream, item, level + 1, state );
		if( state == STATE_SEQUENCE && newState == STATE_OID )
			return( STATE_HOLE_OID );
		if( state == STATE_HOLE_OID )
			{
			if( newState == STATE_NULL )
				return( STATE_HOLE_BITSTRING );
			if( newState == STATE_BOOLEAN )
				return( STATE_HOLE_OCTETSTRING );
			}
		return( ( newState == STATE_ERROR ) ? STATE_ERROR : STATE_NONE );
		}

	/* If we're interested in the data elements and the item has a definite
	   length, skip over it and continue */
	if( !checkDataElements && item->length > 0 )
		{
		sSkip( stream, item->length );
		return( STATE_NONE );
		}

	/* If it's constructed, check the various fields in it */
	if( item->length > 0 || item->indefinite )
		{
		/* If it's constructed, parse the nested object(s) */
		if( ( item->tag & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			{
			newState = checkASN1( stream, item->length, item->indefinite,
								  level + 1, STATE_NONE, checkDataElements );
			return( ( newState == STATE_ERROR ) ? \
					STATE_ERROR : STATE_NONE );
			}

		/* This could be anything */
		if( item->length > 0 )
			sSkip( stream, item->length );
		return( STATE_NONE );
		}

	/* At this point we have a zero-length object that should be an error,
	   however PKCS #10 has the attribute-encoding problem that produces
	   these objects so we can't complain about them */
	return( STATE_NONE );
	}

/* Check a complex ASN.1 object */

static ASN1_STATE checkASN1( STREAM *stream, long length, const int isIndefinite,
							 const int level, ASN1_STATE state,
							 const BOOLEAN checkDataElements )
	{
	ASN1_ITEM item;
	long lastPos = stell( stream );
	BOOLEAN seenEOC = FALSE;
	ASN1_STATE status;

	/* Sanity-check the nesting level */
	if( level > MAX_NESTING_LEVEL )
		return( STATE_ERROR );

	/* Special-case for zero-length objects */
	if( !length && !isIndefinite )
		return( STATE_NONE );

	while( ( status = getItem( stream, &item ) ) == STATE_NONE )
		{
		/* If the length isn't known and the item has a definite length, set
		   the length to the item's length */
		if( length == LENGTH_MAGIC && !item.indefinite )
			length = item.headerSize + item.length;

		/* Check whether this is an EOC for an indefinite item */
		if( !item.indefinite && item.tag == BER_RESERVED )
			seenEOC = TRUE;
		else
			{
			state = checkASN1object( stream, &item, level + 1, state, 
									 checkDataElements );
			if( state == STATE_ERROR || sGetStatus( stream ) != CRYPT_OK )
				return( STATE_ERROR );
			}

		/* If it was an indefinite-length object (no length was ever set) and
		   we've come back to the top level, exit */
		if( length == LENGTH_MAGIC )
			return( 0 );

		length -= stell( stream ) - lastPos;
		lastPos = stell( stream );
		if( isIndefinite )
			{
			if( seenEOC )
				return( STATE_NONE );
			}
		else
			if( length <= 0 )
				return( ( length < 0 ) ? STATE_ERROR : state );
		}

	return( ( status == STATE_NONE ) ? STATE_NONE : STATE_ERROR );
	}

/* Check the encoding of a complete object and determine its length */

int checkObjectEncoding( const void *objectPtr, const int objectLength )
	{
	STREAM stream;
	ASN1_STATE state;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	state = checkASN1( &stream, LENGTH_MAGIC, FALSE, 1, STATE_NONE, TRUE );
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( ( state == STATE_ERROR ) ? CRYPT_ERROR_BADDATA : length );
	}

/* Recursively dig into an ASN.1 object as far as we need to to determine 
   its length */

static long findObjectLength( STREAM *stream, const BOOLEAN isLongObject )
	{
	const long startPos = stell( stream );
	long length;

	/* Try for a definite length */
	readTag( stream );
	length = readLengthValue( stream, isLongObject ? READLENGTH_LONG_INDEF : \
													 READLENGTH_SHORT_INDEF );
	if( cryptStatusError( length ) && length != OK_SPECIAL )
		return( length );

	/* If it's an indefinite-length object, burrow down into it to find its 
	   actual length */
	if( length == OK_SPECIAL )
		{
		sseek( stream, startPos );
		length = checkASN1( stream, LENGTH_MAGIC, FALSE, 1, STATE_NONE, FALSE );
		if( length == STATE_ERROR )
			return( CRYPT_ERROR_BADDATA );
		length = stell( stream ) - startPos;
		}
	else
		/* It's a definite-length object, add the size of the tag+length */
		length += stell( stream ) - startPos;
	sseek( stream, startPos );
	return( length );
	}

int getStreamObjectLength( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( findObjectLength( stream, FALSE ) );
	}

int getObjectLength( const void *objectPtr, const int objectLength )
	{
	STREAM stream;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	length = findObjectLength( &stream, FALSE );
	sMemDisconnect( &stream );

	return( length );
	}

long getLongObjectLength( const void *objectPtr, const long objectLength )
	{
	STREAM stream;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	length = findObjectLength( &stream, TRUE );
	sMemDisconnect( &stream );

	return( length );
	}
