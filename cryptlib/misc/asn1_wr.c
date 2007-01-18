/****************************************************************************
*																			*
*								ASN.1 Write Routines						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Calculate the size of the encoded length octets */

static int calculateLengthSize( const long length )
	{
	assert( length >= 0 );

	/* Use the short form of the length octets if possible */
	if( length <= 0x7F )
		return( 1 );

	/* Use the long form of the length octets, a length-of-length followed 
	   by an 8, 16, 24, or 32-bit length.  We order the comparisons by 
	   likelihood of occurrence, shorter lengths are far more common than 
	   longer ones */
	if( length <= 0xFF )
		return( 1 + 1 );
	if( length <= 0xFFFFL )
		return( 1 + 2 );
	return( 1 + ( ( length > 0xFFFFFFL ) ? 4 : 3 ) );
	}

/* Write the length octets for an ASN.1 item */

static int writeLength( STREAM *stream, const long length )
	{
	BYTE buffer[ 8 + 8 ];
	const int noLengthOctets = ( length <= 0xFF ) ? 1 : \
							   ( length <= 0xFFFFL ) ? 2 : \
							   ( length <= 0xFFFFFFL ) ? 3 : 4;
	int bufPos = 1;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 );

	/* Sanity-check to catch bad length calculations */
	if( length < 0 )
		{
		assert( NOTREACHED );
		return( sSetError( stream, CRYPT_ERROR_INTERNAL ) );
		}

	/* Use the short form of the length octets if possible */
	if( length <= 0x7F )
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

/* Write a (non-bignum) numeric value, used by several routines.  The 
   easiest way to do this is to encode the bytes starting from the LSB
   and then output them in reverse order to get a big-endian encoding */

static int writeNumeric( STREAM *stream, const long integer )
	{
	BYTE buffer[ 16 + 8 ];
	long intValue = integer;
	int length = 0, i, iterationCount = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer >= 0 );

	/* The value 0 is handled specially */
	if( intValue == 0 )
		return( swrite( stream, "\x01\x00", 2 ) );

	/* Assemble the encoded value in little-endian order */
	if( intValue > 0 )
		{
		while( intValue > 0 && \
			   iterationCount++ < FAILSAFE_ITERATIONS_SMALL )
			{
			buffer[ length++ ] = intValue & 0xFF;
			intValue >>= 8;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_SMALL )
			retIntError();

		/* Make sure that we don't inadvertently set the sign bit if the 
		   high bit of the value is set */
		if( buffer[ length - 1 ] & 0x80 )
			buffer[ length++ ] = 0x00;
		}
	else
		{
		/* Write a negative integer values.  This code is never executed, 
		   it's present only in case it's ever needed in the future */
		do
			{
			buffer[ length++ ] = intValue & 0xFF;
			intValue >>= 8;
			}
		while( intValue != -1 && length < sizeof( int ) && \
			   iterationCount++ < FAILSAFE_ITERATIONS_SMALL );
		if( iterationCount >= FAILSAFE_ITERATIONS_SMALL )
			retIntError();

		/* Make sure that we don't inadvertently clear the sign bit if the 
		   high bit of the value is clear */
		if( !( buffer[ length - 1 ] & 0x80 ) )
			buffer[ length++ ] = 0xFF;
		}

	/* Output the value in reverse (big-endian) order */
	sputc( stream, length );
	for( i = length - 1; i > 0; i-- )
		sputc( stream, buffer[ i ] );
	return( sputc( stream, buffer[ 0 ] ) );
	}

/****************************************************************************
*																			*
*								Sizeof Routines								*
*																			*
****************************************************************************/

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

#ifdef USE_PKC

/* Determine the size of a bignum.  When we're writing these we can't use 
   sizeofObject() directly because the internal representation is unsigned 
   whereas the encoded form is signed */

int signedBignumSize( const void *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	return( BN_num_bytes( bignum ) + BN_high_bit( ( BIGNUM * ) bignum ) );
	}
#endif /* USE_PKC */

/****************************************************************************
*																			*
*					Write Routines for Primitive Objects					*
*																			*
****************************************************************************/

/* Write a short/large/bignum integer value */

int writeShortInteger( STREAM *stream, const long integer, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer >= 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );
	return( writeNumeric( stream, integer ) );
	}

int writeInteger( STREAM *stream, const BYTE *integer,
				  const int integerLength, const int tag )
	{
	const BOOLEAN leadingZero = integerLength && ( *integer & 0x80 ) ? 1 : 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( integer, integerLength ) );
	assert( integerLength > 0 );

	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );
	writeLength( stream, integerLength + leadingZero );
	if( leadingZero )
		sputc( stream, 0 );
	return( swrite( stream, integer, integerLength ) );
	}

#ifdef USE_PKC

int writeBignumTag( STREAM *stream, const void *bignum, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( !BN_is_zero( ( BIGNUM * ) bignum ) );

	/* If it's a dummy write, don't go through the full encoding process.
	   This optimisation both speeds things up and reduces unnecessary
	   writing of key data to memory */
	if( sIsNullStream( stream ) )
		return( sSkip( stream, sizeofBignum( bignum ) ) );

	length = BN_bn2bin( ( BIGNUM * ) bignum, buffer );
	status = writeInteger( stream, buffer, length, tag );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}
#endif /* USE_PKC */

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
	BYTE buffer[ 8 + 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? \
				  BER_NULL : BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 0;
	return( swrite( stream, buffer, 2 ) );
	}

/* Write a boolean value */

int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag )
	{
	BYTE buffer[ 8 + 8 ];

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
	assert( tag > 0 );

	writeTag( stream, tag );
	writeLength( stream, length );
	return( swrite( stream, string, length ) );
	}

/* Write a bit string */

int writeBitString( STREAM *stream, const int bitString, const int tag )
	{
	BYTE buffer[ 16 + 8 ];
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

static int writeTime( STREAM *stream, const time_t timeVal, const int tag,
					  const BOOLEAN isUTCTime )
	{
	struct tm timeInfo, *timeInfoPtr = &timeInfo;
	char buffer[ 20 + 8 ];
	const int length = isUTCTime ? 13 : 15;

	/* Sanity check the input data */
	timeInfoPtr = gmTime_s( &timeVal, timeInfoPtr );
	if( timeInfoPtr == NULL || timeInfoPtr->tm_year <= 90 )
		{
		assert( NOTREACHED );
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}

	buffer[ 0 ] = ( tag != DEFAULT_TAG ) ? BER_CONTEXT_SPECIFIC | tag : \
				  isUTCTime ? BER_TIME_UTC : BER_TIME_GENERALIZED;
	buffer[ 1 ] = length;
	if( isUTCTime )
		sPrintf_s( buffer + 2, 16, "%02d%02d%02d%02d%02d%02dZ", 
				   timeInfoPtr->tm_year % 100, timeInfoPtr->tm_mon + 1, 
				   timeInfoPtr->tm_mday, timeInfoPtr->tm_hour, 
				   timeInfoPtr->tm_min, timeInfoPtr->tm_sec );
	else
		sPrintf_s( buffer + 2, 16, "%04d%02d%02d%02d%02d%02dZ", 
				   timeInfoPtr->tm_year + 1900, timeInfoPtr->tm_mon + 1, 
				   timeInfoPtr->tm_mday, timeInfoPtr->tm_hour, 
				   timeInfoPtr->tm_min, timeInfoPtr->tm_sec );
	return( swrite( stream, buffer, length + 2 ) );
	}

int writeUTCTime( STREAM *stream, const time_t timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal > 0 );

	return( writeTime( stream, timeVal, tag, TRUE ) );
	}

int writeGeneralizedTime( STREAM *stream, const time_t timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal > 0 );

	return( writeTime( stream, timeVal, tag, FALSE) );
	}

/****************************************************************************
*																			*
*					Write Routines for Constructed Objects					*
*																			*
****************************************************************************/

/* Write the start of an encapsulating SEQUENCE, SET, or generic tagged
   constructed object.  The difference between writeOctet/BitStringHole() and
   writeGenericHole() is that the octet/bit-string versions create a normal
   or context-specific-tagged primitive string while the generic version 
   creates a pure hole with no processing of tags */

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
