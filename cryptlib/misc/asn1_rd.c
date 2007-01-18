/****************************************************************************
*																			*
*								ASN.1 Read Routines							*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#include <ctype.h>
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

/* When specifying a tag, we can use either the default tag for the object
   (given with DEFAULT_TAG) or a special-case tag.  The following macro
   selects the correct value.  Since these are all primitive objects, we
   force the tag type to a primitive tag */

#define selectTag( tag, defaultTag )	\
		( ( ( tag ) == DEFAULT_TAG ) ? ( defaultTag ) : \
									   ( MAKE_CTAG_PRIMITIVE( tag ) ) )

/* Read the length octets for an ASN.1 data type, with special-case handling
   for long and short lengths and indefinite-length encodings.  The short-
   length read is limited to 32K, the limit for most PKI data and one that 
   doesn't cause type conversion problems on systems where sizeof( int ) != 
   sizeof( long ).  If the caller indicates that indefinite lengths are OK, 
   we return OK_SPECIAL if we encounter one.  Long length reads always allow 
   indefinite lengths since these are quite likely for large objects */

typedef enum {
	READLENGTH_NONE,		/* No length read behaviour */
	READLENGTH_SHORT,		/* Short length, no indef.allowed */
	READLENGTH_SHORT_INDEF,	/* Short length, indef.to OK_SPECIAL */
	READLENGTH_LONG_INDEF,	/* Long length, indef.to OK_SPECIAL */
	READLENGTH_LAST			/* Last possible read type */
	} READLENGTH_TYPE;

static long readLengthValue( STREAM *stream, const READLENGTH_TYPE readType )
	{
	BYTE buffer[ 8 + 8 ], *bufPtr = buffer;
	BOOLEAN shortLen = ( readType == READLENGTH_SHORT || \
						 readType == READLENGTH_SHORT_INDEF );
	long length;
	int noLengthOctets, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( readType > READLENGTH_NONE && readType < READLENGTH_LAST );

	/* Read the first byte of length data.  If it's a short length, we're
	   done */
	length = sgetc( stream );
	if( cryptStatusError( length ) || !( length & 0x80 ) )
		return( length );

	/* Read the actual length octets */
	noLengthOctets = length & 0x7F;
	if( noLengthOctets <= 0 )
		{
		/* If indefinite lengths aren't allowed, signal an error */
		if( readType != READLENGTH_SHORT_INDEF && \
			readType != READLENGTH_LONG_INDEF )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

		/* Indefinite length encoding, warn the caller */
		return( OK_SPECIAL );
		}
	if( noLengthOctets > 8 )
		status = CRYPT_ERROR_BADDATA;
	else
		status = sread( stream, buffer, noLengthOctets );
	if( cryptStatusError( status ) )
		return( sSetError( stream, status ) );

	/* Handle leading zero octets.  Since BER lengths can be encoded in 
	   peculiar ways (at least one text uses a big-endian 32-bit encoding 
	   for everything) we allow up to 8 bytes of non-DER length data, but 
	   only the last 2 or 4 of these (for short or long lengths 
	   respectively) can be nonzero */
	if( buffer[ 0 ] == 0 )
		{
		int i;

		/* Oddball length encoding with leading zero(es) */
		for( i = 0; i < noLengthOctets && buffer[ i ] == 0; i++ );
		noLengthOctets -= i;
		if( noLengthOctets <= 0 )
			return( 0 );		/* Very broken encoding of a zero length */
		bufPtr += i;			/* Skip leading zero(es) */
		}

	/* Make sure that the length size is reasonable */
	if( noLengthOctets > 4 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( shortLen && noLengthOctets > 2 )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );

	/* Read and check the length value */
	length = 0;
	while( noLengthOctets-- > 0 )
		length = ( length << 8 ) | *bufPtr++;
	if( shortLen )
		{
		if( length & 0xFFFF8000UL || length > 32767L )
			/* Length must be < 32K for short lengths */
			return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );
		}
	else
		if( ( length & 0x80000000UL ) || length > MAX_INTLENGTH )
			/* Length must be < MAX_INTLENGTH for standard data */
			return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );
	if( length < 0 )
		/* Shouldn't happen since the above check catches it, but we check
		   again just to be safe */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	return( length );
	}

/* Read the header for a (signed) integer value */

static int readIntegerHeader( STREAM *stream, const int tag )
	{
	int length, iterationCount = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the identifier field if necessary and the length */
	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_INTEGER ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( length <= 0 )
		return( length );	/* Error or zero length */

	/* ASN.1 encoded values are signed while the internal representation is
	   unsigned, so we skip any leading zero bytes needed to encode a value
	   that has the high bit set.  If we get a value with the (supposed) 
	   sign bit set we treat it as an unsigned value, since a number of 
	   implementations get this wrong */
	while( length > 0 && sPeek( stream ) == 0 && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		int status;

		status = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		length--;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	return( length );
	}

/* Read the header for a constructed object */

static int readObjectTag( STREAM *stream, const int tag )
	{
	int tagValue;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	tagValue = readTag( stream );
	if( cryptStatusError( tagValue ) )
		return( tagValue );
	if( tag == ANY_TAG )
		{
		/* Even if we're prepared to accept (almost) any tag, we still have 
		   to check for valid universal tags: BIT STRING, primitive or 
		   constructed OCTET STRING, SEQUENCE, or SET */
		if( ( tagValue & BER_CLASS_MASK ) != BER_CONTEXT_SPECIFIC && \
			tagValue != BER_BITSTRING && tagValue != BER_OCTETSTRING && \
			tagValue != ( BER_OCTETSTRING | BER_CONSTRUCTED ) && \
			tagValue != BER_SEQUENCE && tagValue != BER_SET )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	else
		if( tagValue != tag )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	return( CRYPT_OK );
	}

static int readObjectHeader( STREAM *stream, int *length, const int minLength, 
							 const int tag, const BOOLEAN isBitString, 
							 const BOOLEAN indefOK )
	{
	int dataLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );

	/* Clear return value */
	if( length != NULL )
		*length = 0;

	/* Read the object tag */
	status = readObjectTag( stream, tag );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the length.  If the indefiniteOK flag is set or the length is 
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
		if( dataLength == OK_SPECIAL )
			dataLength = CRYPT_UNUSED;
		else
			return( dataLength );
		}

	/* If it's a bit string there's an extra unused-bits count */
	if( isBitString )
		{
		int value;

		if( dataLength != CRYPT_UNUSED )
			{
			dataLength--;
			if( dataLength < 0 )
				return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
			}
		value = sgetc( stream );
		if( cryptStatusError( value ) )
			return( value );
		}

	/* Make sure that the length is in order and return it to the caller if 
	   necessary */
	if( ( dataLength != CRYPT_UNUSED ) && ( dataLength < minLength ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( length != NULL )
		*length = dataLength;
	return( CRYPT_OK );
	}

static int readLongObjectHeader( STREAM *stream, long *length, const int tag )
	{
	long dataLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	/* Clear return value */
	if( length != NULL )
		*length = 0L;

	/* Read the object tag */
	status = readObjectTag( stream, tag );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the length */
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

/* Read a (short) numeric value, used by several routines */

static int readNumeric( STREAM *stream, long *value )
	{
	BYTE buffer[ 4 + 8 ], *bufPtr = buffer;
	long localValue = 0;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( value == NULL || isWritePtr( value, sizeof( long ) ) );

	/* Clear return value */
	if( value != NULL )
		*value = 0L;

	/* Read the length field and make sure that it's a short value */
	length = readIntegerHeader( stream, NO_TAG );
	if( length <= 0 )
		return( length );	/* Error or zero length */
	if( length > 4 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Read the data */
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) || value == NULL )
		return( status );
	while( length-- > 0 )
		{
		localValue = ( localValue << 8 ) | *bufPtr++;
		if( localValue < 0 )
			/* Integer overflow */
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	*value = localValue;
	return( CRYPT_OK );
	}

/* Read a constrained-length data value, used by several routines */

static int readConstrainedData( STREAM *stream, BYTE *buffer, 
								int *bufferLength, const int length,
								const int maxLength )
	{
	int dataLength = length, remainder = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length > 0 && maxLength > 0 );
	assert( buffer == NULL || isWritePtr( buffer, length ) );
	assert( bufferLength == NULL || \
			isWritePtr( bufferLength, sizeof( int ) ) );

	if( bufferLength != NULL )
		*bufferLength = dataLength;

	/* If we don't care about the return value, skip it and exit */
	if( buffer == NULL )
		return( sSkip( stream, dataLength ) );

	/* Read the object, limiting the size to the maximum buffer size */
	if( dataLength > maxLength )
		{
		remainder = dataLength - maxLength;
		dataLength = maxLength;
		*bufferLength = dataLength;
		}
	status = sread( stream, buffer, dataLength );

	/* Skip any remaining data if necessary */
	if( remainder > 0 && !cryptStatusError( status ) )
		status = sSkip( stream, remainder );

	return( status );
	}

/****************************************************************************
*																			*
*						Read Routines for Primitive Objects					*
*																			*
****************************************************************************/

/* Check for constructed data end-of-contents octets.  Note that this 
   is a standard integer-return function that can return either a boolean 
   TRUE/FALSE or alternatively a stream error code if there's a problem, so 
   it's not a purely boolean function */

int checkEOC( STREAM *stream )
	{
	int tag;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the tag and check for an EOC octet pair */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	if( tag != BER_EOC )
		return( FALSE );
	readTag( stream );
	if( sgetc( stream ) != 0 )
		/* After finding an EOC tag we need to have a length of zero */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	return( TRUE );
	}

/* Read a short (<= 256 bytes) raw object without decoding it.  This is used
   to read short data blocks like object identifiers, which are only ever
   handled in encoded form */

int readRawObject( STREAM *stream, BYTE *buffer, int *bufferLength,
				   const int maxLength, const int tag )
	{
	int length, offset = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( maxLength >= 2 );
	assert( isWritePtr( buffer, maxLength ) );
	assert( isWritePtr( bufferLength, sizeof( int ) ) );
	assert( tag == NO_TAG || tag > 0 );

	/* Clear return value */
	*buffer = '\0';
	*bufferLength = 0;

	/* Read the identifier field and length.  We need to remember each byte 
	   as it's read so we can't just call readLengthValue() for the length, 
	   but since we only need to handle lengths that can be encoded in one 
	   or two bytes this isn't a problem.  Since this function reads a 
	   complete encoded object, the tag (if known) must be specified, so 
	   there's no capability to use DEFAULT_TAG */
	if( tag != NO_TAG )
		{
		const int objectTag = readTag( stream );
		if( tag != objectTag )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		if( buffer != NULL )
			buffer[ offset++ ] = objectTag;
		}
	length = sgetc( stream );
	if( cryptStatusError( length ) )
		return( length );
	buffer[ offset++ ] = length;
	if( length & 0x80 )
		{
		/* If the object is indefinite-length or longer than 256 bytes (i.e. 
		   the length-of-length is anything other than 1), we don't want to 
		   handle it */
		if( length != 0x81 )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		length = sgetc( stream );
		if( cryptStatusError( length ) )
			return( length );
		buffer[ offset++ ] = length;
		}
	if( offset + length > maxLength )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );

	/* Read in the rest of the data */
	*bufferLength = offset + length;
	return( ( length <= 0 ) ? \
			CRYPT_OK : sread( stream, buffer + offset, length ) );
	}

/* Read a large integer value */

int readIntegerTag( STREAM *stream, BYTE *integer, int *integerLength,
					const int maxLength, const int tag )
	{
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer == NULL || isWritePtr( integer, maxLength ) );
	assert( integerLength == NULL || \
			isWritePtr( integerLength, sizeof( int ) ) );
	assert( maxLength > 0 );

	/* Clear return value */
	if( integer != NULL )
		*integer = '\0';
	if( integerLength != NULL )
		*integerLength = 0;

	/* Read the integer header info */
	length = readIntegerHeader( stream, tag );
	if( length <= 0 )
		return( length );	/* Error or zero length */

	/* Read in the numeric value, limiting the size to the maximum buffer 
	   size.  This is safe because the only situation where this can occur 
	   is when reading some blob (whose value we don't care about) dressed 
	   up as an integer rather than for any real integer */
	return( readConstrainedData( stream, integer, integerLength, length, 
								 maxLength ) );
	}

#ifdef USE_PKC

/* Read a bignum integer value */

int readBignumTag( STREAM *stream, void *bignum, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	/* Read the integer header info */
	length = readIntegerHeader( stream, tag );
	if( length <= 0 )
		{
		if( length == 0 )
			/* Make the zero read value explicit */
			BN_zero( bignum );
		return( length );	/* Error or zero length */
		}

	/* Read the value into a fixed buffer */
	if( length > CRYPT_MAX_PKCSIZE )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );
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
#endif /* USE_PKC */

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
	assert( value == NULL || isWritePtr( value, sizeof( long ) ) );

	/* Clear return value */
	if( value != NULL )
		*value = 0L;

	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_INTEGER ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readNumeric( stream, value ) );
	}

/* Read an enumerated value.  This is encoded like an ASN.1 integer so we
   just read it as such */

int readEnumeratedTag( STREAM *stream, int *enumeration, const int tag )
	{
	long value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( enumeration == NULL || \
			isWritePtr( enumeration, sizeof( int ) ) );

	/* Clear return value */
	if( enumeration != NULL )
		*enumeration = 0;

	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_ENUMERATED ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	status = readNumeric( stream, &value );
	if( cryptStatusOK( status ) )
		{
		if( value > 1000 )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		if( enumeration != NULL )
			*enumeration = ( int ) value;
		}
	return( status );
	}

/* Read a null value */

int readNullTag( STREAM *stream, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the identifier if necessary */
	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_NULL ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( sgetc( stream ) != 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( CRYPT_OK );
	}

/* Read a boolean value */

int readBooleanTag( STREAM *stream, BOOLEAN *boolean, const int tag )
	{
	BYTE buffer[ 2 + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( boolean == NULL || \
			isWritePtr( boolean, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	if( boolean != NULL )
		*boolean = FALSE;

	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_BOOLEAN ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	status = sread( stream, buffer, 2 );
	if( cryptStatusError( status ) )
		return( status );
	if( buffer[ 0 ] != 1 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( boolean != NULL )
		*boolean = buffer[ 1 ] ? TRUE : FALSE;
	return( CRYPT_OK );
	}

/* Read an OID and check it against a permitted value or a selection of 
   permitted values */

int readOIDEx( STREAM *stream, const OID_INFO *oidSelection, 
			   const OID_INFO **oidSelectionValue )
	{
	static const OID_INFO nullOidSelection = { NULL, CRYPT_ERROR, NULL };
	BYTE buffer[ MAX_OID_SIZE + 8 ];
	int length, oidEntry, iterationCount = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oidSelection, sizeof( OID_INFO ) * 2 ) );
	assert( oidSelectionValue == NULL || \
			isReadPtr( oidSelectionValue, sizeof( OID_INFO * ) ) );

	/* Clear return value */
	if( oidSelectionValue != NULL )
		*oidSelectionValue = &nullOidSelection;

	/* Read the OID data */
	status = readRawObject( stream, buffer, &length, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	if( length != sizeofOID( buffer ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Try and find the entry for the OID */
	for( oidEntry = 0; oidSelection[ oidEntry ].oid != NULL && \
					   iterationCount++ < FAILSAFE_ITERATIONS_MED; 
		 oidEntry++ )
		{
		if( length == sizeofOID( oidSelection[ oidEntry ].oid ) && \
			!memcmp( buffer, oidSelection[ oidEntry ].oid, length ) )
			break;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	if( oidSelection[ oidEntry ].oid == NULL )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	if( oidSelectionValue != NULL )
		*oidSelectionValue = &oidSelection[ oidEntry ];
	return( CRYPT_OK );
	}

int readOID( STREAM *stream, const OID_INFO *oidInfo, int *selectionID )
	{
	const OID_INFO *oidSelectionInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oidInfo, sizeof( OID_INFO ) * 2 ) );
	assert( isWritePtr( selectionID, sizeof( int ) ) );

	/* Clear return value */
	*selectionID = CRYPT_ERROR;

	status = readOIDEx( stream, oidInfo, &oidSelectionInfo );
	if( cryptStatusOK( status ) )
		*selectionID = oidSelectionInfo->selectionID;
	return( status );
	}

int readFixedOID( STREAM *stream, const BYTE *oid )
	{
	CONST_INIT_STRUCT_A2( OID_INFO oidInfo[ 2 ], oid, NULL );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oid, sizeofOID( oid ) ) && \
			oid[ 0 ] == BER_OBJECT_IDENTIFIER );

	/* Set up a one-entry OID_INFO list to pass down to readOID() */
	CONST_SET_STRUCT_A( memset( oidInfo, 0, sizeof( OID_INFO ) * 2 ); \
						oidInfo[ 0 ].oid = oid );
	return( readOIDEx( stream, oidInfo, NULL ) );
	}

/* Read a raw OID in encoded form */

int readEncodedOID( STREAM *stream, BYTE *oid, int *oidLength,
					const int maxLength, const int tag )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( maxLength >= 5 );
	assert( isWritePtr( oid, maxLength ) );
	assert( isWritePtr( oidLength, sizeof( int ) ) );
	assert( tag == NO_TAG || tag > 0 );

	/* Clear return values */
	*oid = '\0';
	*oidLength = 0;

	/* Read the encoded OID and make sure that it's the right size for a
	   minimal-length OID: tag (optional) + length + minimal-length OID 
	   data */
	status = readRawObject( stream, oid, &length, maxLength, tag );
	if( cryptStatusError( status ) )
		return( status );
	if( length < ( tag == NO_TAG ? 0 : 1 ) + 1 + 3 || length > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	*oidLength = length;
	return( CRYPT_OK );
	}

/* Read an octet string value */

static int readString( STREAM *stream, BYTE *string, int *stringLength,
					   const int minLength, const int maxLength, 
					   const int tag, const BOOLEAN useLiteralTag )
	{
	int length;

	/* Clear return value */
	if( string != NULL )
		{
		*string = '\0';
		*stringLength = 0;
		}

	/* Read the string, limiting the size to the maximum buffer size */
	if( useLiteralTag )
		{
		if( readTag( stream ) != tag )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	else
		{
		if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_OCTETSTRING ) )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	length = readLengthValue( stream, READLENGTH_SHORT );
	if( cryptStatusError( length ) )
		return( length );
	if( length < minLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( length <= 0 )
		return( length );	/* Zero length */
	return( readConstrainedData( stream, string, stringLength, length, 
								 maxLength ) );
	}

int readOctetStringTag( STREAM *stream, BYTE *string, int *stringLength,
						const int minLength, const int maxLength, 
						const int tag )
	{

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( string == NULL || isWritePtr( string, maxLength ) );
	assert( stringLength == NULL || \
			isWritePtr( stringLength, sizeof( int ) ) );
	assert( maxLength > 0 );

	return( readString( stream, string, stringLength, minLength, maxLength, \
						tag, FALSE ) );
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
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( string == NULL || isWritePtr( string, maxLength ) );
	assert( stringLength == NULL || \
			isWritePtr( stringLength, sizeof( int ) ) );
	assert( maxLength > 0 );
	assert( tag > 0 );

	return( readString( stream, string, stringLength, 1, maxLength, \
						tag, TRUE ) );
	}

/* Read a bit string */

int readBitStringTag( STREAM *stream, int *bitString, const int tag )
	{
	int length, data, mask = 0x80, flag = 1, value = 0, noBits, i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( bitString == NULL || isWritePtr( bitString, sizeof( int ) ) );
	
	/* Clear return value */
	if( bitString != NULL )
		*bitString = 0;

	/* Make sure that we have a bitstring with between 0 and sizeof( int ) 
	   bits.  This isn't as machine-dependant as it seems, the only place 
	   where bit strings longer than one or two bytes are used is with the 
	   more obscure CMP error subcodes that just provide further information
	   above and beyond the main error code and text message, and CMP is 
	   highly unlikely to be used on a 16-bit machine */
	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_BITSTRING ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	length = sgetc( stream ) - 1;
	noBits = sgetc( stream );
	if( cryptStatusError( noBits ) )
		return( noBits );
	if( length < 0 || length > sizeof( int ) || noBits < 0 || noBits > 7 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( length <= 0 )
		return( CRYPT_OK );		/* Zero value */
	assert( length >= 1 && length <= sizeof( int ) );
	assert( noBits >= 0 && noBits <= 7 );
	noBits = ( length * 8 ) - noBits;

	/* ASN.1 bitstrings start at bit 0, so we need to reverse the order of
	   the bits before we return the value */
	data = sgetc( stream );
	if( cryptStatusError( data ) )
		return( data );
	for( i = noBits - 8; i > 0; i -= 8 )
		{
		const int dataTmp = sgetc( stream );

		if( cryptStatusError( dataTmp ) )
			return( dataTmp );
		data = ( data << 8 ) | dataTmp;
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
		{
		if( value < 0 )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		*bitString = value;
		}

	return( CRYPT_OK );
	}

/* Read a UTCTime and GeneralizedTime value */

static int getDigits( const BYTE *bufPtr )
	{
	return( ( ( bufPtr[ 0 ] - '0' ) * 10 ) + ( bufPtr[ 1 ] - '0' ) );
	}

static int readTime( STREAM *stream, time_t *timePtr, const BOOLEAN isUTCTime )
	{
	BYTE buffer[ 16 + 8 ], *bufPtr = buffer;
	struct tm theTime,  gmTimeInfo, *gmTimeInfoPtr = &gmTimeInfo;
	time_t utcTime, gmTime;
#if 0
	time_t localTime;
#endif /* 0 */
	int value = 0, length, i, status;

	/* Read the length field and make sure that it's of the correct size.  
	   There's only one encoding allowed although in theory the encoded 
	   value could range in length from 11 to 17 bytes for UTCTime and 13 to 
	   19 bytes for GeneralizedTime.  In practice we also have to allow 11-
	   byte UTCTimes since an obsolete encoding rule allowed the time to be 
	   encoded without seconds, and Sweden Post haven't realised that this 
	   has changed yet */
	length = sgetc( stream );
	if( cryptStatusError( length ) )
		return( length );
	if( ( isUTCTime && length != 13 && length != 11 ) || \
		( !isUTCTime && length != 15 ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Read the encoded time data and make sure that the contents are 
	   valid */
	memset( buffer, 0, 16 );
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	for( i = 0; i < length - 1; i++ )
		{
		if( !isDigit( buffer[ i ] ) )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	if( buffer[ length - 1 ] != 'Z' )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Decode the time fields */
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
	if( length > 11 )
		theTime.tm_sec = getDigits( bufPtr + 10 );

	/* Finally, convert it to the local time.  Since the UTCTime format
	   doesn't take centuries into account (and you'd think that when the 
	   ISO came up with the world's least efficient time encoding format 
	   they could have spared another two bytes to fully specify the year), 
	   we have to adjust by one century for years < 50 if the format is 
	   UTCTime.  Note that there are some implementations that currently 
	   roll over a century from 1970 (the Unix/Posix epoch and sort-of ISO/
	   ANSI C epoch although they never come out and say it), but hopefully 
	   these will be fixed by 2050.

		"The time is out of joint; o cursed spite,
		 That ever I was born to set it right"	- Shakespeare, "Hamlet" */
	if( isUTCTime && theTime.tm_year < 50 )
		theTime.tm_year += 100;
	utcTime = mktime( &theTime );
	if( utcTime < 0 )
		{
		/* Some Java-based apps with 64-bit times use ridiculous validity
		   dates (yes, we're going to be keeping the same key in active use
		   for *forty years*) that postdate the time_t range when time_t is 
		   a signed 32-bit value.  If we can't convert the time, we check 
		   for a year after the time_t overflow (2038) and try again.  In
		   theory we should just reject objects with such broken dates, but
		   since we otherwise accept all sorts of rubbish we at least try 
		   and accept these as well */
		if( theTime.tm_year > 138 && theTime.tm_year < 180 )
			{
			theTime.tm_year = 136;	/* 2036 */
			utcTime = mktime( &theTime );
			}

		/* Some broken apps set dates to 1/1/1970, handling times this close 
		   to the epoch is problematic because once any possible DST 
		   adjustment is taken into account it's no longer possible to
		   represent the converted time as a time_t unless the system allows
		   it to be negative (Windows doesn't, many Unixen do, but having
		   cryptlib return a negative time value is probably a bad thing).  
		   To handle this, if we find a date set anywhere during January 1970 
		   we manually set the time to zero (the epoch) */
		if( theTime.tm_year == 70 && theTime.tm_mon == 0 )
			{
			*timePtr = 0;
			return( CRYPT_OK );
			}
		}
	if( utcTime < 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Convert the UTC time to local time.  This is complicated by the fact 
	   that although the C standard library can convert from local time -> 
	   UTC, it can't convert the time back, so we treat the UTC time as 
	   local time (gmtime_s() always assumes that the input is local time) 
	   and covert to GMT and back, which should give the offset from GMT.  
	   Since we can't assume that time_t is signed, we have to treat a 
	   negative and positive offset separately.  An extra complication is 
	   added by daylight savings time adjustment, some systems adjust for 
	   DST by default, some don't, and some allow you to set it in the 
	   Control Panel so it varies from machine to machine (thanks Bill!), so 
	   we have to make it explicit as part of the conversion process.  Even 
	   this still isn't perfect because it displays the time adjusted for 
	   DST now rather than DST when the cert was created, however this 
	   problem is more or less undecidable, the code used here has the 
	   property that the values for Windows agree with those for Unix and 
	   everything else which is the main thing */
	gmTimeInfoPtr = gmTime_s( &utcTime, gmTimeInfoPtr );
	if( gmTimeInfoPtr != NULL )
		{
		gmTimeInfoPtr->tm_isdst = -1;		/* Force correct DST adjustment */
		gmTime = mktime( gmTimeInfoPtr );
		}
	if( gmTimeInfoPtr == NULL || gmTime < 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( timePtr != NULL )
		{
		if( utcTime < gmTime )
			*timePtr = utcTime - ( gmTime - utcTime );
		else
			*timePtr = utcTime + ( utcTime - gmTime );

		/* This still isn't quite perfect, since it can't handle time at
		   a DST changeover.  This is really a user problem ("Don't do that,
		   then"), but if necessary can be corrected by converting back to
		   GMT as a sanity check and applying a +/- 1 hour correction if 
		   there's a mismatch */
  #if 0
		gmTimeInfoPtr = gmTime_s( timePtr );
		gmTimeInfoPtr->tm_isdst = -1;
		gmTime = mktime( gmTimeInfoPtr );
		if( gmTime != utcTime )
			{
			*timePtr += 3600;		/* Try +1 first */
			gmTimeInfoPtr = gmTime_s( timePtr, gmTimeInfoPtr );
			gmTimeInfoPtr->tm_isdst = -1;
			gmTime = mktime( gmTimeInfoPtr );
			if( gmTime != utcTime )
				*timePtr -= 7200;	/* Nope, use -1 instead */
			}
  #endif /* 0 */
		}

	return( CRYPT_OK );
	}

int readUTCTimeTag( STREAM *stream, time_t *timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal == NULL || isWritePtr( timeVal, sizeof( time_t ) ) );

	/* Clear return value */
	if( timeVal != NULL )
		*timeVal = 0;
	
	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_TIME_UTC ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readTime( stream, timeVal, TRUE ) );
	}

int readGeneralizedTimeTag( STREAM *stream, time_t *timeVal, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( timeVal == NULL || isWritePtr( timeVal, sizeof( time_t ) ) );

	/* Clear return value */
	if( timeVal != NULL )
		*timeVal = 0;
	
	if( tag != NO_TAG && readTag( stream ) != selectTag( tag, BER_TIME_GENERALIZED ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readTime( stream, timeVal, FALSE ) );
	}

/****************************************************************************
*																			*
*						Read Routines for Constructed Objects				*
*																			*
****************************************************************************/

/* Read an encapsulating SEQUENCE or SET or BIT STRING/OCTET STRING hole */

int readSequence( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );

	return( readObjectHeader( stream, length, 0, BER_SEQUENCE, FALSE, FALSE ) );
	}

int readSequenceI( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );

	return( readObjectHeader( stream, length, 0, BER_SEQUENCE, FALSE, TRUE ) );
	}

int readSet( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );

	return( readObjectHeader( stream, length, 0, BER_SET, FALSE, FALSE ) );
	}

int readSetI( STREAM *stream, int *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );

	return( readObjectHeader( stream, length, 0, BER_SET, FALSE, TRUE ) );
	}

int readConstructed( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, 0, ( tag == DEFAULT_TAG ) ? \
							  BER_SEQUENCE : MAKE_CTAG( tag ), FALSE, FALSE ) );
	}

int readConstructedI( STREAM *stream, int *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, 0, ( tag == DEFAULT_TAG ) ? \
							  BER_SEQUENCE : MAKE_CTAG( tag ), FALSE, TRUE ) );
	}

int readOctetStringHole( STREAM *stream, int *length, const int minLength, 
						 const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, minLength, 
							  ( tag == DEFAULT_TAG ) ? \
								BER_OCTETSTRING : MAKE_CTAG_PRIMITIVE( tag ),
							  FALSE, FALSE ) );
	}

int readBitStringHole( STREAM *stream, int *length, const int minLength, 
					   const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, minLength, 
							  ( tag == DEFAULT_TAG ) ? \
								BER_BITSTRING : MAKE_CTAG_PRIMITIVE( tag ),
							  TRUE, FALSE ) );
	}

int readGenericHole( STREAM *stream, int *length, const int minLength, 
					 const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, minLength, 
							  ( tag == DEFAULT_TAG ) ? ANY_TAG : tag, 
							  FALSE, FALSE ) );
	}

int readGenericHoleI( STREAM *stream, int *length, const int minLength, 
					  const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( int ) ) );
	assert( ( tag == DEFAULT_TAG ) || ( tag >= 0 ) );

	return( readObjectHeader( stream, length, minLength, 
							  ( tag == DEFAULT_TAG ) ? ANY_TAG : tag, 
							  FALSE, TRUE ) );
	}

/* Read an abnormally-long encapsulating SEQUENCE or OCTET STRING hole.  
   This is used in place of the usual read in situations where potentially 
   huge data quantities would fail the sanity check enforced by the 
   standard read.  This form always allows indefinite lengths, which are 
   likely for large objects */

int readLongSequence( STREAM *stream, long *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	return( readLongObjectHeader( stream, length, BER_SEQUENCE ) );
	}

int readLongSet( STREAM *stream, long *length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	return( readLongObjectHeader( stream, length, BER_SET ) );
	}

int readLongConstructed( STREAM *stream, long *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	return( readLongObjectHeader( stream, length, ( tag == DEFAULT_TAG ) ? \
								  BER_SEQUENCE : MAKE_CTAG( tag ) ) );
	}

int readLongGenericHole( STREAM *stream, long *length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length == NULL || isWritePtr( length, sizeof( long ) ) );

	return( readLongObjectHeader( stream, length, 							  
								  ( tag == DEFAULT_TAG ) ? ANY_TAG : tag ) );
	}
