/****************************************************************************
*																			*
*						  ASN.1 Constants and Structures					*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifndef _ASN1_DEFINED

#define _ASN1_DEFINED

#include <time.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "stream.h"
  #include "ber.h"
#else
  #include "misc/stream.h"
  #include "misc/ber.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							ASN.1 Constants and Macros						*
*																			*
****************************************************************************/

/* Special-case tags.  If DEFAULT_TAG is given the basic type (e.g. INTEGER,
   ENUMERATED) is used, otherwise the value is used as a context-specific 
   tag.  If NO_TAG is given, processing of the tag is skipped.  If ANY_TAG
   is given, the tag is ignored */

#define DEFAULT_TAG			-1
#define NO_TAG				-2
#define ANY_TAG				-3

/* The maximum allowed size for an (encoded) object identifier */

#define MAX_OID_SIZE		32

/* Macros and functions to work with indefinite-length tags.  The only ones 
   used are SEQUENCE and [0] (for the outer encapsulation) and OCTET STRING 
   (for the data itself) */

#define writeOctetStringIndef( stream )	swrite( stream, BER_OCTETSTRING_INDEF, 2 )
#define writeSequenceIndef( stream )	swrite( stream, BER_SEQUENCE_INDEF, 2 )
#define writeSetIndef( stream )			swrite( stream, BER_SET_INDEF, 2 )
#define writeCtag0Indef( stream )		swrite( stream, BER_CTAG0_INDEF, 2 )
#define writeEndIndef( stream )			swrite( stream, BER_END_INDEF, 2 )
int checkEOC( STREAM *stream );

/****************************************************************************
*																			*
*							ASN.1 Function Prototypes						*
*																			*
****************************************************************************/

/* Determine the size of an object once it's wrapped up with a tag and 
   length */

long sizeofObject( const long length );

/* Generalized ASN.1 type manipulation routines.  readRawObject() reads a
   complete object (including tag and length data) while readUniversal() 
   just skips it */

int readUniversalData( STREAM *stream );
int readUniversal( STREAM *stream );
int readRawObjectTag( STREAM *stream, BYTE *buffer, int *bufferLength,
					  const int maxLength, const int tag );
#define readRawObject( stream, buffer, bufferLength, maxLength, tag ) \
		readRawObjectTag( stream, buffer, bufferLength, maxLength, tag )
#define readRawObjectData( stream, buffer, bufferLength, maxLength ) \
		readRawObjectTag( stream, buffer, bufferLength, maxLength, NO_TAG )
#define writeRawObject( stream, object, size ) \
		swrite( stream, object, size )

/* Routines for handling OBJECT IDENTIFIERS.  This determines the length of
   an encoded object identifier as tag + length + value.  Read/write OID
   routines equivalent to the ones for other ASN.1 types don't exist since
   OIDs are always read and written as a blob with sread()/swrite() */

#define sizeofOID( oid )	( 1 + 1 + ( int ) oid[ 1 ] )
#define writeOID( stream, oid ) \
							swrite( ( stream ), ( oid ), sizeofOID( oid ) )

/* Routines for handling large integers.  When we're writing these we can't
   use sizeofObject() directly because the internal representation is
   unsigned whereas the encoded form is signed.  The following macro performs
   the appropriate conversion on the data length before passing it on to
   sizeofObject() */

#define sizeofInteger( value, valueLength ) \
		( int ) sizeofObject( ( valueLength ) + \
							  ( ( *( BYTE * )( value ) & 0x80 ) ? 1 : 0 ) )
int readIntegerTag( STREAM *stream, BYTE *integer, int *integerLength,
					const int maxLength, const int tag );
int writeInteger( STREAM *stream, const BYTE *integer, 
				  const int integerLength, const int tag );

#define readIntegerData( stream, integer, integerLength, maxLength )	\
		readIntegerTag( stream, integer, integerLength, maxLength, NO_TAG )
#define readInteger( stream, integer, integerLength, maxLength )	\
		readIntegerTag( stream, integer, integerLength, maxLength, DEFAULT_TAG )

/* Routines for handling bignums.  We use void * rather than BIGNUM * to save
   having to include the bignum header everywhere ASN.1 is used */

#define sizeofBignum( bignum ) \
		( ( int ) sizeofObject( signedBignumSize( bignum ) ) )
int signedBignumSize( const void *bignum );

int readBignumTag( STREAM *stream, void *bignum, const int tag );
int writeBignumTag( STREAM *stream, const void *bignum, const int tag );

#define readBignum( stream, bignum ) \
		readBignumTag( stream, bignum, DEFAULT_TAG )
#define writeBignum( stream, bignum ) \
		writeBignumTag( stream, bignum, DEFAULT_TAG )

/* Generally most integers will be non-bignum values, so we also define
   routines to handle values that will fit into a machine word */

#define sizeofShortInteger( value )	\
	( ( ( value ) < 128 ) ? 3 : \
	  ( ( ( long ) value ) < 32768L ) ? 4 : \
	  ( ( ( long ) value ) < 8388608L ) ? 5 : \
	  ( ( ( long ) value ) < 2147483648UL ) ? 6 : 7 )
int writeShortInteger( STREAM *stream, const long value, const int tag );
int readShortIntegerTag( STREAM *stream, long *value, const int tag );

#define readShortIntegerData( stream, integer )	\
		readShortIntegerTag( stream, integer, NO_TAG )
#define readShortInteger( stream, integer )	\
		readShortIntegerTag( stream, integer, DEFAULT_TAG )

/* Routines for handling enumerations */

#define sizeofEnumerated( value )	( ( ( value ) < 128 ) ? 3 : 4 )
int writeEnumerated( STREAM *stream, const int enumerated, const int tag );
int readEnumeratedTag( STREAM *stream, int *enumeration, const int tag );

#define readEnumeratedData( stream, enumeration ) \
		readEnumeratedTag( stream, enumeration, NO_TAG )
#define readEnumerated( stream, enumeration ) \
		readEnumeratedTag( stream, enumeration, DEFAULT_TAG )

/* Routines for handling booleans */

#define sizeofBoolean()	( sizeof( BYTE ) + sizeof( BYTE ) + sizeof( BYTE ) )
int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag );
int readBooleanTag( STREAM *stream, BOOLEAN *boolean, const int tag );

#define readBooleanData( stream, boolean ) \
		readBooleanTag( stream, boolean, NO_TAG )
#define readBoolean( stream, boolean ) \
		readBooleanTag( stream, boolean, DEFAULT_TAG )

/* Routines for handling null values */

#define sizeofNull()	( sizeof( BYTE ) + sizeof( BYTE ) )
int writeNull( STREAM *stream, const int tag );
int readNullTag( STREAM *stream, const int tag );

#define readNullData( stream )	readNullTag( stream, NO_TAG )
#define readNull( stream )		readNullTag( stream, DEFAULT_TAG )

/* Routines for handling octet strings */

int writeOctetString( STREAM *stream, const BYTE *string, const int length, \
					  const int tag );
int readOctetStringTag( STREAM *stream, BYTE *string, int *stringLength,
						const int maxLength, const int tag );

#define readOctetStringData( stream, string, stringLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, maxLength, NO_TAG )
#define readOctetString( stream, string, stringLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, maxLength, DEFAULT_TAG )

/* Routines for handling character strings.  There are a number of oddball
   character string types that are all handled through the same functions -
   it's not worth having a seperate function to handle each of the half-dozen
   types */

int writeCharacterString( STREAM *stream, const BYTE *string,
						  const int length, const int tag );
int readCharacterString( STREAM *stream, BYTE *string, int *stringLength,
						 const int maxLength, const int tag );

/* Routines for handling bit strings.  The sizeof() values are 3 bytes for
   the tag, length, and surplus-bits value, and the data itself */

#define sizeofBitString( value )	\
	( 3 + ( ( ( ( long ) value ) > 0xFFFFFFL ) ? 4 : \
			( ( ( long ) value ) > 0xFFFFL ) ? 3 : \
			( ( value ) > 0xFF ) ? 2 : ( value ) ? 1 : 0 ) )
int writeBitString( STREAM *stream, const int bitString, const int tag );
int readBitStringTag( STREAM *stream, int *bitString, const int tag );

#define readBitStringData( stream, bitString ) \
		readBitStringTag( stream, bitString, NO_TAG )
#define readBitString( stream, bitString ) \
		readBitStringTag( stream, bitString, DEFAULT_TAG )

/* Routines for handling UTC and Generalized time */

#define sizeofUTCTime()			( 1 + 1 + 13 )
int writeUTCTime( STREAM *stream, const time_t timeVal, const int tag );
int readUTCTimeTag( STREAM *stream, time_t *timeVal, const int tag );

#define readUTCTimeData( stream, time )	readUTCTimeTag( stream, time, NO_TAG )
#define readUTCTime( stream, time )		readUTCTimeTag( stream, time, DEFAULT_TAG )

#define sizeofGeneralizedTime()	( 1 + 1 + 15 )
int writeGeneralizedTime( STREAM *stream, const time_t timeVal, const int tag );
int readGeneralizedTimeTag( STREAM *stream, time_t *timeVal, const int tag );

#define readGeneralizedTimeData( stream, time )	\
		readGeneralizedTimeTag( stream, time, NO_TAG )
#define readGeneralizedTime( stream, time )	\
		readGeneralizedTimeTag( stream, time, DEFAULT_TAG )

/* Utilitity routines for reading and writing constructed objects and 
   equivalent holes.  The difference between writeOctet/BitStringHole() and
   writeGenericHole() is that the octet/bit-string versions create a normal
   or context-specific-tagged string while the generic version creates a 
   pure hole with no processing of tags */

int readSequence( STREAM *stream, int *length );
int readSet( STREAM *stream, int *length );
int readConstructed( STREAM *stream, int *length, const int tag );
int readOctetStringHole( STREAM *stream, int *length, const int tag );
int readBitStringHole( STREAM *stream, int *length, const int tag );
int readGenericHole( STREAM *stream, int *length, const int tag );
int writeSequence( STREAM *stream, const int length );
int writeSet( STREAM *stream, const int length );
int writeConstructed( STREAM *stream, const int length, const int tag );
int writeOctetStringHole( STREAM *stream, const int length, const int tag );
int writeBitStringHole( STREAM *stream, const int length, const int tag );
int writeGenericHole( STREAM *stream, const int length, const int tag );

/* Alternative versions of the above that allow indefinite lengths.  This
   (non-DER) behaviour is the exception rather than the rule, so we have to
   enable it explicitly */

int readSequenceI( STREAM *stream, int *length );
int readSetI( STREAM *stream, int *length );
int readConstructedI( STREAM *stream, int *length, const int tag );

/* Determine the length of an ASN.1-encoded object (this just reads the
   outer length if present, but will burrow down into the object if necessary
   if the length is indefinite) and check that an object has valid encoding */

int getStreamObjectLength( STREAM *stream );
int getObjectLength( const void *certObjectPtr, const int length );
int checkObjectEncoding( const void *objectPtr, const int length );

/* Full-length equivalents of length/encapsulating-object read routines.  
   These are used explicitly in the rare situations where long lengths are
   valid, all other ASN.1 code only works with short lengths.  Because these
   can be quite long, they allow definite or indefinite lengths */

long readLongSequence( STREAM *stream, long *length );
long readLongConstructed( STREAM *stream, long *length, const int tag );
long readLongGenericHole( STREAM *stream, long *length, const int tag );
long getLongObjectLength( const void *certObjectPtr, const long length );

#endif /* !_ASN1_DEFINED */
