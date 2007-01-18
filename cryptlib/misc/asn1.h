/****************************************************************************
*																			*
*						  ASN.1 Constants and Structures					*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#ifndef _ASN1_DEFINED

#define _ASN1_DEFINED

#include <time.h>
#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						BER/DER Constants and Macros						*
*																			*
****************************************************************************/

/* Definitions for the ISO 8825:1990 Basic Encoding Rules */

/* Tag class */

#define BER_UNIVERSAL			0x00
#define BER_APPLICATION			0x40
#define BER_CONTEXT_SPECIFIC	0x80
#define BER_PRIVATE				0xC0

/* Whether the encoding is constructed or primitive */

#define BER_CONSTRUCTED			0x20
#define BER_PRIMITIVE			0x00

/* The ID's for universal tag numbers 0-31.  Tag number 0 is reserved for
   encoding the end-of-contents value when an indefinite-length encoding
   is used */

enum { BER_ID_RESERVED, BER_ID_BOOLEAN, BER_ID_INTEGER, BER_ID_BITSTRING,
	   BER_ID_OCTETSTRING, BER_ID_NULL, BER_ID_OBJECT_IDENTIFIER,
	   BER_ID_OBJECT_DESCRIPTOR, BER_ID_EXTERNAL, BER_ID_REAL,
	   BER_ID_ENUMERATED, BER_ID_EMBEDDED_PDV, BER_ID_STRING_UTF8, BER_ID_13,
	   BER_ID_14, BER_ID_15, BER_ID_SEQUENCE, BER_ID_SET,
	   BER_ID_STRING_NUMERIC, BER_ID_STRING_PRINTABLE, BER_ID_STRING_T61,
	   BER_ID_STRING_VIDEOTEX, BER_ID_STRING_IA5, BER_ID_TIME_UTC,
	   BER_ID_TIME_GENERALIZED, BER_ID_STRING_GRAPHIC, BER_ID_STRING_ISO646,
	   BER_ID_STRING_GENERAL, BER_ID_STRING_UNIVERSAL, BER_ID_29,
	   BER_ID_STRING_BMP, BER_ID_LAST };

/* The encodings for the universal types */

#define BER_EOC					0	/* Pseudo-type for first EOC octet */
#define BER_RESERVED			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_RESERVED )
#define BER_BOOLEAN				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BOOLEAN )
#define BER_INTEGER				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_INTEGER )
#define BER_BITSTRING			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BITSTRING )
#define BER_OCTETSTRING			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OCTETSTRING )
#define BER_NULL				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_NULL )
#define BER_OBJECT_IDENTIFIER	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_IDENTIFIER )
#define BER_OBJECT_DESCRIPTOR	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_DESCRIPTOR )
#define BER_EXTERNAL			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EXTERNAL )
#define BER_REAL				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_REAL )
#define BER_ENUMERATED			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_ENUMERATED )
#define BER_EMBEDDED_PDV		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EMBEDDED_PDV )
#define BER_STRING_UTF8			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_UTF8 )
#define BER_13					( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_13 )
#define BER_14					( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_14 )
#define BER_15					( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_15 )
#define BER_SEQUENCE			( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SEQUENCE )
#define BER_SET					( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SET )
#define BER_STRING_NUMERIC		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_NUMERIC )
#define BER_STRING_PRINTABLE	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_PRINTABLE )
#define BER_STRING_T61			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_T61 )
#define BER_STRING_VIDEOTEX		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_VIDEOTEX )
#define BER_STRING_IA5			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_IA5 )
#define BER_TIME_UTC			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_UTC )
#define BER_TIME_GENERALIZED	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_GENERALIZED )
#define BER_STRING_GRAPHIC		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GRAPHIC )
#define BER_STRING_ISO646		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_ISO646 )
#define BER_STRING_GENERAL		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GENERAL )
#define BER_STRING_UNIVERSAL	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_UNIVERSAL )
#define BER_29					( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BER29 )
#define BER_STRING_BMP			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_BMP )

/* The encodings for constructed, indefinite-length tags and lengths */

#define BER_OCTETSTRING_INDEF	( ( BYTE * ) "\x24\x80" )
#define BER_SEQUENCE_INDEF		( ( BYTE * ) "\x30\x80" )
#define BER_SET_INDEF			( ( BYTE * ) "\x31\x80" )
#define BER_CTAG0_INDEF			( ( BYTE * ) "\xA0\x80" )
#define BER_END_INDEF			( ( BYTE * ) "\x00\x00" )

/* Masks to extract information from a tag number */

#define BER_CLASS_MASK			0xC0
#define BER_CONSTRUCTED_MASK	0x20
#define BER_SHORT_ID_MASK		0x1F

/* The maximum size for the short tag number encoding, and the magic value
   which indicates that a long encoding of the number is being used */

#define MAX_SHORT_BER_ID		30
#define LONG_BER_ID				0x1F

/* Turn an identifier into a context-specific tag, and extract the value from
   a tag.  Normally these are constructed, but in a few special cases they
   are primitive */

#define MAKE_CTAG( identifier ) \
		( BER_CONTEXT_SPECIFIC | BER_CONSTRUCTED | ( identifier ) )
#define MAKE_CTAG_PRIMITIVE( identifier ) \
		( BER_CONTEXT_SPECIFIC | ( identifier ) )
#define EXTRACT_CTAG( tag ) \
		( ( tag ) & ~( BER_CONTEXT_SPECIFIC | BER_CONSTRUCTED ) )

/* Macros to read and write primitive tags.  These translate directly to
   sgetc()/sputc()/sPeek(), but we use these macros instead to make it more
   obvious what's going on */

#define writeTag( stream, tag )	sputc( stream, tag )
#define readTag( stream )		sgetc( stream )
#define peekTag( stream )		sPeek( stream )

/****************************************************************************
*																			*
*							ASN.1 Constants and Macros						*
*																			*
****************************************************************************/

/* Special-case tags.  If DEFAULT_TAG is given the basic type (e.g. INTEGER,
   ENUMERATED) is used, otherwise the value is used as a context-specific
   tag.  If NO_TAG is given, processing of the tag is skipped.  If ANY_TAG
   is given, the tag is ignored.  The ranges are chosen so as not to 
   conflict with any of the values in cryptlib.h/crypt.h */

#define DEFAULT_TAG			-200
#define NO_TAG				-201
#define ANY_TAG				-202

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
   just skips it.  Since readRawObject() always requires a tag, we don't
   have the xxx/xxxData() variants that exist for other functions */

int readUniversalData( STREAM *stream );
int readUniversal( STREAM *stream );
int readRawObject( STREAM *stream, BYTE *buffer, int *bufferLength,
				   const int maxLength, const int tag );

#define writeRawObject( stream, object, size ) \
		swrite( stream, object, size )

/* Routines for handling OBJECT IDENTIFIERS.  The sizeof() macro determines
   the length of an encoded object identifier as tag + length + value.
   Write OID routines equivalent to the ones for other ASN.1 types don't
   exist since OIDs are always read and written as a blob with sread()/
   swrite().  OIDs are never tagged so we don't need any special-case
   handling for tags.

   When there's a choice of possible OIDs, the list of OID values and
   corresponding selection IDs is provided in an OID_INFO structure (we also
   provide a shortcut readFixedOID() function when there's only a single OID
   that's valid at that point).  The read OID value is checked against each
   OID in the OID_INFO list, if a match is found the selectionID is returned.

   The OID_INFO includes a pointer to further user-supplied information
   related to this OID that may be used by the user, set when the OID list
   is initialised.  For example it could point to OID-specific handlers for
   the data.  When the caller needs to work with the extraInfo field, it's
   necessary to return the complete OID_INFO entry rather than just the
   selection ID, which is done by the ..Ex() form of the function */

typedef struct {
	const BYTE FAR_BSS *oid;/* OID */
	const int selectionID;	/* Value to return for this OID */
	const void *extraInfo;	/* Additional info for this selection */
	} OID_INFO;

#define sizeofOID( oid )	( 1 + 1 + ( int ) oid[ 1 ] )
int readOID( STREAM *stream, const OID_INFO *oidSelection,
			 int *selectionID );
int readOIDEx( STREAM *stream, const OID_INFO *oidSelection,
			   const OID_INFO **oidSelectionValue );
int readFixedOID( STREAM *stream, const BYTE *oid );
int readEncodedOID( STREAM *stream, BYTE *oid, int *oidLength,
					const int maxLength, const int tag );
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
	( ( ( value ) < 0x80 ) ? 3 : \
	  ( ( ( long ) value ) < 0x8000L ) ? 4 : \
	  ( ( ( long ) value ) < 0x800000L ) ? 5 : \
	  ( ( ( long ) value ) < 0x80000000UL ) ? 6 : 7 )
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
						const int minLength, const int maxLength, 
						const int tag );

#define readOctetStringData( stream, string, stringLength, minLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, minLength, maxLength, NO_TAG )
#define readOctetString( stream, string, stringLength, minLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, minLength, maxLength, DEFAULT_TAG )

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
int readOctetStringHole( STREAM *stream, int *length, const int minLength, 
						 const int tag );
int readBitStringHole( STREAM *stream, int *length, const int minLength,
					   const int tag );
int readGenericHole( STREAM *stream, int *length, const int minLength,
					 const int tag );
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
int readGenericHoleI( STREAM *stream, int *length, const int minLength, 
					  const int tag );

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

int readLongSequence( STREAM *stream, long *length );
int readLongSet( STREAM *stream, long *length );
int readLongConstructed( STREAM *stream, long *length, const int tag );
int readLongGenericHole( STREAM *stream, long *length, const int tag );
long getLongStreamObjectLength( STREAM *stream );
long getLongObjectLength( const void *certObjectPtr, const long length );

#endif /* !_ASN1_DEFINED */
