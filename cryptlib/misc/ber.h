/****************************************************************************
*																			*
*				ASN.1 Basic Encoding Rules Constants and Structures			*
*						Copyright Peter Gutmann 1992-2001					*
*																			*
****************************************************************************/

#ifndef _BER_DEFINED

#define _BER_DEFINED

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
	   BER_ID_STRING_BMP };

/* The encodings for the universal types */

#define BER_EOC				0	/* Pseudo-type for first EOC octet */
#define BER_RESERVED		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_RESERVED )
#define BER_BOOLEAN			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BOOLEAN )
#define BER_INTEGER			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_INTEGER )
#define BER_BITSTRING		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BITSTRING )
#define BER_OCTETSTRING		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OCTETSTRING )
#define BER_NULL			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_NULL )
#define BER_OBJECT_IDENTIFIER	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_IDENTIFIER )
#define BER_OBJECT_DESCRIPTOR	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_DESCRIPTOR )
#define BER_EXTERNAL		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EXTERNAL )
#define BER_REAL			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_REAL )
#define BER_ENUMERATED		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_ENUMERATED )
#define BER_EMBEDDED_PDV	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EMBEDDED_PDV )
#define BER_STRING_UTF8		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_UTF8 )
#define BER_13				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_13 )
#define BER_14				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_14 )
#define BER_15				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_15 )
#define BER_SEQUENCE		( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SEQUENCE )
#define BER_SET				( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SET )
#define BER_STRING_NUMERIC	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_NUMERIC )
#define BER_STRING_PRINTABLE	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_PRINTABLE )
#define BER_STRING_T61		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_T61 )
#define BER_STRING_VIDEOTEX	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_VIDEOTEX )
#define BER_STRING_IA5		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_IA5 )
#define BER_TIME_UTC		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_UTC )
#define BER_TIME_GENERALIZED	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_GENERALIZED )
#define BER_STRING_GRAPHIC	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GRAPHIC )
#define BER_STRING_ISO646	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_ISO646 )
#define BER_STRING_GENERAL	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GENERAL )
#define BER_STRING_UNIVERSAL	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_UNIVERSAL )
#define BER_29				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BER29 )
#define BER_STRING_BMP		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_BMP )

/* The encodings for constructed, indefinite-length tags and lengths */

#define BER_OCTETSTRING_INDEF	( ( BYTE * ) "\x24\x80" )
#define BER_SEQUENCE_INDEF	( ( BYTE * ) "\x30\x80" )
#define BER_SET_INDEF		( ( BYTE * ) "\x31\x80" )
#define BER_CTAG0_INDEF		( ( BYTE * ) "\xA0\x80" )
#define BER_END_INDEF		( ( BYTE * ) "\x00\x00" )

/* Masks to extract information from a tag number */

#define BER_CLASS_MASK			0xC0
#define BER_CONSTRUCTED_MASK	0x20
#define BER_SHORT_ID_MASK		0x1F

/* The maximum size for the short tag number encoding, and the magic value
   which indicates that a long encoding of the number is being used */

#define MAX_SHORT_BER_ID	30
#define LONG_BER_ID			0x1F

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

#endif /* !_BER_DEFINED */
