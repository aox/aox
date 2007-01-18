/****************************************************************************
*																			*
*							Certificate String Routines						*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* The character set (or at least ASN.1 string type) for a string.  Although 
   IA5String and VisibleString/ISO646String are technically different, the 
   only real difference is that IA5String allows the full range of control 
   characters, which isn't notably useful.  For this reason we treat both as 
   ISO646String.  Sometimes we can be fed Unicode strings that are just 
   bloated versions of another string type, so we need to account for these 
   as well.

   UTF-8 strings are a pain because they're almost never supported as any 
   native format.  For this reason we convert them to a more useful local
   character set (ASCII, 8859-1, or Unicode as appropriate) when we read 
   them to make them usable.  Although their use is required after the 
   cutover date of December 2003, by unspoken unanimous consensus of 
   implementors everywhere implementations are sticking with the existing 
   DN encoding to avoid breaking things */

typedef enum {
	STRINGTYPE_NONE,					/* No string type */

	/* 8-bit character types */
	STRINGTYPE_PRINTABLE,				/* PrintableString */
	STRINGTYPE_IA5,						/* IA5String */
		STRINGTYPE_VISIBLE = STRINGTYPE_IA5,	/* VisibleString */
										/* VisibleString as Unicode */
	STRINGTYPE_T61,						/* T61 (8859-1) string */

	/* 8-bit types masquerading as Unicode */
	STRINGTYPE_UNICODE_PRINTABLE,		/* PrintableString as Unicode */
	STRINGTYPE_UNICODE_IA5,				/* IA5String as Unicode */
		STRINGTYPE_UNICODE_VISIBLE = STRINGTYPE_UNICODE_IA5,
	STRINGTYPE_UNICODE_T61,				/* 8859-1 as Unicode */

	/* Unicode/UTF-8 */
	STRINGTYPE_UNICODE,					/* Unicode string */
	STRINGTYPE_UTF8						/* UTF-8 string */
	} ASN1_STRINGTYPE;

/* Since wchar_t can be anything from 8 bits (Borland C++ under DOS) to 64 
   bits (RISC Unixen), we define a bmpchar_t for Unicode/BMPString chars 
   which is always 16 bits as required for BMPStrings, to match wchar_t.  
   The conversion to and from a BMPString and wchar_t may require narrowing 
   or widening of characters, and possibly endianness conversion as well */

typedef unsigned short int bmpchar_t;	/* Unicode data type */
#define UCSIZE	2

/****************************************************************************
*																			*
*						Character Set Management Functions					*
*																			*
****************************************************************************/

/* Because of the bizarre (and mostly useless) collection of ASN.1 character
   types, we need to be very careful about what we allow in a string.  The
   following table is used to determine whether a character is valid within 
   a given string type.

   Although IA5String and VisibleString/ISO646String are technically
   different, the only real difference is that IA5String allows the full
   range of control characters, which isn't notably useful.  For this reason
   we treat both as ISO646String */

#define P	1						/* PrintableString */
#define I	2						/* IA5String/VisibleString/ISO646String */
#define PI	( P | I )				/* PrintableString and IA5String */

static const int FAR_BSS asn1CharFlags[] = {
	/* 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/* 10  11  12  13  14  15  16  17  18  19  1A  1B  1C  1D  1E  1F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/*		!	"	#	$	%	&	'	(	)	*	+	,	-	.	/ */
	   PI,	I,	I,	I,	I,	I,	I, PI, PI, PI,	I, PI, PI, PI, PI, PI,
	/*	0	1	2	3	4	5	6	7	8	9	:	;	<	=	>	? */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I, PI,	I, PI,
	/*	@	A	B	C	D	E	F	G	H	I	J	K	L	M	N	O */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	P	Q	R	S	T	U	V	W	X	Y	Z	[	\	]	^	_ */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	I,
	/*	`	a	b	c	d	e	f	g	h	i	j	k	l	m	n	o */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	p	q	r	s	t	u	v	w	x	y	z	{	|	}	~  DL */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	0
	};

#define nativeCharFlags	asn1CharFlags

/* Extract a widechar or bmpchar from an (arbitrarily-aligned) string */

static wchar_t getWidechar( const BYTE *string )
	{
	wchar_t ch = 0;
#ifdef DATA_LITTLEENDIAN
	int shiftAmt = 0;
#endif /* DATA_LITTLEENDIAN */
	int i;

	/* Since we're reading wchar_t-sized values from a char-aligned source, 
	   we have to assemble the data a byte at a time to handle systems where 
	   non-char values can only be accessed on word-aligned boundaries */
	for( i = 0; i < sizeof( wchar_t ); i++ )
		{
#ifdef DATA_LITTLEENDIAN
		ch |= *string++ << shiftAmt;
		shiftAmt += 8;
#else
		ch = ( ch << 8 ) | *string++;
#endif /* DATA_LITTLEENDIAN */
		}

	return( ch );
	}

static wchar_t getBmpchar( const BYTE *string )
	{
	return( ( ( ( bmpchar_t ) string[ 0 ] ) << 8 ) | \
				( bmpchar_t ) string[ 1 ] );
	}

/* Try and guess whether a native string is a widechar string */

static BOOLEAN isNativeWidecharString( const BYTE *string, const int length )
	{
	wchar_t wCh = getWidechar( string );
	int hiByte = 0, i;

	assert( !( length % WCSIZE ) );

	/* If it's too short to be a widechar string, it's definitely not 
	   Unicode */
	if( length < WCSIZE )
		/* "Too skinny to join the army they said.  Didn't make the weight
		    they said" */
		return( FALSE );

	/* If wchar_t is > 16 bits and the bits above 16 are set or all zero,
	   it's either definitely not Unicode or Unicode.  Note that some
	   compilers will complain of unreachable code here, unfortunately we
	   can't easily fix this since WCSIZE is usually an expression involving
	   sizeof(), which we can't handle via the preprocessor */
#if INT_MAX > 0xFFFFL
	if( WCSIZE > 2 )
		return( ( wCh > 0xFFFF ) ? FALSE : TRUE );
#endif /* > 16-bit machines */

	/* If wchar_t is 8 bits, it's never Unicode.  We make this conditional on
	   the system being 16-bit to avoid compiler warnings about dead code on
	   the majority of systems, which have > 8-bit wchar_t */
#if INT_MAX < 0xFFFFL
	if( WCSIZE < 2 )
		return( FALSE );
#endif /* WCSIZE */

	/* wchar_t is 16 bits, make sure that we don't get false positives with 
	   short strings.  Two-char strings are more likely to be ASCII than a 
	   single widechar, and repeated alternate chars (e.g. "tanaka") in an 
	   ASCII string appear to be widechars for the general-purpose check
	   below so we check for these in strings of 2-3 wide chars before we 
	   perform the general-purpose check */
	if( length <= ( WCSIZE * 3 ) && wCh > 0xFF )
		{
		if( length == WCSIZE )
			{
			/* Check for a two-char ASCII string, usually a country name */
			if( isPrint( string[ 0 ] ) && isPrint( string[ 1 ] ) )
				return( FALSE );
			}
		else
			{
			const int hi1 = wCh >> 8;
			const int hi2 = getWidechar( string + WCSIZE ) >> 8;
			const int hi3 = ( length > WCSIZE * 2 ) ? \
							getWidechar( string + ( WCSIZE * 2 ) ) >> 8 : hi1;

			assert( length == ( WCSIZE * 2 ) || length == ( WCSIZE * 3 ) );

			/* Check for alternate chars being ASCII */
			if( isAlnum( hi1 ) && isAlnum( hi2 ) && isAlnum( hi3 ) && \
				hi1 == hi2 && hi2 == hi3 )
				return( FALSE );
			}
		}

	/* wchar_t is 16 bits, check whether it's in the form { 00 xx }* or
	   { AA|00 xx }*, either ASCII-as-Unicode or Unicode.  The code used 
	   below is safe because to get to this point the string has to be some 
	   multiple of 2 bytes long.  Note that if someone passes in a 1-byte 
	   string and mistakenly includes the terminator in the length it'll be 
	   identified as a 16-bit widechar string, but this doesn't really 
	   matter since it'll get "converted" into a non-widechar string later */
	for( i = 0; i < length; i += WCSIZE )
		{
		wCh = getWidechar( string );
		string += WCSIZE;
		if( wCh > 0xFF )
			{
			const int wChHi = wCh >> 8;

			assert( wChHi );

			/* If we haven't already seen a high byte, remember it */
			if( hiByte == 0 )
				hiByte = wChHi;
			else
				/* If the current high byte doesn't match the previous one,
				   it's probably 8-bit chars */
				if( wChHi != hiByte )
					return( FALSE );
			}
		}

	return( TRUE );				/* Probably 16-bit chars */
	}

/* Try and figure out the true string type for an ASN.1-encoded or native 
   string.  This detects (or at least tries to detect) not only the basic 
   string type, but also basic string types encoded as widechar strings, and 
   widechar strings encoded as basic string types */

static ASN1_STRINGTYPE get8bitStringType( const BYTE *string, 
										  const int stringLen )
	{
	BOOLEAN notPrintable = FALSE, notIA5 = FALSE;
	int length;

	/* Walk down the string checking each character */
	for( length = stringLen; length > 0; length-- )
		{
		const BYTE ch = *string++;

		/* If the high bit is set, it's not an ASCII subset */
		if( ch >= 128 )
			{
			notPrintable = notIA5 = TRUE;
			if( !asn1CharFlags[ ch & 0x7F ] )
				/* It's not 8859-1 either, probably some odd widechar type */
				return( STRINGTYPE_NONE );
			}
		else
			{
			/* Check whether it's a PrintableString */
			if( !( asn1CharFlags[ ch ] & P ) )
				notPrintable = TRUE;

			/* Check whether it's something peculiar */
			if( !asn1CharFlags[ ch ] )
				return( STRINGTYPE_NONE );
			}
		}

	return( notIA5 ? STRINGTYPE_T61 : notPrintable ? STRINGTYPE_IA5 : \
			STRINGTYPE_PRINTABLE );
	}

static ASN1_STRINGTYPE getAsn1StringType( const BYTE *string, 
										  const int stringLen, 
										  const int stringTag )
	{
	assert( isReadPtr( string, stringLen ) );

	/* If it's a multiple of bmpchar_t in size, check whether it's a 
	   BMPString stuffed into a T61String or an 8-bit string encoded as a 
	   BMPString.  The following code assumes that anything claiming to be a 
	   BMPString is always something else, this currently seems to hold true 
	   for all BMPStrings.  Hopefully by the time anyone gets around to 
	   using > 8-bit characters everyone will be using UTF8Strings, because 
	   there's no easy way to distinguish between a byte string which is a 
	   > 8-bit BMPString and a 7/8-bit string */
	if( !( stringLen % UCSIZE ) && *string == '\0' )
		{
		BOOLEAN notPrintable = FALSE, notIA5 = FALSE;
		int length;

		/* The first character is a null, it's an 8-bit string stuffed into 
		   a BMPString (these are always big-endian, even coming from 
		   Microsoft software, so we don't have to check for a null as the
		   second character) */
		for( length = stringLen; length > 0; length -= UCSIZE )
			{
			/* Since we're reading bmpchar_t-sized values from a char-
			   aligned source, we have to assemble the data a byte at a time 
			   to handle systems where non-char values can only be accessed 
			   on word-aligned boundaries */
			const bmpchar_t ch = getBmpchar( string );
			string += UCSIZE;

			/* If the high bit is set, it's not an ASCII subset */
			if( ch >= 128 )
				{
				notPrintable = notIA5 = TRUE;
				if( !asn1CharFlags[ ch & 0x7F ] )
					/* It's not 8859-1 either */
					return( STRINGTYPE_UNICODE );
				}
			else
				/* Check whether it's a PrintableString */
				if( !( asn1CharFlags[ ch ] & P ) )
					notPrintable = TRUE;
			}

		return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
				STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
		}

	/* If it's supposed to be Unicode and not an 8-bit string encoded as a
	   Unicode string, it's Unicode */
	if( stringTag == BER_STRING_BMP && !( stringLen % UCSIZE ) )
		return( STRINGTYPE_UNICODE );

	/* Determine the 8-bit string type */
	return( get8bitStringType( string, stringLen ) );
	}

static ASN1_STRINGTYPE getNativeStringType( const BYTE *string, 
											const int stringLen )
	{
	BOOLEAN notPrintable = FALSE, notIA5 = FALSE;

	assert( isReadPtr( string, stringLen ) );

	/* If it's a multiple of wchar_t in size, check whether it's a widechar 
	   string.  If it's a widechar string it may actually be something else 
	   that's been bloated out into widechars, so we check for this as 
	   well */
	if( !( stringLen % WCSIZE ) && \
		isNativeWidecharString( string, stringLen ) )
		{
		int length;

		for( length = stringLen; length > 0; length -= WCSIZE )
			{
			const wchar_t ch = getWidechar( string );
			string += WCSIZE;

			/* Safety check */
			if( ch & 0xFFFF0000L )
				return( STRINGTYPE_NONE );

			/* If the high bit is set, it's not an ASCII subset */
			if( ch >= 128 )
				{
				notPrintable = notIA5 = TRUE;
				if( !nativeCharFlags[ ch & 0x7F ] )
					/* It's not 8859-1 either */
					return( STRINGTYPE_UNICODE );
				}
			else
				/* Check whether it's a PrintableString */
				if( !( nativeCharFlags[ ch ] & P ) )
					notPrintable = TRUE;
			}

		return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
				STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
		}

	/* Determine the 8-bit string type */
	return( get8bitStringType( string, stringLen ) );
	}

/****************************************************************************
*																			*
*								UTF-8 Functions								*
*																			*
****************************************************************************/

/* UTF-8 length-of-length handling */

static const int utf8bytesTbl[] = {
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6
	};

#define utf8bytes( value )	( ( value <= 192 ) ? 1 : \
							  ( value <= 224 ) ? 2 : \
							  utf8bytesTbl[ ( value ) - 224 ] )

/* Parse one character from the string, enforcing the UTF-8 canonical-
   encoding rules:

	  00 -  7F = 0xxxxxxx
	 80 -  7FF = 110xxxxx 10xxxxxx 
	800 - FFFF = 1110xxxx 10xxxxxx 10xxxxxx */

static long getUTF8Char( const BYTE *string, const int maxLen,
						 int *charByteCount )
	{
	const int firstChar = *string;
	const int count = utf8bytes( firstChar );
	long ch;

	*charByteCount = count;
	if( count < 1 || count > 3 || count > maxLen )
		return( CRYPT_ERROR_BADDATA );
	switch( count )
		{
		case 1:
			ch = firstChar & 0x7F;
			break;

		case 2:
			if( ( firstChar & 0xE0 ) != 0xC0 || \
				( string[ 1 ] & 0xC0 ) != 0x80 )
				return( CRYPT_ERROR_BADDATA );
			ch = ( ( firstChar & 0x1F ) << 6 ) | \
				   ( string[ 1 ] & 0x3F );
			break;

		case 3:
			if( ( firstChar & 0xF0 ) != 0xE0 || \
				( string[ 1 ] & 0xC0 ) != 0x80 || \
				( string[ 2 ] & 0xC0 ) != 0x80 )
				return( CRYPT_ERROR_BADDATA );
			ch = ( ( firstChar & 0x1F ) << 12 ) | \
				 ( ( string[ 1 ] & 0x3F ) << 6 ) | \
				   ( string[ 2 ] & 0x3F );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
		}

	return( ch );
	}

#if 0	/* Currently unused, see note at start */

static int putUTF8Char( BYTE *string, const long ch )
	{
	if( ch < 0x80 )
		{
		*string = ( BYTE ) ch;
		return( 1 );
		}
	if( ch < 0x0800 )
		{
		*string++ = ( BYTE )( 0xC0 | ch >> 6 );
		*string = ( BYTE )( 0x80 | ch & 0x3F );
		return( 2 );
		}
	*string++ = ( BYTE )( 0xE0 | ch >> 12 );
	*string++ = ( BYTE )( 0x80 | ( ( ch >> 6 ) & 0x3F ) );
	*string = ( BYTE )( 0x80 | ch & 0x3F );
	return( 3 );
	}
#endif /* 0 */

/* Determine the length of a string encoded as UTF-8 */

static int utf8DestStringLen( const void *string, const int stringLen,
							  const BOOLEAN isWideChar )
	{
	if( isWideChar )
		{
		const wchar_t *wcStrPtr = ( wchar_t * ) string;
		int length = 0, i;

		for( i = 0; i < stringLen; i += WCSIZE )
			{
			const wchar_t ch = *wcStrPtr++;

			length += ( ch < 0x80 ) ? 1 : ( ch < 0x0800 ) ? 2 : 3;
			}

		return( length );
		}

	return( stringLen );
	}

/* Convert a UTF-8 string to ASCII, 8859-1, or Unicode, and vice versa */

static int copyFromUtf8String( void *dest, int *destLen, const int destMaxLen,
							   const void *source, const int sourceLen )
	{
	ASN1_STRINGTYPE stringType = STRINGTYPE_PRINTABLE;
	const BYTE *srcPtr = source;
	wchar_t *wcDestPtr = dest;
	BYTE *destPtr = dest;
	int noChars = 0, count, i;

	assert( isWritePtr( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtr( source, sourceLen ) );

	/* Clear the return value */
	*destLen = 0;

	/* Scan the string to determine its length and the widest character type 
	   in it.  We have to process the entire string even once we've 
	   identified it as containing the widest string type (Unicode) in order 
	   to check for malformed chars */
	for( i = 0; i < sourceLen; i += count )
		{
		const long ch = getUTF8Char( srcPtr + i, sourceLen - i, &count );

		if( ch < 0 || ch > 0xFFFFL )
			return( CRYPT_ERROR_BADDATA );
		noChars++;
		if( stringType == STRINGTYPE_UNICODE || ch > 0xFF )
			stringType = STRINGTYPE_UNICODE;
		else
			/* If it's not a PrintableString char, mark it as T61 if it's
			   within range, otherwise it's Unicode */
			if( ch >= 128 )
				stringType = ( asn1CharFlags[ ( int ) ch & 0x7F ] & P ) ? \
							 STRINGTYPE_T61 : STRINGTYPE_UNICODE;
		}

	/* Make sure that the translated string will fit into the destination 
	   buffer */
	*destLen = noChars * ( ( stringType == STRINGTYPE_UNICODE ) ? \
						   WCSIZE : 1 );
	if( *destLen > destMaxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Perform a second pass copying the string over */
	for( i = 0; i < sourceLen; i += count )
		{
		const long ch = getUTF8Char( srcPtr + i, sourceLen - i, &count );

		/* Copy the result as a Unicode or ASCII/8859-1 character */
		if( stringType == STRINGTYPE_UNICODE )
			*wcDestPtr++ = ( wchar_t ) ch;
		else
			*destPtr++ = ( BYTE ) ch;
		}

	return( stringType );
	}

#if 0	/* Currently unused, see note at start */

static int copyToUtf8String( void *dest, const int destMaxLen,
							 const void *source, const int sourceLen,
							 const BOOLEAN isWideChar )
	{
	assert( isWritePtr( dest, destMaxLen ) );
	assert( isReadPtr( source, sourceLen ) );

	if( isWideChar )
		{
		const wchar_t *wcStrPtr = source;
		BYTE *destPtr = dest;
		int length = 0, i;

		for( i = 0; i < sourceLen; i += WCSIZE )
			{
			length += putUTF8Char( destPtr, *wcStrPtr++ );
			destPtr += length;
			}
		return( length );
		}

	memcpy( dest, source, sourceLen );
	return( sourceLen );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						ASN.1 String Conversion Functions					*
*																			*
****************************************************************************/

/* Check that a text string contains valid characters for its string type.
   This is used in non-DN strings where we can't vary the string type based 
   on the characters being used */

BOOLEAN checkTextStringData( const char *string, const int stringLength,
							 const BOOLEAN isPrintableString )
	{
	const int charTypeMask = isPrintableString ? P : I;
	int i;

	for( i = 0; i < stringLength; i++ )
		{
		const int ch = string[ i ];

		if( ch < 0 || ch >= 128 || !isPrint( ch ) )
			return( FALSE );
		if( !( nativeCharFlags[ ch ] & charTypeMask ) )
			return( FALSE );
		}

	return( TRUE );
	}

/* Convert a character string from the format used in the certificate into 
   the native format */

int copyFromAsn1String( void *dest, int *destLen, const int maxLen, 
						const void *source, const int sourceLen, 
						const int stringTag )
	{
	const ASN1_STRINGTYPE stringType = getAsn1StringType( source, sourceLen, 
														  stringTag );

	assert( isWritePtr( dest, maxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtr( source, sourceLen ) );

	/* Clear return values */
	*destLen = 0;

	/* If it's a BMP or UTF-8 string, convert it to the native format */
	if( stringType == STRINGTYPE_UNICODE )
		{
		const BYTE *string = source;
		wchar_t *wcDestPtr = ( wchar_t * ) dest;
		const int newLen = ( sourceLen / UCSIZE ) * WCSIZE;
		int i;

		if( newLen > maxLen )
			return( CRYPT_ERROR_OVERFLOW );
		
		/* Since we're reading bmpchar_t-sized values from a char-aligned
		   source, we have to assemble the data a byte at a time to handle
		   systems where non-char values can only be accessed on word-
		   aligned boundaries */
		for( i = 0; i < sourceLen / UCSIZE; i++ )
			{
			*wcDestPtr++ = getBmpchar( string );
			string += UCSIZE;
			}
		*destLen = newLen;
		return( CRYPT_OK );
		}
	if( stringTag == BER_STRING_UTF8 )
		return( copyFromUtf8String( dest, destLen, maxLen, source, 
									sourceLen ) );

	/* If it's something masquerading as Unicode, convert it to the narrower
	   format.  Note that STRINGTYPE_UNICODE_VISIBLE is already covered by 
	   STRINGTYPE_UNICODE_IA5, so we don't need to check for this separately */
	if( stringType == STRINGTYPE_UNICODE_PRINTABLE || \
		stringType == STRINGTYPE_UNICODE_IA5 || \
		stringType == STRINGTYPE_UNICODE_T61 )
		{
		const BYTE *srcPtr = source;
		BYTE *destPtr = dest;
		int i;

		if( sourceLen / UCSIZE > maxLen )
			return( CRYPT_ERROR_OVERFLOW );
		for( i = 1; i < sourceLen; i += UCSIZE )
			*destPtr++ = ( BYTE ) srcPtr[ i ];
		*destLen = sourceLen / UCSIZE;

		return( CRYPT_OK );
		}

	/* It's an 8-bit character set, just copy it across */
	if( sourceLen > maxLen )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( dest, source, sourceLen );
	*destLen = sourceLen;

	/* If it's a T61String, try and guess whether it's using floating 
	   diacritics and convert them to the correct latin-1 representation.  
	   This is mostly guesswork since some implementations use floating 
	   diacritics and some don't, the only known user is Deutsche Telekom 
	   who use them for a/o/u-umlauts so we only interpret the character if 
	   the result would be one of these values */
	if( stringTag == BER_STRING_T61 )
		{
		BYTE *destPtr = dest;
		int length = sourceLen, i;

		for( i = 0; i < length - 1; i++ )
			{
			if( destPtr[ i ] == 0xC8 )
				{
				int ch = destPtr[ i + 1 ];

				/* If it's an umlautable character, convert the following
				   ASCII value to the equivalent latin-1 form and move the
				   rest of the string down */
				if( ch == 0x61 || ch == 0x41 ||		/* a, A */
					ch == 0x6F || ch == 0x4F ||		/* o, O */
					ch == 0x75 || ch == 0x55 )		/* u, U */
					{
					typedef struct { int src, dest; } CHARMAP_INFO;
					static const CHARMAP_INFO charMap[] = {
						{ 0x61, 0xE4 }, { 0x41, 0xC4 },	/* a, A */
						{ 0x6F, 0xF6 }, { 0x4F, 0xD6 },	/* o, O */
						{ 0x75, 0xFC }, { 0x55, 0xDC },	/* u, U */
						{ 0x00, '?' }
						};
					int charIndex;

					for( charIndex = 0; 
						 charMap[ charIndex ].src && \
							charMap[ charIndex ].src != ch && \
							charIndex < FAILSAFE_ARRAYSIZE( charMap, CHARMAP_INFO ); 
						 charIndex++ );
					if( charIndex >= FAILSAFE_ARRAYSIZE( charMap, CHARMAP_INFO ) )
						retIntError();
					destPtr[ i ] = charMap[ charIndex ].dest;
					if( length - i > 2 )
						memmove( destPtr + i + 1, destPtr + i + 2,
								 length - ( i + 2 ) );
					length--;
					}
				}
			}
		*destLen = length;
		}

	return( CRYPT_OK );
	}

/* Convert a character string from the native format to the format used in 
   the certificate */

int getAsn1StringInfo( const void *string, const int stringLen,
					   int *stringType, int *asn1StringType, 
					   int *asn1StringLen )
	{
	assert( isReadPtr( string, stringLen ) );
	assert( isWritePtr( stringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringLen, sizeof( int ) ) );

	*stringType = getNativeStringType( string, stringLen );
	switch( *stringType )
		{
		case STRINGTYPE_UNICODE:
			/* It's a widechar string, output is Unicode */
			*asn1StringLen = ( stringLen / WCSIZE ) * UCSIZE;
			*asn1StringType = BER_STRING_BMP;
			return( CRYPT_OK );

		case STRINGTYPE_UNICODE_PRINTABLE:
		case STRINGTYPE_UNICODE_IA5:
		case STRINGTYPE_UNICODE_T61:
			/* It's an ASCII string masquerading as Unicode, output is an 
			   8-bit string type */
			*asn1StringLen = stringLen / WCSIZE;
			*asn1StringType = ( *stringType == STRINGTYPE_UNICODE_PRINTABLE ) ? \
								BER_STRING_PRINTABLE : \
							  ( *stringType == STRINGTYPE_UNICODE_IA5 ) ? \
								BER_STRING_IA5 : BER_STRING_T61;
			return( CRYPT_OK );

		case STRINGTYPE_UTF8:
			/* It's a widechar string encoded as UTF-8, output is a 
			   variable-length UTF-8 string.  This isn't currently used
			   but is only present as a placeholder, see the comment at the 
			   start of this module for details */
			*asn1StringLen = utf8DestStringLen( string, stringLen,
						( *stringType == STRINGTYPE_UNICODE || \
						  *stringType == STRINGTYPE_UNICODE_PRINTABLE || \
						  *stringType == STRINGTYPE_UNICODE_IA5 || \
							  *stringType == STRINGTYPE_UNICODE_T61 ) ? \
						TRUE : FALSE );
			*asn1StringType = BER_STRING_UTF8;
			return( CRYPT_OK );

		default:
			/* It's an ASCII string */
			*asn1StringLen = stringLen;
			*asn1StringType = ( *stringType == STRINGTYPE_PRINTABLE ) ? \
								BER_STRING_PRINTABLE : \
							  ( *stringType == STRINGTYPE_IA5 ) ? \
								BER_STRING_IA5 : BER_STRING_T61;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

int copyToAsn1String( void *dest, int *destLen, const int maxLen,
					  const void *source, const int sourceLen, 
					  const int stringType )
	{
	assert( isWritePtr( dest, maxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtr( source, sourceLen ) );

	switch( stringType )
		{
		case STRINGTYPE_UNICODE:
			{
			const BYTE *srcPtr = source;
			BYTE *destPtr = dest;
			const int newLen = ( sourceLen / WCSIZE ) * UCSIZE;
			int length = sourceLen, i;

			/* It's a widechar, convert it to Unicode */
			*destLen = newLen;
			if( newLen > maxLen )
				return( CRYPT_ERROR_OVERFLOW );

			/* Copy the string across, converting from wchar_t to bmpchar_t 
			   as we go, with endianness conversion if necessary */
			for( i = 0; i < length; i += WCSIZE )
				{
				const wchar_t wCh = getWidechar( srcPtr );
				srcPtr += WCSIZE;

				*destPtr++ = ( BYTE ) ( ( wCh >> 8 ) & 0xFF );
				*destPtr++ = ( BYTE ) ( wCh & 0xFF );
				}

			return( CRYPT_OK );
			}

		case STRINGTYPE_UNICODE_PRINTABLE:
		case STRINGTYPE_UNICODE_IA5:
		case STRINGTYPE_UNICODE_T61:
			{
			const wchar_t *srcPtr = ( wchar_t * ) source;
			BYTE *destPtr = dest;
			int i;

			/* It's something masquerading as Unicode, convert it to the 
			   narrower format.  Note that STRINGTYPE_UNICODE_VISIBLE is 
			   already covered by STRINGTYPE_UNICODE_IA5, so we don't need 
			   to check for this separately */
			*destLen = sourceLen / WCSIZE;
			if( sourceLen / WCSIZE > maxLen )
				return( CRYPT_ERROR_OVERFLOW );
			for( i = 0; i < sourceLen; i += WCSIZE )
				*destPtr++ = ( BYTE ) *srcPtr++;
			return( CRYPT_OK );
			}

		default:
			/* It's an 8-bit character set, just copy it across */
			*destLen = sourceLen;
			if( sourceLen > maxLen )
				return( CRYPT_ERROR_OVERFLOW );
			memcpy( dest, source, sourceLen );
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
