/****************************************************************************
*																			*
*							Certificate String Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Character Set Management Functions					*
*																			*
****************************************************************************/

/* The character set (or at least ASN.1 string type) for a string.  Although 
   IA5String and VisibleString/ISO646String are technically different, the 
   only real difference is that IA5String allows the full range of control 
   characters, which isn't notably useful.  For this reason we treat both as 
   ISO646String.  Sometimes we can be fed Unicode strings that are just 
   bloated versions of another string type, so we need to account for these 
   as well.

   UTF-8 strings are a pain because they're not supported as any native
   format and almost anything they can do is covered by another character 
   set.  For this reason we currently convert them to a more useful set 
   (ASCII, 8859-1, or Unicode as appropriate) to make them usable.  UTF-8 
   strings are currently, never written, although they'll be required after
   the PKIX cutover date of December 2003.  It'll be interesting to see how
   much software breaks with these strings */

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
	STRINGTYPE_UTF8						/* UTF-8 string (never written) */
	} ASN1_STRINGTYPE;

/* Since wchar_t can be anything from 8 bits (Borland C++ under DOS) to 64 
   bits (RISC Unixen), we define a bmpchar_t for Unicode/BMPString chars 
   which is always 16 bits as required for BMPStrings, to match wchar_t.  
   The conversion to and from a BMPString and wchar_t may require narrowing 
   or widening of characters, and possibly endianness conversion as well */

typedef unsigned short int bmpchar_t;	/* Unicode data type */
#define UCSIZE	2

/* Because of the bizarre (and mostly useless) collection of ASN.1 character
   types, we need to be very careful about what we allow in a string.  The
   following table is used to determine whether a character is valid within
   certain string types.

   Although IA5String and VisibleString/ISO646String are technically
   different, the only real difference is that IA5String allows the full
   range of control characters, which isn't notably useful.  For this reason
   we treat both as ISO646String */

#define P	1						/* PrintableString */
#define I	2						/* IA5String/VisibleString/ISO646String */
#define PI	( P | I )				/* PrintableString and IA5String */

static const FAR_BSS int asn1CharFlags[] = {
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

/* Try and guess whether a native string is a widechar string */

static BOOLEAN isNativeWidecharString( const BYTE *string, const int length )
	{
	wchar_t *wcString = ( wchar_t * ) string;
	int hiByte = 0, i;

	assert( !( length % WCSIZE ) );

	/* If it's too short to be a widechar string, it's definitely not 
	   Unicode */
	if( length < WCSIZE )
		/* "Too skinny to join the army they said.  Didn't make the weight
		    they said" */
		return( FALSE );

	/* If wchar_t is > 16 bits and the bits above 16 are set or all zero,
	   it's either definitely not Unicode or Unicode */
#if INT_MAX > 0xFFFFL
	if( WCSIZE > 2 )
		return( ( *wcString > 0xFFFF ) ? FALSE : TRUE );
#endif /* > 16-bit machines */

	/* wchar_t is 16 bits, check whether it's in the form { 00 xx }* or
	   { AA|00 xx }*, either ASCII-as-Unicode or Unicode.  The code used is 
	   safe because to get to this point the string has to be some multiple 
	   of 2 bytes long.  Note that if someone passes in a 1-byte string and 
	   mistakenly includes the terminator in the length it'll be identified 
	   as a 16-bit widechar string, but this doesn't really matter since 
	   it'll get "converted" into a non-widechar string later */
	for( i = 0; i < length; i += WCSIZE )
		{
		const wchar_t wch = *wcString++;

		if( wch > 0xFF )
			{
			const int wchHi = wch >> 8;

			assert( wchHi );

			/* If we haven't already seen a high byte, remember it */
			if( hiByte == 0 )
				hiByte = wchHi;
			else
				/* If the current high byte doesn't match the previous one,
				   it's probably 8-bit chars */
				if( wchHi != hiByte )
					return( FALSE );

			/* Special-case handling for short strings to reduce false
			   positives: If it's a one- or two-wchar_t string and the high 
			   chars are ASCII chars, it's probably ASCII */
			if( length == WCSIZE && wchHi > ' ' )
				return( FALSE );
			if( length == WCSIZE * 2 && i == WCSIZE && \
				hiByte > ' ' && wchHi > ' ' )
				return( FALSE );
			}
		}

	return( TRUE );				/* Probably 16-bit chars */
	}

/* Try and figure out the string type for a string.  This detects (or at 
   least tries to detect) not only the basic string type, but also basic 
   string types encoded as widechar strings, and widechar strings encoded as 
   basic string types */

static ASN1_STRINGTYPE getAsn1StringType( const BYTE *string, int length )
	{
	BOOLEAN notPrintable = FALSE, notIA5 = FALSE;

	assert( string != NULL );
	assert( length > 0 );

	/* If it's a multiple of bmpchar_t in size, check whether it's a 
	   BMPString stuffed into a T61String or an 8-bit string encoded as a 
	   BMPString.  The following code assumes that anything claiming to be a 
	   BMPString is always something else, this currently seems to hold true 
	   for all BMPStrings.  Hopefully by the time anyone gets around to 
	   using > 8-bit characters everyone will be using UTF8Strings because 
	   there's no easy way to distinguish between a byte string which is a 
	   > 8-bit BMPString and a 7/8-bit string */
	if( !( length % UCSIZE ) )
		{
		bmpchar_t *bmpString = ( bmpchar_t * ) string;
		int stringLength = length;

		/* If the first character is a null, it's an 8-bit string stuffed 
		   into a BMPString */
		if( !*string )
			{
			while( stringLength > 0 )
				{
				/* BMPString characters are always big-endian, so we need to 
				   convert them if we're on a little-endian system */
#ifdef DATA_LITTLEENDIAN
				bmpchar_t ch = ( ( *bmpString & 0xFF ) << 8 ) | \
							   ( *bmpString >> 8 );
#else
				bmpchar_t ch = *bmpString;
#endif /* DATA_LITTLEENDIAN */

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

				bmpString++;
				stringLength -= UCSIZE;
				}

			return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
					STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
			}
		}

	/* Walk down the string checking each character */
	while( length-- )
		{
		BYTE ch = *string;

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

		string++;
		}

	return( notIA5 ? STRINGTYPE_T61 : notPrintable ? STRINGTYPE_IA5 : \
			STRINGTYPE_PRINTABLE );
	}

static ASN1_STRINGTYPE getNativeStringType( const BYTE *string, int length )
	{
	BOOLEAN notPrintable = FALSE, notIA5 = FALSE;

	assert( string != NULL );
	assert( length > 0 );

	/* If it's a multiple of wchar_t in size, check whether it's a widechar 
	   string.  If it's a widechar string it may actually be something else 
	   that has been bloated out into widechars, so we check for this as 
	   well */
	if( !( length % WCSIZE ) && isNativeWidecharString( string, length ) )
		{
		wchar_t *wcString = ( wchar_t * ) string;

		while( length > 0 )
			{
			wchar_t ch = *wcString;

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

			wcString++;
			length -= WCSIZE;
			}

		return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
				STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
		}

	/* Walk down the string checking each character */
	while( length-- )
		{
		BYTE ch = *string;

		/* If the high bit is set, it's not an ASCII subset */
		if( ch >= 128 )
			{
			notPrintable = notIA5 = TRUE;
			if( !nativeCharFlags[ ch & 0x7F ] )
				/* It's not 8859-1 either, probably some odd widechar type */
				return( STRINGTYPE_NONE );
			}
		else
			{
			/* Check whether it's a PrintableString */
			if( !( nativeCharFlags[ ch ] & P ) )
				notPrintable = TRUE;

			/* Check whether it's something peculiar */
			if( !nativeCharFlags[ ch ] )
				return( STRINGTYPE_NONE );
			}

		string++;
		}

	return( notIA5 ? STRINGTYPE_T61 : notPrintable ? STRINGTYPE_IA5 : \
			STRINGTYPE_PRINTABLE );
	}

/* Convert a UTF-8 string to ASCII, 8859-1, or Unicode */

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

static long getUnicodeChar( const BYTE *stringPtr, const int maxLen,
							int *charByteCount )
	{
	const int firstChar = *stringPtr;
	const int count = utf8bytes( firstChar );
	long ch;

	*charByteCount = count;
	if( count < 1 || count > 3 || count > maxLen )
		return( CRYPT_ERROR_BADDATA );
	switch( count )
		{
		case 0:
			ch = firstChar & 0x7F;
			break;

		case 1:
			if( ( firstChar & 0xE0 ) != 0xC0 || \
				( stringPtr[ 1 ] & 0xC0 ) != 0x80 )
				return( CRYPT_ERROR_BADDATA );
			ch = ( ( firstChar & 0x1F ) << 6 ) | \
				   ( stringPtr[ 1 ] & 0x3F );
			break;

		case 2:
			if( ( firstChar & 0xF0 ) != 0xE0 || \
				( stringPtr[ 1 ] & 0xC0 ) != 0x80 || \
				( stringPtr[ 2 ] & 0xC0 ) != 0x80 )
				return( CRYPT_ERROR_BADDATA );
			ch = ( ( firstChar & 0x1F ) << 12 ) | \
				 ( ( stringPtr[ 1 ] & 0x3F ) << 6 ) | \
				   ( stringPtr[ 2 ] & 0x3F );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
		}

	return( ch );
	}

static int copyFromUtf8String( void *dest, int *destLen, const int maxLen,
							   const void *source, const int sourceLen )
	{
	ASN1_STRINGTYPE stringType = STRINGTYPE_PRINTABLE;
	const BYTE *srcPtr = source;
	wchar_t *wcDestPtr = dest;
	BYTE *destPtr = dest;
	int noChars = 0, count, i;

	/* Clear the return value */
	*destLen = 0;

	/* Scan the string to determine the widest character type in it */
	for( i = 0; i < sourceLen; i += count )
		{
		const long ch = getUnicodeChar( srcPtr + i, sourceLen - i, &count );

		if( ch < 0 || ch > 0xFFFFUL )
			return( CRYPT_ERROR_BADDATA );
		noChars++;
		if( ch > 0xFF )
			{
			stringType = STRINGTYPE_UNICODE;
			break;
			}

		/* Check which range it fits into */
		if( !( asn1CharFlags[ ( int ) ch ] & P ) )
			{
			/* If it's not a PrintableString char, mark it as T61 if it's
			   within range and we haven't already hit a Unicode char */
			if( asn1CharFlags[ ( int ) ch & 0x7F ] & I )
				stringType = STRINGTYPE_T61;
			else
				{
				stringType = STRINGTYPE_UNICODE;
				break;
				}
			}
		}

	/* Make sure the translated string will fit in the destination buffer */
	*destLen = noChars * ( ( stringType == STRINGTYPE_UNICODE ) ? \
						   WCSIZE : 1 );
	if( *destLen > maxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Perform a second pass copying the string over */
	for( i = 0; i < sourceLen; i += count )
		{
		const long ch = getUnicodeChar( srcPtr + i, sourceLen - i, &count );

		/* Copy the result as a Unicode or ASCII/8859-1 character */
		if( stringType == STRINGTYPE_UNICODE )
			*wcDestPtr++ = ( wchar_t ) ch;
		else
			*destPtr++ = ( BYTE ) ch;
		}

	return( stringType );
	}

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

/****************************************************************************
*																			*
*						ASN.1 String Conversion Functions					*
*																			*
****************************************************************************/

/* Convert a character string from the format used in the certificate into 
   the native format. This canonicalises the encoding (e.g. Unicode -> ASCII)
   and converts the character set, since we can't read the string with
   readCharacterString() because it hasn't been canonicalised at that point */

int copyFromAsn1String( void *dest, int *destLen, const int maxLen, 
						const void *source, const int sourceLen, 
						const int stringTag )
	{
	const ASN1_STRINGTYPE stringType = getAsn1StringType( source, sourceLen );

	/* Set default return values */
	*destLen = 0;

	/* If it's a BMP or UTF-8 string, convert it to the native format */
	if( stringType == STRINGTYPE_UNICODE )
		{
		const bmpchar_t *bmpSrcPtr = ( bmpchar_t * ) source;
		wchar_t *wcDestPtr = ( wchar_t * ) dest;
		const int newLen = ( sourceLen / UCSIZE ) * WCSIZE;
		int i;

		if( newLen > maxLen )
			return( CRYPT_ERROR_OVERFLOW );
		for( i = 0; i < sourceLen / UCSIZE; i++ )
#ifdef DATA_LITTLEENDIAN
		/* BMPString characters are always big-endian, so we need to convert
		   them if we're on a little-endian system */
			wcDestPtr[ i ] = ( ( bmpSrcPtr[ i ] & 0xFF ) << 8 ) | \
							   ( bmpSrcPtr[ i ] >> 8 );
#else
			wcDestPtr[ i ] = ( wchar_t ) bmpSrcPtr[ i ];
#endif /* DATA_LITTLEENDIAN */
		*destLen = newLen;
		return( CRYPT_OK );
		}
	if( stringTag == BER_STRING_UTF8 )
		{
		return( copyFromUtf8String( dest, destLen, maxLen, source, 
									sourceLen ) );
		}

	/* If it's something masquerading as Unicode, convert it to the narrower
	   format.  Note that STRINGTYPE_UNICODE_VISIBLE is already covered by 
	   STRINGTYPE_UNICODE_IA5, so we don't need to check for this seperately */
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
					static const struct {
						int src, dest;
						} charMap[] = {
						{ 0x61, 0xE4 }, { 0x41, 0xC4 },	/* a, A */
						{ 0x6F, 0xF6 }, { 0x4F, 0xD6 },	/* o, O */
						{ 0x75, 0xFC }, { 0x55, 0xDC },	/* u, U */
						{ 0x00, '?' }
						};
					int charIndex;

					for( charIndex = 0; charMap[ charIndex ].src && \
										charMap[ charIndex ].src != ch; charIndex++ );
					destPtr[ i ] = charMap[ charIndex ].dest;
					if( length - i > 2 )
						memmove( destPtr + i + 1, destPtr + i + 2,
								 length - ( i + 2 ) );
					length--;
					}
				}
		*destLen = length;
		}

	return( CRYPT_OK );
	}

/* Convert a character string from the native format to the format used in 
   the certificate. This canonicalises the encoding (e.g. Unicode -> ASCII)
   but doesn't convert the character set, since this is done by 
   writeCharacterString() */

int copyToAsn1String( void *dest, int *destLen, const int maxLen,
					  const void *source, const int sourceLen )
	{
	const ASN1_STRINGTYPE stringType = getNativeStringType( source, sourceLen );

	/* If it's Unicode, convert it to the appropriate format */
	if( stringType == STRINGTYPE_UNICODE )
		{
		const wchar_t *srcPtr = ( wchar_t * ) source;
		bmpchar_t *bmpDestPtr = ( bmpchar_t * ) dest;
		const int newLen = ( sourceLen / WCSIZE ) * UCSIZE;
		int length = sourceLen, i;

		/* If it's just a length check, we're done */
		*destLen = newLen;
		if( newLen > maxLen )
			return( CRYPT_ERROR_OVERFLOW );
		if( dest == NULL )
			return( BER_STRING_BMP );

		/* Copy the string across, converting from wchar_t to bmpchar_t as 
		   we go, with endianness conversion if necessary */
		for( i = 0; i < length; i += WCSIZE )
			{
			wchar_t ch = *srcPtr++;
#ifdef DATA_LITTLEENDIAN
			ch = ( ( ch & 0xFF ) << 8 ) | ( ch >> 8 );
#endif /* DATA_LITTLEENDIAN */
			*bmpDestPtr++ = ch;
			}

		return( BER_STRING_BMP );
		}

	/* If it's something masquerading as Unicode, convert it to the narrower
	   format.  Note that STRINGTYPE_UNICODE_VISIBLE is already covered by 
	   STRINGTYPE_UNICODE_IA5, so we don't need to check for this seperately */
	if( stringType == STRINGTYPE_UNICODE_PRINTABLE || \
		stringType == STRINGTYPE_UNICODE_IA5 || \
		stringType == STRINGTYPE_UNICODE_T61 )
		{
		*destLen = sourceLen / WCSIZE;
		if( sourceLen / WCSIZE > maxLen )
			return( CRYPT_ERROR_OVERFLOW );
		if( dest != NULL )
			{
			const wchar_t *srcPtr = ( wchar_t * ) source;
			BYTE *destPtr = dest;
			int i;

			for( i = 0; i < sourceLen; i += WCSIZE )
				*destPtr++ = ( BYTE ) *srcPtr++;
			}
		return( ( stringType == STRINGTYPE_UNICODE_PRINTABLE ) ? \
					BER_STRING_PRINTABLE : \
				( stringType == STRINGTYPE_UNICODE_IA5 ) ? \
					BER_STRING_IA5 : BER_STRING_T61 );
		}

	/* It's an 8-bit character set, just copy it across */
	*destLen = sourceLen;
	if( sourceLen > maxLen )
		return( CRYPT_ERROR_OVERFLOW );
	if( dest != NULL )
		memcpy( dest, source, sourceLen );
	return( ( stringType == STRINGTYPE_PRINTABLE ) ? \
				BER_STRING_PRINTABLE : \
			( stringType == STRINGTYPE_IA5 ) ? \
				BER_STRING_IA5 : BER_STRING_T61 );
	}
