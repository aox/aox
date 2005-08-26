/****************************************************************************
*																			*
*							cryptlib Base64 Routines						*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../io/stream.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Base64 encode/decode tables from RFC 1113.  We convert from ASCII <-> 
   EBCDIC on entry and exit, so there's no need for special-case EBCDIC
   handling elsewhere */

#define BPAD		'='		/* Padding for odd-sized output */
#define BERR		0xFF	/* Illegal char marker */
#define BEOF		0x7F	/* EOF marker (padding char or EOL) */

static const FAR_BSS char binToAscii[] = \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const FAR_BSS BYTE asciiToBin[ 256 ] =
	{ BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 00 */
	  BERR, BERR, BEOF, BERR, BERR, BEOF, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 10 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 20 */
	  BERR, BERR, BERR, 0x3E, BERR, BERR, BERR, 0x3F,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,	/* 30 */
	  0x3C, 0x3D, BERR, BERR, BERR, BEOF, BERR, BERR,
	  BERR, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,	/* 40 */
	  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,	/* 50 */
	  0x17, 0x18, 0x19, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,	/* 60 */
	  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	  0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,	/* 70 */
	  0x31, 0x32, 0x33, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 80 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 90 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* A0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* B0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* C0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* D0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* E0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* F0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR
	};

#if 0

/* EBCDIC character mappings:
		A-I C1-C9
		J-R D1-D9
		S-Z E2-E9
		a-i 81-89
		j-r 91-99
		s-z A2-A9
		0-9 F0-F9
		+   4E
		/   61
		=   7E  Uses BEOF in table */

static const FAR_BSS BYTE asciiToBin[ 256 ] =
	{ BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 00 */
	  BERR, BERR, BEOF, BERR, BERR, BEOF, BERR, BERR,		/*	CR, LF */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 10 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 20 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 30 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 40 */
	  BERR, BERR, BERR, BERR, BERR, BERR, 0x3E, BERR,		/*	+ */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 50 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x3F, BERR, BERR, BERR, BERR, BERR, BERR,	/* 60	/ */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* 70 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BEOF, BERR,		/*	= */
	  BERR, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,	/* 80	a-i */
	  0x21, 0x22, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,	/* 90	j-r */
	  0x2A, 0x2B, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31,	/* A0	s-z */
	  0x32, 0x33, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/* B0 */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,	/* C0	A-I */
	  0x07, 0x08, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* D0	J-R */
	  0x10, 0x11, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,	/* E0	S-Z */
	  0x18, 0x19, BERR, BERR, BERR, BERR, BERR, BERR,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,	/* F0	0-9 */
	  0x3C, 0x3D, BERR, BERR, BERR, BERR, BERR, BERR
	};
#endif /* 0 */

/* The size of lines for PEM-type formatting.  This is only used for encoding,
   for decoding we adjust to whatever size the sender has used */

#define TEXT_LINESIZE	64
#define BINARY_LINESIZE	48

/* Basic single-char en/decode functions.  We cast the value to an unsigned
   char to avoid generating negative array offsets if the sign bit is set,
   since the strings are passed as char *'s */

#define encode(data)	binToAscii[ ( BYTE ) data ]
#define decode(data)	asciiToBin[ ( BYTE ) data ]

/* The headers and trailers used for base64-encoded certificate objects */

static const FAR_BSS struct {
	const CRYPT_CERTTYPE_TYPE type;
	const char *header, *trailer;
	} headerInfo[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE,
	  "-----BEGIN CERTIFICATE-----" EOL,
	  "-----END CERTIFICATE-----" EOL },
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT,
	  "-----BEGIN ATTRIBUTE CERTIFICATE-----" EOL,
	  "-----END ATTRIBUTE CERTIFICATE-----" EOL },
	{ CRYPT_CERTTYPE_CERTCHAIN,
	  "-----BEGIN CERTIFICATE CHAIN-----" EOL,
	  "-----END CERTIFICATE CHAIN-----" EOL },
	{ CRYPT_CERTTYPE_CERTREQUEST,
	  "-----BEGIN NEW CERTIFICATE REQUEST-----" EOL,
	  "-----END NEW CERTIFICATE REQUEST-----" EOL },
	{ CRYPT_CERTTYPE_REQUEST_CERT,
	  "-----BEGIN NEW CERTIFICATE REQUEST-----" EOL,
	  "-----END NEW CERTIFICATE REQUEST-----" EOL },
	{ CRYPT_CERTTYPE_CRL,
	  "-----BEGIN CERTIFICATE REVOCATION LIST-----"  EOL,
	  "-----END CERTIFICATE REVOCATION LIST-----" EOL },
	{ CRYPT_CERTTYPE_NONE,			/* Universal catch-all */
	  "-----BEGIN CERTIFICATE OBJECT-----"  EOL,
	  "-----END CERTIFICATE OBJECT-----" EOL }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read a line of text data ending in an EOL */

static int readLine( STREAM *stream, char *buffer, const int maxSize )
	{
	MIME_STATE state;
	int status;

	initMIMEstate( &state, maxSize );
	do
		{
		const int ch = sgetc( stream );

		status = ( cryptStatusError( ch ) ) ? ch : \
				 addMIMEchar( &state, buffer, ch );
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	return( endMIMEstate( &state ) );
	}

/* Check for raw base64 data.  There isn't a 100% reliable check for this,
   but if the first 60 chars (the minimum base64 line length) are all valid
   base64 chars and the first chars match the required values then it's
   reasonably certain that it's base64 data */

static BOOLEAN checkBase64( STREAM *stream )
	{
	char buffer[ 8 ], headerBuffer[ 4 ];
	BOOLEAN gotHeader = FALSE;
	int i, status;

	/* Make sure that there's enough data present to perform a reliable 
	   check */
	if( sMemDataLeft( stream ) < 15 * 4 )
		return( FALSE );

	/* Check that we have at least 15 lots (60 chars) of base64-encoded
	   data */
	for( i = 0; i < 15; i++ )
		{
		BYTE c0, c1, c2, c3, cx;

		status = sread( stream, buffer, 4 );
		if( cryptStatusError( status ) )
			return( FALSE );
		if( !gotHeader )
			{
			memcpy( headerBuffer, buffer, 2 );
			gotHeader = TRUE;
			}
		c0 = decode( buffer[ 0 ] );
		c1 = decode( buffer[ 1 ] );
		c2 = decode( buffer[ 2 ] );
		c3 = decode( buffer[ 3 ] );
		cx = c0 | c1 | c2 | c3;

		if( cx == BEOF || cx == BERR )
			return( FALSE );
		}

	/* Make sure that the content is some form of encoded cert.  For cert
	   data that begins with 30 8x, the corresponding base64 values are
	   MI...; for an SSH public key that begins 00 00 it's AA...; for a PGP
	   public key that begins 99 0x it's mQ... */
	if( strCompare( headerBuffer, "MI", 2 ) && \
		strCompare( headerBuffer, "AA", 2 ) && \
		strCompare( headerBuffer, "mQ", 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Check for PEM-encapsulated data.  All we need to look for is the 
   '-----..' header, which is fairly simple although we also need to handle 
   the SSH '---- ...' variant (4 dashes and a space) */

static int checkPEMHeader( STREAM *stream, int *startPos )
	{
	BOOLEAN isSSH = FALSE, isPGP = FALSE;
	char buffer[ 1024 ], *bufPtr = buffer;
	int i, position, length;

	/* Check for the initial 5 dashes and 'BEGIN ' (unless we're SSH, in
	   which case we use 4 dashes, a space, and 'BEGIN ') */
	length = readLine( stream, buffer, 1024 );
	if( cryptStatusError( length ) )
		return( length );
	if( strCompare( bufPtr, "-----BEGIN ", 11 ) && \
		strCompare( bufPtr, "---- BEGIN ", 11 ) )
		return( CRYPT_CERTFORMAT_NONE );
	bufPtr += 11;
	length -= 11;

	/* Skip the object name */
	if( !strCompare( bufPtr, "SSH2 ", 5 ) )
		isSSH = TRUE;
	else
		if( !strCompare( bufPtr, "PGP ", 4 ) )
			isPGP = TRUE;
	while( length-- > 4 )
		if( *bufPtr++ == '-' )
			break;
	if( length != 4 && length != 3 )
		return( CRYPT_CERTFORMAT_NONE );

	/* Check the the trailing 5 (4 for SSH) dashes */
	if( strCompare( bufPtr, "----", length ) )
		return( CRYPT_CERTFORMAT_NONE );

	/* At this point SSH and PGP can continue with an arbitrary number of
	   type:value pairs that we have to strip before we get to the payload */
	if( isSSH )
		{
		/* SSH runs the header straight into the body so the only way to
		   tell whether we've hit the body is to check for the absence of
		   the ':' separator */
		do
			{
			position = stell( stream );
			length = readLine( stream, buffer, 1024 );
			if( cryptStatusError( length ) )
				return( CRYPT_CERTFORMAT_NONE );
			for( i = 0; i < length && buffer[ i ] != ':'; i++ );
			}
		while( i < length );
		sseek( stream, position );
		}
	if( isPGP )
		{
		/* PGP uses a conventional header format with a blank line as the
		   delimiter so all we have to do is look for a zero-length line */
		do
			{
			length = readLine( stream, buffer, 1024 );
			if( cryptStatusError( length ) )
				return( CRYPT_CERTFORMAT_NONE );
			}
		while( length > 0 );
		}

	/* Return the start position of the payload */
	*startPos = stell( stream );
	return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
	}

/****************************************************************************
*																			*
*							Base64 En/Decoding Functions					*
*																			*
****************************************************************************/

/* Check whether a data item has a header that identifies it as some form of
   encoded object and return the start position of the encoded data.  For
   S/MIME certificate data this can in theory get quite complex because
   there are many possible variations in the headers.  Some early S/MIME
   agents used a content type of "application/x-pkcs7-mime",
   "application/x-pkcs7-signature", and "application/x-pkcs10", while newer
   ones use the same without the "x-" at the start.  In addition Netscape
   have their own MIME data types for certificates, "application/x-x509-"
   "{user-cert|ca-cert|email-cert}, and there are further types in the
   endless stream of RFCs that PKIX churns out.  There are a whole pile of
   other possible headers as well, none of them terribly relevant for our
   purposes, so all we check for is the base64 indicator */
   
CRYPT_CERTFORMAT_TYPE base64checkHeader( const char *data,
										 const int dataLength, int *startPos )
	{
	STREAM stream;
	BOOLEAN seenTransferEncoding = FALSE, isBinaryEncoding = FALSE;
	int position, ch, status;

	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( startPos, sizeof( int ) ) );

	/* Clear return value */
	*startPos = 0;

	/* If the item is too small to contain any useful data, we don't even try
	   and examine it */
	if( dataLength < 64 )
		return( CRYPT_CERTFORMAT_NONE );

	sMemConnect( &stream, data, dataLength );

	/* Sometimes the object can be preceded by a few blank lines.  We're
	   fairly lenient with this.  Note that we can't use readLine() at this
	   point because we don't know yet whether we're getting binary or ASCII
	   data */
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' );
	position = stell( &stream ) - 1;

	/* Perform a quick check to weed out non-encoded cert data, which is
	   usually the case */
	if( ( ch == 0x30 ) && ( !isAlpha( sgetc( &stream ) ) || \
							!isAlpha( sgetc( &stream ) ) || \
							!isAlpha( sgetc( &stream ) ) ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_CERTFORMAT_NONE );
		}
	sseek( &stream, position );

	/* If it starts with a dash, check for PEM header encapsulation */
	if( ch == '-' )
		{
		status = checkPEMHeader( &stream, startPos );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		if( checkBase64( &stream ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
			}
		}

	/* Check for raw base64 data */
	if( checkBase64( &stream ) )
		{
		sMemDisconnect( &stream );
		*startPos = position;
		return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
		}
	sseek( &stream, position );

	/* It doesn't look like raw base64, check for an S/MIME header */
	do
		{
		char buffer[ 1024 ];

		status = readLine( &stream, buffer, 1024 );
		if( !cryptStatusError( status ) && status >= 33 && \
			!strCompare( buffer, "Content-Transfer-Encoding:", 26 ) )
			{
			int index;

			/* Check for a valid content encoding type */
			for( index = 26; index < status && buffer[ index ] == ' '; 
				 index++ );
			if( status - index < 6 )
				/* It's too short to be a valid encoding type, skip it */
				continue;	
			if( !strCompare( buffer + index, "base64", 6 ) )
				seenTransferEncoding = TRUE;
			else
				if( !strCompare( buffer + index, "binary", 6 ) )
					seenTransferEncoding = isBinaryEncoding = TRUE;
			}
		}
	while( status > 0 );
	if( cryptStatusError( status ) || !seenTransferEncoding )
		{
		sMemDisconnect( &stream );
		return( CRYPT_CERTFORMAT_NONE );
		}

	/* Skip trailing blank lines */
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' );
	position = stell( &stream ) - 1;
	sseek( &stream, position );

	/* Make sure that the content is some form of encoded cert */
	*startPos = position;
	status = isBinaryEncoding ? CRYPT_CERTFORMAT_CERTIFICATE : \
			 checkBase64( &stream ) ? CRYPT_ICERTFORMAT_SMIME_CERTIFICATE : \
									  CRYPT_CERTFORMAT_NONE;
	sMemDisconnect( &stream );
	return( status );
	}

/* Encode a block of binary data into the base64 format, returning the total
   number of output bytes */

int base64encode( char *dest, const int destMaxLen, const void *src, 
				  const int srcLen, const CRYPT_CERTTYPE_TYPE certType )
	{
	BYTE *srcPtr = ( BYTE * ) src;
	int srcIndex = 0, destIndex = 0, lineCount = 0, remainder = srcLen % 3;
	int headerInfoIndex;

	assert( destMaxLen > 10 && isWritePtr( dest, destMaxLen ) );
	assert( srcLen > 10 && isReadPtr( src, srcLen ) );

	/* If it's a certificate object, add the header */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		for( headerInfoIndex = 0;
			 headerInfo[ headerInfoIndex ].type != certType && \
				headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE;
			 headerInfoIndex++ );
		assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );
		destIndex = strlen( headerInfo[ headerInfoIndex ].header );
		if( destIndex > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( dest, headerInfo[ headerInfoIndex ].header, destIndex );
		}

	/* Encode the data */
	while( srcIndex < srcLen )
		{
		/* If we've reached the end of a line of binary data and it's a
		   certificate, add the EOL marker */
		if( certType != CRYPT_CERTTYPE_NONE && lineCount >= BINARY_LINESIZE )
			{
			strcpy( dest + destIndex, EOL );
			destIndex += EOL_LEN;
			lineCount = 0;
			}
		lineCount += 3;

		/* Encode a block of data from the input buffer */
		dest[ destIndex++ ] = encode( srcPtr[ srcIndex ] >> 2 );
		dest[ destIndex++ ] = encode( ( ( srcPtr[ srcIndex ] << 4 ) & 0x30 ) |
									  ( ( srcPtr[ srcIndex + 1 ] >> 4 ) & 0x0F ) );
		srcIndex++;
		dest[ destIndex++ ] = encode( ( ( srcPtr[ srcIndex ] << 2 ) & 0x3C ) |
									  ( ( srcPtr[ srcIndex + 1 ] >> 6 ) & 0x03 ) );
		srcIndex++;
		dest[ destIndex++ ] = encode( srcPtr[ srcIndex++ ] & 0x3F );
		if( destIndex > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* Go back and add padding and correctly encode the last char if we've
	   encoded too many characters */
	if( remainder == 2 )
		{
		/* There were only 2 bytes in the last group */
		dest[ destIndex - 1 ] = BPAD;
		dest[ destIndex - 2 ] = \
					encode( ( srcPtr[ srcIndex - 2 ] << 2 ) & 0x3C );
		}
	else
		if( remainder == 1 )
			{
			/* There was only 1 byte in the last group */
			dest[ destIndex - 2 ] = dest[ destIndex - 1 ] = BPAD;
			dest[ destIndex - 3 ] = \
					encode( ( srcPtr[ srcIndex - 3 ] << 4 ) & 0x30 );
			}

	/* If it's a certificate object, add the trailer */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		const int length = strlen( headerInfo[ headerInfoIndex ].trailer );

		if( destIndex + EOL_LEN + length > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( dest + destIndex, EOL, EOL_LEN );
		memcpy( dest + destIndex + EOL_LEN,
				headerInfo[ headerInfoIndex ].trailer, length );
		destIndex += EOL_LEN + length;
		}
	else
		/* It's not a certificate, truncate the unnecessary padding */
		destIndex -= ( 3 - remainder ) % 3;

	/* Return a count of encoded bytes */
#ifdef EBCDIC_CHARS
	asciiToEbcdic( dest, dest, length );
#endif /* EBCDIC_CHARS */
	return( destIndex );
	}

/* Decode a block of binary data from the base64 format, returning the total
   number of decoded bytes */

static int fixedBase64decode( void *dest, const int destMaxLen, 
							  const char *src, const int srcLen )
	{
	int srcIndex = 0, destIndex = 0;
	BYTE *destPtr = dest;

	/* Decode the base64 string as a fixed-length continuous string without
	   padding or newlines */
	while( srcIndex < srcLen )
		{
		BYTE c0, c1, c2 = 0, c3 = 0;
		const int delta = srcLen - srcIndex;

		/* Decode a block of data from the input buffer */
		c0 = decode( src[ srcIndex++ ] );
		c1 = decode( src[ srcIndex++ ] );
		if( delta > 2 )
			{
			c2 = decode( src[ srcIndex++ ] );
			if( delta > 3 )
				c3 = decode( src[ srcIndex++ ] );
			}
		if( ( c0 | c1 | c2 | c3 ) == BERR )
			return( CRYPT_ERROR_BADDATA );

		/* Copy the decoded data to the output buffer */
		destPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( delta > 2 )
			{
			destPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
			if( delta > 3 )
				destPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
			}
		if( destIndex > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

int base64decode( void *dest, const int destMaxLen, const char *src, 
				  const int srcLen, const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0, destIndex = 0, lineCount = 0, lineSize = 0;
	BYTE c0, c1, c2, c3, *destPtr = dest;

	assert( destMaxLen > 10 && isWritePtr( dest, destMaxLen ) );
	assert( srcLen > 10 && isReadPtr( src, srcLen ) );

	/* If it's not a certificate, it's a straight base64 string and we can
	   use the simplified decoding routines */
	if( format == CRYPT_CERTFORMAT_NONE )
		return( fixedBase64decode( dest, destMaxLen, src, srcLen ) );

	/* Decode the encoded object */
	while( srcIndex < srcLen )
		{
		BYTE cx;

		/* Depending on implementations, the length of the base64-encoded
		   line can vary from 60 to 72 chars, we adjust for this by checking
		   for an EOL and setting the line length to this size */
		if( !lineSize && \
			( src[ srcIndex ] == '\r' || src[ srcIndex ] == '\n' ) )
			lineSize = lineCount;

		/* If we've reached the end of a line of text, look for the EOL
		   marker.  There's one problematic special case here where, if the
		   encoding has produced bricktext, the end of the data will 
		   coincide with the EOL.  For CRYPT_CERTFORMAT_TEXT_CERTIFICATE 
		   this will give us '-----END...' on the next line which is easy to 
		   check for, but for CRYPT_ICERTFORMAT_SMIME_CERTIFICATE what we 
		   end up with depends on the calling code, it could truncate 
		   immediately at the end of the data (which it isn't supposed to) 
		   so we get '\0', it could truncate after the EOL (so we get EOL + 
		   '\0'), it could continue with a futher content type after a blank 
		   line (so we get EOL + EOL), or it could truncate without the '\0' 
		   so we get garbage, which is the caller's problem.  Because of 
		   this we look for all of these situations and, if any are found, 
		   set c0 to BEOF and advance srcIndex by 4 to take into account the 
		   adjustment for overshoot that occurs when we break out of the 
		   loop */
		if( lineCount >= lineSize )
			{
			/* Check for '\0' at the end of the data */
			if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
				!src[ srcIndex ] )
				{
				c0 = c1 = c2 = BEOF;
				srcIndex += 4;
				break;
				}

			/* Check for EOL */
			if( src[ srcIndex ] == '\n' )
				srcIndex++;
			else
				if( src[ srcIndex ] == '\r' )
					{
					srcIndex++;

					/* Some broken implementations emit two CRs before the
					   LF.  Stripping these extra CRs clashes with other
					   broken implementations that emit only CRs, which means
					   that we'll be stripping the EOT blank line in MIME
					   encapsulation, however it looks like the two-CR bug
					   (usually from Netscape) appears to be more prevalent
					   than the CR-only bug (old Mac software) */
					if( src[ srcIndex ] == '\r' )
						srcIndex++;

					if( src[ srcIndex ] == '\n' )
						srcIndex++;
					}
			lineCount = 0;

			/* Check for '\0' or EOL (S/MIME) or '----END...' (PEM) after 
			   EOL */
			if( ( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
				  ( !src[ srcIndex ] || src[ srcIndex ] == '\n' || \
					 src[ srcIndex ] == '\r' ) ) || \
				( format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE && \
				  !strCompare( src + srcIndex, "-----END ", 9 ) ) )
				{
				c0 = c1 = c2 = BEOF;
				srcIndex += 4;
				break;
				}

			/* Make sure that we haven't run off into the weeds */
			if( srcIndex >= srcLen )
				break;
			}

		/* Decode a block of data from the input buffer */
		c0 = decode( src[ srcIndex++ ] );
		c1 = decode( src[ srcIndex++ ] );
		c2 = decode( src[ srcIndex++ ] );
		c3 = decode( src[ srcIndex++ ] );
		cx = c0 | c1 | c2 | c3;
		if( c0 == BEOF || cx == BEOF )
			/* We need to check c0 separately since hitting an EOF at c0 may
			   cause later chars to be decoded as BERR */
			break;
		else
			if( cx == BERR )
				return( CRYPT_ERROR_BADDATA );
		lineCount += 4;

		/* Copy the decoded data to the output buffer */
		destPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		destPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2 );
		destPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
		if( destIndex > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* Handle the truncation of data at the end.  Due to the 3 -> 4 encoding,
	   we have the following mapping: 0 chars -> nothing, 1 char -> 2 + 2 pad,
	   2 chars = 3 + 1 pad */
	if( c0 == BEOF )
		/* No padding, move back 4 chars */
		srcIndex -= 4;
	else
		{
		/* 2 chars padding, decode 1 from 2 */
		destPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( c2 != BEOF )
			/* 1 char padding, decode 2 from 3 */
			destPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

/* Calculate the size of a quantity of data once it's en/decoded */

int base64decodeLen( const char *data, const int dataLength )
	{
	STREAM stream;
	int ch, length;

	assert( isReadPtr( data, dataLength ) );

	/* Skip ahead until we find the end of the decodable data */
	sMemConnect( &stream, data, dataLength );
	do
		{
		ch = sgetc( &stream );
		if( cryptStatusError( ch ) || ch == BPAD )
			break;
		ch = decode( ch );
		}
	while( ch != BERR );
	length = stell( &stream );
	sMemDisconnect( &stream );

	/* Return a rough estimate of how much room the decoded data will occupy.
	   This ignores the EOL size so it always overestimates, but a strict
	   value isn't necessary since it's only used for memory buffer
	   allocation */
	return( ( length * 3 ) / 4 );
	}

int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType )
	{
	int length = roundUp( ( dataLength * 4 ) / 3, 4 ), headerInfoIndex;

	for( headerInfoIndex = 0;
		 headerInfo[ headerInfoIndex ].type != certType && \
			headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE;
		 headerInfoIndex++ );
	assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );

	/* Calculate extra length due to EOL's */
	length += ( ( roundUp( length, TEXT_LINESIZE ) / TEXT_LINESIZE ) * EOL_LEN );

	/* Return the total length due to delimiters */
	return( strlen( headerInfo[ headerInfoIndex ].header ) + length + \
			strlen( headerInfo[ headerInfoIndex ].trailer ) );
	}

/****************************************************************************
*																			*
*						PKI User ID En/Decoding Functions					*
*																			*
****************************************************************************/

/* En/decode text representations of binary keys */

static const char codeTable[] = \
						"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";	/* No O/0, I/1 */
static const int hiMask[] = { 0x00, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x03, 0x01 };
static const int loMask[] = { 0x00, 0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0xF0 };

BOOLEAN isPKIUserValue( const char *encVal, const int encValLength )
	{
	int i = 0;

	assert( isReadPtr( encVal, encValLength ) );

	/* Check whether a user value is of the form XXXXX-XXXXX-XXXXX{-XXXXX} */
	if( ( encValLength != ( 3 * 5 ) + 2 ) && \
		( encValLength != ( 4 * 5 ) + 3 ) )
		return( FALSE );
	while( i < encValLength )
		{
		int j;

		for( j = 0; j < 5; j++ )
			{
			const int ch = encVal[ i++ ];

			if( !isAlnum( ch ) )
				return( FALSE );
			}
		if( i < encValLength && encVal[ i++ ] != '-' )
			return( FALSE );
		}
	return( TRUE );
	}

int adjustPKIUserValue( BYTE *value, const int noCodeGroups )
	{
	const int noBits = noCodeGroups * 25;
	const int length = ( roundUp( noBits, 8 ) / 8 ) - 1;

	assert( isWritePtr( value, roundUp( noCodeGroups * 25, 8 ) / 8 ) );

	/* Mask off any bits at the end of the data that can't be encoded using
	   the given number of code groups */
	value[ length - 1 ] &= 0xFF << ( 8 - ( noBits % 8 ) );
	return( length );
	}

int encodePKIUserValue( char *encVal, const BYTE *value,
						const int noCodeGroups )
	{
	BYTE valBuf[ 128 ];
	const int dataBytes = ( roundUp( noCodeGroups * 25, 8 ) / 8 );
	int i, byteCount = 0, bitCount = 0, length;

	assert( isReadPtr( value, dataBytes ) );

	/* Copy across the data bytes, leaving a gap at the start for the
	   checksum */
	memcpy( valBuf + 1, value, dataBytes );
	length = adjustPKIUserValue( valBuf + 1, noCodeGroups ) + 1;

	/* Calculate the Fletcher checksum and prepend it to the data bytes
	   This is easier than handling the addition of a non-byte-aligned
	   quantity to the end of the data */
	valBuf[ 0 ] = checksumData( valBuf + 1, length - 1 ) & 0xFF;

	/* Encode the binary data as text */
	for( length = 0, i = 1; i <= noCodeGroups * 5; i++ )
		{
		int chunkValue;

		/* Extract the next 5-bit chunk and convert it to text form */
		if( bitCount < 3 )
			/* Everything's present in one byte, shift it down to the LSB */
			chunkValue = ( valBuf[ byteCount ] >> ( 3 - bitCount ) ) & 0x1F;
		else
			if( bitCount == 3 )
				/* It's the 5 LSB's */
				chunkValue = valBuf[ byteCount ] & 0x1F;
			else
				/* The data spans two bytes, shift the bits from the high
				   byte up and the bits from the low byte down */
				chunkValue = ( ( valBuf[ byteCount ] & \
								hiMask[ bitCount ] ) << ( bitCount - 3 ) ) | \
							( ( valBuf[ byteCount + 1 ] & \
								loMask[ bitCount ] ) >> ( 11 - bitCount ) );
		encVal[ length++ ] = codeTable[ chunkValue ];
		if( !( i % 5 ) && i < noCodeGroups * 5 )
			encVal[ length++ ] = '-';

		/* Advance by 5 bits */
		bitCount += 5;
		if( bitCount >= 8 )
			{
			bitCount -= 8;
			byteCount++;
			}
		}

	return( length );
	}

int decodePKIUserValue( BYTE *value, const char *encVal,
						const int encValLength )
	{
	BYTE valBuf[ 128 ];
	char encBuf[ 128 ], *encBufPtr = encBuf;
	int i = 0, byteCount = 0, bitCount = 0, length = 0;

	assert( isReadPtr( encVal, encValLength ) );

	/* Undo the formatting of the encoded value */
	while( i < encValLength )
		{
		int j;

		for( j = 0; j < 5; j++ )
			{
			const int ch = encVal[ i++ ];

			if( !isAlnum( ch ) || length >= encValLength )
				return( CRYPT_ERROR_BADDATA );
			encBuf[ length++ ] = toUpper( ch );
			}
		if( i < encValLength && encVal[ i++ ] != '-' )
			return( CRYPT_ERROR_BADDATA );
		}
	if( length % 5 )
		return( CRYPT_ERROR_BADDATA );

	/* Decode the text data into binary */
	memset( valBuf, 0, 128 );
	for( i = 0; i < length; i ++ )
		{
		const int ch = *encBufPtr++;
		int chunkValue;

		for( chunkValue = 0; chunkValue < 0x20; chunkValue++ )
			if( codeTable[ chunkValue ] == ch )
				break;
		if( chunkValue == 0x20 )
			return( CRYPT_ERROR_BADDATA );

		/* Extract the next 5-bit chunk and convert it to text form */
		if( bitCount < 3 )
			/* Everything's present in one byte, shift it up into position */
			valBuf[ byteCount ] |= chunkValue << ( 3 - bitCount );
		else
			if( bitCount == 3 )
				/* It's the 5 LSB's */
				valBuf[ byteCount ] |= chunkValue;
			else
				{
				/* The data spans two bytes, shift the bits from the high
				   byte down and the bits from the low byte up */
				valBuf[ byteCount ] |= \
							( chunkValue >> ( bitCount - 3 ) ) & hiMask[ bitCount ];
				valBuf[ byteCount + 1 ] = \
							( chunkValue << ( 11 - bitCount ) ) & loMask[ bitCount ];
				}

		/* Advance by 5 bits */
		bitCount += 5;
		if( bitCount >= 8 )
			{
			bitCount -= 8;
			byteCount++;
			}
		}

	/* Calculate the Fletcher checksum and make sure that it matches the
	   value at the start of the data bytes */
	if( bitCount )
		byteCount++;	/* More bits in the last partial byte */
	if( valBuf[ 0 ] != ( checksumData( valBuf + 1, byteCount - 1 ) & 0xFF ) )
		return( CRYPT_ERROR_BADDATA );

	/* Return the decoded value to the caller */
	if( value != NULL )
		memcpy( value, valBuf + 1, byteCount - 1 );
	return( byteCount - 1 );
	}
