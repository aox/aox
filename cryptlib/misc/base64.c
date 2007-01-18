/****************************************************************************
*																			*
*							cryptlib Base64 Routines						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
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

static const char FAR_BSS binToAscii[] = \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#ifndef EBCDIC_CHARS

static const BYTE FAR_BSS asciiToBin[ 256 ] =
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

#else

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

static const BYTE FAR_BSS asciiToBin[ 256 ] =
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
#endif /* EBCDIC_CHARS */

/* The size of lines for PEM-type formatting.  This is only used for encoding,
   for decoding we adjust to whatever size the sender has used */

#define TEXT_LINESIZE	64
#define BINARY_LINESIZE	48

/* Basic single-char en/decode functions.  We mask the value to 8 bits to
   avoid generating negative array offsets if the sign bit is set, since the
   strings are passed as char *'s */

#define encode(data)	binToAscii[ ( data ) & 0xFF ]
#define decode(data)	asciiToBin[ ( data ) & 0xFF ]

/* The headers and trailers used for base64-encoded certificate objects */

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	const char FAR_BSS *header, FAR_BSS *trailer;
	} HEADER_INFO;
static const HEADER_INFO FAR_BSS headerInfo[] = {
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
	  "-----END CERTIFICATE OBJECT-----" EOL },
	{ CRYPT_CERTTYPE_NONE,			/* Universal catch-all */
	  "-----BEGIN CERTIFICATE OBJECT-----"  EOL,
	  "-----END CERTIFICATE OBJECT-----" EOL }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used by readTextLine() to read characters from a
   stream */

static int readCharFunction( void *streamPtr )
	{
	return( sgetc( streamPtr ) );
	}

/* Check for raw base64 data.  There isn't a 100% reliable check for this,
   but if the first 60 chars (the minimum base64 line length) are all valid
   base64 chars and the first chars match the required values then it's
   reasonably certain that it's base64 data */

static BOOLEAN checkBase64( STREAM *stream )
	{
	BYTE buffer[ 4 + 8 ], headerBuffer[ 2 + 8 ];
	BOOLEAN gotHeader = FALSE;
	int i, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

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

	/* Make sure that the content is some form of encoded key or cert data.
	   For cert data that begins with 30 8x, the corresponding base64 values
	   are MI...; for an SSH public key that begins 00 00 it's AA...; for a
	   PGP public key that begins 99 0x it's mQ... */
	if( strCompare( headerBuffer, "MI", 2 ) && \
		strCompare( headerBuffer, "AA", 2 ) && \
		strCompare( headerBuffer, "mQ", 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Check for PEM-encapsulated data.  All that we need to look for is the
   '-----..' header, which is fairly simple although we also need to handle
   the SSH '---- ...' variant (4 dashes and a space) */

static int checkPEMHeader( STREAM *stream )
	{
	BOOLEAN isSSH = FALSE, isPGP = FALSE;
	char buffer[ 1024 + 8 ], *bufPtr = buffer;
	int length, iterationCount = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Check for the initial 5 dashes and 'BEGIN ' (unless we're SSH, in
	   which case we use 4 dashes, a space, and 'BEGIN ') */
	length = readTextLine( readCharFunction, stream, buffer, 1024, NULL );
	if( cryptStatusError( length ) )
		return( length );
	if( length < 11 + 5 || \
		strCompare( bufPtr, "-----BEGIN ", 11 ) && \
		strCompare( bufPtr, "---- BEGIN ", 11 ) )
		return( CRYPT_ERROR_BADDATA );
	bufPtr += 11;
	length -= 11;

	/* Skip the object name */
	if( !strCompare( bufPtr, "SSH2 ", 5 ) )
		isSSH = TRUE;
	else
		if( !strCompare( bufPtr, "PGP ", 4 ) )
			isPGP = TRUE;
	while( length >= 4 )
		{
		if( *bufPtr == '-' )
			break;
		bufPtr++;
		length--;
		}
	if( length != 5 && length != 4 )
		return( CRYPT_ERROR_BADDATA );

	/* Check the the trailing 5 (4 for SSH) dashes */
	if( strCompare( bufPtr, "-----", length ) )
		return( CRYPT_ERROR_BADDATA );

	/* At this point SSH and PGP can continue with an arbitrary number of
	   type : value pairs that we have to strip before we get to the
	   payload */
	if( isSSH )
		{
		int position, i;

		/* SSH runs the header straight into the body so the only way to
		   tell whether we've hit the body is to check for the absence of
		   the ':' separator */
		do
			{
			position = stell( stream );
			length = readTextLine( readCharFunction, stream, buffer,
								   1024, NULL );
			if( cryptStatusError( length ) )
				return( length );
			for( i = 0; i < length && buffer[ i ] != ':'; i++ );
			}
		while( i < length && iterationCount++ < FAILSAFE_ITERATIONS_LARGE ); 
		if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();
		sseek( stream, position );
		}
	if( isPGP )
		{
		/* PGP uses a conventional header format with a blank line as the
		   delimiter so all that we have to do is look for a zero-length
		   line */
		do
			{
			length = readTextLine( readCharFunction, stream, buffer,
								   1024, NULL );
			if( cryptStatusError( length ) )
				return( length );
			}
		while( length > 0 && iterationCount++ < FAILSAFE_ITERATIONS_LARGE ); 
		if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();
		}

	return( stell( stream ) );
	}

/* Look for the EOL marker at the end of a line of text.  There's one
   problematic special case here where, if the encoding has produced
   bricktext, the end of the data will coincide with the EOL.  For
   CRYPT_CERTFORMAT_TEXT_CERTIFICATE this will give us '-----END...' on
   the next line which is easy to check for, but for
   CRYPT_ICERTFORMAT_SMIME_CERTIFICATE what we end up with depends on the
   calling code, it could truncate immediately at the end of the data
   (which it isn't supposed to) so we get '\0', it could truncate after the
   EOL (so we get EOL + '\0'), it could continue with a futher content type
   after a blank line (so we get EOL + EOL), or it could truncate without
   the '\0' so we get garbage, which is the caller's problem.  Because of
   this we look for all of these situations and, if any are found, return
   a 0-count EOL indicator */

static int checkEOL( const char *src, const int srcLen,
					 const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0;

	assert( isReadPtr( src, srcLen ) );

	/* Check for a '\0' at the end of the data */
	if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && !*src )
		return( 0 );

	/* Check for EOL */
	if( *src == '\n' )
		srcIndex++;
	else
		{
		if( *src == '\r' )
			{
			srcIndex++;

			/* Some broken implementations emit two CRs before the LF.
			   Stripping these extra CRs clashes with other broken
			   implementations that emit only CRs, which means that we'll
			   be stripping the EOT blank line in MIME encapsulation,
			   however the two-CR bug (usually from older versions of
			   Netscape) appears to be more prevalent than the CR-only
			   bug (old Mac software) */
			if( ( srcIndex < srcLen ) && src[ srcIndex ] == '\r' )
				srcIndex++;
			if( ( srcIndex < srcLen ) && src[ srcIndex ] == '\n' )
				srcIndex++;
			}
		}
	if( srcIndex >= srcLen )
		return( 0 );
	assert( srcIndex < srcLen );

	/* Check for '\0' or EOL (S/MIME) or '----END...' (PEM) after EOL */
	if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
		( !src[ srcIndex ] || src[ srcIndex ] == '\n' || \
		  src[ srcIndex ] == '\r' ) )
		return( 0 );
	if( format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE && \
		srcLen - srcIndex >= 9 && \
		!strCompare( src + srcIndex, "-----END ", 9 ) )
		return( 0 );

	/* Make sure that we haven't run off into the weeds */
	if( srcIndex >= srcLen )
		return( 0 );

	return( srcIndex );
	}

/* Decode a chunk of four base64 characters into three binary characters */

static int decodeBase64chunk( BYTE *dest, const int destLeft,
							  const char *src, const int srcLeft,
							  const BOOLEAN fixedLenData )
	{
	static const int outByteTbl[] = { 0, 0, 1, 2, 3 };
	BYTE c0, c1, c2 = 0, c3 = 0, cx;
	int srcIndex = 0, destIndex = 0, outByteCount;

	/* Make sure that there's sufficient input left to decode.  We need at
	   least two more characters to produce one byte of output */
	if( srcLeft < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Decode a block of data from the input buffer */
	c0 = decode( src[ srcIndex++ ] );
	c1 = decode( src[ srcIndex++ ] );
	if( srcLeft > 2 )
		{
		c2 = decode( src[ srcIndex++ ] );
		if( srcLeft > 3 )
			c3 = decode( src[ srcIndex++ ] );
		}
	cx = c0 | c1 | c2 | c3;
	if( cx == BERR || cx == BEOF )
		{
		/* If we're decoding fixed-length data and the decoding produces
		   an invalid character or an EOF, there's a problem with the
		   input */
		if( fixedLenData )
			return( CRYPT_ERROR_BADDATA );

		/* We're decoding indefinite-length data for which EOF's are valid
		   characters.  We have to be a bit careful with the order of
		   checking since hitting an EOF at an earlier character may cause
		   later chars to be decoded as BERR */
		if( c0 == BEOF )
			/* No more input, we're done */
			return( 0 );
		if( c0 == BERR || c1 == BEOF || c1 == BERR )
			/* We can't produce output with only one char of input, there's
			   a problem with the input */
			return( CRYPT_ERROR_BADDATA );
		if( c2 == BEOF )
			/* Two chars of input, then EOF, resulting in one char of
			   output */
			outByteCount = 1;
		else
			{
			if( c2 == BERR || c3 == BERR )
				return( CRYPT_ERROR_BADDATA );
			assert( c3 == BEOF );
			outByteCount = 2;
			}
		}
	else
		/* All decoded characters are valid */
		outByteCount = outByteTbl[ min( srcLeft, 4 ) ];

	/* Make sure that there's sufficient space to copy out the decoded
	   bytes */
	if( outByteCount > destLeft )
		return( CRYPT_ERROR_OVERFLOW );

	/* Copy the decoded data to the output buffer */
	dest[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
	if( outByteCount > 1 )
		{
		dest[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
		if( outByteCount > 2 )
			dest[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
		}

	return( outByteCount );
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

int base64checkHeader( const char *data, const int dataLength,
					   int *startPos )
	{
	STREAM stream;
	BOOLEAN seenTransferEncoding = FALSE, isBinaryEncoding = FALSE;
	int position, ch, iterationCount, status;

	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( startPos, sizeof( int ) ) );

	/* Clear return value */
	*startPos = 0;

	/* If the item is too small to contain any useful data, we don't even
	   try and examine it.  We don't treat this as a data or underflow error
	   since it may be a short but valid data object like an empty CRL */
	if( dataLength < 64 )
		return( CRYPT_CERTFORMAT_NONE );

	sMemConnect( &stream, data, dataLength );

	/* Sometimes the object can be preceded by a few blank lines.  We're
	   fairly lenient with this.  Note that we can't use readTextLine() at
	   this point because we don't know yet whether we're getting binary or
	   ASCII data */
	iterationCount = 0;
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE ); 
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	if( cryptStatusError( ch ) )
		{
		sMemDisconnect( &stream );
		return( ch );
		}
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
		position = checkPEMHeader( &stream );
		if( cryptStatusError( position ) )
			{
			sMemDisconnect( &stream );
			return( position );
			}
		if( checkBase64( &stream ) )
			{
			sMemDisconnect( &stream );
			*startPos = position;
			return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
			}
		sMemDisconnect( &stream );
		return( CRYPT_ERROR_BADDATA );
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
	iterationCount = 0;
	do
		{
		char buffer[ 1024 + 8 ];

		status = readTextLine( readCharFunction, &stream, buffer,
							   1024, NULL );
		if( !cryptStatusError( status ) && status >= 33 && \
			!strCompare( buffer, "Content-Transfer-Encoding:", 26 ) )
			{
			const int length = status;
			int index;

			/* Check for a valid content encoding type */
			for( index = 26; index < length && buffer[ index ] == ' ';
				 index++ );
			if( length - index < 6 )
				/* It's too short to be a valid encoding type, skip it */
				continue;
			if( !strCompare( buffer + index, "base64", 6 ) )
				seenTransferEncoding = TRUE;
			else
				if( !strCompare( buffer + index, "binary", 6 ) )
					seenTransferEncoding = isBinaryEncoding = TRUE;
			}
		}
	while( status > 0 && iterationCount++ < FAILSAFE_ITERATIONS_LARGE ); 
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	if( cryptStatusError( status ) || !seenTransferEncoding )
		{
		sMemDisconnect( &stream );
		return( cryptStatusError( status ) ? status : CRYPT_ERROR_BADDATA );
		}

	/* Skip trailing blank lines */
	iterationCount = 0;
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE ); 
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	if( cryptStatusError( ch ) )
		{
		sMemDisconnect( &stream );
		return( ch );
		}
	position = stell( &stream ) - 1;

	/* Make sure that the content is some form of encoded cert */
	*startPos = position;
	if( isBinaryEncoding )
		status = CRYPT_CERTFORMAT_CERTIFICATE;
	else
		{
		sseek( &stream, position );
		status = checkBase64( &stream ) ? CRYPT_ICERTFORMAT_SMIME_CERTIFICATE : \
										  CRYPT_ERROR_BADDATA;
		}
	sMemDisconnect( &stream );
	return( status );
	}

/* Encode a block of binary data into the base64 format, returning the total
   number of output bytes */

int base64encode( char *dest, const int destMaxLen, const void *src,
				  const int srcLen, const CRYPT_CERTTYPE_TYPE certType )
	{
	const BYTE *srcPtr = src;
	int srcIndex = 0, destIndex = 0, lineByteCount = 0;
	int remainder = srcLen % 3, headerInfoIndex;

	assert( destMaxLen > 10 && isWritePtr( dest, destMaxLen ) );
	assert( srcLen > 10 && isReadPtr( src, srcLen ) );

	/* If it's a certificate object, add the header */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		for( headerInfoIndex = 0;
			 headerInfo[ headerInfoIndex ].type != certType && \
				headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE && \
				headerInfoIndex < FAILSAFE_ARRAYSIZE( headerInfo, HEADER_INFO );
			 headerInfoIndex++ );
		if( headerInfoIndex >= FAILSAFE_ARRAYSIZE( headerInfo, HEADER_INFO ) )
			retIntError();
		assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );
		destIndex = strlen( headerInfo[ headerInfoIndex ].header );
		if( destIndex >= destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( dest, headerInfo[ headerInfoIndex ].header, destIndex );
		}

	/* Encode the data */
	while( srcIndex < srcLen )
		{
		const int srcLeft = srcLen - srcIndex;

		/* If we've reached the end of a line of binary data and it's a
		   certificate, add the EOL marker */
		if( certType != CRYPT_CERTTYPE_NONE && \
			lineByteCount >= BINARY_LINESIZE )
			{
			if( destIndex + EOL_LEN >= destMaxLen )
				return( CRYPT_ERROR_OVERFLOW );
			memcpy( dest + destIndex, EOL, EOL_LEN );
			destIndex += EOL_LEN;
			lineByteCount = 0;
			}

		/* Encode a block of data from the input buffer */
		if( destIndex + 4 >= destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		dest[ destIndex++ ] = encode( srcPtr[ srcIndex ] >> 2 );
		if( srcLeft < 2 )
			{
			assert( remainder == 1 );
			dest[ destIndex++ ] = encode( ( srcPtr[ srcIndex ] << 4 ) & 0x30 );
			break;
			}
		dest[ destIndex++ ] = encode( ( ( srcPtr[ srcIndex ] << 4 ) & 0x30 ) | \
									  ( ( srcPtr[ srcIndex + 1 ] >> 4 ) & 0x0F ) );
		srcIndex++;
		if( srcLeft < 3 )
			{
			assert( remainder == 2 );
			dest[ destIndex++ ] = encode( ( srcPtr[ srcIndex ] << 2 ) & 0x3C );
			break;
			}
		dest[ destIndex++ ] = encode( ( ( srcPtr[ srcIndex ] << 2 ) & 0x3C ) | \
									  ( ( srcPtr[ srcIndex + 1 ] >> 6 ) & 0x03 ) );
		srcIndex++;
		dest[ destIndex++ ] = encode( srcPtr[ srcIndex++ ] & 0x3F );
		lineByteCount += 3;
		}

	/* Add padding if it's not raw base64 data.  For 0 bytes remainder 
	   there's no padding (the data fits exactly), for 1 byte remainder
	   there's 2 bytes padding ("X=="), and for 2 bytes remainder there's 1 
	   byte padding ("XX=") */
	if( certType != CRYPT_CERTTYPE_NONE && remainder > 0 )
		{
		dest[ destIndex++ ] = BPAD;
		if( remainder == 1 )
			dest[ destIndex++ ] = BPAD;
		}

	/* If it's a certificate object, add the trailer */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		const int length = strlen( headerInfo[ headerInfoIndex ].trailer );

		if( destIndex + EOL_LEN + length >= destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( dest + destIndex, EOL, EOL_LEN );
		memcpy( dest + destIndex + EOL_LEN,
				headerInfo[ headerInfoIndex ].trailer, length );
		destIndex += EOL_LEN + length;
		}
#ifdef EBCDIC_CHARS
	asciiToEbcdic( dest, dest, length );
#endif /* EBCDIC_CHARS */

	/* Return a count of encoded bytes */
	return( destIndex );
	}

/* Decode a block of binary data from the base64 format, returning the total
   number of decoded bytes */

static int fixedBase64decode( BYTE *dest, const int destMaxLen,
							  const char *src, const int srcLen )
	{
	int srcIndex = 0, destIndex = 0;

	/* Decode the base64 string as a fixed-length continuous string without
	   padding or newlines */
	while( srcIndex < srcLen )
		{
		int status;

		status = decodeBase64chunk( dest + destIndex, destMaxLen - destIndex,
									src + srcIndex, srcLen - srcIndex,
									TRUE );
		if( cryptStatusError( status ) )
			return( status );
		srcIndex += 4;
		destIndex += status;
		}

	/* Return a count of decoded bytes */
	return( destIndex );
	}

int base64decode( void *dest, const int destMaxLen, const char *src,
				  const int srcLen, const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0, destIndex = 0, lineByteCount = 0, lineSize = 0;
	BYTE *destPtr = dest;

	assert( destMaxLen > 10 && isWritePtr( dest, destMaxLen ) );
	assert( srcLen > 10 && isReadPtr( src, srcLen ) );

	/* If it's not a certificate, it's a straight base64 string and we can
	   use the simplified decoding routines */
	if( format == CRYPT_CERTFORMAT_NONE )
		return( fixedBase64decode( dest, destMaxLen, src, srcLen ) );

	/* Decode the encoded object */
	while( srcIndex < srcLen )
		{
		int status;

		/* Depending on implementations, the length of the base64-encoded
		   line can vary from 60 to 72 chars.  We adjust for this by
		   checking for the first EOL and setting the line length to the
		   size of the first line of base64 text */
		if( lineSize <= 0 && \
			src[ srcIndex ] == '\r' || src[ srcIndex ] == '\n' )
			{
			if( lineByteCount < 56 )
				/* Suspiciously short text line */
				return( CRYPT_ERROR_BADDATA );
			lineSize = lineByteCount;
			}

		/* If we've reached the end of a line of text, look for the EOL
		   marker */
		if( lineSize > 0 && lineByteCount >= lineSize )
			{
			status = checkEOL( src + srcIndex, srcLen - srcIndex, format );
			if( status <= 0 )
				break;	/* End of input reached, exit */
			srcIndex += status;
			lineByteCount = 0;
			}

		/* Decode a chunk of data from the input buffer */
		status = decodeBase64chunk( destPtr + destIndex,
									destMaxLen - destIndex,
									src + srcIndex, srcLen - srcIndex,
									FALSE );
		if( cryptStatusError( status ) )
			return( status );
		destIndex += status;
		if( status < 3 )
			/* We've reached the end marker on the input data, exit.  Note
			   that we can't just wait for srcIndex to pass srcLen as for
			   the fixed-length decode because there could be extra trailer
			   data following the base64 data.

			   In theory we could call checkEOL() here to make sure that the
			   trailer is well-formed, but if the data is truncated right on
			   the bas64 end marker then this would produce an error, so we
			   just stop decoding as soon as we find the end marker */
			break;
		srcIndex += 4;
		lineByteCount += 4;
		}

	/* Return a count of decoded bytes */
	return( destIndex );
	}

/* Calculate the size of a quantity of data once it's en/decoded */

int base64decodeLen( const char *data, const int dataLength )
	{
	STREAM stream;
	int ch, length, iterationCount = 0;

	assert( isReadPtr( data, dataLength ) );

	/* Skip ahead until we find the end of the decodable data.  Note that
	   this ignores errors on the input stream since at this point all that
	   we're interested in is how much we can decode from it, not whether
	   it's valid or not */
	sMemConnect( &stream, data, dataLength );
	do
		{
		ch = sgetc( &stream );
		if( cryptStatusError( ch ) || ch == BPAD )
			break;
		ch = decode( ch );
		}
	while( ch != BERR && iterationCount++ < FAILSAFE_ITERATIONS_MAX );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();
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
			headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE && \
			headerInfoIndex < FAILSAFE_ARRAYSIZE( headerInfo, HEADER_INFO ); 
		 headerInfoIndex++ );
	if( headerInfoIndex >= FAILSAFE_ARRAYSIZE( headerInfo, HEADER_INFO ) )
		retIntError();
	assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );

	/* Calculate the extra length due to EOL's */
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
					"ABCDEFGHJKLMNPQRSTUVWXYZ23456789____";	/* No O/0, I/1 */
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

		/* Decode each character group.  We know from the length check above
		   that this won't run off the end of the data, so we don't have to
		   check the index value */
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

int encodePKIUserValue( char *encVal, const int encValMaxLen,
						const BYTE *value, const int noCodeGroups )
	{
	BYTE valBuf[ 128 + 8 ];
	const int dataBytes = ( roundUp( noCodeGroups * 25, 8 ) / 8 );
	int i, byteCount = 0, bitCount = 0, length;

	assert( isReadPtr( value, dataBytes ) );
	assert( dataBytes < 128 );

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
		if( length < encValMaxLen && !( i % 5 ) && i < noCodeGroups * 5 )
			encVal[ length++ ] = '-';
		if( length >= encValMaxLen )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_OVERFLOW );
			}

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

int decodePKIUserValue( BYTE *value, const int valueMaxLen,
						const char *encVal, const int encValLength )
	{
	BYTE valBuf[ 128 + 8 ];
	char encBuf[ CRYPT_MAX_TEXTSIZE + 8 ];
	int i = 0, byteCount = 0, bitCount = 0, length = 0;

	assert( isReadPtr( encVal, encValLength ) );

	/* Make sure that the input has a reasonable length (this should have 
	   been checked by the caller using isPKIUserValue(), so we throw an
	   exception if the check fails).  We return CRYPT_ERROR_BADDATA rather 
	   than the more obvious CRYPT_ERROR_OVERFLOW since something returned 
	   from this low a level should be a consistent error code indicating 
	   that there's a problem with the PKI user value as a whole */
	if( encValLength < ( 3 * 5 ) || encValLength > CRYPT_MAX_TEXTSIZE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Undo the formatting of the encoded value from XXXXX-XXXXX-XXXXX... 
	   to XXXXXXXXXXXXXXX... */
	while( i < encValLength )
		{
		int j;

		for( j = 0; j < 5; j++ )
			{
			const int ch = encVal[ i++ ];

			/* Note that we've just incremented 'i', so the range check is
			   '>' rather than '>=' */
			if( !isAlnum( ch ) || i > encValLength )
				return( CRYPT_ERROR_BADDATA );
			encBuf[ length++ ] = toUpper( ch );
			}
		if( i < encValLength && encVal[ i++ ] != '-' )
			return( CRYPT_ERROR_BADDATA );
		}
	if( length % 5 || length > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Decode the text data into binary */
	memset( valBuf, 0, 128 );
	for( i = 0; i < length; i ++ )
		{
		const int ch = encBuf[ i ];
		int chunkValue;

		for( chunkValue = 0; chunkValue < 0x20; chunkValue++ )
			if( codeTable[ chunkValue ] == ch )
				break;
		if( chunkValue >= 0x20 )
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
	if( bitCount > 0 )
		byteCount++;	/* More bits in the last partial byte */
	if( valBuf[ 0 ] != ( checksumData( valBuf + 1, byteCount - 1 ) & 0xFF ) )
		return( CRYPT_ERROR_BADDATA );

	/* Return the decoded value to the caller */
	if( value != NULL )
		{
		if( byteCount - 1 > valueMaxLen )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
			}
		memcpy( value, valBuf + 1, byteCount - 1 );
		}
	return( byteCount - 1 );
	}
