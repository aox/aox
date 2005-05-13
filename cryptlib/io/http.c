/****************************************************************************
*																			*
*						cryptlib HTTP Interface Routines					*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* The maximum number of header lines that we'll read before giving up */

#define MAX_HEADER_LINES	25

/* The maximum number of retries for redirections (and, by extension,
   anything else that can loop), as per RFC 2616 */

#define MAX_RETRY_COUNT		5

/* The size of the HTTP text-line buffer when we're using a dedicated buffer 
   to read header lines, rather than the main stream buffer.  Anything more 
   than this is dropped */

#define HTTP_LINEBUF_SIZE	1024

/* A macro to determine whether we're talking HTTP 1.0 or 1.1 */

#define isHTTP10( stream ) \
		( ( stream )->flags & STREAM_NFLAG_HTTP10 )

/* HTTP state information passed around the various read/write functions */

#define HTTP_FLAG_NONE		0x00	/* No HTTP info */
#define HTTP_FLAG_CHUNKED	0x01	/* Message used chunked encoding */
#define HTTP_FLAG_TRAILER	0x02	/* Chunked encoding has trailer */
#define HTTP_FLAG_NOOP		0x04	/* No-op data (e.g. 100 Continue) */
#define HTTP_FLAG_ERRORMSG	0x08	/* Content is text error message */

/* The various HTTP header types that we can process */

typedef enum { HTTP_HEADER_NONE, HTTP_HEADER_HOST, HTTP_HEADER_CONTENT_LENGTH,
			   HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_TRANSFER_ENCODING,
			   HTTP_HEADER_CONTENT_ENCODING, 
			   HTTP_HEADER_CONTENT_TRANSFER_ENCODING, HTTP_HEADER_TRAILER, 
			   HTTP_HEADER_CONNECTION, HTTP_HEADER_WARNING, 
			   HTTP_HEADER_EXPECT, HTTP_HEADER_LAST
			 } HTTP_HEADER_TYPE;

/* HTTP header parsing information.  Note that the first letter must be 
   uppercase for the case-insensitive quick match */

typedef struct {
	const char *headerString;		/* Header string */
	const int headerStringLen;		/* Length of header string */
	const HTTP_HEADER_TYPE headerType;	/* Type corresponding to header string */
	} HTTP_HEADER_INFO;

static const FAR_BSS HTTP_HEADER_INFO httpHeaderInfo[] = {
	{ "Host:", 5, HTTP_HEADER_HOST },
	{ "Content-Length:", 15, HTTP_HEADER_CONTENT_LENGTH },
	{ "Content-Type:", 13, HTTP_HEADER_CONTENT_TYPE },
	{ "Transfer-Encoding:", 18, HTTP_HEADER_TRANSFER_ENCODING },
	{ "Content-Encoding:", 17, HTTP_HEADER_CONTENT_ENCODING },
	{ "Content-Transfer-Encoding:", 26, HTTP_HEADER_CONTENT_TRANSFER_ENCODING },
	{ "Trailer:", 8, HTTP_HEADER_TRAILER },
	{ "Connection:", 11, HTTP_HEADER_CONNECTION },
	{ "NnCoection:", 11, HTTP_HEADER_CONNECTION },
	{ "Cneonction:", 11, HTTP_HEADER_CONNECTION },
		/* The bizarre spellings are for buggy NetApp NetCache servers, 
		   which unfortunately are widespread enough that we need to provide 
		   special-case handling for them.  For the second mis-spelling we
		   have to capitalise the first letter for our use since we compare
		   the uppercase form for a quick match */
	{ "Warning:", 8, HTTP_HEADER_WARNING },
	{ "Expect:", 7, HTTP_HEADER_EXPECT },
	{ NULL, 0, HTTP_HEADER_NONE }
	};

/* HTTP error/warning messages.  The mapped status for 30x redirects is 
   somewhat special-case, see the comment in readResponseHeader() for 
   details.  This table also contains known non-HTTP codes in the 
   expectation that, when used as a general-purpose substrate, it'll be
   pressed into use in all sorts of situations */

typedef struct {
	const int httpStatus;			/* Numeric status value */
	const char *httpStatusString;	/* String status value */
	const char *httpErrorString;	/* Text description of status */
	const int status;				/* Equivalent cryptlib status */
	} HTTP_STATUS_INFO;

static const FAR_BSS HTTP_STATUS_INFO httpStatusInfo[] = {
	{ 100, "100", "Continue", OK_SPECIAL },
	{ 101, "101", "Switching Protocols", CRYPT_ERROR_READ },
	{ 110, "110", "Warning: Response is stale", CRYPT_OK },
	{ 111, "111", "Warning: Revalidation failed", CRYPT_OK },
	{ 112, "112", "Warning: Disconnected operation", CRYPT_OK },
	{ 113, "113", "Warning: Heuristic expiration", CRYPT_OK },
	{ 199, "199", "Warning: Miscellaneous warning", CRYPT_OK },
	{ 200, "200", "OK", CRYPT_OK },
	{ 201, "201", "Created", CRYPT_ERROR_READ },
	{ 202, "202", "Accepted", CRYPT_ERROR_READ },
	{ 203, "203", "Non-Authoritative Information", CRYPT_OK },
	{ 204, "204", "No Content", CRYPT_ERROR_READ },
	{ 205, "205", "Reset Content", CRYPT_ERROR_READ },
	{ 206, "206", "Partial Content", CRYPT_ERROR_READ },
	{ 214, "214", "Warning: Transformation applied", CRYPT_OK },
	{ 250, "250", "RTSP: Low on Storage Space", CRYPT_OK },
	{ 299, "299", "Warning: Miscellaneous persistent warning", CRYPT_OK },
	{ 300, "300", "Multiple Choices", CRYPT_ERROR_READ },
	{ 301, "301", "Moved Permanently", OK_SPECIAL },
	{ 302, "302", "Moved Temporarily/Found", OK_SPECIAL },
	{ 303, "303", "See Other", CRYPT_ERROR_READ },
	{ 304, "304", "Not Modified", CRYPT_ERROR_READ },
	{ 305, "305", "Use Proxy", CRYPT_ERROR_READ },
	{ 306, "306", "Unused/obsolete", CRYPT_ERROR_READ },
	{ 307, "307", "Temporary Redirect", OK_SPECIAL },
	{ 400, "400", "Bad Request", CRYPT_ERROR_READ },
	{ 401, "401", "Unauthorized", CRYPT_ERROR_PERMISSION },
	{ 402, "402", "Payment Required", CRYPT_ERROR_READ },
	{ 403, "403", "Forbidden", CRYPT_ERROR_PERMISSION },
	{ 404, "404", "Not Found", CRYPT_ERROR_NOTFOUND },
	{ 405, "405", "Method Not Allowed", CRYPT_ERROR_NOTAVAIL },
	{ 406, "406", "Not Acceptable", CRYPT_ERROR_READ },
	{ 407, "407", "Proxy Authentication Required", CRYPT_ERROR_READ },
	{ 408, "408", "Request Time-out", CRYPT_ERROR_READ },
	{ 409, "409", "Conflict", CRYPT_ERROR_READ },
	{ 410, "410", "Gone", CRYPT_ERROR_NOTFOUND },
	{ 411, "411", "Length Required", CRYPT_ERROR_READ },
	{ 412, "412", "Precondition Failed", CRYPT_ERROR_READ },
	{ 413, "413", "Request Entity too Large", CRYPT_ERROR_OVERFLOW },
	{ 414, "414", "Request-URI too Large", CRYPT_ERROR_OVERFLOW },
	{ 415, "415", "Unsupported Media Type", CRYPT_ERROR_READ },
	{ 416, "416", "Requested range not satisfiable", CRYPT_ERROR_READ },
	{ 417, "417", "Expectation Failed", CRYPT_ERROR_READ },
	{ 451, "451", "RTSP: Parameter not Understood", CRYPT_ERROR_BADDATA },
	{ 452, "452", "RTSP: Conference not Found", CRYPT_ERROR_NOTFOUND },
	{ 453, "453", "RTSP: Not enough Bandwidth", CRYPT_ERROR_NOTAVAIL },
	{ 454, "454", "RTSP: Session not Found", CRYPT_ERROR_NOTFOUND },
	{ 455, "455", "RTSP: Method not Valid in this State", CRYPT_ERROR_NOTAVAIL },
	{ 456, "456", "RTSP: Header Field not Valid for Resource", CRYPT_ERROR_NOTAVAIL },
	{ 457, "457", "RTSP: Invalid Range", CRYPT_ERROR_READ },
	{ 458, "458", "RTSP: Parameter is Read-Only", CRYPT_ERROR_PERMISSION },
	{ 459, "459", "RTSP: Aggregate Operation not Allowed", CRYPT_ERROR_PERMISSION },
	{ 460, "460", "RTSP: Only Aggregate Operation Allowed", CRYPT_ERROR_PERMISSION },
	{ 461, "461", "RTSP: Unsupported Transport", CRYPT_ERROR_NOTAVAIL },
	{ 462, "462", "RTSP: Destination Unreachable", CRYPT_ERROR_OPEN },
	{ 500, "500", "Internal Server Error", CRYPT_ERROR_READ },
	{ 501, "501", "Not Implemented", CRYPT_ERROR_NOTAVAIL },
	{ 502, "502", "Bad Gateway", CRYPT_ERROR_READ },
	{ 503, "503", "Service Unavailable", CRYPT_ERROR_READ },
	{ 504, "504", "Gateway Time-out", CRYPT_ERROR_READ },
	{ 505, "505", "HTTP Version not supported", CRYPT_ERROR_READ },
	{ 510, "510", "HTTP-Ext: Not Extended", CRYPT_ERROR_READ },
	{ 551, "551", "RTSP: Option not supported", CRYPT_ERROR_READ },
	{ 0, NULL, "Unknown HTTP status condition", CRYPT_ERROR_READ }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* When reading text data over a network we don't know how much more data is
   to come so we have to read a byte at a time looking for an EOL.  In
   addition we can't use the simple optimisation of reading two bytes at a
   time because some servers only send a LF even though the spec requires a
   CRLF.  This is horribly inefficient but is pretty much eliminated through
   the use of opportunistic read-ahead buffering */

static int readLine( STREAM *stream, char *buffer, const int maxSize )
	{
	MIME_STATE state;
	int status;

	initMIMEstate( &state, maxSize );
	do
		{
		BYTE ch;

		status = stream->bufferedTransportReadFunction( stream, &ch, 1,
														TRANSPORT_FLAG_NONE );
		if( cryptStatusError( status ) )
			/* Network-level error, don't overwrite the extended error
			   information */
			return( status );
		status = addMIMEchar( &state, buffer, ch );
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		/* We got an error other than an EOL condition, exit */
		retExtStream( stream, status, "Invalid HTTP header line" );
	return( endMIMEstate( &state ) );
	}

/* Skip whitespace in a line of text.  We only need to check for spaces as
   whitespace since it's been canonicalised already */

static const char *skipWhitespace( const char *buffer )
	{
	if( buffer == NULL )
		return( NULL );

	while( *buffer == ' ' )
		buffer++;
	return( *buffer ? buffer : NULL );
	}

/* Decode a hex nibble */

static int getNibble( const char srcCh )
	{
	int ch;

	ch = toLower( srcCh );
	if( !isXDigit( ch ) )
		return( CRYPT_ERROR_BADDATA );
	return( ( ch <= '9' ) ? ch - '0' : ch - ( 'a' - 10 ) );
	}

/* Encode/decode a string as per RFC 1866 (although the list of characters 
   that need to be escaped is itself given in RFC 2396).  Characters that 
   are permitted/not permitted are:

	 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	x..x.xx....x...xxxxxxxxxxxx.xxxxx

   Because of this it's easier to check for the most likely permitted
   characters (alphanumerics), and then to check for any special-case
   chars */

static void encodeRFC1866( STREAM *headerStream, const char *source )
	{
	static const char *allowedChars = "$-_.!*'(),\"/";	/* RFC 1738 + '/' */

	while( *source )
		{
		const int ch = *source++;
		int i;

		if( isAlnum( ch ) )
			{
			sputc( headerStream, ch );
			continue;
			}
		if( ch == ' ' )
			{
			sputc( headerStream, '+' );
			continue;
			}
		for( i = 0; allowedChars[ i ] && ch != allowedChars[ i ]; i++ );
		if( allowedChars[ i ] )
			/* It's in the allowed-chars list, output it verbatim */
			sputc( headerStream, ch );
		else
			{
			char escapeString[ 8 ];
			int escapeStringLen;

			/* It's a special char, escape it */
			escapeStringLen = sPrintf( escapeString, "%%%02X", ch );
			swrite( headerStream, escapeString, escapeStringLen );
			}
		}
	}

static int decodeRFC1866( char *dest, const char *source, 
						  const int sourceLen )
	{
	const char *origDestPtr = dest;
	BOOLEAN seenEscape = FALSE;
	int i;

	for( i = 0; i < sourceLen; i++ )
		{
		int chLo, chHi, ch;

		/* If it's not an escape, just copy it straight over */
		if( *source != '%' )
			{
			*dest++ = *source++;
			continue;
			}
		source++;	/* Skip '%' */
		i += 2;		/* Skip escape sequence */
		seenEscape = TRUE;

		/* Decode the escaped character */
		if( sourceLen - i < 1 )
			return( CRYPT_ERROR_BADDATA );
		chHi = getNibble( *source ); source++;
		chLo = getNibble( *source ); source++;
		if( cryptStatusError( chHi ) || cryptStatusError( chLo ) )
			return( CRYPT_ERROR_BADDATA );
		ch = ( chHi << 4 ) | chLo;
		if( !isPrint( ch ) )
			/* It's a special-case/control character of some kind, report
			   it as an error.  This gets rid of things like nulls (treated 
			   as string terminators by some functions) and CR/LF line 
			   terminators, which can be embedded into strings to turn a 
			   single line of supplied text into multi-line responses 
			   containing user-controlled type:value pairs (in other words 
			   they allow user data to be injected into the control 
			   channel) */
			return( CRYPT_ERROR_BADDATA );
		*dest++ = ch;
		}

	/* If we've seen an escape sequence, tell the caller the new length, 
	   otherwise tell them that nothing's changed */
	return( seenEscape ? dest - origDestPtr : OK_SPECIAL );
	}

/* Convert a hex ASCII string used with chunked encoding into a numeric
   value */

static int getChunkLength( const char *buffer, const int bufLen )
	{
	int i, chunkLength = 0, length = bufLen;

	/* Chunk size information can have extensions tacked onto it following a 
	   ';', strip these before we start */
	for( i = 0; i < bufLen; i++ )
		if( buffer[ i ] == ';' )
			{
			/* Move back to the end of the string that precedes the ';' */
			while( i > 0 && buffer[ i - 1 ] == ' ' )
				i--;
			length = i;
			break;
			}

	/* The other side shouldn't be sending us more than 64K of data, given
	   that what we're expecting is a short PKI message */
	if( length < 1 || length > 4 )
		return( CRYPT_ERROR_BADDATA );

	/* Walk down the string converting hex characters into their numeric
	   values */
	for( i = 0; i < length; i++ )
		{
		const int ch = getNibble( buffer[ i ] );

		if( cryptStatusError( ch ) )
			return( CRYPT_ERROR_BADDATA );
		chunkLength = ( chunkLength << 4 ) | ch;
		}

	return( chunkLength );
	}

/* If we time out when sending HTTP header data this would usually be 
   reported as a CRYPT_ERROR_TIMEOUT by the lower-level network I/O 
   routines, however due to the multiple layers of I/O and special case 
   timeout handling when (for example) a cryptlib transport session is 
   layered over the network I/O layer and the fact that to the caller the
   write of the out-of-band HTTP header data is invisible, we have to 
   perform an explicit check to make sure that we sent everything */

static int sendHTTPData( STREAM *stream, void *buffer, const int length,
						 const int flags )
	{
	int status;

	status = stream->bufferedTransportWriteFunction( stream, buffer, length, 
													 flags );
	if( cryptStatusError( status ) )
		/* Network-level error, the lower-level layers have reported the 
		   error details */
		return( status );
	if( status < length )
		/* The write timed out, convert the incomplete HTTP header write to 
		   the appropriate timeout error */
		retExtStream( stream, CRYPT_ERROR_TIMEOUT,
					  "HTTP write timed out before all data could be "
					  "written" );
	return( CRYPT_OK );
	}

/* Send an HTTP error message */

static int sendHTTPError( STREAM *stream, char *headerBuffer, 
						  const int httpStatus )
	{
	const char *statusString = "400";
	const char *errorString = "Bad Request";
	int length, i;

	/* Find the HTTP error string that corresponds to the HTTP status 
	   value */
	for( i = 0; httpStatusInfo[ i ].httpStatus && \
				httpStatusInfo[ i ].httpStatus != httpStatus; i++ );
	if( httpStatusInfo[ i ].httpStatus )
		{
		statusString = httpStatusInfo[ i ].httpStatusString;
		errorString = httpStatusInfo[ i ].httpErrorString;
		}

	/* Send the error message to the peer.  We have to be careful with return
	   values since we could time out before all the data is sent */
	length = sPrintf( headerBuffer, "%s %s %s\r\n\r\n",
					  isHTTP10( stream ) ? "HTTP/1.0" : "HTTP/1.1",
					  statusString, errorString );
	return( sendHTTPData( stream, headerBuffer, length, 
						  TRANSPORT_FLAG_FLUSH ) );
	}

/****************************************************************************
*																			*
*							HTTP Parsing Functions							*
*																			*
****************************************************************************/

/* Parse a sub-segment of a URI, returning its length */

static int parseUriSegment( const char *buffer, const char endChar )
	{
	int length;

	/* Parse the current query sub-segment */
	for( length = 0; length <= CRYPT_MAX_TEXTSIZE && \
					 *buffer && *buffer != endChar; \
		 length++ )
		buffer++;

	/* Make sure that we didn't run out of data */
	if( length >= CRYPT_MAX_TEXTSIZE || !*buffer )
		return( CRYPT_ERROR_BADDATA );

	return( length );
	}

/* Parse a URI of the form * '?' attribute '=' value */

static int parseURI( char *outBuffer, int *outBufPos, 
					 const char *inBuffer, const int inBufLen )
	{
	const char *origOutBuffer = outBuffer, *bufPtr = inBuffer;
	const char *namePtr, *valuePtr;
	int nameLength, valueLength, bufLen = inBufLen, status;

	/* Clear return value */
	*outBufPos = 0;

	/* Decode the URI line.  Since there can be multiple nested levels of
	   encoding, we keep iteratively decoding until decodeRFC1866() cries
	   Uncle.  The first time through the loop we decode from the inBuffer to
	   the outBuffer, in successive iterations we decode in-place in the
	   outBuffer */
	do
		{
		status = decodeRFC1866( outBuffer, bufPtr, bufLen );
		if( !cryptStatusError( status ) )
			/* It's a length-change notification, record the new length */
			bufLen = status;
		else
			if( status != OK_SPECIAL )
				return( CRYPT_ERROR_BADDATA );
		bufPtr = outBuffer;
		}
	while( status != OK_SPECIAL );

	/* Open up a gap at the start of the output buffer to allow for the 
	   encoded return form */
	memmove( outBuffer + 8, outBuffer, bufLen );
	bufPtr = outBuffer + 8;

	/* Parse a URI of the form * '?' attribute '=' value */
	status = parseUriSegment( bufPtr, '?' );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += status + 1;		/* Skip '?' */
	namePtr = bufPtr;
	nameLength = parseUriSegment( bufPtr, '=' );
	if( cryptStatusError( nameLength ) )
		return( nameLength );
	bufPtr += nameLength + 1;	/* Skip '=' */
	valuePtr = bufPtr;
	valueLength = parseUriSegment( bufPtr, ' ' );
	if( cryptStatusError( valueLength ) )
		return( valueLength );

	/* Encode the location, attribute, and value for use by the caller */
	mputWord( outBuffer, 0 );
	mputWord( outBuffer, nameLength );
	memmove( outBuffer, namePtr, nameLength );
	outBuffer += nameLength;
	mputWord( outBuffer, valueLength );
	memmove( outBuffer, valuePtr, valueLength );
	outBuffer += valueLength;
	*outBufPos = outBuffer - origOutBuffer;

	return( ( valuePtr + valueLength ) - origOutBuffer );
	}

/* Check an "HTTP 1.x" ID string.  No PKI client should be sending us an 0.9
   ID, so we only allow 1.x */

static int checkHTTPID( STREAM *stream, const char *buffer, const int length )
	{
	if( length < 8 || strCompare( buffer, "HTTP/1.", 7 ) )
		return( CRYPT_ERROR_BADDATA );
	if( buffer[ 7 ] == '0' )
		stream->flags |= STREAM_NFLAG_HTTP10;
	else
		if( buffer[ 7 ] != '1' )
			return( CRYPT_ERROR_BADDATA );

	return( 8 );
	}

/* Read an HTTP status code.  Some status values are warnings only and
   don't return an error status */

static int readHTTPStatus( STREAM *stream, int *httpStatus,
						   const char *lineBuffer )
	{
	const HTTP_STATUS_INFO *httpStatusPtr;
	const char *lineBufPtr;
	char thirdChar;
	int i;

	/* Clear return value */
	if( httpStatus != NULL )
		*httpStatus = CRYPT_OK;

	/* Process the numeric HTTP status code and translate it into a cryptlib
	   equivalent.  We check the third digit (the one most likely to be 
	   different) for a mismatch to avoid a large number of calls to the 
	   string-compare function.  Most of the HTTP codes don't have any 
	   meaning in a cryptlib context, so we return a generic 
	   CRYPT_ERROR_READ */
	lineBufPtr = skipWhitespace( lineBuffer );
	if( lineBufPtr == NULL || strlen( lineBufPtr ) < 3 || \
		!isDigit( *lineBufPtr ) )
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Invalid/missing HTTP status code" );
	thirdChar = lineBufPtr[ 2 ];
	for( i = 0; \
		 httpStatusInfo[ i ].httpStatus && \
		 ( httpStatusInfo[ i ].httpStatusString[ 2 ] != thirdChar || \
		   strCompare( lineBufPtr, httpStatusInfo[ i ].httpStatusString, 3 ) ); \
		 i++ );
	httpStatusPtr = &httpStatusInfo[ i ];
	if( httpStatus != NULL )
		*httpStatus = aToI( lineBufPtr );
	if( httpStatusPtr->status == OK_SPECIAL )
		/* It's a special-case condition such as a redirect, tell the caller
		   to handle it specially */
		return( OK_SPECIAL );
	if( httpStatusPtr->status != CRYPT_OK )
		{
		/* It's an error condition, return extended error info */
		assert( httpStatusPtr->httpStatusString != NULL );
							/* Catch oddball errors in debug version */
		retExtStream( stream, httpStatusPtr->status, "HTTP status: %s",
					  httpStatusPtr->httpErrorString );
		}
	return( CRYPT_OK );
	}

/* Process an HTTP header line looking for anything that we can handle */

static int checkHeaderLine( char **lineBufPtrPtr, 
							HTTP_HEADER_TYPE *headerType, void *stream )
	{
	const HTTP_HEADER_INFO *headerInfoPtr;
	const char *lineBufPtr = *lineBufPtrPtr;
	const char firstChar = toUpper( *lineBufPtr );
	const int lineLength = strlen( lineBufPtr );
	int i;

	/* Clear return value */
	*headerType = HTTP_HEADER_NONE;

	/* Look for a header line that we recognise */
	for( i = 0; 
		 httpHeaderInfo[ i ].headerString != NULL && \
		 ( httpHeaderInfo[ i ].headerString[ 0 ] != firstChar || \
		   lineLength < httpHeaderInfo[ i ].headerStringLen || \
		   strCompare( lineBufPtr, httpHeaderInfo[ i ].headerString, \
					   httpHeaderInfo[ i ].headerStringLen ) ); 
		 i++ );
	headerInfoPtr = &httpHeaderInfo[ i ];
	if( headerInfoPtr->headerString == NULL )
		/* It's nothing that we can handle, exit */
		return( CRYPT_OK );

	/* Make sure that there's a token present */
	lineBufPtr = skipWhitespace( lineBufPtr + headerInfoPtr->headerStringLen );
	if( lineBufPtr == NULL )
		retExtStream( stream, CRYPT_ERROR_BADDATA, 
					  "Missing HTTP header token for '%s'", 
					  headerInfoPtr->headerString );

	/* Tell the caller what we found */
	*lineBufPtrPtr = ( char * ) lineBufPtr;
	*headerType = headerInfoPtr->headerType;
	return( CRYPT_OK );
	}

/* Read the first line in an HTTP response header */

static int readFirstHeaderLine( STREAM *stream, int *httpStatus,
								char *lineBuffer, const int maxLength )
	{
	int status;

	*httpStatus = CRYPT_OK;

	/* Read the header and check for an HTTP ID */
	status = readLine( stream, lineBuffer, maxLength );
	if( cryptStatusError( status ) )
		return( status );
	status = checkHTTPID( stream, lineBuffer, status );
	if( cryptStatusError( status ) )
		retExtStream( stream, status, "Invalid HTTP ID/version" );

	/* Read the HTTP status info */
	return( readHTTPStatus( stream, httpStatus, lineBuffer + status ) );
	}

/* Read the remaining HTTP header lines after the first one */

static int readHeaderLines( STREAM *stream, char *lineBuffer,
							int *contentLength, int *httpErrorStatus, 
							int *flags, const int minLength, 
							const int maxLength, const BOOLEAN expandBuffer )
	{
	BOOLEAN seenHost = FALSE, seenLength = FALSE;
	int localLength = 0, lineCount, status;

	/* Clear return value */
	if( httpErrorStatus != NULL )
		*httpErrorStatus = 0;
	if( contentLength != NULL )
		*contentLength = 0;

	/* Read each line in the header checking for any fields that we need to 
	   handle */
	for( lineCount = 0; lineCount < MAX_HEADER_LINES; lineCount++ )
		{
		HTTP_HEADER_TYPE headerType;
		char *lineBufPtr = lineBuffer;

		status = readLine( stream, lineBuffer, maxLength );
		if( cryptStatusError( status ) )
			return( status );
		if( status == 0 )
			/* End of input, exit */
			break;
		status = checkHeaderLine( &lineBufPtr, &headerType, stream );
		if( cryptStatusError( status ) )
			return( status );
		switch( headerType )
			{
			case HTTP_HEADER_HOST:
				/* Remember that we've seen a Host: line, to meet the HTTP 
				   1.1 requirements */
				seenHost = TRUE;
				break;
			
			case HTTP_HEADER_CONTENT_LENGTH:
				/* Get the content length.  At this point all we do is a 
				   general sanity check that the length looks OK, a specific
				   check against the caller-supplied minimum allowable 
				   length is performed later since the content length may 
				   also be provided as a chunked encoding length */
				localLength = aToI( lineBufPtr );
				if( localLength <= 0 || localLength > MAX_INTLENGTH )
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content length %d",
								  localLength );
				seenLength = TRUE;
				break;

			case HTTP_HEADER_CONTENT_TYPE:
				/* Sometimes if there's an error it'll be returned at the 
				   HTTP level rather than at the tunnelled-over-HTTP 
				   protocol level.  The easiest way to check for this would 
				   be to make sure that the content-type matches the 
				   expected type and report anything else as an error.  
				   Unfortunately due to the hit-and-miss handling of content-
				   types by PKI software using HTTP as a substrate it's not 
				   safe to do this, so we have to default to allow-all 
				   rather than deny-all, treating only straight text as a 
				   problem type (although there are probably also apps out 
				   there somewhere that send their PKI messages marked as 
				   plain text) */
				if( !strCompare( lineBufPtr, "text/", 5 ) )
					*flags |= HTTP_FLAG_ERRORMSG;
				break;

			case HTTP_HEADER_TRANSFER_ENCODING:
				if( !strCompare( lineBuffer, "Chunked", 7 ) )
					{
					lineBuffer[ CRYPT_MAX_TEXTSIZE ] = '\0';
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP transfer encoding method "
								  "'%s', expected 'Chunked'", lineBuffer );
					}

				/* If it's a chunked encoding, the length is part of the 
				   data and must be read later */
				*flags |= HTTP_FLAG_CHUNKED;
				break;

			case HTTP_HEADER_CONTENT_ENCODING:
				/* We can't handle any type of content encoding (e.g. gzip,
				   compress, deflate) except the no-op identity encoding */
				if( !strCompare( lineBuffer, "Identity", 8 ) )
					{
					if( httpErrorStatus != NULL )
						*httpErrorStatus = 415;
					lineBuffer[ CRYPT_MAX_TEXTSIZE ] = '\0';
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content encoding method "
								  "'%s', expected 'Identity'",
								  lineBuffer );
					}
				break;

			case HTTP_HEADER_CONTENT_TRANSFER_ENCODING:
				/* HTTP uses Transfer-Encoding, not the MIME Content-
				   Transfer-Encoding types such as base64 or quoted-
				   printable.  If any implementations use a C-T-E, we make
				   sure that it's something that we can handle */
				if( !strCompare( lineBuffer, "Identity", 8 ) && \
					!strCompare( lineBuffer, "Binary", 6 ) )
					{
					if( httpErrorStatus != NULL )
						*httpErrorStatus = 415;
					lineBuffer[ CRYPT_MAX_TEXTSIZE ] = '\0';
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content transfer encoding "
								  "method '%s', expected 'Identity' or "
								  "'Binary'", lineBuffer );
					}
				break;

			case HTTP_HEADER_TRAILER:
				/* The body is followed by trailer lines, used with chunked
				   encodings where some header lines can't be produced until
				   the entire body has been generated.  This wasn't added 
				   until RFC 2616, since many implementations are based on 
				   RFC 2068 and don't produce this header we don't do 
				   anything with it.  The trailer can be auto-detected 
				   anyway, it's only present to tell the receiver to perform 
				   certain actions such as creating an MD5 hash of the data 
				   as it arrives */
				*flags |= HTTP_FLAG_TRAILER;
				break;

			case HTTP_HEADER_CONNECTION:
				/* If the other side has indicated that it's going to close 
				   the connection, remember that the stream is now no longer
				   usable */
				if( !strCompare( lineBuffer, "Close", 5 ) )
					sioctl( stream, STREAM_IOCTL_CONNSTATE, NULL, FALSE );
				break;

			case HTTP_HEADER_WARNING:
				/* Read the HTTP status info from the warning, discarding any
				   error status since this isn't an error */
				readHTTPStatus( stream, NULL, lineBufPtr );
				break;

			case HTTP_HEADER_EXPECT:
				/* If the other side wants the go-ahead to continue, give it 
				   to them.  We do this automatically because we're merely 
				   using HTTP as a substrate, the real decision will be made
				   at the higher-level protocol layer.  In theory we could 
				   at least check the content type, but see the comment in
				   the content-type handler for why we don't do this */
				if( !strCompare( lineBuffer, "100-Continue", 12 ) )
					sendHTTPError( stream, lineBuffer, 100 );
				break;
			
			case HTTP_HEADER_NONE:
				/* It's something that we don't know/care about, skip it */
				break;

			default:
				assert( NOTREACHED );
			}
		}
	if( lineCount >= MAX_HEADER_LINES )
		retExtStream( stream, CRYPT_ERROR_OVERFLOW,
					  "Too many HTTP header lines" );

	/* If it's a chunked encoding for which the length is kludged on before
	   the data as a hex string, decode the length value */
	if( *flags & HTTP_FLAG_CHUNKED )
		{
		status = readLine( stream, lineBuffer, maxLength );
		if( cryptStatusError( status ) )
			return( status );
		status = localLength = getChunkLength( lineBuffer, status );
		if( cryptStatusError( status ) )
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Invalid length for HTTP chunked encoding" );
		seenLength = TRUE;
		}

	/* If this is a no-op read (for example lines following an error or 100 
	   Continue response), all that we're interested in is draining the 
	   input, so we don't check any further */
	if( *flags & HTTP_FLAG_NOOP )
		return( CRYPT_OK );

	/* If we're a server talking HTTP 1.1 and we haven't seen a Host: header
	   from the client, return an error */
	if( ( stream->flags & STREAM_NFLAG_ISSERVER ) && \
		!isHTTP10( stream ) && !seenHost )
		{
		if( httpErrorStatus != NULL )
			*httpErrorStatus = 400;
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP host header" );
		}

	/* If it's an idempotent read there's no length, just a GET request, so
	   we can exit now */
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		return( CRYPT_OK );

	/* Make sure that we've been given a length.  In theory a server could
	   indicate the length implicitly by closing the connection once it's
	   sent the last byte, but this isn't allowed for PKI messages.  The
	   client can't use this option either since that would make it 
	   impossible for us to send back the response */
	if( !seenLength )
		{
		if( httpErrorStatus != NULL )
			*httpErrorStatus = 411;
		retExtStream( stream, CRYPT_ERROR_BADDATA, "Missing HTTP length" );
		}

	/* Make sure that the length is sensible */
	if( localLength < minLength )
		retExtStream( stream, CRYPT_ERROR_UNDERFLOW,
					  "Insufficient HTTP content data, need %d bytes but "
					  "only got %d", minLength, localLength );
	if( !expandBuffer && ( localLength > maxLength ) )
		{
		if( httpErrorStatus != NULL )
			*httpErrorStatus = 413;
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Excessive HTTP content data, got %d bytes when "
					  "maximum was %d", localLength, maxLength );
		}
	if( contentLength != NULL )
		*contentLength = localLength;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/write Request Header						*
*																			*
****************************************************************************/

/* Write an HTTP request header */

static int writeRequestHeader( STREAM *stream, const int length )
	{
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	const int transportFlag = ( length > 0 ) ? TRANSPORT_FLAG_NONE : \
											   TRANSPORT_FLAG_FLUSH;
	const int hostLen = strlen( stream->host );
	int headerLength;

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( length > 0 )
		swrite( &headerStream, "POST ", 5 );
	else
		swrite( &headerStream, "GET ", 4 );
	if( stream->flags & STREAM_NFLAG_HTTPPROXY )
		{
		/* If we're going through an HTTP proxy, send an absolute URL rather
		   than just the relative location */
		swrite( &headerStream, "http://", 7 );
		swrite( &headerStream, stream->host, hostLen );
		if( stream->port != 80 )
			{
			char portString[ 16 ];
			int portStringLength;

			portStringLength = sprintf( portString, ":%d", stream->port );
			swrite( &headerStream, portString, portStringLength );
			}
		}
	if( stream->path != NULL )
		swrite( &headerStream, stream->path, strlen( stream->path ) );
	else
		sputc( &headerStream, '/' );
	if( stream->query != NULL )
		{
		sputc( &headerStream, '?' );
		encodeRFC1866( &headerStream, stream->query );
		}
	if( isHTTP10( stream ) )
		swrite( &headerStream, " HTTP/1.0\r\n", 11 );
	else
		{
		swrite( &headerStream, " HTTP/1.1\r\nHost: ", 17 );
		swrite( &headerStream, stream->host, hostLen );
		swrite( &headerStream, "\r\n", 2 );
		if( stream->flags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	if( length > 0 )
		{
		char lengthString[ 16 ];
		int lengthStringLength;

		swrite( &headerStream, "Content-Type: ", 14 );
		swrite( &headerStream, stream->contentType, 
				strlen( stream->contentType ) );
		swrite( &headerStream, "\r\nContent-Length: ", 18 );
		lengthStringLength = sprintf( lengthString, "%d", length );
		swrite( &headerStream, lengthString, lengthStringLength );
		swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
		}
	swrite( &headerStream, "\r\n", 2 );
	headerLength = stell( &headerStream );
	assert( sStatusOK( &headerStream ) );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, headerLength, 
						  transportFlag ) );
	}

/* Read an HTTP request header */

static int readRequestHeader( STREAM *stream, int *contentLength, 
							  char *buffer, const int maxLength, int *flags )
	{
	const char *bufPtr;
	const char *reqName = ( stream->flags & STREAM_NFLAG_IDEMPOTENT ) ? \
						  "GET " : "POST ";
	const int reqNameLen = ( stream->flags & STREAM_NFLAG_IDEMPOTENT ) ? \
						   4 : 5;
	int bufMaxLen = maxLength, idempotentReadLength = 0, length;
	int httpStatus, status;

	assert( stream->flags & STREAM_NFLAG_ISSERVER );

	/* Clear return value */
	*contentLength = CRYPT_ERROR;

	/* Read the header and check for "POST/GET x HTTP/1.x" (=15).  In theory
	   this could be a bit risky because the original CERN server required an
	   extra (spurious) CRLF after a POST, so that various early clients sent
	   an extra CRLF that isn't included in the Content-Length header and
	   ends up preceding the start of the next load of data.  We don't check
	   for this because it only applies to very old pure-HTTP (rather than
	   HTTP-as-a-transport-layer) clients, which are unlikely to be hitting a
	   PKI responder */
	status = length = readLine( stream, buffer, maxLength );
	if( cryptStatusError( status ) )
		{
		/* If it's an HTTP-level error (e.g. line too long), send back an 
		   error response */
		if( status != CRYPT_ERROR_COMPLETE )
			sendHTTPError( stream, buffer, 
						   ( status == CRYPT_ERROR_OVERFLOW ) ? 414 : 400 );
		return( status );
		}
	if( strCompare( buffer, reqName, reqNameLen ) )
		{
		char reqNameBuffer[ 16 ];

		strcpy( reqNameBuffer, reqName );
		reqNameBuffer[ reqNameLen - 1 ] = '\0';	/* Strip trailing space */
		sendHTTPError( stream, buffer, 501 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Invalid HTTP request, expected '%s'", reqName );
		}
	bufPtr = buffer + reqNameLen;

	/* Process the ' '* * ' '* and check for the HTTP ID */
	if( ( bufPtr = skipWhitespace( bufPtr ) ) == NULL )
		{
		sendHTTPError( stream, buffer, 400 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP request URI" );
		}
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		{
		/* If it's an indempotent read the client is sending a GET rather
		   than submitting a POST, process the request details */
		status = parseURI( buffer, &idempotentReadLength, bufPtr, 
						   length - ( bufPtr - buffer ) );
		if( cryptStatusError( status ) || status < 10 )
			{
			sendHTTPError( stream, buffer, 400 );
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Invalid HTTP GET request URI" );
			}
		bufPtr = buffer + status;

		/* At this point part of the read buffer contains the data to be
		   returned to the caller, with the remainder of the buffer 
		   available for processing additional header lines.  To handle this 
		   we adjust the maximum buffer size to accomodate the data already 
		   in the buffer */
		bufMaxLen = maxLength - idempotentReadLength;
		}
	else
		/* For non-idempotent queries we don't care what the location is 
		   since it's not relevant for anything, this also avoids 
		   complications with absolute vs. relative URLs, character 
		   encoding/escape sequences, and so on */
		while( *bufPtr && *bufPtr != ' ' )
			bufPtr++;
	if( ( bufPtr = skipWhitespace( bufPtr ) ) == NULL )
		{
		sendHTTPError( stream, buffer, 400 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP request ID/version" );
		}
	status = checkHTTPID( stream, bufPtr, length - ( bufPtr - buffer ) );
	if( cryptStatusError( status ) )
		{
		sendHTTPError( stream, buffer, 505 );
		retExtStream( stream, status, "Invalid HTTP request ID/version" );
		}

	/* Process the remaining header lines.  ~32 bytes is the minimum-size
	   object that can be returned from any HTTP-based message which is
	   exchanged by cryptlib, this being a TSP request */
	status = readHeaderLines( stream, buffer + idempotentReadLength, 
							  contentLength, &httpStatus, flags, 32, 
							  bufMaxLen, FALSE );
	if( cryptStatusError( status ) )
		/* We always (try and) send an HTTP error response once we get to 
		   this stage since chances are it'll be a problem with an HTTP
		   header rather than a low-level network read problem */
		sendHTTPError( stream, buffer, httpStatus );

	/* If it's an idempotent read, the content length is the length of the 
	   request data and not the body, since there isn't one */
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		*contentLength = idempotentReadLength;

	return( status );
	}

/****************************************************************************
*																			*
*							Read/write Response Header						*
*																			*
****************************************************************************/

/* Write an HTTP response header */

static int writeResponseHeader( STREAM *stream, const int length )
	{
	char headerBuffer[ HTTP_LINEBUF_SIZE ];
	int headerPos;

	/* We don't use a stream to encode the header lines for responses since
	   all of the lines are quite short and can't overflow the buffer */
	if( isHTTP10( stream ) )
		strcpy( headerBuffer, "HTTP/1.0 200 OK\r\n" );
	else
		{
		strcpy( headerBuffer, "HTTP/1.1 200 OK\r\n" );
		if( stream->flags & STREAM_NFLAG_LASTMSG )
			strcat( headerBuffer, "Connection: close\r\n" );
		}
	headerPos = strlen( headerBuffer );
	strcat( headerBuffer + headerPos, "Content-Type: " );
	strcat( headerBuffer + headerPos, stream->contentType );
	strcat( headerBuffer + headerPos, "\r\nContent-Length: " );
	headerPos += strlen( headerBuffer + headerPos );
	sPrintf( headerBuffer + headerPos, 
			 "%d\r\nCache-Control: no-cache\r\n", length );
	if( isHTTP10( stream ) )
		strcat( headerBuffer + headerPos, "Pragma: no-cache\r\n" );
	strcat( headerBuffer + headerPos, "\r\n" );
	headerPos = strlen( headerBuffer );

	return( sendHTTPData( stream, headerBuffer, headerPos,
						  TRANSPORT_FLAG_NONE ) );
	}

/* Read an HTTP response header */

static int readResponseHeader( STREAM *stream, int *contentLength, char *buffer,
							   const int maxLength,
							   const BOOLEAN expandBuffer, int *flags )
	{
	int repeatCount, status;

	/* Clear return value */
	*contentLength = CRYPT_ERROR;

	/* If it's a stateless HTTP read, we need to send the fetch request
	   before we can read anything back */
	if( stream->protocol == STREAM_PROTOCOL_HTTP )
		{
		assert( !*stream->contentType );

		status = writeRequestHeader( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the returned response header from the server, taking various
	   special-case conditions into account.  In theory we could also handle
	   the 503 "Retry-After" status, but there's no sensible reason why
	   anyone should send us this, and even if they do it'll screw up a lot
	   of the PKI protocols, which have timeliness constraints built in */
	for( repeatCount = 0; repeatCount < MAX_RETRY_COUNT; repeatCount++ )
		{
		BOOLEAN needsSpecialHandling = FALSE;
		int httpStatus;

		/* Read the response header */
		status = readFirstHeaderLine( stream, &httpStatus, buffer, maxLength );
		if( status == OK_SPECIAL )
			{
			/* If it's a special-case header (e.g. a 100 Continue), turn the
			   read into a no-op read that drains the input to get to the
			   real data */
			*flags |= HTTP_FLAG_NOOP;
			needsSpecialHandling = TRUE;
			}
		else
			if( cryptStatusError( status ) )
				{
				int localFlags = *flags | HTTP_FLAG_NOOP;

				/* Drain the input and exit */
				readHeaderLines( stream, buffer, NULL, NULL, &localFlags, 
								 5, maxLength, FALSE );
				return( status );
				}

		/* Process the remaining header lines.  5 bytes is the minimum-size
		   object that can be returned from any HTTP-based message which is
		   exchanged by cryptlib, this being an OCSP response containing a
		   single-byte status value, i.e. SEQUENCE { ENUM x } */
		status = readHeaderLines( stream, buffer, contentLength, NULL, 
								  flags, 5, maxLength, expandBuffer );
		*flags &= ~HTTP_FLAG_NOOP;
		if( cryptStatusError( status ) )
			return( status );

		/* If it's not something like a redirect that needs special-case 
		   handling, we're done */
		if( !needsSpecialHandling )
			return( CRYPT_OK );

		assert( httpStatus == 100 || httpStatus == 301 || \
				httpStatus == 302 || httpStatus == 307 );

		/* If we got a 100 Continue response, try for another header that
		   follows the first one */
		if( httpStatus == 100 )
			continue;

		/* If we got a 301, 302, or 307 Redirect then in theory we should 
		   proceed roughly as per the code below, however in practice it's 
		   not nearly as simple as this, because what we're in effect doing 
		   is taking a stream and replacing it with a completely new stream 
		   (different host/abs-path/query info, new socket with optional 
		   proxy handling, etc etc).  One way to do this would be to read 
		   the new location into the current stream buffer and pass it back 
		   with a special status telling the stream-level code to create a 
		   new stream, clean up the old one, and perform a deep copy of the 
		   new stream over to the old one.  We'll leave this for a time when 
		   it's really needed.
		   
		   In addition the semantics of the following don't quite follow 
		   those of RFC 2616 because of the HTTP-as-a-substrate use rather
		   than direct use in a browser.  Specifically, anything other than
		   a GET for a 302 or 307 isn't supposed to perform an automatic 
		   redirect without asking the user, because of concerns that it'll
		   change the semantics of the request.  However, since we're not an
		   interactive web browser there's no way that we can ask a user for 
		   redirect permission, and in any case since we're merely using 
		   HTTP as a substrate for a cryptographically protected PKI 
		   message (and specifically assuming that the HTTP layer is 
		   completely insecure), any problems will be caught by the crypto
		   protocol layer */
#if 0
		if( !*location )
			return( CRYPT_ERROR_READ );
		stream->closeSocketFunction( stream );
		clFree( "readResponseHeader", stream->host );
		stream->host = NULL;
		status = parseLocation( stream, location );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_READ );
#endif /* 0 */
		retExtStream( stream, CRYPT_ERROR_READ,
					  "Unable to process HTTP 301/302 redirect" );
		}

	/* We used up our maximum number of retries, bail out */
	retExtStream( stream, CRYPT_ERROR_READ,
				  "HTTP retry/redirection loop detected" );
	}

/****************************************************************************
*																			*
*							HTTP Access Functions							*
*																			*
****************************************************************************/

/* Read data from an HTTP stream */

static int readFunction( STREAM *stream, void *buffer, int length )
	{
	void *bufPtr = buffer;
	int flags = HTTP_FLAG_NONE, contentLength, readLength, status;

	/* Read the HTTP packet header and adjust the read buffer size if
	   necessary.  This adjustment only occurs on the client side, which 
	   needs to be able to handle arbitrary-length responses from the 
	   server */
	if( stream->flags & STREAM_NFLAG_ISSERVER )
		status = readRequestHeader( stream, &contentLength, buffer, length,
									&flags );
	else
		status = readResponseHeader( stream, &contentLength, buffer, length,
									 ( stream->callbackFunction != NULL ) ? \
									 TRUE : FALSE, &flags );
	if( cryptStatusError( status ) )
		return( status );
	if( contentLength > length )
		{
		if( stream->callbackFunction != NULL )
			{
			/* There's a buffer-adjust callback present, try and increase the
			   buffer size */
			assert( stream->callbackParams != NULL );
			status = stream->callbackFunction( stream->callbackParams,
											   &bufPtr, contentLength );
			if( cryptStatusError( status ) )
				return( status );
			assert( isWritePtr( bufPtr, contentLength ) );
			}
		else
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* If it's an idempotent read, all the information was contained in the 
	   header and we're done */
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		return( contentLength );

	/* Read the payload data from the client/server */
	readLength = status = \
		stream->bufferedTransportReadFunction( stream, bufPtr, contentLength,
											   TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	if( readLength < contentLength )
		/* We timed out before reading all the data.  Usually this will be
		   reported as a CRYPT_ERROR_TIMEOUT by the lower-level read
		   routines, however due to the multiple layers of I/O and special
		   case timeout handling when (for example) a cryptlib transport
		   session is layered over the network I/O layer, we perform an
		   explicit check here to make sure that we got everything */
		retExtStream( stream, CRYPT_ERROR_TIMEOUT,
					  "HTTP read timed out before all data could be read" );

	/* If it's an error message, return it to the caller */
	if( flags & HTTP_FLAG_ERRORMSG )
		{
		( ( char * ) buffer )[ min( readLength, MAX_ERRMSG_SIZE - 32 ) ] = '\0';
		retExtStream( stream, CRYPT_ERROR_READ,
					  "HTTP server reported: '%s'", buffer );
		}

	/* If we're reading chunked data, drain the input by processing the
	   trailer.  The reason why there can be extra header lines at the end 
	   of the chunked data is because it's designed to be an indefinite-
	   length streamable format that doesn't require buffering the entire 
	   message before emitting it.  Since some header information may not be
	   available until the entire message has been generated, the HTTP spec.
	   makes provisions for adding further header lines as a trailer.  In
	   theory we should check for the HTTP_FLAG_TRAILER flag before reading
	   trailer lines rather than just swallowing the last CRLF, however the
	   "Trailer:" header wasn't added until RFC 2616 (RFC 2068 didn't have
	   it) so we can't rely on its presence:

			CRLF
			"0" CRLF
			trailer-lines*
			CRLF

	   Normally we wouldn't have to worry about trailer data, but if it's an 
	   HTTP 1.1 persistent connection we need to clear the way for the next 
	   lot of data */
	if( flags & HTTP_FLAG_CHUNKED )
		{
		char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
		int noopFlags = HTTP_FLAG_NOOP;

		status = readLine( stream, headerBuffer, HTTP_LINEBUF_SIZE );
		if( !cryptStatusError( status ) )
			status = readLine( stream, headerBuffer, HTTP_LINEBUF_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		status = getChunkLength( headerBuffer, status );
		if( status != 0 )
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Unexpected additional data in HTTP chunked data" );
		status = readHeaderLines( stream, headerBuffer, NULL, NULL, 
								  &noopFlags, 0, HTTP_LINEBUF_SIZE, FALSE );
		}

	return( cryptStatusError( status ) ? status : readLength );
	}

/* Write data to an HTTP stream */

static int writeFunction( STREAM *stream, const void *buffer,
						  const int length )
	{
	int localLength = length, status;

	/* Send the out-of-band HTTP header data to the client or server */
	if( stream->flags & STREAM_NFLAG_ISSERVER )
		{
		/* If it's an idempotent get, decode the returned data */
		if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
			{
			const BYTE *bufPtr = buffer;

			status = ( short int ) mgetWord( bufPtr );
			if( cryptStatusError( status ) )
				{
				char headerBuffer[ HTTP_LINEBUF_SIZE ];

				/* It's an error status response, send the translated
				   error status and exit.  We have to map the send return
				   value to a written byte count to avoid triggering the
				   incomplete-write check at the higher level */
				status = sendHTTPError( stream, headerBuffer, 
							( status == CRYPT_ERROR_NOTFOUND ) ? 404 : \
							( status == CRYPT_ERROR_PERMISSION ) ? 401 : \
																400 );
				return( cryptStatusError( status ) ? status : length );
				}
			buffer = bufPtr;
			localLength -= 2;
			}

		status = writeResponseHeader( stream, localLength );
		}
	else
		{
		assert( strlen( stream->contentType ) );
		assert( stream->host != NULL );

		status = writeRequestHeader( stream, localLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the payload data to the client/server.  Since we may have 
	   modified the length of the data being written we have to be careful 
	   to return the correct amount to avoid triggering incomplete-write 
	   checks */
	status = stream->bufferedTransportWriteFunction( stream, buffer, localLength,
													 TRANSPORT_FLAG_FLUSH );
	return( ( status == localLength ) ? length : status );
	}

int setStreamLayerHTTP( STREAM *stream )
	{
	/* Set the access method pointers */
	stream->writeFunction = writeFunction;
	stream->readFunction = readFunction;

	/* HTTP provides its own data-size and flow-control indicators so we 
	   don't want the higher-level code to try and do this for us */
	stream->flags |= STREAM_NFLAG_ENCAPS;

	return( CRYPT_OK );
	}
#endif /* USE_HTTP */
