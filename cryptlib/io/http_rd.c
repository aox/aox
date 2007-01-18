/****************************************************************************
*																			*
*						  cryptlib HTTP Read Routines						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "http.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "io/http.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* The various HTTP header types that we can process */

typedef enum { HTTP_HEADER_NONE, HTTP_HEADER_HOST, HTTP_HEADER_CONTENT_LENGTH,
			   HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_TRANSFER_ENCODING,
			   HTTP_HEADER_CONTENT_ENCODING,
			   HTTP_HEADER_CONTENT_TRANSFER_ENCODING, HTTP_HEADER_TRAILER,
			   HTTP_HEADER_CONNECTION, HTTP_HEADER_WARNING,
			   HTTP_HEADER_EXPECT, HTTP_HEADER_LAST
			 } HTTP_HEADER_TYPE;

/* HTTP header parsing information.  Note that the first letter of the
   header string must be uppercase for the case-insensitive quick match */

typedef struct {
	const char FAR_BSS *headerString;/* Header string */
	const int headerStringLen;		/* Length of header string */
	const HTTP_HEADER_TYPE headerType;	/* Type corresponding to header string */
	} HTTP_HEADER_PARSE_INFO;

static const HTTP_HEADER_PARSE_INFO FAR_BSS httpHeaderParseInfo[] = {
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
	const char FAR_BSS *httpStatusString;	/* String status value */
	const char FAR_BSS *httpErrorString;	/* Text description of status */
	const int status;				/* Equivalent cryptlib status */
	} HTTP_STATUS_INFO;

static const HTTP_STATUS_INFO FAR_BSS httpStatusInfo[] = {
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
	{ 426, "426", "Upgrade Required", CRYPT_ERROR_READ },
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
	{ 0, NULL, "Unrecognised HTTP status condition", CRYPT_ERROR_READ },
		{ 0, NULL, "Unrecognised HTTP status condition", CRYPT_ERROR_READ }
	};

/* HTTP header parsing information as used by readHeaderLines() */

typedef struct {
	/* Returned status information: The body content-length, the HTTP error
	   status (if there is one), and general flags information.  The flags
	   parameter is used as both an input and an output parameter */
	int contentLength;	/* HTTP body content length */
	int httpStatus;		/* HTTP error status, if an HTTP error occurs */
	int flags;			/* General flags */

	/* Range-checking information: The minimum and maximum allowable
	   content-length value */
	int minContentLength, maxContentLength;
	} HTTP_HEADER_INFO;

#define initHeaderInfo( headerInfo, minLength, maxLength, hdrFlags ) \
		memset( headerInfo, 0, sizeof( HTTP_HEADER_INFO ) ); \
		( headerInfo )->flags = ( hdrFlags ); \
		( headerInfo )->minContentLength = ( minLength ); \
		( headerInfo )->maxContentLength = ( maxLength );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used by readTextLine() to read characters from a
   stream.  When reading text data over a network we don't know how much
   more data is to come so we have to read a byte at a time looking for an
   EOL.  In addition we can't use the simple optimisation of reading two
   bytes at a time because some servers only send a LF even though the spec
   requires a CRLF.  This is horribly inefficient but is pretty much
   eliminated through the use of opportunistic read-ahead buffering */

static int readCharFunction( void *streamPtr )
	{
	STREAM *stream = streamPtr;
	BYTE ch;
	int status;

	status = stream->bufferedTransportReadFunction( stream, &ch, 1,
													TRANSPORT_FLAG_NONE );
	return( cryptStatusError( status ) ? status : ch );
	}

/* Skip whitespace in a line of text.  We only need to check for spaces as
   whitespace since it's been canonicalised when it was read */

static int skipWhitespace( const char *data, const int dataLength )
	{
	int i;

	assert( isReadPtr( data, dataLength ) );

	for( i = 0; i < dataLength && data[ i ] == ' '; i++ );
	return( ( i < dataLength ) ? i : CRYPT_ERROR );
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

/* Decode a string as per RFC 1866 (although the list of characters that
   need to be escaped is itself given in RFC 2396).  Characters that are
   permitted/not permitted are:

	 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	x..x.xx....x...xxxxxxxxxxxx.xxxxx

   Because of this it's easier to check for the most likely permitted
   characters (alphanumerics), and then to check for any special-case
   chars */

static int decodeRFC1866( char *buffer, const int bufSize )
	{
	int srcIndex = 0, destIndex = 0;

	assert( isWritePtr( buffer, bufSize ) );

	while( srcIndex < bufSize )
		{
		int chLo, chHi, ch;

		/* If it's not an escape, just copy it straight over.  The input
		   has already been sanitised when it was read so there's no need
		   to perform another check here */
		if( buffer[ srcIndex ] != '%' )
			{
			buffer[ destIndex++ ] = buffer[ srcIndex++ ];
			continue;
			}
		srcIndex++;	/* Skip '%' */

		/* Decode the escaped character */
		if( bufSize - srcIndex < 2 )
			return( CRYPT_ERROR_BADDATA );
		chHi = getNibble( buffer[ srcIndex++ ] );
		chLo = getNibble( buffer[ srcIndex++ ] );
		if( cryptStatusError( chHi ) || cryptStatusError( chLo ) )
			return( CRYPT_ERROR_BADDATA );
		ch = ( chHi << 4 ) | chLo;
		if( !isPrint( ch ) )
			/* It's a special-case/control character of some kind, report
			   it as an error.  This gets rid of things like nulls (treated
			   as string terminators by some functions) and CR/LF line
			   terminators, which can be embedded into strings to turn a
			   single line of supplied text into multi-line responses
			   containing user-controlled type : value pairs (in other
			   words they allow user data to be injected into the control
			   channel) */
			return( CRYPT_ERROR_BADDATA );
		buffer[ destIndex++ ] = ch;
		}

	/* If we've processed an escape sequence (causing the data to change
	   size), tell the caller the new length, otherwise tell them that
	   nothing's changed */
	return( ( destIndex < srcIndex ) ? destIndex : OK_SPECIAL );
	}

/* Convert a hex ASCII string used with chunked encoding into a numeric
   value */

static int getChunkLength( const char *data, const int dataLength )
	{
	int i, chunkLength = 0, length = dataLength;

	assert( isReadPtr( data, dataLength ) );

	/* Chunk size information can have extensions tacked onto it following a
	   ';', strip these before we start */
	for( i = 0; i < length; i++ )
		{
		if( data[ i ] == ';' )
			{
			/* Move back to the end of the string that precedes the ';' */
			while( i > 0 && data[ i - 1 ] == ' ' )
				i--;
			length = i;	/* Adjust length and force loop exit */
			}
		}

	/* The other side shouldn't be sending us more than 64K of data, given
	   that what we're expecting is a short PKI message */
	if( length < 1 || length > 4 )
		return( CRYPT_ERROR_BADDATA );

	/* Walk down the string converting hex characters into their numeric
	   values */
	for( i = 0; i < length; i++ )
		{
		const int ch = getNibble( data[ i ] );

		if( cryptStatusError( ch ) )
			return( CRYPT_ERROR_BADDATA );
		chunkLength = ( chunkLength << 4 ) | ch;
		}
	if( chunkLength < 0 || chunkLength > MAX_INTLENGTH )
		return( CRYPT_ERROR_BADDATA );

	return( chunkLength );
	}

/* Convert a decimal ASCII string into a numeric value */

static int getNumericValue( const char *data, const int dataLength )
	{
	char numericBuffer[ 8 + 8 ];
	const int numericBufLen = min( dataLength, 7 );
	int value;

	assert( isReadPtr( data, dataLength ) );

	if( numericBufLen < 1 )
		return( CRYPT_ERROR_BADDATA );
	memcpy( numericBuffer, data, numericBufLen );
	numericBuffer[ numericBufLen ] = '\0';
	value = aToI( numericBuffer );
	return( ( value <= 0 || value > MAX_INTLENGTH ) ? \
			CRYPT_ERROR_BADDATA : value );
	}

/* Send an HTTP error message.  This function is somewhat unusually placed
   with the read functions because it's used by both read and write code but
   needs access to the HTTP status decoding table, which is part of the
   read code */

int sendHTTPError( STREAM *stream, char *headerBuffer,
				   const int headerBufMaxLen, const int httpStatus )
	{
	STREAM headerStream;
	const char *statusString = "400";
	const char *errorString = "Bad Request";
	int length, i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( headerBuffer, headerBufMaxLen ) );
	assert( headerBufMaxLen >= 256 );

	/* Find the HTTP error string that corresponds to the HTTP status
	   value */
	for( i = 0; httpStatusInfo[ i ].httpStatus > 0 && \
				httpStatusInfo[ i ].httpStatus != httpStatus && \
				i < FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ); 
		 i++ );
	if( i >= FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ) )
		retIntError();
	if( httpStatusInfo[ i ].httpStatus )
		{
		statusString = httpStatusInfo[ i ].httpStatusString;
		errorString = httpStatusInfo[ i ].httpErrorString;
		}

	/* Send the error message to the peer */
	sMemOpen( &headerStream, headerBuffer, headerBufMaxLen );
	swrite( &headerStream, isHTTP10( stream ) ? "HTTP/1.0 " : \
												"HTTP/1.1 ", 9 );
	swrite( &headerStream, statusString, strlen( statusString ) );
	sputc( &headerStream, ' ' );
	swrite( &headerStream, errorString, strlen( errorString ) );
	swrite( &headerStream, "\r\n\r\n", 4 );
	assert( sStatusOK( &headerStream ) );
	length = stell( &headerStream );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, length,
						  TRANSPORT_FLAG_FLUSH ) );
	}

/****************************************************************************
*																			*
*							URI Parsing Functions							*
*																			*
****************************************************************************/

/* Information needed to parse a URI sub-segment: The character that ends a
   segment and an optional alternative segment-end character, and the
   minimum and maximum permitted segment size */

typedef struct {
	const char segmentEndChar, altSegmentEndChar;
	const int segmentMinLength, segmentMaxLength;
	} URI_PARSE_INFO;

/* Get the length of a sub-segment of a URI */

static int getUriSegmentLength( const char *data, const int dataLength,
								const URI_PARSE_INFO *uriParseInfo,
								BOOLEAN *altDelimiterFound )
	{
	const int maxLength = min( dataLength, uriParseInfo->segmentMaxLength );
	int i;

	assert( isReadPtr( data, dataLength ) );
	assert( isReadPtr( uriParseInfo, sizeof( URI_PARSE_INFO  ) ) );
	assert( uriParseInfo->segmentMinLength >= 0 && \
			uriParseInfo->segmentMinLength < \
					uriParseInfo->segmentMaxLength && \
			uriParseInfo->segmentMaxLength <= 1024 );
	assert( ( uriParseInfo->altSegmentEndChar == '\0' && \
			  altDelimiterFound == NULL ) || \
			( uriParseInfo->altSegmentEndChar > '\0' && \
			  isWritePtr( altDelimiterFound, sizeof( BOOLEAN ) ) ) );

	/* Clear return value */
	if( altDelimiterFound != NULL )
		*altDelimiterFound = FALSE;

	/* Parse the current query sub-segment */
	for( i = 0; i < maxLength; i++ )
		{
		if( data[ i ] == uriParseInfo->segmentEndChar )
			break;
		if( uriParseInfo->altSegmentEndChar > '\0' && \
			data[ i ] == uriParseInfo->altSegmentEndChar )
			{
			*altDelimiterFound = TRUE;
			break;
			}
		}

	/* Make sure that we both got enough data and that we didn't run out of
	   data */
	if( i < uriParseInfo->segmentMinLength || i >= maxLength )
		return( CRYPT_ERROR_BADDATA );

	return( i );
	}

/* Parse a URI of the form "* '?' attribute '=' value [ '&' ... ] ",
   returning the parsed form to the caller.  This function needs to return
   two length values since it decodes the URI string according to RFC 1866,
   which means that its length can change.  So as its standard return value
   it returns the number of chars consumed, but it also returns the new
   length of the input as a by-reference parameter */

static int parseUriInfo( char *data, const int dataInLength,
						 int *dataOutLength, HTTP_URI_INFO *uriInfo )
	{
	static const URI_PARSE_INFO locationParseInfo = \
			{ '?', '\0', 1, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO attributeParseInfo = \
			{ '=', '\0', 3, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO valueParseInfo = \
			{ ' ', '&', 3, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO extraParseInfo = \
			{ ' ', '\0', 1, CRYPT_MAX_TEXTSIZE };
	BOOLEAN altDelimiterFound;
	const char *bufPtr = data;
	int length = dataInLength, segmentLength, parsedLength, i, status;

	assert( isWritePtr( data, dataInLength ) );
	assert( isWritePtr( dataOutLength, sizeof( int ) ) );
	assert( isWritePtr( uriInfo, sizeof( HTTP_URI_INFO ) ) );

	/* Clear return values */
	memset( uriInfo, 0, sizeof( HTTP_URI_INFO ) );
	*dataOutLength = 0;

	/* Decode the URI text.  Since there can be multiple nested levels of
	   encoding, we keep iteratively decoding in-place until either 
	   decodeRFC1866() cries Uncle or we hit the sanity-check limit */
	for( i = 0; i < FAILSAFE_ITERATIONS_SMALL; i++ )
		{
		status = decodeRFC1866( data, length );
		if( cryptStatusError( status ) )
			{
			if( status == OK_SPECIAL )
				/* There's been no further change in the data, exit */
				break;
			return( CRYPT_ERROR_BADDATA );
			}
		length = status;	/* Record the new length of the decoded data */
		}
	if( i >= FAILSAFE_ITERATIONS_SMALL )
		{
		/* Sanity-check limit exceeded.  This could be either data error
		   or an internal error, since we can't automatically tell which 
		   we report it as a data error */
		return( CRYPT_ERROR_BADDATA );
		}
	*dataOutLength = length;

	/* We need to get at least 'x?xxx=xxx' */
	if( length < 9 )
		return( CRYPT_ERROR_BADDATA );

	/* Parse a URI of the form "* '?' attribute '=' value [ '&' ... ] ".
	   The URI is followed by the HTTP ID, so we know that it always has to
	   end on a space; running out of input is an error */
	segmentLength = getUriSegmentLength( bufPtr, length,
										 &locationParseInfo, NULL );
	if( cryptStatusError( segmentLength ) )
		return( segmentLength );
	memcpy( uriInfo->location, bufPtr, segmentLength );
	uriInfo->locationLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength = segmentLength + 1;
	segmentLength = getUriSegmentLength( bufPtr, length,
										 &attributeParseInfo, NULL );
	if( cryptStatusError( segmentLength  ) )
		return( segmentLength  );
	memcpy( uriInfo->attribute, bufPtr, segmentLength );
	uriInfo->attributeLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength += segmentLength + 1;
	segmentLength = getUriSegmentLength( bufPtr, length, &valueParseInfo,
										 &altDelimiterFound );
	if( cryptStatusError( segmentLength ) )
		return( segmentLength );
	memcpy( uriInfo->value, bufPtr, segmentLength );
	uriInfo->valueLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength += segmentLength + 1;
	if( altDelimiterFound )
		{
		segmentLength = getUriSegmentLength( bufPtr, length,
											 &extraParseInfo, NULL );
		if( cryptStatusError( segmentLength  ) )
			return( segmentLength  );
		parsedLength += segmentLength + 1;
		}

	return( parsedLength );
	}

/* Check an "HTTP 1.x" ID string.  No PKI client should be sending us an 0.9
   ID, so we only allow 1.x */

static int checkHTTPID( const char *data, const int dataLength,
						STREAM *stream )
	{
	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	if( dataLength < 8 || strCompare( data, "HTTP/1.", 7 ) )
		return( CRYPT_ERROR_BADDATA );
	if( data[ 7 ] == '0' )
		stream->flags |= STREAM_NFLAG_HTTP10;
	else
		if( data[ 7 ] != '1' )
			return( CRYPT_ERROR_BADDATA );

	return( 8 );
	}

/****************************************************************************
*																			*
*							HTTP Header Processing							*
*																			*
****************************************************************************/

/* Read an HTTP status code.  Some status values are warnings only and
   don't return an error status */

static int readHTTPStatus( const char *data, const int dataLength,
						   int *httpStatus, void *errorStream )
	{
	const HTTP_STATUS_INFO *httpStatusPtr;
	char thirdChar;
	int i;

	assert( isReadPtr( data, dataLength ) );
	assert( httpStatus == NULL || \
			isWritePtr( httpStatus, sizeof( int ) ) );
	assert( isWritePtr( errorStream, sizeof( STREAM ) ) );

	/* Clear return value */
	if( httpStatus != NULL )
		*httpStatus = CRYPT_OK;

	/* Process the numeric HTTP status code and translate it into a cryptlib
	   equivalent.  Most of the HTTP codes don't have any meaning in a
	   cryptlib context, so they're mapped to a generic CRYPT_ERROR_READ by
	   the HTTP status decoding table */
	if( dataLength < 3 || !isDigit( *data ) )
		retExtStream( errorStream, CRYPT_ERROR_BADDATA,
					  "Invalid/missing HTTP status code" );
	thirdChar = data[ 2 ];
	for( i = 0; httpStatusInfo[ i ].httpStatus != 0 && \
				i < FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ); 
		 i++ )
		{
		/* We check the third digit (the one most likely to be different)
		   for a mismatch to avoid a large number of calls to the string-
		   compare function */
		if( httpStatusInfo[ i ].httpStatusString[ 2 ] == thirdChar && \
			!strCompare( data, httpStatusInfo[ i ].httpStatusString, 3 ) )
			break;
		}
	if( i >= FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ) )
		retIntError();
	httpStatusPtr = &httpStatusInfo[ i ];
	if( httpStatus != NULL )
		{
		const int value = getNumericValue( data, dataLength );
		if( cryptStatusError( value ) )
			retExtStream( errorStream, CRYPT_ERROR_BADDATA,
						  "Invalid/missing HTTP status code" );
		*httpStatus = value;
		}
	if( httpStatusPtr->status == OK_SPECIAL )
		/* It's a special-case condition such as a redirect, tell the caller
		   to handle it specially */
		return( OK_SPECIAL );
	if( httpStatusPtr->status != CRYPT_OK )
		{
		/* It's an error condition, return extended error info */
		assert( httpStatusPtr->httpStatusString != NULL );
							/* Catch oddball errors in debug version */
		retExtStream( errorStream, httpStatusPtr->status,
					  "HTTP status: %s", httpStatusPtr->httpErrorString );
		}
	return( CRYPT_OK );
	}

/* Process an HTTP header line looking for anything that we can handle */

static int processHeaderLine( const char *data, const int dataLength,
							  HTTP_HEADER_TYPE *headerType,
							  void *errorStream, const int errorLineNo )
	{
	const HTTP_HEADER_PARSE_INFO *headerParseInfoPtr = NULL;
	const char firstChar = toUpper( *data );
	int processedLength, dataLeft, i;

	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( headerType, sizeof( HTTP_HEADER_TYPE ) ) );
	assert( isWritePtr( errorStream, sizeof( STREAM ) ) );
	assert( errorLineNo > 0 && errorLineNo < 1000 );

	/* Clear return value */
	*headerType = HTTP_HEADER_NONE;

	/* Look for a header line that we recognise */
	for( i = 0; 
		 httpHeaderParseInfo[ i ].headerString != NULL && \
			i < FAILSAFE_ARRAYSIZE( httpHeaderParseInfo, HTTP_HEADER_PARSE_INFO ); 
		 i++ )
		{
		if( httpHeaderParseInfo[ i ].headerString[ 0 ] == firstChar && \
			dataLength >= httpHeaderParseInfo[ i ].headerStringLen && \
			!strCompare( data, httpHeaderParseInfo[ i ].headerString, \
						 httpHeaderParseInfo[ i ].headerStringLen ) )
			{
			headerParseInfoPtr = &httpHeaderParseInfo[ i ];
			break;
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( httpHeaderParseInfo, HTTP_HEADER_PARSE_INFO ) )
		retIntError();
	if( headerParseInfoPtr == NULL )
		/* It's nothing that we can handle, exit */
		return( 0 );
	processedLength = headerParseInfoPtr->headerStringLen;

	/* Make sure that there's an attribute value present */
	dataLeft = dataLength - processedLength;
	if( dataLeft > 0 )
		{
		const int extraLength = \
			skipWhitespace( data + processedLength, dataLeft );
		if( extraLength > 0 )
			{
			/* We skipped some whitespace before the attribute value, adjust
			   the consumed/remaining byte counts */
			dataLeft -= extraLength;
			processedLength += extraLength;
			}
		else
			/* If there was a problem, make sure that we fail the following
			   check */
			if( extraLength < 0 )
				dataLeft = CRYPT_ERROR;
		}
	if( dataLeft < 1 )
		retExtStream( errorStream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP header value for '%s' token, line %d",
					  headerParseInfoPtr->headerString, errorLineNo );

	/* Tell the caller what we found */
	*headerType = headerParseInfoPtr->headerType;
	return( processedLength );
	}

/* Read the first line in an HTTP response header */

int readFirstHeaderLine( STREAM *stream, char *dataBuffer,
						 const int dataMaxLength, int *httpStatus )
	{
	BOOLEAN textDataError;
	int length, processedLength, dataLeft;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dataBuffer, dataMaxLength ) );
	assert( isWritePtr( httpStatus, sizeof( int ) ) );

	/* Clear return value */
	*httpStatus = CRYPT_OK;

	/* Read the header and check for an HTTP ID */
	length = readTextLine( readCharFunction, stream, dataBuffer,
						   dataMaxLength, &textDataError );
	if( cryptStatusError( length ) )
		{
		if( !textDataError )
			/* The extended error information has already been set by the
			   readCharFunction() */
			return( length );
		retExtStream( stream, length, "Invalid HTTP header line 1" );
		}
	processedLength = checkHTTPID( dataBuffer, length, stream );
	if( cryptStatusError( processedLength ) )
		retExtStream( stream, cryptStatusError( processedLength ) ? \
							  processedLength : CRYPT_ERROR_BADDATA, \
					  "Invalid HTTP ID/version" );
	dataLeft = length - processedLength;

	/* Skip the whitespace between the HTTP ID and status info */
	if( dataLeft > 0 )
		{
		const int extraLength = \
				skipWhitespace( dataBuffer + processedLength, dataLeft );
		if( extraLength > 0 )
			{
			/* We skipped some whitespace before the HTTP status info,
			   adjust the consumed/remaining byte counts */
			dataLeft -= extraLength;
			processedLength += extraLength;
			}
		else
			/* If there was a problem, make sure that we fail the following
			   check */
			if( extraLength < 0 )
				dataLeft = CRYPT_ERROR;
		}
	if( dataLeft < 1 )
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP status code, line 1" );

	/* Read the HTTP status info */
	return( readHTTPStatus( dataBuffer + processedLength, dataLeft,
							httpStatus, stream ) );
	}

/* Read the remaining HTTP header lines after the first one */

int readHeaderLines( STREAM *stream, char *lineBuffer,
					 const int lineBufMaxLen,
					 HTTP_HEADER_INFO *headerInfo )
	{
	BOOLEAN seenHost = FALSE, seenLength = FALSE;
	int contentLength = 0, lineCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( lineBuffer, lineBufMaxLen ) );
	assert( isWritePtr( headerInfo, sizeof( HTTP_HEADER_INFO ) ) );

	/* Read each line in the header checking for any fields that we need to
	   handle.  We check for a couple of basic problems with the header to
	   avoid malformed-header attacks, for example an attacker could send a
	   request with two 'Content-Length:' headers, one of which covers the
	   entire message body and the other which indicates that there's a
	   second request that begins halfway through the message body.  Some
	   proxies/caches will take the first length, some the second, if the
	   proxy is expected to check/rewrite the request as it passes through
	   then the single/dual-message issue can be used to bypass the checking
	   on the tunnelled second message.  Because of this we only allow a
	   single Host: and Content-Length: header, and disallow a chunked
	   encoding in combination with a content-length (Apache does some
	   really strange things with chunked encodings).  We can't be too
	   finicky with the checking though or we'll end up rejecting non-
	   malicious requests from some of the broken HTTP implementations out
	   there */
	for( lineCount = 0; lineCount < FAILSAFE_ITERATIONS_MED; lineCount++ )
		{
		HTTP_HEADER_TYPE headerType;
		BOOLEAN textDataError;
		char *lineBufPtr;
		int lineLength;

		lineLength = readTextLine( readCharFunction, stream, lineBuffer,
								   lineBufMaxLen, &textDataError );
		if( cryptStatusError( lineLength ) )
			{
			if( !textDataError )
				/* The extended error information has already been set by the
				   readCharFunction() */
				return( lineLength );
			retExtStream( stream, lineLength, "Invalid HTTP header line %d",
						  lineCount + 2 );
			}
		if( lineLength <= 0 )
			/* End of input, exit */
			break;
		status = processHeaderLine( lineBuffer, lineLength, &headerType,
									stream, lineCount + 2 );
		if( cryptStatusError( status ) )
			return( status );
		lineBufPtr = lineBuffer + status;
		lineLength -= status;
		assert( lineLength > 0 );	/* Guaranteed by processHeaderLine() */
		switch( headerType )
			{
			case HTTP_HEADER_HOST:
				/* Make sure that it's a non-duplicate, and remember that
				   we've seen a Host: line, to meet the HTTP 1.1
				   requirements */
				if( seenHost )
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Duplicate HTTP 'Host:' header, line %d",
								  lineCount + 2 );
				seenHost = TRUE;
				break;

			case HTTP_HEADER_CONTENT_LENGTH:
				/* Make sure that it's a non-duplicate and get the content
				   length.  At this point all that we do is perform a
				   general sanity check that the length looks OK, a specific
				   check against the caller-supplied minimum/maximum
				   allowable length is performed later since the content
				   length may also be provided as a chunked encoding length,
				   which we can't check until we've processed all of the
				   header lines */
				if( seenLength )
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Duplicate HTTP 'Content-Length:' header, "
								  "line %d", lineCount + 2 );
				contentLength = getNumericValue( lineBufPtr, lineLength );
				if( cryptStatusError( contentLength ) )
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content length, line %d",
								  lineCount + 2 );
				seenLength = TRUE;
				break;

			case HTTP_HEADER_CONTENT_TYPE:
				/* Sometimes if there's an error it'll be returned as content
				   at the HTTP level rather than at the tunnelled-over-HTTP
				   protocol level.  The easiest way to check for this would
				   be to make sure that the content-type matches the
				   expected type and report anything else as an error.
				   Unfortunately due to the hit-and-miss handling of content-
				   types by PKI software using HTTP as a substrate it's not
				   safe to do this, so we have to default to allow-all
				   rather than deny-all, treating only straight text as a
				   problem type.

				   Unfortunately there are also apps out there that send
				   their PKI messages marked as plain text, so this isn't
				   100% foolproof.  This is particularly problematic for
				   web browsers, where so many servers were misconfigured
				   to return pretty much anything as text/plain that
				   Microsoft added content-type guessing code to MSIE to
				   make web pages served from misconfigured servers work
				   (you can see this by serving a JPEG file as text/plain,
				   MSIE will display it as a JPEG while Mozilla/Firefox/
				   Opera/etc will display it as text or prompt for a helper
				   app to handle it).  Since this content-type guessing is
				   a potential security hole, MS finally made it
				   configurable in Windows XP SP2, but it's still enabled
				   by default even there.

				   In practice however errors-via-HTTP is more common than
				   certs-via-text.  We try and detect the cert-as-plain-text
				   special-case at a later point when we've got the message
				   body available */
				if( lineLength >= 5 && \
					!strCompare( lineBufPtr, "text/", 5 ) )
					headerInfo->flags |= HTTP_FLAG_TEXTMSG;
				break;

			case HTTP_HEADER_TRANSFER_ENCODING:
				if( lineLength < 7 || \
					strCompare( lineBufPtr, "Chunked", 7 ) )
					{
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP transfer encoding method "
								  "'%s', expected 'Chunked', line %d",
								  sanitiseString( lineBufPtr, \
												  min( lineLength, \
													   CRYPT_MAX_TEXTSIZE ) ),
								  lineCount + 2 );
					}

				/* If it's a chunked encoding, the length is part of the
				   data and must be read later */
				if( seenLength )
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Duplicate HTTP 'Content-Length:' header, "
								  "line %d", lineCount + 2 );
				headerInfo->flags |= HTTP_FLAG_CHUNKED;
				seenLength = TRUE;
				break;

			case HTTP_HEADER_CONTENT_ENCODING:
				/* We can't handle any type of content encoding (e.g. gzip,
				   compress, deflate, mpeg4, interpretive dance) except the
				   no-op identity encoding */
				if( lineLength < 8 || \
					strCompare( lineBufPtr, "Identity", 8 ) )
					{
					headerInfo->httpStatus = 415;	/* Unsupp.media type */
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content encoding method "
								  "'%s', expected 'Identity', line %d",
								  sanitiseString( lineBufPtr, \
												  min( lineLength, \
													   CRYPT_MAX_TEXTSIZE ) ),
								  lineCount + 2 );
					}
				break;

			case HTTP_HEADER_CONTENT_TRANSFER_ENCODING:
				/* HTTP uses Transfer-Encoding, not the MIME Content-
				   Transfer-Encoding types such as base64 or quoted-
				   printable.  If any implementations erroneously use a
				   C-T-E, we make sure that it's something that we can
				   handle */
				if( lineLength < 6 || \
					( strCompare( lineBufPtr, "Identity", 8 ) && \
					  strCompare( lineBufPtr, "Binary", 6 ) ) )
					{
					headerInfo->httpStatus = 415;	/* Unsupp.media type */
					retExtStream( stream, CRYPT_ERROR_BADDATA,
								  "Invalid HTTP content transfer encoding "
								  "method '%s', expected 'Identity' or "
								  "'Binary', line %d",
								  sanitiseString( lineBufPtr, \
												  min( lineLength, \
													   CRYPT_MAX_TEXTSIZE ) ),
								  lineCount + 2 );
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
				headerInfo->flags |= HTTP_FLAG_TRAILER;
				break;

			case HTTP_HEADER_CONNECTION:
				/* If the other side has indicated that it's going to close
				   the connection, remember that the stream is now no longer
				   usable */
				if( lineLength >= 5 && \
					!strCompare( lineBufPtr, "Close", 5 ) )
					sioctl( stream, STREAM_IOCTL_CONNSTATE, NULL, FALSE );
				break;

			case HTTP_HEADER_WARNING:
				/* Read the HTTP status info from the warning, discarding any
				   error status since this isn't an error */
				readHTTPStatus( lineBufPtr, lineLength, NULL, stream );
				break;

			case HTTP_HEADER_EXPECT:
				/* If the other side wants the go-ahead to continue, give it
				   to them.  We do this automatically because we're merely
				   using HTTP as a substrate, the real decision will be made
				   at the higher-level protocol layer */
				if( lineLength >= 12 && \
					!strCompare( lineBufPtr, "100-Continue", 12 ) )
					sendHTTPError( stream, lineBufPtr, lineBufMaxLen, 100 );
				break;

			case HTTP_HEADER_NONE:
				/* It's something that we don't know/care about, skip it */
				break;

			default:
				assert( NOTREACHED );
			}
		}
	if( lineCount >= FAILSAFE_ITERATIONS_MED )
		retExtStream( stream, CRYPT_ERROR_OVERFLOW,
					  "Too many HTTP header lines" );

	/* If this is an tunnel being opened via an HTTP proxy, we're done */
	if( !( stream->flags & STREAM_NFLAG_ISSERVER ) && \
		( stream->flags & STREAM_NFLAG_HTTPTUNNEL ) )
		return( CRYPT_OK );

	/* If it's a chunked encoding for which the length is kludged on before
	   the data as a hex string, decode the length value */
	if( headerInfo->flags & HTTP_FLAG_CHUNKED )
		{
		BOOLEAN textDataError;

		const int lineLength = readTextLine( readCharFunction, stream,
											 lineBuffer, lineBufMaxLen,
											 &textDataError );
		if( cryptStatusError( lineLength ) )
			{
			if( !textDataError )
				/* The extended error information has already been set by the
				   readCharFunction() */
				return( lineLength );
			retExtStream( stream, lineLength,
						  "Invalid HTTP chunked encoding header, line %d",
						  lineCount + 2 );
			}
		if( lineLength <= 0 )
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Missing HTTP chunk length, line %d",
						  lineCount + 2 );
		status = contentLength = getChunkLength( lineBuffer, lineLength );
		if( cryptStatusError( status ) )
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Invalid length for HTTP chunked encoding, line %d",
						  lineCount + 2 );
		}

	/* If this is a no-op read (for example lines following an error or 100
	   Continue response), all that we're interested in is draining the
	   input, so we don't check any further */
	if( headerInfo->flags & HTTP_FLAG_NOOP )
		return( CRYPT_OK );

	/* If we're a server talking HTTP 1.1 and we haven't seen a "Host:"
	   header from the client, return an error */
	if( ( stream->flags & STREAM_NFLAG_ISSERVER ) && \
		!isHTTP10( stream ) && !seenHost )
		{
		headerInfo->httpStatus = 400;	/* Bad request */
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP 'Host:' header" );
		}

	/* If it's an idempotent read there's no length, just a GET request, so
	   we can exit now */
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		{
		if( seenLength )
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Unexpected %d bytes HTTP body content received "
						  "in idempotent read", contentLength );
		return( CRYPT_OK );
		}

	/* Make sure that we've been given a length.  In theory a server could
	   indicate the length implicitly by closing the connection once it's
	   sent the last byte, but this isn't allowed for PKI messages.  The
	   client can't use this option either since that would make it
	   impossible for us to send back the response */
	if( !seenLength )
		{
		headerInfo->httpStatus = 411;	/* Length required */
		retExtStream( stream, CRYPT_ERROR_BADDATA, "Missing HTTP length" );
		}

	/* Make sure that the length is sensible */
	if( contentLength < headerInfo->minContentLength || \
		contentLength > headerInfo->maxContentLength )
		retExtStream( stream,
					  ( contentLength < headerInfo->minContentLength ) ? \
						CRYPT_ERROR_UNDERFLOW : CRYPT_ERROR_OVERFLOW,
					  "Invalid HTTP content length %d bytes, expected "
					  "%d...%d bytes", contentLength,
					  headerInfo->minContentLength,
					  headerInfo->maxContentLength );
	headerInfo->contentLength = contentLength;

	return( CRYPT_OK );
	}

/* Read the HTTP trailer lines that follow chunked data:

			CRLF
			"0" CRLF
			trailer-lines*
			CRLF */

static int readTrailerLines( STREAM *stream, char *lineBuffer,
							 const int lineBufMaxLen )
	{
	HTTP_HEADER_INFO headerInfo;
	BOOLEAN textDataError;
	int readLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( lineBuffer, lineBufMaxLen ) );

	/* Read the blank line and chunk length */
	status = readTextLine( readCharFunction, stream, lineBuffer,
						   lineBufMaxLen, &textDataError );
	if( !cryptStatusError( status ) )
		status = readLength = readTextLine( readCharFunction, stream,
											lineBuffer, lineBufMaxLen,
											&textDataError );
	if( cryptStatusError( status ) )
		{
		if( !textDataError )
			/* The extended error information has already been set by the
			   readCharFunction() */
			return( status );
		retExtStream( stream, status,
					  "Invalid HTTP chunked trailer line" );
		}

	/* Make sure that there are no more chunks to follow */
	status = getChunkLength( lineBuffer, readLength );
	if( status != 0 )
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Unexpected additional data following HTTP "
					  "chunked data" );

	/* Read any remaining trailer lines */
	initHeaderInfo( &headerInfo, 0, 0, HTTP_FLAG_NOOP );
	return( readHeaderLines( stream, lineBuffer, lineBufMaxLen,
							 &headerInfo ) );
	}

/****************************************************************************
*																			*
*								Read Request Header							*
*																			*
****************************************************************************/

/* Read an HTTP request header */

static int readRequestHeader( STREAM *stream, char *lineBuffer,
							  const int lineBufSize, int *contentLength,
							  const int contentMaxLen, int *flags,
							  HTTP_URI_INFO *uriInfo )
	{
	HTTP_HEADER_INFO headerInfo;
	BOOLEAN textDataError;
	const BOOLEAN idempotentRead = \
			( stream->flags & STREAM_NFLAG_IDEMPOTENT ) ? TRUE : FALSE;
	const char *reqName = idempotentRead ? "GET " : "POST ";
	const int reqNameLen = idempotentRead ? 4 : 5;
	char *bufPtr;
	int length, offset, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) && \
			stream->flags & STREAM_NFLAG_ISSERVER );
	assert( isWritePtr( lineBuffer, lineBufSize ) );
	assert( isWritePtr( contentLength, sizeof( int ) ) );
	assert( isWritePtr( flags, sizeof( int ) ) );
	assert( ( idempotentRead && \
			  isWritePtr( uriInfo, sizeof( HTTP_URI_INFO ) ) ) || \
			( !idempotentRead && uriInfo == NULL ) );

	/* Clear return value */
	*contentLength = CRYPT_ERROR;

	/* Read the header and check for "POST/GET x HTTP/1.x".  In theory this
	   could be a bit risky because the original CERN server required an
	   extra (spurious) CRLF after a POST, so that various early clients sent
	   an extra CRLF that isn't included in the Content-Length header and
	   ends up preceding the start of the next load of data.  We don't check
	   for this because it only applies to very old pure-HTTP (rather than
	   HTTP-as-a-transport-layer) clients, which are unlikely to be hitting a
	   PKI responder */
	status = length = readTextLine( readCharFunction, stream, lineBuffer,
									lineBufSize, &textDataError );
	if( cryptStatusError( status ) )
		{
		/* If it's an HTTP-level error (e.g. line too long), send back an
		   HTTP-level error response */
		if( status != CRYPT_ERROR_COMPLETE )
			sendHTTPError( stream, lineBuffer, lineBufSize,
						   ( status == CRYPT_ERROR_OVERFLOW ) ? 414 : 400 );
		if( !textDataError )
			/* The extended error information has already been set by the
			   readCharFunction() */
			return( status );
		retExtStream( stream, status, "Invalid HTTP request header line" );
		}
	if( length < reqNameLen || \
		strCompare( lineBuffer, reqName, reqNameLen ) )
		{
		char reqNameBuffer[ 8 + 8 ];

		/* Return the extended error information.  Note that we don't use
		   sanitiseString() here because it's a static string that we
		   supply, however we have to copy it into a temporary buffer so
		   that we can strip the space character at the end */
		sendHTTPError( stream, lineBuffer, lineBufSize, 501 );
		memcpy( reqNameBuffer, reqName, reqNameLen );
		reqNameBuffer[ reqNameLen - 1 ] = '\0';	/* Strip trailing space */
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Invalid HTTP request type, expected '%s'",
					  sanitiseString( reqNameBuffer, reqNameLen - 1 ) );
		}
	bufPtr = lineBuffer + reqNameLen;
	length -= reqNameLen;

	/* Process the ' '* * ' '* and check for the HTTP ID */
	if( length <= 0 || ( offset = skipWhitespace( bufPtr, length ) ) < 0 )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP request URI" );
		}
	bufPtr += offset;
	length -= offset;
	if( idempotentRead )
		{
		/* If it's an indempotent read the client is sending a GET rather
		   than submitting a POST, process the request details.  This
		   performs in-place decoding of (possibly encoded) data, so it
		   returns two length values, the new length after the in-place
		   decoding has occurred, and the offset of the next character of
		   data as usual */
		offset = parseUriInfo( bufPtr, length, &length, uriInfo );
		if( cryptStatusError( offset ) )
			{
			sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
			retExtStream( stream, CRYPT_ERROR_BADDATA,
						  "Invalid HTTP GET request URI" );
			}
		bufPtr += offset;
		length -= offset;
		}
	else
		{
		/* For non-idempotent queries we don't care what the location is
		   since it's not relevant for anything, so we just skip the URI.
		   This also avoids complications with absolute vs. relative URLs,
		   character encoding/escape sequences, and so on */
		while( length > 0 && *bufPtr != ' ' )
			{
			bufPtr++;
			length--;
			}
		}
	if( length <= 0 || ( offset = skipWhitespace( bufPtr, length ) ) < 0 )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Missing HTTP request ID/version" );
		}
	bufPtr += offset;
	length -= offset;
	if( length <= 0 || \
		cryptStatusError( checkHTTPID( bufPtr, length, stream ) ) )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 505 );
		retExtStream( stream, CRYPT_ERROR_BADDATA,
					  "Invalid HTTP request ID/version" );
		}

	/* Process the remaining header lines.  ~32 bytes is the minimum-size
	   object that can be returned from any HTTP-based message which is
	   exchanged by cryptlib, this being a TSP request */
	initHeaderInfo( &headerInfo, 32, contentMaxLen, *flags );
	status = readHeaderLines( stream, lineBuffer, lineBufSize,
							  &headerInfo );
	if( cryptStatusError( status ) )
		{
		/* We always (try and) send an HTTP error response once we get to
		   this stage since chances are that it'll be a problem with an
		   HTTP header rather than a low-level network read problem */
		sendHTTPError( stream, lineBuffer, lineBufSize,
					   headerInfo.httpStatus );
		return( status );
		}

	/* If it's an idempotent read, the content is the request header and not
	   the body, since there isn't one */
	if( idempotentRead )
		headerInfo.contentLength = sizeof( HTTP_URI_INFO );

	/* Copy any status info back to the caller */
	*contentLength = headerInfo.contentLength;
	*flags = headerInfo.flags;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read Response Header						*
*																			*
****************************************************************************/

/* Read an HTTP response header */

static int readResponseHeader( STREAM *stream, char *lineBuffer,
							   const int lineBufSize, int *contentLength,
							   const int contentMaxLen, int *flags )
	{
	int repeatCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( lineBuffer, lineBufSize ) );
	assert( isWritePtr( contentLength, sizeof( int ) ) );
	assert( isWritePtr( flags, sizeof( int ) ) );

	/* Clear return value */
	*contentLength = CRYPT_ERROR;

	/* If it's a stateless HTTP read, we need to first send the initiating
	   HTTP fetch request before we can read anything back */
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
	for( repeatCount = 0; repeatCount < FAILSAFE_ITERATIONS_SMALL; \
		 repeatCount++ )
		{
		HTTP_HEADER_INFO headerInfo;
		BOOLEAN needsSpecialHandling = FALSE;
		int httpStatus;

		/* Read the response header */
		status = readFirstHeaderLine( stream, lineBuffer, lineBufSize,
									  &httpStatus );
		if( cryptStatusError( status ) )
			{
			if( status != OK_SPECIAL )
				{
				/* There's an error with the header, drain the remaining
				   input and exit.  Since we've already encountered an error
				   condition, we don't worry about any further error info
				   returned by readHeaderLines() */
				initHeaderInfo( &headerInfo, 5, contentMaxLen,
								*flags | HTTP_FLAG_NOOP );
				readHeaderLines( stream, lineBuffer, lineBufSize,
								 &headerInfo );
				return( status );
				}

			/* It's a special-case header (e.g. a 100 Continue), turn the 
			   read into a no-op read that drains the input to get to the 
			   real data */
			*flags |= HTTP_FLAG_NOOP;
			needsSpecialHandling = TRUE;
			}

		/* Process the remaining header lines.  5 bytes is the minimum-size
		   object that can be returned from any HTTP-based message which is
		   exchanged by cryptlib, this being an OCSP response containing a
		   single-byte status value, i.e. SEQUENCE { ENUM x } */
		initHeaderInfo( &headerInfo, 5, contentMaxLen, *flags );
		status = readHeaderLines( stream, lineBuffer, lineBufSize,
								  &headerInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Copy any status info back to the caller */
		*flags = headerInfo.flags & ~HTTP_FLAG_NOOP;
		*contentLength = headerInfo.contentLength;

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

		   In addition the semantics of the following pseudocode don't quite
		   match those of RFC 2616 because of the HTTP-as-a-substrate use
		   rather than direct use in a browser.  Specifically, anything
		   other than a GET for a 302 or 307 isn't supposed to perform an
		   automatic redirect without asking the user, because of concerns
		   that it'll change the semantics of the request.  However, since
		   we're not an interactive web browser there's no way that we can
		   ask a user for redirect permission, and in any case since we're
		   merely using HTTP as a substrate for a cryptographically
		   protected PKI message (and specifically assuming that the HTTP
		   layer is completely insecure), any problems will be caught by the
		   crypto protocol layer */
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
					  "Unable to process HTTP %d redirect", httpStatus );
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
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	void *bufPtr = buffer;
	int flags = HTTP_FLAG_NONE, contentLength, readLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( buffer, length ) );
	assert( !( stream->flags & STREAM_NFLAG_IDEMPOTENT ) || \
			( length == sizeof( HTTP_URI_INFO ) ) );

	/* Read the HTTP packet header */
	if( stream->flags & STREAM_NFLAG_ISSERVER )
		{
		/* If we're performing an idempotent read then the content is the
		   URI info present in the header rather than any body content,
		   so we pass in the read buffer to return the URI data */
		status = readRequestHeader( stream, headerBuffer, HTTP_LINEBUF_SIZE,
									&contentLength, length, &flags,
									( stream->flags & STREAM_NFLAG_IDEMPOTENT ) ? \
										( HTTP_URI_INFO * ) buffer : NULL );
		}
	else
		{
		/* If the buffer is dynamically allocated then we allow an
		   effectively arbitrary content length (it's not really possible to
		   provide any sensible limit on this since CRLs can reach > 100MB
		   in size), otherwise it has to fit into the fixed-size read
		   buffer */
		status = readResponseHeader( stream, headerBuffer, HTTP_LINEBUF_SIZE,
									 &contentLength,
									 ( stream->callbackFunction != NULL ) ? \
										MAX_INTLENGTH : length, &flags );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Adjust the read buffer size if necessary.  This adjustment only
	   occurs on the client side, which needs to be able to handle arbitrary-
	   length responses from the server */
	if( contentLength > length )
		{
		/* This situation can only occur if there's a buffer-adjust callback
		   present, in which case we try and increase the buffer size to
		   handle the extra data */
		assert( stream->callbackFunction != NULL && \
				stream->callbackParams != NULL );
		status = stream->callbackFunction( stream->callbackParams,
										   &bufPtr, contentLength );
		if( cryptStatusError( status ) )
			return( status );
		assert( isWritePtr( bufPtr, contentLength ) );
		}

	/* If it's an idempotent read, all of the information was contained in
	   the header and we're done */
	if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
		return( contentLength );

	/* Read the payload data from the client/server */
	readLength = status = \
		stream->bufferedTransportReadFunction( stream, bufPtr, contentLength,
											   TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	if( readLength < contentLength )
		{
		/* We timed out before reading all of the data.  Usually this will 
		   be reported as a CRYPT_ERROR_TIMEOUT by the lower-level read
		   routines, however due to the multiple layers of I/O and special
		   case timeout handling when (for example) a cryptlib transport
		   session is layered over the network I/O layer, we perform an
		   explicit check here to make sure that we got everything */
		retExtStream( stream, CRYPT_ERROR_TIMEOUT,
					  "HTTP read timed out before all data could be read, "
					  "only got %d of %d bytes", readLength, contentLength );
		}

	/* If it's a plain-text error message, return it to the caller */
	if( flags & HTTP_FLAG_TEXTMSG )
		{
		BYTE *byteBufPtr = bufPtr;

		/* Usually a body returned as plain text is an error message that
		   (for some reason) is sent as content rather than an HTTP error,
		   however in some unusual cases the content will be the requested
		   object marked as plain text.  This only seems to occur with
		   straight HTTP fetches from misconfigured servers rather than when
		   HTTP is being used as a tunnelling mechanism for a PKI protocol,
		   so we can filter this by requiring that the fetch is a straight
		   HTTP fetch (not a request/response PKI protocol fetch), that the
		   request is over a minimum size (most error messages are quite
		   short), and that the first bytes match what would be seen in a
		   PKI object such as a cert or CRL */
		if( stream->protocol != STREAM_PROTOCOL_HTTP || \
			contentLength < 256 || ( byteBufPtr[ 0 ] != 0x30 ) || \
			!( byteBufPtr[ 1 ] & 0x80 ) || \
			( isAlpha( byteBufPtr[ 2 ] ) && isAlpha( byteBufPtr[ 3 ] ) && \
			  isAlpha( byteBufPtr[ 4 ] ) ) )
			{
			retExtStream( stream, CRYPT_ERROR_READ,
						  "HTTP server reported: '%s'",
						  sanitiseString( byteBufPtr, \
										  min( readLength, \
											   MAX_ERRMSG_SIZE - 32 ) ) );
			}
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
	   it) so we can't rely on its presence.  Normally we wouldn't have to
	   worry about trailer data, but if it's an HTTP 1.1 persistent
	   connection we need to clear the way for the next lot of data */
	if( flags & HTTP_FLAG_CHUNKED )
		{
		status = readTrailerLines( stream, headerBuffer,
								   HTTP_LINEBUF_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( readLength );
	}

int setStreamLayerHTTP( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Set the access method pointers */
	stream->readFunction = readFunction;
	setStreamLayerHTTPwrite( stream );

	/* HTTP provides its own data-size and flow-control indicators so we
	   don't want the higher-level code to try and do this for us */
	stream->flags |= STREAM_NFLAG_ENCAPS;

	return( CRYPT_OK );
	}
#endif /* USE_HTTP */
