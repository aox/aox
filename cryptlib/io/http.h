/****************************************************************************
*																			*
*						cryptlib HTTP Interface Header						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#ifdef USE_HTTP

#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* The size of the HTTP text-line buffer when we're using a dedicated buffer
   to read header lines rather than the main stream buffer.  Anything more
   than this is dropped */

#define HTTP_LINEBUF_SIZE	1024

/* A macro to determine whether we're talking HTTP 1.0 or 1.1 */

#define isHTTP10( stream )	( ( stream )->flags & STREAM_NFLAG_HTTP10 )

/* HTTP state information passed around the various read/write functions */

#define HTTP_FLAG_NONE		0x00	/* No HTTP info */
#define HTTP_FLAG_CHUNKED	0x01	/* Message used chunked encoding */
#define HTTP_FLAG_TRAILER	0x02	/* Chunked encoding has trailer */
#define HTTP_FLAG_NOOP		0x04	/* No-op data (e.g. 100 Continue) */
#define HTTP_FLAG_TEXTMSG	0x08	/* HTTP content is plain text, probably
									   an error message */

/* Prototypes for functions in http_rd.c */

int sendHTTPError( STREAM *stream, char *headerBuffer,
				   const int headerBufMaxLen, const int httpStatus );

/* Prototypes for functions in http_wr.c */

int writeRequestHeader( STREAM *stream, const int length );
int sendHTTPData( STREAM *stream, void *buffer, const int length,
				  const int flags );
void setStreamLayerHTTPwrite( STREAM *stream );

#endif /* USE_HTTP */
