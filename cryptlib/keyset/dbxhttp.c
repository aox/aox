/****************************************************************************
*																			*
*						 cryptlib HTTP Mapping Routines						*
*						Copyright Peter Gutmann 1998-2002					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "asn1_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "../misc/asn1_rw.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* The default size of the HTTP read buffer.  This is adjusted dynamically if
   the data being read won't fit (eg large CRLs).  The default size is fine
   for certs */

#define HTTP_BUFFER_SIZE	4096

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Set up key information for a query */

static char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype )
	{
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			return( "name" );

		case CRYPT_KEYID_EMAIL:
			return( "email" );

		case CRYPT_IKEYID_KEYID:
			return( "sKIDHash" );

		case CRYPT_IKEYID_ISSUERID:
			return( "iAndSHash" );

		case CRYPT_IKEYID_CERTID:
			return( "certHash" );
		}

	assert( NOTREACHED );
	return( NULL );			/* Get rid of compiler warning */
	}

/* Callback function to adjust the I/O buffer size if the initial buffer
   isn't large enough */

static int bufferAdjustCallback( void *callbackParams, void **bufPtr,
								 const int bufSize )
	{
	KEYSET_INFO *keysetInfo = ( KEYSET_INFO * ) callbackParams;
	void *newBuffer;

	assert( keysetInfo->type == KEYSET_HTTP );
	assert( keysetInfo->subType == KEYSET_SUBTYPE_NONE );
	assert( keysetInfo->keyData != NULL );
	assert( keysetInfo->keyDataSize < bufSize );

	/* Allocate a new buffer and replace the existing one */
	if( ( newBuffer = clAlloc( "bufferAdjustCallback", bufSize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
	clFree( "bufferAdjustCallback", keysetInfo->keyData );
	*bufPtr = newBuffer;
	keysetInfo->keyData = newBuffer;
	keysetInfo->keyDataSize = bufSize;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 		Keyset Access Routines						*
*																			*
****************************************************************************/

/* Retrieve a cert/CRL from an HTTP server, either as a flat URL if the key
   name is "[none]" or as a cert store */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int length, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL );
	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* Set the keyID as the query portion of the URL if necessary */
	if( keyIDlength != 6 || strCompare( keyID, "[none]", 6 ) )
		{
		const char *keyName = getKeyName( keyIDtype );
		char queryBuffer[ 1024 ], *queryBufPtr = queryBuffer;
		const int keyNameLen = strlen( keyName );

		if( keyIDlength > 1024 - 64 && \
		    ( queryBufPtr = clDynAlloc( "getItemFunction", \
										keyIDlength + 64 ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		strcpy( queryBufPtr, keyName );
		strcat( queryBufPtr + keyNameLen, "=" );
		memcpy( queryBufPtr + keyNameLen + 1, keyID, keyIDlength );
		sioctl( &httpInfo->stream, STREAM_IOCTL_QUERY, queryBufPtr, 
				keyNameLen + 1 + keyIDlength );
		if( queryBufPtr != queryBuffer )
			clFree( "getItemFunction", queryBufPtr );
		}

	/* If we haven't allocated a buffer for the data yet, do so now */
	if( keysetInfo->keyData == NULL )
		{
		/* Allocate the initial I/O buffer */
		if( ( keysetInfo->keyData = clAlloc( "getItemFunction", \
											 HTTP_BUFFER_SIZE ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keysetInfo->keyDataSize = HTTP_BUFFER_SIZE;

		/* Since we don't know the size of the data being read in advance,
		   we have to set up a callback to adjust the buffer size if
		   necessary */
		sioctl( &httpInfo->stream, STREAM_IOCTL_CALLBACKFUNCTION,
				( void * ) bufferAdjustCallback, 0 );
		sioctl( &httpInfo->stream, STREAM_IOCTL_CALLBACKPARAMS,
				keysetInfo, 0 );
		}
	httpInfo->bufPos = 0;

	/* Send the request to the server */
	status = sread( &httpInfo->stream, keysetInfo->keyData,
					keysetInfo->keyDataSize );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &httpInfo->stream, httpInfo->errorMessage, 
						  &httpInfo->errorCode );
		return( status );
		}

	/* Find out how much data we got and perform a general check that
	   everything is OK.  We rely on this rather than the read byte count
	   since checking the ASN.1, which is the data which will actually be
	   processed, avoids any vagaries of server implementation oddities,
	   which may send extra null bytes or CRLFs or do who knows what else */
	length = getLongObjectLength( keysetInfo->keyData, 
								  keysetInfo->keyDataSize );
	if( cryptStatusError( length ) )
		return( length );

	/* Create a certificate object from the returned data */
	setMessageCreateObjectIndirectInfo( &createInfo, keysetInfo->keyData,
										length, CRYPT_CERTTYPE_NONE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCryptHandle = createInfo.cryptHandle;
	return( status );
	}

/* Prepare to open a connection to an HTTP server */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;
	NET_CONNECT_INFO connectInfo;
	int status;

	/* Set up the HTTP connection */
	initNetConnectInfo( &connectInfo, keysetInfo->ownerHandle, CRYPT_ERROR, 
						CRYPT_ERROR, NET_OPTION_HOSTNAME );
	connectInfo.name = name;
	connectInfo.port = 80;
	status = sNetConnect( &httpInfo->stream, STREAM_PROTOCOL_HTTP, 
						  &connectInfo, httpInfo->errorMessage, 
						  &httpInfo->errorCode );
	return( status );
	}

/* Close a previously-opened HTTP connection */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;

	sNetDisconnect( &httpInfo->stream );
	if( keysetInfo->keyData != NULL )
		{
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		clFree( "getItemFunction", keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}
	}

int setAccessMethodHTTP( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_HTTP */
