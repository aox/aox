/****************************************************************************
*																			*
*						 cryptlib TSP Session Management					*
*						Copyright Peter Gutmann 1999-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_TSP

/* TSP constants */

#define TSP_PORT					318	/* Default port number */
#define TSP_VERSION					1	/* Version number */
#define TSP_HEADER_SIZE				5	/* 4-byte length + 1-byte type */
#define MIN_MSGIMPRINT_SIZE			20	/* Min.and max.size for message imprint */
#define MAX_MSGIMPRINT_SIZE			( 32 + CRYPT_MAX_HASHSIZE )

/* TSP socket protocol message types.  This is a mutant variant of the CMP
   socket protocol (but incompatible, obviously), with no-one involved in the
   standard really able to explain why it exists, since it doesn't actually
   serve any purpose */

enum { TSP_MESSAGE_REQUEST, TSP_MESSAGE_POLLREP, TSP_MESSAGE_POLLREQ,
	   TSP_MESSAGE_NEGPOLLREP, TSP_MESSAGE_PARTIALMSGREP, TSP_MESSAGE_RESPONSE,
	   TSP_MESSAGE_ERROR };

/* Dummy policy OID for the TSA ('snooze policy, "Anything that arrives, we
   sign") */

#define OID_TSP_POLICY		MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x36\xDD\x24\x36" )

/* TSP protocol state information.  This is passed around the various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	BYTE msgImprint[ MAX_MSGIMPRINT_SIZE + 8 ];
	int msgImprintSize;					/* Message imprint */
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];
	int nonceSize;						/* Nonce (if present) */
	BOOLEAN includeSigCerts;			/* Whether to include signer certs */
	} TSP_PROTOCOL_INFO;

/* Prototypes for functions in cmp.c.  This code is shared due to TSP's use
   of random elements cut&pasted from CMP */

int readPkiStatusInfo( STREAM *stream, int *errorCode, char *errorMessage );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read a TSP request */

static int readTSPRequest( STREAM *stream, TSP_PROTOCOL_INFO *protocolInfo,
						   void *errorInfo )
	{
	BYTE *bufPtr;
	long value;
	int length, status;

	/* Read the request header and make sure everything is in order */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) || value != TSP_VERSION )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid request version %ld", value );

	/* Read the message imprint.  We don't really care what this is so we
	   just treat it as a blob */
	bufPtr = sMemBufPtr( stream );
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) || \
		length < MIN_MSGIMPRINT_SIZE || length > MAX_MSGIMPRINT_SIZE || \
		cryptStatusError( sSkip( stream, length ) ) )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid request data length %d", length );
	length = ( int ) sizeofObject( length );
	memcpy( protocolInfo->msgImprint, bufPtr, length );
	protocolInfo->msgImprintSize = length;

	/* Check for the presence of the assorted optional fields */
	if( peekTag( stream ) == BER_OBJECT_IDENTIFIER )
		{
		/* This could be anything since it's defined as "by prior agreement"
		   so we ignore it and give them whatever policy we happen to
		   implement, if they don't like it they're free to ignore it */
		status = readUniversal( stream );
		}
	if( cryptStatusOK( status ) && peekTag( stream ) == BER_INTEGER )
		{
		/* For some unknown reason the nonce is encoded as an INTEGER 
		   instead of an OCTET STRING, so in theory we'd have to jump 
		   through all sorts of hoops to handle it because it's really an 
		   OCTET STRING blob dressed up as an INTEGER.  To avoid this mess,
		   we just read it as a blob and memcpy() it back to the output */
		status = readRawObject( stream, protocolInfo->nonce,
								&protocolInfo->nonceSize, CRYPT_MAX_HASHSIZE,
								BER_INTEGER );
		}
	if( cryptStatusOK( status ) && peekTag( stream ) == BER_BOOLEAN )
		status = readBoolean( stream, &protocolInfo->includeSigCerts );
	if( cryptStatusOK( status ) && peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		/* The TSP RFC specifies a truly braindamaged interpretation of
		   extension handling, added at the last minute with no debate or
		   discussion.  This says that extensions are handled just like RFC
		   2459 except when they're not.  In particular it requires that you
		   reject all extensions that you don't recognise, even if they
		   don't have the critical bit set (in violation of RFC 2459).
		   Since "recognise" is never defined and the spec doesn't specify
		   any particular extensions that must be handled (via MUST/SHALL/
		   SHOULD), any extension at all is regarded as unrecognised in the
		   context of the RFC.  For example if a request with a
		   subjectAltName is submitted then although the TSA knows perfectly
		   well what a subjectAltName, it has no idea what it's supposed to
		   do with it when it sees it in the request.  Since the semantics of
		   all extensions are unknown (in the context of the RFC), any
		   request with extensions has to be rejected.

		   Along with assorted other confusing and often contradictory terms
		   added in the last-minute rewrite, cryptlib ignores this
		   requirement and instead uses the common-sense interpretation of
		   allowing any extension that the RFC doesn't specifically provide
		   semantics for.  Since it doesn't provide semantics for any
		   extension, we allow anything */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		retExt( errorInfo, CRYPT_ERROR_BADDATA, "Invalid request data" );
	return( CRYPT_OK );
	}

/* Sign a timestamp token */

static int signTSToken( BYTE *tsaResp, int *tsaRespLength,
						const int tsaRespMaxLength, const BYTE *tstInfo,
						const int tstInfoLength,
						const CRYPT_CONTEXT privateKey,
						const BOOLEAN includeCerts )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	DYNBUF essCertDB;
	static const int minBufferSize = MIN_BUFFER_SIZE;
	static const int contentType = CRYPT_CONTENT_TSTINFO;
	int status;

	/* Create the signing attributes.  We don't have to set the content-type
	   attribute since it'll be set automatically based on the envelope
	   content type */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iCmsAttributes = createInfo.cryptHandle;
	status = dynCreate( &essCertDB, privateKey, CRYPT_IATTRIBUTE_ESSCERTID );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, dynData( essCertDB ),
						dynLength( essCertDB ) );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
						&msgData, CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID );
		dynDestroy( &essCertDB );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Create a cryptlib envelope to sign the data.  If we're not being
	   asked to include signer certs, we have to explicitly disable the
	   inclusion of certs in the signature since S/MIME includes them by
	   default */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_CMS );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &minBufferSize,
							  CRYPT_ATTRIBUTE_BUFFERSIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, ( void * ) &tstInfoLength,
							CRYPT_ENVINFO_DATASIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, ( void * ) &contentType,
							CRYPT_ENVINFO_CONTENTTYPE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, ( void * ) &privateKey,
							CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, &iCmsAttributes,
							CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
	if( cryptStatusOK( status ) && !includeCerts )
		status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE,
							CRYPT_IATTRIBUTE_INCLUDESIGCERT );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Push in the data and pop the signed result */
	setMessageData( &msgData, ( void * ) tstInfo, tstInfoLength );
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, tsaResp, tsaRespMaxLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_POPDATA, &msgData, 0 );
		*tsaRespLength = msgData.length;
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* Send a request to a TSP server */

static int sendClientRequest( SESSION_INFO *sessionInfoPtr,
							  TSP_PROTOCOL_INFO *protocolInfo )
	{
	TSP_INFO *tspInfo = sessionInfoPtr->sessionTSP;
	STREAM stream;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	void *msgImprintPtr;

	/* Create the encoded request.  We never ask for the inclusion of
	   signing certs (which is the default behaviour for TSP) because the
	   CMS signature-generation code needs to perform two passes over the
	   data (to get the signed data size for encoding purposes), however
	   we can't get the size without generating a timestamp.  Since the
	   basic TST is compact and fixed-length, we can manage this, but can't
	   easily handle having arbitrary amounts of signing certs being
	   returned */
	protocolInfo->msgImprintSize = \
							sizeofMessageDigest( tspInfo->imprintAlgo,
												 tspInfo->imprintSize );
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 1024 );
	writeSequence( &stream, sizeofShortInteger( TSP_VERSION ) + \
							protocolInfo->msgImprintSize + \
							( protocolInfo->includeSigCerts ? \
								sizeofBoolean() : 0 ) );
	writeShortInteger( &stream, TSP_VERSION, DEFAULT_TAG );
	msgImprintPtr = sMemBufPtr( &stream );
	writeMessageDigest( &stream, tspInfo->imprintAlgo,
						tspInfo->imprint, tspInfo->imprintSize );
	memcpy( protocolInfo->msgImprint, msgImprintPtr,
			protocolInfo->msgImprintSize );
	if( protocolInfo->includeSigCerts )
		writeBoolean( &stream, TRUE, DEFAULT_TAG );
	sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	DEBUG_DUMP( "tsa_req", sessionInfoPtr->receiveBuffer,
				sessionInfoPtr->receiveBufEnd );

	/* If we're using the socket protocol, add the TSP header:
		uint32		length of type + data
		byte		type
		byte[]		data */
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		{
		memmove( bufPtr + TSP_HEADER_SIZE, bufPtr,
				 sessionInfoPtr->receiveBufEnd );
		mputLong( bufPtr, sessionInfoPtr->receiveBufEnd + 1 );
		*bufPtr = TSP_MESSAGE_REQUEST;
		sessionInfoPtr->receiveBufEnd += TSP_HEADER_SIZE;
		}

	/* Send the request to the server */
	return( writePkiDatagram( sessionInfoPtr ) );
	}

/* Read the response from the TSP server */

static int readServerResponse( SESSION_INFO *sessionInfoPtr,
							   TSP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	const int oldBufSize = sessionInfoPtr->receiveBufSize;
	int status;

	/* Reset the buffer position indicators to clear any old data in the
	   buffer from previous transactions */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos = 0;

	/* If we're using the socket protocol, read back the header and make
	   sure it's in order.  The check for a response labelled as a request
	   is necessary because some buggy implementations use the request
	   message type for any normal communication (in fact since the socket
	   protocol arose from a botched cut & paste of the equivalent CMP
	   protocol it serves no actual purpose and so some implementations just
	   memcpy() in a fixed header) */
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		{
		BYTE buffer[ TSP_HEADER_SIZE + 8 ], *bufPtr = buffer;
		long packetLength;

		status = sread( &sessionInfoPtr->stream, buffer, TSP_HEADER_SIZE );
		if( cryptStatusError( status ) )
			{
			sNetGetErrorInfo( &sessionInfoPtr->stream,
							  sessionInfoPtr->errorMessage,
							  &sessionInfoPtr->errorCode );
			return( status );
			}
		packetLength = mgetLong( bufPtr );
		if( packetLength < 16 || \
			packetLength > sessionInfoPtr->receiveBufSize || \
			( *bufPtr != TSP_MESSAGE_REQUEST && \
			  *bufPtr != TSP_MESSAGE_RESPONSE ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid TSP socket protocol data" );

		/* Fiddle the read buffer size to make sure we only try and read as
		   much as the wrapper protocol has told us is present.  This kludge
		   is necessary because the wrapper protocol isn't any normal
		   transport mechanism like HTTP but a botched cut & paste from CMP
		   that can't easily be accommodated by the network-layer code */
		sessionInfoPtr->receiveBufSize = ( int ) packetLength - 1;
		}

	/* Read the response data from the server */
	status = readPkiDatagram( sessionInfoPtr );
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		/* Reset the receive buffer size to its true value */
		sessionInfoPtr->receiveBufSize = oldBufSize;
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->receiveBufEnd < 16 )
		/* If the length is tiny, it's an error response.  We don't even
		   bother trying to feed it to the cert handling code, in theory to
		   save a few cycles but mostly to avoid triggering sanity checks
		   within the code for too-short objects */
		retExt( sessionInfoPtr, CRYPT_ERROR_INVALID,
				"TSA returned error response" );

	/* Strip off the header and check the PKIStatus wrapper to make sure
	   everything is OK */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	status = readPkiStatusInfo( &stream, &sessionInfoPtr->errorCode,
								sessionInfoPtr->errorMessage );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Remember where the encoded timestamp payload starts in the buffer so
	   that we can return it to the caller */
	sessionInfoPtr->receiveBufPos = stell( &stream );

	/* Make sure that we got back a timestamp of the value we sent.  This 
	   check means that it works with and without nonces (in theory someone 
	   could repeatedly contersign the same signature rather than 
	   countersigning the last timestamp as they're supposed to, but (a) 
	   that's rather unlikely and (b) cryptlib doesn't support it so they'd 
	   have to make some rather serious changes to the code to do it) */
	readSequence( &stream, NULL );		/* contentInfo */
	readUniversal( &stream );			/* contentType */
	readConstructed( &stream, NULL, 0 );/* content */
	readSequence( &stream, NULL );			/* signedData */
	readShortInteger( &stream, NULL );		/* version */
	readUniversal( &stream );				/* digestAlgos */
	readSequence( &stream, NULL );			/* encapContent */
	readUniversal( &stream );					/* contentType */
	readConstructed( &stream, NULL, 0 );		/* content */
	readOctetStringHole( &stream, NULL, 16, 
						 DEFAULT_TAG );			/* OCTET STRING hole */
	readSequence( &stream, NULL );					/* tstInfo */
	readShortInteger( &stream, NULL );				/* version */
	status = readUniversal( &stream );				/* policy */
	if( cryptStatusError( status ) )
		status = CRYPT_ERROR_BADDATA;
	else
		if( protocolInfo->msgImprintSize > sMemDataLeft( &stream ) || \
			memcmp( protocolInfo->msgImprint, sMemBufPtr( &stream ),
					protocolInfo->msgImprintSize ) )
			status = CRYPT_ERROR_INVALID;
	sMemDisconnect( &stream );

	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				( status == CRYPT_ERROR_BADDATA ) ? \
					"Invalid timestamp data" : \
					"Timestamp message imprint doesn't match message "
					"imprint" );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Server-side Functions							*
*																			*
****************************************************************************/

/* Send an error response back to the client.  Since there are only a small
   number of these, we write back a fixed blob rather than encoding each
   one */

#define respSize( data )	( data[ 3 ] + 4 )

static const BYTE FAR_BSS respBadGeneric[] = {
	0x00, 0x00, 0x00, 0x08,			/* Length */
	0x05,							/* Type */
	0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02
	};								/* Rejection, unspecified reason */
static const BYTE FAR_BSS respBadData[] = {
	0x00, 0x00, 0x00, 0x0C,			/* Length */
	0x05,							/* Type */
	0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x02, 0x03,
	0x02, 0x05, 0x20				/* Rejection, badDataFormat */
	};
static const BYTE FAR_BSS respBadExtension[] = {
	0x00, 0x00, 0x00, 0x0E,			/* Length */
	0x05,							/* Type */
	0x30, 0x0B, 0x30, 0x09, 0x02, 0x01, 0x02, 0x03,
	0x04, 0x07, 0x00, 0x00, 0x80	/* Rejection, unacceptedExtension */
	};

static int sendErrorResponse( SESSION_INFO *sessionInfoPtr,
							  const BYTE *errorResponse, const int status )
	{
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		{
		memcpy( sessionInfoPtr->receiveBuffer, errorResponse,
				respSize( errorResponse ) );
		sessionInfoPtr->receiveBufEnd = respSize( errorResponse );
		}
	else
		{
		memcpy( sessionInfoPtr->receiveBuffer,
				errorResponse + TSP_HEADER_SIZE,
				respSize( errorResponse ) - TSP_HEADER_SIZE );
		sessionInfoPtr->receiveBufEnd = \
							respSize( errorResponse ) - TSP_HEADER_SIZE;
		}
	writePkiDatagram( sessionInfoPtr );
	return( status );
	}

/* Read a request from a TSP client */

static int readClientRequest( SESSION_INFO *sessionInfoPtr,
							  TSP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	const int oldBufSize = sessionInfoPtr->receiveBufSize;
	int status;

	/* If we're using the socket protocol, read the request header and make
	   sure it's in order.  We don't write an error response at this initial
	   stage to prevent scanning/DOS attacks (vir sapit qui pauca
	   loquitur) */
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		{
		long packetLength;

		status = sread( &sessionInfoPtr->stream, bufPtr, TSP_HEADER_SIZE );
		if( cryptStatusError( status ) )
			{
			sNetGetErrorInfo( &sessionInfoPtr->stream,
							  sessionInfoPtr->errorMessage,
							  &sessionInfoPtr->errorCode );
			return( status );
			}
		packetLength = mgetLong( bufPtr );
		if( packetLength < 16 || \
			packetLength > sessionInfoPtr->receiveBufSize || \
			( *bufPtr != TSP_MESSAGE_REQUEST && \
			  *bufPtr != TSP_MESSAGE_RESPONSE ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid TSP socket protocol data" );

		/* Fiddle the read buffer size to make sure we only try and read as
		   much as the wrapper protocol has told us is present.  This kludge
		   is necessary because the wrapper protocol isn't any normal
		   transport mechanism like HTTP but a botched cut&paste from CMP
		   that can't easily be accommodated by the network-layer code */
		sessionInfoPtr->receiveBufSize = ( int ) packetLength - 1;
		}

	/* Read the request data from the client */
	status = readPkiDatagram( sessionInfoPtr );
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		/* Reset the receive buffer size to its true value */
		sessionInfoPtr->receiveBufSize = oldBufSize;
	if( cryptStatusError( status ) )
		return( sendErrorResponse( sessionInfoPtr, respBadGeneric, status ) );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	status = readTSPRequest( &stream, protocolInfo, sessionInfoPtr );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( sendErrorResponse( sessionInfoPtr, \
					( status == CRYPT_ERROR_BADDATA || \
					  status == CRYPT_ERROR_UNDERFLOW ) ? respBadData : \
					( status == CRYPT_ERROR_INVALID ) ? respBadExtension : \
					respBadGeneric, status ) );
	return( CRYPT_OK );
	}

/* Send the response to the TSP client */

static int sendServerResponse( SESSION_INFO *sessionInfoPtr,
							   TSP_PROTOCOL_INFO *protocolInfo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE serialNo[ 16 + 8 ];
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	const time_t currentTime = getReliableTime( sessionInfoPtr->privateKey );
	const int headerOfs = ( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) ? \
						  0 : TSP_HEADER_SIZE;
	int length, responseLength, status;

	/* If the time is screwed up we can't provide a signed indication of the
	   time.  The error information is somewhat misleading, but there's not
	   much else we can provide at this point */
	if( currentTime <= MIN_TIME_VALUE )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_VALIDFROM,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Create a timestamp token and sign it */
	setMessageData( &msgData, serialNo, 16 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer,
			  sessionInfoPtr->receiveBufSize );
	writeSequence( &stream, sizeofShortInteger( 1 ) + \
			sizeofOID( OID_TSP_POLICY ) + protocolInfo->msgImprintSize + \
			sizeofInteger( serialNo, 16 ) + sizeofGeneralizedTime() + \
			protocolInfo->nonceSize );
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeOID( &stream, OID_TSP_POLICY );
	swrite( &stream, protocolInfo->msgImprint, protocolInfo->msgImprintSize );
	writeInteger( &stream, serialNo, 16, DEFAULT_TAG );
	status = writeGeneralizedTime( &stream, currentTime, DEFAULT_TAG );
	if( protocolInfo->nonceSize > 0 )
		status = swrite( &stream, protocolInfo->nonce,
						 protocolInfo->nonceSize );
	length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		status = signTSToken( sessionInfoPtr->receiveBuffer + headerOfs + 9,
							  &responseLength, sessionInfoPtr->receiveBufSize,
							  sessionInfoPtr->receiveBuffer, length,
							  sessionInfoPtr->privateKey,
							  protocolInfo->includeSigCerts );
	if( cryptStatusError( status ) )
		return( sendErrorResponse( sessionInfoPtr, respBadGeneric, status ) );
	DEBUG_DUMP( "tsa_token",
				sessionInfoPtr->receiveBuffer + headerOfs + 9,
				responseLength );
	assert( responseLength >= 256 );

	/* If we're using the socket protocol, add the TSP header:
		uint32		length of type + data
		byte		type
		byte[]		data */
	if( !( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) )
		{
		bufPtr = sessionInfoPtr->receiveBuffer;
		mputLong( bufPtr, 1 + 9 + responseLength );
		*bufPtr++ = TSP_MESSAGE_RESPONSE;
		}

	/* Add the TSA response wrapper and send it to the client.  This assumes
	   that the TSA response will be >= 256 bytes (for a 4-byte SEQUENCE
	   header encoding), which is always the case since it uses PKCS #7
	   signed data */
	sMemOpen( &stream, bufPtr, 4 + 5 );		/* SEQ + resp.header */
	writeSequence( &stream, 5 + responseLength );
	swrite( &stream, "\x30\x03\x02\x01\x00", 5 );
	sMemDisconnect( &stream );
	sessionInfoPtr->receiveBufEnd = headerOfs + 9 + responseLength;
	return( writePkiDatagram( sessionInfoPtr ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with a TSP client/server */

static int clientTransact( SESSION_INFO *sessionInfoPtr )
	{
	TSP_PROTOCOL_INFO protocolInfo;
	int status;

	/* Make sure that we have all of the needed information */
	if( sessionInfoPtr->sessionTSP->imprintSize == 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_TSP_MSGIMPRINT,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Get a timestamp from the server */
	memset( &protocolInfo, 0, sizeof( TSP_PROTOCOL_INFO ) );
	status = sendClientRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = readServerResponse( sessionInfoPtr, &protocolInfo );
	return( status );
	}

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	TSP_PROTOCOL_INFO protocolInfo;
	int status;

	/* Send a timestamp to the client */
	memset( &protocolInfo, 0, sizeof( TSP_PROTOCOL_INFO ) );
	status = readClientRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = sendServerResponse( sessionInfoPtr, &protocolInfo );
	return( status );
	}

/****************************************************************************
*																			*
*					Control Information Management Functions				*
*																			*
****************************************************************************/

static int getAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 void *data, const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *cryptEnvelopePtr = ( CRYPT_CERTIFICATE * ) data;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int dataSize = sessionInfoPtr->receiveBufEnd - \
						 sessionInfoPtr->receiveBufPos;
	const int bufSize = max( dataSize + 128, MIN_BUFFER_SIZE );
	int status;

	assert( type == CRYPT_SESSINFO_RESPONSE || \
			type == CRYPT_IATTRIBUTE_ENC_TIMESTAMP );

	/* Make sure there's actually a timestamp present (this can happen if
	   we're using a persistent session and a subsequent transaction
	   fails) */
	if( sessionInfoPtr->receiveBufPos <= 0 )
		return( CRYPT_ERROR_NOTFOUND );

	/* If we're being asked for raw encoded timestamp data, return it
	   directly to the caller */
	if( type == CRYPT_IATTRIBUTE_ENC_TIMESTAMP )
		return( attributeCopy( ( MESSAGE_DATA * ) data,
					sessionInfoPtr->receiveBuffer + sessionInfoPtr->receiveBufPos,
					dataSize ) );

	/* We're being asked for interpreted data, create a cryptlib envelope to
	   contain it */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &bufSize, CRYPT_ATTRIBUTE_BUFFERSIZE );

	/* Push in the timestamp data */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer + \
							  sessionInfoPtr->receiveBufPos, dataSize );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
		krnlSendNotifier( sessionInfoPtr->iCertResponse,
						  IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_INCREFCOUNT );
	*cryptEnvelopePtr = sessionInfoPtr->iCertResponse;
	return( status );
	}

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CONTEXT hashContext = *( ( CRYPT_CONTEXT * ) data );
	TSP_INFO *tspInfo = sessionInfoPtr->sessionTSP;
	int status;

	assert( type == CRYPT_SESSINFO_TSP_MSGIMPRINT );

	if( tspInfo->imprintSize != 0 )
		return( CRYPT_ERROR_INITED );

	/* Get the message imprint from the hash context */
	status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE,
							  &tspInfo->imprintAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, tspInfo->imprint, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );
		tspInfo->imprintSize = msgData.length;
		}

	return( cryptStatusError( status ) ? CRYPT_ARGERROR_NUM1 : CRYPT_OK );
	}

static int checkAttributeFunction( SESSION_INFO *sessionInfoPtr,
								   const CRYPT_HANDLE cryptHandle,
								   const CRYPT_ATTRIBUTE_TYPE type )
	{
	int value, status;

	if( type != CRYPT_SESSINFO_PRIVATEKEY )
		return( CRYPT_OK );

	/* Make sure that the key is valid for timestamping */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC_SIGN );
	if( cryptStatusError( status ) )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_CERTINFO_EXTKEY_TIMESTAMPING );
	if( cryptStatusError( status ) || !value )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodTSP( SESSION_INFO *sessionInfoPtr )
	{
	static const ALTPROTOCOL_INFO altProtocolInfo = {
		STREAM_PROTOCOL_TCPIP,		/* Alt.protocol type */
		"tcp://",					/* Alt.protocol URI type */
		TSP_PORT,					/* Alt.protocol port */
		SESSION_ISHTTPTRANSPORT,	/* Protocol flags to replace */
		SESSION_USEALTTRANSPORT		/* Alt.protocol flags */
		};
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		0,							/* Client flags */
		SESSION_NEEDS_PRIVATEKEY |	/* Server flags */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCERT,
		1, 1, 1,					/* Version 1 */
		"application/timestamp-query",/* Client content-type */
		"application/timestamp-reply",/* Server content-type */

		/* Protocol-specific information */
		BUFFER_SIZE_DEFAULT,		/* Send/receive buffers */
		&altProtocolInfo			/* Alt.transport protocol */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( isServer( sessionInfoPtr ) )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		sessionInfoPtr->transactFunction = clientTransact;
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;
	sessionInfoPtr->checkAttributeFunction = checkAttributeFunction;

	return( CRYPT_OK );
	}
#endif /* USE_TSP */
