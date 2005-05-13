/****************************************************************************
*																			*
*						 cryptlib OCSP Session Management					*
*						Copyright Peter Gutmann 1999-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_OCSP

/* OCSP query/response types */

typedef enum {
	OCSPRESPONSE_TYPE_NONE,				/* No response type */
	OCSPRESPONSE_TYPE_OCSP,				/* OCSP standard response */
	OCSPRESPONSE_TYPE_LAST				/* Last valid response type */
	} OCSPRESPONSE_TYPE;

/* OCSP response status values */

enum { OCSP_RESP_SUCCESSFUL, OCSP_RESP_MALFORMEDREQUEST,
	   OCSP_RESP_INTERNALERROR, OCSP_RESP_TRYLATER, OCSP_RESP_DUMMY,
	   OCSP_RESP_SIGREQUIRED, OCSP_RESP_UNAUTHORISED };

/* OCSP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	OCSPRESPONSE_TYPE responseType;		/* Response type to return */
	} OCSP_PROTOCOL_INFO;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Deliver an Einladung betreff Kehrseite to the client.  We don't bother
   checking the return value since there's nothing that we can do in the 
   case of an error except close the connection, which we do anyway since 
   this is the last message */

static void sendErrorResponse( SESSION_INFO *sessionInfoPtr, 
							   const void *responseData, 
							   const int responseDataLength )
	{
	memcpy( sessionInfoPtr->receiveBuffer, responseData, 
			responseDataLength );
	sessionInfoPtr->receiveBufEnd = responseDataLength;
	writePkiDatagram( sessionInfoPtr );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* OID information used to read responses */

static const FAR_BSS OID_INFO ocspOIDinfo[] = {
	{ OID_OCSP_RESPONSE_OCSP, OCSPRESPONSE_TYPE_OCSP },
	{ NULL, 0 }
	};

/* Send a request to an OCSP server */

static int sendClientRequest( SESSION_INFO *sessionInfoPtr )
	{
	RESOURCE_DATA msgData;
	int status;

	/* Get the encoded request data.  We store this in the send buffer, which
	   at its minimum size is roughly two orders of magnitude larger than the
	   request */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't get OCSP request data from OCSP request object" );
	sessionInfoPtr->receiveBufEnd = msgData.length;
	DEBUG_DUMP( "ocsp_req", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Send the request to the responder */
	return( writePkiDatagram( sessionInfoPtr ) );
	}

/* Read the response from the OCSP server */

static int readServerResponse( SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_CERTIFICATE iCertResponse;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE nonceBuffer[ CRYPT_MAX_HASHSIZE ];
	int value, responseType, length, status;

	/* Read the response from the responder */
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP( "ocsp_resp", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Try and extract an OCSP status code from the returned object */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, 
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	status = readEnumerated( &stream, &value );
	if( cryptStatusOK( status ) )
		{
		const char *errorString = NULL;

		sessionInfoPtr->errorCode = value;

		/* If it's an error status, try and translate it into something a
		   bit more meaningful (some of the translations are a bit
		   questionable, but it's better than the generic no vas response) */
		switch( value )
			{
			case OCSP_RESP_SUCCESSFUL:
				status = CRYPT_OK;
				break;

			case OCSP_RESP_TRYLATER:
				errorString = "Try again later";
				status = CRYPT_ERROR_NOTAVAIL;
				break;

			case OCSP_RESP_SIGREQUIRED:
				errorString = "Signed OCSP request required";
				status = CRYPT_ERROR_SIGNATURE;
				break;

			case OCSP_RESP_UNAUTHORISED:
				errorString = "Client isn't authorised to perform query";
				status = CRYPT_ERROR_PERMISSION;
				break;

			default:
				errorString = "Unknown error";
				status = CRYPT_ERROR_INVALID;
				break;
			}
		if( errorString != NULL )
			sPrintf( sessionInfoPtr->errorMessage, 
					 "OCSP server returned status %d: %s", 
					 value, errorString );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* We've got a valid response, read the [0] EXPLICIT SEQUENCE { OID,
	   OCTET STRING { encapsulation and import the response into an OCSP 
	   cert object */
	readConstructed( &stream, NULL, 0 );		/* responseBytes */
	readSequence( &stream, NULL );
	readOID( &stream, ocspOIDinfo,				/* responseType */
			 &responseType );
	status = readGenericHole( &stream, &length, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, status, "Invalid OCSP response header" );
		}
	status = importCertFromStream( &stream, &iCertResponse, length,
								   CRYPT_CERTTYPE_OCSP_RESPONSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Invalid OCSP response data" );

	/* If the request went out with a nonce included (which it does by
	   default), make sure that it matches the nonce in the response.  The
	   comparison is somewhat complex because for no known reason OCSP uses
	   integers rather than octet strings as nonces, so the nonce is encoded 
	   using the integer analog to an OCTET STRING hole and may have a 
	   leading zero byte if the high bit is set.  Because of this we treat the
	   two as equal if they really are equal or if they differ only by a
	   leading zero byte (in practice the cert-handling code ensures that 
	   the high bit is never set, but we leave the extra checking in there 
	   just in case) */
	setMessageData( &msgData, nonceBuffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_OCSP_NONCE );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA responseMsgData;
		BYTE responseNonceBuffer[ CRYPT_MAX_HASHSIZE ];

		setMessageData( &responseMsgData, responseNonceBuffer,
						CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCertResponse, IMESSAGE_GETATTRIBUTE_S, 
								  &responseMsgData, 
								  CRYPT_CERTINFO_OCSP_NONCE );
		if( cryptStatusError( status ) || msgData.length < 4 || \
			!( ( msgData.length == responseMsgData.length && \
				 !memcmp( msgData.data, responseMsgData.data, msgData.length ) ) || \
			   ( msgData.length == responseMsgData.length - 1 && \
				 responseNonceBuffer[ 0 ] == 0 && \
				 !memcmp( msgData.data, responseNonceBuffer + 1, msgData.length ) ) ) )
			{
			/* The response doesn't contain a nonce or it doesn't match what
			   we sent, we can't trust it.  The best error that we can return 
			   here is a signature error to indicate that the integrity check
			   failed */
			krnlSendNotifier( iCertResponse, IMESSAGE_DECREFCOUNT );
			retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
					cryptStatusError( status ) ? \
					"OCSP response doesn't contain a nonce" : \
					"OCSP response nonce doesn't match the one in the "
					"request" );
			}
		}
	krnlSendNotifier( sessionInfoPtr->iCertRequest, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertRequest = CRYPT_ERROR;
	sessionInfoPtr->iCertResponse = iCertResponse;

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

#define RESPONSE_SIZE		5

static const FAR_BSS BYTE respBadRequest[] = {
	0x30, 0x03, 0x0A, 0x01, 0x01	/* Rejection, malformed request */
	};
static const FAR_BSS BYTE respIntError[] = {
	0x30, 0x03, 0x0A, 0x01, 0x02	/* Rejection, internal error */
	};

/* Read a request from an OCSP client */

static int readClientRequest( SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_CERTIFICATE iOcspRequest;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	int status;

	/* Read the request data from the client.  We don't write an error
	   response at this initial stage to prevent scanning/DOS attacks 
	   (vir sapit qui pauca loquitur) */
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP( "ocsp_sreq", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Basic lint filter to check for approximately-OK requests */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, 
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	readSequence( &stream, NULL );
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		readUniversal( &stream );
	if( peekTag( &stream ) == MAKE_CTAG( 1 ) )
		readUniversal( &stream );
	readSequence( &stream, NULL );
	status = readSequence( &stream, NULL );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Invalid OCSP request header" );

	/* Import the request as a cryptlib object */
	setMessageCreateObjectIndirectInfo( &createInfo,
										sessionInfoPtr->receiveBuffer, 
										sessionInfoPtr->receiveBufEnd,
										CRYPT_CERTTYPE_OCSP_REQUEST );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, respBadRequest, RESPONSE_SIZE );
		retExt( sessionInfoPtr, status, "Invalid OCSP request data" );
		}
	iOcspRequest = createInfo.cryptHandle;

	/* Create an OCSP response and add the request information to it */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_OCSP_RESPONSE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iOcspRequest, IMESSAGE_DECREFCOUNT );
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_SETATTRIBUTE, &iOcspRequest,
							  CRYPT_IATTRIBUTE_OCSPREQUEST );
	krnlSendNotifier( iOcspRequest, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		retExt( sessionInfoPtr, status, 
				"Couldn't create OCSP response from request" );
		}
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Return a response to an OCSP client */

static int sendServerResponse( SESSION_INFO *sessionInfoPtr )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	int responseLength, responseDataLength, status;

	/* Check the entries from the request against the cert store and sign
	   the resulting status information ("Love, ken").  Note that
	   CRYPT_ERROR_INVALID is a valid return status for the sigcheck call
	   since it indicates that one (or more) of the certs was revoked */
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_SIGCHECK, NULL,
							  sessionInfoPtr->cryptKeyset );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_INVALID )
		{
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		retExt( sessionInfoPtr, status, 
				"Couldn't check OCSP request against certificate store" );
		}
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_SIGN, NULL,
							  sessionInfoPtr->privateKey );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sessionInfoPtr->iCertResponse,
								  IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_CERTFORMAT_CERTIFICATE );
	responseDataLength = msgData.length;
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		retExt( sessionInfoPtr, status, 
				"Couldn't create signed OCSP response" );
		}

	/* Write the wrapper for the response */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer,
			  sessionInfoPtr->receiveBufSize );
	responseLength = sizeofOID( OID_OCSP_RESPONSE_OCSP ) + \
					 sizeofObject( responseDataLength );
	writeSequence( &stream, sizeofEnumerated( 0 ) + \
				   sizeofObject( sizeofObject( responseLength ) ) );
	writeEnumerated( &stream, 0, DEFAULT_TAG );		/* respStatus */
	writeConstructed( &stream, sizeofObject( responseLength ), 0 );
	writeSequence( &stream, responseLength );		/* respBytes */
	writeOID( &stream, OID_OCSP_RESPONSE_OCSP );	/* respType */
	writeOctetStringHole( &stream, responseDataLength, DEFAULT_TAG );
													/* response */
	/* Get the encoded response data */
	status = exportCertToStream( &stream, sessionInfoPtr->iCertResponse, 
								 CRYPT_CERTFORMAT_CERTIFICATE );
	sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		return( status );
		}
	DEBUG_DUMP( "ocsp_sresp", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Send the response to the client */
	return( writePkiDatagram( sessionInfoPtr ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with an OCSP client/server */

static int clientTransact( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	/* Get cert revocation information from the server */
	status = sendClientRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = readServerResponse( sessionInfoPtr );
	return( status );
	}

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	/* Send cert revocation information to the client */
	status = readClientRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = sendServerResponse( sessionInfoPtr );
	return( status );
	}

/****************************************************************************
*																			*
*					Control Information Management Functions				*
*																			*
****************************************************************************/

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CERTIFICATE ocspRequest = *( ( CRYPT_CERTIFICATE * ) data );
	RESOURCE_DATA msgData = { NULL, 0 };
	int status;

	assert( type == CRYPT_SESSINFO_REQUEST );

	/* Make sure that everything is set up ready to go.  Since OCSP requests
	   aren't (usually) signed like normal cert objects, we can't just check
	   the immutable attribute but have to perform a dummy export for which
	   the cert export code will return an error status if there's a
	   problem with the request.  If not, it pseudo-signs the request (if it
	   hasn't already done so) and prepares it for use */
	status = krnlSendMessage( ocspRequest, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* If we haven't already got a server name explicitly set, try and get
	   it from the request */
	if( findSessionAttribute( sessionInfoPtr->attributeList,
							  CRYPT_SESSINFO_SERVER_NAME ) == NULL )
		{
		char buffer[ MAX_URL_SIZE ];

		setMessageData( &msgData, buffer, MAX_URL_SIZE );
		status = krnlSendMessage( ocspRequest, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RESPONDERURL );
		if( cryptStatusOK( status ) )
			krnlSendMessage( sessionInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_SESSINFO_SERVER_NAME );
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( ocspRequest, IMESSAGE_INCREFCOUNT );
	sessionInfoPtr->iCertRequest = ocspRequest;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodOCSP( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		SESSION_NEEDS_REQUEST,		/* Client attributes */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYSET,
		1, 1, 2,					/* Version 1 */
		"application/ocsp-request",	/* Client content-type */
		"application/ocsp-response"	/* Server content-type */

		/* Protocol-specific information */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		sessionInfoPtr->transactFunction = clientTransact;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;

	return( CRYPT_OK );
	}
#endif /* USE_OCSP */
