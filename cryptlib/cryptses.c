/****************************************************************************
*																			*
*						cryptlib Secure Session Routines					*
*						Copyright Peter Gutmann 1998-2005					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "stream.h"
  #include "session.h"
#else
  #include "misc/asn1.h"
  #include "io/stream.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

/* The number of entries in the SSL session cache.  Note that when changing 
   the SESSIONCACHE_SIZE value you need to also change MAX_ALLOC_SIZE in 
   sec_mem.c to allow the allocation of such large amounts of secure 
   memory */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define SESSIONCACHE_SIZE			128
#else
  #define SESSIONCACHE_SIZE			1024
#endif /* CONFIG_CONSERVE_MEMORY */

static SCOREBOARD_INFO scoreboardInfo;

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( SESSION_INFO *sessionInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( sessionInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( SESSION_INFO *sessionInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotInited( SESSION_INFO *sessionInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTINITED ) );
	}

static int exitErrorNotFound( SESSION_INFO *sessionInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Exit after saving a detailed error message.  This is used by lower-level 
   session code to provide more information to the caller than a basic error 
   code */

int retExtFnSession( SESSION_INFO *sessionInfoPtr, const int status, 
					 const char *format, ... )
	{
	va_list argPtr;

	va_start( argPtr, format );
	vsprintf_s( sessionInfoPtr->errorMessage, MAX_ERRMSG_SIZE, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

int retExtExFnSession( SESSION_INFO *sessionInfoPtr, 
					   const int status, const CRYPT_HANDLE extErrorObject, 
					   const char *format, ... )
	{
	MESSAGE_DATA msgData;
	va_list argPtr;
	int extErrorStatus;

	/* Check whether there's any additional error information available */
	va_start( argPtr, format );
	setMessageData( &msgData, NULL, 0 );
	extErrorStatus = krnlSendMessage( extErrorObject, MESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );
	if( cryptStatusOK( extErrorStatus ) )
		{
		char errorString[ MAX_ERRMSG_SIZE + 8 ];
		char extraErrorString[ MAX_ERRMSG_SIZE + 8 ];
		int errorStringLen, extraErrorStringLen;

		/* There's additional information present via the additional object, 
		   fetch it and append it to the session-level error message */
		setMessageData( &msgData, extraErrorString, MAX_ERRMSG_SIZE );
		extErrorStatus = krnlSendMessage( extErrorObject, MESSAGE_GETATTRIBUTE_S,
										  &msgData, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );
		if( cryptStatusOK( extErrorStatus ) )
			extraErrorString[ msgData.length ] = '\0';
		else
			strcpy( extraErrorString, "(None available)" );
		extraErrorStringLen = strlen( extraErrorString );
		vsprintf_s( errorString, MAX_ERRMSG_SIZE, format, argPtr );
		errorStringLen = strlen( errorString );
		if( errorStringLen < MAX_ERRMSG_SIZE - 64 )
			{
			const int extErrorLenToCopy = \
							min( MAX_ERRMSG_SIZE - ( 32 + errorStringLen ), 
								 extraErrorStringLen );

			strcpy( errorString + errorStringLen, ". Additional information: " );
			memcpy( errorString + errorStringLen + 26, extraErrorString,
					extErrorLenToCopy );
			errorString[ errorStringLen + 26 + extErrorLenToCopy ] = '\0';
			}
		strcpy( sessionInfoPtr->errorMessage, errorString );
		}
	else
		vsprintf_s( sessionInfoPtr->errorMessage, MAX_ERRMSG_SIZE, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/* Add the contents of an encoded URL to a session.  This requires parsing
   the individual session attribute components out of the URL and then 
   adding each one in turn */

static int addUrl( SESSION_INFO *sessionInfoPtr, const void *url,
				   const int urlLength )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( url, urlLength ) );
	assert( urlLength > 0 && urlLength < MAX_URL_SIZE );

	/* If there's already a transport session or network socket specified, 
	   we can't set a server name as well */
	if( sessionInfoPtr->transportSession != CRYPT_ERROR )
		return( exitErrorInited( sessionInfoPtr, CRYPT_SESSINFO_SESSION ) );
	if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
		return( exitErrorInited( sessionInfoPtr, 
								 CRYPT_SESSINFO_NETWORKSOCKET ) );

	/* Parse the server name */
	status = sNetParseURL( &urlInfo, url, urlLength );
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* We can only use autodetection with PKI services */
	if( !strCompare( url, "[Autodetect]", urlLength ) && \
		!protocolInfoPtr->isReqResp )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* Remember the server name */
	if( urlInfo.hostLen + urlInfo.locationLen + 1 > MAX_URL_SIZE )
		{
		/* This should never happen since the overall URL size has to be 
		   less than MAX_URL_SIZE */
		assert( NOTREACHED );
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}
	if( urlInfo.locationLen <= 0 )
		status = addSessionAttribute( &sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME, 
									  urlInfo.host, urlInfo.hostLen );
	else
		{
		char urlBuffer[ MAX_URL_SIZE + 8 ];

		memcpy( urlBuffer, urlInfo.host, urlInfo.hostLen );
		memcpy( urlBuffer + urlInfo.hostLen, urlInfo.location, 
				urlInfo.locationLen );
		status = addSessionAttribute( &sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME, urlBuffer, 
									  urlInfo.hostLen + urlInfo.locationLen );
		}
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* If there's a port or user name specified in the URL, remember them.  
	   We have to add the user name after we add any other attributes 
	   because it's paired with a password, so adding the user name and then 
	   following it with something that isn't a password will cause an error 
	   return */
	if( urlInfo.port > 0 )
		{
		krnlSendMessage( sessionInfoPtr->objectHandle, 
						 IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_SESSINFO_SERVER_PORT );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &urlInfo.port,
								  CRYPT_SESSINFO_SERVER_PORT );
		}
	if( cryptStatusOK( status ) && urlInfo.userInfoLen > 0 )
		{
		MESSAGE_DATA userInfoMsgData;

		krnlSendMessage( sessionInfoPtr->objectHandle, 
						 IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_SESSINFO_USERNAME );
		setMessageData( &userInfoMsgData, ( void * ) urlInfo.userInfo, 
						urlInfo.userInfoLen );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &userInfoMsgData,
								  CRYPT_SESSINFO_USERNAME );
		}
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* Remember the transport type */
	if( protocolInfoPtr->altProtocolInfo != NULL && \
		urlInfo.schemaLen == \
					strlen( protocolInfoPtr->altProtocolInfo->uriType ) && \
		!strCompare( urlInfo.schema, 
					 protocolInfoPtr->altProtocolInfo->uriType,
					 strlen( protocolInfoPtr->altProtocolInfo->uriType ) ) )
		{
		/* The caller has specified the use of the altnernate transport 
		   protocol type, switch to that instead of HTTP */
		sessionInfoPtr->flags &= ~protocolInfoPtr->altProtocolInfo->oldFlagsMask;
		sessionInfoPtr->flags |= protocolInfoPtr->altProtocolInfo->newFlags;
		}
	else
		if( sessionInfoPtr->protocolInfo->flags & SESSION_ISHTTPTRANSPORT )
			{
			sessionInfoPtr->flags &= ~SESSION_USEALTTRANSPORT;
			sessionInfoPtr->flags |= SESSION_ISHTTPTRANSPORT;
			}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Session Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a session object */

static int processGetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			int value, status;

			status = getSessionAttributeCursor( sessionInfoPtr->attributeList,
									sessionInfoPtr->attributeListCurrent, 
									messageValue, &value );
			if( status == OK_SPECIAL )
				/* The attribute list wasn't initialised yet, initialise it 
				   now */
				sessionInfoPtr->attributeListCurrent = \
										sessionInfoPtr->attributeList;
			else
				if( cryptStatusError( status ) )
					return( exitError( sessionInfoPtr, messageValue, 
									   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
			*valuePtr = value;
			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->connectTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->readTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->writeTimeout;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = sessionInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = sessionInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->receiveBufSize;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:
			*valuePtr = sessionInfoPtr->errorCode;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Only secure transport sessions can be persistently active,
			   request/response sessions are only active while the 
			   transaction is in progress.  Note that this differs from the
			   connection-active state, which records the fact that there's 
			   a network-level connection established but no messages or
			   secure session active across it.  See the comment in 
			   processSetAttribute() for more on this */
			*valuePtr = sessionInfoPtr->iCryptInContext != CRYPT_ERROR && \
						( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CONNECTIONACTIVE:
			*valuePtr = ( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
		case CRYPT_SESSINFO_CLIENT_PORT:
			{
			const ATTRIBUTE_LIST *attributeListPtr = \
						findSessionAttribute( sessionInfoPtr->attributeList,
											  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = attributeListPtr->intValue;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_VERSION:
			*valuePtr = sessionInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_AUTHRESPONSE:
			*valuePtr = sessionInfoPtr->authResponse;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const int value = *( int * ) messageDataPtr;
	int status;

	/* If we're in the middle of a paired-attribute add, make sure that the
	   conditions under which it's occurring are valid.  In theory since 
	   non-string attributes are never part of any paired attributes we 
	   shouldn't really allow them to be added if we're in the middle of a
	   paired-attribute add, but in practice this isn't such a big deal 
	   because the only attribute add that can affect an attribute pair is
	   an attempt to move the attribute cursor, so we only disallow this 
	   type of attribute add.  This leniency makes it less difficult to add
	   related attributes like a server URL, user name, and port */
	if( sessionInfoPtr->lastAddedAttributeID != CRYPT_ATTRIBUTE_NONE && \
		( messageValue == CRYPT_ATTRIBUTE_CURRENT || \
		  messageValue == CRYPT_ATTRIBUTE_CURRENT_GROUP ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			ATTRIBUTE_LIST *attributeListPtr = \
									sessionInfoPtr->attributeListCurrent;

			status = setSessionAttributeCursor( sessionInfoPtr->attributeList,
									&attributeListPtr, messageValue, value );
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, messageValue, 
								   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
			sessionInfoPtr->attributeListCurrent = attributeListPtr;
			return( status );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			sessionInfoPtr->connectTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			sessionInfoPtr->readTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			sessionInfoPtr->writeTimeout = value;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			assert( !( sessionInfoPtr->flags & SESSION_ISOPEN ) );
			sessionInfoPtr->receiveBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			{
			CRYPT_ATTRIBUTE_TYPE missingInfo;

			/* Session state and persistent sessions are handled as follows:
			   The CRYPT_SESSINFO_ACTIVE attribute records the active state
			   of the session as a whole, and the CRYPT_SESSINFO_-
			   CONNECTIONACTIVE attribute records the state of the 
			   underlying comms session.  Setting CRYPT_SESSINFO_ACTIVE for 
			   the first time activates the comms session, and leaves it 
			   active if the underlying mechanism (e.g. HTTP 1.1 persistent 
			   connections) supports it.  The CRYPT_SESSINFO_ACTIVE 
			   attribute is reset once the transaction completes, and 
			   further transactions can be initiated as long as 
			   CRYPT_SESSINFO_CONNECTIONACTIVE is set:

										Obj.state	_active		_connactive
										---------	-------		-----------
				create						0			0			0
				setattr						0			0			0
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
				setattr						1			0			1
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
					(peer closes conn)		1			0			0
				setattr							CRYPT_ERROR_COMPLETE */
			if( value == FALSE )
				return( CRYPT_OK );	/* No-op */

			/* If the session is in the partially-open state while we wait 
			   for the caller to allow or disallow the session 
			   authentication, they have to provide a clear yes or no 
			   indication if they try to continue the session activation */
			if( ( sessionInfoPtr->flags & SESSION_PARTIALOPEN ) && \
				sessionInfoPtr->authResponse == CRYPT_UNUSED )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_AUTHRESPONSE ) );

			/* Make sure that all the information that we need to proceed is 
			   present */
			missingInfo = checkMissingInfo( sessionInfoPtr->attributeList,
								isServer( sessionInfoPtr ) ? TRUE : FALSE );
			if( missingInfo != CRYPT_ATTRIBUTE_NONE )
				return( exitErrorNotInited( sessionInfoPtr, missingInfo ) );

			status = activateSession( sessionInfoPtr );
			if( cryptArgError( status ) )
				{
				/* Catch leaked low-level status values.  The session 
				   management code does a large amount of work involving 
				   other cryptlib objects, so it's possible that an 
				   unexpected failure at some point will leak through an 
				   inappropriate status value */
				assert( NOTREACHED );
				status = CRYPT_ERROR_FAILED;
				}
			return( status );
			}

		case CRYPT_SESSINFO_SERVER_PORT:
			/* If there's already a transport session or network socket 
			   specified, we can't set a port as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			return( addSessionAttribute( &sessionInfoPtr->attributeList,
										 CRYPT_SESSINFO_SERVER_PORT, NULL,
										 value ) );

		case CRYPT_SESSINFO_VERSION:
			if( value < sessionInfoPtr->protocolInfo->minVersion || \
				value > sessionInfoPtr->protocolInfo->maxVersion )
				return( CRYPT_ARGERROR_VALUE );
			sessionInfoPtr->version = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PRIVATEKEY:
			{
			const int requiredAttributeFlags = isServer( sessionInfoPtr ) ? \
						sessionInfoPtr->serverReqAttrFlags : \
						sessionInfoPtr->clientReqAttrFlags;

			/* Make sure that it's a private key */
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusError( status ) )
				{
				if( sessionInfoPtr->type != CRYPT_SESSION_SSL )
					return( CRYPT_ARGERROR_NUM1 );

				/* SSL can also do key agreement-based key exchange, so we
				   fall back to this if key transport-based exchange isn't
				   possible */
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_KA_EXPORT );
				if( cryptStatusError( status ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* If we need a private key with certain capabilities, make sure 
			   that it has these capabilities.  This is a more specific check 
			   than that allowed by the kernel ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYSIGN )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_SIGN );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCRYPT )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_DECRYPT );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}

			/* If we need a private key with a cert, make sure that the
			   appropriate type of initialised cert object is present.  This
			   is a more specific check than that allowed by the kernel 
			   ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCERT )
				{
				int attrValue;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_IMMUTABLE );
				if( cryptStatusError( status ) || !attrValue )
					return( CRYPT_ARGERROR_NUM1 );
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) ||
					( attrValue != CRYPT_CERTTYPE_CERTIFICATE && \
					  attrValue != CRYPT_CERTTYPE_CERTCHAIN ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( ( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCACERT ) && \
				cryptStatusError( \
					krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
					return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key meets the mininum height requirements.  
			   We only perform this check if we're explicitly being asked to
			   perform the check and it's a server session (which has certain
			   minimum length requirements for private keys), for client
			   sessions the permitted length/security level is controlled by
			   the server so we can't really perform much checking */
			if( sessionInfoPtr->protocolInfo->requiredPrivateKeySize && \
				isServer( sessionInfoPtr ) )
				{
				int length;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &length, CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) || \
					length < sessionInfoPtr->protocolInfo->requiredPrivateKeySize )
					return( exitError( sessionInfoPtr,
									   CRYPT_SESSINFO_PRIVATEKEY,
									   CRYPT_ERRTYPE_ATTR_SIZE,
									   CRYPT_ARGERROR_NUM1 ) );
				}

			/* Perform any protocol-specific checks if necessary */
			if( sessionInfoPtr->checkAttributeFunction != NULL )
				{
				status = sessionInfoPtr->checkAttributeFunction( sessionInfoPtr,
											value, CRYPT_SESSINFO_PRIVATEKEY );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Add the private key and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->privateKey = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_KEYSET:
			{
			int type;

			/* Make sure that it's either a cert store (rather than just a 
			   generic keyset) if required, or specifically not a cert 
			   store.  This is to prevent a session running with unnecessary
			   privs, we should only be using a cert store if it's actually
			   required.  The checking is already performed by the kernel,
			   but we do it again here just to be safe */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &type, 
									  CRYPT_IATTRIBUTE_SUBTYPE );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSTORE )
				{
				if( type != SUBTYPE_KEYSET_DBMS_STORE )
					return( CRYPT_ARGERROR_NUM1 );
				}
			else
				{
				if( type != SUBTYPE_KEYSET_DBMS )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* Add the keyset and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->cryptKeyset = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_AUTHRESPONSE:
			sessionInfoPtr->authResponse = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SESSION:
			/* If there's already a host or network socket specified, we 
			   can't set a transport session as well */
			if( findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Add the transport mechanism and increment its reference
			   count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->transportSession = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_NETWORKSOCKET:
			{
			NET_CONNECT_INFO connectInfo;
			STREAM stream;

			/* If there's already a host or session specified, we can't set 
			   a network socket as well */
			if( findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );

			/* Create a dummy network stream to make sure that the network 
			   socket is OK */
			initNetConnectInfo( &connectInfo, sessionInfoPtr->ownerHandle, 
								sessionInfoPtr->readTimeout, 
								sessionInfoPtr->connectTimeout,
								NET_OPTION_NETWORKSOCKET_DUMMY );
			connectInfo.networkSocket = value;
			status = sNetConnect( &stream, STREAM_PROTOCOL_TCPIP, 
								  &connectInfo, sessionInfoPtr->errorMessage, 
								  &sessionInfoPtr->errorCode );
			if( cryptStatusError( status ) )
				return( status );
			sNetDisconnect( &stream );

			/* Add the network socket */
			sessionInfoPtr->networkSocket = value;
			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	const ATTRIBUTE_LIST *attributeListPtr;
	MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( exitErrorNotFound( sessionInfoPtr,
									   messageValue ) );

		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			if( !*sessionInfoPtr->errorMessage )
				/* We don't set extended error information for this atribute
				   because it's usually read in response to an existing error, 
				   which would overwrite the existing error information */
				return( CRYPT_ERROR_NOTFOUND );
			return( attributeCopy( msgData, sessionInfoPtr->errorMessage,
								   strlen( sessionInfoPtr->errorMessage ) ) );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_CLIENT_NAME:
			attributeListPtr = \
					findSessionAttribute( sessionInfoPtr->attributeList,
										  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			return( attributeCopy( msgData, attributeListPtr->value,
								   attributeListPtr->valueLength ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;

	/* If we're in the middle of a paired-attribute add, make sure that the
	   conditions under which it's occurring are valid */
	if( sessionInfoPtr->lastAddedAttributeID != CRYPT_ATTRIBUTE_NONE )
		{
		switch( sessionInfoPtr->lastAddedAttributeID )
			{
			case CRYPT_SESSINFO_USERNAME:
				/* Username must be followed by a password */
				if( messageValue != CRYPT_SESSINFO_PASSWORD )
					return( CRYPT_ARGERROR_VALUE );
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR_INTERNAL );
			}
		}

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never used */
			return( CRYPT_ARGERROR_VALUE );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
			{
			int flags = isServer( sessionInfoPtr ) ? \
						ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;
			int status;

			assert( msgData->length > 0 && \
					msgData->length <= CRYPT_MAX_TEXTSIZE );

			/* If this is a client session, we can only have a single 
			   instance of this attribute */
			if( !isServer( sessionInfoPtr ) && \
				findSessionAttribute( sessionInfoPtr->attributeList, 
									  messageValue ) != NULL )
				return( exitErrorInited( sessionInfoPtr, messageValue ) );
				
			/* If it's a username, make sure that it doesn't duplicate an
			   existing one */
			if( messageValue == CRYPT_SESSINFO_USERNAME )
				{
				if( findSessionAttributeEx( sessionInfoPtr->attributeList, 
											messageValue, msgData->data, 
											msgData->length ) != NULL )
					return( exitError( sessionInfoPtr, messageValue,
									   CRYPT_ERRTYPE_ATTR_PRESENT, 
									   CRYPT_ERROR_DUPLICATE ) );
				}
			else
				{
				/* It's a password, make sure that there's an associated
				   username to go with it.  There are two approaches that
				   we can take here, the first simply requires that the
				   current cursor position is a username, implying that
				   the last-added attribute was a username.  The other is
				   to try and move the cursor to the last username in the
				   attribute list and check that the next attribute isn't
				   a password and then add it there, however this is doing
				   a bit too much behind the user's back, is somewhat 
				   difficult to back out of, and leads to exceptions to
				   exceptions, so we keep it simple and only allow passwords
				   to be added if there's an immediately preceding
				   username */
				if( sessionInfoPtr->lastAddedAttributeID != CRYPT_SESSINFO_USERNAME )
					return( exitErrorNotInited( sessionInfoPtr, 
												CRYPT_SESSINFO_USERNAME ) );
				}

			/* If it could be an encoded PKI value, check its validity */
			if( isPKIUserValue( msgData->data, msgData->length ) )
				{
				BYTE decodedValue[ 64 + 8 ];

				/* It's an encoded value, make sure that it's in order */
				status = decodePKIUserValue( decodedValue, 64, 
											 msgData->data, msgData->length );
				zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
				if( cryptStatusError( status ) )
					return( status );
				flags = ATTR_FLAG_ENCODEDVALUE;
				}

			/* Remember the value */
			status = addSessionAttributeEx( &sessionInfoPtr->attributeList,
											messageValue, msgData->data, 
											msgData->length, flags );
			if( cryptStatusError( status ) )
				return( status );
			sessionInfoPtr->lastAddedAttributeID = \
							( messageValue == CRYPT_SESSINFO_USERNAME ) ? \
							CRYPT_SESSINFO_USERNAME : CRYPT_ATTRIBUTE_NONE;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
			/* Remember the value */
			return( addSessionAttribute( &sessionInfoPtr->attributeList,
										 messageValue, msgData->data, 
										 msgData->length ) );

		case CRYPT_SESSINFO_SERVER_NAME:
			return( addUrl( sessionInfoPtr, msgData->data, 
							msgData->length ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processDeleteAttribute( SESSION_INFO *sessionInfoPtr,
								   const int messageValue )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->readTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->writeTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_SERVER_PORT:
			/* Make sure that the attribute to delete is actually present */
			attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  messageValue );
			if( attributeListPtr == NULL )
				return( exitErrorNotFound( sessionInfoPtr, messageValue ) );

			/* If we're in the middle of a paired-attribute add and the 
			   delete affects the paired attribute, delete it.  This can
			   get quite complex because the user could (for example) add
			   a { username, password } pair, then add a second username
			   (but not password), and then delete the first password, which
			   will reset the lastAddedAttributeID, leaving an orphaned
			   password followed by an orphaned username.  There isn't any
			   easy way to fix this short of forcing some form of group 
			   delete of paired attributes, but this gets too complicated
			   both to implement and to explain to the user in an error
			   status.  What we do here is handle the simple case and let
			   the pre-session-activation sanity check catch situations 
			   where the user's gone out of their way to be difficult */
			if( sessionInfoPtr->lastAddedAttributeID == messageValue )
				sessionInfoPtr->lastAddedAttributeID = CRYPT_ATTRIBUTE_NONE;

			/* Delete the attribute */
			deleteSessionAttribute( &sessionInfoPtr->attributeList,
									&sessionInfoPtr->attributeListCurrent,
									( ATTRIBUTE_LIST * ) attributeListPtr );
			return( CRYPT_OK );

		case CRYPT_SESSINFO_REQUEST:
			if( sessionInfoPtr->iCertRequest == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_REQUEST ) );
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCertRequest = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_TSP_MSGIMPRINT:
			if( sessionInfoPtr->sessionTSP->imprintAlgo == CRYPT_ALGO_NONE || \
				sessionInfoPtr->sessionTSP->imprintSize <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_TSP_MSGIMPRINT ) );
			sessionInfoPtr->sessionTSP->imprintAlgo = CRYPT_ALGO_NONE;
			sessionInfoPtr->sessionTSP->imprintSize = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Session Message Handler						*
*																			*
****************************************************************************/

/* Handle a message sent to a session object */

static int sessionMessageFunction( const void *objectInfoPtr,
								   const MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	SESSION_INFO *sessionInfoPtr = ( SESSION_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the session if required.  Nemo nisi mors */
		if( sessionInfoPtr->flags & SESSION_ISOPEN )
			{
			sessionInfoPtr->flags |= SESSION_ISCLOSINGDOWN;
			sessionInfoPtr->shutdownFunction( sessionInfoPtr );
			}

		/* Clear and free session state information if necessary */
		if( sessionInfoPtr->sendBuffer != NULL )
			{
			zeroise( sessionInfoPtr->sendBuffer,
					 sessionInfoPtr->sendBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->sendBuffer );
			}
		if( sessionInfoPtr->receiveBuffer != NULL )
			{
			zeroise( sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->receiveBuffer );
			}

		/* Clear session attributes if necessary */
		if( sessionInfoPtr->attributeList != NULL )
			deleteSessionAttributes( &sessionInfoPtr->attributeList,
									 &sessionInfoPtr->attributeListCurrent );

		/* Clean up any session-related objects if necessary */
		if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertRequest != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertResponse,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privateKey != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privateKey,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->transportSession != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->transportSession,
							  IMESSAGE_DECREFCOUNT );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		/* If it's a protocol-specific attribute, forward it directly to
		   the low-level code */
		if( message != MESSAGE_DELETEATTRIBUTE && \
			( ( messageValue >= CRYPT_SESSINFO_FIRST_SPECIFIC && \
				messageValue <= CRYPT_SESSINFO_LAST_SPECIFIC ) || \
			  messageValue == CRYPT_IATTRIBUTE_ENC_TIMESTAMP ) )
			{
			int status;

			if( message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S )
				{
				assert( sessionInfoPtr->setAttributeFunction != NULL );

				status = sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_INITED )
					return( exitErrorInited( sessionInfoPtr, 
											 messageValue ) );
				}
			else
				{
				assert( message == MESSAGE_GETATTRIBUTE || \
						message == MESSAGE_GETATTRIBUTE_S );
				assert( sessionInfoPtr->getAttributeFunction != NULL );

				status = sessionInfoPtr->getAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_NOTFOUND )
					return( exitErrorNotFound( sessionInfoPtr, 
											   messageValue ) );
				}
			return( status );
			}

		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_DELETEATTRIBUTE )
			return( processDeleteAttribute( sessionInfoPtr, messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_ENV_PUSHDATA )
		{
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;
		const int length = msgData->length;
		int bytesCopied, status;

		/* Unless we're told otherwise, we've copied zero bytes */
		msgData->length = 0;

		/* If the session isn't open yet, perform an implicit open */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			{
			status = krnlSendMessage( sessionInfoPtr->objectHandle, 
									  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
									  CRYPT_SESSINFO_ACTIVE );
			if( cryptStatusError( status ) )
				return( status );

			/* The session is ready to process data, move it into the high
			   state */
			krnlSendMessage( sessionInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED );
			}
		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->sendBuffer != NULL );
		assert( sessionInfoPtr->preparePacketFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->flags & SESSION_SENDCLOSED )
			/* If the other side has closed its receive channel (which is 
			   our send channel), we can't send any more data, although we 
			   can still get data on our receive channel if we haven't closed
			   it as well.  The closing of the other side's send channel is 
			   detected during a read and isn't a write error but a normal 
			   state change in the channel, so we don't treat it as an error 
			   when it's seen at the read stage until the caller actually 
			   tries to write data to the closed channel */
			sessionInfoPtr->writeErrorState = CRYPT_ERROR_COMPLETE;
		if( sessionInfoPtr->writeErrorState != CRYPT_OK )
			return( sessionInfoPtr->writeErrorState );

		/* Write the data */
		clearErrorInfo( sessionInfoPtr );
		status = putSessionData( sessionInfoPtr, msgData->data, length, 
								 &bytesCopied );
		if( cryptStatusOK( status ) )
			msgData->length = bytesCopied;
		assert( ( cryptStatusError( status ) && bytesCopied == 0 ) || \
				( cryptStatusOK( status ) && bytesCopied >= 0 ) );
		return( status );
		}
	if( message == MESSAGE_ENV_POPDATA )
		{
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;
		const int length = msgData->length;
		int bytesCopied, status;

		/* Unless we're told otherwise, we've copied zero bytes */
		msgData->length = 0;

		/* If the session isn't open, there's nothing to pop */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			return( CRYPT_ERROR_NOTINITED );

		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->receiveBuffer != NULL );
		assert( sessionInfoPtr->readHeaderFunction != NULL );
		assert( sessionInfoPtr->processBodyFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->readErrorState != CRYPT_OK )
			return( sessionInfoPtr->readErrorState );

		/* Read the data */
		clearErrorInfo( sessionInfoPtr );
		status = getSessionData( sessionInfoPtr, msgData->data, length,
								 &bytesCopied );
		if( cryptStatusOK( status ) )
			msgData->length = bytesCopied;
		assert( ( cryptStatusError( status ) && bytesCopied == 0 ) || \
				( cryptStatusOK( status ) && bytesCopied >= 0 ) );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a session.  This is a low-level function encapsulated by createSession()
   and used to manage error exits */

static int openSession( CRYPT_SESSION *iCryptSession,
						const CRYPT_USER cryptOwner,
						const CRYPT_SESSION_TYPE sessionType,
						SESSION_INFO **sessionInfoPtrPtr )
	{
	SESSION_INFO *sessionInfoPtr;
	const PROTOCOL_INFO *protocolInfoPtr;
	typedef struct {
		const CRYPT_SESSION_TYPE sessionType;
		const CRYPT_SESSION_TYPE baseSessionType;
		const OBJECT_SUBTYPE subType;
		} SESSIONTYPE_INFO;
	static const SESSIONTYPE_INFO sessionTypes[] = {
	{ CRYPT_SESSION_SSH, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH },
	{ CRYPT_SESSION_SSH_SERVER, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH_SVR },
	{ CRYPT_SESSION_SSL, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL },
	{ CRYPT_SESSION_SSL_SERVER, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL_SVR },
	{ CRYPT_SESSION_RTCS, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS },
	{ CRYPT_SESSION_RTCS_SERVER, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS_SVR },
	{ CRYPT_SESSION_OCSP, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP },
	{ CRYPT_SESSION_OCSP_SERVER, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP_SVR },
	{ CRYPT_SESSION_TSP, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP },
	{ CRYPT_SESSION_TSP_SERVER, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP_SVR },
	{ CRYPT_SESSION_CMP, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP },
	{ CRYPT_SESSION_CMP_SERVER, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP_SVR },
	{ CRYPT_SESSION_SCEP, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP },
	{ CRYPT_SESSION_SCEP_SERVER, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP_SVR },
	{ CRYPT_SESSION_CERTSTORE_SERVER, CRYPT_SESSION_CERTSTORE_SERVER, SUBTYPE_SESSION_CERT_SVR },
	{ CRYPT_SESSION_NONE, CRYPT_SESSION_NONE, CRYPT_ERROR },
	{ CRYPT_SESSION_NONE, CRYPT_SESSION_NONE, CRYPT_ERROR }
	};
	int storageSize, i, status;

	assert( sessionInfoPtrPtr != NULL );

	/* Clear the return values */
	*iCryptSession = CRYPT_ERROR;
	*sessionInfoPtrPtr = NULL;

	/* Map the external session type to a base type and internal object
	   subtype */
	for( i = 0; sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE && \
				i < FAILSAFE_ARRAYSIZE( sessionTypes, SESSIONTYPE_INFO ); 
		 i++ )
		{
		if( sessionTypes[ i ].sessionType == sessionType )
			break;
		}
	if( i >= FAILSAFE_ARRAYSIZE( sessionTypes, SESSIONTYPE_INFO ) )
		retIntError();
	assert( sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE );

	/* Set up subtype-specific information */
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_SSH:
			storageSize = sizeof( SSH_INFO );
			break;

		case CRYPT_SESSION_SSL:
			storageSize = sizeof( SSL_INFO );
			break;

		case CRYPT_SESSION_TSP:
			storageSize = sizeof( TSP_INFO );
			break;

		case CRYPT_SESSION_CMP:
			storageSize = sizeof( CMP_INFO );
			break;
		
		case CRYPT_SESSION_RTCS:
		case CRYPT_SESSION_OCSP:
		case CRYPT_SESSION_SCEP:
		case CRYPT_SESSION_CERTSTORE_SERVER:
			storageSize = 0;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Create the session object */
	status = krnlCreateObject( ( void ** ) &sessionInfoPtr, 
							   sizeof( SESSION_INFO ) + storageSize, 
							   OBJECT_TYPE_SESSION, sessionTypes[ i ].subType,
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, sessionMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*sessionInfoPtrPtr = sessionInfoPtr;
	*iCryptSession = sessionInfoPtr->objectHandle = status;
	sessionInfoPtr->ownerHandle = cryptOwner;
	sessionInfoPtr->type = sessionTypes[ i ].baseSessionType;
	if( storageSize > 0 )
		{
		switch( sessionTypes[ i ].baseSessionType )
			{
			case CRYPT_SESSION_SSH:
				sessionInfoPtr->sessionSSH = \
								( SSH_INFO * ) sessionInfoPtr->storage;
				break;

			case CRYPT_SESSION_SSL:
				sessionInfoPtr->sessionSSL = \
								( SSL_INFO * ) sessionInfoPtr->storage;
				break;

			case CRYPT_SESSION_TSP:
				sessionInfoPtr->sessionTSP = \
								( TSP_INFO * ) sessionInfoPtr->storage;
				break;

			case CRYPT_SESSION_CMP:
				sessionInfoPtr->sessionCMP = \
								( CMP_INFO * ) sessionInfoPtr->storage;
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR );
			}
		}
	sessionInfoPtr->storageSize = storageSize;

	/* If it's a server session, mark it as such.  An HTTP certstore session 
	   is a special case in that it's always a server session */
	if( ( sessionTypes[ i ].sessionType != \
		  sessionTypes[ i ].baseSessionType ) || \
		( sessionTypes[ i ].sessionType == CRYPT_SESSION_CERTSTORE_SERVER ) )
		sessionInfoPtr->flags = SESSION_ISSERVER;

	/* Set up any internal objects to contain invalid handles */
	sessionInfoPtr->iKeyexCryptContext = \
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
	sessionInfoPtr->iCryptInContext = \
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
	sessionInfoPtr->iAuthInContext = \
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
	sessionInfoPtr->iCertRequest = \
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	sessionInfoPtr->privateKey = CRYPT_ERROR;
	sessionInfoPtr->cryptKeyset = CRYPT_ERROR;
	sessionInfoPtr->privKeyset =  CRYPT_ERROR;
	sessionInfoPtr->transportSession = CRYPT_ERROR;
	sessionInfoPtr->networkSocket = CRYPT_ERROR;
	sessionInfoPtr->readTimeout = \
		sessionInfoPtr->writeTimeout = \
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;

	/* Set up any additinal values */
	sessionInfoPtr->authResponse = CRYPT_UNUSED;

	/* Set up the access information for the session and initialise it */
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_CERTSTORE_SERVER:
			status = setAccessMethodCertstore( sessionInfoPtr );
			break;

		case CRYPT_SESSION_CMP:
			status = setAccessMethodCMP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_RTCS:
			status = setAccessMethodRTCS( sessionInfoPtr );
			break;

		case CRYPT_SESSION_OCSP:
			status = setAccessMethodOCSP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SCEP:
			status = setAccessMethodSCEP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSH:
			status = setAccessMethodSSH( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSL:
			status = setAccessMethodSSL( sessionInfoPtr );
			break;

		case CRYPT_SESSION_TSP:
			status = setAccessMethodTSP( sessionInfoPtr );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a session type that uses the scoreboard, set up the 
	   scoreboard information for the session */
	if( sessionType == CRYPT_SESSION_SSL_SERVER )
		sessionInfoPtr->sessionSSL->scoreboardInfo = scoreboardInfo;

	/* Check that the protocol info is OK */
	protocolInfoPtr = sessionInfoPtr->protocolInfo;
	assert( ( protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->bufSize == 0 && \
			  protocolInfoPtr->sendBufStartOfs == 0 && \
			  protocolInfoPtr->maxPacketSize == 0 ) || 
			( !protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->bufSize >= MIN_BUFFER_SIZE && \
			  protocolInfoPtr->sendBufStartOfs >= 5 && \
			  protocolInfoPtr->maxPacketSize <= protocolInfoPtr->bufSize ) );
	assert( ( ( protocolInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) && \
			  protocolInfoPtr->port == 80 ) || \
			( protocolInfoPtr->port != 80 ) );
	assert( protocolInfoPtr->port > 21 );
	assert( protocolInfoPtr->version >= 0 );
	assert( ( protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->clientContentType != NULL && \
			  protocolInfoPtr->serverContentType != NULL ) || 
			( !protocolInfoPtr->isReqResp && \
			  protocolInfoPtr->clientContentType == NULL && \
			  protocolInfoPtr->serverContentType == NULL ) );

	/* Copy mutable protocol-specific information into the session info */
	sessionInfoPtr->flags |= protocolInfoPtr->flags;
	sessionInfoPtr->clientReqAttrFlags = protocolInfoPtr->clientReqAttrFlags;
	sessionInfoPtr->serverReqAttrFlags = protocolInfoPtr->serverReqAttrFlags;
	sessionInfoPtr->version = protocolInfoPtr->version;
	if( protocolInfoPtr->isReqResp )
		{
		sessionInfoPtr->sendBufSize = CRYPT_UNUSED;
		sessionInfoPtr->receiveBufSize = MIN_BUFFER_SIZE;
		}
	else
		{
		sessionInfoPtr->sendBufSize = sessionInfoPtr->receiveBufSize = \
				protocolInfoPtr->bufSize;
		sessionInfoPtr->sendBufStartOfs = sessionInfoPtr->receiveBufStartOfs = \
				protocolInfoPtr->sendBufStartOfs;
		sessionInfoPtr->maxPacketSize = protocolInfoPtr->maxPacketSize;
		}

	/* Install default handlers if no session-specific ones are provided */
	initSessionIO( sessionInfoPtr );

	/* Check that the handlers are all OK */
	assert( sessionInfoPtr->connectFunction != NULL );
	assert( sessionInfoPtr->transactFunction != NULL );
	assert( ( protocolInfoPtr->isReqResp && \
			  sessionInfoPtr->readHeaderFunction == NULL && \
			  sessionInfoPtr->processBodyFunction == NULL && \
			  sessionInfoPtr->preparePacketFunction == NULL ) || \
			( !protocolInfoPtr->isReqResp && \
			  sessionInfoPtr->readHeaderFunction != NULL && \
			  sessionInfoPtr->processBodyFunction != NULL && \
			  sessionInfoPtr->preparePacketFunction != NULL ) );

	return( CRYPT_OK );
	}

int createSession( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_SESSION iCryptSession;
	SESSION_INFO *sessionInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_SESSION_NONE || \
		createInfo->arg1 >= CRYPT_SESSION_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = openSession( &iCryptSession, createInfo->cryptOwner,
							  createInfo->arg1, &sessionInfoPtr );
	if( sessionInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptSession, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptSession, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptSession;
	return( CRYPT_OK );
	}

/* Generic management function for this class of object */

int sessionManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	static int initLevel = 0;
	int status;

	assert( action == MANAGEMENT_ACTION_INIT || \
			action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			action == MANAGEMENT_ACTION_SHUTDOWN );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			status = netInitTCP();
			if( cryptStatusOK( status ) )
				{
				initLevel++;
				if( krnlIsExiting() )
					/* The kernel is shutting down, exit */
					return( CRYPT_ERROR_PERMISSION );
				status = initScoreboard( &scoreboardInfo, 
										 SESSIONCACHE_SIZE );
				}
			if( cryptStatusOK( status ) )
				initLevel++;
			return( status );

		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* We have to wait for the driver binding to complete before we
			   can start the shutdown process */
			krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );
			if( initLevel > 0 )
				netSignalShutdown();
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_SHUTDOWN:
			if( initLevel > 1 )
				endScoreboard( &scoreboardInfo );
			if( initLevel > 0 )
				netEndTCP();
			initLevel = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
#endif /* USE_SESSIONS */
