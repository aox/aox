/****************************************************************************
*																			*
*						 cryptlib SCEP Session Management					*
*						Copyright Peter Gutmann 1999-2005					*
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

#ifdef USE_SCEP

/* Various SCEP constants */

#define SCEP_NONCE_SIZE		16

/* The SCEP message type, status, and failure info.  For some bizarre
   reason these integer values are communicated as text strings */

#define MESSAGETYPE_CERTREP				"3"
#define MESSAGETYPE_PKCSREQ				"19"

#define MESSAGESTATUS_SUCCESS			"0"
#define MESSAGESTATUS_FAILURE			"2"
#define MESSAGESTATUS_PENDING			"3"

#define MESSAGEFAILINFO_BADALG			"0"
#define MESSAGEFAILINFO_BADMESSAGECHECK	"1"
#define MESSAGEFAILINFO_BADREQUEST		"2"
#define MESSAGEFAILINFO_BADTIME			"3"
#define MESSAGEFAILINFO_BADCERTID		"4"

/* Numeric equivalents of the above, to make them easier to work with */

#define MESSAGETYPE_CERTREP_VALUE		3
#define MESSAGETYPE_PKCSREQ_VALUE		19

#define MESSAGESTATUS_SUCCESS_VALUE		0
#define MESSAGESTATUS_FAILURE_VALUE		2
#define MESSAGESTATUS_PENDING_VALUE		3

/* SCEP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* Identification/state variable information.  SCEP uses a single
	   nonce, but when present in the initiator's message it's identified
	   as a sender nonce and when present in the responder's message
	   it's identified as a recipient nonce.
	
	   In order to accommodate nonstandard implementations, we allow for 
	   nonces that are slightly larger than the required size */
	BYTE transID[ CRYPT_MAX_HASHSIZE + 8 ];	/* Transaction nonce */
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];	/* Nonce */
	int transIDsize, nonceSize;

	/* When sending/receiving SCEP messages, the user has to sign the
	   request data and decrypt the response data.  Since they don't
	   have a cert at this point, they need to create an ephemeral
	   self-signed cert to handle this task */
	CRYPT_CERTIFICATE iScepCert;
	} SCEP_PROTOCOL_INFO;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise and clean up protocol info */

static void initProtocolInfo( SCEP_PROTOCOL_INFO *protocolInfo )
	{
	memset( protocolInfo, 0, sizeof( SCEP_PROTOCOL_INFO ) );
	protocolInfo->iScepCert = CRYPT_ERROR;
	}

static void destroyProtocolInfo( SCEP_PROTOCOL_INFO *protocolInfo )
	{
	if( protocolInfo->iScepCert != CRYPT_ERROR )
		krnlSendNotifier( protocolInfo->iScepCert, IMESSAGE_DECREFCOUNT );

	zeroise( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) );
	}

/* Check that the information supplied in a request matches what's stored for
   a PKI user */

static int checkPkiUserInfo( SESSION_INFO *sessionInfoPtr,
							 SCEP_PROTOCOL_INFO *protocolInfo )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	MESSAGE_DATA msgData;
	BYTE keyIDbuffer[ 64 + 8 ], *keyIDptr = userNamePtr->value;
	BYTE requestPassword[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE userPassword[ CRYPT_MAX_TEXTSIZE + 8 ];
	int requestPasswordSize, userPasswordSize;
	int keyIDsize = userNamePtr->valueLength, status;

	/* Get the password from the PKCS #10 request */
	setMessageData( &msgData, requestPassword, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_CHALLENGEPASSWORD );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't get challenge password from PKCS #10 request" );
	requestPasswordSize = msgData.length;

	/* If it's a cryptlib encoded user ID, we need to decode it before we can 
	   look up a PKI user with it */
	if( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		keyIDsize = decodePKIUserValue( keyIDbuffer, 64, userNamePtr->value, 
										userNamePtr->valueLength );
		keyIDptr = keyIDbuffer;
		}

	/* Get the user info for the request from the cert store */
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID, keyIDptr, 
						   keyIDsize, NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PKIUSER );
	if( cryptStatusError( status ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		retExt( sessionInfoPtr, status,
				"Couldn't get PKI user information for requested user" );
		}

	/* Get the password from the PKI user object */
	setMessageData( &msgData, userPassword, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( getkeyInfo.cryptHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD );
	if( cryptStatusError( status ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, status, 
				"Couldn't read PKI user data from PKI user object" );
		}
	userPasswordSize = msgData.length;
	updateSessionAttribute( &sessionInfoPtr->attributeList, 
							CRYPT_SESSINFO_PASSWORD, userPassword, 
							userPasswordSize, CRYPT_MAX_TEXTSIZE,
							ATTR_FLAG_ENCODEDVALUE );

	/* Make sure that the password matches the one in the request */
	if( userPasswordSize != requestPasswordSize || \
		memcmp( userPassword, requestPassword, userPasswordSize ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		zeroise( userPassword, CRYPT_MAX_TEXTSIZE );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, status, 
				"Supplied password doesn't match PKI user password" );
		}
	zeroise( userPassword, CRYPT_MAX_TEXTSIZE );

	/* If the subject only knows their CN, they may send a CN-only subject DN 
	   in the hope that we can fill it in for them.  In addition there may be 
	   other constraints that the CA wants to apply, these are handled by
	   applying the PKI user info to the request */
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_SETATTRIBUTE, &getkeyInfo.cryptHandle,
							  CRYPT_IATTRIBUTE_PKIUSERINFO );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_INVALID, 
				"User information in request can't be reconciled with our "
				"information for the user" );

	return( CRYPT_OK );
	}

/* For some bizarre reason integer status values are encoded as strings,
   so we have to convert them to numeric values before we can do anything
   with them */

static int getStatusValue( const CRYPT_CERTIFICATE iCmsAttributes,
						   const CRYPT_ATTRIBUTE_TYPE attributeType,
						   int *value )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ 128 + 8 ];
	int status;

	*value = CRYPT_ERROR;
	setMessageData( &msgData, buffer, 128 );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusError( status ) )
		return( status );
	buffer[ msgData.length ] = '\0';
	status = aToI( buffer );
	if( status == 0 && *buffer != '0' )
		/* atoi() can't really indicate an error except by returning 0, 
		   which is identical to an SCEP success status.  In order to
		   avoid having bad data seen as a successful result, we have
		   to check to make sure that a value of 0 really does correspond
		   to an input ASCII zero */
		return( CRYPT_ERROR_BADDATA );
	*value = status;
	return( CRYPT_OK );
	}

/* Convert a standard cert to a data-only cert.  This is easier than trying 
   to disconnect and re-connect certificate and context objects directly,
   which would be required for the ephemeral cert that we use to sign 
   requests */

static int createDataOnlyCert( CRYPT_CERTIFICATE *iNewCert,
							   const CRYPT_CERTIFICATE iCryptCert )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE buffer[ 2048 + 8 ], *bufPtr = buffer;
	int status;

	*iNewCert = CRYPT_ERROR;

	/* Export the current cert and re-import it in data-only format */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		if( msgData.length > 2048 && \
			( bufPtr = clDynAlloc( "createDataOnlyCert", \
								   msgData.length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		msgData.data = bufPtr;
		status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_CERTFORMAT_CERTIFICATE );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectIndirectInfo( &createInfo, msgData.data,
											msgData.length,
											CERTFORMAT_DATAONLY );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		}
	if( bufPtr != buffer )
		clFree( "createDataOnlyCert", bufPtr );
	if( cryptStatusOK( status ) )
		*iNewCert = createInfo.cryptHandle;
	return( status );
	}

/* Create a self-signed certificate for signing the request and decrypting
   the response */

static int createScepCert( SESSION_INFO *sessionInfoPtr,
						   SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iNewCert;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	/* Create a certificate, add the cert request and other information 
	   required by SCEP to it, and sign it.  SCEP requires that the 
	   certificate serial number match the user name/transaction ID, the 
	   spec actually says that the transaction ID should be a hash of the 
	   public key, but since it never specifies exactly what is hashed 
	   ("MD5 hash on [sic] public key") this can probably be anything.  We 
	   use the user name, which is required to identify the pkiUser entry 
	   in the CA cert store */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionInfoPtr->iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusOK( status ) )
		{
		const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );

		/* Set the serial number to the user name/transaction ID,
		   required by SCEP.  This is the only time that we can write a 
		   serial number to a certificate, normally it's set automagically
		   by the cert-management code */
		setMessageData( &msgData, userNamePtr->value,
						userNamePtr->valueLength );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_SERIALNUMBER );
		}
	if( cryptStatusOK( status ) )
		{
		static const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
									CRYPT_KEYUSAGE_KEYENCIPHERMENT;

		/* Set the cert usage to signing (to sign the request) and
		   encryption (to decrypt the response).  We delete the attribute
		   before we try and set it in case there was already one present
		   in the request */
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_DELETEATTRIBUTE, 
						 NULL, CRYPT_CERTINFO_KEYUSAGE );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, ( void * ) &keyUsage, 
								  CRYPT_CERTINFO_KEYUSAGE );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
								  CRYPT_CERTINFO_SELFSIGNED );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, status,
				"Couldn't create ephemeral self-signed SCEP certificate" );
		}

	/* Now that we have a cert, attach it to the private key.  This is 
	   somewhat ugly since it alters the private key by attaching a cert 
	   that (as far as the user is concerned) shouldn't really exist, but
	   we need to do this to allow signing and decryption.  A side-effect
	   is that it constrains the private-key actions to make them internal-
	   only since it now has a cert attached, hopefully the user won't
	   notice this since the key will have a proper CA-issued cert attached 
	   to it shortly.

	   To further complicate things, we can't directly attach the newly-
	   created cert because it already has a public-key context attached to
	   it, which would result in two keys being associated with the single
	   cert.  To resolve this, we create a second copy of the cert as a
	   data-only cert and attach that to the private key */
	status = createDataOnlyCert( &iNewCert, createInfo.cryptHandle );
	if( cryptStatusOK( status ) )
		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_SETDEPENDENT, 
						 &iNewCert, SETDEP_OPTION_NOINCREF );
	protocolInfo->iScepCert = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Complete the user-supplied PKCS #10 request by adding SCEP-internal
   attributes and information */

static int createScepRequest( SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	MESSAGE_DATA msgData;
	int status = CRYPT_ERROR_NOTINITED;

	/* Add the password to the PKCS #10 request as a ChallengePassword
	   attribute and sign the request.  We always send this in its
	   ASCII string form even if it's an encoded value because the
	   ChallengePassword attribute has to be a text string */
	if( attributeListPtr != NULL )
		{
		setMessageData( &msgData, attributeListPtr->value,
						attributeListPtr->valueLength );
		status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_CHALLENGEPASSWORD );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't finalise PKCS #10 cert request" );
	return( CRYPT_OK );
	}

/* Create SCEP signing attributes */

static int createScepAttributes( SESSION_INFO *sessionInfoPtr,
								 SCEP_PROTOCOL_INFO *protocolInfo,
								 CRYPT_CERTIFICATE *iScepAttributes,
								 const BOOLEAN isInitiator,
								 const int scepStatus )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	/* Clear return value */
	*iScepAttributes = CRYPT_ERROR;

	/* Create the signing attributes needed by SCEP and add the user name/
	   transaction ID and message type */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iCmsAttributes = createInfo.cryptHandle;
	setMessageData( &msgData, userNamePtr->value, userNamePtr->valueLength );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_TRANSACTIONID );
	if( cryptStatusOK( status ) )
		{
		const char *messageType = isInitiator ? MESSAGETYPE_PKCSREQ : \
												MESSAGETYPE_CERTREP;

		setMessageData( &msgData, ( void * ) messageType, 
						strlen( messageType ) );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_SCEP_MESSAGETYPE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the message status */
	if( !isInitiator && cryptStatusError( scepStatus ) )
		{
		const char *failInfo = ( scepStatus == CRYPT_ERROR_SIGNATURE ) ? \
				MESSAGEFAILINFO_BADMESSAGECHECK : MESSAGEFAILINFO_BADREQUEST;

		/* SCEP provides an extremely limited set of error codes so there's 
		   not much that we can return in the way of additional failure 
		   info */
		setMessageData( &msgData, ( void * ) failInfo, strlen( failInfo ) );
		krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_CERTINFO_SCEP_FAILINFO );
		setMessageData( &msgData, MESSAGESTATUS_FAILURE,
						strlen( MESSAGESTATUS_FAILURE ) );
		}
	else
		setMessageData( &msgData, MESSAGESTATUS_SUCCESS,
						strlen( MESSAGESTATUS_SUCCESS ) );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_PKISTATUS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the nonce, identified as a sender nonce if we're the initiator and 
	   a recipient nonce if we're the responder */
	if( isInitiator )
		{
		/* If we're the initiator, generate a new nonce */
		setMessageData( &msgData, protocolInfo->nonce, SCEP_NONCE_SIZE );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		protocolInfo->nonceSize = SCEP_NONCE_SIZE;
		}
	else
		/* We're the responder, use the initiator's nonce */
		setMessageData( &msgData, protocolInfo->nonce, 
						protocolInfo->nonceSize );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, isInitiator ? \
								CRYPT_CERTINFO_SCEP_SENDERNONCE : \
								CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) )
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	else
		*iScepAttributes = iCmsAttributes;
	return( status );
	}

/* Deliver an Einladung betreff Kehrseite to the client.  We don't bother
   checking the return value since there's nothing that we can do in the case 
   of an error except close the connection, which we do anyway since this is 
   the last message, and we don't return extended error information since 
   this would overwrite the information for the error that caused us to 
   return an error response */

static int sendErrorResponse( SESSION_INFO *sessionInfoPtr,
							  SCEP_PROTOCOL_INFO *protocolInfo,
							  const int scepStatus )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	int status;

	/* Sign the error response using the CA key and SCEP attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, FALSE, scepStatus );
	if( cryptStatusError( status ) )
		return( status );
	status = envelopeSign( sessionInfoPtr->receiveBuffer, 0,
						   sessionInfoPtr->receiveBuffer, 
						   &sessionInfoPtr->receiveBufEnd, 
						   sessionInfoPtr->receiveBufSize, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP( "scep_srespx", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Return the response to the client */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, NULL, TRUE );
	writePkiDatagram( sessionInfoPtr );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* Create an SCEP request message */

static int createPkcsRequest( SESSION_INFO *sessionInfoPtr,
							  SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_DATA msgData;
	int dataLength, status;

	/* Extract the request data into the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't get PKCS #10 request data from SCEP request object" );
	DEBUG_DUMP( "scep_req0", sessionInfoPtr->receiveBuffer, msgData.length );

	/* Phase 1: Encrypt the data using the CA's key */
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, msgData.length,
						   sessionInfoPtr->receiveBuffer, &dataLength, 
						   sessionInfoPtr->receiveBufSize,
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
						   sessionInfoPtr->iAuthInContext );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't encrypt request data with CA key" );
	DEBUG_DUMP( "scep_req1", sessionInfoPtr->receiveBuffer, dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, TRUE, CRYPT_OK );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't create SCEP request signing attributes" );

	/* Phase 2: Sign the data using the self-signed cert and SCEP attributes */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   &sessionInfoPtr->receiveBufEnd, 
						   sessionInfoPtr->receiveBufSize, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't sign request data with ephemeral SCEP "
				"certificate" );
	DEBUG_DUMP( "scep_req2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	return( CRYPT_OK );
	}

/* Check an SCEP response message */

static int checkPkcsResponse( SESSION_INFO *sessionInfoPtr,
							  SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int dataLength, sigResult, value, status;

	/* Phase 1: Sig.check the data using the CA's key */
	DEBUG_DUMP( "scep_resp2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, &dataLength, 
							   sessionInfoPtr->receiveBufSize, 
							   sessionInfoPtr->iAuthInContext, &sigResult,
							   NULL, &iCmsAttributes );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Invalid CMS signed data in CA response" );
	DEBUG_DUMP( "scep_res1", sessionInfoPtr->receiveBuffer, dataLength );
	if( cryptStatusError( sigResult ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, sigResult, 
				"Bad signature on CA response data" );
		}

	/* Check that the returned nonce matches our initial nonce.  It's now
	   identified as a recipient nonce since it's coming from the 
	   responder */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) || \
		msgData.length != protocolInfo->nonceSize || \
		memcmp( buffer, protocolInfo->nonce, protocolInfo->nonceSize ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
				"Returned nonce doesn't match our original nonce" );
		}

	/* Check that the operation succeeded */
	status = getStatusValue( iCmsAttributes,
							 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusOK( status ) && value != MESSAGETYPE_CERTREP_VALUE )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		status = getStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_PKISTATUS, &value );
	if( cryptStatusOK( status ) && value != MESSAGESTATUS_SUCCESS_VALUE )
		{
		sessionInfoPtr->errorCode = value;
		status = getStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_FAILINFO, &value );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->errorCode = value;
		status = CRYPT_ERROR_FAILED;
		}
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"SCEP server reports that certificate issue operation "
				"failed" );

	/* Phase 2: Decrypt the data using our self-signed key */
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
							 sessionInfoPtr->receiveBuffer, &dataLength, 
							 sessionInfoPtr->receiveBufSize,
							 sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't decrypt CMS enveloped data in CA response" );
	DEBUG_DUMP( "scep_res0", sessionInfoPtr->receiveBuffer, dataLength );

	/* Finally, import the returned cert(s) as a PKCS #7 chain */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTCHAIN );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Invalid PKCS #7 certificate chain in CA response" );
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Server-side Functions							*
*																			*
****************************************************************************/

/* Check an SCEP request message */

static int checkPkcsRequest( SESSION_INFO *sessionInfoPtr,
							 SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int dataLength, sigResult, value, status;

	/* Phase 1: Sig.check the self-signed data */
	DEBUG_DUMP( "scep_sreq2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, &dataLength, 
							   sessionInfoPtr->receiveBufSize, 
							   CRYPT_UNUSED, &sigResult, 
							   &protocolInfo->iScepCert, &iCmsAttributes );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Invalid CMS signed data in client request" );
	DEBUG_DUMP( "scep_sreq1", sessionInfoPtr->receiveBuffer, dataLength );
	if( cryptStatusError( sigResult ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, sigResult, 
				"Bad signature on client request data" );
		}

	/* Make sure that the client cert is valid for signing and decryption.
	   In effect the signing capability has already been checked by the fact
	   that the cert signed the request, but we do an explicit check here
	   just to be thorough */
	status = krnlSendMessage( protocolInfo->iScepCert, IMESSAGE_CHECK, 
							  NULL, MESSAGE_CHECK_PKC_SIGCHECK );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( protocolInfo->iScepCert, IMESSAGE_CHECK, 
								  NULL, MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_INVALID, 
				"Ephemeral SCEP client certificate isn't valid for "
				"signing/encryption" );
		}

	/* Get the nonce and transaction ID and save it for the reply */
	setMessageData( &msgData, protocolInfo->nonce, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_SENDERNONCE );
	if( cryptStatusOK( status ) )
		{
		protocolInfo->nonceSize = msgData.length;
		setMessageData( &msgData, protocolInfo->transID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
								  &msgData,
								  CRYPT_CERTINFO_SCEP_TRANSACTIONID );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Request is missing nonce/transaction ID" );
		}
	protocolInfo->transIDsize = msgData.length;

	/* We've got a transaction ID (user ID), remember it for later, 
	   remembering whether it's a cryptlib encoded ID */
	status = updateSessionAttribute( &sessionInfoPtr->attributeList,
						CRYPT_SESSINFO_USERNAME, protocolInfo->transID, 
						protocolInfo->transIDsize, CRYPT_MAX_HASHSIZE,
						( protocolInfo->transIDsize == 17 && \
						  isPKIUserValue( protocolInfo->transID, \
										  protocolInfo->transIDsize ) ) ? \
						ATTR_FLAG_ENCODEDVALUE : ATTR_FLAG_NONE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Check that we've been sent the correct type of message */
	status = getStatusValue( iCmsAttributes,
							 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusOK( status ) && value != MESSAGETYPE_PKCSREQ_VALUE )
		status = CRYPT_ERROR_BADDATA;
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Incorrect SCEP message type %d",
				value );

	/* Phase 2: Decrypt the data using our CA key */
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
							 sessionInfoPtr->receiveBuffer, &dataLength, 
							 sessionInfoPtr->receiveBufSize,
							 sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't decrypt CMS enveloped data in client request" );

	/* Finally, import the request as a PKCS #10 request */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTREQUEST );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Invalid PKCS #10 request in client request" );
	sessionInfoPtr->iCertRequest = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Create an SCEP response message */

static int createPkcsResponse( SESSION_INFO *sessionInfoPtr,
							   SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_DATA msgData;
	int dataLength, status;

	/* Extract the response data into the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTCHAIN );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't get PKCS #7 cert chain from SCEP response object" );
	DEBUG_DUMP( "scep_sresp0", sessionInfoPtr->receiveBuffer, msgData.length );

	/* Phase 1: Encrypt the data using the client's key */
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, msgData.length,
						   sessionInfoPtr->receiveBuffer, &dataLength, 
						   sessionInfoPtr->receiveBufSize,
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
						   protocolInfo->iScepCert );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't encrypt response data with client key" );
	DEBUG_DUMP( "scep_sresp1", sessionInfoPtr->receiveBuffer, dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, FALSE, CRYPT_OK );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't create SCEP response signing attributes" );

	/* Phase 2: Sign the data using the CA key and SCEP attributes */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   &sessionInfoPtr->receiveBufEnd, 
						   sessionInfoPtr->receiveBufSize, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't sign response data with CA key" );
	DEBUG_DUMP( "scep_sresp2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with an SCEP client/server */

static int clientTransact( SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	int status;

	/* Make sure that we have all of the needed information */
	if( sessionInfoPtr->iAuthInContext == CRYPT_ERROR )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CACERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Create the self-signed cert that we need in order to sign and decrypt 
	   messages */
	initProtocolInfo( &protocolInfo );
	status = createScepRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = createScepCert( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a new cert from the server */
	status = createPkcsRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_QUERY,
				"operation=PKIOperation", 22 );
		status = writePkiDatagram( sessionInfoPtr );
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_QUERY, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkPkcsResponse( sessionInfoPtr, &protocolInfo );
	krnlSendNotifier( protocolInfo.iScepCert, IMESSAGE_DECREFCOUNT );
	return( status );
	}

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	int status;

	/* Read the initial message from the client.  We don't write an error
	   response at the initial read stage to prevent scanning/DOS attacks 
	   (vir sapit qui pauca loquitur) */
	initProtocolInfo( &protocolInfo );
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkPkcsRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the request is permitted and convert it into a 
	   certificate */
	status = checkPkiUserInfo( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, 
							   NULL, 0, KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = sessionInfoPtr->iCertRequest;
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_SETKEY, &setkeyInfo, 
								  KEYMGMT_ITEM_REQUEST );
		if( cryptStatusError( status ) )
			strcpy( sessionInfoPtr->errorMessage, 
					"Request couldn't be added to cert store" );
		}
	if( cryptStatusOK( status ) )
		{
		MESSAGE_CERTMGMT_INFO certMgmtInfo;

		setMessageCertMgmtInfo( &certMgmtInfo, sessionInfoPtr->privateKey,
								sessionInfoPtr->iCertRequest );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
								  CRYPT_CERTACTION_ISSUE_CERT );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iCertResponse = certMgmtInfo.cryptCert;
		else
			strcpy( sessionInfoPtr->errorMessage,
					"Couldn't issue certificate for user" );
		}
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* Return the certificate to the client */
	status = createPkcsResponse( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = writePkiDatagram( sessionInfoPtr );
	destroyProtocolInfo( &protocolInfo );
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
	CRYPT_CERTIFICATE cryptCert = *( ( CRYPT_CERTIFICATE * ) data );
	int value, status;

	assert( type == CRYPT_SESSINFO_REQUEST || \
			type == CRYPT_SESSINFO_CACERTIFICATE );

	/* Make sure that everything is set up ready to go */
	status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_CERTINFO_IMMUTABLE );
#if 0
	if( cryptStatusError( status ) || !value )
		return( CRYPT_ARGERROR_NUM1 );
#else
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		{
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* For now we require that the PKCS #10 request be unsigned so that 
		   we can add the challengePassword */
		if( cryptStatusError( status ) || value )
			return( CRYPT_ARGERROR_NUM1 );
#endif
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		{
#if 0	/* RA certs aren't necessarily CA certs */
		/* Make sure that it really is a CA cert */
		status = krnlSendMessage( cryptCert, IMESSAGE_CHECK, NULL, 
								  MESSAGE_CHECK_CA );
		if( cryptStatusError( status ) )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_CA,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ARGERROR_NUM1 );
			}
#endif /* 0 */

		/* Make sure that it can sign and encrypt (normally a bad idea for CA
		   certs, but needed for SCEP) */
		status = krnlSendMessage( cryptCert, IMESSAGE_CHECK, NULL, 
								  MESSAGE_CHECK_PKC_SIGCHECK );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( cryptCert, IMESSAGE_CHECK, NULL, 
									  MESSAGE_CHECK_PKC_ENCRYPT );
		if( cryptStatusError( status ) )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( cryptCert, IMESSAGE_INCREFCOUNT );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		sessionInfoPtr->iAuthInContext = cryptCert;
	else
		sessionInfoPtr->iCertRequest = cryptCert;

	return( CRYPT_OK );
	}

static int checkAttributeFunction( SESSION_INFO *sessionInfoPtr,
								   const CRYPT_HANDLE cryptHandle,
								   const CRYPT_ATTRIBUTE_TYPE type )
	{
	int status;

	if( type != CRYPT_SESSINFO_PRIVATEKEY )
		return( CRYPT_OK );

	/* If it's a client key, make sure that there's no cert attached */
	if( !isServer( sessionInfoPtr ) )
		{
		int value;

		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusOK( status ) )
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodSCEP( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		SESSION_NEEDS_USERID |		/* Client attributes */
			SESSION_NEEDS_PASSWORD | \
			SESSION_NEEDS_PRIVATEKEY | \
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_REQUEST,
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_PRIVKEYCACERT | \
			SESSION_NEEDS_CERTSTORE,
		1, 1, 1,					/* Version 1 */
		"application/x-pki-message",/* Client content-type */
		"application/x-pki-message",/* Server content-type */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( isServer( sessionInfoPtr ) )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		sessionInfoPtr->transactFunction = clientTransact;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;
	sessionInfoPtr->checkAttributeFunction = checkAttributeFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SCEP */
