/****************************************************************************
*																			*
*						 cryptlib CMP Session Management					*
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
  #include "cmp.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

/* CMP requires a variety of authentication contexts, which are mapped to 
   session info contexts as follows:

			|	iAuthIn		|	iAuthOut
	--------+---------------+-------------------
	Client	|	CA cert		|	Client privKey
			|				|		or MAC
	Server	|	Client cert	|	CA privKey
			|		or MAC	|

   In addition general user information on the server side is stored in the 
   cmpUserInfo object */

#ifdef USE_CMP

/* If we're reading predefined requests/responses from disk instead of 
   communicating with the client/server, skip the network reads/writes */

#ifdef SKIP_IO
  #define readPkiDatagram( dummy )	CRYPT_OK
  #define writePkiDatagram( dummy )	CRYPT_OK
#endif /* SKIP_IO */

/* The following macro can be used to enable dumping of PDUs to disk.  As a
   safeguard, this only works in the Win32 debug version to prevent it from
   being accidentally enabled in any release version */

#if defined( __WIN32__ ) && !defined( NDEBUG )
/* #define DUMP_SERVER_MESSAGES */
  #define DEBUG_DUMP_CMP( type, level, sessionInfo ) \
		  debugDump( type, level, sessionInfo )
#else
  #define DEBUG_DUMP_CMP( type, level, sessionInfo )
#endif /* Win32 debug */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if defined( __WIN32__ ) && !defined( NDEBUG )

/* Dump a message to disk for diagnostic purposes.  The CMP messages are
   complex enough that we can't use the normal DEBUG_DUMP() macro but have
   to use a special-purpose function that uses meaningful names for all
   of the files that are created */

static void debugDump( const int type, const int phase,
					   const SESSION_INFO *sessionInfoPtr )
	{
	static const FAR_BSS char *irStrings[] = \
		{ "cmpi1_ir", "cmpi2_ip", "cmpi3_conf", "cmpi4_confack" };
	static const FAR_BSS char *crStrings[] = \
		{ "cmpc1_cr", "cmpc2_cp", "cmpc3_conf", "cmpc4_confack" };
	static const FAR_BSS char *kurStrings[] = \
		{ "cmpk1_kur", "cmpk2_kup", "cmpk3_conf", "cmpk4_confack" };
	static const FAR_BSS char *rrStrings[] = \
		{ "cmpr1_rr", "cmpr2_rp" };
	static const FAR_BSS char *gmStrings[] = \
		{ "cmpg1_gr", "cmpg2_gp" };
	static const FAR_BSS char *errorStrings[] = \
		{ "cmpe1_error" };
	static const FAR_BSS char *unkStrings[] = \
		{ "cmp_unknown1", "cmp_unknown2", "cmp_unknown3", "cmp_unknown4" };
	const char **fnStringPtr = ( type == CTAG_PB_IR ) ? irStrings : \
							   ( type == CTAG_PB_CR ) ? crStrings : \
							   ( type == CTAG_PB_KUR ) ? kurStrings : \
							   ( type == CTAG_PB_RR ) ? rrStrings : \
							   ( type == CTAG_PB_GENM ) ? gmStrings : \
							   ( type == CTAG_PB_ERROR ) ? errorStrings : \
							  unkStrings;
	FILE *filePtr;
	char fileName[ 1024 ];

#ifndef DUMP_SERVER_MESSAGES
	/* Server messages have complex names based on the server DN, so we only 
	   dump them if explicitly requested */
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		return;
#endif /* !DUMP_SERVER_MESSAGES */

/*	GetTempPath( 512, fileName ); */
	strcpy( fileName, "/tmp/" );
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		{
		RESOURCE_DATA msgData;
		const int pathLength = strlen( fileName );
		int i;

		setMessageData( &msgData, fileName + pathLength, 1024 - pathLength );
		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_CERTINFO_DN );
		for( i = 0; i < msgData.length; i++ )
			{
			const int ch = fileName[ pathLength + i ];

			if( ch == ' ' || ch == '\'' || ch == '"' || ch == '?' || \
				ch == '*' || ch == '[' || ch == ']' || ch == '`' || \
				ch == ',' || ch < ' ' || ch > 'z' )
				fileName[ pathLength + i ] = '_';
			}
		strcat( fileName, "_" );
		}
	strcat( fileName, fnStringPtr[ phase - 1 ] );
	strcat( fileName, ".der" );

	filePtr = fopen( fileName, "wb" );
	if( filePtr != NULL )
		{
		fwrite( sessionInfoPtr->receiveBuffer, 1,
				sessionInfoPtr->receiveBufEnd, filePtr );
		fclose( filePtr );
		}
	}
#endif /* Windows debug mode only */

/* Map request to response types */

static const struct {
	const int request, response;
	const int cryptlibRequest;
	} reqRespMapTbl[] = {
	{ CTAG_PB_IR, CTAG_PB_IP, CRYPT_REQUESTTYPE_INITIALISATION },
	{ CTAG_PB_CR, CTAG_PB_CP, CRYPT_REQUESTTYPE_CERTIFICATE },
	{ CTAG_PB_P10CR, CTAG_PB_CP, CRYPT_REQUESTTYPE_CERTIFICATE },
	{ CTAG_PB_POPDECC, CTAG_PB_POPDECR, CRYPT_ERROR },
	{ CTAG_PB_KUR, CTAG_PB_KUP, CRYPT_REQUESTTYPE_KEYUPDATE },
	{ CTAG_PB_KRR, CTAG_PB_KRP, CRYPT_ERROR },
	{ CTAG_PB_RR, CTAG_PB_RP, CRYPT_REQUESTTYPE_REVOCATION },
	{ CTAG_PB_CCR, CTAG_PB_CCP, CRYPT_ERROR },
	{ CTAG_PB_GENM, CTAG_PB_GENP, CRYPT_REQUESTTYPE_PKIBOOT },
	{ CTAG_PB_LAST, CTAG_PB_LAST, CRYPT_ERROR }
	};

int reqToResp( const int reqType )
	{
	int i;

	for( i = 0; reqRespMapTbl[ i ].request != reqType && \
				reqRespMapTbl[ i ].request != CTAG_PB_LAST; i++ );
	return( reqRespMapTbl[ i ].response );
	}
static int reqToClibReq( const int reqType )
	{
	int i;

	for( i = 0; reqRespMapTbl[ i ].request != reqType && \
				reqRespMapTbl[ i ].request != CTAG_PB_LAST; i++ );
	return( reqRespMapTbl[ i ].cryptlibRequest );
	}
static int clibReqToReq( const int reqType )
	{
	int i;

	for( i = 0; reqRespMapTbl[ i ].cryptlibRequest != reqType && \
				reqRespMapTbl[ i ].request != CTAG_PB_LAST; i++ );
	return( reqRespMapTbl[ i ].request );
	}

/* Initialise the MAC info used to protect the messages */

int initMacInfo( const CRYPT_CONTEXT iMacContext, const void *userPassword, 
				 const int userPasswordLength, const void *salt, 
				 const int saltLength, const int iterations )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	BYTE macKey[ CRYPT_MAX_HASHSIZE ];
	const void *passwordPtr = userPassword;
	int passwordLength = userPasswordLength, status;

	/* Turn the user password into an HMAC key using the CMP/Entrust password
	   derivation mechanism */
	setMechanismDeriveInfo( &mechanismInfo, macKey, CMP_HMAC_KEYSIZE,
							passwordPtr, passwordLength, CRYPT_ALGO_SHA,
							( void * ) salt, saltLength, iterations );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
							  &mechanismInfo, MECHANISM_DERIVE_CMP );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the MAC context */
	setMessageData( &msgData, macKey, CMP_HMAC_KEYSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_KEY );
	zeroise( macKey, CRYPT_MAX_HASHSIZE );
	return( status );
	}

/* Initialise and destroy the protocol state information */

#define PROTOCOLINFO_SET_USERID		0x01
#define PROTOCOLINFO_SET_TRANSID	0x02
#define PROTOCOLINFO_SET_MACINFO	0x04
#define PROTOCOLINFO_SET_MACCTX		0x08
#define PROTOCOLINFO_SET_ALL		( PROTOCOLINFO_SET_USERID | \
									  PROTOCOLINFO_SET_TRANSID | \
									  PROTOCOLINFO_SET_MACINFO | \
									  PROTOCOLINFO_SET_MACCTX )

static void initProtocolInfo( CMP_PROTOCOL_INFO *protocolInfo, 
							  const BOOLEAN isCryptlib )
	{
	memset( protocolInfo, 0, sizeof( CMP_PROTOCOL_INFO ) );
	protocolInfo->iMacContext = protocolInfo->iAltMacContext = CRYPT_ERROR;
	protocolInfo->authContext = CRYPT_ERROR;
	if( isCryptlib )
		protocolInfo->isCryptlib = TRUE;
	}

static int setProtocolInfo( CMP_PROTOCOL_INFO *protocolInfo, 
							const void *userID, const int userIDlength, 
							const int flags )
	{
	RESOURCE_DATA msgData;
	int status;

	/* Set state info */
	setMessageData( &msgData, protocolInfo->senderNonce, CMP_NONCE_SIZE );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	protocolInfo->senderNonceSize = CMP_NONCE_SIZE;

	/* Set fixed identification information */
	if( flags & PROTOCOLINFO_SET_USERID )
		{
		assert( isReadPtr( userID, userIDlength ) );
		memcpy( protocolInfo->userID, userID, userIDlength );
		protocolInfo->userIDsize = userIDlength;
		}
	if( flags & PROTOCOLINFO_SET_TRANSID )
		{
		setMessageData( &msgData, protocolInfo->transID, CMP_NONCE_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->transIDsize = CMP_NONCE_SIZE;
		}

	/* Set the MAC info and context */
	if( flags & PROTOCOLINFO_SET_MACINFO )
		{
		setMessageData( &msgData, protocolInfo->salt, CMP_NONCE_SIZE );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		protocolInfo->saltSize = CMP_NONCE_SIZE;
		protocolInfo->iterations = CMP_PASSWORD_ITERATIONS;
		}
	if( flags & PROTOCOLINFO_SET_MACCTX )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		assert( protocolInfo->iMacContext == CRYPT_ERROR && \
				protocolInfo->iAltMacContext == CRYPT_ERROR );
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_HMAC_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->iMacContext = createInfo.cryptHandle;
		protocolInfo->useMACsend = protocolInfo->useMACreceive = TRUE;
		}

	return( CRYPT_OK );
	}

static void destroyProtocolInfo( CMP_PROTOCOL_INFO *protocolInfo )
	{
	/* Destroy any active MAC contexts.  The authContext is just a reference 
	   to the appropriate context in the session info so we don't destroy it 
	   here */
	if( protocolInfo->iMacContext != CRYPT_ERROR )
		krnlSendNotifier( protocolInfo->iMacContext, IMESSAGE_DECREFCOUNT );
	if( protocolInfo->iAltMacContext != CRYPT_ERROR )
		krnlSendNotifier( protocolInfo->iMacContext, IMESSAGE_DECREFCOUNT );

	zeroise( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) );
	}

/* Set up user authentication information (either a MAC context or a public 
   key) based on a request submitted by the client.  This is done whenever 
   the client starts a new transaction with a new user ID or cert ID */

int initServerAuthentMAC( SESSION_INFO *sessionInfoPtr, 
						  CMP_PROTOCOL_INFO *protocolInfo )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	/* Set up general authentication information and if there's user info 
	   still present from a previous transaction, clear it */
	status = setProtocolInfo( protocolInfo, NULL, 0, 
							  PROTOCOLINFO_SET_MACCTX );
	if( cryptStatusError( status ) )
		return( status );
	if( cmpInfo->userInfo != CRYPT_ERROR )
		{
		krnlSendNotifier( cmpInfo->userInfo, IMESSAGE_DECREFCOUNT );
		cmpInfo->userInfo = CRYPT_ERROR;
		}

	/* Get the user info for the user identified by the user ID from the 
	   cert store.  If we get a not-found error we report it as "signer not 
	   trusted", which can also mean "signer unknown".
	   
	   In theory we could perform a quick-reject check that the userID is 
	   the correct length for a cryptlib-created ID (9 bytes), but it's 
	   better to pass it into the system and let the failure come back
	   through the standard error-handling mechanisms */
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
						   protocolInfo->userID, protocolInfo->userIDsize, 
						   NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PKIUSER );
	if( cryptStatusError( status ) )
		{
		const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
		char userID[ CRYPT_MAX_TEXTSIZE + 8 ];

		if( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE && \
			userNamePtr->valueLength > 10 && \
			userNamePtr->valueLength < CRYPT_MAX_TEXTSIZE )
			{
			memcpy( userID, userNamePtr->value, userNamePtr->valueLength );
			userID[ userNamePtr->valueLength ] = '\0';
			}
		else
			strcpy( userID, "the requested user" );
		protocolInfo->pkiFailInfo = CMPFAILINFO_SIGNERNOTTRUSTED;
		retExt( sessionInfoPtr, status, 
				"Couldn't find PKI user information for %s",
				userID );
		}
	cmpInfo->userInfo = getkeyInfo.cryptHandle;
	protocolInfo->userIDchanged = FALSE;

	/* Get the password from the PKI user object if necessary */
	if( findSessionAttribute( sessionInfoPtr->attributeList,
							  CRYPT_SESSINFO_PASSWORD ) == NULL )
		{
		RESOURCE_DATA msgData;
		char password[ CRYPT_MAX_TEXTSIZE + 8 ];

		setMessageData( &msgData, password, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( cmpInfo->userInfo,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status, 
					"Couldn't read PKI user data from PKI user object" );
		updateSessionAttribute( &sessionInfoPtr->attributeList,
								CRYPT_SESSINFO_PASSWORD, password, 
								msgData.length, CRYPT_MAX_TEXTSIZE,
								ATTR_FLAG_ENCODEDVALUE );
		zeroise( password, CRYPT_MAX_TEXTSIZE );
		}

	return( CRYPT_OK );
	}

int initServerAuthentSign( SESSION_INFO *sessionInfoPtr, 
						   CMP_PROTOCOL_INFO *protocolInfo )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	/* Set up general authentication information and if there's client auth. 
	   info still present from a previous transaction that used MAC
	   authentication, clear it */
	status = setProtocolInfo( protocolInfo, NULL, 0, 0 );
	if( cryptStatusError( status ) )
		return( status );
	if( cmpInfo->userInfo != CRYPT_ERROR )
		{
		krnlSendNotifier( cmpInfo->userInfo, IMESSAGE_DECREFCOUNT );
		cmpInfo->userInfo = CRYPT_ERROR;
		}

	/* Get the user info for the user that originally authorised the issue
	   of the cert that signed the request.  This serves two purposes, it 
	   obtains the user ID if it wasn't supplied in the request (for example 
	   if the request uses only a cert ID), and it verifies that the 
	   authorising cert belongs to a valid user */
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID,
						   protocolInfo->certID, protocolInfo->certIDsize, 
						   NULL, 0, KEYMGMT_FLAG_GETISSUER );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PKIUSER );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_SIGNERNOTTRUSTED;
		retExt( sessionInfoPtr, status, 
				"Couldn't find PKI user information for owner of requesting "
				"cert" );
		}

	/* If there's currently no user ID present or if it's present but it's a
	   non-userID value such as a cert ID, replace it with the PKI user ID */
	if( userNamePtr == NULL || \
		!( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE ) )
		{
		RESOURCE_DATA msgData;
		char userName[ CRYPT_MAX_TEXTSIZE + 8 ];

		setMessageData( &msgData, userName, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( getkeyInfo.cryptHandle,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_PKIUSER_ID );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			retExt( sessionInfoPtr, status, 
					"Couldn't read PKI user data from PKI user object" );
			}
		updateSessionAttribute( &sessionInfoPtr->attributeList,
								CRYPT_SESSINFO_USERNAME, userName, 
								msgData.length, CRYPT_MAX_TEXTSIZE,
								ATTR_FLAG_ENCODEDVALUE );
		}
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	/* Get the public key identified by the cert ID from the cert store.  
	   This assumes that the owner of an existing cert/existing user is 
	   authorised to request further certs using the existing one.  If we 
	   get a not found error we report it as "signer not trusted", which 
	   can also mean "signer unknown" */
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID,
						   protocolInfo->certID, protocolInfo->certIDsize, 
						   NULL, 0, KEYMGMT_FLAG_USAGE_SIGN );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_SIGNERNOTTRUSTED;
		retExt( sessionInfoPtr, status, 
				"Couldn't find certificate for requested user" );
		}
	sessionInfoPtr->iAuthInContext = getkeyInfo.cryptHandle;
	protocolInfo->userIDchanged = FALSE;

	return( CRYPT_OK );
	}

/* Hash/MAC the message header and body */

int hashMessageContents( const CRYPT_CONTEXT iHashContext,
						 const void *data, const int length )
	{
	STREAM stream;
	BYTE buffer[ 8 ];

	/* Delete the hash/MAC value, which resets the context */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_HASHVALUE );

	/* Write the pseudoheader used for hashing/MACing the header and body and
	   hash/MAC it */
	sMemOpen( &stream, buffer, 8 );
	writeSequence( &stream, length );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 
					 stell( &stream ) );
	sMemClose( &stream );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data, 
					 length );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 0 ) );
	}

/* Deliver an Einladung betreff Kehrseite to the client.  We don't bother
   checking the return value since there's nothing that we can do in the 
   case of an error except close the connection, which we do anyway since 
   this is the last message */

static void sendErrorResponse( SESSION_INFO *sessionInfoPtr,
							   CMP_PROTOCOL_INFO *protocolInfo,
							   const int status )
	{
	/* If we were going to protect the communication with the client with a
	   MAC and something failed, make sure that we don't try and MAC the
	   response since the failure could be a client MAC failure, failure to
	   locate the MAC key, etc etc */
	protocolInfo->useMACsend = FALSE;
	protocolInfo->status = status;
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, NULL, TRUE );
	writePkiMessage( sessionInfoPtr, protocolInfo, CMPBODY_ERROR );
	DEBUG_DUMP_CMP( CTAG_PB_ERROR, 1, sessionInfoPtr );
	writePkiDatagram( sessionInfoPtr );
	}

/* Set up information needed to perform a client-side transaction */

static int initClientInfo( SESSION_INFO *sessionInfoPtr,
						   CMP_PROTOCOL_INFO *protocolInfo )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	int status;

	assert( !( sessionInfoPtr->flags & SESSION_ISSERVER ) );

	/* Determine what we need to do based on the request type */
	protocolInfo->operation = clibReqToReq( cmpInfo->requestType );

	/* If we're using public key-based authentication, set up the key and 
	   user ID information */
	if( cmpInfo->requestType != CRYPT_REQUESTTYPE_PKIBOOT && \
		cmpInfo->requestType != CRYPT_REQUESTTYPE_INITIALISATION && \
		!( cmpInfo->requestType == CRYPT_REQUESTTYPE_REVOCATION && \
		   passwordPtr != NULL ) )
		{
		/* If it's an encryption-only key, remember this for later when we 
		   need to authenticate our request messages */
		status = krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_CHECK, 
								  NULL, MESSAGE_CHECK_PKC_SIGN );
		if( cryptStatusError( status ) )
			{
			/* The private key can't be used for signature creation, use
			   the alternate authentication key instead */
			protocolInfo->authContext = sessionInfoPtr->iAuthOutContext;
			protocolInfo->cryptOnlyKey = TRUE;
			}
		else
			/* The private key that we're using is capable of authenticating 
			   requests */
			protocolInfo->authContext = sessionInfoPtr->privateKey;

		/* If we're not talking to a cryptlib peer, get the user ID.  If 
		   it's a standard signed request the authenticating object will be 
		   the private key, however if the private key is an encryption-only 
		   key the message authentication key is a separate object.  To 
		   handle this we get the user ID from the signing key rather than 
		   automatically using the private key */
		if( !protocolInfo->isCryptlib )
			{
			RESOURCE_DATA msgData;
			BYTE userID[ CRYPT_MAX_HASHSIZE ];

			setMessageData( &msgData, userID, CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( protocolInfo->authContext, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
			if( cryptStatusOK( status ) )
				status = setProtocolInfo( protocolInfo, userID, 
										  msgData.length, 
										  PROTOCOLINFO_SET_USERID | \
										  PROTOCOLINFO_SET_TRANSID );
			return( status );
			}

		/* It's a cryptlib peer, the cert is identified by an unambiguous 
		   cert ID */
		return( setProtocolInfo( protocolInfo, NULL, 0, 
								 PROTOCOLINFO_SET_TRANSID ) );
		}

	/* If there's a MAC context present from a previous transaction, reuse 
	   it for the current one */
	if( cmpInfo->savedMacContext != CRYPT_ERROR )
		{
		setProtocolInfo( protocolInfo, NULL, 0, PROTOCOLINFO_SET_TRANSID );
		protocolInfo->useMACsend = protocolInfo->useMACreceive = TRUE;
		protocolInfo->iMacContext = cmpInfo->savedMacContext;
		cmpInfo->savedMacContext = CRYPT_ERROR;
		return( CRYPT_OK );
		}

	/* We're using MAC authentication, initialise the protocol info */
	if( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		BYTE decodedValue[ CRYPT_MAX_TEXTSIZE ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded user ID, decode it into its binary 
		   value */
		decodedValueLength = decodePKIUserValue( decodedValue,
												 userNamePtr->value, 
												 userNamePtr->valueLength );
		if( cryptStatusError( decodedValueLength ) )
			{
			assert( NOTREACHED );
			retExt( sessionInfoPtr, decodedValueLength, 
					"Invalid PKI user value" );
			}
		status = setProtocolInfo( protocolInfo, decodedValue,
								  decodedValueLength, PROTOCOLINFO_SET_ALL );
		zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
		}
	else
		/* It's a standard user ID, use it as is */
		status = setProtocolInfo( protocolInfo, userNamePtr->value,
								  userNamePtr->valueLength, 
								  PROTOCOLINFO_SET_ALL );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the MAC context used to authenticate messages */
	if( passwordPtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		BYTE decodedValue[ CRYPT_MAX_TEXTSIZE ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary 
		   value */
		decodedValueLength = decodePKIUserValue( decodedValue,
						passwordPtr->value, passwordPtr->valueLength );
		if( cryptStatusError( decodedValueLength ) )
			{
			assert( NOTREACHED );
			retExt( sessionInfoPtr, decodedValueLength, 
					"Invalid PKI user value" );
			}
		status = initMacInfo( protocolInfo->iMacContext, decodedValue, 
							  decodedValueLength, protocolInfo->salt, 
							  protocolInfo->saltSize, 
							  protocolInfo->iterations );
		zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
		}
	else
		/* It's a standard password, use it as is */
		status = initMacInfo( protocolInfo->iMacContext,
							  passwordPtr->value, passwordPtr->valueLength,
							  protocolInfo->salt, protocolInfo->saltSize,
							  protocolInfo->iterations );
	return( status );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Prepare a CMP session */

static int clientStartup( SESSION_INFO *sessionInfoPtr )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	NET_CONNECT_INFO connectInfo;
	int status;

	/* Make sure that we have all the needed information.  Plug-and-play PKI 
	   uses PKIBoot to get the CA cert and generates the requests internally, 
	   so we only need to check for these values if we're doing standard 
	   CMP.  The check for user ID and authentication information has
	   already been done at the general session level */
	if( !( cmpInfo->flags & CMP_PFLAG_PNPPKI ) )
		{
		if( cmpInfo->requestType == CRYPT_REQUESTTYPE_NONE )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_REQUESTTYPE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		if( sessionInfoPtr->iAuthInContext == CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CACERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		if( cmpInfo->requestType != CRYPT_REQUESTTYPE_PKIBOOT && \
			sessionInfoPtr->iCertRequest == CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_REQUEST,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}

/*-----------------------------------------------------------------------*/
#ifdef SKIP_IO
goto skipIO;
#endif /* SKIP_IO */
/*-----------------------------------------------------------------------*/
	/* Connect to the remote server */
	initSessionNetConnectInfo( sessionInfoPtr, &connectInfo );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		status = sNetConnect( &sessionInfoPtr->stream,
							  STREAM_PROTOCOL_HTTP_TRANSACTION, 
							  &connectInfo, sessionInfoPtr->errorMessage, 
							  &sessionInfoPtr->errorCode );
	else
		{
		const ALTPROTOCOL_INFO *altProtocolInfoPtr = \
									protocolInfoPtr->altProtocolInfo;

		assert( sessionInfoPtr->flags & SESSION_USEALTTRANSPORT );

		/* If we're using the HTTP port for a session-specific protocol, 
		   change it to the default port for the session-specific protocol 
		   instead */
		if( connectInfo.port == 80 )
			connectInfo.port = altProtocolInfoPtr->port;
		status = sNetConnect( &sessionInfoPtr->stream, 
							  altProtocolInfoPtr->type, 
							  &connectInfo, sessionInfoPtr->errorMessage, 
							  &sessionInfoPtr->errorCode );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONTENTTYPE,
				( void * ) protocolInfoPtr->clientContentType, 
				strlen( protocolInfoPtr->clientContentType ) );
	return( CRYPT_OK );
	}

/* Shut down a CMP session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;

	/* Clean up CMP-specific objects */
	if( cmpInfo->userInfo != CRYPT_ERROR )
		krnlSendNotifier( cmpInfo->userInfo, IMESSAGE_DECREFCOUNT );
	if( cmpInfo->savedMacContext != CRYPT_ERROR )
		krnlSendNotifier( cmpInfo->savedMacContext, IMESSAGE_DECREFCOUNT );

	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Exchange data with a CMP client/server.  Since the plug-and-play PKI 
   client performs multiple transactions, we wrap the basic clientTransact() 
   in an external function that either calls it indirectly when required 
   from the PnP code or just passes the call through to the transaction 
   function */

static int clientTransact( SESSION_INFO *sessionInfoPtr )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	CMP_PROTOCOL_INFO protocolInfo;
	int status;

	/* Check that everything we need is present.  If it's a general CMP 
	   session this will already have been checked in clientStartup(), but
	   if it's coming from the PnPPKI wrapper it doesn't go through the
	   startup checks each time so we double-check here.  Since any problem
	   is just a one-off programming error, we only need a debug assertion
	   rather than a hardcoded check */
	assert( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE );
	assert( cmpInfo->requestType == CRYPT_REQUESTTYPE_PKIBOOT || \
			sessionInfoPtr->iCertRequest != CRYPT_ERROR );
	assert( cmpInfo->requestType == CRYPT_REQUESTTYPE_PKIBOOT || \
			sessionInfoPtr->iAuthInContext != CRYPT_ERROR );

	/* Initialise the client-side protocol state info */
	initProtocolInfo( &protocolInfo, 
					  sessionInfoPtr->flags & SESSION_ISCRYPTLIB );
	status = initClientInfo( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		{
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* Write the message into the session buffer and send it to the server */
	status = writePkiMessage( sessionInfoPtr, &protocolInfo, 
							  ( cmpInfo->requestType == \
									CRYPT_REQUESTTYPE_PKIBOOT ) ? \
							  CMPBODY_GENMSG : CMPBODY_NORMAL );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_CMP( protocolInfo.operation, 1, sessionInfoPtr );
		if( ( protocolInfo.operation == CTAG_PB_GENM || \
			  protocolInfo.operation == CTAG_PB_RR ) && \
			!( sessionInfoPtr->protocolFlags & CMP_PFLAG_RETAINCONNECTION ) )
			/* There's no confirmation handshake for PKIBoot or a revocation 
			   request so we mark this as the last message if required */
			sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, NULL,
					TRUE );
		status = writePkiDatagram( sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		{
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* Read the server response */
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_CMP( protocolInfo.operation, 2, sessionInfoPtr );
		status = readPkiMessage( sessionInfoPtr, &protocolInfo, 
								 reqToResp( protocolInfo.operation ) );
		}
	if( cryptStatusOK( status ) && protocolInfo.operation == CTAG_PB_GENM )
		{
		/* It's a PKIBoot, add the trusted certs.  If the user wants the 
		   setting made permanent, they need to flush the config to disk 
		   after the session has completed */
		status = krnlSendMessage( sessionInfoPtr->ownerHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  &sessionInfoPtr->iCertResponse,
								  CRYPT_IATTRIBUTE_CTL );
		if( status == CRYPT_ERROR_INITED )
			/* If the certs are already present, trying to add them again
			   isn't an error */
			status = CRYPT_OK;
		}
	if( cryptStatusError( status ) )
		{
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* If it's a transaction type that doesn't need a confirmation, we're 
	   done */
	if( protocolInfo.operation == CTAG_PB_GENM || \
		protocolInfo.operation == CTAG_PB_RR )
		{
		if( protocolInfo.iMacContext != CRYPT_ERROR )
			{
			/* Remember the authentication context in case we can reuse it 
			   for another transaction */
			cmpInfo->savedMacContext = protocolInfo.iMacContext;
			protocolInfo.iMacContext = CRYPT_ERROR;
			}
		destroyProtocolInfo( &protocolInfo );
		return( CRYPT_OK );
		}

	/* Exchange confirmation data with the server */
	if( !( sessionInfoPtr->protocolFlags & CMP_PFLAG_RETAINCONNECTION ) )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, NULL, 
				TRUE );
	status = writePkiMessage( sessionInfoPtr, &protocolInfo,
							  CMPBODY_CONFIRMATION );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_CMP( protocolInfo.operation, 3, sessionInfoPtr );
		status = writePkiDatagram( sessionInfoPtr );
		}
	if( cryptStatusOK( status ) )
		status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_CMP( protocolInfo.operation, 4, sessionInfoPtr );
		status = readPkiMessage( sessionInfoPtr, &protocolInfo, CTAG_PB_PKICONF );
		}
	if( cryptStatusOK( status ) && protocolInfo.iMacContext != CRYPT_ERROR )
		{
		/* Remember the authentication context in case we can reuse it for 
		   another transaction */
		cmpInfo->savedMacContext = protocolInfo.iMacContext;
		protocolInfo.iMacContext = CRYPT_ERROR;
		}
	destroyProtocolInfo( &protocolInfo );
	return( status );
	}

static int clientTransactWrapper( SESSION_INFO *sessionInfoPtr )
	{
	if( sessionInfoPtr->sessionCMP->flags & CMP_PFLAG_PNPPKI )
		{
		int status;

		/* If we're doing plug-and-play PKI, point the transaction function 
		   at the client-transact function to execute the PnP steps, then 
		   reset it back to the PnP wrapper after we're done */
		sessionInfoPtr->transactFunction = clientTransact;
		status = pnpPkiSession( sessionInfoPtr );
		sessionInfoPtr->transactFunction = clientTransactWrapper;
		return( status );
		}
	return( clientTransact( sessionInfoPtr ) );
	}

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	MESSAGE_CERTMGMT_INFO certMgmtInfo;
	CMP_PROTOCOL_INFO protocolInfo;
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	int status;

	/* Initialise the server-side protocol state info.  Since the server 
	   doesn't have a user ID (it uses what the client sends it), we set the
	   userID-sent flag to indicate that it's been implicitly exchanged */
	initProtocolInfo( &protocolInfo,
					  sessionInfoPtr->flags & SESSION_ISCRYPTLIB );
	protocolInfo.authContext = sessionInfoPtr->privateKey;
	sessionInfoPtr->protocolFlags |= CMP_PFLAG_USERIDSENT;
	if( userNamePtr != NULL )
		{
		/* There's already user info present from a previous transaction, 
		   try and re-use the info from it (this can be overridden by the
		   client sending us new user info) */
		if( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE )
			/* It's a cryptlib-style encoded user ID, decode it into its 
			   binary value */
			protocolInfo.userIDsize = \
					decodePKIUserValue( protocolInfo.userID,
										userNamePtr->value,
										userNamePtr->valueLength );
		else
			{
			/* It's a standard user ID, use it as is */
			memcpy( protocolInfo.userID, userNamePtr->value, 
					userNamePtr->valueLength );
			protocolInfo.userIDsize = userNamePtr->valueLength;
			}
		protocolInfo.iMacContext = cmpInfo->savedMacContext;
		cmpInfo->savedMacContext = CRYPT_ERROR;
		}

	/* Read the initial message from the client.  We don't write an error
	   response at the initial read stage to prevent scanning/DOS attacks 
	   (vir sapit qui pauca loquitur) */
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusError( status ) )
		{
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}
	status = readPkiMessage( sessionInfoPtr, &protocolInfo,
							 CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}
	DEBUG_DUMP_CMP( protocolInfo.operation, 1, sessionInfoPtr );
	cmpInfo->requestType = reqToClibReq( protocolInfo.operation );

	/* If it's a PKIBoot request, send the PKIBoot response and retry the 
	   read unless the client closes the stream.  This assumes that the 
	   client will generally send a PKIBoot request in conjunction with a 
	   cert management request (i.e. as part of a PnP PKI transaction), 
	   which allows us to reuse the user authentication info to process the 
	   request that follows the PKIBoot */
	if( cmpInfo->requestType == CRYPT_REQUESTTYPE_PKIBOOT )
		{
		int streamState;

		/* Handle the PKIBoot request */
		status = writePkiMessage( sessionInfoPtr, &protocolInfo, 
								  CMPBODY_GENMSG );
		if( cryptStatusOK( status ) )
			{
			DEBUG_DUMP_CMP( CTAG_PB_GENM, 2, sessionInfoPtr );
			status = writePkiDatagram( sessionInfoPtr );
			}
		if( cryptStatusError( status ) )
			{
			sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
			destroyProtocolInfo( &protocolInfo );
			return( status );
			}

		/* Check whether the client left the stream open.  If they haven't,
		   it was a standalone PKIBoot request and we're done */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONNSTATE, 
				&streamState, 0 );
		if( !streamState )
			{
			destroyProtocolInfo( &protocolInfo );
			return( CRYPT_OK );
			}

		/* Process the request that follows the PKIBoot.  If the client
		   was only performing a standardlone PKIBoot but left the 
		   connection open in case further transactions were necesary
		   later, but then shut down the connection without performing
		   any further transactions, we'll get a read error at this point,
		   which we convert into a OK status */
		status = readPkiDatagram( sessionInfoPtr );
		if( cryptStatusOK( status ) )
			status = readPkiMessage( sessionInfoPtr, &protocolInfo,
									 CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			{
			sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONNSTATE, 
					&streamState, 0 );
			if( streamState )
				/* Only send an error response if the stream is still open */
				sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
			destroyProtocolInfo( &protocolInfo );
			return( streamState ? status : CRYPT_OK );
			}
		}

	/* Make sure that the signature on the request data is OK (unless it's a 
	   non-signed revocation request or a request for an encryption-only 
	   key) and add it to the cert store */
	if( protocolInfo.operation != CTAG_PB_RR && !protocolInfo.cryptOnlyKey )
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_CRT_SIGCHECK, NULL, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		strcpy( sessionInfoPtr->errorMessage, 
				"Request signature check failed" );
	else
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, NULL, 0,
							   ( protocolInfo.operation == CTAG_PB_KUR ) ? \
									KEYMGMT_FLAG_UPDATE : KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = sessionInfoPtr->iCertRequest;
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_SETKEY, &setkeyInfo, 
								  KEYMGMT_ITEM_REQUEST );
		if( cryptStatusError( status ) )
			{
			/* A common error condition at this point arises when the user 
			   tries to submit a second initialisation request for a PKI 
			   user that has already had a cert issued for it, so we catch 
			   this condition and provide a more informative error response
			   than the generic message */
			if( protocolInfo.operation == CTAG_PB_IR && \
				status == CRYPT_ERROR_DUPLICATE )
				{
				strcpy( sessionInfoPtr->errorMessage, 
						"Initialisation request couldn't be added to the "
						"cert store because another initialisation request "
						"has already been processed for this user" );
				protocolInfo.pkiFailInfo = CMPFAILINFO_DUPLICATECERTREQ;
				}
			else
				strcpy( sessionInfoPtr->errorMessage, 
						"Request couldn't be added to the cert store" );
			}
		}
	if( cryptStatusError( status ) )
		{
		/* If the cert store reports that there's a problem with the request,
		   convert it to an invalid request error */
		if( status == CRYPT_ARGERROR_NUM1 )
			status = CRYPT_ERROR_INVALID;
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* Create or revoke a cert from the request */
	if( protocolInfo.operation != CTAG_PB_RR )
		{
		setMessageCertMgmtInfo( &certMgmtInfo, sessionInfoPtr->privateKey,
								sessionInfoPtr->iCertRequest );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
								  CRYPT_CERTACTION_CERT_CREATION );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iCertResponse = certMgmtInfo.cryptCert;
		}
	else
		{
		setMessageCertMgmtInfo( &certMgmtInfo, CRYPT_UNUSED,
								sessionInfoPtr->iCertRequest );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
								  CRYPT_CERTACTION_REVOKE_CERT );
		}
	if( cryptStatusError( status ) )
		{
		/* If the cert store reports that there's a problem with the request,
		   convert it to an invalid request error */
		if( status == CRYPT_ARGERROR_NUM1 )
			status = CRYPT_ERROR_INVALID;
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		retExt( sessionInfoPtr, status, "%s was denied by cert store",
				( protocolInfo.operation != CTAG_PB_RR ) ? \
				"Cert issue" : "Revocation" );
		}

	/* Send the response to the client */
	status = writePkiMessage( sessionInfoPtr, &protocolInfo, CMPBODY_NORMAL );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_CMP( protocolInfo.operation, 2, sessionInfoPtr );
		status = writePkiDatagram( sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		if( protocolInfo.operation != CTAG_PB_RR )
			{
			/* If there was a problem, drop the partially-issued cert.  We
			   don't have to go all the way and do a full reversal because
			   it hasn't really been issued yet since we couldn't get it to
			   the client.  In addition we don't do anything with the return
			   status since we want to return the status that caused the
			   problem, not the result of the drop operation */
			setMessageCertMgmtInfo( &certMgmtInfo, CRYPT_UNUSED,
									sessionInfoPtr->iCertResponse );
			krnlSendMessage( sessionInfoPtr->cryptKeyset,
							 IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
							 CRYPT_CERTACTION_CERT_CREATION_DROP );
			}
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* If it's a transaction type that doesn't need a confirmation, we're 
	   done */
	if( protocolInfo.operation == CTAG_PB_RR )
		{
		/* Remember the authentication context in case we can reuse it for 
		   another transaction */
		cmpInfo->savedMacContext = protocolInfo.iMacContext;
		protocolInfo.iMacContext = CRYPT_ERROR;
		destroyProtocolInfo( &protocolInfo );
		return( CRYPT_OK );
		}

	/* Read back the confirmation from the client */
	status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = readPkiMessage( sessionInfoPtr, &protocolInfo,
								 CTAG_PB_CERTCONF );
	if( cryptStatusError( status ) || \
		protocolInfo.status == CRYPT_ERROR )
		{
		int localStatus;

		/* If the client rejected the cert this isn't a protocol error so we
		   send back a standard ack, otherwise we send back an error response */
		if( protocolInfo.status == CRYPT_ERROR )
			{
			writePkiMessage( sessionInfoPtr, &protocolInfo, CMPBODY_ACK );
			writePkiDatagram( sessionInfoPtr );
			}
		else
			sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );

		/* Reverse the cert issue operation by revoking the incompletely-
		   issued cert.  We only return the status from this operation if
		   we're performing the reversal at the request of the user (i.e. if
		   the earlier operations succeeded), if not we return the status
		   that caused the failure earlier on */
		setMessageCertMgmtInfo( &certMgmtInfo, CRYPT_UNUSED,
								sessionInfoPtr->iCertResponse );
		localStatus = krnlSendMessage( sessionInfoPtr->cryptKeyset,
									IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
									CRYPT_CERTACTION_CERT_CREATION_REVERSE );
		return( cryptStatusOK( status ) ? localStatus : status );
		}
	DEBUG_DUMP_CMP( protocolInfo.operation, 3, sessionInfoPtr );

	/* The client has confirmed the cert creation, finalise it */
	setMessageCertMgmtInfo( &certMgmtInfo, CRYPT_UNUSED,
							sessionInfoPtr->iCertResponse );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
							  CRYPT_CERTACTION_CERT_CREATION_COMPLETE );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		retExt( sessionInfoPtr, status, "Cert issue completion failed" );
		}

	/* Send back the final ack and clean up.  We don't bother checking the
	   return status since the message write can never fail (it just encodes
	   a null data value) and there's not much we can do if the final socket
	   write fails.  In addition we remember the authentication context in 
	   case we can reuse it for another transaction */
	writePkiMessage( sessionInfoPtr, &protocolInfo, CMPBODY_ACK );
	DEBUG_DUMP_CMP( protocolInfo.operation, 4, sessionInfoPtr );
	writePkiDatagram( sessionInfoPtr );
	cmpInfo->savedMacContext = protocolInfo.iMacContext;
	protocolInfo.iMacContext = CRYPT_ERROR;
	destroyProtocolInfo( &protocolInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

static int getAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 void *data, const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *cmpResponsePtr = ( CRYPT_CERTIFICATE * ) data;
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;

	assert( type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
			type == CRYPT_SESSINFO_RESPONSE );

	/* If it's a general protocol-specific attribute read, return the
	   information and exit */
	if( type == CRYPT_SESSINFO_CMP_REQUESTTYPE )
		{
		if( cmpInfo->requestType == CRYPT_REQUESTTYPE_NONE )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_REQUESTTYPE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		*( ( int * ) data ) = cmpInfo->requestType;
		return( CRYPT_OK );
		}

	/* If we didn't get a response there's nothing to return */
	if( sessionInfoPtr->iCertResponse == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_INCREFCOUNT );
	*cmpResponsePtr = sessionInfoPtr->iCertResponse;
	return( CRYPT_OK );
	}

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE cryptCert = *( ( CRYPT_CERTIFICATE * ) data );
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	int value, status;

	assert( type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
			type == CRYPT_SESSINFO_CMP_PRIVKEYSET || \
			type == CRYPT_SESSINFO_REQUEST || \
			type == CRYPT_SESSINFO_CACERTIFICATE );

	/* Standard CMP (with user-supplied request info) can't be combined with
	   plug-and-play CMP (with automatically-generated request info) */
	if( ( type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
		  type == CRYPT_SESSINFO_REQUEST ) && \
		sessionInfoPtr->privKeyset != CRYPT_ERROR )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_PRIVKEYSET,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}
	if( type == CRYPT_SESSINFO_CMP_PRIVKEYSET && \
		( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE || \
		  sessionInfoPtr->iCertRequest != CRYPT_ERROR ) )
		{
		setErrorInfo( sessionInfoPtr, 
					  ( sessionInfoPtr->iCertRequest != CRYPT_ERROR ) ? \
						CRYPT_SESSINFO_REQUEST : \
						CRYPT_SESSINFO_CMP_REQUESTTYPE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* If it's general protocol-specific information other than a request or 
	   cert, set it */
	if( type == CRYPT_SESSINFO_CMP_REQUESTTYPE )
		{
		/* Make sure that the value hasn't been set yet */
		value = *( ( int * ) data );
		if( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_REQUESTTYPE,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* If the request object is already present, make sure that it 
		   matches the request type.  We can't do this check unconditionally 
		   because the request type may be set before the request object is 
		   set */
		if( sessionInfoPtr->iCertRequest != CRYPT_ERROR )
			{
			int requestType;

			status = krnlSendMessage( sessionInfoPtr->iCertRequest,
									  IMESSAGE_GETATTRIBUTE, &requestType, 
									  CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) )
				return( status );
			if( requestType == CRYPT_CERTTYPE_REQUEST_CERT )
				{
				if( value != CRYPT_REQUESTTYPE_INITIALISATION && \
					value != CRYPT_REQUESTTYPE_CERTIFICATE && \
					value != CRYPT_REQUESTTYPE_KEYUPDATE )
					status = CRYPT_ERROR_INVALID;
				}
			else
				if( value != CRYPT_REQUESTTYPE_REVOCATION )
					status = CRYPT_ERROR_INVALID;
			if( cryptStatusError( status ) )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_REQUEST,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( status );
				}
			}

		/* Set the request type and tell the higher-level code that further
		   information needs to be provided before we can activate the
		   session */
		cmpInfo->requestType = value;
		if( value == CRYPT_REQUESTTYPE_INITIALISATION || \
			value == CRYPT_REQUESTTYPE_PKIBOOT )
			sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_USERID | \
									SESSION_NEEDS_PASSWORD;
		else
			if( value == CRYPT_REQUESTTYPE_REVOCATION )
				sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_PRIVATEKEY | \
									SESSION_NEEDS_PRIVKEYSIGN | \
									SESSION_NEEDS_PRIVKEYCERT | \
									SESSION_NEEDS_KEYORPASSWORD;
			else
				sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_PRIVATEKEY | \
									SESSION_NEEDS_PRIVKEYSIGN | \
									SESSION_NEEDS_PRIVKEYCERT;
		return( CRYPT_OK );
		}
	if( type == CRYPT_SESSINFO_CMP_PRIVKEYSET )
		{
		CRYPT_CERTIFICATE privKeyset = *( ( CRYPT_CERTIFICATE * ) data );

		/* Make sure that the value hasn't been set yet */
		if( sessionInfoPtr->privKeyset != CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_PRIVKEYSET,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* Remember that we're using plug-and-play PKI functionality */
		sessionInfoPtr->sessionCMP->flags |= CMP_PFLAG_PNPPKI;

		krnlSendNotifier( privKeyset, IMESSAGE_INCREFCOUNT );
		sessionInfoPtr->privKeyset = privKeyset;
		return( CRYPT_OK );
		}

	/* Make sure that the request/cert type is consistent with the operation
	   being performed.  The requirements for this are somewhat more complex 
	   than the basic ACL-based check can manage, so we handle it here with 
	   custom code */
	status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	switch( type )
		{
		case CRYPT_SESSINFO_REQUEST:
			if( value != CRYPT_CERTTYPE_REQUEST_CERT && \
				value != CRYPT_CERTTYPE_REQUEST_REVOCATION )
				return( CRYPT_ARGERROR_NUM1 );

			/* If the request type is already present, make sure that it 
			   matches the request object.  We can't do this check 
			   unconditionally because the request object may be set before 
			   the request type is set */
			if( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE )
				{
				const CRYPT_REQUESTTYPE_TYPE requestType = \
										cmpInfo->requestType;

				if( value == CRYPT_CERTTYPE_REQUEST_CERT )
					{
					if( requestType != CRYPT_REQUESTTYPE_INITIALISATION && \
						requestType != CRYPT_REQUESTTYPE_CERTIFICATE && \
						requestType != CRYPT_REQUESTTYPE_KEYUPDATE )
						status = CRYPT_ERROR_INVALID;
					}
				else
					if( requestType != CRYPT_REQUESTTYPE_REVOCATION )
						status = CRYPT_ERROR_INVALID;
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, 
								  CRYPT_SESSINFO_CMP_REQUESTTYPE,
								  CRYPT_ERRTYPE_CONSTRAINT );
					return( status );
					}
				}

			/* If it's a non-ir cert request, make sure that there's a 
			   subject DN present.  We perform this check because subject 
			   DNs are optional for irs but not for any other request types 
			   and we want to catch this before we get into the CMP exchange
			   itself */
			if( cmpInfo->requestType == CRYPT_REQUESTTYPE_CERTIFICATE || \
				cmpInfo->requestType == CRYPT_REQUESTTYPE_KEYUPDATE )
				{
				RESOURCE_DATA msgData = { NULL, 0 };

				status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE_S, 
										  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
								  CRYPT_ERRTYPE_ATTR_ABSENT );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}
			break;

		case CRYPT_SESSINFO_CACERTIFICATE:
			if( value != CRYPT_CERTTYPE_CERTIFICATE )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		default:
			assert( NOTREACHED );
		}
	if( value == CRYPT_CERTTYPE_CERTIFICATE || \
		value == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		/* Make sure that everything is set up ready to go */
		status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );
#if 0	/* RA certs aren't necessarily CA certs */
		if( type == CRYPT_SESSINFO_CACERTIFICATE )
			{
			/* Make sure that it really is a CA cert */
			status = krnlSendMessage( cryptCert, IMESSAGE_CHECK, NULL, 
									  MESSAGE_CHECK_CA );
			if( cryptStatusError( status ) )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_CA,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ARGERROR_NUM1 );
				}
			}
#endif /* 0 */
		}
	else
		{
		RESOURCE_DATA msgData = { NULL, 0 };

		/* Make sure that everything is set up ready to go.  Since revocation
		   requests aren't signed like normal cert objects we can't just
		   check the immutable attribute but have to perform a dummy export
		   for which the cert export code will return an error status if
		   there's a problem with the request */
		status = krnlSendMessage( cryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_ICERTFORMAT_DATA );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( cryptCert, IMESSAGE_INCREFCOUNT );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		sessionInfoPtr->iAuthInContext = cryptCert;
	else
		sessionInfoPtr->iCertRequest = cryptCert;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodCMP( SESSION_INFO *sessionInfoPtr )
	{
	static const ALTPROTOCOL_INFO altProtocolInfo = {
		STREAM_PROTOCOL_CMP,		/* Alt.xport protocol type */
		"cmp://",					/* Alt.xport protocol URI type */
		CMP_PORT					/* Alt.xport protocol port */
		};
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		0,							/* Client attributes */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_PRIVKEYCACERT | \
			SESSION_NEEDS_KEYSET | \
			SESSION_NEEDS_CERTSTORE,
		2, 2, 2,					/* Version 2 */
		"application/pkixcmp",		/* Client content-type */
		"application/pkixcmp",		/* Server content-type */
	
		/* Protocol-specific information */
		BUFFER_SIZE_DEFAULT,		/* Buffer size info */
		&altProtocolInfo			/* Alt.transport protocol */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		{
		sessionInfoPtr->connectFunction = clientStartup;
		sessionInfoPtr->transactFunction = clientTransactWrapper;
		}
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;

	/* Initialise CMP-specific objects */
	sessionInfoPtr->sessionCMP->userInfo = CRYPT_ERROR;
	sessionInfoPtr->sessionCMP->savedMacContext = CRYPT_ERROR;

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
