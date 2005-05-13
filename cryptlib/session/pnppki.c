/****************************************************************************
*																			*
*						cryptlib Plug-and-play PKI Routines					*
*						 Copyright Peter Gutmann 1999-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "cmp.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/* When we generate a new key, there are a variety of different key types
   (meaning key usages) that we can generate it for, constrained to some
   extent by what the underlying cert management protocol supports.  The
   following values identify the key type that we need to generate */

typedef enum {
	KEYTYPE_NONE,			/* No key type */
	KEYTYPE_ENCRYPTION,		/* Encryption key */
	KEYTYPE_SIGNATURE,		/* Signature key */
	KEYTYPE_BOTH,			/* Dual encryption/signature key */
	KEYTYPE_LAST			/* Last possible key type */
	} KEY_TYPE;

/* A structure to store key type-related information, indexed by the KEY_TYPE 
   value */

static const struct {
	const char *label;		/* Label for private key */
	const int actionPerms;	/* Context action perms */
	const int keyUsage;		/* Cert key usage */
	} keyInfo[] = {
	{ NULL, 0, 0 },
	{ "Encryption key", 
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL ),
		CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ "Signature key", 
		MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL ),
		CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ "Private key",
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL ),
		CRYPT_KEYUSAGE_KEYENCIPHERMENT | CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ NULL, 0, 0 }
	};

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Clean up an object if the PnP operation fails.  This is required when 
   working with devices since we need to explicitly delete anything that
   was created in the device as well as just deleting the cryptlib object */

static void cleanupObject( const CRYPT_CONTEXT iPrivateKey, 
						   const KEY_TYPE keyType )
	{
	CRYPT_DEVICE iCryptDevice;
	MESSAGE_KEYMGMT_INFO deletekeyInfo;
	int status;

	/* Delete the cryptlib object.  If it's a native object, we're done */
	krnlSendNotifier( iPrivateKey, IMESSAGE_DECREFCOUNT );
	status = krnlSendMessage( iPrivateKey, IMESSAGE_GETDEPENDENT,
							  &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return;

	/* Delete the key from the device.  We set the item type to delete to
	   public key since the device object will interpret this correctly
	   to mean that it should also delete the associated private key */
	setMessageKeymgmtInfo( &deletekeyInfo, CRYPT_KEYID_NAME, 
						   keyInfo[ keyType ].label,
						   strlen( keyInfo[ keyType ].label ), NULL, 0, 
						   KEYMGMT_FLAG_NONE );
	krnlSendMessage( iCryptDevice, IMESSAGE_KEY_DELETEKEY,
					 &deletekeyInfo, KEYMGMT_ITEM_PUBLICKEY );
	}

/* Check whether a network connection is still open, used when performing
   multiple transactions in a single session */

static BOOLEAN isConnectionOpen( SESSION_INFO *sessionInfoPtr )
	{
	int streamState;

	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONNSTATE, 
			&streamState, 0 );
	return( streamState );
	}

/* Check for the presence of a named object in a keyset/device */

static BOOLEAN isNamedObjectPresent( const CRYPT_HANDLE iCryptHandle,
									 const KEY_TYPE keyType )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	const char *keyLabel = keyInfo[ keyType ].label;
	int status;

	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_NAME, keyLabel, 
						   strlen( keyLabel ), NULL, 0,
						   KEYMGMT_FLAG_CHECK_ONLY );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_KEY_GETKEY, 
							  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_NAME, keyLabel, 
							   strlen( keyLabel ), NULL, 0,
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_KEY_GETKEY, 
								  &getkeyInfo, KEYMGMT_ITEM_PRIVATEKEY );
		}
	return( cryptStatusOK( status ) ? TRUE : FALSE );
	}

/* Recreate a cert from an existing cert, either converting a standard cert
   to a data-only cert or vice versa.  This is easier than trying to 
   disconnect and re-connect certificate and context objects directly */

static int recreateCert( CRYPT_CERTIFICATE *iNewCert,
						 const CRYPT_CERTIFICATE iCryptCert,
						 const BOOLEAN isDataOnlyCert )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE buffer[ 2048 ], *bufPtr = buffer;
	int status;

	*iNewCert = CRYPT_ERROR;

	/* Recreate a cert by exporting the current cert and re-importing it in 
	   the required format */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > 2048 && \
		( bufPtr = clDynAlloc( "recreateCert", msgData.length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	msgData.data = bufPtr;
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectIndirectInfo( &createInfo, msgData.data,
											msgData.length,
											isDataOnlyCert ? \
												CERTFORMAT_DATAONLY : \
												CRYPT_CERTTYPE_CERTIFICATE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		}
	if( bufPtr != buffer )
		clFree( "recreateCert", bufPtr );
	if( cryptStatusOK( status ) )
		*iNewCert = createInfo.cryptHandle;
	return( status );
	}

/* Get the identified CA/RA cert from a CTL */

static int getCACert( CRYPT_CERTIFICATE *iNewCert, 
					  const CRYPT_CERTIFICATE iCTL, const void *certID, 
					  const int certIDlength )
	{
	int status;

	assert( certIDlength == 0 || certIDlength == KEYID_SIZE );

	*iNewCert = CRYPT_ERROR;

	/* Step through the cert trust list checking each cert in turn to see
	   if it's the identified CA/RA cert.  Some CAs may only send a single 
	   cert in the CTL and not explicitly identify it, so if there's no cert
	   ID present we just use the first cert */
	status = krnlSendMessage( iCTL, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORFIRST,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	if( certIDlength > 0 )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, ( void * ) certID, KEYID_SIZE );
		do
			{
			status = krnlSendMessage( iCTL, IMESSAGE_COMPARE, &msgData, 
									  MESSAGE_COMPARE_FINGERPRINT );
			}
		while( cryptStatusError( status ) && \
			   krnlSendMessage( iCTL, IMESSAGE_SETATTRIBUTE,
								MESSAGE_VALUE_CURSORNEXT,
								CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_NOTFOUND );
		}

	/* We've found the identified cert, convert it from the data-only form
	   in the CTL to a full cert that can be used to verify returned data */
	return( recreateCert( iNewCert, iCTL, FALSE ) );
	}

/****************************************************************************
*																			*
*						Cert Creation/Update Routines						*
*																			*
****************************************************************************/

/* Generate a new key of the appropriate type */

static int generateKey( CRYPT_CONTEXT *iPrivateKey,
						const CRYPT_USER iCryptUser,
						const CRYPT_DEVICE iCryptDevice,
						const KEY_TYPE keyType )
	{
	CRYPT_QUERY_INFO queryInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	int value, status;

	/* Clear return value */
	*iPrivateKey = CRYPT_ERROR;

	/* Get the algorithm to use for the key.  We try and use the given 
	   default PKC algorithm, however some devices don't support all 
	   algorithm types so if this isn't available we fall back to other 
	   choices */
	krnlSendMessage( iCryptUser, IMESSAGE_GETATTRIBUTE, &value, 
					 CRYPT_OPTION_PKC_ALGO );
	if( cryptStatusError( \
			krnlSendMessage( iCryptDevice, IMESSAGE_DEV_QUERYCAPABILITY, 
							 &queryInfo, value ) ) )
		{
		/* The default algorithm type isn't available for this device, try 
		   and fall back to an alternative */
		switch( value )
			{
			case CRYPT_ALGO_RSA:
				value = CRYPT_ALGO_DSA;
				break;

			case CRYPT_ALGO_DSA:
				value = CRYPT_ALGO_RSA;
				break;

			default:
				return( CRYPT_ERROR_NOTAVAIL );
			}
		if( cryptStatusError( \
				krnlSendMessage( iCryptDevice, IMESSAGE_DEV_QUERYCAPABILITY, 
								 &queryInfo, value ) ) )
			return( CRYPT_ERROR_NOTAVAIL );
		}
	if( keyType == KEYTYPE_ENCRYPTION && value == CRYPT_ALGO_DSA )
		/* If we're being asked for an encryption key (which implies that 
		   we've already successfully completed the process of acquiring a 
		   signature key) and only a non-encryption algorithm is available, 
		   we return OK_SPECIAL to tell the caller that the failure is non-
		   fatal */
		return( OK_SPECIAL );

	/* Create a new key using the given PKC algorithm and of the default 
	   size */
	setMessageCreateObjectInfo( &createInfo, value );
	status = krnlSendMessage( iCryptDevice, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( iCryptUser, IMESSAGE_GETATTRIBUTE, &value, 
					 CRYPT_OPTION_PKC_KEYSIZE );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( int * ) &value, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) keyInfo[ keyType ].label, 
						strlen( keyInfo[ keyType ].label ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_LABEL );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Generate the key */
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_CTX_GENKEY, NULL, FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE,
								  ( int * ) &keyInfo[ keyType ].actionPerms,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iPrivateKey = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Create a cert request for a key.  If a cert with a subject DN template is
   provided, we copy this into the request, otherwise we create a minimal 
   key-only request */

static int createCertRequest( CRYPT_CERTIFICATE *iCertReq, 
							  const CRYPT_CONTEXT iPrivateKey,
							  const CRYPT_CERTIFICATE iSubjDNCert,
							  const KEY_TYPE keyType )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	const BOOLEAN isPKCS10 = ( keyType == KEYTYPE_BOTH );
	int status;

	/* Clear return value */
	*iCertReq = CRYPT_ERROR;

	/* Create the signing key cert request */
	setMessageCreateObjectInfo( &createInfo, isPKCS10 ? \
								CRYPT_CERTTYPE_CERTREQUEST : \
								CRYPT_CERTTYPE_REQUEST_CERT );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the key information to the request and sign it if it's a CMP
	   request.  We can't sign PKCS #10 requests (for SCEP) because the 
	   client session has to add further information which is required by 
	   the server to the request before it submits it */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( int * ) &iPrivateKey,
							  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  ( int * ) &keyInfo[ keyType ].keyUsage, 
								  CRYPT_CERTINFO_KEYUSAGE );
	if( cryptStatusOK( status ) && iSubjDNCert != CRYPT_UNUSED )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  ( int * ) &iSubjDNCert,
								  CRYPT_CERTINFO_CERTIFICATE );
	if( cryptStatusOK( status ) && !isPKCS10 )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CRT_SIGN,
								  NULL, iPrivateKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCertReq = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Update a keyset/device with a newly-created key and cert */

static int updateKeys( const CRYPT_HANDLE iCryptHandle,
					   const CRYPT_CONTEXT iPrivateKey,
					   const CRYPT_CERTIFICATE iCryptCert,
					   const char *password, const int passwordLength )
	{
	MESSAGE_KEYMGMT_INFO setkeyInfo;
	int value, status;

	/* Find out whether the storage object is a keyset or a device.  If it's
	   a device there's no need to add the private key since it'll have been
	   created inside the device */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the private key and certificate to the keyset/device */
	if( value == OBJECT_TYPE_KEYSET )
		{
		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
							   ( void * ) password, passwordLength,
							   KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = iPrivateKey;
		status = krnlSendMessage( iCryptHandle, IMESSAGE_KEY_SETKEY,
								  &setkeyInfo, KEYMGMT_ITEM_PRIVATEKEY );
		if( cryptStatusError( status ) )
			return( status );
		}
	setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
						   NULL, 0, KEYMGMT_FLAG_NONE );
	setkeyInfo.cryptHandle = iCryptCert;
	return( krnlSendMessage( iCryptHandle, IMESSAGE_KEY_SETKEY,
							 &setkeyInfo, KEYMGMT_ITEM_PUBLICKEY ) );
	}

/* Update the keyset/device with any required trusted certs up to the root.  
   This ensures that we can still build a full cert chain even if the 
   PKIBoot trusted certs aren't preserved */

static int updateTrustedCerts( const CRYPT_HANDLE iCryptHandle,
							   const CRYPT_HANDLE iLeafCert )
	{
	CRYPT_CERTIFICATE iCertCursor = iLeafCert;
	int status;

	do
		{
		/* Get the trusted issuer cert for the current cert and send it to
		   the keyset/device */
		status = krnlSendMessage( iCertCursor, 
								  IMESSAGE_SETATTRIBUTE, &iCertCursor, 
								  CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_KEYMGMT_INFO setkeyInfo;

			setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
								   NULL, 0, KEYMGMT_FLAG_NONE );
			setkeyInfo.cryptHandle = iCertCursor;
			status = krnlSendMessage( iCryptHandle, IMESSAGE_KEY_SETKEY, 
									  &setkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
			}
		}
	while( cryptStatusOK( status ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							PnP PKI Session Management						*
*																			*
****************************************************************************/

/* Run a plug-and-play PKI session */

int pnpPkiSession( SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice = SYSTEM_OBJECT_HANDLE;
	CRYPT_CONTEXT iPrivateKey1, iPrivateKey2 ;
	CRYPT_CERTIFICATE iCertReq, iCACert;
	const ATTRIBUTE_LIST *attributeListPtr;
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	const KEY_TYPE keyType = ( sessionInfoPtr->type == CRYPT_SESSION_CMP ) ? \
							 KEYTYPE_SIGNATURE : KEYTYPE_BOTH;
	BOOLEAN isCAcert;
	int value, status;

	/* If we've been passed a device as the private-key storage location,
	   create the key in the device instead of as a local object */
	status = krnlSendMessage( sessionInfoPtr->privKeyset,
							  IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) )
		return( status );
	if( value == OBJECT_TYPE_DEVICE )
		iCryptDevice = sessionInfoPtr->privKeyset;

	/* Make sure that the named objects that are about to be created aren't 
	   already present in the keyset/device */
	if( isNamedObjectPresent( sessionInfoPtr->privKeyset, keyType ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_DUPLICATE,
				"%s is already present in keyset/device",
				( keyType == KEYTYPE_SIGNATURE ) ? "Signature key" : "Key" );
	if( sessionInfoPtr->type == CRYPT_SESSION_CMP )
		{
		if( isNamedObjectPresent( sessionInfoPtr->privKeyset, 
								  KEYTYPE_ENCRYPTION ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_DUPLICATE,
					"Encryption key is already present in keyset/device" );
		}

	/* Perform the PKIBoot exchange to get the initial trusted cert set.  We 
	   also set the retain-connection flag since we're going to follow this 
	   with another transaction */
	if( sessionInfoPtr->type == CRYPT_SESSION_CMP )
		sessionInfoPtr->sessionCMP->requestType = CRYPT_REQUESTTYPE_PKIBOOT;
	sessionInfoPtr->protocolFlags |= CMP_PFLAG_RETAINCONNECTION;
	status = sessionInfoPtr->transactFunction( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( !isConnectionOpen( sessionInfoPtr ) )
		{
		/* If the connection was shut down by the other side, signal an 
		   error.  This is possibly a bit excessive since we could always 
		   try reactivating the session, but there's no good reason for the 
		   other side to simply close the connection and requiring it to 
		   remain open simplifies the implementation */
		krnlSendNotifier( sessionInfoPtr->iCertResponse, 
						  IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_READ,
				"Server closed connection after PKIBoot phase before any "
				"certificates could be issued" );
		}

	/* Get the CA/RA cert from the returned CTL and set it as the cert to 
	   use for authenticating server responses */
	attributeListPtr = \
			findSessionAttribute( sessionInfoPtr->attributeList,
								  CRYPT_SESSINFO_SERVER_FINGERPRINT );
	if( attributeListPtr == NULL )
		status = CRYPT_ERROR_NOTFOUND;
	else
		status = getCACert( &iCACert, sessionInfoPtr->iCertResponse, 
							attributeListPtr->value, 
							attributeListPtr->valueLength );
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't read CA/RA certificate from returned certificate "
				"trust list" );
	sessionInfoPtr->iAuthInContext = iCACert;

	/* Create a private key and a cert request for it */
	status = generateKey( &iPrivateKey1, sessionInfoPtr->ownerHandle,
						  iCryptDevice, keyType );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Couldn't create %s key",
				( keyType == KEYTYPE_SIGNATURE ) ? "signature" : "private" );
	status = createCertRequest( &iCertReq, iPrivateKey1, CRYPT_UNUSED, 
								keyType );
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, keyType );
		retExt( sessionInfoPtr, status,
				"Couldn't create %skey cert request",
				( keyType == KEYTYPE_SIGNATURE ) ? "signature " : "" );
		}

	/* Set up the request info and activate the session */
	if( sessionInfoPtr->type == CRYPT_SESSION_CMP )
		/* If it's CMP, start with an ir.  The second cert will be fetched 
		   with a cr */
		sessionInfoPtr->sessionCMP->requestType = CRYPT_REQUESTTYPE_INITIALISATION;
	sessionInfoPtr->iCertRequest = iCertReq;
	status = sessionInfoPtr->transactFunction( sessionInfoPtr );
	krnlSendNotifier( sessionInfoPtr->iCertRequest, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertRequest = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, keyType );
		return( status );
		}

	/* Check whether we've been issued a standalone CA cert rather than a 
	   standard signature cert to be followed by an encryption cert */
	status = krnlSendMessage( sessionInfoPtr->iCertResponse, 
							  IMESSAGE_GETATTRIBUTE, &isCAcert,
							  CRYPT_CERTINFO_CA );
	if( cryptStatusError( status ) )
		isCAcert = FALSE;

	/* If the connection was shut down by the other side and we're 
	   performing a multi-part operation that requires it to remain open, 
	   signal an error.  This is possibly a bit excessive since we could 
	   always try reactivating the session, but there's no good reason for 
	   the other side to simply close the connection and requiring it to 
	   remain open simplifies the implementation */
	if( sessionInfoPtr->type == CRYPT_SESSION_CMP && \
		!isConnectionOpen( sessionInfoPtr ) && !isCAcert )
		{
		cleanupObject( iPrivateKey1, keyType );
		krnlSendNotifier( sessionInfoPtr->iCertResponse, 
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
		retExt( sessionInfoPtr, CRYPT_ERROR_READ,
				"Server closed connection before second (encryption) "
				"certificate could be issued" );
		}

	/* We've got the first cert, update the keyset/device */
	status = updateKeys( sessionInfoPtr->privKeyset, iPrivateKey1,
						 sessionInfoPtr->iCertResponse, 
						 passwordPtr->value, passwordPtr->valueLength );
	if( cryptStatusOK( status ) )
		{
		CRYPT_CERTIFICATE iNewCert;

		/* Recreate the cert as a data-only cert and attach it to the 
		   signing key so that we can use it to authenticate a request for 
		   an encryption key.  We need to recreate the cert because we're 
		   about to attach it to the private-key context for further 
		   operations, and attaching a cert with a public-key context 
		   already attached isn't possible.  Even if we're not getting a
		   second cert, we still need the current cert attached so that we 
		   can use it as the base cert for the trusted cert update that
		   we perform before we exit */
		status = recreateCert( &iNewCert, sessionInfoPtr->iCertResponse, 
							   TRUE );
		if( cryptStatusOK( status ) )
			krnlSendMessage( iPrivateKey1, IMESSAGE_SETDEPENDENT, &iNewCert, 
							 SETDEP_OPTION_NOINCREF );
		}
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, keyType );
		retExt( sessionInfoPtr, ( status == CRYPT_ARGERROR_NUM1 ) ? \
				CRYPT_ERROR_INVALID : status,
				"Couldn't update keyset/device with %skey/certificate",
				isCAcert ? "CA " : \
				( keyType == KEYTYPE_SIGNATURE ) ? "signature " : "" );
		}

	/* If it's a combined encryption/signature key or a standalone CA key, 
	   we're done.  See the comment at the end for the trusted-certs update
	   process */
	if( keyType == KEYTYPE_BOTH || isCAcert )
		{
		updateTrustedCerts( sessionInfoPtr->privKeyset, iPrivateKey1 );
		krnlSendNotifier( iPrivateKey1, IMESSAGE_DECREFCOUNT );
		return( CRYPT_OK );
		}

	/* We're running a CMP session from this point on.  Create the second, 
	   encryption private key and a cert request for it */
	status = generateKey( &iPrivateKey2, sessionInfoPtr->ownerHandle,
						  iCryptDevice, KEYTYPE_ENCRYPTION );
	if( status == OK_SPECIAL )
		{
		/* Encryption isn't available via this device, exit without going
		   through the second phase of the exchange, leaving only the
		   signature key and certs set up */
		updateTrustedCerts( sessionInfoPtr->privKeyset, iPrivateKey1 );
		krnlSendNotifier( iPrivateKey1, IMESSAGE_DECREFCOUNT );
		return( CRYPT_OK );
		}
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, KEYTYPE_SIGNATURE );
		retExt( sessionInfoPtr, status, "Couldn't create encryption key" );
		}
	status = createCertRequest( &iCertReq, iPrivateKey2, iPrivateKey1,
								KEYTYPE_ENCRYPTION );
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, KEYTYPE_SIGNATURE );
		cleanupObject( iPrivateKey2, KEYTYPE_ENCRYPTION );
		retExt( sessionInfoPtr, status,
				"Couldn't create encryption key cert request" );
		}

	/* Set up the request info and activate the session.  This request is 
	   slightly different to the previous one since we now have a signature 
	   cert that we can use to authenticate the request (in fact we have to
	   use this since we can't authenticate the message with an encryption-
	   only key).  In addition since this is the last transaction we turn 
	   off the retain-connection flag */
	sessionInfoPtr->protocolFlags &= ~CMP_PFLAG_RETAINCONNECTION;
	sessionInfoPtr->sessionCMP->requestType = CRYPT_REQUESTTYPE_CERTIFICATE;
	sessionInfoPtr->iCertRequest = iCertReq;
	sessionInfoPtr->privateKey = iPrivateKey2;
	sessionInfoPtr->iAuthOutContext = iPrivateKey1;
	status = sessionInfoPtr->transactFunction( sessionInfoPtr );
	sessionInfoPtr->privateKey = CRYPT_ERROR;
	sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
	krnlSendNotifier( sessionInfoPtr->iCertRequest, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertRequest = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, KEYTYPE_SIGNATURE );
		cleanupObject( iPrivateKey2, KEYTYPE_ENCRYPTION );
		return( status );
		}

	/* We've got the second cert, update the keyset/device */
	status = updateKeys( sessionInfoPtr->privKeyset, iPrivateKey2,
						 sessionInfoPtr->iCertResponse, 
						 passwordPtr->value, passwordPtr->valueLength );
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		cleanupObject( iPrivateKey1, KEYTYPE_SIGNATURE );
		cleanupObject( iPrivateKey2, KEYTYPE_ENCRYPTION );
		retExt( sessionInfoPtr, status,
				"Couldn't update keyset/device with encryption "
				"key/certificate" );
		}

	/* Finally, update the keyset/device with any required trusted certs up 
	   to the root.  This ensures that we can still build a full cert chain 
	   even if the PKIBoot trusted certs aren't preserved.  We don't check 
	   for errors from this function since it's not worth aborting the 
	   process for some minor CA cert update problem, the user keys and certs
	   will still function without them */
	updateTrustedCerts( sessionInfoPtr->privKeyset, iPrivateKey1 );

	/* Both keys were certified and the keys and certs sent to the keyset/
	   device, we're done */
	krnlSendNotifier( iPrivateKey1, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( iPrivateKey2, IMESSAGE_DECREFCOUNT );
	return( CRYPT_OK );
	}
#endif /* USE_CMP */
