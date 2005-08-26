/****************************************************************************
*																			*
*					  cryptlib DBMS CA Cert Add Interface					*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
  #include "asn1.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../keyset/dbms.h"
  #include "../misc/asn1.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
  #include "misc/asn1.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check that the request we've been passed is in order */

BOOLEAN checkRequest( const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTACTION_TYPE action )
	{
	RESOURCE_DATA msgData;
	int certType, value, status;

	/* Make sure that the request type is consistent with the operation
	   being performed */
	status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( FALSE );
	switch( action )
		{
		case CRYPT_CERTACTION_CERT_CREATION:
		case CRYPT_CERTACTION_ISSUE_CERT:
			if( certType != CRYPT_CERTTYPE_CERTREQUEST && \
				certType != CRYPT_CERTTYPE_REQUEST_CERT )
				return( FALSE );
			break;

		case CRYPT_CERTACTION_REVOKE_CERT:
			if( certType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
				return( FALSE );
			break;

		case CRYPT_CERTACTION_NONE:
			/* We're performing a straight add of a request to the store,
			   any request type is permitted */
			break;

		default:
			assert( NOTREACHED );
			return( FALSE );
		}

	/* Make sure that the request is completed and valid.  We don't check
	   the signature on revocation requests since they aren't signed, and
	   have to be careful with CRMF requests, which can be unsigned for
	   encryption-only keys */
	status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_IMMUTABLE );
	if( cryptStatusError( status ) || !value )
		return( FALSE );
	switch( certType )
		{
		case CRYPT_CERTTYPE_REQUEST_CERT:
			if( cryptStatusOK( \
					krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
									 &value, CRYPT_CERTINFO_SELFSIGNED ) ) && \
				!value )
				{
				/* It's an unsigned CRMF request, make sure that it really 
				   is an encryption-only key */
				status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
										  &value, CRYPT_CERTINFO_KEYUSAGE );
				if( cryptStatusOK( status ) && \
					( value & ( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								CRYPT_KEYUSAGE_NONREPUDIATION ) ) )
					return( FALSE );
				break;
				}

			/* Fall through */

		case CRYPT_CERTTYPE_CERTREQUEST:
			status = krnlSendMessage( iCertRequest, IMESSAGE_CRT_SIGCHECK,
									  NULL, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* Revocation requests are unsigned so we can't perform a sig.
			   check on them */
			break;

		default:
			assert( NOTREACHED );
			return( FALSE );
		}

	/* Check that required parameters are present.  This is necessary for
	   CRMF requests where every single parameter is optional, for our use
	   we require that a cert request contains at least a subject DN and
	   public key and a revocation request contains at least an issuer DN and
	   serial number */
	switch( certType )
		{
		case CRYPT_CERTTYPE_CERTREQUEST:
		case CRYPT_CERTTYPE_REQUEST_CERT:
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
			if( cryptStatusError( status ) )
				return( FALSE );
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_SPKI );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, 
									  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		default:
			assert( NOTREACHED );
			return( FALSE );
		}

	return( TRUE );
	}

/* Check that a revocation request is consistent with information held in the
   cert store */

static int checkRevRequest( DBMS_INFO *dbmsInfo,
							const CRYPT_CERTIFICATE iCertRequest )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ], issuerID[ DBXKEYID_BUFFER_SIZE ];
	int length, status;

	/* Check that the cert being referred to in the request is present and
	   active */
	status = length = getKeyID( issuerID, iCertRequest,
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( !cryptStatusError( status ) )
		status = dbmsQuery(
			"SELECT certData FROM certificates WHERE issuerID = ?",
							NULL, 0, issuerID, length, 0,
							DBMS_CACHEDQUERY_ISSUERID, DBMS_QUERY_CHECK );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* The cert isn't an active cert, it's either not present or not active,
	   return an appropriate error code.  If this request has been entered
	   into the cert log then it's a duplicate request, otherwise it's a
	   request to revoke a non-present cert (either that or something really
	   obscure which is best reported as a non-present cert problem) */
	status = length = getKeyID( certID, iCertRequest,
								CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( !cryptStatusError( status ) )
		status = dbmsQuery(
			"SELECT certData FROM certLog WHERE certID = ?",
							NULL, 0, certID, length, 0,
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
	return( cryptStatusOK( status ) ? \
			CRYPT_ERROR_DUPLICATE : CRYPT_ERROR_NOTFOUND );
	}

/****************************************************************************
*																			*
*								Cert Add Functions							*
*																			*
****************************************************************************/

/* Add a new PKI user to the cert store */

int caAddPKIUser( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iPkiUser )
	{
	RESOURCE_DATA msgData;
	BYTE certData[ MAX_CERT_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int certDataLength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isHandleRangeValid( iPkiUser ) );

	/* Extract the information we need from the PKI user object.  In
	   addition to simply obtaining the information for logging purposes we
	   also need to perform this action to tell the cert management code to
	   fill in the remainder of the (implicitly-added) user info before we
	   start querying fields as we add it to the cert store.  Because of this
	   we also need to place the certID fetch after the object export, since
	   it's in an incomplete state before this point */
	setMessageData( &msgData, certData, MAX_CERT_SIZE );
	status = krnlSendMessage( iPkiUser, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusOK( status ) )
		status = getKeyID( certID, iPkiUser, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );
	certDataLength = msgData.length;

	/* Update the cert store */
	status = addCert( dbmsInfo, iPkiUser, CRYPT_CERTTYPE_PKIUSER,
					  CERTADD_NORMAL, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_ADDUSER, certID,
								NULL, NULL, certData, certDataLength,
								DBMS_UPDATE_COMMIT );
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );

	return( status );
	}

/* Delete a PKI user from the cert store */

int caDeletePKIUser( DBMS_INFO *dbmsInfo, const CRYPT_KEYID_TYPE keyIDtype,
					 const void *keyID, const int keyIDlength )
	{
	CRYPT_CERTIFICATE iPkiUser;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int dummy, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_URI );
	assert( isReadPtr( keyID, keyIDlength ) );

	/* Get info on the user that we're about to delete */
	status = getItemData( dbmsInfo, &iPkiUser, &dummy, keyIDtype,
						  keyID, keyIDlength, KEYMGMT_ITEM_PKIUSER, 
						  KEYMGMT_FLAG_NONE );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( certID, iPkiUser, 
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
		krnlSendNotifier( iPkiUser, IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Delete the PKI user info and record the deletion */
	dbmsFormatSQL( sqlBuffer,
			"DELETE FROM pkiUsers WHERE certID = '$'",
				   certID );
	status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_DELETEUSER, 
								NULL, NULL, certID, NULL, 0, 
								DBMS_UPDATE_COMMIT );
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );

	return( status );
	}

/* Add a cert issue or revocation request to the cert store */

int caAddCertRequest( DBMS_INFO *dbmsInfo,
					  const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTTYPE_TYPE requestType,
					  const BOOLEAN isRenewal )
	{
	BYTE certData[ MAX_CERT_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ], *reqCertIDptr = reqCertID;
	int reqCertIDlength, certDataLength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isHandleRangeValid( iCertRequest ) );
	assert( requestType == CRYPT_CERTTYPE_CERTREQUEST || \
			requestType == CRYPT_CERTTYPE_REQUEST_CERT || \
			requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION );

	/* Make sure that the request is OK, and if it's a revocation request
	   make sure that it refers to a cert which is both present in the store
	   and currently active */
	if( !checkRequest( iCertRequest, CRYPT_CERTACTION_NONE ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		status = checkRevRequest( dbmsInfo, iCertRequest );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Extract the information that we need from the cert request */
	status = getKeyID( certID, iCertRequest,
					   CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( !cryptStatusError( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCertRequest, IMESSAGE_CRT_EXPORT,
					&msgData,
					( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
					CRYPT_ICERTFORMAT_DATA : CRYPT_CERTFORMAT_CERTIFICATE );
		certDataLength = msgData.length;
		}
	if( cryptStatusOK( status ) )
		{
		status = reqCertIDlength = getKeyID( reqCertID, iCertRequest,
											 CRYPT_IATTRIBUTE_AUTHCERTID );
		if( cryptStatusError( status ) )
			{
			/* If the request is being added directly by the user, there's no
			   authorising certificate/PKI user info present */
			reqCertIDptr = NULL;
			reqCertIDlength = 0;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the PKI user who authorised this cert issue still exists.
	   If the CA has deleted them, all further requests for certs fail */
	if( reqCertIDptr != NULL )
		{
		CRYPT_CERTIFICATE iPkiUser;

		status = caGetIssuingUser( dbmsInfo, &iPkiUser, reqCertID, 
								   reqCertIDlength );
		if( cryptStatusOK( status ) )
			krnlSendNotifier( iPkiUser, IMESSAGE_DECREFCOUNT );
		else
			{
			reqCertID[ reqCertIDlength ] = '\0';
			updateCertErrorLog( dbmsInfo, CRYPT_ERROR_DUPLICATE,
								"Cert request submitted for nonexistant PKI "
								"user", NULL, reqCertID, NULL, NULL, 0 );
			return( CRYPT_ERROR_PERMISSION );
			}
		}

	/* If there's an authorising PKI user present, make sure that it hasn't
	   already been used to authorise the issuance of a cert.  This is 
	   potentially vulnerable to the following race condition:

		1: check authCertID -> OK
		2: check authCertID -> OK
		1: add
		2: add

	   In theory we could detect this by requiring the reqCertID to be 
	   unique, however a PKI user can be used to request both a cert and 
	   a revocation for the cert, and a signing cert can be used to request
	   an update or revocation of both itself and one or more associated
	   encryption certs.  We could probably handle this via the ID-mangling
	   used for certIDs, but this makes tracing events through the audit log
	   complex since there'll now be different effective IDs for the 
	   authorising cert depending on what it was authorising.  In addition
	   it's not certain how many further operations a cert (rather than a PKI
	   user) can authorise, in theory a single signing cert can authorise at
	   least four further operations, these being the update of itself, the
	   update of an associated encryption cert, and the revocation of itself
	   and the encryption cert.  In addition its possible that a signing cert
	   could be used to authorise a series of short-duration encryption 
	   certs, or a variety of other combinations of operations.

	   Because of these issues, we can't use a uniqueness constraint on the
	   reqCertID to enforce a single use of issuing authorisation by the
	   database ifself, but have to do a manual check here, checking 
	   specifically for the case where a PKI user authorises a cert issue */
#if 0	/* This check is too restrictive because it blocks any further cert
		   issues after the first one.  This is because as soon as a single
		   issue has been authorised for a user, there'll be a request for
		   that user logged so all further attempts to submit a request (for
		   example for a renewal, or an encryption cert to go with a signing
		   one) will fail */
	if( reqCertIDptr != NULL )
		{
		status = dbmsQuery(
			"SELECT certID FROM certLog WHERE reqCertID = ? "
			"AND action = " TEXT_CERTACTION_REQUEST_CERT,
							NULL, 0, reqCertID, reqCertIDlength, 0,
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
		if( cryptStatusOK( status ) )
			{
			/* This user has already authorised the issue of a cert, it 
			   can't be used to issue a second cert */
			reqCertID[ reqCertIDlength ] = '\0';
			updateCertErrorLog( dbmsInfo, CRYPT_ERROR_DUPLICATE,
								"Attempt to authorise additional cert issue "
								"when a cert for this user has already been "
								"issued", NULL, reqCertID, NULL, NULL, 0 );
			return( CRYPT_ERROR_DUPLICATE );
			}
		}
#endif /* 0 */

	/* Update the cert store.  Since a revocation request generally won't
	   have any fields of any significance set, we have to use a special cut-
	   down insert statement that doesn't expect to find any fields except
	   the cert ID */
	if( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		if( !hasBinaryBlobs( dbmsInfo ) )
			{
			char encodedCertData[ MAX_ENCODED_CERT_SIZE ];
			int length;

			length = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
								   certData, certDataLength,
								   CRYPT_CERTTYPE_NONE );
			encodedCertData[ length ] = '\0';
			dbmsFormatSQL( sqlBuffer,
				"INSERT INTO certRequests VALUES ("
				TEXT_CERTTYPE_REQUEST_REVOCATION ", '', '', '', '', '', '', "
				"'', '$', '$')",
						   certID, encodedCertData );
			}
		else
			{
			dbmsFormatSQL( sqlBuffer,
				"INSERT INTO certRequests VALUES ("
				TEXT_CERTTYPE_REQUEST_REVOCATION ", '', '', '', '', '', '', "
				"'', '$', ?)",
						   certID );
			}
		status = dbmsUpdate( sqlBuffer, hasBinaryBlobs( dbmsInfo ) ? \
							 certData : NULL, certDataLength, 0,
							 DBMS_UPDATE_BEGIN );
		}
	else
		status = addCert( dbmsInfo, iCertRequest, CRYPT_CERTTYPE_REQUEST_CERT,
						  CERTADD_NORMAL, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		status = updateCertLog( dbmsInfo,
						( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
							CRYPT_CERTACTION_REQUEST_REVOCATION : \
						( isRenewal ) ? \
							CRYPT_CERTACTION_REQUEST_RENEWAL : \
							CRYPT_CERTACTION_REQUEST_CERT,
						certID, reqCertIDptr, NULL, certData,
						certDataLength, DBMS_UPDATE_COMMIT );
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );

	return( status );
	}
#endif /* USE_DBMS */
