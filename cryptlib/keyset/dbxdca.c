/****************************************************************************
*																			*
*						  cryptlib DBMS CA Interface						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbxdbx.h"
  #include "asn1_rw.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../keyset/dbxdbx.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbxdbx.h"
  #include "misc/asn1_rw.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#if 0

/* Get the ultimate successor cert for one that has been superseded */

static int getSuccessorCert( DBMS_INFO *dbmsInfo,
							 CRYPT_CERTIFICATE *iCertificate,
							 const char *initialCertID )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	/* Walk through the chain of renewals in the cert log until we find the
	   ultimate successor cert to the current one */
	strcpy( certID, initialCertID );
	do
		{
		BYTE keyCertID[ DBXKEYID_SIZE ];
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
		char certData[ MAX_CERT_SIZE ];
		int certDataLength, dummy;

		/* Find the request to renew this certificate */
		dbmsFormatSQL( sqlBuffer,
			"SELECT certID FROM certLog WHERE subjCertID = '$' "
				"AND action = " TEXT_CERTACTION_REQUEST_RENEWAL,
					   certID );
		status = dbmsQuery( sqlBuffer, certData, &certDataLength, 0,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );

		/* Find the resulting certificate */
		memcpy( certID, certData,
				min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ) );
		dbmsFormatSQL( sqlBuffer,
			"SELECT certID FROM certLog WHERE reqCertID = '$' "
				"AND action = " TEXT_CERTACTION_CERT_CREATION,
					   certID );
		status = dbmsQuery( sqlBuffer, certData, &certDataLength, 0,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		base64decode( keyCertID, certData,
					  min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ),
					  CRYPT_CERTFORMAT_NONE );

		/* Try and get the replacement cert */
		status = getItemData( dbmsInfo, iCertificate, &dummy,
							  getKeyName( CRYPT_IKEYID_CERTID ), keyCertID,
							  KEYMGMT_ITEM_PUBLICKEY, KEYMGMT_FLAG_NONE );
		}
	while( status == CRYPT_ERROR_NOTFOUND );

	return( status );
	}
#endif /* 0 */

/* Get the PKI user that originally authorised the issuance of a cert.  This
   can involve chaining back through multiple generations of certificates, 
   for example to check authorisation on a revocation request we might have
   to go through:

	rev_req:	get reqCertID = update_req
	update_req:	get reqCertID = cert_req
	cert_req:	get reqCertID = init_req
	init_req:	get reqCertID = pki_user */

static int getIssuingUser( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iPkiUser,
						   const char *initialCertID )
	{
	BYTE keyCertID[ DBXKEYID_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int chainingLevel, dummy, status;

	/* Walk through the chain of updates in the cert log until we find the
	   PKI user that authorised the first cert issue */
	strcpy( certID, initialCertID );
	for( chainingLevel = 0; chainingLevel < 25; chainingLevel++ )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
		char certData[ MAX_CERT_SIZE ];
		int certDataLength;

		/* Find out whether this is a PKI user.  The comparison for the 
		   action type is a bit odd since some backends will return the 
		   action as text and some as a binary numeric value, rather than 
		   relying on the backend glue code to perform the appropriate 
		   conversion we just check for either value type */
		dbmsFormatSQL( sqlBuffer,
			"SELECT action FROM certLog WHERE certID = '$'",
					   certID );
		status = dbmsQuery( sqlBuffer, certData, &certDataLength, 0,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		if( certData[ 0 ] == CRYPT_CERTACTION_ADDUSER || \
			certData[ 0 ] == TEXTCH_CERTACTION_ADDUSER )
			{
			/* We've found the PKI user, extract the ID and exit */
			base64decode( keyCertID, certData,
						  min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ),
						  CRYPT_CERTFORMAT_NONE );
			break;
			}

		/* Find the certificate that was issued, recorded either as a 
		   CERTACTION_CERT_CREATION for a multi-phase CMP-based cert 
		   creation or a CERTACTION_ISSUE_CERT for a one-step creation */
		dbmsFormatSQL( sqlBuffer,
			"SELECT reqCertID FROM certLog WHERE certID = '$'",
					   certID );
		status = dbmsQuery( sqlBuffer, certData, &certDataLength, 0,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( certID, certData,
				min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ) );

		/* Find the request to issue this certificate.  For a CMP-based issue
		   this will have an authorising object (found in the next iteration
		   through the loop), for a one-step issue it won't */
		dbmsFormatSQL( sqlBuffer,
			"SELECT reqCertID FROM certLog WHERE certID = '$'",
					   certID );
		status = dbmsQuery( sqlBuffer, certData, &certDataLength, 0,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( certID, certData,
				min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ) );
		}

	/* If we've chained through too many entries, bail out */
	if( chainingLevel >= 25 )
		return( CRYPT_ERROR_FAILED );

	/* We've found the original PKI user, get the user info */
	return( getItemData( dbmsInfo, iPkiUser, &dummy,
						 getKeyName( CRYPT_IKEYID_CERTID ), certID,
						 KEYMGMT_ITEM_PKIUSER, KEYMGMT_FLAG_NONE ) );
	}

/* Get a partially-issued certificate.  We have to perform the import
   ourselves since it's marked as an incompletely-issued cert and so is
   invisible to access via the standard cert fetch routines */

static int getNextPartialCert( DBMS_INFO *dbmsInfo,
							   CRYPT_CERTIFICATE *iCertificate,
							   BYTE *prevCertData, const BOOLEAN isRenewal )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE certificate[ MAX_CERT_SIZE ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE ];
	void *certPtr = hasBinaryBlobs( dbmsInfo ) ? \
					( void * ) certificate : encodedCertData;
	int certSize, status;

	*iCertificate = CRYPT_ERROR;

	/* Find the next cert and import it */
	status = dbmsQuery( isRenewal ? \
				"SELECT certData FROM certificates WHERE keyID LIKE '++%'" : \
				"SELECT certData FROM certificates WHERE keyID LIKE '--%'",
						certPtr, &certSize, 0, DBMS_QUERY_NORMAL );
	if( cryptStatusOK( status ) && !hasBinaryBlobs( dbmsInfo ) )
		{
		certSize = base64decode( certificate, encodedCertData, certSize,
								 CRYPT_CERTFORMAT_NONE );
		if( certSize <= 0 )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're stuck in a loop fetching the same value over and over, make
	   an emergency exit */
	if( !memcmp( prevCertData, certificate, 128 ) )
		return( CRYPT_ERROR_DUPLICATE );
	memcpy( prevCertData, certificate, 128 );

	/* Reset the first byte of the certificate data from the not-present
	   magic value to allow it to be imported and create a certificate from
	   it */
	certificate[ 0 ] = 0x30;
	setMessageCreateObjectIndirectInfo( &createInfo, certificate, certSize,
										CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*								Logging Functions							*
*																			*
****************************************************************************/

/* Add an entry to the CA log */

int updateCertLog( DBMS_INFO *dbmsInfo, const int action, const char *certID, 
				   const char *reqCertID, const char *subjCertID, 
				   const void *data, const int dataLength,
				   const DBMS_UPDATE_TYPE updateType )
	{
	char sqlFormatBuffer[ MAX_SQL_QUERY_SIZE ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ], actionString[ 5 ];
	char certIDbuffer[ DBXKEYID_BUFFER_SIZE ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE ];
	char *certIDptr = ( char * ) certID;
	const void *param1ptr, *param2ptr = "", *param3ptr = "";
	const time_t boundDate = getApproxTime();

	/* Build up the necessary SQL format string required to insert the log
	   entry.  This is complicated somewhat by the fact that some of the
	   values may be NULL, so we have to insert them by naming the columns
	   (some databases allow the use of the DEFAULT keyword but this isn't
	   standardised enough to be safe) */
	strcpy( sqlFormatBuffer,
			"INSERT INTO certLog (action, actionTime, certID" );
	if( reqCertID != NULL )
		strcat( sqlFormatBuffer, ", reqCertID" );
	if( subjCertID != NULL )
		strcat( sqlFormatBuffer, ", subjCertID" );
	if( data != NULL )
		strcat( sqlFormatBuffer, ", certData" );
	strcat( sqlFormatBuffer, ") VALUES ($, ?, '$'" );
	if( reqCertID != NULL )
		strcat( sqlFormatBuffer, ", '$'" );
	if( subjCertID != NULL )
		strcat( sqlFormatBuffer, ", '$'" );
	if( data != NULL )
		strcat( sqlFormatBuffer, hasBinaryBlobs( dbmsInfo ) ? ", ?" : ", '$'" );
	strcat( sqlFormatBuffer, ")" );

	/* Set up the appropriate parameter pointers to build the SQL command */
	if( reqCertID == NULL )
		{
		if( subjCertID == NULL )
			param1ptr = encodedCertData;
		else
			{
			param1ptr = subjCertID;
			param2ptr = encodedCertData;
			}
		}
	else
		{
		param1ptr = reqCertID;
		if( subjCertID == NULL )
			param2ptr = encodedCertData;
		else
			{
			param2ptr = subjCertID;
			param3ptr = encodedCertData;
			}
		}

	/* If we're not worried about the certID, we just insert a nonce value
	   which is used to meet the constraints for a unique entry.  In order
	   to ensure that it doesn't clash with a real certID, we set the first
	   four characters to an out-of-band value */
	if( certID == NULL )
		{
		RESOURCE_DATA msgData;
		BYTE nonce[ KEYID_SIZE ];
		int status;

		certIDptr = certIDbuffer;
		setMessageData( &msgData, nonce, KEYID_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		base64encode( certIDptr, nonce, DBXKEYID_SIZE, CRYPT_CERTTYPE_NONE );
		certIDptr[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
		memset( certIDptr, '-', 4 );
		}

	/* Update the cert log */
	sPrintf( actionString, "%d", action );
	if( !hasBinaryBlobs( dbmsInfo ) )
		base64encode( encodedCertData, data, dataLength, CRYPT_CERTTYPE_NONE );
	dbmsFormatSQL( sqlBuffer, sqlFormatBuffer, actionString, certIDptr,
				   param1ptr, param2ptr, param3ptr );
	return( dbmsUpdate( sqlBuffer, hasBinaryBlobs( dbmsInfo ) ? \
						data : NULL, dataLength, boundDate, updateType ) );
	}

static int updateCertErrorLog( DBMS_INFO *dbmsInfo, const int errorStatus,
							   const char *errorString, const char *certID,
							   const char *reqCertID, const char *subjCertID,
							   const void *data, const int dataLength )
	{
	STREAM stream;
	BYTE errorData[ MAX_CERT_SIZE ];
	const int errorStringLength = strlen( errorString );
	int errorDataLength;

	assert( data == NULL );

	/* Encode the error information:
		SEQUENCE {
			errorStatus	INTEGER,
			errorString	UTF8String,
			certData	ANY OPTIONAL
			} */
	sMemOpen( &stream, errorData, MAX_CERT_SIZE );
	writeSequence( &stream, sizeofShortInteger( -errorStatus ) + \
							( int ) sizeofObject( errorStringLength ) );
	writeShortInteger( &stream, -errorStatus, DEFAULT_TAG );
	writeCharacterString( &stream, errorString, errorStringLength,
						  BER_STRING_UTF8 );
	errorDataLength = stell( &stream );
	sMemDisconnect( &stream );

	/* Update the cert log with the error information as the data value */
	return( updateCertLog( dbmsInfo, CRYPT_CERTACTION_ERROR, certID,
						   reqCertID, subjCertID, errorData,
						   errorDataLength, DBMS_UPDATE_NORMAL ) );
	}

static int updateCertErrorLogMsg( DBMS_INFO *dbmsInfo,
								  const int errorStatus,
								  const char *errorString )
	{
	return( updateCertErrorLog( dbmsInfo, errorStatus, errorString,
								NULL, NULL, NULL, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*							Cert Revocation Functions						*
*																			*
****************************************************************************/

/* Check that a revocation request is consistent with information held in the
   cert store */

static int checkRevRequest( DBMS_INFO *dbmsInfo,
							const CRYPT_CERTIFICATE iCertRequest )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ], issuerID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	/* Check that the cert being referred to in the request is present and
	   active */
	status = getKeyID( issuerID, iCertRequest,
					   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"SELECT certData FROM certificates WHERE issuerID = '$'",
					   issuerID );
		status = dbmsStaticQuery( sqlBuffer, DBMS_QUERY_CHECK );
		}
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* The cert isn't an active cert, it's either not present or not active,
	   return an appropriate error code.  If this request has been entered
	   into the cert log then it's a duplicate request, otherwise it's a
	   request to revoke a non-present cert (either that or something really
	   obscure which is best reported as a non-present cert problem) */
	status = getKeyID( certID, iCertRequest, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"SELECT certData FROM certLog WHERE certID = '$'",
					   certID );
		status = dbmsStaticQuery( sqlBuffer, DBMS_QUERY_CHECK );
		}
	return( cryptStatusOK( status ) ? \
			CRYPT_ERROR_DUPLICATE : CRYPT_ERROR_NOTFOUND );
	}

/* Get the cert indicated in a revocation request */

static int getCertToRevoke( DBMS_INFO *dbmsInfo,
							CRYPT_CERTIFICATE *iCertificate,
							const CRYPT_CERTIFICATE iCertRequest )
	{
	char issuerID[ DBXKEYID_BUFFER_SIZE ];
	int dummy, status;

	*iCertificate = CRYPT_ERROR;

	/* Extract the certificate identity information from the request and try
	   and fetch it from the cert store */
	status = getKeyID( issuerID, iCertRequest,
					   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );
	return( getItemData( dbmsInfo, iCertificate, &dummy,
						 getKeyName( CRYPT_IKEYID_ISSUERID ), issuerID,
						 KEYMGMT_ITEM_PUBLICKEY, KEYMGMT_FLAG_NONE ) );
	}

/* Handle an indirect cert revocation (one where we need to reverse a cert
   issue or otherwise remove the cert without obtaining a direct revocation
   request from the user).  The various revocation situations are:

	Complete cert renewal				original cert supplied
		CERTACTION_REVOKE_CERT			reason = superseded
										fail -> straight delete

	Reverse issue due to cancel in CMP	original cert supplied
		CERTACTION_CREATION_REVERSE		reason = neverValid
										date = cert issue date
										fail -> straight delete

	Undo issue after restart			original cert supplied
		CERTACTION_CREATION_REVERSE		reason = neverValid
										date = cert issue date
										fail -> straight delete

	( Standard revocation				original cert not supplied
		CERTACTION_REVOKE_CERT			reason = <in request>
										delete request
										fail -> no action ) */

static int revokeCertDirect( DBMS_INFO *dbmsInfo,
							 const CRYPT_CERTIFICATE iCertificate,
							 const CRYPT_CERTACTION_TYPE action )
	{
	STATIC_FN int caRevokeCert( DBMS_INFO *dbmsInfo,
								const CRYPT_CERTIFICATE iCertRequest,
								const CRYPT_CERTIFICATE iCertificate,
								const CRYPT_CERTACTION_TYPE action );
	MESSAGE_CREATEOBJECT_INFO createInfo;
	time_t certDate;
	int status;

	assert( checkHandleRange( iCertificate ) );
	assert( action == CRYPT_CERTACTION_REVOKE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	/* Get any information needed for the revocation from the cert */
	if( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, &certDate, sizeof( time_t ) );
		status = krnlSendMessage( iCertificate, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDFROM );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create a (single-entry) CRL to contain the revocation info for the
	   certificate and revoke it via the standard channels.  We go directly
	   to a CRL rather than doing it via a revocation request because we need
	   to add information that can only be added by a CA to a CRL */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CRL );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_SETATTRIBUTE, ( void * ) &iCertificate,
							  CRYPT_CERTINFO_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		if( action == CRYPT_CERTACTION_REVOKE_CERT )
			{
			static const int crlReason = CRYPT_CRLREASON_SUPERSEDED;

			/* We're revoking the cert because we're about to replace it, set
			   the revocation reason to superseded */
			status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, ( void * ) &crlReason, 
							CRYPT_CERTINFO_CRLREASON );
			}
		else
			{
			static const int crlReason = CRYPT_CRLREASON_NEVERVALID;
			RESOURCE_DATA msgData;

			/* We're revoking a cert issued in error, set the revocation and
			   invalidity dates to the same value (the time of cert issue) in
			   the hope of ensuring that it's regarded as never being valid.
			   This isn't too accurate, but since X.509 makes the assumption
			   that all CAs are perfect and never make mistakes there's no
			   way to indicate that a cert was issued in error.  In addition
			   to this we set the extended reason to neverValid, but not too
			   many implementations will check this */
			setMessageData( &msgData, &certDate, sizeof( time_t ) );
			status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_REVOCATIONDATE );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_INVALIDITYDATE );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( createInfo.cryptHandle,
							IMESSAGE_SETATTRIBUTE, ( void * ) &crlReason, 
							CRYPT_CERTINFO_CRLREASON );
			}
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED,
								  CRYPT_IATTRIBUTE_INITIALISED );
	if( cryptStatusOK( status ) )
		status = caRevokeCert( dbmsInfo, createInfo.cryptHandle,
							   iCertificate, action );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Revoke a cert from the revocation request */

static int caRevokeCert( DBMS_INFO *dbmsInfo,
						 const CRYPT_CERTIFICATE iCertRequest,
						 const CRYPT_CERTIFICATE iCertificate,
						 const CRYPT_CERTACTION_TYPE action )
	{
	CRYPT_CERTIFICATE iLocalCertificate = iCertificate;
	CRYPT_CERTIFICATE iLocalCRL = iCertRequest;
	BYTE certData[ MAX_CERT_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ], *reqCertIDptr = reqCertID;
	char subjCertID[ DBXKEYID_BUFFER_SIZE ];
	const BOOLEAN reqPresent = \
					( action == CRYPT_CERTACTION_RESTART_REVOKE_CERT || \
					  ( action == CRYPT_CERTACTION_REVOKE_CERT && \
						iCertificate == CRYPT_UNUSED ) ) ? TRUE : FALSE;
	int certDataLength, status = CRYPT_OK;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( checkHandleRange( iCertRequest ) );
	assert( action == CRYPT_CERTACTION_REVOKE_CERT || \
			action == CRYPT_CERTACTION_RESTART_REVOKE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	/* This function handles a number of operations, summarised in the table
	   below:

		Operation			Action				Request	On disk	Cert
		---------			------				-------	-------	----
		Complete revocation	RESTART_REVOKE_CERT	Rev.req	  Yes	 --
		on restart

		Standard revocation	REVOKE_CERT			Rev.req	  Yes	 --

		Complete renewal	REVOKE_CERT			crlEntry   --	Supplied

		Reverse issue (CMP	CREATION_REVERSE	crlEntry   --	Supplied
		or due to restart)

	   The following assertion checks that the cert parameter is correct.
	   Checking the request parameter isn't so easy since it requires
	   multiple function calls, and is done as part of the code */
	assert( ( action == CRYPT_CERTACTION_RESTART_REVOKE_CERT && \
			  iCertificate == CRYPT_UNUSED ) || \
			( action == CRYPT_CERTACTION_REVOKE_CERT ) || \
			( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE && \
			  checkHandleRange( iCertificate ) ) );

	/* If it's a standard revocation (rather than one done as part of an
	   internal cert management operation, which passes in a single-entry
	   CRL), fetch the cert we're going to revoke and set up a CRL object
	   to contain the revocation information */
	if( iCertificate == CRYPT_UNUSED )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Get the cert being revoked via the revocation request and create
		   the CRL to contain the revocation information */
		status = getKeyID( reqCertID, iCertRequest,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( cryptStatusOK( status ) )
			status = getCertToRevoke( dbmsInfo, &iLocalCertificate,
									  iCertRequest );
		if( cryptStatusError( status ) )
			return( status );
		setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CRL );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iLocalCRL = createInfo.cryptHandle;

		/* Fill in the CRL from the revocation request */
		status = krnlSendMessage( iLocalCRL, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iCertRequest,
								  CRYPT_IATTRIBUTE_REVREQUEST );
		}
	else
		/* This is a direct revocation done as part of an internal cert
		   management operation, there's no explicit request for the
		   revocation present, and the caller has passed us a CRL ready to
		   use */
		reqCertIDptr = NULL;
	if( cryptStatusOK( status ) )
		status = getKeyID( subjCertID, iLocalCertificate,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iLocalCRL, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_CRLENTRY );
		certDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		{
		/* If we created the necessary objects locally rather than having
		   them passed in by the caller, we have to clean them up again
		   before we exit */
		if( iCertificate == CRYPT_UNUSED )
			{
			krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
			krnlSendNotifier( iLocalCRL, IMESSAGE_DECREFCOUNT );
			}
		return( status );
		}

	/* Update the cert store.  This is the ugliest CA operation since it
	   updates every table, luckily it's performed only rarely.  If this is
	   a reversal operation or revocation of a cert to be replaced, which is
	   a direct follow-on to a certificate creation, there's no corresponding
	   request present so we don't have to update the requests table */
	status = addCRL( dbmsInfo, iLocalCRL, iLocalCertificate,
					 DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		status = updateCertLog( dbmsInfo, action, NULL, reqCertIDptr,
								subjCertID, certData, certDataLength,
								DBMS_UPDATE_CONTINUE );
	if( cryptStatusOK( status ) && reqPresent )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certRequests WHERE certID = '$'",
					   reqCertID );
		status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_CONTINUE );
		}
	if( cryptStatusOK( status ) )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		if( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE )
			dbmsFormatSQL( sqlBuffer,
				"DELETE FROM certificates WHERE certID = '--$'",
						   subjCertID + 2 );
		else
			dbmsFormatSQL( sqlBuffer,
				"DELETE FROM certificates WHERE certID = '$'",
						   subjCertID );
		status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_COMMIT );
		}
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );
	if( iCertificate == CRYPT_UNUSED )
		{
		/* If we created the necessary objects locally rather than having
		   them passed in by the caller, we have to clean them up again
		   before we exit */
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iLocalCRL, IMESSAGE_DECREFCOUNT );
		}

	/* If the operation failed, record the details and if it was a direct
	   revocation done invisibly as part of an internal cert management
	   operation, try again with a straight delete */
	if( cryptStatusError( status ) )
		{
		updateCertErrorLog( dbmsInfo, status,
							( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE ) ? \
							"Certificate issue reversal operation failed, "
								"performing straight delete" : \
							( action == CRYPT_CERTACTION_REVOKE_CERT && \
							  iCertificate != CRYPT_UNUSED ) ? \
							"Revocation of certificate to be replaced "
								"failed, performing straight delete" :
							"Certificate revocation operation failed",
							NULL, reqCertIDptr, NULL, NULL, 0 );
		if( !reqPresent )
			{
			char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

			assert( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE || \
					action == CRYPT_CERTACTION_REVOKE_CERT );

			if( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE )
				dbmsFormatSQL( sqlBuffer,
					"DELETE FROM certificates WHERE certID = '--$'",
							   subjCertID + 2 );
			else
				dbmsFormatSQL( sqlBuffer,
					"DELETE FROM certificates WHERE certID = '$'",
							   subjCertID );
			status = dbmsStaticUpdate( sqlBuffer );
			if( cryptStatusError( status ) )
				updateCertErrorLogMsg( dbmsInfo, status, "Fallback "
									   "straight delete failed" );
			}
		}

	return( status );
	}

/* Create a CRL from revocation entries in the certificate store */

static int caIssueCRL( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCryptCRL,
					   const CRYPT_CONTEXT caKey )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE crlEntry[ MAX_CERT_SIZE ];
	BOOLEAN crlEntryAdded = FALSE;
	char crlEntryBuffer[ MAX_QUERY_RESULT_SIZE ];
	char *crlEntryPtr = crlEntryBuffer;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char nameID[ DBXKEYID_BUFFER_SIZE ];
	char *operationString;
	int operationStatus = CRYPT_OK, status;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( isWritePtr( iCryptCRL, CRYPT_CERTIFICATE * ) );
	assert( checkHandleRange( caKey ) );

	/* Extract the information we need to build the CRL from the CA cert */
	status = getKeyID( nameID, caKey, CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the CRL object to hold the entries */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CRL );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we have binary blob support, fetch the data directly into the
	   certificate buffer */
	if( hasBinaryBlobs( dbmsInfo ) )
		crlEntryPtr = ( char * ) crlEntry;

	/* Submit a query to fetch every CRL entry for this CA.  We don't have
	   to do a date check since the presence of revocation entries for
	   expired certs is controlled by whether the CA's policy involves
	   removing entries for expired certs or not */
	dbmsFormatSQL( sqlBuffer,
		"SELECT certData FROM CRLs WHERE nameID = '$'",
				   nameID );
	status = dbmsStaticQuery( sqlBuffer, DBMS_QUERY_START );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Rumble through the cert store fetching every entry and adding it to
	   the CRL.  We only stop once we've run out of entries, which ensures 
	   that some minor error at some point won't prevent the CRL from being
	   issued, however if there was a problem somewhere we create a log
	   entry to record it */
	while( status != CRYPT_ERROR_COMPLETE )
		{
		int crlEntryLength;

		status = dbmsQuery( NULL, crlEntryPtr, &crlEntryLength, 0,
							DBMS_QUERY_CONTINUE );
		if( cryptStatusOK( status ) && !hasBinaryBlobs( dbmsInfo ) )
			{
			crlEntryLength = base64decode( crlEntry, crlEntryBuffer,
									crlEntryLength, CRYPT_CERTFORMAT_NONE );
			if( crlEntryLength <= 0 )
				status = CRYPT_ERROR_BADDATA;
			}
		if( cryptStatusError( status ) && status != CRYPT_ERROR_COMPLETE && \
			cryptStatusOK( operationStatus ) )
			{
			operationStatus = status;
			operationString = "Some CRL entries couldn't be read from the "
							  "certificate store";
			}
		if( cryptStatusOK( status ) )
			{
			RESOURCE_DATA msgData;

			/* Add the entry to the CRL */
			setMessageData( &msgData, crlEntry, crlEntryLength );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_CRLENTRY );
			if( cryptStatusOK( status ) )
				crlEntryAdded = TRUE;
			else
				if( cryptStatusOK( operationStatus ) )
					{
					operationStatus = status;
					operationString = "Some CRL entries couldn't be added "
									  "to the CRL";
					}
			}
		}
	if( cryptStatusError( operationStatus ) )
		{
		/* If nothing could be added to the CRL, something is wrong, don't
		   try and continue */
		if( !crlEntryAdded )
			{
			operationString = "No CRL entries could be added to the CRL";
			updateCertErrorLogMsg( dbmsInfo, status, operationString );
			return( status );
			}

		/* At least some entries could be added to the CRL, record that there
		   was a problem but continue */
		updateCertErrorLogMsg( dbmsInfo, operationStatus, operationString );
		}

	/* We've got all the CRL entries, sign the CRL and return it to the
	   caller */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CRT_SIGN, 
							  NULL, caKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		updateCertErrorLogMsg( dbmsInfo, operationStatus,
							   "CRL creation failed" );
		}
	else
		{
		*iCryptCRL = createInfo.cryptHandle;
		updateCertLog( dbmsInfo, CRYPT_CERTACTION_ISSUE_CRL, NULL, NULL,
					   NULL, NULL, 0, DBMS_UPDATE_NORMAL );
		}

	return( status );
	}

/****************************************************************************
*																			*
*								Cert Issue Functions						*
*																			*
****************************************************************************/

/* Check that the request we've been passed is in order */

static BOOLEAN checkRequest( const CRYPT_CERTIFICATE iCertRequest,
							 const CRYPT_CERTACTION_TYPE action )
	{
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
	if( certType == CRYPT_CERTTYPE_REQUEST_CERT && \
		cryptStatusOK( \
			krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE, 
							 &value, CRYPT_CERTINFO_SELFSIGNED ) ) && \
		!value )
		{
		/* It's an unsigned CRMF request, make sure that it really is an 
		   encryption-only key */
		status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE, 
								  &value, CRYPT_CERTINFO_KEYUSAGE );
		if( cryptStatusOK( status ) && \
			( value & ( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
						CRYPT_KEYUSAGE_NONREPUDIATION ) ) )
			return( FALSE );
		}
	else
		if( certType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			status = krnlSendMessage( iCertRequest, IMESSAGE_CRT_SIGCHECK,
									  NULL, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( FALSE );
			}

	/* Check that required parameters are present.  This is necessary for
	   CRMF requests where every single parameter is optional, for our use
	   we require that a cert request contains at least a subject DN and
	   public key and a revocation request contains at least an issuer DN and
	   serial number */
	if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		RESOURCE_DATA msgData;

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
		}
	if( certType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusError( status ) )
			return( FALSE );
		}

	return( TRUE );
	}

/* Get the issue type (new request, renewal, etc) for a particular cert
   request or certificate */

static int getCertIssueType( DBMS_INFO *dbmsInfo,
							 const CRYPT_CERTIFICATE iCertificate,
							 const BOOLEAN isCert )
	{
	BYTE requestTypeData[ MAX_CERT_SIZE ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int requestTypeLength, status;

	/* Get the certID of the request that resulted in the cert creation */
	status = getKeyID( certID, iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) && isCert )
		{
		/* If it's a cert we have to apply an extra level of indirection to
		   get the request that resulted in its creation */
		dbmsFormatSQL( sqlBuffer,
			"SELECT reqCertID FROM certLog WHERE certID = '$'",
					   certID );
		status = dbmsQuery( sqlBuffer, requestTypeData, &requestTypeLength,
							0, DBMS_QUERY_NORMAL );
		if( cryptStatusOK( status ) )
			memcpy( certID, requestTypeData,
					min( requestTypeLength, MAX_ENCODED_DBXKEYID_SIZE ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Find out whether this was a cert update by checking whether it was
	   added as a standard or renewal request, then set the update type
	   appropriately.  The comparison for the action type is a bit odd since
	   some backends will return the action as text and some as a binary
	   numeric value, rather than relying on the backend glue code to
	   perform the appropriate conversion we just check for either value
	   type */
	dbmsFormatSQL( sqlBuffer,
		"SELECT action FROM certLog WHERE certID = '$'",
				   certID );
	status = dbmsQuery( sqlBuffer, requestTypeData, &requestTypeLength, 0,
						DBMS_QUERY_NORMAL );
	if( cryptStatusOK( status ) )
		switch( requestTypeData[ 0 ] )
			{
			case CRYPT_CERTACTION_REQUEST_CERT:
			case TEXTCH_CERTACTION_REQUEST_CERT:
				status = CERTADD_PARTIAL;
				break;

			case CRYPT_CERTACTION_REQUEST_RENEWAL:
			case TEXTCH_CERTACTION_REQUEST_RENEWAL:
				status = CERTADD_PARTIAL_RENEWAL;
				break;

			default:
				status = CRYPT_ERROR_NOTFOUND;
			}
	return( status );
	}

/* Replace one cert (usually a partially-issued one) with another (usually
   its completed form).  The types of operations and their corresponding
   add-type values are:

	-- -> std	CERTADD_PARTIAL				Completion of partial
	-- -> ++	CERTADD_PARTIAL_RENEWAL		First half of renewal
	++ -> std	CERTADD_RENEWAL_COMPLETE	Second half of renewal */

static int completeCert( DBMS_INFO *dbmsInfo,
						 const CRYPT_CERTIFICATE iCertificate,
						 const CERTADD_TYPE addType )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	assert( addType == CERTADD_PARTIAL || \
			addType == CERTADD_PARTIAL_RENEWAL || \
			addType == CERTADD_RENEWAL_COMPLETE );

	status = getKeyID( certID, iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );
	status = addCert( dbmsInfo, iCertificate, CRYPT_CERTTYPE_CERTIFICATE,
					  ( addType == CERTADD_PARTIAL_RENEWAL ) ? \
						CERTADD_PARTIAL_RENEWAL : CERTADD_NORMAL,
					  DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		{
		dbmsFormatSQL( sqlBuffer, ( addType == CERTADD_RENEWAL_COMPLETE ) ? \
			"DELETE FROM certificates WHERE certID = '++$'" : \
			"DELETE FROM certificates WHERE certID = '--$'",
					   certID + 2 );
		status = dbmsUpdate( sqlBuffer, NULL, 0, 0,
							 ( addType == CERTADD_PARTIAL_RENEWAL ) ? \
							 DBMS_UPDATE_COMMIT : DBMS_UPDATE_CONTINUE );
		}
	if( cryptStatusOK( status ) )
		{
		if( addType != CERTADD_PARTIAL_RENEWAL )
			status = updateCertLog( dbmsInfo,
									CRYPT_CERTACTION_CERT_CREATION_COMPLETE,
									NULL, NULL, certID, NULL, 0,
									DBMS_UPDATE_COMMIT );
		}
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );

	/* If the operation failed, record the details */
	if( cryptStatusError( status ) )
		updateCertErrorLog( dbmsInfo, status,
							"Certificate creation - completion operation "
							"failed", NULL, NULL, certID, NULL, 0 );

	return( status );
	}

/* Complete a certificate renewal operation by revoking the cert to be
   replaced and replacing it with the newly-issued cert */

static int completeCertRenewal( DBMS_INFO *dbmsInfo,
								const CRYPT_CERTIFICATE iReplaceCertificate )
	{
	CRYPT_CERTIFICATE iOrigCertificate;
	const char *keyName = getKeyName( CRYPT_IKEYID_KEYID );
	char keyID[ DBXKEYID_BUFFER_SIZE ];
	int dummy, status;

	/* Extract the key ID from the new cert and use it to fetch the existing
	   cert issued for the same key */
	status = getCertKeyID( keyID, iReplaceCertificate );
	if( cryptStatusOK( status ) )
		status = getItemData( dbmsInfo, &iOrigCertificate, &dummy,
							  keyName, keyID, KEYMGMT_ITEM_PUBLICKEY,
							  KEYMGMT_FLAG_NONE );
	if( status == CRYPT_ERROR_NOTFOUND )
		/* If the original cert fetch fails with a notfound error this is OK
		   since we may be resuming from a point where the revocation has
		   already occurred, or the cert may have already expired or been
		   otherwise replaced, so we just slide in the new cert */
		return( completeCert( dbmsInfo, iReplaceCertificate,
							  CERTADD_RENEWAL_COMPLETE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Replace the original cert with the new one */
	status = revokeCertDirect( dbmsInfo, iOrigCertificate,
							   CRYPT_CERTACTION_REVOKE_CERT );
	if( cryptStatusOK( status ) )
		status = completeCert( dbmsInfo, iReplaceCertificate,
							   CERTADD_RENEWAL_COMPLETE );
	krnlSendNotifier( iOrigCertificate, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Issue a cert from a cert request */

static int caIssueCert( DBMS_INFO *dbmsInfo,
						const CRYPT_CERTIFICATE iCertificate,
						const CRYPT_CERTIFICATE iCertRequest,
						const CRYPT_CERTACTION_TYPE action )
	{
	BYTE certData[ MAX_CERT_SIZE ];
	char issuerID[ DBXKEYID_BUFFER_SIZE ], certID[ DBXKEYID_BUFFER_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ];
	CERTADD_TYPE addType = CERTADD_NORMAL;
	int certDataLength, status;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( checkHandleRange( iCertificate ) );
	assert( checkHandleRange( iCertRequest ) );
	assert( action == CRYPT_CERTACTION_ISSUE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION );

	/* Extract the information that we need from the cert */
	status = getKeyID( certID, iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) )
		status = getKeyID( issuerID, iCertificate,
						   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCertificate, IMESSAGE_CRT_EXPORT,
								  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
		certDataLength = msgData.length;
		}
	if( cryptStatusOK( status ) )
		status = getKeyID( reqCertID, iCertRequest,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're doing a partial cert creation, handle the complexities
	   created by things like cert renewals that create pseudo-duplicates
	   while the update is taking place */
	if( action == CRYPT_CERTACTION_CERT_CREATION )
		{
		/* Make sure that this cert hasn't been added yet.  In theory we 
		   wouldn't need to do this since the keyID uniqueness constraint 
		   will catch duplicates, however duplicates are allowed for updates 
		   and won't automatically be caught for partial adds because the 
		   keyID has to be added in a special form to enable the completion 
		   of the partial add to work.  What we therefore need to check for 
		   is that a partial add (which will add the keyID in special form) 
		   won't in the future clash with a keyID in standard form.  The 
		   checking for a keyID clash in special form happens automagically 
		   through the uniqueness constraint.

		   There are two special cases in which the issue can fail during
		   the completion rather than initial add phase, one is during an
		   update (which can't be avoided, since clashes are legal for this
		   and we can't resolve things until the completion phase), and the
		   other is through a race condition caused by the following sequence
		   of updates:

				1: check keyID -> OK
				2: check keyID -> OK
				1: add as --keyID
				1: issue as keyID
				2: add as --keyID
				2: issue -> fails

		   This condition will be fairly rare.  Note that in neither case are
		   the integrity constraints of the cert issuing process violated,
		   the only thing that happens is that a failure due to duplicates
		   is detected at a later stage than it normally would be */
		status = getCertIssueType( dbmsInfo, iCertRequest, FALSE );
		if( status == CERTADD_PARTIAL )
			{
			char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
			char keyID[ DBXKEYID_BUFFER_SIZE ];

			status = getCertKeyID( keyID, iCertificate );
			if( cryptStatusError( status ) )
				return( status );
			dbmsFormatSQL( sqlBuffer,
				"SELECT certData FROM certificates WHERE keyID = '$'",
						   keyID );
			status = cryptStatusOK( dbmsStaticQuery( sqlBuffer, \
													 DBMS_QUERY_CHECK ) ) ? \
					 CRYPT_ERROR_DUPLICATE : CRYPT_OK;
			}
		if( cryptStatusError( status ) )
			return( status );

		/* This is a partial add, make sure that the cert is added in the
		   appropriate manner */
		addType = CERTADD_PARTIAL;
		}

	/* Update the cert store */
	status = addCert( dbmsInfo, iCertificate, CRYPT_CERTTYPE_CERTIFICATE,
					  addType, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		status = updateCertLog( dbmsInfo, action, certID, reqCertID, NULL,
								certData, certDataLength,
								DBMS_UPDATE_CONTINUE );
	if( cryptStatusOK( status ) )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certRequests WHERE certID = '$'",
					   reqCertID );
		status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_COMMIT );
		}
	else
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );

	/* If the operation failed, record the details */
	if( cryptStatusError( status ) )
		updateCertErrorLog( dbmsInfo, status,
							( action == CRYPT_CERTACTION_ISSUE_CERT ) ? \
								"Certificate issue operation failed" : \
								"Certificate creation operation failed",
							NULL, reqCertID, NULL, NULL, 0 );

	return( status );
	}

/* Complete a previously-started cert issue */

static int caIssueCertComplete( DBMS_INFO *dbmsInfo,
								const CRYPT_CERTIFICATE iCertificate,
								const CRYPT_CERTACTION_TYPE action )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( checkHandleRange( iCertificate ) );
	assert( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
			action == CRYPT_CERTACTION_CERT_CREATION_DROP || \
			action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	/* Extract the information we need from the cert */
	status = getKeyID( certID, iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're abandoning the certificate issue process, delete the
	   incomplete cert and exit */
	if( action == CRYPT_CERTACTION_CERT_CREATION_DROP )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certificates WHERE certID = '--$'",
					   certID + 2 );
		status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_BEGIN );
		if( cryptStatusOK( status ) )
			status = updateCertLog( dbmsInfo, action, NULL, NULL, certID,
									NULL, 0, DBMS_UPDATE_COMMIT );
		else
			/* Something went wrong, abort the transaction */
			dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );
		if( cryptStatusOK( status ) )
			return( CRYPT_OK );

		/* The operation failed, record the details and fall back to a
		   straight delete */
		updateCertErrorLog( dbmsInfo, status,
							"Certificate creation - drop operation failed, "
							"performing straight delete", NULL, NULL,
							certID, NULL, 0 );
		status = dbmsStaticUpdate( sqlBuffer );
		if( cryptStatusError( status ) )
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
		return( status );
		}

	/* If we're completing the certificate issue process, replace the
	   incomplete cert with the completed one and exit */
	if( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE )
		{
		CERTADD_TYPE issueType;

		status = getCertIssueType( dbmsInfo, iCertificate, TRUE );
		if( !cryptStatusError( status ) )
			{
			issueType = status;
			status = completeCert( dbmsInfo, iCertificate, issueType );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* If we're doing a cert renewal, complete the multi-phase update
		   required to replace an existing cert */
		if( issueType == CERTADD_PARTIAL_RENEWAL )
			status = completeCertRenewal( dbmsInfo, iCertificate );
		return( status );
		}

	/* We're reversing a cert creation, we need to explicitly revoke the cert
	   rather than just deleting it */
	assert( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	return( revokeCertDirect( dbmsInfo, iCertificate,
							  CRYPT_CERTACTION_CERT_CREATION_REVERSE ) );
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

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( checkHandleRange( iPkiUser ) );

	/* Extract the information we need from the PKI user object.  In
	   addition to simply obtaining the information for logging purposes we
	   also need to perform this action to tell the cert management code to
	   fill in the remainder of the (implicitly-added) user info before we
	   start querying fields as we add it to the cert store.  Because of this
	   we also need to place the certID read after the object export, since 
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

/* Add a cert issue or revocation request to the cert store */

int caAddCertRequest( DBMS_INFO *dbmsInfo, 
					  const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTTYPE_TYPE requestType, 
					  const BOOLEAN isRenewal )
	{
	BYTE certData[ MAX_CERT_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ], *reqCertIDptr = reqCertID;
	int certDataLength, status;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( checkHandleRange( iCertRequest ) );
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

	/* Extract the information we need from the cert request */
	status = getKeyID( certID, iCertRequest, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) )
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
		status = getKeyID( reqCertID, iCertRequest,
						   CRYPT_IATTRIBUTE_AUTHCERTID );
		if( cryptStatusError( status ) )
			{
			/* If the request is being added directly by the user, there's no
			   authorising certificate/PKI user info present */
			reqCertIDptr = NULL;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

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

			base64encode( encodedCertData, certData, certDataLength,
						  CRYPT_CERTTYPE_NONE );
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

/****************************************************************************
*																			*
*							Miscellaneous CA Functions						*
*																			*
****************************************************************************/

/* Get the PKI user that originally authorised the issuing of a cert */

int caGetIssuingUser( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iPkiUser,
					  const char *initialCertID )
	{
	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( isWritePtr( iPkiUser, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( initialCertID, MAX_ENCODED_DBXKEYID_SIZE ) );

	return( getIssuingUser( dbmsInfo, iPkiUser, initialCertID ) );
	}

/* Perform a cleanup operation on the certificate store, removing incomplete,
   expired, and otherwise leftover certificates */

static int caCleanup( DBMS_INFO *dbmsInfo,
					  const CRYPT_CERTACTION_TYPE action )
	{
	BYTE prevCertData[ 128 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	const time_t currentTime = getTime();
	int status;

	assert( isWritePtr( dbmsInfo, DBMS_INFO ) );
	assert( action == CRYPT_CERTACTION_EXPIRE_CERT || \
			action == CRYPT_CERTACTION_CLEANUP );

	/* If the time is screwed up we can't perform time-based cleanup 
	   actions */
	if( currentTime < MIN_TIME_VALUE )
		return( CRYPT_ERROR_FAILED );

	/* Rumble through the cert store either deleting leftover requests or
	   expiring every cert which is no longer current.  Since we're cleaning
	   up the cert store we try and continue even if an error occurs */
	memset( prevCertData, 0, 8 );
	do
		{
		char certID[ MAX_QUERY_RESULT_SIZE ];
		int certIDsize;

		/* Find the cert ID of the next expired cert or next cert request
		   (revocation requests are handled later by completing the
		   revocation).  Note that the select requires that the database
		   glue code return a single result and then finish the query, for
		   some backends there may be a need to explicitly cancel the query
		   after the first result is returned if the database returns an
		   entire result set */
		if( action == CRYPT_CERTACTION_EXPIRE_CERT )
			status = dbmsQuery(
						"SELECT certID FROM certificates WHERE validTo < ?",
								certID, &certIDsize, currentTime,
								DBMS_QUERY_NORMAL );
		else
			status = dbmsQuery(
						"SELECT certID FROM certRequests WHERE type = "
							TEXT_CERTTYPE_REQUEST_CERT,
								certID, &certIDsize, 0, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) || \
			certIDsize > MAX_ENCODED_DBXKEYID_SIZE )
			continue;
		certID[ certIDsize ] = '\0';
		if( !memcmp( prevCertData, certID, MAX_ENCODED_DBXKEYID_SIZE ) )
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			break;
		memcpy( prevCertData, certID, MAX_ENCODED_DBXKEYID_SIZE );

		/* Clean up/expire the cert.  Since CRYPT_CERTACTION_CLEANUP is a
		   composite action that encompasses a whole series of operations,
		   we replace it with a more specific action code */
		status = updateCertLog( dbmsInfo,
								( action == CRYPT_CERTACTION_CLEANUP ) ? \
								CRYPT_CERTACTION_RESTART_CLEANUP : action,
								NULL, NULL, certID, NULL, 0,
								DBMS_UPDATE_BEGIN );
		if( cryptStatusOK( status ) )
			{
			dbmsFormatSQL( sqlBuffer,
					   ( action == CRYPT_CERTACTION_EXPIRE_CERT ) ? \
				"DELETE FROM certificates WHERE certID = '$'" : \
				"DELETE FROM certRequests WHERE certID = '$'",
						   certID );
			status = dbmsUpdate( sqlBuffer, NULL, 0, 0, DBMS_UPDATE_COMMIT );
			}
		else
			/* Something went wrong, abort the transaction */
			dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );
		}
	while( status != CRYPT_ERROR_NOTFOUND );

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		if( action == CRYPT_CERTACTION_EXPIRE_CERT )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Expire operation "
								   "failed, performing fallback straight "
								   "delete" );
			status = dbmsUpdate(
						"DELETE FROM certificates WHERE validTo < ?",
								 NULL, 0, currentTime, DBMS_UPDATE_NORMAL );
			}
		else
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Cert request "
								   "cleanup operation failed, performing "
								   "fallback straight delete" );
			status = dbmsStaticUpdate(
						"DELETE FROM certRequests WHERE type = "
							TEXT_CERTTYPE_REQUEST_CERT );
			}
		if( cryptStatusError( status ) )
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
		}

	/* If it's an expiry action we've done the expired certs, now remove any
	   stale CRL entries and exit.  If there are no CRL entries in the
	   expiry period this isn't an error, so we remap the error code if
	   necessary */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT )
		{
		status = dbmsUpdate(
					"DELETE FROM CRLs WHERE expiryDate < ?",
							 NULL, 0, currentTime, DBMS_UPDATE_NORMAL );
		return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );
		}

	/* It's a restart, process any incompletely-issued certificates in the
	   same manner as the expiry/cleanup is handled.  Since we don't know at
	   what stage the issue process was interrupted, we have to make a worst-
	   case assumption and do a full reversal */
	memset( prevCertData, 0, 8 );
	do
		{
		CRYPT_CERTIFICATE iCertificate;

		/* Get the next partially-issued cert */
		status = getNextPartialCert( dbmsInfo, &iCertificate, prevCertData,
									 FALSE );
		if( status == CRYPT_ERROR_DUPLICATE )
			/* We're stuck in a loop fetching the same cert over and over,
			   exit */
			break;
		if( cryptStatusOK( status ) )
			{
			/* We found a cert to revoke, complete the revocation */
			status = revokeCertDirect( dbmsInfo, iCertificate,
									   CRYPT_CERTACTION_CERT_CREATION_REVERSE );
			krnlSendNotifier( iCertificate, IMESSAGE_DECREFCOUNT );
			}
		}
	while( status != CRYPT_ERROR_NOTFOUND );

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Partially-issued "
							   "certificate cleanup operation failed, "
							   "performing fallback straight delete" );
		status = dbmsStaticUpdate(
			"DELETE FROM certificates WHERE keyID LIKE '--%'" );
		if( cryptStatusError( status ) )
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
		}

	/* Now process any partially-completed renewals */
	memset( prevCertData, 0, 8 );
	do
		{
		CRYPT_CERTIFICATE iCertificate;

		/* Get the next partially-completed cert */
		status = getNextPartialCert( dbmsInfo, &iCertificate, prevCertData,
									 TRUE );
		if( status == CRYPT_ERROR_DUPLICATE )
			/* We're stuck in a loop fetching the same cert over and over,
			   exit */
			break;
		if( cryptStatusOK( status ) )
			{
			/* We found a partially-completed cert, complete the renewal */
			status = completeCertRenewal( dbmsInfo, iCertificate );
			krnlSendNotifier( iCertificate, IMESSAGE_DECREFCOUNT );
			}
		}
	while( status != CRYPT_ERROR_NOTFOUND );

	/* Finally, process any pending revocations */
	memset( prevCertData, 0, 8 );
	do
		{
		CRYPT_CERTIFICATE iCertRequest;
		const char *keyName = getKeyName( CRYPT_IKEYID_CERTID );
		char certID[ MAX_QUERY_RESULT_SIZE ];	/* Safety margin */
		int dummy, certIDsize;

		/* Find the next revocation request and import it.  This is slightly
		   ugly since we could grab it directly by fetching the data based on
		   the request type field, but there's no way to easily get to the
		   low-level import functions from here so we have to first fetch the
		   cert ID and then pass that down to the lower-level functions to
		   fetch the actual request */
		status = dbmsQuery(
					"SELECT certID FROM certRequests WHERE type = "
						TEXT_CERTTYPE_REQUEST_REVOCATION,
							certID, &certIDsize, 0, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) || \
			certIDsize > MAX_ENCODED_DBXKEYID_SIZE )
			continue;
		certID[ certIDsize ] = '\0';
		if( !memcmp( prevCertData, certID, MAX_ENCODED_DBXKEYID_SIZE ) )
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			break;
		memcpy( prevCertData, certID, MAX_ENCODED_DBXKEYID_SIZE );
		status = getItemData( dbmsInfo, &iCertRequest, &dummy, keyName, certID,
							  KEYMGMT_ITEM_REQUEST, KEYMGMT_FLAG_NONE );
		if( cryptStatusError( status ) )
			continue;

		/* Complete the revocation */
		status = caRevokeCert( dbmsInfo, iCertRequest, CRYPT_UNUSED,
							   CRYPT_CERTACTION_RESTART_REVOKE_CERT );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* This is an allowable error type, just delete the entry */
			dbmsFormatSQL( sqlBuffer,
				"DELETE FROM certRequests WHERE certID = '$'",
						   certID );
			status = dbmsStaticUpdate( sqlBuffer );
			updateCertErrorLog( dbmsInfo, status, "Deleted revocation "
								"request for non-present certificate",
								NULL, NULL, certID, NULL, 0 );
			}
		krnlSendNotifier( iCertRequest, IMESSAGE_DECREFCOUNT );
		}
	while( status != CRYPT_ERROR_NOTFOUND );

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Revocation request "
							   "cleanup operation failed, performing "
							   "fallback straight delete" );
		status = dbmsStaticUpdate(
					"DELETE FROM certRequests WHERE type = "
						TEXT_CERTTYPE_REQUEST_REVOCATION );
		if( cryptStatusError( status ) )
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Perform a cert management operation */

static int certMgmtFunction( KEYSET_INFO *keysetInfo,
							 CRYPT_CERTIFICATE *iCertificate,
							 const CRYPT_CERTIFICATE caKey,
							 const CRYPT_CERTIFICATE request,
							 const CRYPT_CERTACTION_TYPE action )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	/* In order for various SQL query strings to use the correct values the
	   type values have to match their text equivalents defined at the start
	   of this file.  Since we can't check this at compile time we have to
	   do it here via an assertion */
	assert( TEXT_CERTTYPE_REQUEST_CERT[ 0 ] - '0' == \
			CRYPT_CERTTYPE_REQUEST_CERT );
	assert( TEXT_CERTTYPE_REQUEST_REVOCATION[ 0 ] - '0' == \
			CRYPT_CERTTYPE_REQUEST_REVOCATION );
	assert( TEXT_CERTACTION_CREATE[ 0 ] - '0' == \
			CRYPT_CERTACTION_CREATE );
	assert( TEXTCH_CERTACTION_ADDUSER - '0' == \
			CRYPT_CERTACTION_ADDUSER );
	assert( TEXTCH_CERTACTION_REQUEST_CERT - '0' == \
			CRYPT_CERTACTION_REQUEST_CERT );
	assert( TEXT_CERTACTION_REQUEST_RENEWAL[ 0 ] - '0' == \
			CRYPT_CERTACTION_REQUEST_RENEWAL );
	assert( TEXTCH_CERTACTION_REQUEST_RENEWAL - '0' == \
			CRYPT_CERTACTION_REQUEST_RENEWAL );
	assert( TEXT_CERTACTION_CERT_CREATION[ 0 ] - '0' == \
			CRYPT_CERTACTION_CERT_CREATION );

	/* Clear the return value */
	if( iCertificate != NULL )
		*iCertificate = CRYPT_ERROR;

	/* If it's a simple cert expire or cleanup, there are no parameters to
	   check so we can perform the action immediately */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT || \
		action == CRYPT_CERTACTION_CLEANUP )
		{
		assert( caKey == CRYPT_UNUSED );
		assert( request == CRYPT_UNUSED );

		return( caCleanup( dbmsInfo, action ) );
		}

	/* If it's the completion of a cert creation, process it */
	if( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
		action == CRYPT_CERTACTION_CERT_CREATION_DROP || \
		action == CRYPT_CERTACTION_CERT_CREATION_REVERSE )
		{
		assert( caKey == CRYPT_UNUSED );

		return( caIssueCertComplete( dbmsInfo, request, action ) );
		}

	/* Check that the objects that we've been passed are in order.  These 
	   checks are performed automatically during the issue process by the 
	   kernel when we try and convert the request into a cert, however we 
	   perform them explicitly here so that we can return a more meaningful 
	   error message to the caller */
	if( action != CRYPT_CERTACTION_REVOKE_CERT )
		{
		/* If we're issuing a CRL, the key must be capable of CRL signing */
		if( action == CRYPT_CERTACTION_ISSUE_CRL )
			{
			int value;

			status = krnlSendMessage( caKey, IMESSAGE_GETATTRIBUTE, &value, 
									  CRYPT_CERTINFO_KEYUSAGE );
			if( cryptStatusError( status ) || \
				!( value & CRYPT_KEYUSAGE_CRLSIGN ) )
				return( CRYPT_ARGERROR_NUM1 );
			}
		else
			/* For anything else, the key must be a CA key */
			if( cryptStatusError( \
					krnlSendMessage( caKey, IMESSAGE_CHECK, NULL, 
									 MESSAGE_CHECK_CA ) ) )
				return( CRYPT_ARGERROR_NUM1 );
		}
	if( action == CRYPT_CERTACTION_ISSUE_CRL )
		{
		assert( request == CRYPT_UNUSED );

		/* If it's a CRL issue, it's a read-only operation on the CRL store
		   for which we only need the CA cert (there's no request involved) */
		return( caIssueCRL( dbmsInfo, iCertificate, caKey ) );
		}
	if( !checkRequest( request, action ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Make sure that the request is present in the request table in order 
	   to issue a certificate for it.  Again, this will be checked later, 
	   but we can return a more meaningful error here */
	status = getKeyID( reqCertID, request, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM2 );
	dbmsFormatSQL( sqlBuffer,
		"SELECT certData FROM certRequests WHERE certID = '$'",
				   reqCertID );
	status = dbmsStaticQuery( sqlBuffer, DBMS_QUERY_CHECK );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* If it's a revocation request, process it */
	if( action == CRYPT_CERTACTION_REVOKE_CERT )
		{
		assert( caKey == CRYPT_UNUSED );

		return( caRevokeCert( dbmsInfo, request, CRYPT_UNUSED,
							  CRYPT_CERTACTION_REVOKE_CERT ) );
		}

	/* It's a cert issue request */
	assert( action == CRYPT_CERTACTION_ISSUE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION );

	/* We're ready to perform the cert issue transaction.  First, we turn the
	   request into a cert */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, ( void * ) &request,
								  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CRT_SIGN, 
								  NULL, caKey );
	if( cryptStatusError( status ) )
		return( status );

	/* Then we update the cert store with the newly-issued cert */
	status = caIssueCert( dbmsInfo, createInfo.cryptHandle, request,
						  action );
	if( cryptStatusOK( status ) && iCertificate != NULL )
		*iCertificate = createInfo.cryptHandle;
	else
		/* There was a problem issuing the cert or the caller isn't
		   interested in it, destroy it */
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Set up the function pointers to the keyset methods */

int initDBMSCA( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS->certMgmtFunction = certMgmtFunction;

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
