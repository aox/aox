/****************************************************************************
*																			*
*					cryptlib DBMS CA Cert Revocation Interface				*
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
*							Cert Revocation Functions						*
*																			*
****************************************************************************/

/* Get the cert indicated in a revocation request */

static int getCertToRevoke( DBMS_INFO *dbmsInfo,
							CRYPT_CERTIFICATE *iCertificate,
							const CRYPT_CERTIFICATE iCertRequest )
	{
	char issuerID[ DBXKEYID_BUFFER_SIZE ];
	int dummy, length, status;

	*iCertificate = CRYPT_ERROR;

	/* Extract the certificate identity information from the request and try
	   and fetch it from the cert store */
	status = length = getKeyID( issuerID, iCertRequest,
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );
	return( getItemData( dbmsInfo, iCertificate, &dummy,
						 CRYPT_IKEYID_ISSUERID, issuerID, length,
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

int revokeCertDirect( DBMS_INFO *dbmsInfo,
					  const CRYPT_CERTIFICATE iCertificate,
					  const CRYPT_CERTACTION_TYPE action )
	{
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

int caRevokeCert( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iCertRequest,
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

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
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
	   CRL), fetch the cert that we're going to revoke and set up a CRL 
	   object to contain the revocation information */
	if( iCertificate == CRYPT_UNUSED )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Get the cert being revoked via the revocation request and create
		   the CRL to contain the revocation information */
		status = getKeyID( reqCertID, iCertRequest,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( !cryptStatusError( status ) )
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
	if( !cryptStatusError( status ) )
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
				"DELETE FROM certificates WHERE certID = '" KEYID_ESC1 "$'",
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
					"DELETE FROM certificates WHERE certID = '" KEYID_ESC1 "$'",
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

int caIssueCRL( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCryptCRL,
				const CRYPT_CONTEXT caKey )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE crlEntry[ MAX_QUERY_RESULT_SIZE ];
	BOOLEAN crlEntryAdded = FALSE;
	char crlEntryBuffer[ MAX_QUERY_RESULT_SIZE ];
	void *crlEntryPtr = crlEntryBuffer;
	char nameID[ DBXKEYID_BUFFER_SIZE ];
	char *operationString;
	int operationStatus = CRYPT_OK, errorCount = 0, length, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iCryptCRL, sizeof( CRYPT_CERTIFICATE * ) ) );
	assert( checkHandleRange( caKey ) );

	/* Extract the information that we need to build the CRL from the CA 
	   cert */
	status = length = getKeyID( nameID, caKey, CRYPT_IATTRIBUTE_SUBJECT );
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
		crlEntryPtr = crlEntry;

	/* Submit a query to fetch every CRL entry for this CA.  We don't have
	   to do a date check since the presence of revocation entries for
	   expired certs is controlled by whether the CA's policy involves
	   removing entries for expired certs or not */
	status = dbmsQuery(
		"SELECT certData FROM CRLs WHERE nameID = ?",
						NULL, 0, nameID, length, 0, DBMS_CACHEDQUERY_NONE,
						DBMS_QUERY_START );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Rumble through the cert store fetching every entry and adding it to
	   the CRL.  We only stop once we've run out of entries or we hit too 
	   many errors, which ensures that some minor error at some point won't 
	   prevent the CRL from being issued, however if there was a problem 
	   somewhere we create a log entry to record it */
	do
		{
		RESOURCE_DATA msgData;
		int crlEntryLength;

		/* Read the CRL entry data */
		status = dbmsQuery( NULL, crlEntryPtr, &crlEntryLength, NULL, 0, 0,
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CONTINUE );
		if( status == CRYPT_ERROR_COMPLETE )
			{
			/* We've got all the entries, complete the query and exit */
			dbmsStaticQuery( NULL, DBMS_CACHEDQUERY_NONE,
							 DBMS_QUERY_CANCEL );
			break;
			}
		if( cryptStatusOK( status ) && !hasBinaryBlobs( dbmsInfo ) )
			{
			crlEntryLength = base64decode( crlEntry, MAX_CERT_SIZE,
										   crlEntryBuffer, crlEntryLength,
										   CRYPT_CERTFORMAT_NONE );
			if( cryptStatusError( crlEntryLength ) )
				{
				assert( NOTREACHED );
				status = crlEntryLength;
				}
			}
		if( cryptStatusError( status ) )
			{
			/* Remember the error details for later if necessary */
			if( cryptStatusOK( operationStatus ) )
				{
				operationStatus = status;
				operationString = "Some CRL entries couldn't be read from "
								  "the certificate store";
				}
			errorCount++;
			continue;
			}

		/* Add the entry to the CRL */
		setMessageData( &msgData, crlEntry, crlEntryLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_CRLENTRY );
		if( cryptStatusError( status ) )
			{
			/* Remember the error details for later if necessary */
			if( cryptStatusOK( operationStatus ) )
				{
				operationStatus = status;
				operationString = "Some CRL entries couldn't be added to "
								  "the CRL";
				}
			errorCount++;
			continue;
			}

		crlEntryAdded = TRUE;
		}
	while( status != CRYPT_ERROR_COMPLETE && errorCount < 10 );
	if( cryptStatusError( operationStatus ) )
		{
		/* If nothing could be added to the CRL, something is wrong, don't
		   try and continue */
		if( !crlEntryAdded )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "No CRL entries could "
								   "be added to the CRL" );
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
#endif /* USE_DBMS */
