/****************************************************************************
*																			*
*					  cryptlib DBMS CA Cert Misc Interface					*
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

#if 0

/* Get the ultimate successor cert for one that's been superseded */

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
		BYTE keyCertID[ DBXKEYID_SIZE + BASE64_OVFL_SIZE ];
		char certData[ MAX_QUERY_RESULT_SIZE ];
		int certDataLength, length, dummy;

		/* Find the request to renew this certificate */
		status = dbmsQuery( 
			"SELECT certID FROM certLog WHERE subjCertID = ? "
			"AND action = " TEXT_CERTACTION_REQUEST_RENEWAL,
							certData, &certDataLength, certID, 
							strlen( certID ), 0, DBMS_CACHEDQUERY_NONE,
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );

		/* Find the resulting certificate */
		memcpy( certID, certData,
				min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE + 1 ) );
		certID[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
		status = dbmsQuery( 
			"SELECT certID FROM certLog WHERE reqCertID = ? "
				"AND action = " TEXT_CERTACTION_CERT_CREATION,
							certData, &certDataLength, certID, 
							strlen( certID ), 0, DBMS_CACHEDQUERY_NONE, 
							DBMS_QUERY_NORMAL );
		if( cryptStatusOK( status ) )
			{
			status = length = \
				base64decode( keyCertID, certData,
							  min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE ),
							  CRYPT_CERTFORMAT_NONE );
			assert( !cryptStatusError( status ) );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Try and get the replacement cert */
		status = getItemData( dbmsInfo, iCertificate, &dummy,
							  getKeyName( CRYPT_IKEYID_CERTID ), 
							  keyCertID, length, KEYMGMT_ITEM_PUBLICKEY, 
							  KEYMGMT_FLAG_NONE );
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
						   const char *initialCertID, 
						   const int initialCertIDlength )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int certIDlength, chainingLevel, dummy, status;

	/* Walk through the chain of updates in the cert log until we find the
	   PKI user that authorised the first cert issue */
	memcpy( certID, initialCertID, initialCertIDlength );
	certIDlength = initialCertIDlength;
	for( chainingLevel = 0; chainingLevel < 25; chainingLevel++ )
		{
		char certData[ MAX_QUERY_RESULT_SIZE ];
		int certDataLength;

		/* Find out whether this is a PKI user.  The comparison for the 
		   action type is a bit odd since some back-ends will return the 
		   action as text and some as a binary numeric value.  Rather than 
		   relying on the back-end glue code to perform the appropriate 
		   conversion we just check for either value type */
		status = dbmsQuery( 
			"SELECT action FROM certLog WHERE certID = ?",
							certData, &certDataLength, certID, certIDlength, 
							0, DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		if( certData[ 0 ] == CRYPT_CERTACTION_ADDUSER || \
			certData[ 0 ] == TEXTCH_CERTACTION_ADDUSER )
			/* We've found the PKI user, we're done */
			break;

		/* Find the certificate that was issued, recorded either as a 
		   CERTACTION_CERT_CREATION for a multi-phase CMP-based cert 
		   creation or a CERTACTION_ISSUE_CERT for a one-step creation */
		status = dbmsQuery( 
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, &certDataLength, certID, certIDlength, 
							0, DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		certIDlength = min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE );
		memcpy( certID, certData, certIDlength );

		/* Find the request to issue this certificate.  For a CMP-based issue
		   this will have an authorising object (found in the next iteration
		   through the loop), for a one-step issue it won't */
		status = dbmsQuery( 
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, &certDataLength, certID, certIDlength, 
							0, DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		certIDlength = min( certDataLength, MAX_ENCODED_DBXKEYID_SIZE );
		memcpy( certID, certData, certIDlength );
		}

	/* If we've chained through too many entries, bail out */
	if( chainingLevel >= 25 )
		return( CRYPT_ERROR_OVERFLOW );

	/* We've found the original PKI user, get the user info */
	return( getItemData( dbmsInfo, iPkiUser, &dummy, CRYPT_IKEYID_CERTID, 
						 certID, certIDlength, KEYMGMT_ITEM_PKIUSER, 
						 KEYMGMT_FLAG_NONE ) );
	}

/* Get a partially-issued certificate.  We have to perform the import
   ourselves since it's marked as an incompletely-issued cert and so is
   invisible to access via the standard cert fetch routines */

static int getNextPartialCert( DBMS_INFO *dbmsInfo,
							   CRYPT_CERTIFICATE *iCertificate,
							   BYTE *prevCertData, const BOOLEAN isRenewal )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE certificate[ MAX_QUERY_RESULT_SIZE ];
	char encodedCertData[ MAX_QUERY_RESULT_SIZE ];
	void *certPtr = hasBinaryBlobs( dbmsInfo ) ? \
					( void * ) certificate : encodedCertData;
	int certSize, status;			/* Cast needed for gcc */

	*iCertificate = CRYPT_ERROR;

	/* Find the next cert and import it.  Although this would appear to be 
	   fetching the same cert over and over again, the caller will be 
	   deleting the currently-fetched cert after we return it to them, so
	   in practice it fetches a new cert each time */
	status = dbmsQuery( isRenewal ? \
				"SELECT certData FROM certificates WHERE keyID LIKE '" KEYID_ESC2 "%'" : \
				"SELECT certData FROM certificates WHERE keyID LIKE '" KEYID_ESC1 "%'",
						certPtr, &certSize, NULL, 0, 0, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	if( !hasBinaryBlobs( dbmsInfo ) )
		{
		certSize = base64decode( certificate, MAX_CERT_SIZE, 
								 encodedCertData, certSize,
								 CRYPT_CERTFORMAT_NONE );
		if( cryptStatusError( certSize ) )
			{
			assert( NOTREACHED );
			return( certSize );
			}
		}

	/* If we're stuck in a loop fetching the same value over and over, make
	   an emergency exit */
	if( !memcmp( prevCertData, certificate, 128 ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_DUPLICATE );
		}
	memcpy( prevCertData, certificate, 128 );

	/* Reset the first byte of the cert data from the not-present magic 
	   value to allow it to be imported and create a certificate from it */
	certificate[ 0 ] = BER_SEQUENCE;
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
	const void *dataPtr = data;
	const void *param1ptr, *param2ptr = "", *param3ptr = "";
	const time_t boundDate = getApproxTime();
	int dataPtrLength = dataLength;

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
		if( cryptStatusOK( status ) )
			{
			status = base64encode( certIDptr, DBXKEYID_BUFFER_SIZE, nonce, 
								   DBXKEYID_SIZE, CRYPT_CERTTYPE_NONE );
			certIDptr[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
			}
		if( cryptStatusError( status ) )
			{
			/* Normally this is a should-never-occur error, however if 
			   cryptlib has been shut down from another thread the kernel
			   will fail all non shutdown-related calls with a permission 
			   error.  To avoid false alarms, we mask out failures due to
			   permission errors */
			assert( ( status == CRYPT_ERROR_PERMISSION ) || NOTREACHED );
			return( status );
			}
		memset( certIDptr, '-', 4 );
		}

	/* Update the cert log */
	sPrintf( actionString, "%d", action );
	if( data != NULL && !hasBinaryBlobs( dbmsInfo ) )
		{
		dataPtrLength = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE, 
									  data, dataLength, CRYPT_CERTTYPE_NONE );
		if( cryptStatusError( dataPtrLength ) )
			{
			assert( NOTREACHED );
			return( dataPtrLength );
			}
		encodedCertData[ dataPtrLength ] = '\0';
		dataPtr = encodedCertData;
		}
	dbmsFormatSQL( sqlBuffer, sqlFormatBuffer, actionString, certIDptr,
				   param1ptr, param2ptr, param3ptr );
	return( dbmsUpdate( sqlBuffer, dataPtr, dataPtrLength, boundDate, 
						updateType ) );
	}

int updateCertErrorLog( DBMS_INFO *dbmsInfo, const int errorStatus,
						const char *errorString, const char *certID,
						const char *reqCertID, const char *subjCertID,
						const void *data, const int dataLength )
	{
	STREAM stream;
	BYTE errorData[ MAX_CERT_SIZE ];
	const int errorStringLength = strlen( errorString );
	int errorDataLength, status;

	/* Encode the error information:
		SEQUENCE {
			errorStatus	INTEGER,
			errorString	UTF8String,
			certData	ANY OPTIONAL
			} */
	sMemOpen( &stream, errorData, MAX_CERT_SIZE );
	writeSequence( &stream, sizeofShortInteger( -errorStatus ) + \
							( int ) sizeofObject( errorStringLength ) + \
							dataLength );
	writeShortInteger( &stream, -errorStatus, DEFAULT_TAG );
	status = writeCharacterString( &stream, errorString, errorStringLength,
								   BER_STRING_UTF8 );
	if( dataLength > 0 )
		status = swrite( &stream, data, dataLength );
	errorDataLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		sMemOpen( &stream, errorData, MAX_CERT_SIZE );
		writeSequence( &stream, ( 1 + 1 + 1 ) + ( 1 + 1 + 31 ) );
		writeShortInteger( &stream, -( CRYPT_ERROR_FAILED ), DEFAULT_TAG );
		writeCharacterString( &stream, "Error writing error information", 31,
							  BER_STRING_UTF8 );
		errorDataLength = stell( &stream );
		sMemDisconnect( &stream );
		}

	/* Update the cert log with the error information as the data value */
	return( updateCertLog( dbmsInfo, CRYPT_CERTACTION_ERROR, certID,
						   reqCertID, subjCertID, errorData,
						   errorDataLength, DBMS_UPDATE_NORMAL ) );
	}

int updateCertErrorLogMsg( DBMS_INFO *dbmsInfo, const int errorStatus,
						   const char *errorString )
	{
	return( updateCertErrorLog( dbmsInfo, errorStatus, errorString,
								NULL, NULL, NULL, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*							Miscellaneous CA Functions						*
*																			*
****************************************************************************/

/* Get the PKI user that originally authorised the issuing of a cert */

int caGetIssuingUser( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iPkiUser,
					  const char *initialCertID, 
					  const int initialCertIDlength )
	{
	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iPkiUser, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( initialCertID, MAX_ENCODED_DBXKEYID_SIZE ) );
	assert( initialCertIDlength >= MAX_ENCODED_DBXKEYID_SIZE );

	return( getIssuingUser( dbmsInfo, iPkiUser, initialCertID, 
							initialCertIDlength ) );
	}

/* Perform a cleanup operation on the certificate store, removing incomplete,
   expired, and otherwise leftover certificates */

static int caCleanup( DBMS_INFO *dbmsInfo,
					  const CRYPT_CERTACTION_TYPE action )
	{
	BYTE prevCertData[ 128 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	const time_t currentTime = getTime();
	int errorCount, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( action == CRYPT_CERTACTION_EXPIRE_CERT || \
			action == CRYPT_CERTACTION_CLEANUP );

	/* If the time is screwed up we can't perform time-based cleanup 
	   actions */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT && \
		currentTime < MIN_TIME_VALUE )
		return( CRYPT_ERROR_FAILED );

	/* Rumble through the cert store either deleting leftover requests or
	   expiring every cert which is no longer current.  Since we're cleaning
	   up the cert store we try and continue even if an error occurs, at
	   least up to a limit */
	memset( prevCertData, 0, 8 );
	errorCount = 0;
	do
		{
		char certID[ MAX_QUERY_RESULT_SIZE ];
		int certIDlength;

		/* Find the cert ID of the next expired cert or next cert request
		   (revocation requests are handled later by completing the
		   revocation).  Note that the select requires that the database
		   glue code be capable of returning a single result and then 
		   finishing the query, for some back-ends there may be a need to 
		   explicitly cancel the query after the first result is returned if 
		   the database returns an entire result set */
		if( action == CRYPT_CERTACTION_EXPIRE_CERT )
			status = dbmsQuery(
						"SELECT certID FROM certificates WHERE validTo < ?",
								certID, &certIDlength, NULL, 0, currentTime,
								DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		else
			status = dbmsQuery(
						"SELECT certID FROM certRequests WHERE type = "
							TEXT_CERTTYPE_REQUEST_CERT,
								certID, &certIDlength, NULL, 0, 0, 
								DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) || \
			certIDlength > MAX_ENCODED_DBXKEYID_SIZE )
			{
			errorCount++;
			continue;
			}
		if( !memcmp( prevCertData, certID, certIDlength ) )
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			break;
		memcpy( prevCertData, certID, certIDlength );

		/* Clean up/expire the cert.  Since CRYPT_CERTACTION_CLEANUP is a
		   composite action that encompasses a whole series of operations,
		   we replace it with a more specific action code */
		certID[ certIDlength ] = '\0';
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
			{
			/* Something went wrong, abort the transaction */
			dbmsUpdate( NULL, NULL, 0, 0, DBMS_UPDATE_ABORT );
			errorCount++;
			}
		}
	while( status != CRYPT_ERROR_NOTFOUND && errorCount < 10 );

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
	errorCount = 0;
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
		else
			errorCount++;
		}
	while( status != CRYPT_ERROR_NOTFOUND && errorCount < 10 );

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Partially-issued "
							   "certificate cleanup operation failed, "
							   "performing fallback straight delete" );
		status = dbmsStaticUpdate(
			"DELETE FROM certificates WHERE keyID LIKE '" KEYID_ESC1 "%'" );
		if( cryptStatusError( status ) )
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
		}

	/* Now process any partially-completed renewals */
	memset( prevCertData, 0, 8 );
	errorCount = 0;
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
		else
			errorCount++;
		}
	while( status != CRYPT_ERROR_NOTFOUND && errorCount < 10 );

	/* Finally, process any pending revocations */
	memset( prevCertData, 0, 8 );
	errorCount = 0;
	do
		{
		CRYPT_CERTIFICATE iCertRequest;
		char certID[ MAX_QUERY_RESULT_SIZE ];
		int certIDlength, dummy;

		/* Find the next revocation request and import it.  This is slightly
		   ugly since we could grab it directly by fetching the data based on
		   the request type field, but there's no way to easily get to the
		   low-level import functions from here so we have to first fetch the
		   cert ID and then pass that down to the lower-level functions to
		   fetch the actual request */
		status = dbmsQuery(
					"SELECT certID FROM certRequests WHERE type = "
						TEXT_CERTTYPE_REQUEST_REVOCATION,
							certID, &certIDlength, NULL, 0, 0, 
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) || \
			certIDlength > MAX_ENCODED_DBXKEYID_SIZE )
			{
			errorCount++;
			continue;
			}
		if( !memcmp( prevCertData, certID, certIDlength ) )
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			break;
		memcpy( prevCertData, certID, certIDlength );
		status = getItemData( dbmsInfo, &iCertRequest, &dummy, 
							  CRYPT_IKEYID_CERTID, certID, certIDlength, 
							  KEYMGMT_ITEM_REQUEST, KEYMGMT_FLAG_NONE );
		if( cryptStatusError( status ) )
			{
			errorCount++;
			continue;
			}

		/* Complete the revocation */
		status = caRevokeCert( dbmsInfo, iCertRequest, CRYPT_UNUSED,
							   CRYPT_CERTACTION_RESTART_REVOKE_CERT );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* This is an allowable error type since the cert may have 
			   expired or been otherwise removed after the revocation 
			   request was received, just delete the entry */
			certID[ certIDlength ] = '\0';
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
	while( status != CRYPT_ERROR_NOTFOUND && errorCount < 10 );

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

/****************************************************************************
*																			*
*							CA Cert Management Interface					*
*																			*
****************************************************************************/

/* Perform a cert management operation */

static int certMgmtFunction( KEYSET_INFO *keysetInfo,
							 CRYPT_CERTIFICATE *iCertificate,
							 const CRYPT_CERTIFICATE caKey,
							 const CRYPT_CERTIFICATE request,
							 const CRYPT_CERTACTION_TYPE action )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	char reqCertID[ DBXKEYID_BUFFER_SIZE ];
	int length, status;

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
	assert( TEXT_CERTACTION_REQUEST_CERT[ 0 ] - '0' == \
			CRYPT_CERTACTION_REQUEST_CERT );
	assert( TEXTCH_CERTACTION_REQUEST_CERT - '0' == \
			CRYPT_CERTACTION_REQUEST_CERT );
	assert( TEXT_CERTACTION_REQUEST_RENEWAL[ 0 ] - '0' == \
			CRYPT_CERTACTION_REQUEST_RENEWAL );
	assert( TEXTCH_CERTACTION_REQUEST_RENEWAL - '0' == \
			CRYPT_CERTACTION_REQUEST_RENEWAL );
	assert( TEXT_CERTACTION_CERT_CREATION[ 0 ] - '0' == \
			CRYPT_CERTACTION_CERT_CREATION / 10 );
	assert( TEXT_CERTACTION_CERT_CREATION[ 1 ] - '0' == \
			CRYPT_CERTACTION_CERT_CREATION % 10 );

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

	/* Check that the CA key that we've been passed is in order.  These 
	   checks are performed automatically during the issue process by the 
	   kernel when we try and convert the request into a cert, however we 
	   perform them explicitly here so that we can return a more meaningful 
	   error message to the caller */
	if( action == CRYPT_CERTACTION_ISSUE_CRL )
		{
		int value;

		/* If we're issuing a CRL, the key must be capable of CRL signing */
		status = krnlSendMessage( caKey, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_KEYUSAGE );
		if( cryptStatusError( status ) || \
			!( value & CRYPT_KEYUSAGE_CRLSIGN ) )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* For anything other than a revocation action (which just updates the 
		   cert store without doing anything else), the key must be a CA key */
		if( action != CRYPT_CERTACTION_REVOKE_CERT )
			if( cryptStatusError( \
					krnlSendMessage( caKey, IMESSAGE_CHECK, NULL, 
									 MESSAGE_CHECK_CA ) ) )
				return( CRYPT_ARGERROR_NUM1 );

	/* If it's a CRL issue, it's a read-only operation on the CRL store
	   for which we only need the CA cert (there's no request involved) */
	if( action == CRYPT_CERTACTION_ISSUE_CRL )
		{
		assert( request == CRYPT_UNUSED );

		return( caIssueCRL( dbmsInfo, iCertificate, caKey ) );
		}

	/* We're processing an action that request an explicit cert request, 
	   perform further checks on the request */
	if( !checkRequest( request, action ) )
		return( CRYPT_ARGERROR_NUM2 );

	/* Make sure that the request is present in the request table in order 
	   to issue a certificate for it.  Again, this will be checked later, 
	   but we can return a more meaningful error here */
	status = length = getKeyID( reqCertID, request, 
								CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM2 );
	status = dbmsQuery( 
		"SELECT certData FROM certRequests WHERE certID = ?",
						NULL, 0, reqCertID, length, 0, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* If it's a revocation request, process it */
	if( action == CRYPT_CERTACTION_REVOKE_CERT )
		{
		assert( caKey == CRYPT_UNUSED );

		return( caRevokeCert( dbmsInfo, request, CRYPT_UNUSED,
							  CRYPT_CERTACTION_REVOKE_CERT ) );
		}

	/* It's a cert issue request, issue the certificate */
	assert( action == CRYPT_CERTACTION_ISSUE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION );
	assert( checkHandleRange( caKey ) );

	return( caIssueCert( dbmsInfo, iCertificate, caKey, request, action ) );
	}

/* Set up the function pointers to the keyset methods */

int initDBMSCA( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS->certMgmtFunction = certMgmtFunction;

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
