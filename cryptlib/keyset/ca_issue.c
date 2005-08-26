/****************************************************************************
*																			*
*					  cryptlib DBMS CA Cert Issue Interface					*
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
*								Cert Issue Functions						*
*																			*
****************************************************************************/

/* Get the issue type (new request, renewal, etc) for a particular cert
   request or certificate */

static int getCertIssueType( DBMS_INFO *dbmsInfo,
							 const CRYPT_CERTIFICATE iCertificate,
							 const BOOLEAN isCert )
	{
	BYTE certData[ MAX_QUERY_RESULT_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int certIDlength, length, status;

	/* Get the certID of the request that resulted in the cert creation */
	status = certIDlength = getKeyID( certID, iCertificate, 
									  CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( !cryptStatusError( status ) && isCert )
		{
		/* If it's a cert we have to apply an extra level of indirection to
		   get the request that resulted in its creation */
		status = dbmsQuery(
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, &length, certID, certIDlength, 0, 
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusOK( status ) )
			{
			if( length > MAX_ENCODED_DBXKEYID_SIZE )
				length = MAX_ENCODED_DBXKEYID_SIZE;
			memcpy( certID, certData, length );
			certIDlength = length;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Find out whether this was a cert update by checking whether it was
	   added as a standard or renewal request, then set the update type
	   appropriately.  The comparison for the action type is a bit odd since
	   some back-ends will return the action as text and some as a binary
	   numeric value, rather than relying on the back-end glue code to
	   perform the appropriate conversion we just check for either value
	   type */
	status = dbmsQuery(
		"SELECT action FROM certLog WHERE certID = ?",
						certData, &length, certID, certIDlength, 0, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	switch( certData[ 0 ] )
		{
		case CRYPT_CERTACTION_REQUEST_CERT:
		case TEXTCH_CERTACTION_REQUEST_CERT:
			return( CERTADD_PARTIAL );

		case CRYPT_CERTACTION_REQUEST_RENEWAL:
		case TEXTCH_CERTACTION_REQUEST_RENEWAL:
			return( CERTADD_PARTIAL_RENEWAL );

		default:
			assert( NOTREACHED );
		}
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Replace one cert (usually a partially-issued one) with another (usually
   its completed form).  The types of operations and their corresponding
   add-type values are:

	ESC1 -> std		CERTADD_PARTIAL				Completion of partial
	ESC1 -> ESC2	CERTADD_PARTIAL_RENEWAL		First half of renewal
	ESC2 -> std		CERTADD_RENEWAL_COMPLETE	Second half of renewal */

static int completeCert( DBMS_INFO *dbmsInfo,
						 const CRYPT_CERTIFICATE iCertificate,
						 const CERTADD_TYPE addType )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int length, status;

	assert( addType == CERTADD_PARTIAL || \
			addType == CERTADD_PARTIAL_RENEWAL || \
			addType == CERTADD_RENEWAL_COMPLETE );

	status = length = getKeyID( certID, iCertificate,
								CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );
	status = addCert( dbmsInfo, iCertificate, CRYPT_CERTTYPE_CERTIFICATE,
					  ( addType == CERTADD_PARTIAL_RENEWAL ) ? \
						CERTADD_PARTIAL_RENEWAL : CERTADD_NORMAL,
					  DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		{
		char specialCertID[ DBXKEYID_BUFFER_SIZE ];

		/* Turn the general certID into the form required for special-case
		   cert data */
		memcpy( specialCertID, certID, length + 1 );
		memcpy( specialCertID,
				( addType == CERTADD_RENEWAL_COMPLETE ) ? \
				KEYID_ESC2 : KEYID_ESC1, KEYID_ESC_SIZE );
		specialCertID[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
		dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certificates WHERE certID = '$'",
					   specialCertID );
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

int completeCertRenewal( DBMS_INFO *dbmsInfo,
						 const CRYPT_CERTIFICATE iReplaceCertificate )
	{
	CRYPT_CERTIFICATE iOrigCertificate;
	char keyID[ DBXKEYID_BUFFER_SIZE ];
	int dummy, length, status;

	/* Extract the key ID from the new cert and use it to fetch the existing
	   cert issued for the same key */
	status = length = getCertKeyID( keyID, iReplaceCertificate );
	if( !cryptStatusError( status ) )
		status = getItemData( dbmsInfo, &iOrigCertificate, &dummy,
							  CRYPT_IKEYID_KEYID, keyID, length,
							  KEYMGMT_ITEM_PUBLICKEY, KEYMGMT_FLAG_NONE );
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

int caIssueCert( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 const CRYPT_CERTIFICATE caKey,
				 const CRYPT_CERTIFICATE iCertRequest,
				 const CRYPT_CERTACTION_TYPE action )
	{
	CRYPT_CERTIFICATE iLocalCertificate;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE certData[ MAX_CERT_SIZE ];
	char issuerID[ DBXKEYID_BUFFER_SIZE ], certID[ DBXKEYID_BUFFER_SIZE ];
	char reqCertID[ DBXKEYID_BUFFER_SIZE ];
	CERTADD_TYPE addType = CERTADD_NORMAL;
	int certDataLength, issueType, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isHandleRangeValid( iCertRequest ) );
	assert( action == CRYPT_CERTACTION_ISSUE_CERT || \
			action == CRYPT_CERTACTION_CERT_CREATION );

	/* Clear return value */
	if( iCertificate != NULL )
		*iCertificate = CRYPT_ERROR;

	/* Extract the information that we need from the cert request */
	status = issueType = getCertIssueType( dbmsInfo, iCertRequest, FALSE );
	if( !cryptStatusError( status ) )
		status = getKeyID( reqCertID, iCertRequest,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CAMGMT_ARGERROR_REQUEST : status );

	/* We're ready to perform the cert issue transaction.  First, we turn the
	   request into a cert */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iLocalCertificate = createInfo.cryptHandle;
	status = krnlSendMessage( iLocalCertificate, IMESSAGE_SETATTRIBUTE, 
							  ( void * ) &iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Sanitise the new cert of potentially dangerous attributes.  For our 
	   use we clear all CA and CA-equivalent attributes to prevent users 
	   from submitting requests that turn them into CAs */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		const CRYPT_CERTIFICATE iTemplateCertificate = createInfo.cryptHandle;
		int value;

		/* Add the CA flag, CA-equivalent values (in this case the old 
		   Netscape usage flags, which (incredibly) are still used today by 
		   some CAs in place of the X.509 keyUsage extension), and the CA 
		   keyUsages, as disallowed values */
		status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE, 
								  MESSAGE_VALUE_TRUE, CRYPT_CERTINFO_CA );
		if( cryptStatusOK( status ) )
			{
			value = CRYPT_NS_CERTTYPE_SSLCA | CRYPT_NS_CERTTYPE_SMIMECA | \
					CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA;
			status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE, 
									  &value, CRYPT_CERTINFO_NS_CERTTYPE );
			}
		if( cryptStatusOK( status ) )
			{
			value = CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN;
			status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE, 
									  &value, CRYPT_CERTINFO_KEYUSAGE );
			}
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iLocalCertificate, IMESSAGE_SETATTRIBUTE, 
									  ( void * ) &iTemplateCertificate,
									  CRYPT_IATTRIBUTE_BLOCKEDATTRS );
		if( status == CRYPT_ERROR_INVALID )
			/* If the request would have resulted in the creation of an 
			   invalid cert, report it as an error with the request */
			status = CAMGMT_ARGERROR_REQUEST;
		krnlSendNotifier( iTemplateCertificate, IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Finally, sign the cert */
	status = krnlSendMessage( iLocalCertificate, IMESSAGE_CRT_SIGN, NULL, 
							  caKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		return( ( status == CRYPT_ARGERROR_VALUE ) ? \
				CAMGMT_ARGERROR_CAKEY : status );
		}

	/* Extract the information that we need from the newly-created cert */
	status = getKeyID( certID, iLocalCertificate, 
					   CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( !cryptStatusError( status ) )
		status = getKeyID( issuerID, iLocalCertificate,
						   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( !cryptStatusError( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iLocalCertificate, IMESSAGE_CRT_EXPORT,
								  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
		certDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		return( status );
		}

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
				1: add as ESC1+keyID
				1: issue as keyID
				2: add as ESC1+keyID
				2: issue -> fails

		   This condition will be fairly rare.  Note that in neither case are
		   the integrity constraints of the cert issuing process violated,
		   the only thing that happens is that a failure due to duplicates
		   is detected at a later stage than it normally would be */
		if( issueType == CERTADD_PARTIAL )
			{
			char keyID[ DBXKEYID_BUFFER_SIZE ];
			int length;

			status = length = getCertKeyID( keyID, iLocalCertificate );
			if( !cryptStatusError( status ) )
				status = cryptStatusOK( \
							dbmsQuery( \
				"SELECT certData FROM certificates WHERE keyID = ?",
									NULL, NULL, keyID, length, 0,
									DBMS_CACHEDQUERY_NONE,
									DBMS_QUERY_CHECK ) ) ? \
						 CRYPT_ERROR_DUPLICATE : CRYPT_OK;
			if( cryptStatusError( status ) )
				{
				krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
				return( status );
				}
			resetErrorInfo( dbmsInfo );
			}

		/* This is a partial add, make sure that the cert is added in the
		   appropriate manner */
		addType = CERTADD_PARTIAL;
		}

	/* Update the cert store */
	status = addCert( dbmsInfo, iLocalCertificate, CRYPT_CERTTYPE_CERTIFICATE,
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
		{
		updateCertErrorLog( dbmsInfo, status,
							( action == CRYPT_CERTACTION_ISSUE_CERT ) ? \
								"Certificate issue operation failed" : \
								"Certificate creation operation failed",
							NULL, reqCertID, NULL, NULL, 0 );
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* The cert has been successfully issued, return it to the caller if
	   necessary */
	if( iCertificate != NULL )
		*iCertificate = iLocalCertificate;
	else
		/* The caller isn't interested in the cert, destroy it */
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
	return( CRYPT_OK );
	}

/* Complete a previously-started cert issue */

int caIssueCertComplete( DBMS_INFO *dbmsInfo, 
						 const CRYPT_CERTIFICATE iCertificate,
						 const CRYPT_CERTACTION_TYPE action )
	{
	char certID[ DBXKEYID_BUFFER_SIZE ];
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isHandleRangeValid( iCertificate ) );
	assert( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
			action == CRYPT_CERTACTION_CERT_CREATION_DROP || \
			action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	/* Extract the information that we need from the cert */
	status = getKeyID( certID, iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );

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

	/* If we're abandoning the certificate issue process, delete the
	   incomplete cert and exit */
	if( action == CRYPT_CERTACTION_CERT_CREATION_DROP )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certificates WHERE certID = '" KEYID_ESC1 "$'",
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

	/* We're reversing a cert creation, we need to explicitly revoke the cert
	   rather than just deleting it */
	assert( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	return( revokeCertDirect( dbmsInfo, iCertificate,
							  CRYPT_CERTACTION_CERT_CREATION_REVERSE ) );
	}
#endif /* USE_DBMS */
