/****************************************************************************
*																			*
*							Set Certificate Components						*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in certcget.c */

int moveCursorToField( CERT_INFO *certInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE certInfoType );
int selectGeneralName( CERT_INFO *certInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE certInfoType,
					   const SELECTION_OPTION option );
int selectDN( CERT_INFO *certInfoPtr, const CRYPT_ATTRIBUTE_TYPE certInfoType,
			  const SELECTION_OPTION option );
void syncSelection( CERT_INFO *certInfoPtr );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Set the serial number for a certificate.  Ideally we would store this as 
   a static value in the configuration database, but this has three 
   disadvantages: Updating the serial number updates the entire 
   configuration database (including things the user might not want 
   updated), if the config database update fails the serial number never 
   changes, and the predictable serial number allows tracking of the number 
   of certificates which have been issued by the CA.  Because of this, we 
   just use a 64-bit nonce if the user doesn't supply a value */

int setSerialNumber( CERT_INFO *certInfoPtr, const void *serialNumber, 
					 const int serialNumberLength )
	{
	RESOURCE_DATA msgData;
	void *serialNumberPtr;
	BYTE buffer[ 128 ];
	int length = ( serialNumberLength > 0 ) ? serialNumberLength : 8;
	int bufPos, status;

	assert( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			( serialNumber != NULL && serialNumberLength > 0 ) );

	/* If a serial number has already been set explicitly, don't override
	   it with an implicitly-set one */
	if( certInfoPtr->serialNumber != NULL )
		{
		assert( serialNumber == NULL && serialNumberLength == 0 );
		return( CRYPT_OK );
		}

	/* If we're using user-supplied serial number data, canonicalise it into 
	   a form suitable for use as an INTEGER-hole */
	if( serialNumber != NULL )
		{
		STREAM stream;

		sMemOpen( &stream, buffer, 128 );
		status = writeInteger( &stream, serialNumber, serialNumberLength, 
							   DEFAULT_TAG );
		length = stell( &stream ) - 2;
		sMemDisconnect( &stream );
		bufPos = 2;		/* Skip tag + length */
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* Generate a random serial number and ensure that the first byte of 
		   the value we use is nonzero (to guarantee a DER encoding) and 
		   clear the high bit to provide a constant-length ASN.1 encoded 
		   value */
		setMessageData( &msgData, buffer, 16 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		for( bufPos = 0; bufPos < length; bufPos++ )
			if( buffer[ bufPos ] )
				break;
		if( bufPos >= length )
			buffer[ bufPos ] = 1;
		buffer[ bufPos ] &= 0x7F;
		}

	/* Copy across the canonicalised serial number value */
	if( length < SERIALNO_BUFSIZE )
		certInfoPtr->serialNumber = certInfoPtr->serialNumberBuffer;
	else
		{
		if( ( serialNumberPtr = clDynAlloc( "setSerialNumber", \
											length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		certInfoPtr->serialNumber = serialNumberPtr;
		}
	memcpy( certInfoPtr->serialNumber, buffer + bufPos, length );
	certInfoPtr->serialNumberLength = length;

	return( CRYPT_OK );
	}

/* Copy the encoded issuer DN */

static int copyIssuerDnData( CERT_INFO *destCertInfoPtr,
						 const CERT_INFO *srcCertInfoPtr )
	{
	void *dnDataPtr;

	assert( srcCertInfoPtr->issuerDNptr != NULL );

	if( ( dnDataPtr = clAlloc( "copyIssuerDnData",
							   srcCertInfoPtr->issuerDNsize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( dnDataPtr, srcCertInfoPtr->issuerDNptr,
			srcCertInfoPtr->issuerDNsize );
	destCertInfoPtr->issuerDNptr = destCertInfoPtr->issuerDNdata = dnDataPtr;
	destCertInfoPtr->issuerDNsize = srcCertInfoPtr->issuerDNsize;

	return( CRYPT_OK );
	}

/* Copy revocation information into a CRL or revocation request */

static int copyRevocationInfo( CERT_INFO *certInfoPtr,
							   const CERT_INFO *revInfoPtr )
	{
	int status = CRYPT_OK;

	assert( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION );

	/* If there's an issuer name recorded, make sure that it matches the one
	   in the cert that's being added */
	if( certInfoPtr->issuerDNptr != NULL )
		{
		if( certInfoPtr->issuerDNsize != revInfoPtr->issuerDNsize || \
			memcmp( certInfoPtr->issuerDNptr, revInfoPtr->issuerDNptr,
					certInfoPtr->issuerDNsize ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			status = CRYPT_ERROR_INVALID;
			}
		}
	else
		/* There's no issuer name present yet, set the CRL issuer name to
		   the cert's issuer to make sure that we can't add certs or sign
		   the CRL with a different issuer.  We do this here rather than
		   after setting the revocation list entry because of the
		   difficulty of undoing the revocation entry addition */
		status = copyIssuerDnData( certInfoPtr, revInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the cert information to the revocation list and make it the
	   currently selected entry.  The ID type isn't quite an 
	   issueAndSerialNumber, but the checking code eventually converts 
	   it into this form using the supplied issuer cert DN  */
	status = addRevocationEntry( &certInfoPtr->revocations,
								 &certInfoPtr->currentRevocation,
								 CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								 revInfoPtr->serialNumber,
								 revInfoPtr->serialNumberLength, FALSE );
	if( status == CRYPT_ERROR_DUPLICATE )
		/* If this cert is already present in the list, set the extended
		   error code for it */
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
	return( status );
	}

/* Convert a DN in string form into a certificate DN */

static int getEncodedDn( CERT_INFO *certInfoPtr, const void *dnString, 
						 const int dnStringLength )
	{
	SELECTION_STATE savedState;
	int status;

	/* If there's already a DN set, we can't do anything else */
	saveSelectionState( savedState, certInfoPtr );
	status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, MUST_BE_PRESENT );
	if( cryptStatusOK( status ) && \
		*certInfoPtr->currentSelection.dnPtr == NULL )
		/* There's a DN selected but it's empty, we're OK */
		status = CRYPT_ERROR;
	restoreSelectionState( savedState, certInfoPtr );
	if( cryptStatusOK( status ) )
		return( CRYPT_ERROR_INITED );
	status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, CREATE_IF_ABSENT );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the entire DN from its string form into the selected DN */
	status = readDNstring( dnString, dnStringLength,
						   certInfoPtr->currentSelection.dnPtr );
	if( cryptStatusOK( status ) && \
		certInfoPtr->currentSelection.updateCursor )
		/* If we couldn't update the cursor earlier on because the attribute 
		   field in question hadn't been created yet, do it now */
		selectGeneralName( certInfoPtr,
						   certInfoPtr->currentSelection.generalName,
						   MAY_BE_ABSENT );
	return( status );
	}

/* The OCSPv1 ID doesn't contain any usable fields so we pre-encode it when
   the cert is added to the OCSP request and treat it as a blob thereafter */

static int writeOCSPv1ID( STREAM *stream, const CERT_INFO *certInfoPtr,
						  const void *issuerKeyHash )
	{
	HASHFUNCTION hashFunction;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
	int hashSize;

	assert( certInfoPtr->issuerDNptr != NULL );
	assert( certInfoPtr->serialNumber != NULL );

	/* Get the issuerName hash */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( NULL, hashBuffer, certInfoPtr->issuerDNptr,
				  certInfoPtr->issuerDNsize, HASH_ALL );

	/* Write the request data */
	writeSequence( stream, sizeofAlgoID( CRYPT_ALGO_SHA ) + \
						   sizeofObject( hashSize ) + \
						   sizeofObject( hashSize ) + \
						   sizeofInteger( certInfoPtr->serialNumber,
										  certInfoPtr->serialNumberLength ) );
	writeAlgoID( stream, CRYPT_ALGO_SHA );
	writeOctetString( stream, hashBuffer, hashSize, DEFAULT_TAG );
	writeOctetString( stream, issuerKeyHash, 20, DEFAULT_TAG );
	return( writeInteger( stream, certInfoPtr->serialNumber,
						  certInfoPtr->serialNumberLength, DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*								Copy Cert Info								*
*																			*
****************************************************************************/

/* Copy public key data into a certificate object */

static int copyPublicKeyInfo( CERT_INFO *certInfoPtr,
							  const CRYPT_HANDLE cryptHandle,
							  const CERT_INFO *srcCertInfoPtr )
	{
	void *publicKeyInfoPtr;
	int length, status;

	assert( ( checkHandleRange( cryptHandle ) && srcCertInfoPtr == NULL ) || \
			( !checkHandleRange( cryptHandle ) && srcCertInfoPtr != NULL ) );

	/* Make sure that we haven't already got a public key present */
	if( certInfoPtr->iPubkeyContext != CRYPT_ERROR || \
		certInfoPtr->publicKeyInfo != NULL )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* If we've been given a data-only cert, copy over the public key data */
	if( srcCertInfoPtr != NULL )
		{
		assert( srcCertInfoPtr->publicKeyAlgo > CRYPT_ALGO_NONE );
		assert( memcmp( srcCertInfoPtr->publicKeyID, 
						"\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
		assert( ( ( BYTE * ) srcCertInfoPtr->publicKeyInfo )[ 0 ] == 0x30 );

		length = srcCertInfoPtr->publicKeyInfoSize;
		if( ( publicKeyInfoPtr = clAlloc( "copyPublicKeyInfo", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( publicKeyInfoPtr, srcCertInfoPtr->publicKeyInfo, length );
		certInfoPtr->publicKeyAlgo = srcCertInfoPtr->publicKeyAlgo;
		certInfoPtr->publicKeyFeatures = srcCertInfoPtr->publicKeyFeatures;
		memcpy( certInfoPtr->publicKeyID, srcCertInfoPtr->publicKeyID,
				KEYID_SIZE );
		}
	else
		{
		CRYPT_CONTEXT iCryptContext;
		RESOURCE_DATA msgData;

		/* Get the context handle.  All other checking has already been
		   performed by the kernel */
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT,
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( status );
			}
		assert( cryptStatusOK( \
					krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_PKC ) ) );

		/* Get the key information */
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
								  &certInfoPtr->publicKeyAlgo, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
									  &certInfoPtr->publicKeyFeatures, 
									  CRYPT_IATTRIBUTE_KEYFEATURES );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, certInfoPtr->publicKeyID, KEYID_SIZE );
			status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
									  &msgData, CRYPT_IATTRIBUTE_KEYID );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Copy over the public-key data.  We copy the data rather than 
		   keeping a reference to the context for two reasons.  Firstly, 
		   when the cert is transitioned into the high state it will 
		   constrain the attached context, so a context shared between two 
		   certs could be constrained in unexpected ways.  Secondly, the 
		   context could be a private-key context, and attaching that to a 
		   cert would be rather inappropriate.  Furthermore, the constraint 
		   issue is even more problematic in that a context constrained by 
		   an encryption-only request could then no longer be used to sign 
		   the request or a PKI protocol message containing the request */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		if( cryptStatusOK( status ) )
			{
			length = msgData.length;
			if( ( publicKeyInfoPtr = clAlloc( "copyPublicKeyInfo",
											  length ) ) == NULL )
				status = CRYPT_ERROR_MEMORY;
			}
		if( cryptStatusError( status ) )
			return( status );
		msgData.data = publicKeyInfoPtr;
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		if( cryptStatusError( status ) )
			return( status );
		}
	certInfoPtr->publicKeyData = certInfoPtr->publicKeyInfo = \
		publicKeyInfoPtr;
	certInfoPtr->publicKeyInfoSize = length;
	certInfoPtr->flags |= CERT_FLAG_DATAONLY;

	return( CRYPT_OK );
	}

/* Copy cert request info into a certificate object.  This copies the public 
   key context, the DN, any valid attributes, and any other relevant bits and 
   pieces if it's a CRMF request */

static int copyCertReqInfo( CERT_INFO *certInfoPtr,
							CERT_INFO *certRequestInfoPtr )
	{
	int status;

	assert( certRequestInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
			certRequestInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT );

	/* Copy the public key context, the DN, and the attributes.  Type 
	   checking has already been performed by the kernel.  We copy the 
	   attributes across after the DN because that copy is the hardest to 
	   undo: If there are already attributes present, the copied attributes 
	   will be mixed in among them so it's not really possible to undo the 
	   copy later without performing a complex selective delete */
	status = copyDN( &certInfoPtr->subjectName,
					 certRequestInfoPtr->subjectName );
	if( cryptStatusOK( status ) )
		{
		if( certRequestInfoPtr->flags & CERT_FLAG_DATAONLY )
			status = copyPublicKeyInfo( certInfoPtr, CRYPT_UNUSED,
										certRequestInfoPtr );
		else
			status = copyPublicKeyInfo( certInfoPtr, 
										certRequestInfoPtr->iPubkeyContext,	
										NULL );
		}
	if( cryptStatusOK( status ) && \
		certRequestInfoPtr->attributes != NULL )
		{
		status = copyAttributes( &certInfoPtr->attributes,
								 certRequestInfoPtr->attributes,
								 &certInfoPtr->errorLocus,
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			deleteDN( &certInfoPtr->subjectName );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a CRMF request there could also be a validity period 
	   specified */
	if( certRequestInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		const time_t currentTime = getApproxTime();

		/* We don't allow start times backdated by more than a year, or end 
		   times before the start time.  Since these are trivial things, we
		   don't abort if there's a problem but just quietly fix the value */
		if( certRequestInfoPtr->startTime > 0 && \
			certRequestInfoPtr->startTime > currentTime - ( 86400 * 365 ) )
			certInfoPtr->startTime = certRequestInfoPtr->startTime;
		if( certRequestInfoPtr->endTime > 0 && \
			certRequestInfoPtr->endTime > certInfoPtr->startTime )
			certInfoPtr->endTime = certRequestInfoPtr->endTime;
		}

	return( CRYPT_OK );
	}

/* Copy what we need to identify the cert to be revoked and any revocation 
   information into a certificate object */

static int copyRevReqInfo( CERT_INFO *certInfoPtr,
						   CERT_INFO *revRequestInfoPtr )
	{
	int status;

	status = copyRevocationInfo( certInfoPtr, revRequestInfoPtr );
	if( cryptStatusError( status ) || \
		revRequestInfoPtr->attributes == NULL )
		return( status );
	return( copyRevocationAttributes( &certInfoPtr->attributes,
									  revRequestInfoPtr->attributes,
									  &certInfoPtr->errorLocus, 
									  &certInfoPtr->errorType ) );
	}

/* Copy user certificate info into a certificate object */

static int copyUserCertInfo( CERT_INFO *certInfoPtr,
							 CERT_INFO *userCertInfoPtr,
							 const CRYPT_HANDLE iCryptHandle )
	{
	STREAM stream;
	BYTE certHash[ CRYPT_MAX_HASHSIZE ];
	int certHashLength = CRYPT_MAX_HASHSIZE, status;

	assert( userCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			userCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	assert( userCertInfoPtr->certificate != NULL );

	/* If it's a CRL, copy the revocation information across */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		return( copyRevocationInfo( certInfoPtr, userCertInfoPtr ) );

	/* If it's a CRMF cert request, copy the public key and DN.  We copy the 
	   full DN rather than just the encoded form in case the user wants to 
	   query the request details after creating it */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		status = copyDN( &certInfoPtr->subjectName,
						 userCertInfoPtr->subjectName );
		if( cryptStatusError( status ) )
			return( status );
		if( certInfoPtr->iPubkeyContext != CRYPT_ERROR || \
			certInfoPtr->publicKeyInfo != NULL )
			/* If a key has already been added as 
			   CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, there's nothing further
			   to do.  Checking for this (rather than returning an error)
			   allows the DN information from an existing cert to be copied
			   into a request for a new key */
			return( CRYPT_OK );
		status = copyPublicKeyInfo( certInfoPtr, iCryptHandle, NULL );
		if( cryptStatusError( status ) )
			deleteDN( &certInfoPtr->subjectName );
		return( status );
		}

	/* If it's a CRMF revocation request, copy across the issuer and serial 
	   number */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		/* If the info is already present we can't add it again */
		if( certInfoPtr->issuerName != NULL )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* Copy across the issuer name and allocate any further storage that 
		   we need.  We don't care about any internal structure of the issuer 
		   DN so we just copy the pre-encoded form, we could in theory copy 
		   the full DN but it isn't really the issuer (creator) of the object 
		   so it's better if it appears to have no issuer DN than a 
		   misleading one */
		status = copyIssuerDnData( certInfoPtr, userCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		status = setSerialNumber( certInfoPtr, userCertInfoPtr->serialNumber,
								  userCertInfoPtr->serialNumberLength );
		if( cryptStatusOK( status ) && \
			certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION && \
			( certInfoPtr->subjectDNdata = \
					  clAlloc( "copyUserCertInfo",
							   userCertInfoPtr->subjectDNsize ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		if( cryptStatusError( status ) )
			{
			clFree( "copyUserCertInfo", certInfoPtr->issuerDNdata );
			certInfoPtr->issuerDNptr = certInfoPtr->issuerDNdata = NULL;
			certInfoPtr->issuerDNsize = 0;
			if( certInfoPtr->serialNumber != NULL && \
				certInfoPtr->serialNumber != certInfoPtr->serialNumberBuffer )
				clFree( "copyUserCertInfo", certInfoPtr->serialNumber );
			certInfoPtr->serialNumber = NULL;
			return( status );
			}

		/* If it's a CRMF revocation request, copy the subject DN for use in 
		   CMP */
		if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			memcpy( certInfoPtr->subjectDNdata, userCertInfoPtr->subjectDNptr,
					userCertInfoPtr->subjectDNsize );
			certInfoPtr->subjectDNptr = certInfoPtr->subjectDNdata;
			certInfoPtr->subjectDNsize = userCertInfoPtr->subjectDNsize;
			}

		return( CRYPT_OK );
		}

	/* It's an RTCS or OCSP request, remember the responder URL if there's 
	   one present (we can't leave it to be read out of the cert because 
	   authorityInfoAccess isn't a valid attribute for RTCS/OCSP requests) 
	   and copy the cert information to the validity/revocation list */
	assert( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST );

	/* If there's no responder URL set, check whether the user cert contains 
	   a responder URL in the RTCS/OCSP authorityInfoAccess GeneralName */
	if( certInfoPtr->responderUrl == NULL )
		{
		const CRYPT_ATTRIBUTE_TYPE aiaAttribute = \
					( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
					CRYPT_CERTINFO_AUTHORITYINFO_RTCS : \
					CRYPT_CERTINFO_AUTHORITYINFO_OCSP;
		SELECTION_STATE savedState;
		int urlSize;

		saveSelectionState( savedState, userCertInfoPtr );
		status = selectGeneralName( userCertInfoPtr, aiaAttribute,
									MAY_BE_ABSENT );
		if( cryptStatusOK( status ) )
			status = selectGeneralName( userCertInfoPtr,
										CRYPT_ATTRIBUTE_NONE,
										MUST_BE_PRESENT );
		if( cryptStatusOK( status ) )
			status = getCertComponent( userCertInfoPtr,
								CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
								NULL, &urlSize );
		if( cryptStatusOK( status ) )
			{
			/* There's a responder URL present, copy it to the request */
			if( ( certInfoPtr->responderUrl = \
						clAlloc( "copyUserCertInfo", urlSize ) ) == NULL )
				status = CRYPT_ERROR_MEMORY;
			else
				getCertComponent( userCertInfoPtr,
								  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
								  certInfoPtr->responderUrl,
								  &certInfoPtr->responderUrlSize );
			}
		else
			/* If there's no responder URL present it's not a (fatal) 
			   error */
			status = CRYPT_OK;
		restoreSelectionState( savedState, userCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we're using OCSP, make sure that the CA cert hash (needed for the
	   weird cert ID) is present.  We add the necessary information as a 
	   pre-encoded blob since we can't do much with the ID fields */
	if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST )
		{
		BYTE idBuffer[ 256 ], *idBufPtr = idBuffer;
		const int idLength = ( int ) \
					sizeofObject( \
						sizeofAlgoID( CRYPT_ALGO_SHA ) + \
						sizeofObject( 20 ) + sizeofObject( 20 ) + \
						sizeofInteger( userCertInfoPtr->serialNumber, \
									   userCertInfoPtr->serialNumberLength ) );

		/* Make sure there's a CA cert hash present */
		if( !certInfoPtr->certHashSet )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* Generate the OCSPv1 cert ID */
		if( idLength > 256 && \
		    ( idBufPtr = clDynAlloc( "copyUserCertInfo", \
									 idLength ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		sMemOpen( &stream, idBufPtr, idLength );
		status = writeOCSPv1ID( &stream, userCertInfoPtr,
								certInfoPtr->certHash );
		sMemDisconnect( &stream );
		if( cryptStatusOK( status ) )
			status = addRevocationEntry( &certInfoPtr->revocations,
										 &certInfoPtr->currentRevocation,
										 CRYPT_KEYID_NONE, idBufPtr, 
										 idLength, FALSE );
		if( idBufPtr != idBuffer )
			clFree( "copyUserCertInfo", idBufPtr );

		/* Add the cert information again as an ESSCertID extension to work 
		   around the problems inherent in OCSPv1 IDs.  This isn't currently 
		   used because non-cryptlib v1 responders won't understand it and 
		   cryptlib uses RTCS that doesn't have the OCSP problems */

		if( status == CRYPT_ERROR_DUPLICATE )
			/* If this cert is already present in the list, set the extended 
			   error code for it */
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( status );
		}

	/* It's an RTCS request, add the cert hash.  We read the cert hash 
	   indirectly since it's computed on demand and may not have been 
	   evaluated yet */
	status = getCertComponent( userCertInfoPtr, 
							   CRYPT_CERTINFO_FINGERPRINT_SHA, certHash, 
							   &certHashLength );
	if( cryptStatusOK( status ) )
		status = addValidityEntry( &certInfoPtr->validityInfo,
								   &certInfoPtr->currentValidity, certHash, 
								   certHashLength );
	if( status == CRYPT_ERROR_DUPLICATE )
		/* If this cert is already present in the list, set the extended 
		   error code for it */
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
	return( status );
	}

/* Get the hash of the public key (for an OCSPv1 request), possibly 
   overwriting a previous hash if there are multiple entries in the 
   request */

static int copyCaCertInfo( CERT_INFO *certInfoPtr,
						   CERT_INFO *caCertInfoPtr )
	{
	HASHFUNCTION hashFunction;
	STREAM stream;
	int length, status;

	assert( caCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			caCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	assert( caCertInfoPtr->publicKeyInfo != NULL );

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	/* Dig down into the encoded key data to find the weird bits of key that 
	   OCSP requires us to hash.  We store the result as the cert hash, 
	   which is safe because it isn't used for an OCSP request so it can't 
	   be accessed externally */
	sMemConnect( &stream, caCertInfoPtr->publicKeyInfo,
				 caCertInfoPtr->publicKeyInfoSize );
	readSequence( &stream, NULL );	/* Wrapper */
	readUniversal( &stream );		/* AlgoID */
	status = readBitStringHole( &stream, &length, DEFAULT_TAG );
	if( cryptStatusError( status ) )/* BIT STRING wrapper */
		{
		/* There's a problem with the format of the key */
		assert( NOTREACHED );
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}
	hashFunction( NULL, certInfoPtr->certHash, sMemBufPtr( &stream ),
				  length, HASH_ALL );
	certInfoPtr->certHashSet = TRUE;
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Copy revocation information from an RTCS or OCSP request to a response */

static int copyRtcsReqInfo( CERT_INFO *certInfoPtr,
							CERT_INFO *rtcsRequestInfoPtr )
	{
	int status;

	/* Copy the cert validity information and extensions */
	status = copyValidityEntries( &certInfoPtr->validityInfo,
							rtcsRequestInfoPtr->validityInfo,
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( cryptStatusOK( status ) )
		status = copyRequestAttributes( &certInfoPtr->attributes,
							rtcsRequestInfoPtr->attributes,
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	return( status );
	}

static int copyOcspReqInfo( CERT_INFO *certInfoPtr,
							CERT_INFO *ocspRequestInfoPtr )
	{
	int status;

	/* Copy the revocation information and extensions */
	status = copyRevocationEntries( &certInfoPtr->revocations,
							ocspRequestInfoPtr->revocations,
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( cryptStatusOK( status ) )
		status = copyRequestAttributes( &certInfoPtr->attributes,
							ocspRequestInfoPtr->attributes,
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the response type based on the format specifier in the request */
	certInfoPtr->responseType = OCSPRESPONSE_TYPE_OCSP;

	return( CRYPT_OK );
	}

/* Set or modify data in a cert request based on the PKI user info */

static int copyPkiUserInfo( CERT_INFO *certInfoPtr,
							CERT_INFO *pkiUserInfoPtr )
	{
	char commonName[ CRYPT_MAX_TEXTSIZE ];
	int commonNameLength, status;

	assert( pkiUserInfoPtr->type == CRYPT_CERTTYPE_PKIUSER );
	assert( pkiUserInfoPtr->certificate != NULL );

	/* If there's no DN present in the request, try and fill it in from the 
	   CA-supplied PKI user info */
	if( certInfoPtr->subjectName == NULL )
		{
		/* If neither the request nor the PKI user info has a DN present, we 
		   can't continue */
		if( pkiUserInfoPtr->subjectName == NULL )
			return( CRYPT_ERROR_NOTINITED );

		assert( pkiUserInfoPtr->subjectDNptr != NULL );

		/* There's no DN present in the request, it's been supplied by the 
		   CA in the PKI user info, copy over the DN and its encoded form 
		   from the user info */
		status = copyDN( &certInfoPtr->subjectName,
						 pkiUserInfoPtr->subjectName );
		if( cryptStatusError( status ) )
			return( status );
		if( ( certInfoPtr->subjectDNdata = \
					clAlloc( "copyPkiUserInfo",
							 pkiUserInfoPtr->subjectDNsize ) ) == NULL )
			{
			deleteDN( &certInfoPtr->subjectName );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( certInfoPtr->subjectDNdata, pkiUserInfoPtr->subjectDNptr,
				pkiUserInfoPtr->subjectDNsize );
		certInfoPtr->subjectDNptr = certInfoPtr->subjectDNdata;
		certInfoPtr->subjectDNsize = pkiUserInfoPtr->subjectDNsize;
		return( CRYPT_OK );
		}

	/* If there's no PKI user DN with the potential to conflict with the one 
	   in the request present, we're done */
	if( pkiUserInfoPtr->subjectName == NULL )
		return( CRYPT_OK );

	/* There's both a request DN and PKI user DN present.  If the request 
	   contains only a CN, combine it with the PKI user DN and update the 
	   request */
	status = getDNComponentValue( certInfoPtr->subjectName,
								  CRYPT_CERTINFO_COMMONNAME, commonName,
								  &commonNameLength, CRYPT_MAX_TEXTSIZE );
	if( cryptStatusOK( status ) )
		{
		void *tempDN = NULL;
		BOOLEAN isCommonNameDN;

		/* Check whether the request DN contains only a CN.  There's no easy 
		   way to do this directly, the only way we can do it is by creating 
		   a temporary DN consisting of only the CN and comparing it to the 
		   request DN.  We use sizeofDN() rather than compareDN() since it's 
		   much faster than a full DN comparison, this is safe because we 
		   know that both contain at least the same CN so any size mismatch 
		   indicates a DN value mismatch */
		status = insertDNComponent( &tempDN, CRYPT_CERTINFO_COMMONNAME,
									commonName, commonNameLength,
									&certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		isCommonNameDN = sizeofDN( certInfoPtr->subjectName ) == \
						 sizeofDN( tempDN );
		deleteDN( &tempDN );

		/* If the request DN consists only of a CN, append it to the PKI 
		   user DN */
		if( isCommonNameDN )
			{
			STREAM stream;
			void *tempDNdata;
			int tempDNsize;

			/* Copy the DN template, append the user-supplied CN, and
			   allocate room for the encoded form */
			status = copyDN( &tempDN, pkiUserInfoPtr->subjectName );
			if( cryptStatusError( status ) )
				return( status );
			status = insertDNComponent( &tempDN, CRYPT_CERTINFO_COMMONNAME,
										commonName, commonNameLength,
										&certInfoPtr->errorType );
			if( cryptStatusOK( status ) )
				{
				tempDNsize = sizeofDN( tempDN );
				if( ( tempDNdata = clAlloc( "copyPkiUserInfo",
											tempDNsize ) ) == NULL )
					status = CRYPT_ERROR_MEMORY;
				}
			if( cryptStatusError( status ) )
				{
				if( tempDN != NULL )
					deleteDN( &tempDN );
				return( status );
				}

			/* Everything went OK, replace the existing DN with the new one 
			   and set up the encoded form */
			deleteDN( &certInfoPtr->subjectName );
			certInfoPtr->subjectName = tempDN;
			sMemOpen( &stream, tempDNdata, tempDNsize );
			writeDN( &stream, tempDN, DEFAULT_TAG );
			assert( sStatusOK( &stream ) );
			sMemDisconnect( &stream );
			certInfoPtr->subjectDNdata = \
				certInfoPtr->subjectDNptr = tempDNdata;
			certInfoPtr->subjectDNsize = tempDNsize;

			return( CRYPT_OK );
			}
		}

	/* There are full DNs present in both objects, make sure that they're 
	   the same */
	return( compareDN( certInfoPtr->subjectName,
					   pkiUserInfoPtr->subjectName, FALSE ) ? \
			CRYPT_OK : CRYPT_ERROR_INVALID );
	}

/****************************************************************************
*																			*
*									Set Cert Info							*
*																			*
****************************************************************************/

/* Set XYZZY certificate info */

static int setXyzzyInfo( CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
						 CRYPT_KEYUSAGE_NONREPUDIATION | \
						 CRYPT_KEYUSAGE_KEYENCIPHERMENT | \
						 CRYPT_KEYUSAGE_KEYCERTSIGN | \
						 CRYPT_KEYUSAGE_CRLSIGN;
	const time_t currentTime = getApproxTime();
	int status;

	/* Make sure that we haven't already set up this certificate as a XYZZY 
	   cert */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_CERTPOLICYID,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && \
		attributeListPtr->valueLength == sizeofOID( OID_CRYPTLIB_XYZZYCERT ) && \
		!memcmp( attributeListPtr->value, OID_CRYPTLIB_XYZZYCERT, 
				 attributeListPtr->valueLength ) )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_XYZZY,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Clear any existing attribute values before trying to set new ones */
	certInfoPtr->startTime = certInfoPtr->endTime = 0;
	deleteCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE );
	deleteCertComponent( certInfoPtr, CRYPT_CERTINFO_CERTIFICATEPOLICIES );

	/* Give the cert a 20-year expiry time, make it a self-signed CA cert 
	   with all key usage types enabled, and set the policy OID to identify 
	   it as a XYZZY cert */
	certInfoPtr->startTime = currentTime;
	certInfoPtr->endTime = certInfoPtr->startTime + ( 86400 * 365 * 20 );
	certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CA,
							   MESSAGE_VALUE_TRUE, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
								   &keyUsage, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CERTPOLICYID,
								   OID_CRYPTLIB_XYZZYCERT,
								   sizeofOID( OID_CRYPTLIB_XYZZYCERT ) );
	if( cryptStatusOK( status ) )
		findAttributeFieldEx( certInfoPtr->attributes,
					CRYPT_CERTINFO_CERTPOLICYID )->flags |= ATTR_FLAG_LOCKED;
	return( status );
	}

/* Set certificate cursor info */

static int setCertCursorInfo( CERT_INFO *certInfoPtr, const int value )
	{
	const BOOLEAN isCertChain = \
					( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? \
					TRUE : FALSE;
	const BOOLEAN isRTCS = \
					( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
					  certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? \
					TRUE : FALSE;

	assert( isCertChain || certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			certInfoPtr->type == CRYPT_CERTTYPE_CRL || isRTCS || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

	/* If it's a single cert, there's nothing to do (see the 
	   CRYPT_CERTINFO_CURRENT_CERTIFICATE ACL comment for why we (apparently) 
	   allow cursor movement movement on single certificates) */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE && \
		certInfoPtr->certChainEnd <= 0 )
		return( ( value == CRYPT_CURSOR_FIRST || \
				  value == CRYPT_CURSOR_LAST ) ? \
				CRYPT_OK : CRYPT_ERROR_NOTFOUND );

	switch( value )
		{
		case CRYPT_CURSOR_FIRST:
			if( isCertChain )
				certInfoPtr->certChainPos = CRYPT_ERROR;
			else
				if( isRTCS )
					{
					certInfoPtr->currentValidity = certInfoPtr->validityInfo;
					if( certInfoPtr->currentValidity == NULL )
						return( CRYPT_ERROR_NOTFOUND );
					}
				else
					{
					certInfoPtr->currentRevocation = certInfoPtr->revocations;
					if( certInfoPtr->currentRevocation == NULL )
						return( CRYPT_ERROR_NOTFOUND );
					}
			break;

		case CRYPT_CURSOR_PREVIOUS:
			if( isCertChain )
				{
				if( certInfoPtr->certChainPos < 0 )
					return( CRYPT_ERROR_NOTFOUND );
				certInfoPtr->certChainPos--;
				}
			else
				if( isRTCS )
					{
					VALIDITY_INFO *valInfo = certInfoPtr->validityInfo;

					if( valInfo == NULL || \
						certInfoPtr->currentValidity == NULL || \
						valInfo == certInfoPtr->currentValidity )
						/* No validity info or we're already at the start of 
						   the list */
						return( CRYPT_ERROR_NOTFOUND );

					/* Find the previous element in the list */
					while( valInfo != NULL && \
						   valInfo->next != certInfoPtr->currentValidity )
						valInfo = valInfo->next;
					certInfoPtr->currentValidity = valInfo;
					}
				else
					{
					REVOCATION_INFO *revInfo = certInfoPtr->revocations;

					if( revInfo == NULL || \
						certInfoPtr->currentRevocation == NULL || \
						revInfo == certInfoPtr->currentRevocation )
						/* No revocations or we're already at the start of 
						   the list */
						return( CRYPT_ERROR_NOTFOUND );

					/* Find the previous element in the list */
					while( revInfo != NULL && \
						   revInfo->next != certInfoPtr->currentRevocation )
						revInfo = revInfo->next;
					certInfoPtr->currentRevocation = revInfo;
					}
			break;

		case CRYPT_CURSOR_NEXT:
			if( isCertChain )
				{
				if( certInfoPtr->certChainPos >= certInfoPtr->certChainEnd - 1 )
					return( CRYPT_ERROR_NOTFOUND );
				certInfoPtr->certChainPos++;
				}
			else
				if( isRTCS )
					{
					if( certInfoPtr->currentValidity == NULL || \
						certInfoPtr->currentValidity->next == NULL )
						return( CRYPT_ERROR_NOTFOUND );
					certInfoPtr->currentValidity = certInfoPtr->currentValidity->next;
					}
				else
					{
					if( certInfoPtr->currentRevocation == NULL || \
						certInfoPtr->currentRevocation->next == NULL )
						return( CRYPT_ERROR_NOTFOUND );
					certInfoPtr->currentRevocation = certInfoPtr->currentRevocation->next;
					}
			break;

		case CRYPT_CURSOR_LAST:
			if( isCertChain )
				certInfoPtr->certChainPos = certInfoPtr->certChainEnd - 1;
			else
				if( isRTCS )
					{
					VALIDITY_INFO *valInfo = certInfoPtr->validityInfo;

					if( valInfo == NULL )
						/* No validity info present */
						return( CRYPT_ERROR_NOTFOUND );

					/* Go to the end of the list */
					while( valInfo->next != NULL )
						valInfo = valInfo->next;
					certInfoPtr->currentValidity = valInfo;
					}
				else
					{
					REVOCATION_INFO *revInfo = certInfoPtr->revocations;

					if( revInfo == NULL )
						/* No revocations present */
						return( CRYPT_ERROR_NOTFOUND );

					/* Go to the end of the list */
					while( revInfo->next != NULL )
						revInfo = revInfo->next;
					certInfoPtr->currentRevocation = revInfo;
					}
			break;

		default:
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/* Set attribute cursor info */

static int setCursorInfo( CERT_INFO *certInfoPtr, 
						  const CRYPT_ATTRIBUTE_TYPE certInfoType,
						  const int value )
	{
	int status;

	assert( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION || \
			certInfoType == CRYPT_CERTINFO_CURRENT_FIELD || \
			certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT );

	/* If the new position is specified relative to a previous position, try 
	   and move to that position.  Note that the seemingly illogical 
	   comparison is used because the cursor positioning codes are negative 
	   values */
	if( value <= CRYPT_CURSOR_FIRST && value >= CRYPT_CURSOR_LAST )
		{
		/* If we're moving to an extension field and there's a saved
		   GeneralName selection present, we've tried to select a non-present 
		   GeneralName, so we can't move to a field in it */
		if( certInfoType != CRYPT_CERTINFO_CURRENT_EXTENSION && \
			certInfoPtr->currentSelection.generalName != CRYPT_ATTRIBUTE_NONE )
			return( CRYPT_ERROR_NOTFOUND );

		/* If it's an absolute positioning code, pre-set the attribute 
		   cursor if required */
		if( value == CRYPT_CURSOR_FIRST || value == CRYPT_CURSOR_LAST )
			{
			if( certInfoPtr->attributes == NULL )
				return( CRYPT_ERROR_NOTFOUND );

			/* It's an absolute attribute positioning code, reset the
			   attribute cursor to the start of the list before we try to
			   move it */
			if( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION )
				certInfoPtr->attributeCursor = certInfoPtr->attributes;
			else
				/* It's a field or component positioning code, initialise the 
				   attribute cursor if necessary */
				if( certInfoPtr->attributeCursor == NULL )
					certInfoPtr->attributeCursor = certInfoPtr->attributes;
			}
		else
			/* It's a relative positioning code, return a not-inited error
			   rather than a not-found error if the cursor isn't set since 
			   there may be attributes present but the cursor hasn't been 
			   initialised yet by selecting the first or last absolute 
			   attribute */
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTINITED );

		/* Move the attribute cursor */
		if( certInfoPtr->attributeCursor == NULL )
			return( ( value == CRYPT_CURSOR_FIRST || \
					  value == CRYPT_CURSOR_LAST ) ? \
					 CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_NOTINITED );
		status = moveAttributeCursor( &certInfoPtr->attributeCursor,
									  certInfoType, value );
		if( cryptStatusError( status ) )
			return( status );
		syncSelection( certInfoPtr );
		return( CRYPT_OK );
		}

	/* It's a field in an extension, try and move to the start of the 
	   extension that contains this field */
	if( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		attributeListPtr = findAttribute( certInfoPtr->attributes, value, 
										  TRUE );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->attributeCursor = attributeListPtr;
		syncSelection( certInfoPtr );
		return( CRYPT_OK );
		}

	assert( certInfoType == CRYPT_CERTINFO_CURRENT_FIELD || \
			certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT );
	assert( value >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			value <= CRYPT_CERTINFO_LAST_EXTENSION );

	/* If it's a GeneralName selection component, locate the attribute field 
	   that it corresponds to */
	if( isGeneralNameSelectionComponent( value ) )
		return( selectGeneralName( certInfoPtr, value, MAY_BE_ABSENT ) );

	/* It's a standard attribute field, try and locate it */
	return( moveCursorToField( certInfoPtr, value ) );
	}

/****************************************************************************
*																			*
*									Add a Component							*
*																			*
****************************************************************************/

/* Add a certificate component */

int addCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  const void *certInfo, const int certInfoLength )
	{
	CRYPT_CERTIFICATE addedCert;
	CERT_INFO *addedCertInfoPtr;
	int status;

	/* If we're adding data to a certificate, clear the error information */
	if( !isPseudoInformation( certInfoType ) )
		clearErrorInfo( certInfoPtr );

	/* If it's a GeneralName or DN component, add it.  These are special-
	   case attribute values, so they have to come before the attribute-
	   handling code */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		status = selectGeneralName( certInfoPtr, certInfoType, 
									MAY_BE_ABSENT );
		if( cryptStatusError( status ) )
			return( status );
		return( selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
								   MUST_BE_PRESENT ) );
		}
	if( isGeneralNameComponent( certInfoType ) )
		{
		status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
									CREATE_IF_ABSENT );
		if( cryptStatusOK( status ) )
			status = addAttributeField( &certInfoPtr->attributes,
					( certInfoPtr->attributeCursor != NULL ) ? \
						certInfoPtr->attributeCursor->fieldID : \
						certInfoPtr->currentSelection.generalName,
					certInfoType, certInfo, certInfoLength, ATTR_FLAG_NONE,
					&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusOK( status ) && \
			certInfoPtr->currentSelection.updateCursor )
			/* If we couldn't update the cursor earlier on because the
			   attribute field in question hadn't been created yet, do it
			   now */
			selectGeneralName( certInfoPtr,
							   certInfoPtr->currentSelection.generalName,
							   MAY_BE_ABSENT );
		return( status );
		}
	if( isDNComponent( certInfoType ) )
		{
		/* Add the string component to the DN */
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
						   CREATE_IF_ABSENT );
		if( cryptStatusOK( status ) )
			status = insertDNComponent( certInfoPtr->currentSelection.dnPtr,
									certInfoType, certInfo, certInfoLength,
									&certInfoPtr->errorType );
		if( cryptStatusOK( status ) && \
			certInfoPtr->currentSelection.updateCursor )
			/* If we couldn't update the cursor earlier on because the
			   attribute field in question hadn't been created yet, do it
			   now */
			selectGeneralName( certInfoPtr,
							   certInfoPtr->currentSelection.generalName,
							   MAY_BE_ABSENT );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_MEMORY )
			certInfoPtr->errorLocus = certInfoType;
		return( status );
		}

	/* If it's standard cert or CMS attribute, add it to the certificate */
	if( ( certInfoType >= CRYPT_CERTINFO_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_CERTINFO_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_CERTINFO_FIRST_CMS && \
		  certInfoType <= CRYPT_CERTINFO_LAST_CMS ) )
		{
		int localCertInfoType = certInfoType;

		/* Revocation reason codes are actually a single range of values
		   spread across two different extensions, so we adjust the
		   (internal) type based on the reason code value */
		if( certInfoType == CRYPT_CERTINFO_CRLREASON || \
			certInfoType == CRYPT_CERTINFO_CRLEXTREASON )
			localCertInfoType = \
					( *( ( int * ) certInfo ) < CRYPT_CRLREASON_LAST ) ? \
					CRYPT_CERTINFO_CRLREASON : CRYPT_CERTINFO_CRLEXTREASON;

		/* If it's a CRL, RTCS, or OCSP per-entry attribute, add the 
		   attribute to the currently selected entry unless it's a 
		   revocation request, in which case it goes in with the main 
		   attributes */
		if( isRevocationEntryComponent( localCertInfoType ) && \
			certInfoPtr->type != CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				{
				if( certInfoPtr->currentValidity == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				return( addAttributeField( \
						&certInfoPtr->currentValidity->attributes,
						localCertInfoType, CRYPT_ATTRIBUTE_NONE, 
						certInfo, certInfoLength, ATTR_FLAG_NONE, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
				}
			if( certInfoPtr->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			return( addAttributeField( \
						&certInfoPtr->currentRevocation->attributes,
						localCertInfoType, CRYPT_ATTRIBUTE_NONE, 
						certInfo, certInfoLength, ATTR_FLAG_NONE, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
			}

		return( addAttributeField( &certInfoPtr->attributes,
				localCertInfoType, CRYPT_ATTRIBUTE_NONE, certInfo, certInfoLength,
				ATTR_FLAG_NONE, &certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
		}

	/* If it's anything else, handle it specially */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SELFSIGNED:
			if( *( ( int * ) certInfo ) )
				certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
			else
				certInfoPtr->flags &= ~CERT_FLAG_SELFSIGNED;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_XYZZY:
			return( setXyzzyInfo( certInfoPtr ) );

		case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
			return( setCertCursorInfo( certInfoPtr,
									   *( ( int * ) certInfo ) ) );

		case CRYPT_CERTINFO_CURRENT_EXTENSION:
		case CRYPT_CERTINFO_CURRENT_FIELD:
		case CRYPT_CERTINFO_CURRENT_COMPONENT:
			return( setCursorInfo( certInfoPtr, certInfoType,
								   *( ( int * ) certInfo ) ) );

		case CRYPT_CERTINFO_TRUSTED_USAGE:
			certInfoPtr->trustedUsage = *( ( int * ) certInfo );
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_IMPLICIT:
			return( krnlSendMessage( certInfoPtr->ownerHandle,
									 IMESSAGE_SETATTRIBUTE,
									 &certInfoPtr->objectHandle,
									 *( ( int * ) certInfo ) ? \
										CRYPT_IATTRIBUTE_CERT_TRUSTED : \
										CRYPT_IATTRIBUTE_CERT_UNTRUSTED ) );

		case CRYPT_CERTINFO_SIGNATURELEVEL:
			certInfoPtr->signatureLevel = *( ( int * ) certInfo );
			return( CRYPT_OK );

		case CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO:
			return( copyPublicKeyInfo( certInfoPtr,
									   *( ( CRYPT_HANDLE * ) certInfo ), 
									   NULL ) );

		case CRYPT_CERTINFO_CERTIFICATE:
			/* If it's a certificate, copy across various components or 
			   store the entire cert where required */
			status = krnlSendMessage( *( ( CRYPT_HANDLE * ) certInfo ),
									  IMESSAGE_GETDEPENDENT, &addedCert,
									  OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );

			/* If it's a cert chain, we're adding the complete cert, just 
			   store it and exit */
			if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
				{
				int i;

				if( certInfoPtr->certChainEnd >= MAX_CHAINLENGTH - 1 )
					return( CRYPT_ERROR_OVERFLOW );

				/* Perform a simple check to make sure that it hasn't been 
				   added already */
				for( i = 0; i < certInfoPtr->certChainEnd; i++ )
					if( cryptStatusOK( \
						krnlSendMessage( addedCert, IMESSAGE_COMPARE,
										 &certInfoPtr->certChain[ i ],
										 MESSAGE_COMPARE_CERTOBJ ) ) )
						{
						setErrorInfo( certInfoPtr, 
									  CRYPT_CERTINFO_CERTIFICATE,
									  CRYPT_ERRTYPE_ATTR_PRESENT );
						return( CRYPT_ERROR_INITED );
						}

				/* Add the user cert and increment its reference count */
				krnlSendNotifier( addedCert, IMESSAGE_INCREFCOUNT );
				certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = addedCert;
				return( CRYPT_OK );
				}

			/* For remaining operations we need access to the user cert
			   internals */
			status = krnlGetObject( addedCert, OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyUserCertInfo( certInfoPtr, addedCertInfoPtr,
									   *( ( CRYPT_HANDLE * ) certInfo ) );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_CACERTIFICATE:
			/* We can't add another CA cert if there's already one present, 
			   in theory this is valid but it's more likely to be an 
			   implementation problem than an attempt to query multiple CAs 
			   through a single responder */
			if( certInfoPtr->certHashSet )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			assert( certInfoPtr->version == 1 );

			/* Get the cert handle and make sure that it really is a CA 
			   cert */
			status = krnlSendMessage( *( ( CRYPT_HANDLE * ) certInfo ),
									  IMESSAGE_GETDEPENDENT, &addedCert,
									  OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptStatusError( \
					krnlSendMessage( addedCert, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlGetObject( addedCert, OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyCaCertInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_SERIALNUMBER:
			if( certInfoPtr->serialNumber != NULL )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			return( setSerialNumber( certInfoPtr, certInfo, 
									 certInfoLength ) );

		case CRYPT_CERTINFO_SUBJECTNAME:
		case CRYPT_CERTINFO_ISSUERNAME:
			if( *( ( int * ) certInfo ) != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM1 );
			return( selectDN( certInfoPtr, certInfoType, MAY_BE_ABSENT ) );

		case CRYPT_CERTINFO_VALIDFROM:
		case CRYPT_CERTINFO_THISUPDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo );

			if( certInfoPtr->startTime )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			if( certInfoPtr->endTime && certTime >= certInfoPtr->endTime )
				{
				setErrorInfo( certInfoPtr,
							  ( certInfoType == CRYPT_CERTINFO_VALIDFROM ) ? \
								CRYPT_CERTINFO_VALIDTO : CRYPT_CERTINFO_NEXTUPDATE,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ARGERROR_STR1 );
				}
			certInfoPtr->startTime = certTime;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_VALIDTO:
		case CRYPT_CERTINFO_NEXTUPDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo );

			if( certInfoPtr->endTime )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			if( certInfoPtr->startTime && certTime <= certInfoPtr->startTime )
				{
				setErrorInfo( certInfoPtr,
							  ( certInfoType == CRYPT_CERTINFO_VALIDTO ) ? \
								CRYPT_CERTINFO_VALIDFROM : CRYPT_CERTINFO_THISUPDATE,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ARGERROR_STR1 );
				}
			certInfoPtr->endTime = certTime;
			return( CRYPT_OK );
			}
	
		case CRYPT_CERTINFO_CERTREQUEST:
			/* Make sure that we haven't already got a public key or DN
			   present */
			if( ( certInfoPtr->iPubkeyContext != CRYPT_ERROR || \
				  certInfoPtr->publicKeyInfo != NULL ) || \
				certInfoPtr->subjectName != NULL )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTREQUEST,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			status = krnlGetObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyCertReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_REVOCATIONDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo ), *revocationTimePtr;

			/* If there's a specific invalid/revoked cert selected, set its 
			   invalidity/revocation time, otherwise if there are invalid/
			   revoked certs present set the first cert's invalidity/
			   revocation time, otherwise set the default invalidity/
			   revocation time */
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				revocationTimePtr = \
						( certInfoPtr->currentValidity != NULL ) ? \
							&certInfoPtr->currentValidity->invalidityTime : \
						( certInfoPtr->validityInfo != NULL ) ? \
							&certInfoPtr->validityInfo->invalidityTime : \
							&certInfoPtr->revocationTime;
			else
				revocationTimePtr = \
						( certInfoPtr->currentRevocation != NULL ) ? \
							&certInfoPtr->currentRevocation->revocationTime : \
						( certInfoPtr->revocations != NULL ) ? \
							&certInfoPtr->revocations->revocationTime : \
							&certInfoPtr->revocationTime;
			if( *revocationTimePtr )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			*revocationTimePtr = certTime;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_DN:
			return( getEncodedDn( certInfoPtr, certInfo, certInfoLength ) );

		case CRYPT_IATTRIBUTE_CRLENTRY:
			{
			STREAM stream;

			assert( certInfoPtr->type == CRYPT_CERTTYPE_CRL );

			/* The revocation information is being provided to us in pre-
			   encoded form from a cert store, decode it so that we can add
			   it to the CRL */
			sMemConnect( &stream, certInfo, certInfoLength );
			status = readCRLentry( &stream, &certInfoPtr->revocations,
								   &certInfoPtr->errorLocus,
								   &certInfoPtr->errorType );
			sMemDisconnect( &stream );
			return( status );
			}
	
		case CRYPT_IATTRIBUTE_CERTCOLLECTION:
			return( copyCertChain( certInfoPtr,
								   *( ( CRYPT_CERTIFICATE * ) certInfo ), 
								   TRUE ) );

		case CRYPT_IATTRIBUTE_RTCSREQUEST:
			status = krnlGetObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyRtcsReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_OCSPREQUEST:
			status = krnlGetObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyOcspReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_REVREQUEST:
			status = krnlGetObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyRevReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_PKIUSERINFO:
			status = krnlGetObject( *( ( CRYPT_HANDLE * ) certInfo ),
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &addedCertInfoPtr,
									CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyPkiUserInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_AUTHCERTID:
			assert( certInfoLength == KEYID_SIZE );
			memcpy( certInfoPtr->authCertID, certInfo, KEYID_SIZE );
			return( CRYPT_OK );
		}

	/* Everything else isn't available */
	assert( NOTREACHED );
	return( CRYPT_ARGERROR_VALUE );
	}
