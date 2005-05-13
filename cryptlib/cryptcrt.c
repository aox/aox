/****************************************************************************
*																			*
*					cryptlib Certificate Management Routines				*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

/* "By the power vested in me, I now declare this text string and this bit
	string 'name' and 'key'.  What RSA has joined, let no man put asunder".
											-- Bob Blakley */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The minimum size for an OBJECT IDENTIFIER expressed as ASCII characters */

#define MIN_ASCII_OIDSIZE	7

/* Prototypes for functions in certext.c */

BOOLEAN isValidField( const CRYPT_ATTRIBUTE_TYPE fieldID,
					  const CRYPT_CERTTYPE_TYPE certType );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Convert an ASCII OID arc sequence into an encoded OID and back.  We allow
   dots as well as whitespace for arc separators, these are an IETF-ism but
   are in common use */

static long scanValue( char **string, int *length )
	{
	char *strPtr = *string;
	long retVal = -1;
	int count = *length;

	if( count && isDigit( *strPtr ) )
		{
		retVal = *strPtr++ - '0';
		count--;
		}
	while( count && isDigit( *strPtr ) )
		{
		retVal = ( retVal * 10 ) + ( *strPtr++ - '0' );
		count--;
		}
	while( count && ( *strPtr == ' ' || *strPtr == '.' || *strPtr == '\t' ) )
		{
		strPtr++;
		count--;
		}
	if( count && !isDigit( *strPtr ) )
		retVal = -1;
	*string = strPtr;
	*length = count;
	return( retVal );
	}

int textToOID( const char *oid, const int oidLength, BYTE *binaryOID )
	{
	char *oidPtr = ( char * ) oid;
	long value, val2;
	int length = 3, count = oidLength;

	/* Perform some basic checks and make sure that the first two arcs are in
	   order */
	if( oidLength < MIN_ASCII_OIDSIZE || oidLength > CRYPT_MAX_TEXTSIZE )
		return( 0 );
	while( count && ( *oidPtr == ' ' || *oidPtr == '.' || *oidPtr == '\t' ) )
		{
		oidPtr++;	/* Skip leading whitespace */
		count--;
		}
	value = scanValue( &oidPtr, &count );
	val2 = scanValue( &oidPtr, &count );
	if( value < 0 || value > 2 || val2 < 1 || \
		( ( value < 2 && val2 > 39 ) || ( value == 2 && val2 > 175 ) ) )
		return( 0 );
	binaryOID[ 0 ] = 0x06;	/* OBJECT IDENTIFIER tag */
	binaryOID[ 2 ] = ( BYTE )( ( value * 40 ) + val2 );

	/* Convert the remaining arcs */
	while( count )
		{
		BOOLEAN hasHighBits = FALSE;

		/* Scan the next value and write the high octets (if necessary) with
		   flag bits set, followed by the final octet */
		value = scanValue( &oidPtr, &count );
		if( value < 0 )
			break;
		if( value >= 16384 )
			{
			binaryOID[ length++ ] = ( BYTE ) ( 0x80 | ( value >> 14 ) );
			value %= 16384;
			hasHighBits = TRUE;
			}
		if( ( value > 128 ) || hasHighBits )
			{
			binaryOID[ length++ ] = ( BYTE ) ( 0x80 | ( value >> 7 ) );
			value %= 128;
			}
		binaryOID[ length++ ] = ( BYTE ) value;
		if( length >= MAX_OID_SIZE - 2 )
			return( 0 );
		}
	binaryOID[ 1 ] = length - 2;

	return( value == -1 ? 0 : length );
	}

/* Compare values to data in a certificate */

static int compareCertInfo( CERT_INFO *certInfoPtr, const int compareType,
							const void *messageDataPtr )
	{
	const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int status;

	switch( compareType )
		{
		case MESSAGE_COMPARE_SUBJECT:
			if( msgData->length != certInfoPtr->subjectDNsize || \
				memcmp( msgData->data, certInfoPtr->subjectDNptr,
						certInfoPtr->subjectDNsize ) )
				return( CRYPT_ERROR );
			return( CRYPT_OK );

		case MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
			{
			STREAM stream;
			const BYTE *dataStart;
			int serialNoLength, length;

			if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
				return( CRYPT_ERROR );

			/* Comparing an iAndS can get quite tricky because of assorted 
			   braindamage in encoding methods, so that two dissimilar 
			   iAndSs aren't necessarily supposed to be regarded as non-
			   equal.  First we try a trivial reject check, if that passes 
			   we compare the issuerName and serialNumber with corrections 
			   for common encoding braindamage.  Note that even this 
			   comparison can fail since older versions of the Entegrity 
			   toolkit rewrote T61Strings in certs as PrintableStrings in 
			   recipientInfo, which means that any kind of straight 
			   comparison fails.  We don't bother handling this sort of 
			   thing, and it's likely that most other software won't either 
			   (this situation only occurs when a cert issuerName contains 
			   PrintableString text incorrectly encoded as T61String, which 
			   is rare enough that it required artifically-created certs 
			   just to reproduce the problem).  In addition the trivial 
			   reject check can also fail since in an extreme encoding 
			   braindamage case a BMPString rewritten as a PrintableString 
			   would experience a large enough change in length to fail the 
			   check, but as with the Entegrity problem this is a level of 
			   brokenness up with which we will not put */
			length = ( int ) sizeofObject( \
						certInfoPtr->issuerDNsize + \
						sizeofObject( certInfoPtr->cCertCert->serialNumberLength ) );
			if( length < msgData->length - 2 || \
				length > msgData->length + 2 )
				/* Trivial reject, the lengths are too dissimilar for any 
				   fixup attempts to work */
				return( CRYPT_ERROR );

			/* We got past the trivial reject check, try a more detailed check, 
			   first the issuerName */
			sMemConnect( &stream, msgData->data, msgData->length );
			readSequence( &stream, NULL );
			dataStart = sMemBufPtr( &stream );
			length = getObjectLength( dataStart, msgData->length - 2 );
			status = readUniversal( &stream );
			if( cryptStatusError( status ) || \
				length != certInfoPtr->issuerDNsize || \
				memcmp( dataStart, certInfoPtr->issuerDNptr,
						certInfoPtr->issuerDNsize ) )
				{
				sMemDisconnect( &stream );
				return( CRYPT_ERROR );
				}

			/* Compare the serialNumber */
			readGenericHole( &stream, &serialNoLength, BER_INTEGER );
			dataStart = sMemBufPtr( &stream );
			status = sSkip( &stream, serialNoLength );
			sMemDisconnect( &stream );
			if( cryptStatusError( status ) )
				return( CRYPT_ERROR );
			if( compareSerialNumber( certInfoPtr->cCertCert->serialNumber,
									 certInfoPtr->cCertCert->serialNumberLength,
									 dataStart, serialNoLength ) )
				return( CRYPT_ERROR );

			return( CRYPT_OK );
			}

		case MESSAGE_COMPARE_FINGERPRINT:
			{
			BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
			int fingerPrintLength = CRYPT_MAX_HASHSIZE;

			/* If the cert hasn't been signed yet, we can't compare the 
			   fingerprint */
			if( certInfoPtr->certificate == NULL )
				return( CRYPT_ERROR_NOTINITED );
			
			/* Get the cert fingerprint and compare it to what we've been 
			   given */
			status = getCertComponent( certInfoPtr, 
									   CRYPT_CERTINFO_FINGERPRINT_SHA,
									   fingerPrint, &fingerPrintLength );
			if( cryptStatusOK( status ) && \
				( msgData->length != fingerPrintLength || \
				  memcmp( msgData->data, fingerPrint, fingerPrintLength ) ) )
				status = CRYPT_ERROR;
			return( status );
			}

		case MESSAGE_COMPARE_CERTOBJ:
			{
			CERT_INFO *certInfoPtr2;

			status = krnlAcquireObject( *( ( CRYPT_CERTIFICATE * ) messageDataPtr ), 
										OBJECT_TYPE_CERTIFICATE, 
										( void ** ) &certInfoPtr2,
										CRYPT_ERROR_SIGNALLED );
			if( cryptStatusError( status ) )
				return( status );
			if( certInfoPtr->certificate == NULL || \
				certInfoPtr2->certificate == NULL )
				{
				/* If the cert objects haven't been signed yet, we can't 
				   compare them */
				krnlReleaseObject( certInfoPtr2->objectHandle );
				return( CRYPT_ERROR_NOTINITED );
				}

			/* Compare the encoded certificate data.  This is the same as
			   comparing the fingerprint without requiring any hashing */
			status = ( certInfoPtr->certificateSize == \
								certInfoPtr2->certificateSize && \
					   !memcmp( certInfoPtr->certificate, certInfoPtr2->certificate,
								certInfoPtr->certificateSize ) ) ? \
					 CRYPT_OK : CRYPT_ERROR;
			krnlReleaseObject( certInfoPtr2->objectHandle );
			return( status );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*					Internal Certificate/Key Management Functions			*
*																			*
****************************************************************************/

/* Import a certificate blob or cert chain by sending get_next_cert messages 
   to the source object to obtain all the certs in a chain.  Returns the 
   length of the certificate.
   
   This isn't really a direct certificate function since the control flow 
   sequence is:

	import indirect: 
		GETNEXTCERT -> source object
			source object: 
				CREATEOBJECT_INDIRECT -> system device
					system device: createCertificate() 
		GETNEXTCERT -> source object
			source object: 
				CREATEOBJECT_INDIRECT -> system device
					system device: createCertificate() 
		[...]					

   however this seems to be the best place to put the code */

int iCryptImportCertIndirect( CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource, 
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  const int options )
	{
	assert( iCertificate != NULL );
	assert( keyIDtype > CRYPT_KEYID_NONE && keyIDtype < CRYPT_KEYID_LAST );
	assert( keyID != NULL && keyIDlength >= 1 );
	assert( ( options & ~KEYMGMT_MASK_CERTOPTIONS ) == 0 );

	/* We're importing a sequence of certs as a chain from a source object, 
	   assemble the collection via the object */
	return( assembleCertChain( iCertificate, iCertSource, keyIDtype, 
							   keyID, keyIDlength, options ) );
	}

/* Read a public key from an X.509 SubjectPublicKeyInfo record, creating the
   context necessary to contain it in the process.  Like the cert import 
   function above, this is another function of no fixed abode that exists
   here because it's the least inappropriate location.
   
   The use of the void * instead of STREAM * is necessary because the STREAM
   type isn't visible at the global level */

int iCryptReadSubjectPublicKey( void *streamPtr, 
								CRYPT_CONTEXT *iPubkeyContext,
								const BOOLEAN deferredLoad )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	STREAM *stream = streamPtr;
	void *spkiPtr = sMemBufPtr( stream );
	int length, spkiLength, status;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iPubkeyContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Read the SubjectPublicKeyInfo header field and create a context to
	   read the public key information into.  Because all sorts of bizarre
	   tagging exists due to things like CRMF, we read the wrapper as a
	   generic hole rather than the more obvious sequence.  The length
	   values (which are also checked in the kernel, we perform the check
	   here to avoid unnecessarily creating a cert object) are only 
	   approximate because there's wrapper data involved, and (for the 
	   maximum length) several of the DLP PKC values are only a fraction 
	   of CRYPT_MAX_PKCSIZE, the rest of the space requirement being 
	   allocated to the wrapper */
	status = readGenericHole( stream, &length, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	spkiLength = ( int ) sizeofObject( length );
	if( spkiLength < 8 + bitsToBytes( MIN_PKCSIZE_BITS ) || \
		spkiLength > CRYPT_MAX_PKCSIZE * 4 || \
		length > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_BADDATA );
	readAlgoID( stream, &cryptAlgo );
	status = readUniversal( stream );
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectInfo( &createInfo, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the public-key data to the context */
	setMessageData( &msgData, spkiPtr, spkiLength );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  deferredLoad ? \
								CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL : \
								CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iPubkeyContext = createInfo.cryptHandle;
	assert( cryptStatusError( \
				krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CHECK, 
								 NULL, MESSAGE_CHECK_PKC_PRIVATE ) ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Certificate Management API Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a cert object */

static int processCertData( CERT_INFO *certInfoPtr,
						    const MESSAGE_TYPE message,
							void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int *valuePtr = ( int * ) messageDataPtr;

	/* Process get/set/delete attribute messages */
	if( message == MESSAGE_GETATTRIBUTE )
		{
		if( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE )
			{
			*valuePtr = certInfoPtr->errorType;
			return( CRYPT_OK );
			}
		if( messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS )
			{
			*valuePtr = certInfoPtr->errorLocus;
			return( CRYPT_OK );
			}
		return( getCertComponent( certInfoPtr, messageValue, valuePtr, NULL ) );
		}
	if( message == MESSAGE_GETATTRIBUTE_S )
		return( getCertComponent( certInfoPtr, messageValue, 
								  msgData->data, &msgData->length ) );
	if( message == MESSAGE_SETATTRIBUTE )
		{
		const BOOLEAN validCursorPosition = \
			( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
			messageValue >= CRYPT_CERTINFO_FIRST_CMS && \
								messageValue <= CRYPT_CERTINFO_LAST_CMS : \
			messageValue >= CRYPT_CERTINFO_FIRST_EXTENSION && \
								messageValue <= CRYPT_CERTINFO_LAST_EXTENSION;

		/* If it's a completed certificate, we can only add a restricted 
		   class of component selection control values to the object */
#ifndef __WINCE__	/* String too long for compiler */
		assert( certInfoPtr->certificate == NULL || \
				isDNSelectionComponent( messageValue ) || \
				isGeneralNameSelectionComponent( messageValue ) || \
				isCursorComponent( messageValue ) || \
				isControlComponent( messageValue ) || \
				messageValue == CRYPT_IATTRIBUTE_INITIALISED || \
				messageValue == CRYPT_IATTRIBUTE_PKIUSERINFO );
#endif /* !__WINCE__ */

		/* If it's an initialisation message, there's nothing to do (we get 
		   these when importing a cert, when the import is complete the 
		   import code sends this message to move the cert into the high
		   state because it's already signed) */
		if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
			return( CRYPT_OK );

		/* If the passed-in value is a cursor-positioning code, make sure 
		   that it's valid */
		if( *valuePtr < 0 && *valuePtr != CRYPT_UNUSED && \
			( *valuePtr > CRYPT_CURSOR_FIRST || *valuePtr < CRYPT_CURSOR_LAST ) &&
			!validCursorPosition && messageValue != CRYPT_CERTINFO_SELFSIGNED )
			return( CRYPT_ARGERROR_NUM1 );

		return( addCertComponent( certInfoPtr, messageValue, valuePtr, 
								  CRYPT_UNUSED ) );
		}
	if( message == MESSAGE_SETATTRIBUTE_S )
		return( addCertComponent( certInfoPtr, messageValue, msgData->data, 
								  msgData->length ) );
	if( message == MESSAGE_DELETEATTRIBUTE )
		return( deleteCertComponent( certInfoPtr, messageValue ) );

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Handle a message sent to a certificate context */

static int certificateMessageFunction( const void *objectInfoPtr,
									   const MESSAGE_TYPE message,
									   void *messageDataPtr,
									   const int messageValue )
	{
	CERT_INFO *certInfoPtr = ( CERT_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Clear the encoded certificate and miscellaneous components if
		   necessary.  Note that there's no need to clear the associated
		   encryption context (if any) since this is a dependent object of
		   the cert and is destroyed by the kernel when the cert is 
		   destroyed */
		if( certInfoPtr->certificate != NULL )
			{
			zeroise( certInfoPtr->certificate, certInfoPtr->certificateSize );
			clFree( "certificateMessageFunction", certInfoPtr->certificate );
			}
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			{
			if( certInfoPtr->cCertCert->serialNumber != NULL && \
				certInfoPtr->cCertCert->serialNumber != \
					certInfoPtr->cCertCert->serialNumberBuffer )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertCert->serialNumber );
			}
		if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			if( certInfoPtr->cCertReq->serialNumber != NULL && \
				certInfoPtr->cCertReq->serialNumber != \
					certInfoPtr->cCertReq->serialNumberBuffer )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertReq->serialNumber );
			}
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE )
			{
			if( certInfoPtr->cCertCert->subjectUniqueID != NULL )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertCert->subjectUniqueID );
			if( certInfoPtr->cCertCert->issuerUniqueID != NULL )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertCert->issuerUniqueID );
			}
		if( certInfoPtr->publicKeyData != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->publicKeyData  );
		if( certInfoPtr->subjectDNdata != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->subjectDNdata );
		if( certInfoPtr->issuerDNdata != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->issuerDNdata );
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			{
			if( certInfoPtr->cCertRev->responderUrl != NULL )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertRev->responderUrl );
			}
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			{
			if( certInfoPtr->cCertVal->responderUrl != NULL )
				clFree( "certificateMessageFunction", 
						certInfoPtr->cCertVal->responderUrl );
			}

		/* Clear the DN's if necessary */
		if( certInfoPtr->issuerName != NULL )
			deleteDN( &certInfoPtr->issuerName );
		if( certInfoPtr->subjectName != NULL )
			deleteDN( &certInfoPtr->subjectName );

		/* Clear the attributes and validity/revocation info if necessary */
		if( certInfoPtr->attributes != NULL )
			deleteAttributes( &certInfoPtr->attributes );
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			{
			if( certInfoPtr->cCertVal->validityInfo != NULL )
				deleteValidityEntries( &certInfoPtr->cCertVal->validityInfo );
			}
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			{
			if( certInfoPtr->cCertRev->revocations != NULL )
				deleteRevocationEntries( &certInfoPtr->cCertRev->revocations );
			}

		/* Clear the cert chain if necessary */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
			certInfoPtr->cCertCert->chainEnd > 0)
			{
			int i;

			for( i = 0; i < certInfoPtr->cCertCert->chainEnd; i++ )
				krnlSendNotifier( certInfoPtr->cCertCert->chain[ i ],
								  IMESSAGE_DECREFCOUNT );
			}

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		/* If it's a cert chain, lock the currently selected cert in the 
		   chain unless the message being processed is a certificate cursor 
		   movement command or something specifically directed at the entire 
		   chain (for example a get type or self-signed status command - we 
		   want to get the type/status of the chain, not of the certs within 
		   it) */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
			certInfoPtr->cCertCert->chainPos >= 0 && \
			!( ( message == MESSAGE_SETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CURRENT_CERTIFICATE ) ) && \
			!( ( message == MESSAGE_GETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CERTTYPE || \
				 messageValue == CRYPT_CERTINFO_SELFSIGNED ) ) )
			{
			CERT_INFO *certChainInfoPtr;
			int status;

			status = krnlAcquireObject( certInfoPtr->cCertCert->chain[ certInfoPtr->cCertCert->chainPos ], 
										OBJECT_TYPE_CERTIFICATE, 
										( void ** ) &certChainInfoPtr,
										CRYPT_ARGERROR_OBJECT );
			if( cryptStatusError( status ) )
				return( status );
			status = processCertData( certChainInfoPtr, message, messageDataPtr, 
									  messageValue );
			krnlReleaseObject( certChainInfoPtr->objectHandle );
			return( status );
			}

		return( processCertData( certInfoPtr, message, messageDataPtr, 
								 messageValue ) );
		}

	/* Process messages that compare the object */
	if( message == MESSAGE_COMPARE )
		return( compareCertInfo( certInfoPtr, messageValue, 
								 messageDataPtr ) );

	/* Process messages that check a certificate */
	if( message == MESSAGE_CHECK )
		{
		int complianceLevel, keyUsageValue, checkKeyFlag = CHECKKEY_FLAG_NONE;
		int status;

		/* Map the check type to a key usage that we check for */
		switch( messageValue )
			{
			case MESSAGE_CHECK_PKC_PRIVATE:
				/* This check type can be encountered when checking a private
				   key with a cert attached */
				keyUsageValue = CRYPT_UNUSED;
				checkKeyFlag = CHECKKEY_FLAG_PRIVATEKEY;
				break;

			case MESSAGE_CHECK_PKC_ENCRYPT:
			case MESSAGE_CHECK_PKC_ENCRYPT_AVAIL:
				keyUsageValue = CRYPT_KEYUSAGE_KEYENCIPHERMENT;
				break;

			case MESSAGE_CHECK_PKC_DECRYPT:
			case MESSAGE_CHECK_PKC_DECRYPT_AVAIL:
				keyUsageValue = CRYPT_KEYUSAGE_KEYENCIPHERMENT;
				checkKeyFlag = CHECKKEY_FLAG_PRIVATEKEY;
				break;

			case MESSAGE_CHECK_PKC_SIGN:
			case MESSAGE_CHECK_PKC_SIGN_AVAIL:
				keyUsageValue = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								CRYPT_KEYUSAGE_NONREPUDIATION | \
								CRYPT_KEYUSAGE_KEYCERTSIGN | \
								CRYPT_KEYUSAGE_CRLSIGN;
				checkKeyFlag = CHECKKEY_FLAG_PRIVATEKEY;
				break;

			case MESSAGE_CHECK_PKC_SIGCHECK:
			case MESSAGE_CHECK_PKC_SIGCHECK_AVAIL:
				keyUsageValue = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								CRYPT_KEYUSAGE_NONREPUDIATION | \
								CRYPT_KEYUSAGE_KEYCERTSIGN | \
								CRYPT_KEYUSAGE_CRLSIGN;
				break;

			case MESSAGE_CHECK_PKC_KA_EXPORT:
			case MESSAGE_CHECK_PKC_KA_EXPORT_AVAIL:
				/* exportOnly usage falls back to plain keyAgreement if 
				   necessary */
				keyUsageValue = CRYPT_KEYUSAGE_KEYAGREEMENT | \
								CRYPT_KEYUSAGE_ENCIPHERONLY;
				break;

			case MESSAGE_CHECK_PKC_KA_IMPORT:
			case MESSAGE_CHECK_PKC_KA_IMPORT_AVAIL:
				/* importOnly usage falls back to plain keyAgreement if 
				   necessary */
				keyUsageValue = CRYPT_KEYUSAGE_KEYAGREEMENT | \
								CRYPT_KEYUSAGE_DECIPHERONLY;
				break;

			case MESSAGE_CHECK_CA:
				/* A special-case version of MESSAGE_CHECK_PKC_SIGN/
				   MESSAGE_CHECK_PKC_SIGCHECK that applies only to 
				   certificates */
				keyUsageValue = CRYPT_KEYUSAGE_KEYCERTSIGN;
				checkKeyFlag = CHECKKEY_FLAG_CA;
				break;
			
			case MESSAGE_CHECK_PKC:
				/* If we're just checking for generic PKC functionality
				   then any kind of usage is OK */
				return( CRYPT_OK );

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR_INVALID );
			}

		/* Cert requests are special-case objects in that the key they 
		   contain is usable only for signature checking of the self-
		   signature on the object (it can't be used for general-purpose 
		   usages, which would make it equivalent to a trusted self-signed 
		   cert).  This is problematic because the keyUsage may indicate 
		   that the key is valid for other things as well, or not valid for 
		   signature checking.  To get around this, we indicate that the key 
		   has a single trusted usage, signature checking, and disallow any 
		   other usage regardless of what the keyUsage says.  The actual 
		   keyUsage usage is only valid once the request has been converted 
		   into a certificate */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
			{
			if( messageValue == MESSAGE_CHECK_PKC_SIGCHECK || \
				messageValue == MESSAGE_CHECK_PKC_SIGCHECK_AVAIL )
				return( CRYPT_OK );
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_TRUSTED_USAGE, 
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

		/* Only cert objects with associated public keys are valid for check 
		   messages (which are checking the capabilities of the key) */
		assert( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
				certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

		/* Cert collections are pure container objects for which the base 
		   cert object doesn't correspond to an actual cert */
		if( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_INVALID );
			}

		/* Check the key usage for the cert */
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
								  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
		if( cryptStatusError( status ) )
			return( status );
		status = checkKeyUsage( certInfoPtr, checkKeyFlag, keyUsageValue, 
								complianceLevel, &certInfoPtr->errorLocus, 
								&certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			/* Convert the status value to the correct form */
			return( CRYPT_ARGERROR_OBJECT );

		return( CRYPT_OK );
		}

	/* Process internal notification messages */
	if( message == MESSAGE_CHANGENOTIFY )
		{
		/* If the object is being accessed for cryptlib-internal use, save/
		   restore the internal state */
		if( messageValue == MESSAGE_CHANGENOTIFY_STATE )
			{
			if( messageDataPtr == MESSAGE_VALUE_TRUE )
				{
				/* Save the current volatile state so that any changes made 
				   while the object is in use aren't reflected back to the 
				   caller */
				saveSelectionState( certInfoPtr->selectionState, 
									certInfoPtr );
				}
			else
				{
				/* Restore the volatile state from before the object was 
				   used */
				restoreSelectionState( certInfoPtr->selectionState, 
									   certInfoPtr );
				}

			return( CRYPT_OK );
			}

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_CRT_SIGN )
		{
		int status;

		assert( certInfoPtr->certificate == NULL );

		/* Make sure that the signing object can actually be used for 
		   signing */
		status = krnlSendMessage( messageValue, IMESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_PKC_SIGN );
		if( cryptStatusError( status ) )
			{
			/* The only time we can use a signing object that can't sign is
			   when we have a CRMF request, which can be created with an
			   encryption-only key if the private key POP is performed via 
			   an out-of-band mechanism.  If this is the case, we make sure
			   that the key can decrypt, which is the other way of performing 
			   POP if a signing key isn't available */
			if( certInfoPtr->type != CRYPT_CERTTYPE_REQUEST_CERT )
				return( CRYPT_ARGERROR_VALUE );
			status = krnlSendMessage( messageValue, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_DECRYPT );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_VALUE );
			}

		/* We're changing data in a certificate, clear the error 
		   information */
		clearErrorInfo( certInfoPtr );

		return( signCert( certInfoPtr, messageValue ) );
		}
	if( message == MESSAGE_CRT_SIGCHECK )
		{
		assert( certInfoPtr->certificate != NULL || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE || \
				certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

		/* We're checking data in a certificate, clear the error 
		   information */
		clearErrorInfo( certInfoPtr );

		return( checkCertValidity( certInfoPtr, messageValue ) );
		}
	if( message == MESSAGE_CRT_EXPORT )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		assert( messageValue > CRYPT_CERTFORMAT_NONE && \
				messageValue < CRYPT_CERTFORMAT_LAST );

		/* Unsigned object types like CMS attributes aren't signed like other 
		   cert.objects so they aren't pre-encoded when we sign them, and 
		   have the potential to change on each use if the same CMS 
		   attributes are reused for multiple signatures.  Because of this 
		   we write them out on export rather than copying the pre-encoded 
		   form from an internal buffer */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
			{
			STREAM stream;
			int i;

			assert( messageValue == CRYPT_ICERTFORMAT_DATA );

			for( i = 0; \
				 certWriteTable[ i ].type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				 certWriteTable[ i ].type != CRYPT_CERTTYPE_NONE; i++ );
			if( certWriteTable[ i ].type == CRYPT_CERTTYPE_NONE )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_NOTAVAIL );
				}
			sMemOpen( &stream, msgData->data, msgData->length );
			status = certWriteTable[ i ].writeFunction( &stream, certInfoPtr,
														NULL, CRYPT_UNUSED );
			msgData->length = stell( &stream );
			sMemDisconnect( &stream );

			return( status );
			}

		/* Some objects aren't signed, or are pseudo-signed or optionally 
		   signed, and have to be handled specially.  RTCS requests and
		   responses are never signed (they're pure data containers like
		   CMS attributes, with protection being provided by CMS).  OCSP 
		   requests can be optionally signed but usually aren't, so if 
		   we're fed an OCSP request without any associated encoded data we 
		   pseudo-sign it to produce encoded data.  PKI user data is never 
		   signed but needs to go through a one-off setup process to 
		   initialise the user data fields so it has the same semantics as a 
		   pseudo-signed object.  CRMF revocation requests are never signed 
		   (thus ruling out suicide-note revocations) */
		if( ( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			  certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			  certInfoPtr->type == CRYPT_CERTTYPE_PKIUSER || \
			  certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION ) && \
			certInfoPtr->certificate == NULL )
			{
			status = signCert( certInfoPtr, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* If we're exporting a single cert from a chain, lock the currently 
		   selected cert in the chain and export that */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
			certInfoPtr->cCertCert->chainPos >= 0 && \
			( messageValue == CRYPT_CERTFORMAT_CERTIFICATE || \
			  messageValue == CRYPT_CERTFORMAT_TEXT_CERTIFICATE || \
			  messageValue == CRYPT_CERTFORMAT_XML_CERTIFICATE ) )
			{
			CERT_INFO *certChainInfoPtr;

			status = krnlAcquireObject( certInfoPtr->cCertCert->chain[ certInfoPtr->cCertCert->chainPos ], 
										OBJECT_TYPE_CERTIFICATE, 
										( void ** ) &certChainInfoPtr,
										CRYPT_ARGERROR_OBJECT );
			if( cryptStatusError( status ) )
				return( status );
			status = exportCert( msgData->data, &msgData->length, 
								 messageValue, certChainInfoPtr, 
								 msgData->length );
			krnlReleaseObject( certChainInfoPtr->objectHandle );
			return( status );
			}

		assert( ( ( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION ) && \
				  certInfoPtr->certificate == NULL ) || \
				certInfoPtr->certificate != NULL );

		return( exportCert( msgData->data, &msgData->length, 
							messageValue, certInfoPtr, msgData->length ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Create a certificate object, returning a pointer to the locked cert info 
   ready for further initialisation */

int createCertificateInfo( CERT_INFO **certInfoPtrPtr, 
						   const CRYPT_USER cryptOwner,
						   const CRYPT_CERTTYPE_TYPE certType )
	{
	CRYPT_CERTIFICATE iCertificate;
	CERT_INFO *certInfoPtr;
	int storageSize, subType;

	assert( certInfoPtrPtr != NULL );

	/* Clear the return values */
	*certInfoPtrPtr = NULL;

	/* Set up subtype-specific information */
	switch( certType )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
			subType = ( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
					  SUBTYPE_CERT_CERT : SUBTYPE_CERT_ATTRCERT;
			storageSize = sizeof( CERT_CERT_INFO );
			break;

		case CRYPT_CERTTYPE_CERTCHAIN:
			/* A cert chain is a special case of a cert (and/or vice versa)
			   so it uses the same subtype-specific storage */
			subType = SUBTYPE_CERT_CERTCHAIN;
			storageSize = sizeof( CERT_CERT_INFO );
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			subType = SUBTYPE_CERT_CERTREQ;
			storageSize = 0;
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			subType = ( certType == CRYPT_CERTTYPE_REQUEST_CERT ) ? \
					  SUBTYPE_CERT_REQ_CERT : SUBTYPE_CERT_REQ_REV;
			storageSize = sizeof( CERT_REQ_INFO );
			break;

		case CRYPT_CERTTYPE_CRL:
			subType = SUBTYPE_CERT_CRL;
			storageSize = sizeof( CERT_REV_INFO );
			break;

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
			subType = SUBTYPE_CERT_CMSATTR;
			storageSize = 0;
			break;

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
			subType = ( certType == CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
					  SUBTYPE_CERT_RTCS_REQ : SUBTYPE_CERT_RTCS_RESP;
			storageSize = sizeof( CERT_VAL_INFO );
			break;

		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			subType = ( certType == CRYPT_CERTTYPE_OCSP_REQUEST ) ? \
					  SUBTYPE_CERT_OCSP_REQ : SUBTYPE_CERT_OCSP_RESP;
			storageSize = sizeof( CERT_REV_INFO );
			break;

		case CRYPT_CERTTYPE_PKIUSER:
			subType = SUBTYPE_CERT_PKIUSER;
			storageSize = sizeof( CERT_PKIUSER_INFO );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}

	/* Create the certificate object */
	iCertificate = krnlCreateObject( ( void ** ) &certInfoPtr, 
									 sizeof( CERT_INFO ) + storageSize, 
									 OBJECT_TYPE_CERTIFICATE, subType,
									 CREATEOBJECT_FLAG_NONE, cryptOwner, 
									 ACTION_PERM_NONE_ALL, 
									 certificateMessageFunction );
	if( cryptStatusError( iCertificate ) )
		return( iCertificate );
	certInfoPtr->objectHandle = iCertificate;
	certInfoPtr->ownerHandle = cryptOwner;
	certInfoPtr->type = certType;
	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_CERTCHAIN:
			certInfoPtr->cCertCert = ( CERT_CERT_INFO * ) certInfoPtr->storage;
			certInfoPtr->cCertCert->chainPos = CRYPT_ERROR;
			certInfoPtr->cCertCert->trustedUsage = CRYPT_ERROR;
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			certInfoPtr->cCertReq = ( CERT_REQ_INFO * ) certInfoPtr->storage;
			break;

		case CRYPT_CERTTYPE_CRL:
		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			certInfoPtr->cCertRev = ( CERT_REV_INFO * ) certInfoPtr->storage;
			break;

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
			certInfoPtr->cCertVal = ( CERT_VAL_INFO * ) certInfoPtr->storage;
			break;

		case CRYPT_CERTTYPE_PKIUSER:
			certInfoPtr->cCertUser = ( CERT_PKIUSER_INFO * ) certInfoPtr->storage;
			break;
		}

	/* Set up the default version number.  These values are set here mostly 
	   so that attempting to read the version attribute won't return a 
	   version of 0.

	   In some cases this is an indication only that will be modified based 
	   on information added to the object (for example the CRL version is 
	   implicitly set based on whether extensions are added or not).  If this 
	   can happen we start with the lowest version available (the default 
	   v1), which will be automatically incremented whenever information 
	   that can't be represented with that format version is added */
	switch( certType )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_CERTCHAIN:
			certInfoPtr->version = 3;
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
			certInfoPtr->version = 2;
			break;

		default:
			certInfoPtr->version = 1;
			break;
		}

	/* Set up any internal objects to contain invalid handles */
	certInfoPtr->iPubkeyContext = CRYPT_ERROR;

	/* Set the state information to its initial state */
	initSelectionInfo( certInfoPtr );

	/* Return the cert info pointer */
	*certInfoPtrPtr = certInfoPtr;
	return( iCertificate );
	}

/* Create a certificate */

int createCertificate( MESSAGE_CREATEOBJECT_INFO *createInfo, 
					   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_CERTIFICATE iCertificate;
	CERT_INFO *certInfoPtr;
	int status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );
	assert( createInfo->arg2 == 0 );
	assert( createInfo->strArg1 == NULL );
	assert( createInfo->strArgLen1 == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_CERTTYPE_NONE || \
		createInfo->arg1 >= CRYPT_CERTTYPE_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	status = createCertificateInfo( &certInfoPtr, createInfo->cryptOwner,
									createInfo->arg1 );
	if( cryptStatusError( status ) )
		return( status );
	iCertificate = status;

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	status = krnlSendMessage( iCertificate, IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) )
		createInfo->cryptHandle = iCertificate;
	return( status );
	}

/* Create a certificate by instantiating it from its encoded form */

int createCertificateIndirect( MESSAGE_CREATEOBJECT_INFO *createInfo, 
							   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_CERTIFICATE iCertificate;
	int status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );
	assert( createInfo->arg1 >= CRYPT_CERTTYPE_NONE && \
			createInfo->arg1 < CERTFORMAT_LAST );
	assert( createInfo->strArg1 != NULL );
	assert( createInfo->strArgLen1 > 16 );	/* May be CMS attr.*/
	assert( ( createInfo->arg2 == 0 && createInfo->strArg2 == NULL && \
			  createInfo->strArgLen2 == 0 ) || \
			( ( createInfo->arg2 == CRYPT_IKEYID_KEYID || \
				createInfo->arg2 == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
			  createInfo->strArg2 != NULL && createInfo->strArgLen2 > 2 ) );

	/* Pass the call through to the low-level import function.  This returns 
	   a length value so we convert it to a proper status for the caller */
	status = importCert( createInfo->strArg1, createInfo->strArgLen1,
						 &iCertificate, createInfo->cryptOwner,
						 createInfo->arg2, createInfo->strArg2, 
						 createInfo->strArgLen2, createInfo->arg1 );
	if( cryptStatusOK( status ) )
		createInfo->cryptHandle = iCertificate;
	return( status );
	}

/* Generic management function for this class of object */

int certManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Get/add/delete certificate attributes */

#ifdef EBCDIC_CHARS

static char *bufferToAscii( char *buffer, const char *string )
	{
	strcpy( buffer, string );
	ebcdicToAscii( buffer, strlen( string ) );
	return( buffer );
	}
#endif /* EBCDIC_CHARS */

C_RET cryptGetCertExtension( C_IN CRYPT_CERTIFICATE certificate,
							 C_IN char C_PTR oid, 
							 C_OUT int C_PTR criticalFlag,
							 C_OUT void C_PTR extension, 
							 C_IN int extensionMaxLength,
							 C_OUT int C_PTR extensionLength )
	{
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
#ifdef EBCDIC_CHARS
	char asciiOID[ CRYPT_MAX_TEXTSIZE + 1 ];
#endif /* EBCDIC_CHARS */
	BOOLEAN returnData = ( extension != NULL ) ? TRUE : FALSE;
	int value, status;

	/* Perform basic parameter error checking */
	if( !isReadPtr( oid, MIN_ASCII_OIDSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( !isWritePtr( criticalFlag, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*criticalFlag = CRYPT_ERROR;
	if( extension != NULL )
		{
		if( extensionMaxLength <= 3 )
			return( CRYPT_ERROR_PARAM5 );
		if( !isWritePtr( extension, extensionMaxLength ) )
			return( CRYPT_ERROR_PARAM4 );
		*( ( BYTE * ) extension ) = 0;
		}
	if( !isWritePtr( extensionLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM6 );
	*extensionLength = CRYPT_ERROR;
	if( strlen( oid ) > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_PARAM2 );
#ifdef EBCDIC_CHARS
	bufferToAscii( asciiOID, oid );
	if( !textToOID( asciiOID, strlen( asciiOID ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#else
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#endif /* EBCDIC_CHARS */

	/* Perform object error checking.  Normally this is handled by the 
	   kernel, however since this function accesses multiple parameters and
	   the target isn't a cryptlib attribute, we have to handle the access
	   ourselves here.  In order to avoid potential race conditions, we 
	   check whether the object is internal twice, once before we lock it 
	   and again afterwards.  We perform the check by reading the locked
	   property attribute, which is always available */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlAcquireObject( certificate, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certInfoPtr, 
								CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE, &value,
							  CRYPT_PROPERTY_LOCKED );
	if( cryptStatusError( status ) )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
		certInfoPtr->cCertCert->chainPos >= 0 )
		{
		CERT_INFO *certChainInfoPtr;

		status = krnlAcquireObject( certInfoPtr->cCertCert->chain[ certInfoPtr->cCertCert->chainPos ], 
									OBJECT_TYPE_CERTIFICATE, 
									( void ** ) &certChainInfoPtr, 
									CRYPT_ERROR_PARAM1 );
		if( cryptStatusError( status ) )
			return( status );
		krnlReleaseObject( certInfoPtr->objectHandle );
		certInfoPtr = certChainInfoPtr;
		}

	/* Locate the attribute identified by the OID and get its information */
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, binaryOID );
	if( attributeListPtr == NULL )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_NOTFOUND );
		}
	*criticalFlag = ( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ? \
					TRUE : FALSE;
	*extensionLength = attributeListPtr->valueLength;
	if( returnData )
		{
		const void *dataPtr = attributeListPtr->value;

		if( !isWritePtr( extension, attributeListPtr->valueLength ) )
			status = CRYPT_ERROR_PARAM3;
		else
			memcpy( extension, dataPtr, attributeListPtr->valueLength );
		}
	krnlReleaseObject( certInfoPtr->objectHandle );
	return( status );
	}

C_RET cryptAddCertExtension( C_IN CRYPT_CERTIFICATE certificate,
							 C_IN char C_PTR oid, C_IN int criticalFlag,
							 C_IN void C_PTR extension,
							 C_IN int extensionLength )
	{
	CERT_INFO *certInfoPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
#ifdef EBCDIC_CHARS
	char asciiOID[ CRYPT_MAX_TEXTSIZE + 1 ];
#endif /* EBCDIC_CHARS */
	int value, status;

	/* Perform basic parameter error checking */
	if( !isReadPtr( oid, MIN_ASCII_OIDSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( extensionLength <= 3 || extensionLength > MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ERROR_PARAM5 );
	if( !isReadPtr( extension, extensionLength ) )
		return( CRYPT_ERROR_PARAM4 );
	status = checkObjectEncoding( extension, extensionLength );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM4 );
	if( strlen( oid ) > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_PARAM2 );
#ifdef EBCDIC_CHARS
	bufferToAscii( asciiOID, oid );
	if( !textToOID( asciiOID, strlen( asciiOID ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#else
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#endif /* EBCDIC_CHARS */

	/* Perform object error checking.  Normally this is handled by the 
	   kernel, however since this function accesses multiple parameters and
	   the target isn't a cryptlib attribute, we have to handle the access
	   ourselves here.  In order to avoid potential race conditions, we 
	   check whether the object is internal twice, once before we lock it 
	   and again afterwards.  We perform the check by reading the locked
	   property attribute, which is always available */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlAcquireObject( certificate, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certInfoPtr, 
								CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE, &value,
							  CRYPT_PROPERTY_LOCKED );
	if( cryptStatusError( status ) )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
		certInfoPtr->cCertCert->chainPos >= 0 )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PERMISSION );
		}
	if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		criticalFlag != CRYPT_UNUSED )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM3 );
		}

	/* Add the attribute to the certificate */
	status = addAttribute( \
				( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
					ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, 
				&certInfoPtr->attributes, binaryOID, 
				( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
					FALSE : criticalFlag, 
				extension, extensionLength, ATTR_FLAG_NONE );
	if( status == CRYPT_ERROR_INITED )
		/* If the attribute is already present, set error information for it.
		   We can't set an error locus since it's an unknown blob */
		setErrorInfo( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
	krnlReleaseObject( certInfoPtr->objectHandle );
	return( status );
	}

C_RET cryptDeleteCertExtension( C_IN CRYPT_CERTIFICATE certificate,
								C_IN char C_PTR oid )
	{
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
#ifdef EBCDIC_CHARS
	char asciiOID[ CRYPT_MAX_TEXTSIZE + 1 ];
#endif /* EBCDIC_CHARS */
	int value, status;

	/* Perform basic parameter error checking */
	if( !isReadPtr( oid, MIN_ASCII_OIDSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( strlen( oid ) > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_PARAM2 );
#ifdef EBCDIC_CHARS
	bufferToAscii( asciiOID, oid );
	if( !textToOID( asciiOID, strlen( asciiOID ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#else
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		return( CRYPT_ERROR_PARAM2 );
#endif /* EBCDIC_CHARS */

	/* Perform object error checking.  Normally this is handled by the 
	   kernel, however since this function accesses multiple parameters and
	   the target isn't a cryptlib attribute, we have to handle the access
	   ourselves here.  In order to avoid potential race conditions, we 
	   check whether the object is internal twice, once before we lock it 
	   and again afterwards.  We perform the check by reading the locked
	   property attribute, which is always available */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlAcquireObject( certificate, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certInfoPtr, 
								CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE, &value,
							  CRYPT_PROPERTY_LOCKED );
	if( cryptStatusError( status ) )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN && \
		certInfoPtr->cCertCert->chainPos >= 0 )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Find the attribute identified by the OID and delete it */
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, 
										   binaryOID );
	if( attributeListPtr == NULL )
		status = CRYPT_ERROR_NOTFOUND;
	else
		deleteAttribute( &certInfoPtr->attributes, NULL, attributeListPtr, 
						 NULL );
	krnlReleaseObject( certInfoPtr->objectHandle );
	return( status );
	}
