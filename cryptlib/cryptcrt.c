/****************************************************************************
*																			*
*					cryptlib Certificate Management Routines				*
*						Copyright Peter Gutmann 1996-2003					*
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
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
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

/* Compare a serial number in canonical form to a generic serial number, 
   with special handling for leading-zero truncation.  This one can get a 
   bit tricky because Microsoft fairly consistently encode the serial 
   numbers incorrectly, so we normalise the values to have no leading zero, 
   which is the lowest common denominator */

int compareSerialNumber( const void *canonSerialNumber, 
						 const int canonSerialNumberLength,
						 const void *serialNumber, 
						 const int serialNumberLength )
	{
	const BYTE *canonSerialNumberPtr = canonSerialNumber;
	const BYTE *serialNumberPtr = serialNumber;
	int canonSerialLength = canonSerialNumberLength;
	int serialLength = serialNumberLength;

	/* Internal serial numbers are canonicalised, so all we need to do is
	   strip a possible leading zero */
	if( !canonSerialNumberPtr[ 0 ] )
		{
		canonSerialNumberPtr++;
		canonSerialLength--;
		}
	assert( canonSerialLength == 0 || canonSerialNumberPtr[ 0 ] );

	/* Serial numbers from external sources can be arbitarily strangely 
	   encoded, so we strip leading zeroes until we get to actual data */
	while( serialLength > 0 && !serialNumberPtr[ 0 ] )
		{
		serialNumberPtr++;
		serialLength--;
		}

	/* Finally we've got them in a form where we can compare them */
	if( canonSerialLength != serialLength || \
		memcmp( canonSerialNumberPtr, serialNumberPtr, serialLength ) )
		return( 1 );

	return( 0 );
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
									sizeofObject( certInfoPtr->serialNumberLength ) );
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
			if( compareSerialNumber( certInfoPtr->serialNumber,
									 certInfoPtr->serialNumberLength,
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

			status = krnlGetObject( *( ( CRYPT_CERTIFICATE * ) messageDataPtr ), 
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
		assert( certInfoPtr->certificate == NULL || \
				isDNSelectionComponent( messageValue ) || \
				isGeneralNameSelectionComponent( messageValue ) || \
				isCursorComponent( messageValue ) || \
				isControlComponent( messageValue ) || \
				messageValue == CRYPT_IATTRIBUTE_INITIALISED || \
				messageValue == CRYPT_IATTRIBUTE_PKIUSERINFO );

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
		if( certInfoPtr->serialNumber != NULL && \
			certInfoPtr->serialNumber != certInfoPtr->serialNumberBuffer )
			clFree( "certificateMessageFunction", certInfoPtr->serialNumber );
		if( certInfoPtr->subjectUniqueID != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->subjectUniqueID );
		if( certInfoPtr->issuerUniqueID != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->issuerUniqueID );
		if( certInfoPtr->publicKeyData != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->publicKeyData  );
		if( certInfoPtr->subjectDNdata != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->subjectDNdata );
		if( certInfoPtr->issuerDNdata != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->issuerDNdata );
		if( certInfoPtr->responderUrl != NULL )
			clFree( "certificateMessageFunction", certInfoPtr->responderUrl );

		/* Clear the DN's if necessary */
		if( certInfoPtr->issuerName != NULL )
			deleteDN( &certInfoPtr->issuerName );
		if( certInfoPtr->subjectName != NULL )
			deleteDN( &certInfoPtr->subjectName );

		/* Clear the attributes and CRL's if necessary */
		if( certInfoPtr->attributes != NULL )
			deleteAttributes( &certInfoPtr->attributes );
		if( certInfoPtr->revocations != NULL )
			deleteRevocationEntries( &certInfoPtr->revocations );

		/* Clear the cert chain if necessary */
		if( certInfoPtr->certChainEnd )
			{
			int i;

			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				krnlSendNotifier( certInfoPtr->certChain[ i ],
								  IMESSAGE_DECREFCOUNT );
			}

		/* Delete the object itself */
		zeroise( certInfoPtr, sizeof( CERT_INFO ) );
		clFree( "certificateMessageFunction", certInfoPtr );

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
		if( certInfoPtr->certChainPos >= 0 && \
			!( ( message == MESSAGE_SETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CURRENT_CERTIFICATE ) ) && \
			!( ( message == MESSAGE_GETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CERTTYPE || \
				 messageValue == CRYPT_CERTINFO_SELFSIGNED ) ) )
			{
			CERT_INFO *certChainInfoPtr;
			int status;

			status = krnlGetObject( certInfoPtr->certChain[ certInfoPtr->certChainPos ], 
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
		const int certCheckValue = \
			( messageValue == MESSAGE_CHECK_PKC_ENCRYPT || \
              messageValue == MESSAGE_CHECK_PKC_DECRYPT ) ? \
				CRYPT_KEYUSAGE_KEYENCIPHERMENT : \
			( messageValue == MESSAGE_CHECK_PKC_SIGN || \
              messageValue == MESSAGE_CHECK_PKC_SIGCHECK ) ? \
				( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
				  CRYPT_KEYUSAGE_NONREPUDIATION | \
				  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN ) : \
			( messageValue == MESSAGE_CHECK_PKC_KA_EXPORT ) ? \
				CRYPT_KEYUSAGE_ENCIPHERONLY : \
			( messageValue == MESSAGE_CHECK_PKC_KA_IMPORT ) ? \
				CRYPT_KEYUSAGE_DECIPHERONLY : \
			( messageValue == MESSAGE_CHECK_CA ) ? \
				CRYPT_KEYUSAGE_KEYCERTSIGN : 0;
			/* enc/decOnly usage falls back to plain keyAgree if necessary */
		int status;

		/* If we're not checking for a specific type of functionality 
		   restriction set by the cert then any kind of usage is OK */
		if( !certCheckValue )
			return( CRYPT_OK );

		status = checkCertUsage( certInfoPtr, certCheckValue, messageValue,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		status = cryptStatusError( status ) ? \
				 CRYPT_ARGERROR_OBJECT : CRYPT_OK;	/* Convert to correct form */
		return( status );
		}

	/* Process internal notification messages */
	if( message == MESSAGE_CHANGENOTIFY )
		{
		/* If the object has been locked/unlocked, save/restore the internal 
		   state */
		if( messageValue == CRYPT_IATTRIBUTE_LOCKED )
			{
			if( messageDataPtr == MESSAGE_VALUE_TRUE )
				{
				/* Save the current volatile state so that any changes made 
				   while the object is locked aren't reflected back to the 
				   caller */
				saveSelectionState( certInfoPtr->selectionState, 
									certInfoPtr );
				}
			else
				{
				/* Restore the volatile state from before the object was 
				   locked */
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
		if( certInfoPtr->certChainPos >= 0 && \
			( messageValue == CRYPT_CERTFORMAT_CERTIFICATE || \
			  messageValue == CRYPT_CERTFORMAT_TEXT_CERTIFICATE || \
			  messageValue == CRYPT_CERTFORMAT_XML_CERTIFICATE ) )
			{
			CERT_INFO *certChainInfoPtr;

			status = krnlGetObject( certInfoPtr->certChain[ certInfoPtr->certChainPos ], 
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
	const int subType = \
		/* Standard types */
		( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? SUBTYPE_CERT_CERT : \
		( certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT ) ? SUBTYPE_CERT_ATTRCERT : \
		( certType == CRYPT_CERTTYPE_CERTCHAIN ) ? SUBTYPE_CERT_CERTCHAIN : \
		( certType == CRYPT_CERTTYPE_CERTREQUEST ) ? SUBTYPE_CERT_CERTREQ : \
		( certType == CRYPT_CERTTYPE_REQUEST_CERT ) ? SUBTYPE_CERT_REQ_CERT : \
		( certType == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? SUBTYPE_CERT_REQ_REV : \
		( certType == CRYPT_CERTTYPE_CRL ) ? SUBTYPE_CERT_CRL : \
		( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? SUBTYPE_CERT_CMSATTR : \
		( certType == CRYPT_CERTTYPE_RTCS_REQUEST ) ? SUBTYPE_CERT_RTCS_REQ : \
		( certType == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? SUBTYPE_CERT_RTCS_RESP : \
		( certType == CRYPT_CERTTYPE_OCSP_REQUEST ) ? SUBTYPE_CERT_OCSP_REQ : \
		( certType == CRYPT_CERTTYPE_OCSP_RESPONSE ) ? SUBTYPE_CERT_OCSP_RESP : \
		( certType == CRYPT_CERTTYPE_PKIUSER ) ? SUBTYPE_CERT_PKIUSER : 0;

	assert( certInfoPtrPtr != NULL );
	assert( subType != 0 );

	*certInfoPtrPtr = NULL;

	/* Create the certificate object */
	iCertificate = krnlCreateObject( ( void ** ) &certInfoPtr, 
									 sizeof( CERT_INFO ), 
									 OBJECT_TYPE_CERTIFICATE, subType,
									 CREATEOBJECT_FLAG_NONE, cryptOwner, 
									 ACTION_PERM_NONE_ALL, 
									 certificateMessageFunction );
	if( cryptStatusError( iCertificate ) )
		return( iCertificate );
	certInfoPtr->objectHandle = iCertificate;
	certInfoPtr->ownerHandle = cryptOwner;
	certInfoPtr->type = certType;

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
	certInfoPtr->certChainPos = CRYPT_ERROR;
	certInfoPtr->trustedUsage = CRYPT_ERROR;
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
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrWrite( criticalFlag, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*criticalFlag = CRYPT_ERROR;
	if( extension != NULL )
		*( ( BYTE * ) extension ) = 0;
	if( checkBadPtrWrite( extensionLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM5 );
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
	   and again afterwards */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlGetObject( certificate, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &certInfoPtr, CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) || value )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos >= 0 )
		{
		CERT_INFO *certChainInfoPtr;

		status = krnlGetObject( certInfoPtr->certChain[ certInfoPtr->certChainPos ], 
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

		if( checkBadPtrWrite( extension, attributeListPtr->valueLength ) )
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
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( extensionLength <= 3 || extensionLength > MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ERROR_PARAM5 );
	if( checkBadPtrRead( extension, extensionLength ) )
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
	   and again afterwards */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlGetObject( certificate, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &certInfoPtr, CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) || value )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos >= 0 )
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
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
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
	   and again afterwards */
	status = krnlSendMessage( certificate, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlGetObject( certificate, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &certInfoPtr, CRYPT_ERROR_PARAM1 );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certificate, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) || value )
		{
		krnlReleaseObject( certInfoPtr->objectHandle );
		return( CRYPT_ERROR_PARAM1 );
		}
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos >= 0 )
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
