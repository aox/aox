/****************************************************************************
*																			*
*						  Certificate Signing Routines						*
*						Copyright Peter Gutmann 1997-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in sign_x509.c */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const int sigMaxLength, const void *object,
						 const int objectLength,
						 const CRYPT_CONTEXT signContext,
						 const CRYPT_ALGO_TYPE hashAlgo,
						 const int formatInfo, const int extraDataLength );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Recover information normally set up on cert import.  After signing, the
   cert data is present without the cert having been explicitly imported, so
   we have to explicitly perform the actions normally performed on cert
   import here */

static int recoverCertData( CERT_INFO *certInfoPtr,
							const void *encodedCertData,
							const int encodedCertDataLength,
							const CRYPT_CERTTYPE_TYPE certType )
	{
	STREAM stream;
	int status;

	/* If there's public-key data stored with the cert, free it since we now
	   have a copy as part of the encoded cert */
	if( certInfoPtr->publicKeyData != NULL )
		{
		zeroise( certInfoPtr->publicKeyData, certInfoPtr->publicKeyInfoSize );
		clFree( "recoverCertData", certInfoPtr->publicKeyData );
		certInfoPtr->publicKeyData = NULL;
		}

	/* If it's a CRMF request, parse the signed form to locate the start of
	   the encoded DN if there is one (the issuer DN is already set up when
	   the issuer cert is added) and the public key.  The public key is
	   actually something of a special case in that in the CRMF/CMP tradition
	   it has a weird nonstandard tag, which means that a straight memcpy()
	   won't move the data across correctly */
	if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readSequence( &stream, NULL );			/* Outer wrapper */
		readSequence( &stream, NULL );
		readUniversal( &stream );				/* Request ID */
		status = readSequence( &stream, NULL );	/* Inner wrapper */
		if( peekTag( &stream ) == MAKE_CTAG( 4 ) )
			status = readUniversal( &stream );	/* Validity */
		if( peekTag( &stream ) == MAKE_CTAG( 5 ) )
			{
			readConstructed( &stream, NULL, 5 );/* Subj.name wrapper */
			certInfoPtr->subjectDNptr = sMemBufPtr( &stream );
			status = readUniversal( &stream );
			}
		assert( peekTag( &stream ) == MAKE_CTAG( 6 ) );/* Public key */
		certInfoPtr->publicKeyInfo = sMemBufPtr( &stream );
		assert( certInfoPtr->publicKeyInfoSize == \
				getStreamObjectLength( &stream ) );
		sMemDisconnect( &stream );

		assert( cryptStatusOK( status ) );
		return( status );
		}

	/* If it's PKI user data, parse the encoded form to locate the start of
	   the user DN */
	if( certInfoPtr->type == CRYPT_CERTTYPE_PKIUSER )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readSequence( &stream, NULL );		/* Outer wrapper */
		status = readSequence( &stream, &certInfoPtr->subjectDNsize );
		certInfoPtr->subjectDNptr = sMemBufPtr( &stream );
		sMemDisconnect( &stream );

		assert( cryptStatusOK( status ) );
		return( status );
		}

	assert( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			certType == CRYPT_CERTTYPE_CERTCHAIN );

	/* It's a certificate, parse the signed form to locate the start of the
	   encoded issuer and subject DN and public key (the length is recorded
	   when the cert data is written, but the position of the other elements
	   in the cert can't be determined until the cert has been signed) */
	sMemConnect( &stream, encodedCertData, encodedCertDataLength );
	readSequence( &stream, NULL );			/* Outer wrapper */
	readSequence( &stream, NULL );			/* Inner wrapper */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		readUniversal( &stream );			/* Version */
	readUniversal( &stream );				/* Serial number */
	readUniversal( &stream );				/* Sig.algo */
	certInfoPtr->issuerDNptr = sMemBufPtr( &stream );
	readUniversal( &stream );				/* Issuer DN */
	readUniversal( &stream );				/* Validity */
	certInfoPtr->subjectDNptr = sMemBufPtr( &stream );
	status = readUniversal( &stream );		/* Subject DN */
	certInfoPtr->publicKeyInfo = sMemBufPtr( &stream );
	assert( certInfoPtr->publicKeyInfoSize == \
			getStreamObjectLength( &stream ) );
	sMemDisconnect( &stream );
	assert( cryptStatusOK( status ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Since the cert may be used for public-key operations as soon as it's
	   signed, we have to reconstruct the public-key context and apply to
	   it the constraints that would be applied on import */
	sMemConnect( &stream, certInfoPtr->publicKeyInfo,
				 certInfoPtr->publicKeyInfoSize );
	status = iCryptReadSubjectPublicKey( &stream,
										 &certInfoPtr->iPubkeyContext,
										 FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( certInfoPtr->objectHandle,
								  IMESSAGE_SETDEPENDENT,
								  &certInfoPtr->iPubkeyContext,
								  SETDEP_OPTION_NOINCREF );
	if( cryptStatusOK( status ) )
		certInfoPtr->flags &= ~CERT_FLAG_DATAONLY;
	return( status );
	}

/****************************************************************************
*																			*
*								Signing Functions							*
*																			*
****************************************************************************/

/* Pseudo-sign certificate information by writing the outer wrapper and
   moving the object into the initialised state */

static int pseudoSignCertificate( CERT_INFO *certInfoPtr,
								  void *signedCertObject,
								  const void *certObject,
								  const int certObjectLength )
	{
	STREAM stream;
	int signedCertObjectLength;

	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_PKIUSER:
			/* It's an unsigned OCSP request or PKI user info, write the
			   outer wrapper */
			signedCertObjectLength = sizeofObject( certObjectLength );
			sMemOpen( &stream, signedCertObject, signedCertObjectLength );
			writeSequence( &stream, certObjectLength );
			swrite( &stream, certObject, certObjectLength );
			assert( sStatusOK( &stream ) );
			sMemDisconnect( &stream );
			if( certInfoPtr->type == CRYPT_CERTTYPE_PKIUSER )
				recoverCertData( certInfoPtr, signedCertObject,
								 signedCertObjectLength,
								 CRYPT_CERTTYPE_PKIUSER );
			break;

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			/* It's an RTCS request/response or OCSP response, it's already
			   in the form required */
			signedCertObjectLength = certObjectLength;
			memcpy( signedCertObject, certObject, certObjectLength );
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
			{
			const int dataSize = certObjectLength + \
								 sizeofObject( sizeofShortInteger( 0 ) );

			assert( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT );

			/* It's an encryption-only key, wrap up the cert data with an
			   indication that private key POP will be performed via out-of-
			   band means and remember where the encoded data starts */
			signedCertObjectLength = sizeofObject( dataSize );
			sMemOpen( &stream, signedCertObject, signedCertObjectLength );
			writeSequence( &stream, dataSize );
			swrite( &stream, certObject, certObjectLength );
			writeConstructed( &stream, sizeofShortInteger( 0 ), 2 );
			writeShortInteger( &stream, 0, 1 );
			assert( sStatusOK( &stream ) );
			sMemDisconnect( &stream );
			recoverCertData( certInfoPtr, signedCertObject,
							 signedCertObjectLength,
							 CRYPT_CERTTYPE_REQUEST_CERT );

			/* The pseudo-signature has been checked (since we just created
			   it), this also avoids nasty semantic problems with not-really-
			   signed CRMF requests with encryption-only keys */
			certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
			break;
			}

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* Revocation requests can't be signed so the (pseudo-)signed
			   data is just the object data */
			memcpy( signedCertObject, certObject, certObjectLength );
			signedCertObjectLength = certObjectLength;

			/* Since revocation requests can't be signed we mark them as
			   pseudo-signed to avoid any problems that might arise from
			   this */
			certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	certInfoPtr->certificate = signedCertObject;
	certInfoPtr->certificateSize = signedCertObjectLength;

	/* The object is now (pseudo-)signed and initialised */
	certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		/* If it's a CRMF request with POP done via out-of-band means, we
		   got here via a standard signing action (except that the key was
		   an encryption-only key), don't change the object state since the
		   kernel will do this as the post-signing step */
		return( CRYPT_OK );
	return( krnlSendMessage( certInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED,
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}

/* Sign a certificate object */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	CERT_INFO *issuerCertInfoPtr = NULL;
	STREAM stream;
	const CERTWRITE_INFO *certWriteInfo;
	const CRYPT_SIGNATURELEVEL_TYPE signatureLevel = \
				( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST ) ? \
					certInfoPtr->cCertRev->signatureLevel : \
					CRYPT_SIGNATURELEVEL_NONE;
	const BOOLEAN isCertificate = \
			( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? TRUE : FALSE;
	BOOLEAN issuerCertAcquired = FALSE, nonSigningKey = FALSE;
	BYTE certObjectBuffer[ 1024 + 8 ], *certObjectPtr = certObjectBuffer;
	void *signedCertObject;
	const time_t currentTime = ( signContext == CRYPT_UNUSED ) ? \
							   getTime() : getReliableTime( signContext );
	const int certWriteInfoSize = sizeofCertWriteTable();
	int certObjectLength, signedCertObjectLength, signedCertAllocSize;
	int extraDataLength = 0, complianceLevel;
	int iterationCount = 0, status = CRYPT_OK;

	assert( certInfoPtr->certificate == NULL );

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( certInfoPtr->ownerHandle,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a non-signing key we have to create a special format of cert
	   request that isn't signed but contains an indication that the private
	   key POP will be performed by out-of-band means.  We also have to check
	   for the signContext being absent to handle OCSP requests for which the
	   signature is optional so there may be no signing key present */
	if( signContext == CRYPT_UNUSED || \
		cryptStatusError( krnlSendMessage( signContext, IMESSAGE_CHECK,
						  NULL, MESSAGE_CHECK_PKC_SIGN ) ) )
		nonSigningKey = TRUE;

	/* Obtain the issuer certificate from the private key if necessary */
	if( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		( ( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE ) && \
		  !nonSigningKey ) )
		{
		/* If it's a self-signed cert, the issuer is also the subject */
		if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
			issuerCertInfoPtr = certInfoPtr;
		else
			{
			CRYPT_CERTIFICATE dataOnlyCert;

			/* Get the data-only certificate from the context */
			status = krnlSendMessage( signContext, IMESSAGE_GETDEPENDENT,
									  &dataOnlyCert, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
						CRYPT_ARGERROR_VALUE : status );
			status = krnlAcquireObject( dataOnlyCert, OBJECT_TYPE_CERTIFICATE,
										( void ** ) &issuerCertInfoPtr,
										CRYPT_ARGERROR_VALUE );
			if( cryptStatusError( status ) )
				return( status );
			issuerCertAcquired = TRUE;
			}

		/* Make sure that the signing key is associated with a complete
		   issuer cert which is valid for cert/CRL signing (if it's a self-
		   signed cert then we don't have to have a completed cert present
		   because the self-sign operation hasn't created it yet) */
		if( ( !( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) && \
			  issuerCertInfoPtr->certificate == NULL ) || \
			( issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			  issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN ) )
			{
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( CRYPT_ARGERROR_VALUE );
			}

		/* If it's an OCSP request or response, the signing cert has to be
		   valid for signing */
		if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_NONE,
						CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
						CRYPT_KEYUSAGE_NONREPUDIATION,
						complianceLevel, &certInfoPtr->errorLocus,
						&certInfoPtr->errorType );
		else
			/* If it's a non-self-signed object, it must be signed by a CA
			   cert */
			if( !( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
				{
				status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA,
							isCertificate ? CRYPT_KEYUSAGE_KEYCERTSIGN : \
											CRYPT_KEYUSAGE_CRLSIGN,
							complianceLevel, &certInfoPtr->errorLocus,
							&certInfoPtr->errorType );
				if( cryptStatusError( status ) && \
					certInfoPtr->errorType == CRYPT_ERRTYPE_CONSTRAINT )
					/* If there was a constraint problem, it's something in
					   the issuer's cert rather than the cert being signed
					   so we have to change the error type accordingly.
					   What's reported isn't strictly accurate since the
					   locus is in the issuer rather than subject cert, but
					   it's the best we can do */
					certInfoPtr->errorType = CRYPT_ERRTYPE_ISSUERCONSTRAINT;
				}
		if( cryptStatusError( status ) )
			{
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* If we need to include extra data in the signature, make sure that it's
	   available and determine how big it'll be.  If there's no issuer cert
	   available and we've been asked for extra signature data, we fall back
	   to providing just a raw signature rather than bailing out completely */
	if( signatureLevel > CRYPT_SIGNATURELEVEL_NONE && \
		issuerCertInfoPtr != NULL )
		{
		assert( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
				certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST );

		if( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
			status = exportCert( NULL, &extraDataLength,
								 CRYPT_CERTFORMAT_CERTIFICATE,
								 issuerCertInfoPtr, CRYPT_UNUSED );
		else
			{
			MESSAGE_DATA msgData;

			assert( signatureLevel == CRYPT_SIGNATURELEVEL_ALL );

			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( issuerCertInfoPtr->objectHandle,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_ICERTFORMAT_CERTSEQUENCE );
			extraDataLength = msgData.length;
			}
		if( cryptStatusError( status ) )
			{
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* If it's a certificate chain, copy over the signing cert(s) */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* If there's a chain of certs present (for example from a previous
		   signing attempt that wasn't completed due to an error), free
		   them */
		if( certInfoPtr->cCertCert->chainEnd > 0 )
			{
			int i;
			
			for( i = 0; i < certInfoPtr->cCertCert->chainEnd && \
						i < MAX_CHAINLENGTH; i++ )
				krnlSendNotifier( certInfoPtr->cCertCert->chain[ i ],
								  IMESSAGE_DECREFCOUNT );
			certInfoPtr->cCertCert->chainEnd = 0;
			}

		/* If it's a self-signed cert, it must be the only cert in the chain
		   (creating a chain like this doesn't make much sense, but we handle
		   it anyway) */
		if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
			{
			if( certInfoPtr->cCertCert->chainEnd > 0 )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				status = CRYPT_ERROR_INVALID;
				}
			}
		else
			/* Copy the cert chain into the cert to be signed */
			status = copyCertChain( certInfoPtr, signContext, FALSE );
		if( cryptStatusError( status ) )
			{
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* If it's some certificate variant or CRL/OCSP response and the various
	   timestamps haven't been set yet, start them at the current time and
	   give them the default validity period or next update time if these
	   haven't been set.  The time used is the local time, this is converted
	   to GMT when we write it to the certificate.  Issues like validity
	   period nesting and checking for valid time periods are handled
	   elsewhere */
	if( ( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		  certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE ) && \
		certInfoPtr->startTime <= MIN_TIME_VALUE )
		{
		/* If the time is screwed up we can't provide a signed indication
		   of the time */
		if( currentTime <= MIN_TIME_VALUE )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( CRYPT_ERROR_NOTINITED );
			}
		certInfoPtr->startTime = currentTime;
		}
	if( isCertificate && certInfoPtr->endTime <= MIN_TIME_VALUE )
		{
		int validity;

		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &validity, 
								  CRYPT_OPTION_CERT_VALIDITY );
		if( cryptStatusError( status ) )
			return( status );
		certInfoPtr->endTime = certInfoPtr->startTime + \
							   ( ( time_t ) validity * 86400L );
		}
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		if( certInfoPtr->endTime <= MIN_TIME_VALUE )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
				/* OCSP responses come directly from the certificate store
				   and represent an atomic (and ephemeral) snapshot of the
				   store state.  Because of this the next-update time is
				   effectively immediately, since the next snapshot could
				   provide a different response */
				certInfoPtr->endTime = currentTime;
			else
				{
				int updateInterval;

				status = krnlSendMessage( certInfoPtr->ownerHandle,
										  IMESSAGE_GETATTRIBUTE, &updateInterval,
										  CRYPT_OPTION_CERT_UPDATEINTERVAL );
				if( cryptStatusError( status ) )
					return( status );
				certInfoPtr->endTime = certInfoPtr->startTime + \
									   ( ( time_t ) updateInterval * 86400L );
				}
			}
		if( certInfoPtr->cCertRev->revocationTime <= MIN_TIME_VALUE )
			certInfoPtr->cCertRev->revocationTime = currentTime;
		}

	/* If it's a certificate, set up the certificate serial number */
	if( isCertificate )
		{
		status = setSerialNumber( certInfoPtr, NULL, 0 );
		if( cryptStatusError( status ) )
			{
			if( issuerCertAcquired )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* Determine the hash algorithm to use and, if it's a cert or CRL,
	   remember it for when we write the cert (the value is embedded in
	   the cert to prevent an obscure attack on unpadded RSA signature
	   algorithms) */
	krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE,
					 &hashAlgo, CRYPT_OPTION_ENCR_HASH );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN || \
		certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		certInfoPtr->cCertCert->hashAlgo = hashAlgo;
	else
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
			certInfoPtr->cCertRev->hashAlgo = hashAlgo;

	/* Select the function to use to write the certificate object to be
	   signed */
	for( certWriteInfo = getCertWriteTable();
		 certWriteInfo->type != certInfoPtr->type && \
			certWriteInfo->type != CRYPT_CERTTYPE_NONE && \
			iterationCount++ < certWriteInfoSize; 
		 certWriteInfo++ );
	if( iterationCount >= certWriteInfoSize || \
		certWriteInfo->type == CRYPT_CERTTYPE_NONE )
		{
		assert( NOTREACHED );
		if( issuerCertAcquired )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Determine how big the encoded certificate information will be,
	   allocate memory for it and the full signed certificate, and write the
	   encoded certificate information */
	sMemOpen( &stream, NULL, 0 );
	status = certWriteInfo->writeFunction( &stream, certInfoPtr, 
										   issuerCertInfoPtr, signContext );
	certObjectLength = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		{
		if( issuerCertAcquired )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		return( status );
		}
	signedCertAllocSize = certObjectLength + 1024 + extraDataLength;
	if( ( certObjectLength > 1024 && \
		  ( certObjectPtr = clDynAlloc( "signCert", \
										certObjectLength ) ) == NULL ) || \
		( signedCertObject = clAlloc( "signCert", \
									  signedCertAllocSize ) ) == NULL )
		{
		if( certObjectPtr != NULL )
			clFree( "signCert", certObjectPtr );
		if( issuerCertAcquired )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		return( CRYPT_ERROR_MEMORY );
		}
	sMemOpen( &stream, certObjectPtr, certObjectLength );
	status = certWriteInfo->writeFunction( &stream, certInfoPtr, 
										   issuerCertInfoPtr, signContext );
	assert( certObjectLength == stream.bufPos );
	sMemDisconnect( &stream );
	assert( checkObjectEncoding( certObjectPtr, certObjectLength ) > 0 );
	if( issuerCertAcquired )
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
	if( cryptStatusError( status ) )
		{
		zeroise( certObjectPtr, certObjectLength );
		if( certObjectPtr != certObjectBuffer )
			clFree( "signCert", certObjectPtr );
		clFree( "signCert", signedCertObject );
		return( status );
		}

	/* If there's no signing key present, pseudo-sign the certificate
	   information by writing the outer wrapper and moving the object into
	   the initialised state */
	if( nonSigningKey )
		{
		status = pseudoSignCertificate( certInfoPtr, signedCertObject,
										certObjectPtr, certObjectLength );
		zeroise( certObjectPtr, certObjectLength );
		if( certObjectPtr != certObjectBuffer )
			clFree( "signCert", certObjectPtr );
		assert( checkObjectEncoding( certInfoPtr->certificate, \
									 certInfoPtr->certificateSize ) > 0 );
		return( status );
		}

	/* Sign the certificate information.  CRMF and OCSP use a b0rken
	   signature format (the authors couldn't quite manage a cut & paste of
	   two lines of text), so if it's one of these we have to use nonstandard
	   formatting */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST )
		{
		const int extraDataEncodedLength = \
				( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT ) ? \
					( int ) sizeofObject( sizeofObject( extraDataLength ) ) : \
				( signatureLevel == CRYPT_SIGNATURELEVEL_ALL ) ? \
					( int ) sizeofObject( extraDataLength ) : 0;
		const int formatInfo = \
				( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT ) ? \
				1 : ( 0 | 0x80 );

		status = createX509signature( signedCertObject,
							&signedCertObjectLength, signedCertAllocSize,
							certObjectPtr, certObjectLength, signContext,
							hashAlgo, formatInfo, extraDataEncodedLength );
		}
	else
		/* It's a standard signature */
		status = createX509signature( signedCertObject,
							&signedCertObjectLength, signedCertAllocSize,
							certObjectPtr, certObjectLength, signContext,
							hashAlgo, CRYPT_UNUSED, 0 );
	zeroise( certObjectPtr, certObjectLength );
	if( certObjectPtr != certObjectBuffer )
		clFree( "signCert", certObjectPtr );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_NUM1 ) ? \
				CRYPT_ARGERROR_VALUE : status );
	certInfoPtr->certificate = signedCertObject;
	certInfoPtr->certificateSize = signedCertObjectLength;

	/* If we need to include extra data with the signature, attach it to the
	   end of the sig */
	if( extraDataLength > 0 )
		{
		const int extraDataType = \
			( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT ) ? \
			CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_ICERTFORMAT_CERTSEQUENCE;

		sMemOpen( &stream, ( BYTE * ) signedCertObject + signedCertObjectLength,
				  signedCertAllocSize - signedCertObjectLength );
		if( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
			{
			writeConstructed( &stream, sizeofObject( extraDataLength ), 0 );
			writeSequence( &stream, extraDataLength );
			}
		else
			{
			assert( signatureLevel == CRYPT_SIGNATURELEVEL_ALL );

			writeConstructed( &stream, extraDataLength, 0 );
			}
		status = exportCertToStream( &stream, issuerCertInfoPtr->objectHandle,
									 extraDataType );
		certInfoPtr->certificateSize = signedCertObjectLength + \
									   stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			{
			zeroise( certInfoPtr->certificate, signedCertAllocSize );
			clFree( "signCert", certInfoPtr->certificate );
			certInfoPtr->certificate = NULL;
			certInfoPtr->certificateSize = 0;
			return( status );
			}
		}
	assert( checkObjectEncoding( certInfoPtr->certificate, \
								 certInfoPtr->certificateSize ) > 0 );

	/* If it's a certification request, it's now self-signed.  In addition
	   the signature has been checked, since we just created it */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
		certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;

#if 0	/* 15/6/04 Only the root should be marked as self-signed, having
				   supposedly self-signed certs inside the chain causes
				   problems when trying to detect pathkludge certs */
	/* If it's a cert chain and the root is self-signed, the entire chain
	   counts as self-signed */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		int selfSigned;

		status = krnlSendMessage( \
					certInfoPtr->cCertCert->chain[ certInfoPtr->cCertCert->chainEnd - 1 ],
					IMESSAGE_GETATTRIBUTE, &selfSigned,
					CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusOK( status ) && selfSigned )
			certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
		}
#endif /* 0 */

	/* If it's not an object type with special-case post-signing
	   requirements, we're done */
	if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
		certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN && \
		certInfoPtr->type != CRYPT_CERTTYPE_REQUEST_CERT )
		return( CRYPT_OK );

	/* Recover information such as pointers to encoded cert data */
	return( recoverCertData( certInfoPtr, signedCertObject,
							 signedCertObjectLength, certInfoPtr->type ) );
	}
