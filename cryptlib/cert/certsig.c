/****************************************************************************
*																			*
*					  Certificate Signing/Checking Routines					*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in sign.c */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const int sigMaxLength, const void *object, 
						 const int objectLength, 
						 const CRYPT_CONTEXT signContext,
						 const CRYPT_ALGO_TYPE hashAlgo,
						 const int formatInfo, const int extraDataLength );
int checkX509signature( const void *signedObject, const int signedObjectLength,
						void **object, int *objectLength, 
						const CRYPT_CONTEXT sigCheckContext,
						const int formatInfo );

/****************************************************************************
*																			*
*							Certificate Signing Functions					*
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
	CERT_INFO *issuerCertInfoPtr = NULL;
	STREAM stream;
	const BOOLEAN isCertificate = \
			( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? TRUE : FALSE;
	BOOLEAN issuerCertPresent = FALSE, nonSigningKey = FALSE;
	BYTE certObjectBuffer[ 1024 ], *certObjectPtr = certObjectBuffer;
	int ( *writeCertObjectFunction )( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
									  const CERT_INFO *issuerCertInfoPtr,
									  const CRYPT_CONTEXT iIssuerCryptContext );
	void *signedCertObject;
	const time_t currentTime = ( signContext == CRYPT_UNUSED ) ? \
							   getTime() : getReliableTime( signContext );
	int certObjectLength, signedCertObjectLength, signedCertAllocSize;
	int extraDataLength = 0, i, status = CRYPT_OK;

	assert( certInfoPtr->certificate == NULL );

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
			status = krnlGetObject( dataOnlyCert, OBJECT_TYPE_CERTIFICATE, 
									( void ** ) &issuerCertInfoPtr, 
									CRYPT_ARGERROR_VALUE );
			if( cryptStatusError( status ) )
				return( status );
			issuerCertPresent = TRUE;
			}

		/* Make sure that the signing key is associated with a complete 
		   issuer cert which is valid for cert/CRL signing */
		if( ( issuerCertPresent && issuerCertInfoPtr->certificate == NULL ) || \
			( issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			  issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN ) )
			{
			if( issuerCertPresent )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( CRYPT_ARGERROR_VALUE );
			}

		/* If it's an OCSP request or response, the signing cert has to be 
		   valid for signing */
		if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			status = checkCertUsage( issuerCertInfoPtr, 
							CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION,
							MESSAGE_CHECK_PKC_SIGN, &certInfoPtr->errorLocus, 
							&certInfoPtr->errorType );
		else
			/* If it's a non-self-signed object, it must be signed by a CA 
			   cert */
			if( issuerCertPresent )
				{
				status = checkCertUsage( issuerCertInfoPtr, isCertificate ? \
							CRYPT_KEYUSAGE_KEYCERTSIGN : CRYPT_KEYUSAGE_CRLSIGN,
							MESSAGE_CHECK_CA, &certInfoPtr->errorLocus, 
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
			if( issuerCertPresent )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* If we need to include extra data in the signature, make sure that it's
	   available and determine how big it'll be.  If there's no issuer cert
	   available and we've been asked for extra signature data, we fall back 
	   to providing just a raw signature rather than bailing out completely */
	if( certInfoPtr->signatureLevel > CRYPT_SIGNATURELEVEL_NONE && \
		issuerCertInfoPtr != NULL )
		{
		assert( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
				certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST );

		if( certInfoPtr->signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
			status = exportCert( NULL, &extraDataLength,
								 CRYPT_CERTFORMAT_CERTIFICATE, 
								 issuerCertInfoPtr, CRYPT_UNUSED );
		else
			{
			RESOURCE_DATA msgData;

			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( issuerCertInfoPtr->objectHandle, 
									  IMESSAGE_CRT_EXPORT, &msgData, 
									  CRYPT_ICERTFORMAT_CERTSEQUENCE );
			extraDataLength = msgData.length;
			}
		if( cryptStatusError( status ) )
			{
			if( issuerCertPresent )
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
		if( certInfoPtr->certChainEnd )
			{
			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				krnlSendNotifier( certInfoPtr->certChain[ i ],
								  IMESSAGE_DECREFCOUNT );
			certInfoPtr->certChainEnd = 0;
			}

		/* If it's a self-signed cert, it must be the only cert in the chain
		   (creating a chain like this doesn't make much sense, but we handle
		   it anyway) */
		if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
			{
			if( certInfoPtr->certChainEnd )
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
			if( issuerCertPresent )
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
		certInfoPtr->startTime <= 0 )
		{
		/* If the time is screwed up we can't provide a signed indication
		   of the time */
		if( currentTime < MIN_TIME_VALUE )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_NOTINITED );
			}
		certInfoPtr->startTime = currentTime;
		}
	if( isCertificate && certInfoPtr->endTime <= 0 )
		{
		int validity;

		krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE, 
						 &validity, CRYPT_OPTION_CERT_VALIDITY );
		certInfoPtr->endTime = certInfoPtr->startTime + \
							   ( ( time_t ) validity * 86400L );
		}
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		if( certInfoPtr->endTime <= 0 )
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

				krnlSendMessage( certInfoPtr->ownerHandle, 
								 IMESSAGE_GETATTRIBUTE, &updateInterval, 
								 CRYPT_OPTION_CERT_UPDATEINTERVAL );

				certInfoPtr->endTime = certInfoPtr->startTime + \
									   ( ( time_t ) updateInterval * 86400L );
				}
			}
		if( certInfoPtr->revocationTime <= 0 )
			certInfoPtr->revocationTime = currentTime;
		}

	/* If it's a certificate, set up the certificate serial number */
	if( isCertificate )
		{
		status = setSerialNumber( certInfoPtr, NULL, 0 );
		if( cryptStatusError( status ) )
			{
			if( issuerCertPresent )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* Select the function to use to write the certificate object to be
	   signed */
	for( i = 0; certWriteTable[ i ].type != certInfoPtr->type && \
				certWriteTable[ i ].type != CRYPT_CERTTYPE_NONE; i++ );
	if( certWriteTable[ i ].type == CRYPT_CERTTYPE_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	writeCertObjectFunction = certWriteTable[ i ].writeFunction;

	/* Determine how big the encoded certificate information will be,
	   allocate memory for it and the full signed certificate, and write the
	   encoded certificate information */
	sMemOpen( &stream, NULL, 0 );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	certObjectLength = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		{
		if( issuerCertPresent )
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
		if( issuerCertPresent )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		return( CRYPT_ERROR_MEMORY );
		}
	sMemOpen( &stream, certObjectPtr, certObjectLength );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	assert( certObjectLength == stream.bufPos );
	sMemDisconnect( &stream );
	if( issuerCertPresent )
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
				( certInfoPtr->signatureLevel == \
							CRYPT_SIGNATURELEVEL_SIGNERCERT ) ? \
					( int ) sizeofObject( sizeofObject( extraDataLength ) ) : \
				( certInfoPtr->signatureLevel == \
							CRYPT_SIGNATURELEVEL_ALL ) ? \
					( int ) sizeofObject( extraDataLength ) : 0;
		const int formatInfo = \
				( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT ) ? \
				1 : ( 0 | 0x80 );

		status = createX509signature( signedCertObject, 
							&signedCertObjectLength, signedCertAllocSize,
							certObjectPtr, certObjectLength, signContext, 
							CRYPT_ALGO_SHA, formatInfo, 
							extraDataEncodedLength );
		}
	else
		/* It's a standard signature */
		status = createX509signature( signedCertObject, 
							&signedCertObjectLength, signedCertAllocSize, 
							certObjectPtr, certObjectLength, signContext, 
							CRYPT_ALGO_SHA, CRYPT_UNUSED, 0 );
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
		sMemOpen( &stream, ( BYTE * ) signedCertObject + signedCertObjectLength, 
				  signedCertAllocSize - signedCertObjectLength );
		if( certInfoPtr->signatureLevel == \
								CRYPT_SIGNATURELEVEL_SIGNERCERT )
			{
			writeConstructed( &stream, sizeofObject( extraDataLength ), 0 );
			writeSequence( &stream, extraDataLength );
			assert( sStatusOK( &stream ) && \
					sMemDataLeft( &stream ) >= extraDataLength );
			status = exportCert( sMemBufPtr( &stream ), &extraDataLength,
								 CRYPT_CERTFORMAT_CERTIFICATE, 
								 issuerCertInfoPtr, sMemDataLeft( &stream ) );
			}
		else
			{
			writeConstructed( &stream, extraDataLength, 0 );
			assert( sStatusOK( &stream ) && \
					sMemDataLeft( &stream ) >= extraDataLength );
			status = exportCertToStream( &stream, 
										 issuerCertInfoPtr->objectHandle,
										 CRYPT_ICERTFORMAT_CERTSEQUENCE );
			}
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

	/* If it's a certification request, it's now self-signed.  In addition 
	   the signature has been checked, since we just created it */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
		certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;

	/* If it's a cert chain and the root is self-signed, the entire chain 
	   counts as self-signed */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		int selfSigned;

		status = krnlSendMessage( \
						certInfoPtr->certChain[ certInfoPtr->certChainEnd - 1 ], 
						IMESSAGE_GETATTRIBUTE, &selfSigned,
						CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusOK( status ) && selfSigned )
			certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
		}

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

/****************************************************************************
*																			*
*							Certificate Checking Functions					*
*																			*
****************************************************************************/

/* Generate a nameID or issuerID.  These are needed when storing/retrieving a
   cert to/from an database keyset, which can't handle the awkward 
   heirarchical IDs usually used in certs.  There are two types of IDs, the 
   nameID, which is an SHA-1 hash of the DN and is used for certs, and the 
   issuerID, which is an SHA-1 hash of the IssuerAndSerialNumber and is used 
   for CRLs and CMS */

static int generateCertID( const void *dn, const int dnLength,
						   const void *serialNumber,
						   const int serialNumberLength, BYTE *certID )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	STREAM stream;
	BYTE buffer[ MAX_SERIALNO_SIZE + 8 ];
	int status;

	assert( isReadPtr( dn, dnLength ) );
	assert( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			( isReadPtr( serialNumber, serialNumberLength ) && \
			  serialNumberLength <= MAX_SERIALNO_SIZE ) );

	/* Get the hash algorithm information */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	/* If it's a pure DN hash, we don't have to perform any encoding */
	if( serialNumber == NULL )
		{
		hashFunction( NULL, certID, dn, dnLength, HASH_ALL );
		return( CRYPT_OK );
		}

	/* Write the relevant information to a buffer and hash the data to get
	   the ID */
	sMemOpen( &stream, buffer, MAX_SERIALNO_SIZE + 8 );
	writeSequence( &stream, dnLength + \
							sizeofInteger( serialNumber, serialNumberLength ) );
	hashFunction( hashInfo, NULL, buffer, stell( &stream ), HASH_START );
	hashFunction( hashInfo, NULL, dn, dnLength, HASH_CONTINUE );
	sseek( &stream, 0 );
	status = writeInteger( &stream, serialNumber, serialNumberLength, 
						   DEFAULT_TAG );
	hashFunction( hashInfo, certID, buffer, stell( &stream ), HASH_END );
	sMemClose( &stream );

	return( status );
	}

/* Check the entries in an RTCS or OCSP response object against a cert 
   store.  The semantics for this one are a bit odd, the source information 
   for the check is from a request, but the destination information is in a 
   response, since we don't have a copy-and-verify function we do the 
   checking from the response even though, technically, it's the request 
   data which is being checked */

int checkRTCSResponse( CERT_INFO *certInfoPtr, 
					   const CRYPT_KEYSET cryptKeyset )
	{
	VALIDITY_INFO *validityInfo;
	BOOLEAN isInvalid = FALSE;

	/* Walk down the list of validity entries fetching status information 
	   on each one from the cert store */
	for( validityInfo = certInfoPtr->validityInfo;
		 validityInfo != NULL; validityInfo = validityInfo->next )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		int status;

		/* Determine the validity of the object */
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, 
							   validityInfo->data, KEYID_SIZE, NULL, 0,
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( cryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			/* The cert is present and OK, we're done */
			validityInfo->status = TRUE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_VALID;
			}
		else
			{
			/* The cert isn't present/OK, record the fact that we've seen at 
			   least one invalid cert */
			validityInfo->status = FALSE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_NOTVALID;
			isInvalid = TRUE;
			}
		}

	/* If at least one cert was invalid, indicate this to the caller.  Note
	   that if there are multiple certs present in the query, it's up to the
	   caller to step through the list to find out which ones were invalid */
	return( isInvalid ? CRYPT_ERROR_INVALID : CRYPT_OK );
	}

int checkOCSPResponse( CERT_INFO *certInfoPtr, 
					   const CRYPT_KEYSET cryptKeyset )
	{
	REVOCATION_INFO *revocationInfo;
	BOOLEAN isRevoked = FALSE;

	/* Walk down the list of revocation entries fetching status information 
	   on each one from the cert store */
	for( revocationInfo = certInfoPtr->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		CERT_INFO *crlEntryInfoPtr;
		REVOCATION_INFO *crlRevocationInfo;
		int status;

		assert( revocationInfo->type == CRYPT_KEYID_NONE || \
				revocationInfo->type == CRYPT_IKEYID_CERTID || \
				revocationInfo->type == CRYPT_IKEYID_ISSUERID );

		/* If it's an OCSPv1 ID, we can't really do anything with it because
		   the one-way hashing process required by the standard destroys the 
		   information */
		if( revocationInfo->type == CRYPT_KEYID_NONE )
			{
			revocationInfo->status = CRYPT_OCSPSTATUS_UNKNOWN;
			continue;
			}

		/* Determine the revocation status of the object.  Unfortunately
		   because of the way OCSP returns status information we can't just
		   return a yes/no response but have to perform multiple queries to
		   determine whether a cert is not revoked, revoked, or unknown.
		   Optimising the query strategy is complicated by the fact that
		   although in theory the most common status will be not-revoked, we
		   could also get a large number of unknown queries, for example if
		   a widely-deployed implementation which is pointed at a cryptlib-
		   based server gets its ID-hashing wrong and submits huge numbers of
		   queries with IDs that match no known cert.  The best we can do is
		   assume that a not-revoked status will be the most common, and if 
		   that fails fall back to a revoked status check */
		setMessageKeymgmtInfo( &getkeyInfo, revocationInfo->type,
							   revocationInfo->dataPtr, KEYID_SIZE, NULL, 0,
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( cryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			/* The cert is present and not revoked/OK, we're done */
			revocationInfo->status = CRYPT_OCSPSTATUS_NOTREVOKED;
			continue;
			}

		/* The cert isn't a currently active cert, if it weren't for the need 
		   to return the CRL-based OCSP status values we could just return 
		   not-OK now, but as it is we have to differentiate between revoked 
		   and unknown, so we perform a second query, this time of the 
		   revocation information */
		setMessageKeymgmtInfo( &getkeyInfo, revocationInfo->type, 
							   revocationInfo->dataPtr, KEYID_SIZE, NULL, 0,
							   KEYMGMT_FLAG_NONE );
		status = krnlSendMessage( cryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_REVOCATIONINFO );
		if( cryptStatusError( status ) )
			{
			/* No revocation information found, status is unknown */
			revocationInfo->status = CRYPT_OCSPSTATUS_UNKNOWN;
			continue;
			}

		/* The cert has been revoked, copy the revocation information across
		   from the CRL entry.  We don't check for problems in copying the
		   attributes since bailing out at this late stage is worse than
		   missing a few obscure annotations to the revocation */
		status = krnlGetObject( getkeyInfo.cryptHandle, 
								OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &crlEntryInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		crlRevocationInfo = crlEntryInfoPtr->revocations;
		if( crlRevocationInfo != NULL )
			{
			revocationInfo->revocationTime = \
									crlRevocationInfo->revocationTime;
			if( crlRevocationInfo->attributes != NULL )
				copyRevocationAttributes( &revocationInfo->attributes,
						crlRevocationInfo->attributes, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
			}
		krnlReleaseObject( crlEntryInfoPtr->objectHandle );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

		/* Record the fact that we've seen at least one revoked cert */
		revocationInfo->status = CRYPT_OCSPSTATUS_REVOKED;
		isRevoked = TRUE;
		}

	/* If at least one cert was revoked, indicate this to the caller.  Note
	   that if there are multiple certs present in the query, it's up to the
	   caller to step through the list to find out which ones were revoked */
	return( isRevoked ? CRYPT_ERROR_INVALID : CRYPT_OK );
	}

/* Check a certificate using an RTCS or OCSP responder */

static int checkResponder( CERT_INFO *certInfoPtr, 
						   const CRYPT_SESSION cryptSession )
	{
	CRYPT_CERTIFICATE cryptResponse;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int type, status;

	status = krnlSendMessage( cryptSession, IMESSAGE_GETATTRIBUTE, &type,
							  CRYPT_IATTRIBUTE_SUBTYPE );
	if( cryptStatusError( status ) )
		return( status );

	assert( ( type == SUBTYPE_SESSION_RTCS ) || \
			( type == SUBTYPE_SESSION_OCSP ) );

	/* Create the request, add the certificate, and add the request to the 
	   session */
	setMessageCreateObjectInfo( &createInfo, 
							    ( type == SUBTYPE_SESSION_RTCS ) ? \
									CRYPT_CERTTYPE_RTCS_REQUEST : \
									CRYPT_CERTTYPE_OCSP_REQUEST );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					&certInfoPtr->objectHandle, CRYPT_CERTINFO_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptSession, IMESSAGE_SETATTRIBUTE,
					&createInfo.cryptHandle, CRYPT_SESSINFO_REQUEST );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Activate the session and get the response info */
	status = krnlSendMessage( cryptSession, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_SESSINFO_ACTIVE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptSession, IMESSAGE_GETATTRIBUTE,
								  &cryptResponse, CRYPT_SESSINFO_RESPONSE );
	if( cryptStatusError( status ) )
		return( status );
	if( type == SUBTYPE_SESSION_RTCS )
		{
		int certStatus;

		status = krnlSendMessage( cryptResponse, IMESSAGE_GETATTRIBUTE, 
								  &certStatus, CRYPT_CERTINFO_CERTSTATUS );
		if( cryptStatusOK( status ) && \
			( certStatus != CRYPT_CERTSTATUS_VALID ) )
			status = CRYPT_ERROR_INVALID;
		}
	else
		{
		int revocationStatus;

		status = krnlSendMessage( cryptResponse, IMESSAGE_GETATTRIBUTE, 
								  &revocationStatus, 
								  CRYPT_CERTINFO_REVOCATIONSTATUS );
		if( cryptStatusOK( status ) && \
			( revocationStatus != CRYPT_OCSPSTATUS_NOTREVOKED ) )
			status = CRYPT_ERROR_INVALID;
		}
	krnlSendNotifier( cryptResponse, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Check a certificate against a CRL */

static int checkCRL( CERT_INFO *certInfoPtr, const CRYPT_CERTIFICATE cryptCRL )
	{
	CERT_INFO *crlInfoPtr;
	int i, status;

	/* Check that the CRL is a complete, signed CRL and not a newly-created 
	   CRL object */
	status = krnlGetObject( cryptCRL, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &crlInfoPtr, CRYPT_ARGERROR_VALUE );
	if( cryptStatusError( status ) )
		return( status );
	if( crlInfoPtr->certificate == NULL )
		{
		krnlReleaseObject( crlInfoPtr->objectHandle );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Check the base cert against the CRL.  If it's been revoked or there's
	   only a single cert present, exit */
	status = checkRevocation( certInfoPtr, crlInfoPtr );
	if( cryptStatusError( status ) || \
		certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
		{
		krnlReleaseObject( crlInfoPtr->objectHandle );
		return( status );
		}

	/* It's a cert chain, check every remaining cert in the chain against the
	   CRL.  In theory this is pointless because a CRL can only contain 
	   information for a single cert in the chain, however the caller may 
	   have passed us a CRL for an intermediate cert (in which case the check
	   for the leaf cert was pointless).  In any case it's easier to just do
	   the check for all certs than to determine which cert the CRL applies 
	   to, so we check for all certs */
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainInfoPtr;

		/* Check this cert against the CRL */
		status = krnlGetObject( certInfoPtr->certChain[ i ], 
								OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certChainInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
		if( cryptStatusOK( status ) )
			{
			status = checkRevocation( certChainInfoPtr, crlInfoPtr );
			krnlReleaseObject( certChainInfoPtr->objectHandle );
			}

		/* If the cert has been revoked, remember which one is the revoked
		   cert and exit */
		if( cryptStatusError( status ) )
			{
			certInfoPtr->certChainPos = i;
			krnlReleaseObject( crlInfoPtr->objectHandle );
			return( status );
			}
		}

	krnlReleaseObject( crlInfoPtr->objectHandle );
	return( CRYPT_OK );
	}

/* Check a self-signed certificate like a cert request or a self-signed 
   cert */

static int checkSelfSignedCert( CERT_INFO *certInfoPtr, 
								const int formatInfo )
	{
	CRYPT_CONTEXT iCryptContext;
	CERT_INFO *issuerCertInfoPtr;
	int status;

	/* Since there's no signer cert provided it has to be either explicitly 
	   self-signed or signed by a trusted cert */
	if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		{
		iCryptContext = certInfoPtr->iPubkeyContext;
		issuerCertInfoPtr = certInfoPtr;
		}
	else
		{
		CRYPT_CERTIFICATE iCryptCert = certInfoPtr->objectHandle;

		/* If it's a certificate, it may be implicitly trusted */
		if( ( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT ) && \
			cryptStatusOK( \
				krnlSendMessage( certInfoPtr->ownerHandle, 
								 IMESSAGE_SETATTRIBUTE, &iCryptCert, 
								 CRYPT_IATTRIBUTE_CERT_CHECKTRUST ) ) )
			/* The cert is implicitly trusted, we're done */
			return( CRYPT_OK );

		/* If it's not self-signed, it has to be signed by a trusted cert */
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_SETATTRIBUTE, &iCryptCert, 
								  CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
		if( cryptStatusError( status ) )
			/* There's no trusted signer present, indicate that we need
			   something to check the cert with */
			return( CRYPT_ARGERROR_VALUE );
		status = krnlGetObject( iCryptCert, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &issuerCertInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		iCryptContext = iCryptCert;
		}

	/* Check the signer details and signature */
	status = checkCert( certInfoPtr, issuerCertInfoPtr, FALSE,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( issuerCertInfoPtr != certInfoPtr )
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
	if( cryptStatusError( status ) )
		return( status );
	if( ( certInfoPtr->flags & CERT_FLAG_SIGCHECKED ) || \
		cryptStatusOK( \
			krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE,
							 &certInfoPtr->objectHandle, 
							 CRYPT_IATTRIBUTE_CERT_CHECKTRUST ) ) )
		/* We've already checked the signature or it's an implicitly trusted 
		   cert, we don't have to go any further */
		return( CRYPT_OK );
	status = checkX509signature( certInfoPtr->certificate, 
								 certInfoPtr->certificateSize, NULL, NULL,
								 iCryptContext, formatInfo );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_NUM1 ) ? \
				CRYPT_ARGERROR_OBJECT : status );
	certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;
	return( CRYPT_OK );
	}

/* Check the validity of a cert object, either against an issuing key/
   certificate or against a CRL */

int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey )
	{
	CRYPT_CONTEXT iCryptContext;
	CRYPT_CERTTYPE_TYPE sigCheckKeyType = CRYPT_ERROR;
	CERT_INFO *issuerCertInfoPtr = NULL;
	OBJECT_TYPE type;
	const int formatInfo = \
				( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT ) ? 1 : \
				( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST ) ? ( 0 | 0x80 ) : \
				CRYPT_UNUSED;
	int status;

	assert( certInfoPtr->certificate != NULL || \
			certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

	/* If there's no signature checking key supplied, the cert must be self-
	   signed, either an implicitly self-signed object like a cert chain or
	   an explicitly self-signed object like a cert request or self-signed
	   cert */
	if( sigCheckKey == CRYPT_UNUSED )
		{
		/* If it's a cert chain, it's a (complex) self-signed object 
		   containing more than one cert so we need a special function to 
		   check the entire chain */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );

		/* It's an explicitly self-signed object */
		return( checkSelfSignedCert( certInfoPtr, formatInfo ) );
		}

	/* Find out what the sig.check object is */
	status = krnlSendMessage( sigCheckKey, IMESSAGE_GETATTRIBUTE, &type, 
							  CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_VALUE : status );
	if( type == OBJECT_TYPE_CERTIFICATE )
		krnlSendMessage( sigCheckKey, IMESSAGE_GETATTRIBUTE, 
						 &sigCheckKeyType, CRYPT_CERTINFO_CERTTYPE );

	/* Perform a general validity check on the object being checked and the
	   associated verification object.  This is somewhat more strict than 
	   the kernel checks since the kernel only knows about valid subtypes 
	   but not that some subtypes are only valid in combination with some 
	   types of object being checked */
	switch( type )
		{
		case OBJECT_TYPE_CERTIFICATE:
		case OBJECT_TYPE_CONTEXT:
			break;

		case OBJECT_TYPE_KEYSET:
			/* A keyset can only be used as a source of revocation 
			   information for checking a certificate or to populate the
			   status fields of an RTCS/OCSP response */
			if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				certInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT && \
				certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN && \
				certInfoPtr->type != CRYPT_CERTTYPE_RTCS_RESPONSE && \
				certInfoPtr->type != CRYPT_CERTTYPE_OCSP_RESPONSE )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case OBJECT_TYPE_SESSION:
			/* An (RTCS or OCSP) session can only be used as a source of 
			   validity/revocation information for checking a certificate */
			if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				certInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT && \
				certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
				return( CRYPT_ARGERROR_VALUE );
			break;

		default:
			return( CRYPT_ARGERROR_VALUE );
		}

	/* If the checking key is a CRL, a keyset that may contain a CRL, or an
	   RTCS or OCSP session, then this is a validity/revocation check that 
	   works rather differently from a straight signature check */
	if( type == OBJECT_TYPE_CERTIFICATE && \
		sigCheckKeyType == CRYPT_CERTTYPE_CRL )
		return( checkCRL( certInfoPtr, sigCheckKey ) );
	if( type == OBJECT_TYPE_KEYSET )
		{
		BYTE issuerID[ CRYPT_MAX_HASHSIZE ];

		/* If it's an RTCS or OCSP response, use the certificate store to fill 
		   in the status information fields */
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			return( checkRTCSResponse( certInfoPtr, sigCheckKey ) );
		if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			return( checkOCSPResponse( certInfoPtr, sigCheckKey ) );

		assert( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
				certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

		/* Generate the issuerID for this cert and check whether it's present 
		   in the CRL.  Since all we're interested in is a yes/no answer, we 
		   tell the keyset to perform a check only */
		status = generateCertID( certInfoPtr->issuerDNptr,
						certInfoPtr->issuerDNsize, certInfoPtr->serialNumber, 
						certInfoPtr->serialNumberLength, issuerID );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_ISSUERID, 
								   issuerID, KEYID_SIZE, NULL, 0, 
								   KEYMGMT_FLAG_CHECK_ONLY );
			status = krnlSendMessage( sigCheckKey, IMESSAGE_KEY_GETKEY, 
									  &getkeyInfo, 
									  KEYMGMT_ITEM_REVOCATIONINFO );

			/* Reverse the results of the check: OK -> certificate revoked, 
			   not found -> certificate not revoked */
			if( cryptStatusOK( status ) )
				status = CRYPT_ERROR_INVALID;
			else
				if( status == CRYPT_ERROR_NOTFOUND )
					status = CRYPT_OK;
			}

		return( status );
		}
	if( type == OBJECT_TYPE_SESSION )
		return( checkResponder( certInfoPtr, sigCheckKey ) );

	/* If we've been given a self-signed cert, make sure that the sig.check 
	   key is the same as the cert.  To test this we have to compare both 
	   the signing key and, if the sig check object is a cert, the cert */
	if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		{
		RESOURCE_DATA msgData;
		BYTE keyID[ KEYID_SIZE ];

		/* Check that the key in the cert and the key in the sig.check object 
		   are identical */
		setMessageData( &msgData, keyID, KEYID_SIZE );
		status = krnlSendMessage( sigCheckKey, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( certInfoPtr->objectHandle, 
									  IMESSAGE_COMPARE, &msgData,
									  MESSAGE_COMPARE_KEYID );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_VALUE );

		/* If the sig.check object is a cert (even though what's being 
		   checked is already a self-signed cert), check that it's identical 
		   to the cert being checked (which it must be if the cert is self-
		   signed).  This may be somewhat stricter than required, but it'll 
		   weed out technically valid but questionable combinations like a 
		   cert request being used to validate a cert and misleading ones 
		   such as one cert chain being used to check a second chain */
		if( type == OBJECT_TYPE_CERTIFICATE )
			{
			status = krnlSendMessage( certInfoPtr->objectHandle, 
									  IMESSAGE_COMPARE, ( void * ) &sigCheckKey, 
									  MESSAGE_COMPARE_CERTOBJ );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_VALUE );
			}

		/* If it's a cert chain, it's a (complex) self-signed object 
		   containing more than one cert so we need a special function to check 
		   the entire chain */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );

		/* Check the signer details and signature.  Issuer and subject cert 
		   info is the same, since it's a self-signed cert */
		status = checkCert( certInfoPtr, certInfoPtr, FALSE,
							&certInfoPtr->errorLocus,
							&certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		if( ( certInfoPtr->flags & CERT_FLAG_SIGCHECKED ) || \
			cryptStatusOK( \
				krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE,
								 &certInfoPtr->objectHandle, 
								 CRYPT_IATTRIBUTE_CERT_CHECKTRUST ) ) )
			/* We've already checked the signature or it's an implicitly 
			   trusted cert, we don't have to go any further */
			return( CRYPT_OK );
		status = checkX509signature( certInfoPtr->certificate, 
									 certInfoPtr->certificateSize, NULL, NULL,
									 certInfoPtr->iPubkeyContext, formatInfo );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_NUM1 ) ? \
					CRYPT_ARGERROR_OBJECT : status );
		certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;
		return( CRYPT_OK );
		}

	/* The signature check key may be a certificate or a context.  If it's 
	   a cert, we get the issuer cert info and extract the context from it 
	   before continuing */
	if( type == OBJECT_TYPE_CERTIFICATE )
		{
		/* Get the context from the issuer certificate */
		status = krnlSendMessage( sigCheckKey, IMESSAGE_GETDEPENDENT, 
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
					CRYPT_ARGERROR_VALUE : status );

		/* Get the issuer certificate info */
		status = krnlGetObject( sigCheckKey, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &issuerCertInfoPtr, 
								CRYPT_ARGERROR_VALUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		CRYPT_CERTIFICATE localCert;

		iCryptContext = sigCheckKey;

		/* It's a context, we may have a certificate present in it so we try 
		   to extract that and use it as the issuer certificate if possible.  
		   If the issuer cert isn't present this isn't an error, since it 
		   could be just a raw context */
		status = krnlSendMessage( sigCheckKey, IMESSAGE_GETDEPENDENT,
								  &localCert, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			status = krnlGetObject( localCert, OBJECT_TYPE_CERTIFICATE, 
									( void ** ) &issuerCertInfoPtr, 
									CRYPT_ARGERROR_VALUE );
		if( cryptStatusError( status ) )
			/* There's no issuer cert present, all we can do is perform a 
			   pure signature check using the context */
			issuerCertInfoPtr = NULL;
		}

	/* If there's an issuer certificate present, check the validity of the
	   subject cert based on it */
	if( issuerCertInfoPtr != NULL )
		{
		status = checkCert( certInfoPtr, issuerCertInfoPtr, FALSE,
							&certInfoPtr->errorLocus,
							&certInfoPtr->errorType );
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check the signature */
	if( ( certInfoPtr->flags & CERT_FLAG_SIGCHECKED ) || \
		cryptStatusOK( \
			krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE,
							 &certInfoPtr->objectHandle, 
							 CRYPT_IATTRIBUTE_CERT_CHECKTRUST ) ) )
		/* We've already checked the signature or it's an implicitly 
		   trusted cert, we don't have to go any further */
		return( CRYPT_OK );
	status = checkX509signature( certInfoPtr->certificate, 
								 certInfoPtr->certificateSize, NULL, NULL, 
								 iCryptContext, formatInfo );
	if( cryptStatusOK( status ) )
		/* The signature is OK, we don't need to check it again */
		certInfoPtr->flags |= CERT_FLAG_SIGCHECKED;
	else
		if( status == CRYPT_ARGERROR_NUM1 )
			status = CRYPT_ARGERROR_VALUE;
	return( status );
	}
