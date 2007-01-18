/****************************************************************************
*																			*
*								Write CMP Messages							*
*						Copyright Peter Gutmann 1999-2003					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

/* The CMP message header includes a large amount of ambiguous, confusing, 
   and redundant information, we remove all the unnecessary junk required by 
   CMP by only sending the fields that are actually useful.  Fields that are 
   completely pointless or can't be provided (sender and recipient DN, 
   nonces) are omitted entirely, fields that remain static throughout an 
   exchange (user ID info) are only sent in the first message and are 
   assumed to be the same as for the previous message if absent.  The 
   general schema for message fields during various sample exchanges is:

	ir:		transID	userID-user	mac-param	clibID
	ip:		transID				mac			clibID

	cr:		transID				sig			clibID	certID-user
	cp:		transID				sig			clibID	certID-CA

	ir:		transID	userID-user	mac-param	clibID
	ip:		transID				mac			clibID
	ir:		transID				mac
	ip:		transID				mac

	ir:		transID	userID-user	mac-param	clibID
	ip:		transID				mac			clibID
	cr:		transID				sig					certID-user
	cp:		transID				sig					certID-CA

	genm:	transID	userID-user	mac-param	clibID
	genp:	transID				mac			clibID	certID-CA
	ir:		transID				mac
	ip:		transID				mac
	cr:		transID				sig					certID-user
	cp:		transID				sig

   The transID (= nonce) is sent in all messages.  The user ID, cert ID, 
   and MAC parameters are sent once, if absent they're assumed to be "same 
   as previous" (in the case of the MAC parameters we simply send the MAC
   OID with NULL parameters to indicate no change).  The cryptlib ID is sent 
   in the first message only.

   The sending of the CA cert ID in the PKIBoot response even though the 
   response is MAC'd is necessary because we need this value to identify 
   which of the certs in the CTL is the CA/RA cert to be used for further 
   exchanges.  There are actually several ways in which we can identify 
   the cert:

	1. PKIBoot response is a CTL, CA cert is implicitly trusted (via the CTL).

		Issues: Mostly an implementation issue, we need to provide a CA cert 
		when we activate the session, not having this requires special-case 
		handling in the CMP startup code to check for an implicitly-trusted
		cert if a CA cert isn't explicitly provided.  In addition there 
		currently isn't a means of fetching a trusted cert based on its cert 
		ID, only of querying whether a cert is trusted or fetching a trusted 
		issuer cert for an existing cert.

	2. PKIBoot response is a CTL, userID identifies the CA cert.

		Issues: The userID is probably only meant to identify the 
		authenticator of the message (the spec is, as usual, unclear on 
		this), not a random cert located elsewhere.

	3. PKIBoot response is a CTL, certID identifies the CA cert.

		Issues: A less serious version of (2) above, we're overloading the 
		certID to some extent but since it doesn't affect CMP messages as a
		whole (as overloading the userID would) this is probably OK.	

	4. PKIBoot response is SignedData, signer is CA cert.

		Issues: Mostly nitpicks, we should probably only be sending a pure 
		CTL rather than signed data, and the means of identifying the CA 
		cert seems a bit clunky.  On one hand it provides POP of the CA key 
		at the PKIBoot stage, but on the other it requires a signing 
		operation for every PKIBoot exchange, which can get rather 
		heavyweight if clients use it in a DHCP-like manner every time they
		start up.  In addition it requires a general-purpose signature-
		capable CA key, which often isn't the case if it's reserved 
		specifically for cert and CRL signing.

   Enabling the following define forces the use of full headers at all times.
   cryptlib always sends minimal headers once it detects that the other side 
   is using cryptlib, ommitting as much of the unnecessary junk as possible, 
   which significantly reduces the overall message size */

/* #define USE_FULL_HEADERS */

/* Prototypes for functions in lib_sign.c */

int createRawSignature( void *signature, int *signatureLength,
						const int sigMaxLength, 
						const CRYPT_CONTEXT iSignContext,
						const CRYPT_CONTEXT iHashContext );

#ifdef USE_CMP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Write full cert ID info.  This is written as an attribute in the
   generalInfo field of the message header to allow unambiguous
   identification of the signing cert, which the standard CMP format can't
   do.  Although CMP uses a gratuitously incompatible definition of the
   standard attribute type (calling it InfoTypeAndValue), it's possible to
   shoehorn a standard attribute type in by taking the "ANY" in "ANY DEFINED
   BY x" to mean "SET OF AttributeValue" (for once the use of obsolete ASN.1
   is a help, since it's so imprecise that we can shovel in anything and it's
   still valid):

	SigningCertificate ::=  SEQUENCE {
		certs			SEQUENCE OF ESSCertID	-- Size (1)
		}

	ESSCertID ::= SEQUENCE {
		certID			OCTET STRING
		}

   All we really need is the cert ID, so instead of writing a full ESSCertID
   (which also contains an optional incompatible reinvention of the CMS
   IssuerAndSerialNumber) we write the sole mandatory field, the cert hash,
   which also keeps the overall size down */

static int writeCertID( STREAM *stream, const CRYPT_CONTEXT iCryptCert )
	{
	MESSAGE_DATA msgData;
	BYTE certHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int essCertIDSize, payloadSize, status;

	/* Find out how big the payload will be */
	setMessageData( &msgData, certHash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusError( status ) )
		return( status );
	essCertIDSize = ( int ) sizeofObject( msgData.length );
	payloadSize = objSize( objSize( objSize( essCertIDSize ) ) );

	/* If we've been passed a null stream, it's a size request only */
	if( stream == NULL )
		return( objSize( sizeofOID( OID_ESS_CERTID ) + \
						 sizeofObject( payloadSize ) ) );

	/* Write the signing cert ID info */
	writeSequence( stream, sizeofOID( OID_ESS_CERTID ) + \
						   ( int ) sizeofObject( payloadSize ) );
	writeOID( stream, OID_ESS_CERTID );
	writeSet( stream, payloadSize );
	writeSequence( stream, objSize( objSize( essCertIDSize ) ) );
	writeSequence( stream, objSize( essCertIDSize ) );
	writeSequence( stream, essCertIDSize );
	return( writeOctetString( stream, certHash, msgData.length, 
							  DEFAULT_TAG ) );
	}

/* Write PKIStatus information:

	PKIStatusInfo ::= SEQUENCE {
		status			INTEGER,
		statusString	SEQUENCE OF UTF8String OPTIONAL,
		failInfo		BIT STRING OPTIONAL
		} */

static int writePkiStatusInfo( STREAM *stream, const int pkiStatus,
							   const long pkiFailureInfo )
	{
	const long localPKIFailureInfo = \
		( pkiFailureInfo != CMPFAILINFO_OK ) ? pkiFailureInfo : \
		( pkiStatus == CRYPT_ERROR_NOTAVAIL ) ? CMPFAILINFO_BADALG : \
		( pkiStatus == CRYPT_ERROR_SIGNATURE ) ? CMPFAILINFO_BADMESSAGECHECK :	\
		( pkiStatus == CRYPT_ERROR_PERMISSION ) ? CMPFAILINFO_BADREQUEST :	\
		( pkiStatus == CRYPT_ERROR_BADDATA ) ? CMPFAILINFO_BADDATAFORMAT :	\
		( pkiStatus == CRYPT_ERROR_INVALID ) ? CMPFAILINFO_BADCERTTEMPLATE : \
		( pkiStatus == CRYPT_ERROR_DUPLICATE ) ? CMPFAILINFO_DUPLICATECERTREQ : \
		( pkiStatus == CRYPT_ERROR_WRONGKEY ) ? CMPFAILINFO_SIGNERNOTTRUSTED : \
		0;
	const int length = \
			sizeofShortInteger( PKISTATUS_REJECTED ) + \
			( localPKIFailureInfo ? sizeofBitString( localPKIFailureInfo ) : 0 );
	int status;

	/* If we've been passed a null stream, it's a size request only */
	if( stream == NULL )
		return( objSize( length ) );

	/* Write the error status info.  If there's a specific failure info code
	   set by the caller we use that, otherwise we try and convert the
	   cryptlib status into an appropriate failure info value */
	writeSequence( stream, length );
	status = writeShortInteger( stream, PKISTATUS_REJECTED, DEFAULT_TAG );
	if( localPKIFailureInfo )
		status = writeBitString( stream, localPKIFailureInfo, DEFAULT_TAG );
	return( status );
	}

/* Write the CMP/Entrust MAC information:

	macInfo ::= SEQUENCE {
		algoID			OBJECT IDENTIFIER (entrustMAC),
		algoParams		SEQUENCE {
			salt		OCTET STRING,
			pwHashAlgo	AlgorithmIdentifier (SHA-1)
			iterations	INTEGER,
			macAlgo		AlgorithmIdentifier (HMAC-SHA1)
			} OPTIONAL
		} */

static int writeMacInfo( STREAM *stream,
						 const CMP_PROTOCOL_INFO *protocolInfo,
						 const BOOLEAN parametersSent )
	{
	int paramSize;

	/* If we've already sent the MAC parameters in an earlier transaction,
	   just send an indication that we're using MAC protection */
	if( parametersSent )
		{
		writeSequence( stream, sizeofOID( OID_ENTRUST_MAC ) + sizeofNull() );
		writeOID( stream, OID_ENTRUST_MAC );
		return( writeNull( stream, DEFAULT_TAG ) );
		}

	/* Determine how big the payload will be */
	paramSize = ( int ) sizeofObject( protocolInfo->saltSize ) + \
				sizeofAlgoID( CRYPT_ALGO_SHA ) + \
				sizeofShortInteger( CMP_PASSWORD_ITERATIONS ) + \
				sizeofAlgoID( CRYPT_ALGO_HMAC_SHA );

	/* Write the wrapper */
	writeSequence( stream, sizeofOID( OID_ENTRUST_MAC ) + \
						   ( int ) sizeofObject( paramSize ) );
	writeOID( stream, OID_ENTRUST_MAC );

	/* Write the payload */
	writeSequence( stream, paramSize );
	writeOctetString( stream, protocolInfo->salt, protocolInfo->saltSize,
					  DEFAULT_TAG );
	writeAlgoID( stream, CRYPT_ALGO_SHA );
	writeShortInteger( stream, CMP_PASSWORD_ITERATIONS, DEFAULT_TAG );
	return( writeAlgoID( stream, CRYPT_ALGO_HMAC_SHA ) );
	}

/****************************************************************************
*																			*
*								PKI Body Functions							*
*																			*
****************************************************************************/

/* Write request body */

static int writeRequestBody( STREAM *stream,
							 const SESSION_INFO *sessionInfoPtr,
							 const CMP_PROTOCOL_INFO *protocolInfo )
	{
	const CRYPT_CERTFORMAT_TYPE certType = \
				( protocolInfo->operation == CTAG_PB_RR ) ? \
				CRYPT_ICERTFORMAT_DATA : CRYPT_CERTFORMAT_CERTIFICATE;
	MESSAGE_DATA msgData;
	int status;

	UNUSED( protocolInfo );

	/* Find out how big the payload will be.  Since revocation requests are
	   unsigned entities we have to vary the attribute type that we're 
	   reading based on whether we're submitting a signed or unsigned object 
	   in the request */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData, certType );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the request body */
	writeConstructed( stream, objSize( msgData.length ),
					  protocolInfo->operation );
	writeSequence( stream, msgData.length );
	return( exportCertToStream( stream, sessionInfoPtr->iCertRequest, 
								certType ) );
	}

/* Write response body.  If we're returning an encryption-only cert, we send 
   it as standard CMS data under a new tag to avoid having to hand-assemble 
   the garbled mess that CMP uses for this */

static int writeResponseBody( STREAM *stream,
							  const SESSION_INFO *sessionInfoPtr,
							  const CMP_PROTOCOL_INFO *protocolInfo )
	{
	MESSAGE_DATA msgData;
	const int startPos = stell( stream );
	int payloadSize = sizeofShortInteger( 0 ), dataLength, status;

	UNUSED( protocolInfo );

	/* Find out how big the payload will be */
	if( protocolInfo->operation != CTAG_PB_RR )
		{
		/* If it's an encryption-only key we return the cert in encrypted
		   form.  The client performs POP by decrypting the returned cert */
		if( protocolInfo->cryptOnlyKey )
			{
			void *bufPtr = sMemBufPtr( stream ) + 100;
			int bufSize = sMemDataLeft( stream ) - 100;

			/* Extract the response data into the session buffer and wrap 
			   it in the standard format using the client's cert.  Since the 
			   client doesn't actually have the cert yet (only we have it, 
			   since it's only just been issued), we have to use the S/MIME 
			   v3 format (keys identified by key ID rather than 
			   issuerAndSerialNumber) because the client won't know its
			   iAndS until it decrypts the cert */
			setMessageData( &msgData, bufPtr, bufSize );
			status = krnlSendMessage( sessionInfoPtr->iCertResponse,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusOK( status ) )
				status = envelopeWrap( bufPtr, msgData.length, 
									   bufPtr, &dataLength, bufSize,
									   CRYPT_FORMAT_CRYPTLIB, 
									   CRYPT_CONTENT_NONE, 
									   sessionInfoPtr->iCertResponse );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			/* If it's a signature-capable key, return it in standard form */
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( sessionInfoPtr->iCertResponse,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			dataLength = msgData.length;
			}
		payloadSize += objSize( sizeofShortInteger( 0 ) ) + \
					   objSize( objSize( dataLength ) );
		}

	/* Write the response body wrapper */
	writeConstructed( stream, objSize( objSize( objSize( payloadSize ) ) ),
					  reqToResp( protocolInfo->operation ) );
	writeSequence( stream, objSize( objSize( payloadSize ) ) );

	/* Write the response.  We always write an OK status here because an
	   error will have been communicated by sending an explicit error
	   response */
	writeSequence( stream, objSize( payloadSize ) );
	writeSequence( stream, payloadSize );
	if( protocolInfo->operation != CTAG_PB_RR )
		{
		writeShortInteger( stream, 0, DEFAULT_TAG );
		writeSequence( stream, sizeofShortInteger( 0 ) );
		}
	status = writeShortInteger( stream, PKISTATUS_OK, DEFAULT_TAG );
	if( protocolInfo->operation == CTAG_PB_RR )
		/* If it's a revocation request, there's no data included in the
		   response */
		return( status );

	/* Write the cert data, either as a standard cert or as CMS encrypted 
	   data if the request was for an encryption-only cert */
	writeSequence( stream, objSize( dataLength ) );
	if( protocolInfo->cryptOnlyKey )
		{
		BYTE *bufPtr;

		assert( startPos + 100 - stell( stream ) > 0 );
		writeConstructed( stream, dataLength, CTAG_CK_NEWENCRYPTEDCERT );
		bufPtr = sMemBufPtr( stream );
		memmove( bufPtr, bufPtr + startPos + 100 - stell( stream ), 
				 dataLength );
		return( sSkip( stream, dataLength ) );
		}
	writeConstructed( stream, dataLength, CTAG_CK_CERT );
	return( exportCertToStream( stream, sessionInfoPtr->iCertResponse, 
								CRYPT_CERTFORMAT_CERTIFICATE ) );
	}

/* Write conf body */

static int writeConfBody( STREAM *stream,
						  const SESSION_INFO *sessionInfoPtr,
						  const CMP_PROTOCOL_INFO *protocolInfo )
	{
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int length, status;

	/* Get the certificate hash */
	setMessageData( &msgData, hashBuffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
						IMESSAGE_GETATTRIBUTE_S, &msgData,
						( protocolInfo->confHashAlgo == CRYPT_ALGO_SHA ) ? \
							CRYPT_CERTINFO_FINGERPRINT_SHA : \
							CRYPT_CERTINFO_FINGERPRINT_MD5 );
	if( cryptStatusError( status ) )
		return( status );
	length = ( int ) objSize( msgData.length ) + sizeofShortInteger( 0 );

	/* Write the confirmation body */
	writeConstructed( stream, objSize( objSize( length ) ),
					  CTAG_PB_CERTCONF );
	writeSequence( stream, objSize( length ) );
	writeSequence( stream, length );
	writeOctetString( stream, hashBuffer, msgData.length, DEFAULT_TAG );
	return( writeShortInteger( stream, 0, DEFAULT_TAG ) );
	}

/* Write genMsg body */

static int writeGenMsgBody( STREAM *stream,
							SESSION_INFO *sessionInfoPtr,
							const CMP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCTL;
	MESSAGE_DATA msgData;
	int status;

	UNUSED( protocolInfo );

	/* Get the CTL from the CA object.  We recreate this each time rather 
	   than cacheing it in the session to ensure that changes in the trusted
	   cert set while the session is active get reflected back to the 
	   caller.
	   
	   In addition to the explicitly trusted certs, we also include the CA 
	   cert(s) in the CTL as implicitly-trusted certs.  This is done both
	   because users often forget to mark them as trusted on the server and 
	   then wonder where their CA certs are on the client, and because these 
	   should inherently be trusted, since the user is about to get their 
	   certs issued by them */
	status = krnlSendMessage( sessionInfoPtr->ownerHandle,
							  IMESSAGE_GETATTRIBUTE, &iCTL,
							  CRYPT_IATTRIBUTE_CTL );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCTL, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &sessionInfoPtr->privateKey,
							  CRYPT_IATTRIBUTE_CERTCOLLECTION );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCTL, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_CERTFORMAT_CERTCHAIN );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCTL, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Write the response body wrapper.  As with the cert ID, we can use the
	   imprecision of the ASN.1 that CMP is specified in to interpret the
	   InfoTypeAndValue:

		InfoTypeAndValue ::= SEQUENCE {
			infoType	OBJECT IDENTIFIER,
			infoValue	ANY DEFINED BY infoType OPTIONAL
			}

	   as:

		infoType ::= id-signedData
		infoValue ::= [0] EXPLICIT SignedData

	   which makes it standard CMS data that can be passed directly to the 
	   CMS code */
	writeConstructed( stream, objSize( msgData.length ), CTAG_PB_GENP );
	writeSequence( stream, msgData.length );
	status = exportCertToStream( stream, iCTL, CRYPT_CERTFORMAT_CERTCHAIN );
	krnlSendNotifier( iCTL, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Write error body */

static int writeErrorBody( STREAM *stream,
						   const CMP_PROTOCOL_INFO *protocolInfo )
	{
	const int length = writePkiStatusInfo( NULL, protocolInfo->status,
										   protocolInfo->pkiFailInfo );

	/* Write the error body.  We don't write the error text string because
	   it reveals too much about the internal operation of the CA, some of 
	   which may aid an attacker */
	writeConstructed( stream, objSize( length ), CTAG_PB_ERROR );
	writeSequence( stream, length );
	return( writePkiStatusInfo( stream, protocolInfo->status,
								protocolInfo->pkiFailInfo ) );
	}

/****************************************************************************
*																			*
*								Write a PKI Header							*
*																			*
****************************************************************************/

/* Write a PKI header.  Fields marked with a * are redundant and are only 
   sent when we're not sending minimal headers.  Fields marked with a + are
   only sent in the first message or when not sending minimal headers:

	header				SEQUENCE {
		version			INTEGER (2),
	   *sender		[4]	EXPLICIT DirectoryName,	-- DN of initiator
	   *recipient	[4]	EXPLICIT DirectoryName,	-- DN of responder
		protAlgo	[1]	EXPLICIT AlgorithmIdentifier,
	   +protKeyID	[2] EXPLICIT OCTET STRING,
		transID		[4] EXPLICIT OCTET STRING SIZE (16),-- Random/copied from sender
	   *nonce		[5] EXPLICIT OCTET STRING SIZE (16),-- Random
	   *nonceX		[6] EXPLICIT OCTET STRING SIZE (n),	-- Copied from sender
		generalInfo	[8] EXPLICIT SEQUENCE OF Info OPT	-- cryptlib-specific info
		} */

static int writePkiHeader( STREAM *stream, SESSION_INFO *sessionInfoPtr,
						   CMP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_HANDLE senderNameObject = isServer( sessionInfoPtr ) ? \
				sessionInfoPtr->privateKey : \
									protocolInfo->cryptOnlyKey ? \
				sessionInfoPtr->iAuthOutContext : \
				sessionInfoPtr->iCertRequest;
	const CRYPT_HANDLE recipNameObject = isServer( sessionInfoPtr ) ? \
			sessionInfoPtr->iCertResponse : sessionInfoPtr->iAuthInContext;
	STREAM nullStream;
	MESSAGE_DATA msgData;
#ifdef USE_FULL_HEADERS
	const BOOLEAN useFullHeader = TRUE;
#else
	const BOOLEAN useFullHeader = !( protocolInfo->isCryptlib || \
									 protocolInfo->operation == CTAG_PB_GENM );
			/* Send a minimal header if the other side is cryptlib or if 
			   we're doing PKIBoot, for which we couldn't send full headers 
			   if we wanted to */
#endif /* USE_MINIMAL_HEADERS */
	BOOLEAN sendClibID = FALSE, sendCertID = FALSE;
	int senderNameLength = 0, recipNameLength = 0, attributeLength = 0;
	int protInfoLength, totalLength, status;

	assert( !useFullHeader || protocolInfo->userIDsize > 0 );

	krnlSendMessage( sessionInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE, 
					 &protocolInfo->hashAlgo, CRYPT_OPTION_ENCR_HASH );

	/* Determine how big the sender and recipient info will be.  We 
	   shouldn't need to send a recipient name for an ir because it won't
	   usually be known yet, but various implementations can't handle a zero-
	   length GeneralName, so we supply it if it's available even though it's 
	   redundant */
	if( useFullHeader )
		{
		/* Get the sender DN info */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( senderNameObject, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
		if( status == CRYPT_ERROR_NOTFOUND && !isServer( sessionInfoPtr ) && \
			protocolInfo->operation == CTAG_PB_IR )
			{
			/* If there's no subject DN present and it's the first message 
			   in a client's ir exchange, this isn't an error because the 
			   subject may not know their DN yet (at least that's the 
			   theory, most servers will reject a message with no sender 
			   name) */
			if( sessionInfoPtr->iCertResponse == CRYPT_ERROR )
				{
				senderNameObject = CRYPT_ERROR;
				msgData.length = ( int ) sizeofObject( 0 );
				status = CRYPT_OK;
				}
			else
				{
				/* Try again with the response from the server, which 
				   contains our newly-allocated DN */
				senderNameObject = sessionInfoPtr->iCertResponse;
				status = krnlSendMessage( senderNameObject,
										  IMESSAGE_GETATTRIBUTE_S, &msgData,
										  CRYPT_IATTRIBUTE_SUBJECT );
				}
			}
		if( cryptStatusError( status ) )
			return( status );
		senderNameLength = msgData.length;

		/* Get the recipient DN info */
		setMessageData( &msgData, NULL, 0 );
		if( recipNameObject != CRYPT_ERROR )
			status = krnlSendMessage( recipNameObject,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_SUBJECT );
		else
			/* If we're sending an error response there may not be any 
			   recipient name information present yet if the error occurred 
			   before the recipient information could be established, and if 
			   this is a MAC-authenticated PKIBoot we don't have the CA's 
			   cert yet so we don't know its DN.  To work around this we 
			   send a zero-length DN (this is one of those places where an 
			   optional field is specified as being mandatory, to lend 
			   balance to the places where mandatory fields are specified as 
			   optional) */
			msgData.length = ( int ) sizeofObject( 0 );
		if( cryptStatusError( status ) )
			return( status );
		recipNameLength = msgData.length;
		}

	/* Determine how big the remaining header data will be */
	sMemOpen( &nullStream, NULL, 0 );
	if( protocolInfo->useMACsend )
		writeMacInfo( &nullStream, protocolInfo, 
					  sessionInfoPtr->protocolFlags & CMP_PFLAG_MACINFOSENT );
	else
		writeContextAlgoID( &nullStream, protocolInfo->authContext, 
							protocolInfo->hashAlgo, 
							ALGOID_FLAG_ALGOID_ONLY );
	protInfoLength = stell( &nullStream );
	sMemClose( &nullStream );
	if( !( sessionInfoPtr->protocolFlags & CMP_PFLAG_CLIBIDSENT ) )
		{
		attributeLength += sizeofObject( \
								sizeofOID( OID_CRYPTLIB_PRESENCECHECK ) + \
								sizeofObject( 0 ) );
		sendClibID = TRUE;
		}
	if( !( sessionInfoPtr->protocolFlags & CMP_PFLAG_CERTIDSENT ) && \
		( ( isServer( sessionInfoPtr ) && \
			protocolInfo->operation == CTAG_PB_GENM ) || \
		  !protocolInfo->useMACsend ) )
		{
		attributeLength += writeCertID( NULL, protocolInfo->authContext );
		sendCertID = TRUE;
		}
	totalLength = sizeofShortInteger( CMP_VERSION ) + \
				  objSize( senderNameLength ) + objSize( recipNameLength ) + \
				  objSize( protInfoLength );
	if( protocolInfo->transIDsize > 0 )
		totalLength += objSize( sizeofObject( protocolInfo->transIDsize ) );
	if( useFullHeader || \
		!( sessionInfoPtr->protocolFlags & CMP_PFLAG_USERIDSENT ) )
		totalLength += objSize( sizeofObject( protocolInfo->userIDsize ) );
	if( useFullHeader )
		totalLength += ( protocolInfo->senderNonceSize > 0 ? \
						 objSize( sizeofObject( protocolInfo->senderNonceSize ) ) : 0 ) + \
					   ( protocolInfo->recipNonceSize > 0 ? \
						 objSize( sizeofObject( protocolInfo->recipNonceSize ) ) : 0 );
	if( attributeLength > 0 )
		totalLength += objSize( objSize( attributeLength ) );
	if( sizeofObject( totalLength ) > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Write the PKI header wrapper, version info, and sender and recipient
	   names if there's name information present */
	writeSequence( stream, totalLength );
	writeShortInteger( stream, CMP_VERSION, DEFAULT_TAG );
	if( useFullHeader )
		{
		writeConstructed( stream, senderNameLength, 4 );
		if( senderNameObject != CRYPT_ERROR )
			{
			status = exportAttributeToStream( stream, senderNameObject, 
											  CRYPT_IATTRIBUTE_SUBJECT );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			writeSequence( stream, 0 );
		writeConstructed( stream, recipNameLength, 4 );
		if( recipNameObject != CRYPT_ERROR )
			{
			status = exportAttributeToStream( stream, recipNameObject, 
											  CRYPT_IATTRIBUTE_SUBJECT );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			writeSequence( stream, 0 );
		}
	else
		{
		/* This is one of the portions of CMP where an optional field is 
		   marked as mandatory, to balance out the mandatory fields that are 
		   marked as optional.  To work around this, we write the names as 
		   zero-length DNs */
		writeConstructed( stream, 0, 4 );
		writeConstructed( stream, 0, 4 );
		}

	/* Write the protection info, assorted nonces and IDs, and extra
	   information that the other side may be able to make use of */
	writeConstructed( stream, protInfoLength, CTAG_PH_PROTECTIONALGO );
	if( protocolInfo->useMACsend )
		{
		writeMacInfo( stream, protocolInfo, 
					  sessionInfoPtr->protocolFlags & CMP_PFLAG_MACINFOSENT );
		sessionInfoPtr->protocolFlags |= CMP_PFLAG_MACINFOSENT;
		}
	else
		writeContextAlgoID( stream, protocolInfo->authContext, 
							protocolInfo->hashAlgo, 
							ALGOID_FLAG_ALGOID_ONLY );
	if( useFullHeader || \
		!( sessionInfoPtr->protocolFlags & CMP_PFLAG_USERIDSENT ) )
		{
		/* We're using full headers or we're the client sending our first
		   message, identify the sender key */
		writeConstructed( stream, objSize( protocolInfo->userIDsize ),
						  CTAG_PH_SENDERKID );
		writeOctetString( stream, protocolInfo->userID,
						  protocolInfo->userIDsize, DEFAULT_TAG );
		sessionInfoPtr->protocolFlags |= CMP_PFLAG_USERIDSENT;
		}
	if( protocolInfo->transIDsize > 0 )
		{
		/* If we're sending an error response to an initial message that we 
		   couldn't even start to parse, the transaction ID won't be present
		   yet so we only send this if it's present */
		writeConstructed( stream, objSize( protocolInfo->transIDsize ),
						  CTAG_PH_TRANSACTIONID );
		status = writeOctetString( stream, protocolInfo->transID,
								   protocolInfo->transIDsize, DEFAULT_TAG );
		}
	if( useFullHeader )
		{
		if( protocolInfo->senderNonceSize > 0 )
			{
			writeConstructed( stream, 
							  objSize( protocolInfo->senderNonceSize ),
							  CTAG_PH_SENDERNONCE );
			status = writeOctetString( stream, protocolInfo->senderNonce,
									   protocolInfo->senderNonceSize, 
									   DEFAULT_TAG );
			}
		if( protocolInfo->recipNonceSize > 0 )
			{
			writeConstructed( stream, 
							  objSize( protocolInfo->recipNonceSize ),
							  CTAG_PH_RECIPNONCE );
			status = writeOctetString( stream, protocolInfo->recipNonce,
									   protocolInfo->recipNonceSize, 
									   DEFAULT_TAG );
			}
		}
	if( attributeLength > 0 )
		{
		assert( sendClibID || sendCertID );

		/* We haven't sent any messages yet, let the other side know that 
		   we're running cryptlib and identify our signing cert */
		writeConstructed( stream, objSize( attributeLength ),
						  CTAG_PH_GENERALINFO );
		status = writeSequence( stream, attributeLength );
		if( sendClibID )
			{
			writeSequence( stream, sizeofOID( OID_CRYPTLIB_PRESENCECHECK ) + \
								   sizeofObject( 0 ) );
			writeOID( stream, OID_CRYPTLIB_PRESENCECHECK );
			status = writeSet( stream, 0 );
			sessionInfoPtr->protocolFlags |= CMP_PFLAG_CLIBIDSENT;
			}
		if( sendCertID )
			{
			status = writeCertID( stream, protocolInfo->authContext );
			sessionInfoPtr->protocolFlags |= CMP_PFLAG_CERTIDSENT;
			}
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Write a PKI Message								*
*																			*
****************************************************************************/

/* Write a PKI message:

	PkiMessage ::= SEQUENCE {
		header			PKIHeader,
		body			CHOICE { [0]... [24]... },
		protection	[0]	BIT STRING
		} */

int writePkiMessage( SESSION_INFO *sessionInfoPtr,
					 CMP_PROTOCOL_INFO *protocolInfo,
					 const CMPBODY_TYPE bodyType )
	{
	BYTE protInfo[ 64 + MAX_PKCENCRYPTED_SIZE + 8 ], headerBuffer[ 8 + 8 ];
	STREAM stream;
	int headerSize, protInfoSize, status;

	/* Write the header and payload so that we can MAC/sign it */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer,
			  sessionInfoPtr->receiveBufSize );
	status = writePkiHeader( &stream, sessionInfoPtr, protocolInfo );
	if( cryptStatusOK( status ) )
		{
		switch( bodyType )
			{
			case CMPBODY_NORMAL:
				if( isServer( sessionInfoPtr ) )
					status = writeResponseBody( &stream, sessionInfoPtr,
												protocolInfo );
				else
					status = writeRequestBody( &stream, sessionInfoPtr,
											   protocolInfo );
				break;

			case CMPBODY_CONFIRMATION:
				status = writeConfBody( &stream, sessionInfoPtr,
										protocolInfo );
				break;

			case CMPBODY_ACK:
				writeConstructed( &stream, objSize( sizeofNull() ),
								  CTAG_PB_PKICONF );
				writeSequence( &stream, sizeofNull() );
				status = writeNull( &stream, DEFAULT_TAG );
				break;

			case CMPBODY_GENMSG:
				if( isServer( sessionInfoPtr ) )
					status = writeGenMsgBody( &stream, sessionInfoPtr,
											  protocolInfo );
				else
					{
					writeConstructed( &stream,
							objSize( objSize( sizeofOID( OID_PKIBOOT ) ) ),
							CTAG_PB_GENM );
					writeSequence( &stream,
								   objSize( sizeofOID( OID_PKIBOOT ) ) );
					writeSequence( &stream, sizeofOID( OID_PKIBOOT ) );
					status = writeOID( &stream, OID_PKIBOOT );
					}
				break;

			case CMPBODY_ERROR:
				status = writeErrorBody( &stream, protocolInfo );
				break;

			default:
				assert( NOTREACHED );
			}
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}

	/* Generate the MAC or signature as appropriate */
	if( protocolInfo->useMACsend )
		{
		BYTE macValue[ CRYPT_MAX_HASHSIZE + 8 ];

		status = hashMessageContents( protocolInfo->iMacContext,
						sessionInfoPtr->receiveBuffer, stell( &stream ) );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_DATA msgData;

			setMessageData( &msgData, macValue, CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( protocolInfo->iMacContext,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_HASHVALUE );
			protInfoSize = msgData.length;
			}
		if( cryptStatusOK( status ) )
			{
			STREAM macStream;

			/* Write the MAC value with BIT STRING encapsulation */
			sMemOpen( &macStream, protInfo, 64 + MAX_PKCENCRYPTED_SIZE );
			writeBitStringHole( &macStream, protInfoSize, DEFAULT_TAG );
			swrite( &macStream, macValue, protInfoSize );
			protInfoSize = stell( &macStream );
			sMemDisconnect( &macStream );
			}
		}
	else
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Hash the data and create the signature */
		setMessageCreateObjectInfo( &createInfo, protocolInfo->hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			status = hashMessageContents( createInfo.cryptHandle,
						sessionInfoPtr->receiveBuffer, stell( &stream ) );
			if( cryptStatusOK( status ) )
				status = createRawSignature( protInfo, &protInfoSize,
											 sizeof( protInfo ),
											 protocolInfo->authContext,
											 createInfo.cryptHandle );
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			}
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}

	/* Attach the MAC/signature to the payload */
	writeConstructed( &stream, protInfoSize, CTAG_PM_PROTECTION );
	status = swrite( &stream, protInfo, protInfoSize );
	sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the wrapper and move it onto the front of the message */
	sMemOpen( &stream, headerBuffer, 8 );
	writeSequence( &stream, sessionInfoPtr->receiveBufEnd );
	headerSize = stell( &stream );
	sMemDisconnect( &stream );
	memmove( sessionInfoPtr->receiveBuffer + headerSize,
			 sessionInfoPtr->receiveBuffer,
			 sessionInfoPtr->receiveBufEnd );
	memcpy( sessionInfoPtr->receiveBuffer, headerBuffer, headerSize );
	sessionInfoPtr->receiveBufEnd += headerSize;

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
