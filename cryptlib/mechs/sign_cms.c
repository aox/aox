/****************************************************************************
*																			*
*								CMS Signature Routines						*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/* CMS version */

#define CMS_VERSION		1

/* The maximum size for the encoded CMS signed attributes */

#define ENCODED_ATTRIBUTE_SIZE	512

/* A structure to store CMS attribute information */

typedef struct {
	/* The format of the signature: Basic CMS or full S/MIME */
	CRYPT_FORMAT_TYPE formatType;

	/* Objects needed to create the attributes.  The time source is a device
	   associated with the signing key (usually the system device, but can
	   be a crypto device) used to obtain the signing time.  The TSP session
	   is an optional session that's used to timestamp the signature */
	CRYPT_CERTIFICATE iCmsAttributes;	/* CMS attributes */
	CRYPT_CONTEXT iMessageHash;			/* Hash for MessageDigest */
	CRYPT_HANDLE iTimeSource;			/* Time source for signing time */
	CRYPT_SESSION iTspSession;			/* Optional TSP session */

	/* The encoded attributes.  The encodedAttributes pointer is null if 
	   there are no attributes present, or points to the buffer containing 
	   the encoded attributes */
	BYTE *encodedAttributes, attributeBuffer[ ENCODED_ATTRIBUTE_SIZE + 8 ];
	int maxEncodedAttributeSize;

	/* Returned data: The size of the encoded attribute information in the
	   buffer */
	int encodedAttributeSize;
	} CMS_ATTRIBUTE_INFO;

#define initCmsAttributeInfo( attributeInfo, format, cmsAttributes, messageHash, timeSource, tspSession ) \
		memset( attributeInfo, 0, sizeof( CMS_ATTRIBUTE_INFO ) ); \
		( attributeInfo )->formatType = format; \
		( attributeInfo )->iCmsAttributes = cmsAttributes; \
		( attributeInfo )->iMessageHash = messageHash; \
		( attributeInfo )->iTimeSource = timeSource; \
		( attributeInfo )->iTspSession = tspSession; \
		( attributeInfo )->maxEncodedAttributeSize = ENCODED_ATTRIBUTE_SIZE;

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

/* Write CMS signer information:

	SignerInfo ::= SEQUENCE {
		version					INTEGER (1),
		issuerAndSerialNumber	IssuerAndSerialNumber,
		digestAlgorithm			AlgorithmIdentifier,
		signedAttrs		  [ 0 ]	IMPLICIT SET OF Attribute OPTIONAL,
		signatureAlgorithm		AlgorithmIdentifier,
		signature				OCTET STRING,
		unsignedAttrs	  [ 1 ]	IMPLICIT SET OF Attribute OPTIONAL
		} */

static int writeCmsSignerInfo( STREAM *stream,
							   const CRYPT_CERTIFICATE certificate,
							   const CRYPT_ALGO_TYPE hashAlgo,
							   const void *attributes, const int attributeSize,
							   const void *signature, const int signatureSize,
							   const CRYPT_HANDLE unsignedAttrObject )
	{
	MESSAGE_DATA msgData;
	DYNBUF iAndSDB;
	const int sizeofHashAlgoID = sizeofAlgoID( hashAlgo );
	int timeStampSize, unsignedAttributeSize = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( certificate ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( ( attributes == NULL && attributeSize == 0 ) || \
			isReadPtr( attributes, attributeSize ) );
	assert( isReadPtr( signature, signatureSize ) );
	assert( unsignedAttrObject == CRYPT_UNUSED || \
			isHandleRangeValid( unsignedAttrObject ) );

	if( cryptStatusError( sizeofHashAlgoID ) )
		return( sizeofHashAlgoID );

	/* Get the signerInfo information */
	if( unsignedAttrObject != CRYPT_UNUSED )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( unsignedAttrObject, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_TIMESTAMP );
		if( cryptStatusError( status ) )
			return( status );
		timeStampSize = msgData.length;
		unsignedAttributeSize = ( int ) \
						sizeofObject( sizeofOID( OID_TSP_TSTOKEN ) + \
									  sizeofObject( timeStampSize ) );
		}
	status = dynCreate( &iAndSDB, certificate,
						CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the outer SEQUENCE wrapper and version number */
	writeSequence( stream, sizeofShortInteger( CMS_VERSION ) + \
						   dynLength( iAndSDB ) + sizeofHashAlgoID + \
						   attributeSize + signatureSize + \
						   ( ( unsignedAttributeSize ) ? \
							 ( int ) sizeofObject( unsignedAttributeSize ) : 0 ) );
	writeShortInteger( stream, CMS_VERSION, DEFAULT_TAG );

	/* Write the issuerAndSerialNumber, digest algorithm identifier,
	   attributes (if there are any) and signature */
	swrite( stream, dynData( iAndSDB ), dynLength( iAndSDB ) );
	writeAlgoID( stream, hashAlgo );
	if( attributeSize > 0 )
		swrite( stream, attributes, attributeSize );
	status = swrite( stream, signature, signatureSize );
	dynDestroy( &iAndSDB );
	if( cryptStatusError( status ) || unsignedAttributeSize <= 0 )
		return( status );

	/* Write the unsigned attributes.  Note that the only unsigned attribute
	   in use at this time is a (not-quite) countersignature containing a
	   timestamp, so the following code always assumes that the attribute is
	   a timestamp.  First, we write the [1] IMPLICT SET OF attribute
	   wrapper */
	writeConstructed( stream, unsignedAttributeSize, 1 );
	writeSequence( stream, sizeofOID( OID_TSP_TSTOKEN ) + \
						   sizeofObject( timeStampSize ) );
	writeOID( stream, OID_TSP_TSTOKEN );
	writeSet( stream, timeStampSize );

	/* Copy the timestamp data directly into the stream */
	return( exportAttributeToStream( stream, unsignedAttrObject,
									 CRYPT_IATTRIBUTE_ENC_TIMESTAMP ) );
	}

/* Create a CMS countersignature */

static int createCmsCountersignature( const void *dataSignature,
									  const int dataSignatureSize,
									  const CRYPT_ALGO_TYPE hashAlgo,
									  const CRYPT_SESSION iTspSession )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	int length, status;

	assert( isReadPtr( dataSignature, dataSignatureSize ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( isHandleRangeValid( iTspSession ) );

	/* Hash the signature data to create the hash value to countersign.
	   The CMS spec requires that the signature is calculated on the
	   contents octets (in other words the V of the TLV) of the signature,
	   so we have to skip the signature algorithm and OCTET STRING wrapper */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
#if 1	/* Standard CMS countersignature */
	sMemConnect( &stream, dataSignature, dataSignatureSize );
	readUniversal( &stream );
	status = readOctetStringHole( &stream, &length, 16, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  sMemBufPtr( &stream ), length );
	sMemDisconnect( &stream );
#else	/* Broken TSP not-quite-countersignature */
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 ( void * ) dataSignature, dataSignatureSize );
#endif /* 1 */
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  "", 0 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iTspSession, IMESSAGE_SETATTRIBUTE,
								  &createInfo.cryptHandle,
								  CRYPT_SESSINFO_TSP_MSGIMPRINT );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Send the result to the TSA for countersigning */
	return( krnlSendMessage( iTspSession, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_TRUE, CRYPT_SESSINFO_ACTIVE ) );
	}

/****************************************************************************
*																			*
*							Create CMS Attributes 							*
*																			*
****************************************************************************/

/* Finalise processing of and hash the CMS attributes */

static int hashCmsAttributes( CMS_ATTRIBUTE_INFO *cmsAttributeInfo,
							  const CRYPT_CONTEXT iAttributeHash,
							  const BOOLEAN lengthCheckOnly )
	{
	MESSAGE_DATA msgData;
	BYTE temp, hash[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isWritePtr( cmsAttributeInfo, sizeof( CMS_ATTRIBUTE_INFO ) ) );
	assert( isHandleRangeValid( cmsAttributeInfo->iCmsAttributes ) );
	assert( isHandleRangeValid( cmsAttributeInfo->iMessageHash ) );
	assert( isWritePtr( cmsAttributeInfo->encodedAttributes, \
						cmsAttributeInfo->maxEncodedAttributeSize ) );
	assert( isHandleRangeValid( iAttributeHash ) );

	/* Extract the message hash information and add it as a messageDigest
	   attribute, replacing any existing value if necessary.  If we're
	   doing a call just to get the length of the exported data, we use a
	   dummy hash value since the hashing may not have completed yet */
	krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
					 IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	if( lengthCheckOnly )
		status = krnlSendMessage( cmsAttributeInfo->iMessageHash, 
								  IMESSAGE_GETATTRIBUTE, &msgData.length, 
								  CRYPT_CTXINFO_BLOCKSIZE );
	else
		status = krnlSendMessage( cmsAttributeInfo->iMessageHash, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're creating the attributes for a real signature (rather than
	   just as part of a size check) and there's a reliable time source
	   present, use the time from that instead of the built-in system time */
	if( !lengthCheckOnly )
		{
		const time_t currentTime = \
				getReliableTime( cmsAttributeInfo->iTimeSource );

		if( currentTime > MIN_TIME_VALUE )
			{
			setMessageData( &msgData, ( void * ) &currentTime,
							sizeof( time_t ) );
			krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
							 IMESSAGE_DELETEATTRIBUTE, NULL,
							 CRYPT_CERTINFO_CMS_SIGNINGTIME );
			krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
							 IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_CERTINFO_CMS_SIGNINGTIME );
			}
		}

	/* Export the attributes into an encoded signedAttributes data block */
	if( lengthCheckOnly )
		{ setMessageData( &msgData, NULL, 0 ); }
	else
		{ 
		setMessageData( &msgData, cmsAttributeInfo->encodedAttributes,
						cmsAttributeInfo->maxEncodedAttributeSize );
		}
	status = krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		return( status );
	cmsAttributeInfo->encodedAttributeSize = msgData.length;

	/* If it's a length check, just generate a dummy hash value and exit */
	if( lengthCheckOnly )
		return( krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH, "", 0 ) );

	/* Replace the IMPLICIT [ 0 ] tag at the start with a SET OF tag to 
	   allow the attributes to be hashed, hash them into the attribute hash 
	   context, and replace the original tag */
	temp = cmsAttributeInfo->encodedAttributes[ 0 ];
	cmsAttributeInfo->encodedAttributes[ 0 ] = BER_SET;
	krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH,
					 cmsAttributeInfo->encodedAttributes,
					 cmsAttributeInfo->encodedAttributeSize );
	status = krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH, "", 0 );
	cmsAttributeInfo->encodedAttributes[ 0 ] = temp;
	return( status );
	}

static int createCmsAttributes( CMS_ATTRIBUTE_INFO *cmsAttributeInfo,
								CRYPT_CONTEXT *iCmsHashContext,
								const CRYPT_ALGO_TYPE hashAlgo,
								const BOOLEAN lengthCheckOnly )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BOOLEAN createdLocalAttributes = FALSE, createdHashContext = FALSE;
	int value, status;

	assert( isWritePtr( cmsAttributeInfo, sizeof( CMS_ATTRIBUTE_INFO ) ) );
	assert( cmsAttributeInfo->formatType == CRYPT_FORMAT_CMS || \
			cmsAttributeInfo->formatType == CRYPT_FORMAT_SMIME );
	assert( ( cmsAttributeInfo->iCmsAttributes == CRYPT_USE_DEFAULT ) || \
			isHandleRangeValid( cmsAttributeInfo->iCmsAttributes ) );
	assert( isHandleRangeValid( cmsAttributeInfo->iMessageHash ) );
	assert( isHandleRangeValid( cmsAttributeInfo->iTimeSource ) );
	assert( ( cmsAttributeInfo->iTspSession == CRYPT_UNUSED ) || \
			isHandleRangeValid( cmsAttributeInfo->iTspSession ) );
	assert( cmsAttributeInfo->encodedAttributes == NULL && \
			cmsAttributeInfo->encodedAttributeSize == 0 );
	assert( isWritePtr( cmsAttributeInfo->attributeBuffer, \
						cmsAttributeInfo->maxEncodedAttributeSize ) );
	assert( isWritePtr( iCmsHashContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );

	/* Clear return value */
	*iCmsHashContext = CRYPT_ERROR;

	/* Set up the attribute buffer */
	cmsAttributeInfo->encodedAttributes = cmsAttributeInfo->attributeBuffer;

	/* If the user hasn't supplied the attributes, generate them ourselves */
	if( cmsAttributeInfo->iCmsAttributes == CRYPT_USE_DEFAULT )
		{
		setMessageCreateObjectInfo( &createInfo,
									CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		cmsAttributeInfo->iCmsAttributes = createInfo.cryptHandle;
		createdLocalAttributes = TRUE;
		}

	/* If it's an S/MIME (vs.pure CMS) signature, add the sMIMECapabilities
	   if they're not already present to further bloat things up */
	if( ( cmsAttributeInfo->formatType == CRYPT_FORMAT_SMIME ) && \
		cryptStatusError( \
			krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
							 IMESSAGE_GETATTRIBUTE, &value,
							 CRYPT_CERTINFO_CMS_SMIMECAPABILITIES ) ) )
			{
			krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
							 CRYPT_CERTINFO_CMS_SMIMECAP_3DES );
			if( algoAvailable( CRYPT_ALGO_CAST ) )
				krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_CERTINFO_CMS_SMIMECAP_CAST128 );
			if( algoAvailable( CRYPT_ALGO_IDEA ) )
				krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_CERTINFO_CMS_SMIMECAP_IDEA );
			if( algoAvailable( CRYPT_ALGO_AES ) )
				krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_CERTINFO_CMS_SMIMECAP_AES );
			if( algoAvailable( CRYPT_ALGO_RC2 ) )
				krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_CERTINFO_CMS_SMIMECAP_RC2 );
			if( algoAvailable( CRYPT_ALGO_SKIPJACK ) )
				krnlSendMessage( cmsAttributeInfo->iCmsAttributes, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK );
			}

	/* Generate the attributes and hash them into the CMS hash context */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		createdHashContext = TRUE;
		status = hashCmsAttributes( cmsAttributeInfo, createInfo.cryptHandle, 
									lengthCheckOnly );
		}
	if( createdLocalAttributes )
		{
		krnlSendNotifier( cmsAttributeInfo->iCmsAttributes, 
						  IMESSAGE_DECREFCOUNT );
		cmsAttributeInfo->iCmsAttributes = CRYPT_UNUSED;
		}
	if( cryptStatusError( status ) )
		{
		if( createdHashContext )
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Return the hash of the attributes to the caller */
	*iCmsHashContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Create/Check a CMS Signature 					*
*																			*
****************************************************************************/

/* Create a CMS signature.  The extraData parameter contains the information 
   for signed attributes, and can take one of three values:

	Cert.object handle: Signed attributes to use.

	CRYPT_USE_DEFAULT: Generate default signing attributes when we create 
					   the signature.

	CRYPT_UNUSED: Don't use signing attributes */

int createSignatureCMS( void *signature, int *signatureLength,
						const int sigMaxLength, 
						const CRYPT_CONTEXT signContext,
						const CRYPT_CONTEXT iHashContext,
						const CRYPT_CERTIFICATE extraData,
						const CRYPT_SESSION iTspSession,
						const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_CERTIFICATE iSigningCert;
	CRYPT_ALGO_TYPE hashAlgo;
	STREAM stream;
	CMS_ATTRIBUTE_INFO cmsAttributeInfo;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 128 + 8 ];
	BYTE *bufPtr = ( signature == NULL ) ? NULL : buffer;
	const int bufSize = ( signature == NULL ) ? 0 : CRYPT_MAX_PKCSIZE + 128;
	int dataSignatureSize, length, status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isReadPtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isHandleRangeValid( signContext ) );
	assert( isHandleRangeValid( iHashContext ) );
	assert( ( extraData == CRYPT_UNUSED ) || \
			( extraData == CRYPT_USE_DEFAULT ) || \
			isHandleRangeValid( extraData ) );
	assert( ( iTspSession == CRYPT_UNUSED ) || \
			isHandleRangeValid( iTspSession ) );
	assert( formatType == CRYPT_FORMAT_CMS || \
			formatType == CRYPT_FORMAT_SMIME );

	initCmsAttributeInfo( &cmsAttributeInfo, formatType, extraData, \
						  iHashContext, signContext, iTspSession );

	/* Get the message hash algo and signing cert */
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );
	status = krnlSendMessage( signContext, IMESSAGE_GETDEPENDENT,
							  &iSigningCert, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );

	/* If we're using signed attributes, set them up to be added to the
	   signature info */
	if( cmsAttributeInfo.iCmsAttributes != CRYPT_UNUSED )
		{
		status = createCmsAttributes( &cmsAttributeInfo, &iCmsHashContext, 
									  hashAlgo, ( signature == NULL ) ? \
									  TRUE : FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the signature */
	status = createSignature( bufPtr, &dataSignatureSize, bufSize, 
							  signContext, iCmsHashContext, CRYPT_UNUSED, 
							  SIGNATURE_CMS );
	if( iCmsHashContext != iHashContext )
		krnlSendNotifier( iCmsHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're countersigning the signature (typically done via a
	   timestamp), create the countersignature */
	if( iTspSession != CRYPT_UNUSED && signature != NULL )
		{
		status = createCmsCountersignature( buffer, dataSignatureSize,
											hashAlgo, iTspSession );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the signerInfo record */
	sMemOpen( &stream, signature, ( signature == NULL ) ? 0 : sigMaxLength );
	status = writeCmsSignerInfo( &stream, iSigningCert, hashAlgo,
								 cmsAttributeInfo.encodedAttributes, 
								 cmsAttributeInfo.encodedAttributeSize,
								 buffer, dataSignatureSize,
								 ( signature == NULL ) ? CRYPT_UNUSED : iTspSession );
	length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( iTspSession != CRYPT_UNUSED && signature == NULL )
		{
		/* If we're countersigning the signature with a timestamp and doing
		   a length check only, inflate the total size to the nearest
		   multiple of the envelope parameter MIN_BUFFER_SIZE, which is the
		   size of the envelope's auxData buffer used to contain the
		   signature.  In other words, we're always going to trigger an
		   increase in the auxBuffer size because its initial size is
		   MIN_BUFFER_SIZE, so when we grow it we grow it to a nice round
		   value rather than just ( length + MIN_BUFFER_SIZE ).  The actual
		   size increase is just a guess since we can't really be sure how
		   much bigger it'll get without contacting the TSA, however this
		   should be big enough to hold a simple SignedData value without
		   attached certs.  If a TSA gets the implementation wrong and
		   returns a timestamp with an attached cert chain and the chain is
		   too large, the worst that'll happen is that we'll get a
		   CRYPT_ERROR_OVERFLOW when we try and read the TSA data from the
		   session object.  Note that this behaviour is envelope-specific
		   and assumes that we're being called from the enveloping code, 
		   this is curently the only location from which we can be called 
		   because a timestamp only makes sense as a countersignature on CMS 
		   data */
		if( MIN_BUFFER_SIZE - length <= 1024 )
			length = roundUp( length, MIN_BUFFER_SIZE ) + MIN_BUFFER_SIZE;
		else
			/* It should fit in the buffer, don't bother expanding it */
			length = 1024;
		}
	*signatureLength = length;

	return( CRYPT_OK );
	}

/* Check a CMS signature */

int checkSignatureCMS( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT sigCheckContext,
					   const CRYPT_CONTEXT iHashContext,
					   CRYPT_CERTIFICATE *iExtraData,
					   const CRYPT_HANDLE iSigCheckKey )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_ALGO_TYPE hashAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	QUERY_INFO queryInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isReadPtr( signature, signatureLength ) );
	assert( isHandleRangeValid( sigCheckContext ) );
	assert( isHandleRangeValid( iHashContext ) );
	assert( ( iExtraData == NULL ) || \
			isWritePtr( iExtraData, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isHandleRangeValid( iSigCheckKey ) );

	if( iExtraData != NULL )
		*iExtraData = CRYPT_ERROR;

	/* Get the message hash algo */
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* Unpack the SignerInfo record and make sure that the supplied key is
	   the correct one for the sig.check and the supplied hash context
	   matches the algorithm used in the signature */
	sMemConnect( &stream, signature, signatureLength );
	status = queryAsn1Object( &stream, &queryInfo );
	if( cryptStatusOK( status ) && \
		( queryInfo.formatType != CRYPT_FORMAT_CMS && \
		  queryInfo.formatType != CRYPT_FORMAT_SMIME ) )
		status = CRYPT_ERROR_BADDATA;
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, \
					( BYTE * ) signature + queryInfo.iAndSStart, \
					queryInfo.iAndSLength );
	status = krnlSendMessage( iSigCheckKey, IMESSAGE_COMPARE, &msgData,
							  MESSAGE_COMPARE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		/* A failed comparison is reported as a generic CRYPT_ERROR,
		   convert it into a wrong-key error if necessary */
		return( ( status == CRYPT_ERROR ) ? \
				CRYPT_ERROR_WRONGKEY : status );
	if( queryInfo.hashAlgo != hashAlgo )
		return( CRYPT_ARGERROR_NUM2 );

	/* If there are signedAttributes present, hash the data, substituting a
	   SET OF tag for the IMPLICIT [ 0 ] tag at the start */
	if( queryInfo.attributeStart > 0 )
		{
		static const BYTE setTag[] = { BER_SET };

		setMessageCreateObjectInfo( &createInfo, queryInfo.hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 ( BYTE * ) setTag, sizeof( BYTE ) );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 ( BYTE * ) signature + queryInfo.attributeStart + 1,
						 queryInfo.attributeLength - 1 );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  "", 0 );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iCmsHashContext = createInfo.cryptHandle;
		}

	/* Check the signature */
	status = checkSignature( signature, signatureLength, sigCheckContext,
							 iCmsHashContext, CRYPT_UNUSED, SIGNATURE_CMS );
	if( queryInfo.attributeStart <= 0 )
		/* No signed attributes, we're done */
		return( status );
	krnlSendNotifier( iCmsHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the attributes and make sure that the data hash value given in
	   the signed attributes matches the user-supplied hash */
	setMessageCreateObjectIndirectInfo( &createInfo,
						( BYTE * ) signature + queryInfo.attributeStart,
						queryInfo.attributeLength,
						CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hashValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusOK( status ) && \
		cryptStatusError( \
			krnlSendMessage( iHashContext, IMESSAGE_COMPARE, &msgData,
							 MESSAGE_COMPARE_HASH ) ) )
		status = CRYPT_ERROR_SIGNATURE;
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* If the user wants to look at the authenticated attributes, make them
	   externally visible, otherwise delete them */
	if( iExtraData != NULL )
		*iExtraData = createInfo.cryptHandle;
	else
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	return( CRYPT_OK );
	}
