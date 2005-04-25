/****************************************************************************
*																			*
*							Signature Routines								*
*						Copyright Peter Gutmann 1993-2004					*
*																			*
****************************************************************************/

#include <string.h>
#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp.h"
  #include "mechanism.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "mechanism.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "../misc/misc_rw.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "mechs/mechanism.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Low-level Signature Functions 					*
*																			*
****************************************************************************/

/* Generic signature creation and checking functions, called from higher-
   level functions within this module, with two external wrapper points for 
   X.509 and raw signatures */

static int createSignature( void *signature, int *signatureLength,
							const int sigMaxLength, 
							const CRYPT_CONTEXT iSignContext,
							const CRYPT_CONTEXT iHashContext,
							const CRYPT_CONTEXT iHashContext2,
							const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO_TYPE signAlgo, hashAlgo;
	MECHANISM_SIGN_INFO mechanismInfo;
	STREAM stream;
	const WRITESIG_FUNCTION writeSigFunction = sigWriteTable[ signatureType ];
	BYTE signatureData[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( signature == NULL || isWritePtr( signature, sigMaxLength ) );
	assert( ( signatureType == SIGNATURE_SSL && \
			  iHashContext2 != CRYPT_UNUSED ) || \
			( signatureType != SIGNATURE_SSL && \
			  iHashContext2 == CRYPT_UNUSED ) );

	/* Make sure that the requested signature format is available */
	if( writeSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, &signAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE, 
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* If we're just doing a length check, write dummy data to a null stream
	   and return its length */
	if( signature == NULL )
		{
 		STREAM nullStream;

		assert( signatureType != SIGNATURE_SSH );

		/* Determine how long the signature will be.  In the case of the DLP-
		   based PKCs written in cryptlib format it's just an estimate since 
		   it can change by up to two bytes depending on whether the 
		   signature values have the high bit set or not, which requires 
		   zero-padding of the ASN.1-encoded integers.  This is rather nasty 
		   because it means we can't tell how large a signature will be 
		   without actually creating it.

		   The 6/10 bytes at the start are for the ASN.1 SEQUENCE and 2 * 
		   INTEGER encoding */
		if( signAlgo == CRYPT_ALGO_DSA )
			length = ( signatureType == SIGNATURE_PGP ) ? \
					 2 * ( 2 + 20 ) : 6 + ( 2 * ( 20 + 1 ) );
		else
			{
			/* Calculate the eventual signature size */
			setMechanismSignInfo( &mechanismInfo, NULL, 0, iHashContext, 
								  iHashContext2, iSignContext );
			status = krnlSendMessage( iSignContext, IMESSAGE_DEV_SIGN, 
									  &mechanismInfo, 
									  ( signatureType == SIGNATURE_SSL ) ? \
										MECHANISM_SIG_SSL : \
										MECHANISM_SIG_PKCS1 );
			length = mechanismInfo.signatureLength;
			clearMechanismInfo( &mechanismInfo );
			if( cryptStatusError( status ) )
				/* The mechanism messages place the acted-on object (in this
				   case the hash context) first while the higher-level 
				   functions place the signature context next to the 
				   signature data, in other words before the hash context.
				   Because of this we have to reverse parameter error values
				   when translating from the mechanism to the signature
				   function level */
				return( ( status == CRYPT_ARGERROR_NUM1 ) ? \
							CRYPT_ARGERROR_NUM2 : \
						( status == CRYPT_ARGERROR_NUM2 ) ? \
							CRYPT_ARGERROR_NUM1 : status );
			}

		/* Write the data to a null stream to determine its size */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeSigFunction( &nullStream, iSignContext, hashAlgo, 
								   signAlgo, signatureData, length );
		*signatureLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* DLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) )
		{
		DLP_PARAMS dlpParams;
		RESOURCE_DATA msgData;
		BYTE hash[ CRYPT_MAX_HASHSIZE ];

		/* Extract the hash value from the context */
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );

		/* DSA is only defined for hash algorithms with a block size of 160
		   bits */
		if( msgData.length != 20 )
			return( CRYPT_ARGERROR_NUM1 );

		/* Sign the data */
		setDLPParams( &dlpParams, hash, 20, signatureData, CRYPT_MAX_PKCSIZE );
		if( signatureType == SIGNATURE_PGP )
			dlpParams.formatType = CRYPT_FORMAT_PGP;			
		if( signatureType == SIGNATURE_SSH )
			dlpParams.formatType = CRYPT_IFORMAT_SSH;			
		status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGN, &dlpParams, 
								  sizeof( DLP_PARAMS ) );
		length = dlpParams.outLen;
		}
	else
		{
		setMechanismSignInfo( &mechanismInfo, signatureData, CRYPT_MAX_PKCSIZE,
							  iHashContext, iHashContext2, iSignContext );
		status = krnlSendMessage( iSignContext, IMESSAGE_DEV_SIGN, 
								  &mechanismInfo, 
								  ( signatureType == SIGNATURE_SSL ) ? \
									MECHANISM_SIG_SSL : \
									MECHANISM_SIG_PKCS1 );
		if( cryptStatusError( status ) )
			/* The mechanism messages place the acted-on object (in this case 
			   the hash context) first while the higher-level functions place 
			   the signature context next to the signature data, in other 
			   words before the hash context.  Because of this we have to 
			   reverse parameter error values when translating from the 
			   mechanism to the signature function level */
			status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
						CRYPT_ARGERROR_NUM2 : \
					 ( status == CRYPT_ARGERROR_NUM2 ) ? \
						CRYPT_ARGERROR_NUM1 : status;
		else
			length = mechanismInfo.signatureLength;
		clearMechanismInfo( &mechanismInfo );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( signatureData, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Write the signature record to the output */
	sMemOpen( &stream, signature, sigMaxLength );
	status = writeSigFunction( &stream, iSignContext, hashAlgo, signAlgo, 
							   signatureData, length );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );

	/* Clean up */
	zeroise( signatureData, CRYPT_MAX_PKCSIZE );
	return( status );
	}

static int checkSignature( const void *signature, const int signatureLength,
						   const CRYPT_CONTEXT iSigCheckContext,
						   const CRYPT_CONTEXT iHashContext,
						   const CRYPT_CONTEXT iHashContext2,
						   const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO_TYPE signAlgo, hashAlgo;
	MECHANISM_SIGN_INFO mechanismInfo;
	const READSIG_FUNCTION readSigFunction = sigReadTable[ signatureType ];
	QUERY_INFO queryInfo;
	STREAM stream;
	void *signatureData;
	int signatureDataLength, status;

	assert( ( signatureType == SIGNATURE_SSL && \
			  iHashContext2 != CRYPT_UNUSED ) || \
			( signatureType != SIGNATURE_SSL && \
			  iHashContext2 == CRYPT_UNUSED ) );

	/* Make sure that the requested signature format is available */
	if( readSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE, 
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* Read the signature record up to the start of the signature itself */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, signature, signatureLength );
	status = readSigFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Make sure that we've been given the correct algorithms.  Raw 
	   signatures specify the algorithm information elsewhere, so the check 
	   is done elsewhere when we process the signature data */
	if( signatureType != SIGNATURE_RAW && signatureType != SIGNATURE_SSL )
		{
		if( signAlgo != queryInfo.cryptAlgo )
			status = CRYPT_ERROR_SIGNATURE;
		if( signatureType != SIGNATURE_SSH && \
			hashAlgo != queryInfo.hashAlgo )
			status = CRYPT_ERROR_SIGNATURE;
		if( cryptStatusError( status ) )
			{
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			return( status );
			}
		}

	/* Make sure that we've been given the correct key if the signature 
	   format supports this type of check.  SIGNATURE_CMS supports a check 
	   with MESSAGE_COMPARE_ISSUERANDSERIALNUMBER but this has already been 
	   done while procesing the other CMS data before we were called so we 
	   don't need to do it again */
	if( signatureType == SIGNATURE_CRYPTLIB )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE, 
								  &msgData, MESSAGE_COMPARE_KEYID );
		if( cryptStatusError( status ) )
			{
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a wrong-key error if necessary */
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			return( ( status == CRYPT_ERROR ) ? \
					CRYPT_ERROR_WRONGKEY : status );
			}
		}
	if( signatureType == SIGNATURE_PGP )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE, 
								  &msgData, 
								  ( queryInfo.version == PGP_VERSION_2 ) ? \
									MESSAGE_COMPARE_KEYID_PGP : \
									MESSAGE_COMPARE_KEYID_OPENPGP );
		if( cryptStatusError( status ) )
			{
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a wrong-key error if necessary */
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			return( ( status == CRYPT_ERROR ) ? \
					CRYPT_ERROR_WRONGKEY : status );
			}
		}
	signatureData = queryInfo.dataStart;
	signatureDataLength = queryInfo.dataLength;
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	/* DLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) )
		{
		DLP_PARAMS dlpParams;
		RESOURCE_DATA msgData;
		BYTE hash[ CRYPT_MAX_HASHSIZE ];

		/* Extract the hash value from the context */
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );

		/* DSA is only defined for hash algorithms with a block size of 160 
		   bits */
		if( msgData.length != 20 )
			return( CRYPT_ARGERROR_NUM1 );

		/* Check the signature validity using the encoded signature data and
		   hash */
		setDLPParams( &dlpParams, hash, 20, NULL, 0 );
		dlpParams.inParam2 = signatureData;
		dlpParams.inLen2 = signatureDataLength;
		if( signatureType == SIGNATURE_PGP )
			dlpParams.formatType = CRYPT_FORMAT_PGP;
		if( signatureType == SIGNATURE_SSH )
			dlpParams.formatType = CRYPT_IFORMAT_SSH;
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_CTX_SIGCHECK,
								  &dlpParams, sizeof( DLP_PARAMS ) );
		}
	else
		{
		setMechanismSignInfo( &mechanismInfo, signatureData, 
							  signatureDataLength, iHashContext, 
							  iHashContext2, iSigCheckContext );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_SIGCHECK, &mechanismInfo, 
								  ( signatureType == SIGNATURE_SSL ) ? \
									MECHANISM_SIG_SSL : \
									MECHANISM_SIG_PKCS1 );
		if( cryptStatusError( status ) )
			/* The mechanism messages place the acted-on object (in this case 
			   the hash context) first while the higher-level functions place 
			   the signature context next to the signature data, in other 
			   words before the hash context.  Because of this we have to 
			   reverse parameter error values when translating from the 
			   mechanism to the signature function level */
			status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
						CRYPT_ARGERROR_NUM2 : \
					 ( status == CRYPT_ARGERROR_NUM2 ) ? \
						CRYPT_ARGERROR_NUM1 : status;

		clearMechanismInfo( &mechanismInfo );
		}

	return( status );
	}

/****************************************************************************
*																			*
*							X.509-style Signature Functions 				*
*																			*
****************************************************************************/

/* Create/check an X.509-style signature.  These work with objects of the
   form:

	signedObject ::= SEQUENCE {
		object				ANY,
		signatureAlgorithm	AlgorithmIdentifier,
		signature			BIT STRING
		}

   This is complicated by a variety of b0rken PKI protocols that couldn't
   quite manage a cut & paste of two lines of text, adding all sorts of 
   unnecessary extra tagging and wrappers to the signature.  To handle the
   tagging and presence of extra data, we allow two extra parameters, a 
   tag/wrapper formatting info specifier and an extra data length value (with
   the data being appended by the caller).  If the tag/wrapper is a small
   integer value, it's treated as [n] { ... }; if it has the 7th bit set 
   (0x80), it's treated as [n] { SEQUENCE { ... }} */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const int sigMaxLength,
						 const void *object, const int objectLength,
						 const CRYPT_CONTEXT signContext, 
						 const CRYPT_ALGO_TYPE hashAlgo,
						 const int formatInfo, const int extraDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
#if INT_MAX > 32767
	int startOffset = ( objectLength > 64500 ) ? 5 : 4;
#else
	int startOffset = 4;
#endif /* 32-bit ints */
	BYTE *payloadStart = ( BYTE * ) signedObject + startOffset;
	int sigWrapperSize = ( formatInfo == CRYPT_UNUSED ) ? 0 : 16;
	int signatureLength, totalSigLength, delta, status;

	/* Hash the data to be signed */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
					 ( void * ) object, objectLength );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
					 ( void * ) object, 0 );

	/* Create the wrapped-up signed object.  This gets somewhat ugly because
	   the only way we can find out how long the signature will be is by
	   actually creating it, since the ASN.1 encoding constraints mean that 
	   the size can vary by a few bytes depending on what values the integers
	   that make up the signature take.  Because of this, we first generate
	   the signature a reasonable distance back from the start of the buffer,
	   write the header and data to sign at the start, and finally move the
	   signature down to the end of the header if required.  startOffset is
	   the initial estimate of the length of the encapsulating SEQUENCE and
	   covers a payload length of 256-64K bytes, delta is the difference
	   between the estimate and the actual size that we later need to 
	   correct for.  Since the combination of data to sign and signature are 
	   virtually always in the range 256-64K bytes, the data move is almost 
	   never performed:

		 startOfs			objLength		sigLength
			v					v				v
		+---+-------------------+-------+-------+
		|	|		object		|wrapper|  sig	|
		+---+-------------------+-------+-------+
			|							^
		payloadStart			  sigWrapperSize */
	status = createSignature( payloadStart + objectLength + sigWrapperSize, 
							  &signatureLength, 
							  sigMaxLength - ( startOffset + objectLength + \
											   sigWrapperSize ), 
							  signContext, createInfo.cryptHandle, 
							  CRYPT_UNUSED, SIGNATURE_X509 );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	if( formatInfo == CRYPT_UNUSED )
		totalSigLength = signatureLength + extraDataLength;
	else
		if( !( formatInfo & 0x80 ) )
			totalSigLength = ( int ) \
				sizeofObject( signatureLength + extraDataLength );
		else
			totalSigLength = ( int ) \
				sizeofObject( sizeofObject( signatureLength + extraDataLength ) );
	sMemOpen( &stream, signedObject, startOffset );
	writeSequence( &stream, objectLength + totalSigLength );
	delta = startOffset - stell( &stream );
	sMemDisconnect( &stream );
	if( delta > 0 )
		{
		payloadStart -= delta;
		startOffset -= delta;
		}
	memcpy( payloadStart, object, objectLength );
	if( sigWrapperSize > 0 )
		{
		const int oldSigWrapperSize = sigWrapperSize;

		sMemOpen( &stream, payloadStart + objectLength, sigWrapperSize );
		if( !( formatInfo & 0x80 ) )
			writeConstructed( &stream, signatureLength + extraDataLength, 
							  formatInfo );
		else
			{
			writeConstructed( &stream, 
						sizeofObject( signatureLength + extraDataLength ), 
						formatInfo & 0x7F );
			writeSequence( &stream, signatureLength + extraDataLength );
			}
		sigWrapperSize = stell( &stream );
		sMemDisconnect( &stream );
		memmove( payloadStart + objectLength + sigWrapperSize,
				 payloadStart + objectLength + oldSigWrapperSize,
				 signatureLength );
		}
	if( delta > 0 )
		memmove( payloadStart + objectLength, 
				 payloadStart + delta + objectLength, 
				 sigWrapperSize + signatureLength );
	*signedObjectLength = startOffset + objectLength + sigWrapperSize + \
						  signatureLength;

	return( status );
	}

int checkX509signature( const void *signedObject, const int signedObjectLength,
						void **object, int *objectLength, 
						const CRYPT_CONTEXT sigCheckContext,
						const int formatInfo )
	{
	CRYPT_ALGO_TYPE signAlgo, sigCheckAlgo, hashAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	void *objectPtr, *sigPtr;
	int status, length, signatureLength;

	/* Check the start of the object and record the start and size of the 
	   encapsulated signed object, with special handling for unsually long
	   data in mega-CRLs.  The use of the length from readSequence() is safe 
	   here because the data has to be DER if it's signed */
	sMemConnect( &stream, signedObject, signedObjectLength );
#if INT_MAX > 32767
	readLongSequence( &stream, NULL );
#else
	readSequence( &stream, NULL );
#endif /* Non-16-bit systems */
	objectPtr = sMemBufPtr( &stream );
#if INT_MAX > 32767
	if( signedObjectLength >= 32767 )
		{
		long longLength;

		status = readLongSequence( &stream, &longLength );
		if( cryptStatusOK( status ) )
			{
			/* If it's an (invalid) indefinite-length encoding we can't do 
			   anything with it */
			if( longLength == CRYPT_UNUSED )
				status = CRYPT_ERROR_BADDATA;
			else
				length = ( int ) longLength;
			}
		}
	else
#endif /* Non-16-bit systems */
		status = readSequence( &stream, &length );
	if( cryptStatusOK( status ) )
		{
		status = sSkip( &stream, length );		/* Move past the object */
		length = ( int ) sizeofObject( length );/* Include header size */
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( objectLength != NULL )
		*objectLength = length;
	if( object != NULL )
		*object = objectPtr;

	/* Make sure that the signing parameters are in order and create a hash 
	   context from the algorithm identifier of the signature */
	status = krnlSendMessage( sigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &sigCheckAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		/* If it's a broken signature, process the extra encapsulation */
		if( formatInfo != CRYPT_UNUSED )
			{
			if( !( formatInfo & 0x80 ) )
				readConstructed( &stream, NULL, formatInfo );
			else
				{
				readConstructed( &stream, NULL, formatInfo & 0x7F );
				readSequence( &stream, NULL );
				}
			}
		sigPtr = sMemBufPtr( &stream );
		status = readAlgoIDex( &stream, &signAlgo, &hashAlgo, NULL );
		}
	signatureLength = sMemDataLeft( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( sigCheckAlgo != signAlgo )
		/* The signature algorithm isn't what we expected, the best we can do
		   is report a signature error */
		return( CRYPT_ERROR_SIGNATURE );
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the signed data and check the signature on the object */
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
					 objectPtr, length );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
					 objectPtr, 0 );
	status = checkSignature( sigPtr, signatureLength, sigCheckContext, 
							 createInfo.cryptHandle, CRYPT_UNUSED, 
							 SIGNATURE_X509 );

	/* Clean up */
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/****************************************************************************
*																			*
*							PKI Protocol Signature Functions 				*
*																			*
****************************************************************************/

/* The various cert management protocols are built using the twin design 
   guidelines that nothing should use a standard style of signature and no
   two protocols should use the same nonstandard format, the only way to 
   handle these (without creating dozens of new signature types, each with
   their own special-case handling) is to process most of the signature 
   information at the protocol level and just check the raw signature here */

int createRawSignature( void *signature, int *signatureLength,
						const int sigMaxLength, 
						const CRYPT_CONTEXT iSignContext,
						const CRYPT_CONTEXT iHashContext )
	{
	return( createSignature( signature, signatureLength, sigMaxLength, 
							 iSignContext, iHashContext, CRYPT_UNUSED, 
							 SIGNATURE_RAW ) );
	}

int checkRawSignature( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT iSigCheckContext,
					   const CRYPT_CONTEXT iHashContext )
	{
	return( checkSignature( signature, signatureLength, iSigCheckContext, 
							iHashContext, CRYPT_UNUSED, SIGNATURE_RAW ) );
	}

/****************************************************************************
*																			*
*							Create/Check a CMS Signature 					*
*																			*
****************************************************************************/

/* CMS version */

#define CMS_VERSION		1

/* The maximum size for the encoded CMS signed attributes */

#define ENCODED_ATTRIBUTE_SIZE	512

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
							   const CRYPT_ALGO_TYPE hashAlgorithm,
							   const void *attributes, const int attributeSize,
							   const void *signature, const int signatureSize,
							   const CRYPT_HANDLE unsignedAttrObject )
	{
	RESOURCE_DATA msgData;
	DYNBUF iAndSDB;
	int timeStampSize, unsignedAttributeSize = 0;
	int status;

	/* Get the signerInfo information */
	status = dynCreate( &iAndSDB, certificate, 
						CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );
	if( unsignedAttrObject != CRYPT_UNUSED )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( unsignedAttrObject, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_ENC_TIMESTAMP );
		timeStampSize = msgData.length;
		if( cryptStatusOK( status ) )
			unsignedAttributeSize = ( int ) \
						sizeofObject( sizeofOID( OID_TSP_TSTOKEN ) + \
									  sizeofObject( timeStampSize ) );
		}
	if( cryptStatusError( status ) )
		{
		dynDestroy( &iAndSDB );
		return( status );
		}

	/* Write the outer SEQUENCE wrapper and version number */
	writeSequence( stream, sizeofShortInteger( CMS_VERSION ) + \
						   dynLength( iAndSDB ) + \
						   sizeofAlgoID( hashAlgorithm ) + \
						   attributeSize + signatureSize + \
						   ( ( unsignedAttributeSize ) ? \
							 ( int ) sizeofObject( unsignedAttributeSize ) : 0 ) );
	writeShortInteger( stream, CMS_VERSION, DEFAULT_TAG );

	/* Write the issuerAndSerialNumber, digest algorithm identifier, 
	   attributes (if there are any) and signature */
	swrite( stream, dynData( iAndSDB ), dynLength( iAndSDB ) );
	writeAlgoID( stream, hashAlgorithm );
	if( attributeSize )
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
									 CRYPT_IATTRIBUTE_ENC_TIMESTAMP,
									 CRYPT_USE_DEFAULT ) );
	}

/* Create CMS signed attributes */

static int createCmsSignedAttributes( CRYPT_CONTEXT iAttributeHash,
									  BYTE *encodedAttributes,
									  int *encodedAttributeSize,
									  const CRYPT_CERTIFICATE iCmsAttributes,
									  const CRYPT_CONTEXT iMessageHash,
									  const CRYPT_HANDLE iTimeSource )
	{
	RESOURCE_DATA msgData;
	BYTE temp, hash[ CRYPT_MAX_HASHSIZE ];
	int status;

	/* Clear return value */
	*encodedAttributeSize = 0;

	/* Extract the message hash information and add it as a messageDigest 
	   attribute, replacing any existing value if necessary.  If we're
	   doing a call just to get the length of the exported data, we use a 
	   dummy hash value since the hashing may not have completed yet */
	krnlSendMessage( iCmsAttributes, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	if( encodedAttributes == NULL )
		status = krnlSendMessage( iMessageHash, IMESSAGE_GETATTRIBUTE,
								  &msgData.length, CRYPT_CTXINFO_BLOCKSIZE );
	else
		status = krnlSendMessage( iMessageHash, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're creating the attributes for a real signature (rather than 
	   just as part of a size check) and there's a reliable time source 
	   present, use the time from that instead of the built-in system time */
	if( encodedAttributes != NULL )
		{
		const time_t currentTime = getReliableTime( iTimeSource );

		if( currentTime > MIN_TIME_VALUE )
			{
			setMessageData( &msgData, ( void * ) &currentTime, 
							sizeof( time_t ) );
			krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_CERTINFO_CMS_SIGNINGTIME );
			}
		}

	/* Export the attributes into an encoded signedAttributes data block,
	   replace the IMPLICIT [ 0 ] tag at the start with a SET OF tag to allow
	   the attributes to be hashed, hash them into the attribute hash context, 
	   and replace the original tag */
	if( encodedAttributes == NULL )
		{ setMessageData( &msgData, NULL, 0 ); }
	else
		setMessageData( &msgData, encodedAttributes, ENCODED_ATTRIBUTE_SIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		return( status );
	*encodedAttributeSize = msgData.length;
	if( encodedAttributes == NULL )
		/* If it's a length check, just generate a dummy hash value and 
		   exit */
		return( krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH, "", 0 ) );
	temp = encodedAttributes[ 0 ];
	encodedAttributes[ 0 ] = BER_SET;
	krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH, 
					 encodedAttributes, *encodedAttributeSize );
	status = krnlSendMessage( iAttributeHash, IMESSAGE_CTX_HASH, 
							  "", 0 );
	encodedAttributes[ 0 ] = temp;

	return( status );
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
	status = readOctetStringHole( &stream, &length, DEFAULT_TAG );
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

/* Create a CMS signature */

static int createSignatureCMS( void *signature, int *signatureLength,
							   const int sigMaxLength,
							   const CRYPT_CONTEXT signContext,
							   const CRYPT_CONTEXT iHashContext,
							   const CRYPT_CERTIFICATE extraData,
							   const CRYPT_SESSION iTspSession,
							   const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_CERTIFICATE iCmsAttributes = extraData, iSigningCert;
	CRYPT_ALGO_TYPE hashAlgo;
	STREAM stream;
	BYTE encodedAttributes[ ENCODED_ATTRIBUTE_SIZE + 8 ];
	BYTE dataSignature[ CRYPT_MAX_PKCSIZE + 128 ];
	int encodedAttributeSize, dataSignatureSize, length, status;

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
	if( extraData != CRYPT_UNUSED )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		int value;

		if( extraData == CRYPT_USE_DEFAULT )
			{
			/* If there are no attributes included as extra data, generate 
			   them ourselves */
			setMessageCreateObjectInfo( &createInfo, 
										CRYPT_CERTTYPE_CMS_ATTRIBUTES );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			iCmsAttributes = createInfo.cryptHandle;
			}

		/* If it's an S/MIME (vs.pure CMS) signature, add the 
		   sMIMECapabilities if they're not already present to further bloat 
		   things up */
		if( formatType == CRYPT_FORMAT_SMIME && \
			cryptStatusError( \
				krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE, &value, 
								 CRYPT_CERTINFO_CMS_SMIMECAPABILITIES ) ) )
			{
			krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_3DES );
			if( algoAvailable( CRYPT_ALGO_CAST ) )
				krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_CAST128 );
			if( algoAvailable( CRYPT_ALGO_IDEA ) )
				krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_IDEA );
			if( algoAvailable( CRYPT_ALGO_AES ) )
				krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_AES );
			if( algoAvailable( CRYPT_ALGO_RC2 ) )
				krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_RC2 );
			if( algoAvailable( CRYPT_ALGO_SKIPJACK ) )
				krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE, 
					MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK );
			}

		/* Generate the signed attributes and hash them into the CMS hash
		   context */
		setMessageCreateObjectInfo( &createInfo, hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			if( extraData == CRYPT_USE_DEFAULT )
				krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		status = createCmsSignedAttributes( createInfo.cryptHandle, 
						( signature == NULL ) ? NULL : encodedAttributes, 
						&encodedAttributeSize, iCmsAttributes, iHashContext,
						signContext );
		if( extraData == CRYPT_USE_DEFAULT )
			krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iCmsHashContext = createInfo.cryptHandle;
		}
	else
		/* No signed attributes present */
		encodedAttributeSize = 0;

	/* Create the signature */
	status = createSignature( ( signature == NULL ) ? NULL : dataSignature,
							  &dataSignatureSize, CRYPT_MAX_PKCSIZE + 128, 
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
		status = createCmsCountersignature( dataSignature, dataSignatureSize,
											hashAlgo, iTspSession );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the signerInfo record */
	sMemOpen( &stream, signature, ( signature == NULL ) ? 0 : sigMaxLength );
	status = writeCmsSignerInfo( &stream, iSigningCert, hashAlgo, 
								 encodedAttributes, encodedAttributeSize,
								 dataSignature, dataSignatureSize, 
								 ( signature == NULL ) ? CRYPT_UNUSED : iTspSession );
	length = stell( &stream );
	sMemDisconnect( &stream );
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
		   and assumes we're being called from the enveloping code, this is
		   curently the only location from which we can be called because a
		   timestamp only makes sense as a countersignature on CMS data */
		if( MIN_BUFFER_SIZE - length <= 1024 )
			length = roundUp( length, MIN_BUFFER_SIZE ) + MIN_BUFFER_SIZE;
		else
			/* It should fit in the buffer, don't bother expanding it */
			length = 1024;
		}
	if( cryptStatusOK( status ) )
		*signatureLength = length;

	return( status );
	}

/* Check a CMS signature */

static int checkSignatureCMS( const void *signature, const int signatureLength,
							  const CRYPT_CONTEXT sigCheckContext,
							  const CRYPT_CONTEXT iHashContext, 
							  CRYPT_CERTIFICATE *iExtraData,
							  const CRYPT_HANDLE iSigCheckKey )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_ALGO_TYPE hashAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	QUERY_INFO queryInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	int status;

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
	if( queryInfo.formatType != CRYPT_FORMAT_CMS && \
		queryInfo.formatType != CRYPT_FORMAT_SMIME )
		status = CRYPT_ERROR_BADDATA;
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, queryInfo.iAndSStart, queryInfo.iAndSLength );
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
	if( queryInfo.attributeStart != NULL )
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
						 ( ( BYTE * ) queryInfo.attributeStart ) + 1, 
						 queryInfo.attributeLength - 1 );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
						 "", 0 );
		iCmsHashContext = createInfo.cryptHandle;
		}

	/* Check the signature */
	status = checkSignature( signature, signatureLength, sigCheckContext, 
							 iCmsHashContext, CRYPT_UNUSED, SIGNATURE_CMS );
	if( queryInfo.attributeStart == NULL )
		/* No signed attributes, we're done */
		return( status );
	krnlSendNotifier( iCmsHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the attributes and make sure that the data hash value given in 
	   the signed attributes matches the user-supplied hash */
	setMessageCreateObjectIndirectInfo( &createInfo, 
						queryInfo.attributeStart, queryInfo.attributeLength,
						CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hashValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_COMPARE, &msgData, 
								  MESSAGE_COMPARE_HASH );
		if( status == CRYPT_ERROR )
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a signature error if necessary */
			status = CRYPT_ERROR_SIGNATURE;
		}
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

	return( status );
	}

/****************************************************************************
*																			*
*							Create/Check a PGP Signature					*
*																			*
****************************************************************************/

#ifdef USE_PGP

/* Write a PGP signature packet header:
		-- Start of hashed data --
		byte	version = 4
		byte	sigType
		byte	sigAlgo
		byte	hashAlgo
		byte[2]	length of auth.attributes
		byte[]	authenticated attributes
		-- End of hashed data --
		byte[2]	length of unauth.attributes = 0
	  [	byte[2]	hash check ]
	  [	mpi(s)	signature  ]

   PGP processes the authenticated attributes in an odd way, first hashing 
   part of the packet from the version number to the end of the authenticated
   attributes, then some more stuff, and finally signing that.  Because of
   this complex way of handling things, we can't write the signature packet 
   in one go but instead have to write the part that's hashed, hash it, and 
   then go back and reassemble the whole thing from the pre-hashed data and 
   the length, hash check, and signature */

static int writePgpSigPacketHeader( void *dataBuffer, const int dataBufSize,
									const CRYPT_CONTEXT iSignContext, 
									const CRYPT_CONTEXT iHashContext,
									const int iAndSlength )
	{
	CRYPT_ALGO_TYPE hashAlgo, signAlgo;
	STREAM stream;
	RESOURCE_DATA msgData;
	BYTE keyID[ PGP_KEYID_SIZE ];
	BYTE iAndSHeader[ 64 ];
	BYTE buffer[ 8 ], *bufPtr = buffer;
	const time_t currentTime = getApproxTime();
	int length, iAndSHeaderLength = 0, status;

	/* Get the signature information */
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE, 
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, 
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );

	/* Write the issuerAndSerialNumber packet header if necessary.  Since 
	   this is a variable-length packet we need to pre-encode it before we 
	   can write the main packet data:

		byte[]		length
		byte		subpacketType
		byte[4]		flags = 0
		byte[2]		typeLength
		byte[2]		valueLength
		byte[]		type
		byte[]		value

	   Note that type and value are reversed, this is required by the spec */
	if( iAndSlength > 0 )
		{
		STREAM headerStream;

		sMemOpen( &headerStream, iAndSHeader, 64 );
		pgpWriteLength( &headerStream, 1 + 4 + 2 + 2 + 21 + iAndSlength );
		sputc( &headerStream, PGP_SUBPACKET_TYPEANDVALUE );
		swrite( &headerStream, "\x00\x00\x00\x00", 4 );
		sputc( &headerStream, 0 );
		sputc( &headerStream, 21 );
		sputc( &headerStream, ( iAndSlength >> 8 ) & 0xFF );
		sputc( &headerStream, iAndSlength & 0xFF );
		swrite( &headerStream, "issuerAndSerialNumber", 21 );
		iAndSHeaderLength = stell( &headerStream );
		assert( sStatusOK( &headerStream ) );
		sMemDisconnect( &headerStream );
		}

	/* Write the general header information */
	sMemOpen( &stream, dataBuffer, dataBufSize );
	sputc( &stream, PGP_VERSION_OPENPGP );
	sputc( &stream, PGP_SIG_DATA );
	sputc( &stream, cryptlibToPgpAlgo( signAlgo ) );
	sputc( &stream, cryptlibToPgpAlgo( hashAlgo ) );

	/* Write the authenticated attributes.  The signer ID is optional, but
	   if we omit it GPG fails the signature check so we always include it */
	length = 1 + 1 + 4 + 1 + 1 + PGP_KEYID_SIZE;
	if( iAndSlength )
		length += iAndSHeaderLength + iAndSlength;
	sputc( &stream, ( length >> 8 ) & 0xFF );
	sputc( &stream, length & 0xFF );
	sputc( &stream, 1 + 4 );
	sputc( &stream, PGP_SUBPACKET_TIME );
	mputLong( bufPtr, currentTime );
	swrite( &stream, buffer, 4 );
	sputc( &stream, 1 + PGP_KEYID_SIZE );
	sputc( &stream, PGP_SUBPACKET_KEYID );
	swrite( &stream, keyID, PGP_KEYID_SIZE );
	if( iAndSlength )
		{
		swrite( &stream, iAndSHeader, iAndSHeaderLength );
		if( dataBuffer == NULL )
			{ setMessageData( &msgData, NULL, 0 ); }
		else
			{ setMessageData( &msgData, sMemBufPtr( &stream ), 
							  sMemDataLeft( &stream ) - 2 ); }
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, 
								  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusError( status ) )
			{
			sMemClose( &stream );
			return( status );
			}
		sSkip( &stream, msgData.length );
		}

	/* Write the unauthenticated attributes */
	sputc( &stream, 0 );
	status = sputc( &stream, 0 );

	/* Clean up */
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( cryptStatusError( status ) ? status : length );
	}

static int createSignaturePGP( void *signature, int *signatureLength,
							   const int sigMaxLength, 
							   const CRYPT_CONTEXT iSignContext,
							   const CRYPT_CONTEXT iHashContext )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], signatureData[ CRYPT_MAX_PKCSIZE + 128 ];
	BYTE extraData[ 1024 + 8 ], *extraDataPtr = extraData;
	int extraDataLength = 1024, signatureDataLength, iAndSlength = 0, status;

	/* If it's a length check only, determine how large the signature data
	   will be */
	if( signature == NULL )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, 
								  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusOK( status ) )
			iAndSlength = msgData.length;
		status = extraDataLength = \
			writePgpSigPacketHeader( NULL, 0, iSignContext, iHashContext, 
									 iAndSlength );
		if( !cryptStatusError( status ) )
			status = createSignature( NULL, &signatureDataLength, 0,
									  iSignContext, iHashContext, 
									  CRYPT_UNUSED, SIGNATURE_PGP );
		if( cryptStatusError( status ) )
			return( status );
		*signatureLength = 1 + pgpSizeofLength( extraDataLength + 2 + \
												signatureDataLength ) + \
						   extraDataLength + 2 + signatureDataLength;

		return( CRYPT_OK );
		}

	/* Check whether there's an issuerAndSerialNumber present and allocate a
	   larger buffer for it if necessary.  Note that we can't use a dynBuf 
	   for this because we're allocating a buffer larger than the attribute,
	   not the same size as the attribute */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		{
		if( msgData.length > extraDataLength - 128 )
			{
			extraDataLength = 128 + msgData.length;
			if( ( extraDataPtr = clDynAlloc( "createSignaturePGP", \
											 extraDataLength ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			}
		iAndSlength = msgData.length;
		}

	/* Complete the hashing and create the signature.  In theory this could 
	   get ugly because there could be multiple one-pass signature packets 
	   present, however PGP handles multiple signatures by nesting them so 
	   this isn't a problem.

	   PGP processes the authenticated attributes in an odd way, first 
	   hashing part of the packet from the version number to the end of the 
	   authenticated attributes, then some more stuff, and finally signing 
	   that.  Because of this complex way of handling things, we can't write 
	   the signature packet in one go but instead have to write the part 
	   we can create now, hash the portion that's hashed (all but the last
	   16 bits, the length of the unathenticated attributes), and then go 
	   back and assemble the whole thing including the length and signature 
	   later on from the individual parts */
	status = extraDataLength = \
		writePgpSigPacketHeader( extraData, extraDataLength, iSignContext, 
								 iHashContext, iAndSlength );
	if( !cryptStatusError( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  extraData, extraDataLength - 2 );
		if( status == CRYPT_ERROR_COMPLETE )
			/* Unlike standard signatures, PGP requires that the hashing
			   not be wrapped up before the signature is generated, since
			   it needs to hash in further data before it can generate
			   the signature.  Since completing the hashing is likely to be 
			   a common error, we specifically check for this and return an
			   appropriate error code */
			status = CRYPT_ARGERROR_NUM2;
		}
	if( cryptStatusOK( status ) )
		{
		BYTE buffer[ 8 ], *bufPtr = buffer + 2;

		/* Hash in even more stuff at the end.  This is a complex jumble of 
		   items  constituting a version number, an 0xFF, and another length.
		   This was motivated by a concern that something that meant one 
		   thing in a version n sig could mean something different when 
		   interpreted as a version n+1 sig.  For this reason a hash-
		   convention version (v4) was added, along with a disambiguator 
		   0xFF that will never be found at that position in older (v3) 
		   hash-convention sigs (the 0x04 is in fact redundant, but may be 
		   needed at some point if the hash convention moves to a v5 
		   format).  The length has something to do with parsing the packet 
		   from the end, so that out-of-band data doesn't  run into payload 
		   data */
		buffer[ 0 ] = 0x04;
		buffer[ 1 ] = 0xFF;
		mputLong( bufPtr, extraDataLength - 2 );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 6 );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = createSignature( signatureData, &signatureDataLength, 
								  CRYPT_MAX_PKCSIZE + 128, iSignContext, 
								  iHashContext, CRYPT_UNUSED, SIGNATURE_PGP );
		if( cryptStatusOK( status ) && \
			( 1 + pgpSizeofLength( extraDataLength + 1024 ) + \
			  extraDataLength + 16 + signatureDataLength ) > sigMaxLength )
			status = CRYPT_ERROR_OVERFLOW;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( extraDataPtr, extraDataLength );
		if( extraDataPtr != extraData )
			clFree( "createSignaturePGP", extraDataPtr );
		return( status );
		}

	/* Write the signature packet:
	  [	signature packet header ]
		byte[2]	hash check
		mpi		signature

	  Since we've already had to write half the packet earlier on in order
	  to hash it, we copy this pre-encoded information across and add the
	  header and trailer around it */
	sMemOpen( &stream, signature, 
			  1 + pgpSizeofLength( extraDataLength + 2 + \
								   signatureDataLength ) + \
			  extraDataLength + 2 + signatureDataLength );
	pgpWritePacketHeader( &stream, PGP_PACKET_SIGNATURE, 
						  extraDataLength + 2 + signatureDataLength );
	swrite( &stream, extraData, extraDataLength );
	swrite( &stream, hash, 2 );			/* Hash check */
	status = swrite( &stream, signatureData, signatureDataLength );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );
	zeroise( extraDataPtr, extraDataLength );
	zeroise( signatureData, CRYPT_MAX_PKCSIZE + 128 );
	if( extraDataPtr != extraData )
		clFree( "createSignaturePGP", extraDataPtr );

	return( status );
	}

/* Check a PGP signature */

static int checkSignaturePGP( const void *signature, const int signatureLength,
							  const CRYPT_CONTEXT sigCheckContext,
							  const CRYPT_CONTEXT iHashContext )
	{
	QUERY_INFO queryInfo;
	STREAM stream;
	int status;

	/* Determine whether there are any authenticated attributes attached to 
	   the signature */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, signature, signatureLength );
	status = sigReadTable[ SIGNATURE_PGP ]( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* After hashing the content, PGP also hashes in extra authenticated
	   attributes */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
							  queryInfo.attributeStart, 
							  queryInfo.attributeLength );
	if( cryptStatusOK( status ) && queryInfo.attributeLength != 5 )
		{
		BYTE buffer[ 8 ], *bufPtr = buffer + 2;

		/* In addition to the standard authenticated attributes, OpenPGP
		   hashes in even more stuff at the end */
		buffer[ 0 ] = 0x04;
		buffer[ 1 ] = 0xFF;
		mputLong( bufPtr, queryInfo.attributeLength );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  buffer, 6 );
		}
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	if( cryptStatusOK( status ) )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the signature */
	return( checkSignature( signature, signatureLength, sigCheckContext, 
							iHashContext, CRYPT_UNUSED, SIGNATURE_PGP ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*							Extended Create/Check a Signature 				*
*																			*
****************************************************************************/

/* Create/check an extended signature type */

C_RET cryptCreateSignatureEx( C_OUT void C_PTR signature, 
							  C_IN int signatureMaxLength,
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_HANDLE extraData )
	{
	BOOLEAN isCertChain = FALSE;
	int certType, value, status;

	/* Perform basic error checking.  We have to use an internal message to
	   check for signing capability because the DLP algorithms have 
	   specialised data-formatting requirements that can't normally be 
	   directly accessed via external messages, and even the non-DLP
	   algorithms may be internal-use-only if there's a cert attached to 
	   the context.  If we're performing a sign operation this is OK since 
	   they're being used from cryptlib-internal routines, but to make sure
	   that the context is OK we first check its external accessibility by
	   performing a dummy attribute read */
	if( signature != NULL )
		{
		if( signatureMaxLength < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isWritePtr( signature, signatureMaxLength ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( !isWritePtr( signatureLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*signatureLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || \
		formatType >= CRYPT_FORMAT_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM4 );
	status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( signContext, IMESSAGE_CHECK, NULL, 
							  MESSAGE_CHECK_PKC_SIGN );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_HASH );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM6 : status );

	/* If the signing context has a cert chain attached, the currently-
	   selected cert may not be the leaf cert.  To ensure that we use the
	   correct cert, we lock the chain (which both protects us from having 
	   the user select a different cert while we're using it, and saves the 
	   selection state for when we later unlock it) and explicitly select 
	   the leaf cert */
	status = krnlSendMessage( signContext, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		status = krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
		isCertChain = TRUE;
		}

	/* Call the low-level signature create function to create the 
	   signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_AUTO:
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature, there can't be any extra
			   signing attributes present */
			if( extraData != CRYPT_USE_DEFAULT )
				{
				status = CRYPT_ERROR_PARAM7;
				break;
				}

			status = createSignature( signature, signatureLength, 
									  signatureMaxLength, signContext, 
									  hashContext, CRYPT_UNUSED, 
									  SIGNATURE_CRYPTLIB );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			/* Make sure that the signing context has a cert attached to 
			   it */
			status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				{
				status = CRYPT_ERROR_PARAM5;
				break;
				}

			/* Make sure that the extra data object is in order */
			if( extraData != CRYPT_USE_DEFAULT )
				{
				status = krnlSendMessage( extraData, MESSAGE_GETATTRIBUTE,
										  &certType, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) || \
					certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
					{
					status = CRYPT_ERROR_PARAM7;
					break;
					}
				}

			status = createSignatureCMS( signature, signatureLength, 
										 signatureMaxLength, signContext, 
										 hashContext, extraData, 
										 CRYPT_UNUSED, formatType );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = createSignaturePGP( signature, signatureLength, 
										 signatureMaxLength, signContext, 
										 hashContext );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_PARAM4;
		}
	if( isCertChain )
		/* We're signing with a cert chain, restore its state and unlock it 
		   to allow others access */
		krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptArgError( status ) )
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM5 : CRYPT_ERROR_PARAM6;
	return( status );
	}

C_RET cryptCreateSignature( C_OUT void C_PTR signature, 
							C_IN int signatureMaxLength,
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext )
	{
	int status;

	status = cryptCreateSignatureEx( signature, signatureMaxLength,
									 signatureLength, CRYPT_FORMAT_CRYPTLIB,
									 signContext, hashContext,
									 CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		{
		/* Remap parameter errors to the correct position */
		if( status == CRYPT_ERROR_PARAM5 )
			status = CRYPT_ERROR_PARAM4;
		if( status == CRYPT_ERROR_PARAM6 )
			status = CRYPT_ERROR_PARAM5;
		}
	return( status );
	}

static CRYPT_FORMAT_TYPE getFormatType( const void *data )
	{
	STREAM stream;
	const BYTE *dataPtr = data;
#ifdef USE_PGP
	long length;
#endif /* USE_PGP */
	int status;

	/* Figure out what we've got.  A PKCS #7/CMS/SMIME signature begins:
		cryptlibSignature ::= SEQUENCE {
			version		INTEGER (3),
			keyID [ 0 ]	OCTET STRING
	   while a CMS signature begins:
		cmsSignature ::= SEQUENCE {
			version		INTEGER (1),
			digestAlgo	SET OF {
	   which allows us to determine which type of object we have */
	if( *dataPtr == BER_SEQUENCE )
		{
		CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;

		sMemConnect( &stream, data, 16 );
		status = readSequence( &stream, NULL );
		if( cryptStatusOK( status ) )
			{
			long version;

			if( cryptStatusOK( readShortInteger( &stream, &version ) ) )
				formatType = ( version == 1 ) ? CRYPT_FORMAT_CMS : \
							 ( version == 3 ) ? CRYPT_FORMAT_CRYPTLIB : \
							 CRYPT_FORMAT_NONE;
			}
		sMemDisconnect( &stream );

		return( formatType );
		}

#ifdef USE_PGP
	/* It's not ASN.1 data, check for PGP data */
	sMemConnect( &stream, data, 16 );
	status = pgpReadPacketHeader( &stream, NULL, &length );
	if( cryptStatusOK( status ) && length > 30 && length < 8192 )
		{
		sMemDisconnect( &stream );
		return( CRYPT_FORMAT_PGP );
		}
	sMemDisconnect( &stream );
#endif /* USE_PGP */

	return( CRYPT_FORMAT_NONE );
	}

C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN int signatureLength,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT CRYPT_HANDLE C_PTR extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT sigCheckContext;
	int status;

	/* Perform basic error checking */
	if( signature != NULL )
		{
		if( signatureLength < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isReadPtr( signature, signatureLength ) )
			return( CRYPT_ERROR_PARAM1 );
		}
	if( ( formatType = getFormatType( signature ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );
	status = krnlSendMessage( sigCheckKey, MESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigCheckContext, IMESSAGE_CHECK, 
								  NULL, MESSAGE_CHECK_PKC_SIGCHECK );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_HASH );
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM4;
		}
	else
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM3;
	if( cryptStatusError( status ) )
		return( status );
	if( formatType == CRYPT_FORMAT_CMS )
		{
		int certType;

		/* Make sure that the sig check key includes a cert */
		status = krnlSendMessage( sigCheckKey, MESSAGE_GETATTRIBUTE,
								  &certType, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			return( CRYPT_ERROR_PARAM3 );
		}

	/* Call the low-level signature check function to check the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature, there can't be any extra
			   signing attributes present */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );

			status = checkSignature( signature, signatureLength, 
									 sigCheckContext, hashContext, 
									 CRYPT_UNUSED, SIGNATURE_CRYPTLIB );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			if( extraData != NULL )
				{
				if( !isWritePtr( extraData, sizeof( int ) ) )
					return( CRYPT_ERROR_PARAM6 );
				*extraData = CRYPT_ERROR;
				}
			status = checkSignatureCMS( signature, signatureLength, 
										sigCheckContext, hashContext, 
										extraData, sigCheckKey );
			if( cryptStatusOK( status ) && extraData != NULL )
				/* Make the recovered signing attributes externally 
				   visible */
				krnlSendMessage( *extraData, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE, 
								 CRYPT_IATTRIBUTE_INTERNAL );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			/* PGP doesn't have signing attributes */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );
			status = checkSignaturePGP( signature, signatureLength, 
										sigCheckContext, hashContext );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_PARAM4 );
		}

	if( cryptArgError( status ) )
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM3 : CRYPT_ERROR_PARAM4;
	return( status );
	}

C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN int signatureLength,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext )
	{
	return( cryptCheckSignatureEx( signature, signatureLength, sigCheckKey, 
								   hashContext, NULL ) );
	}

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions that have already checked the parameters for validity.  In
   addition the iExtraData value can take an extra value CRYPT_UNUSED 
   (don't use any signing attributes) */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const int sigMaxLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_HANDLE iExtraData,
							 const CRYPT_SESSION iTspSession )
	{
	BOOLEAN isCertChain = FALSE;
	int certType, status;

	/* Clear return value */
	*signatureLength = 0;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			( signature != NULL && \
			  sigMaxLength > 64 && sigMaxLength < 32768 ) );
	assert( signature == NULL || isWritePtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( checkHandleRange( iSignContext ) );
	assert( checkHandleRange( iHashContext ) );

	/* If the signing context has a cert chain attached, the currently-
	   selected cert may not be the leaf cert.  To ensure that we use the
	   correct cert, we lock the chain (which both protects us from having 
	   the user select a different cert while we're using it, and saves the 
	   selection state for when we later unlock it) and explicitly select 
	   the leaf cert */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		status = krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
		isCertChain = TRUE;
		}

	/* Call the low-level signature create function to create the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			status = createSignature( signature, signatureLength, 
									  sigMaxLength, iSignContext, 
									  iHashContext, CRYPT_UNUSED, 
									  SIGNATURE_CRYPTLIB );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = createSignaturePGP( signature, signatureLength, 
										 sigMaxLength, iSignContext, 
										 iHashContext );
			break;
#endif /* USE_PGP */

#ifdef USE_SSL
		case CRYPT_IFORMAT_SSL:
			status = createSignature( signature, signatureLength, 
									  sigMaxLength, iSignContext, 
									  iHashContext, iExtraData, 
									  SIGNATURE_SSL );
			break;
#endif /* USE_SSL */

		case CRYPT_IFORMAT_SSH:
			status = createSignature( signature, signatureLength, 
									  sigMaxLength, iSignContext, 
									  iHashContext, CRYPT_UNUSED, 
									  SIGNATURE_SSH );
			break;

		default:
			status = createSignatureCMS( signature, signatureLength, 
										 sigMaxLength, iSignContext, 
										 iHashContext, iExtraData,
										 iTspSession, formatType );
		}
	if( isCertChain )
		/* If we're signing with a cert chain, restore its state and unlock 
		   it to allow others access */
		krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );

	return( status );
	}

int iCryptCheckSignatureEx( const void *signature, const int signatureLength,
							const CRYPT_FORMAT_TYPE formatType,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData )
	{
	CRYPT_CONTEXT sigCheckContext;
	int status;

	assert( isReadPtr( signature, signatureLength ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( checkHandleRange( iSigCheckKey ) );
	assert( checkHandleRange( iHashContext ) );

	/* Perform basic error checking */
	status = krnlSendMessage( iSigCheckKey, IMESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the low-level signature check function to check the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			return( checkSignature( signature, signatureLength, 
									sigCheckContext, iHashContext, 
									CRYPT_UNUSED, SIGNATURE_CRYPTLIB ) );

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			return( checkSignaturePGP( signature, signatureLength, 
									   sigCheckContext, iHashContext ) );
#endif /* USE_PGP */

#ifdef USE_SSL
		case CRYPT_IFORMAT_SSL:
			return( checkSignature( signature, signatureLength, 
									sigCheckContext, iHashContext, 
									*extraData, SIGNATURE_SSL ) );
#endif /* USE_SSL */

		case CRYPT_IFORMAT_SSH:
			return( checkSignature( signature, signatureLength, 
									sigCheckContext, iHashContext, 
									CRYPT_UNUSED, SIGNATURE_SSH ) );
		}

	if( extraData != NULL )
		*extraData = CRYPT_ERROR;
	return( checkSignatureCMS( signature, signatureLength, sigCheckContext, 
							   iHashContext, extraData, iSigCheckKey ) );
	}
