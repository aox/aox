/****************************************************************************
*																			*
*							X.509/PKI Signature Routines					*
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
						 const CRYPT_CONTEXT iSignContext,
						 const CRYPT_ALGO_TYPE hashAlgo,
						 const int formatInfo, const int extraDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	BYTE dataSignature[ CRYPT_MAX_PKCSIZE + 128 + 8 ];
	int signatureLength, totalSigLength, status;

	assert( ( signedObject == NULL && sigMaxLength == 0 ) || \
			isWritePtr( signedObject, sigMaxLength ) );
	assert( isWritePtr( signedObjectLength, sizeof( int ) ) );
	assert( isReadPtr( object, objectLength ) && \
			checkObjectEncoding( object, objectLength ) > 0 );
	assert( isHandleRangeValid( iSignContext ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( ( formatInfo == CRYPT_UNUSED && extraDataLength == 0 ) || \
			( formatInfo > 0 && extraDataLength >= 0 ) );

	/* Hash the data to be signed */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 ( void * ) object, objectLength );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							  ( void * ) object, 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the signature and calculate the overall length of the payload, 
	   optional signature wrapper, and signature data */
	status = createSignature( dataSignature, &signatureLength, 
							  CRYPT_MAX_PKCSIZE + 128, iSignContext, 
							  createInfo.cryptHandle, CRYPT_UNUSED, 
							  SIGNATURE_X509 );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	if( formatInfo == CRYPT_UNUSED )
		totalSigLength = signatureLength + extraDataLength;
	else
		{
		/* It's a nonstandard format, figure out the size due to the 
		   additional signature wrapper */
		if( !( formatInfo & 0x80 ) )
			totalSigLength = ( int ) \
				sizeofObject( signatureLength + extraDataLength );
		else
			totalSigLength = ( int ) \
				sizeofObject( sizeofObject( signatureLength + extraDataLength ) );
		}

	/* Write the outer SEQUENCE wrapper and copy the payload into place 
	   behind it */
	sMemOpen( &stream, signedObject, sigMaxLength );
	writeSequence( &stream, objectLength + totalSigLength );
	swrite( &stream, object, objectLength );

	/* If it's a nonstandard (b0rken PKI protocol) signature, we have to 
	   kludge in a variety of additional wrappers around the signature */
	if( formatInfo != CRYPT_UNUSED )
		{
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
		}

	/* Finally, append the signature */
	status = swrite( &stream, dataSignature, signatureLength );
	*signedObjectLength = stell( &stream );
	sMemDisconnect( &stream );
	assert( extraDataLength > 0 || \
			checkObjectEncoding( signedObject, *signedObjectLength ) > 0 );

	return( status );
	}

int checkX509signature( const void *signedObject, const int signedObjectLength,
						const CRYPT_CONTEXT sigCheckContext,
						const int formatInfo )
	{
	CRYPT_ALGO_TYPE signAlgo, sigCheckAlgo, hashAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	void *objectPtr, *sigPtr;
	long length;
	int status, sigLength;

	assert( isReadPtr( signedObject, signedObjectLength ) );
	assert( isHandleRangeValid( sigCheckContext ) );
	assert( ( formatInfo == CRYPT_UNUSED ) || ( formatInfo >= 0 ) );

	/* Make sure that the signing parameters are in order */
	status = krnlSendMessage( sigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &sigCheckAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the start of the object and record the start and size of the
	   encapsulated signed object.  We have to use the long-length form of
	   the length functions to handle mega-CRLs */
	sMemConnect( &stream, signedObject, signedObjectLength );
	readLongSequence( &stream, NULL );
	objectPtr = sMemBufPtr( &stream );
	length = getLongStreamObjectLength( &stream );
	if( !cryptStatusError( length ) )
		/* Move past the object */
		status = sSkip( &stream, length );
	else
		status = ( int ) length;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* If it's a broken signature, process the extra encapsulation */
	if( formatInfo != CRYPT_UNUSED )
		{
		if( !( formatInfo & 0x80 ) )
			status = readConstructed( &stream, NULL, formatInfo );
		else
			{
			readConstructed( &stream, NULL, formatInfo & 0x7F );
			status = readSequence( &stream, NULL );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}

	/* Remember the location and size of the signature data */
	sigPtr = sMemBufPtr( &stream );
	sigLength = sMemDataLeft( &stream );
	status = readAlgoIDex( &stream, &signAlgo, &hashAlgo, NULL );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If the signature algorithm isn't what we expected, the best that we
	   can do is report a signature error */
	if( sigCheckAlgo != signAlgo )
		return( CRYPT_ERROR_SIGNATURE );

	/* Create a hash context from the algorithm identifier of the
	   signature */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the signed data and check the signature on the object */
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 objectPtr, length );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							  objectPtr, 0 );
	if( cryptStatusOK( status ) )
		status = checkSignature( sigPtr, sigLength, sigCheckContext,
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
	assert( isWritePtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isHandleRangeValid( iHashContext ) );

	return( createSignature( signature, signatureLength, sigMaxLength,
							 iSignContext, iHashContext, CRYPT_UNUSED,
							 SIGNATURE_RAW ) );
	}

int checkRawSignature( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT iSigCheckContext,
					   const CRYPT_CONTEXT iHashContext )
	{
	assert( isReadPtr( signature, signatureLength ) );
	assert( isHandleRangeValid( iSigCheckContext ) );
	assert( isHandleRangeValid( iHashContext ) );

	return( checkSignature( signature, signatureLength, iSigCheckContext,
							iHashContext, CRYPT_UNUSED, SIGNATURE_RAW ) );
	}
