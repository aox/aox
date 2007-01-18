/****************************************************************************
*																			*
*						cryptlib Internal Envelope API						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Data Wrap/Unwrap Functions						*
*																			*
****************************************************************************/

/* General-purpose enveloping functions, used by various high-level
   protocols */

int envelopeWrap( const void *inData, const int inDataLength, void *outData,
				  int *outDataLength, const int outDataMaxLength,
				  const CRYPT_FORMAT_TYPE formatType,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_HANDLE iCryptKey )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength + 512 );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 && \
			outDataMaxLength >= inDataLength + 512 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( contentType == CRYPT_CONTENT_NONE || \
			( contentType > CRYPT_CONTENT_NONE && \
			  contentType < CRYPT_CONTENT_LAST ) );
	assert( ( iCryptKey == CRYPT_UNUSED ) || \
			isHandleRangeValid( iCryptKey ) );

	/* Clear return value */
	*outDataLength = 0;

	/* Create an envelope to wrap the data, add the encryption key if
	   necessary, and pop the wrapped result */
	setMessageCreateObjectInfo( &createInfo, formatType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &inDataLength,
							  CRYPT_ENVINFO_DATASIZE );
	if( cryptStatusOK( status ) && contentType != CRYPT_CONTENT_NONE )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &contentType,
								  CRYPT_ENVINFO_CONTENTTYPE );
	if( cryptStatusOK( status ) && iCryptKey != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iCryptKey,
								  CRYPT_ENVINFO_PUBLICKEY );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) inData, inDataLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		if( cryptStatusOK( status ) && msgData.length < inDataLength )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_OVERFLOW;
			}
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		if( cryptStatusOK( status ) && msgData.length >= outDataMaxLength )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_OVERFLOW;
			}
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

int envelopeUnwrap( const void *inData, const int inDataLength,
					void *outData, int *outDataLength,
					const int outDataMaxLength,
					const CRYPT_CONTEXT iDecryptKey )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 && \
			outDataMaxLength >= inDataLength );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( ( iDecryptKey == CRYPT_UNUSED ) || \
			isHandleRangeValid( iDecryptKey ) );

	/* Clear return value */
	*outDataLength = 0;

	/* Create an envelope to unwrap the data, add the decryption key if
	   necessary, and pop the unwrapped result */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	setMessageData( &msgData, ( void * ) inData, inDataLength );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) && msgData.length < inDataLength )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_OVERFLOW;
		}
	if( status == CRYPT_ENVELOPE_RESOURCE )
		{
		/* If the caller wasn't expecting encrypted data, let them know */
		if( iDecryptKey == CRYPT_UNUSED )
			status = CRYPT_ERROR_WRONGKEY;
		else
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
									  ( void * ) &iDecryptKey,
									  CRYPT_ENVINFO_PRIVATEKEY );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		if( cryptStatusOK( status ) && msgData.length >= outDataMaxLength )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_OVERFLOW;
			}
		}

	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

/****************************************************************************
*																			*
*							Data Sign/Verify Functions						*
*																			*
****************************************************************************/

int envelopeSign( const void *inData, const int inDataLength,
				  void *outData, int *outDataLength,
				  const int outDataMaxLength,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_CONTEXT iSigKey,
				  const CRYPT_CERTIFICATE iCmsAttributes )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength + 1024 );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 || \
			( contentType == CRYPT_CONTENT_NONE && \
			  isHandleRangeValid( iCmsAttributes ) && \
			  inDataLength == 0 ) );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 && \
			outDataMaxLength >= inDataLength + 512 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( contentType >= CRYPT_CONTENT_NONE && \
			contentType < CRYPT_CONTENT_LAST );
	assert( isHandleRangeValid( iSigKey ) );
	assert( iCmsAttributes == CRYPT_UNUSED || \
			isHandleRangeValid( iCmsAttributes ) );

	/* Clear return value */
	*outDataLength = 0;

	/* Create an envelope to sign the data, add the signature key and
	   optional signing attributes, and pop the signed result */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_CMS );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &inDataLength,
							  CRYPT_ENVINFO_DATASIZE );
	if( cryptStatusOK( status ) && contentType != CRYPT_CONTENT_NONE )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &contentType,
								  CRYPT_ENVINFO_CONTENTTYPE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iSigKey,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) && iCmsAttributes != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iCmsAttributes,
								  CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
	if( cryptStatusOK( status ) )
		{
		/* If there's no data supplied, it's an attributes-only message
		   containing only authenticated attributes */
		if( inDataLength <= 0 )
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE,
									  CRYPT_IATTRIBUTE_ATTRONLY );
		else
			{
			setMessageData( &msgData, ( void * ) inData, inDataLength );
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
									  &msgData, 0 );
			if( cryptStatusOK( status ) && msgData.length < inDataLength )
				{
				assert( NOTREACHED );
				status = CRYPT_ERROR_OVERFLOW;
				}
			}
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		if( cryptStatusOK( status ) && msgData.length >= outDataMaxLength )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_OVERFLOW;
			}
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

int envelopeSigCheck( const void *inData, const int inDataLength,
					  void *outData, int *outDataLength,
					  const int outDataMaxLength,
					  const CRYPT_CONTEXT iSigCheckKey,
					  int *sigResult, CRYPT_CERTIFICATE *iSigningCert,
					  CRYPT_CERTIFICATE *iCmsAttributes )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 && \
			outDataMaxLength >= inDataLength );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( iSigCheckKey == CRYPT_UNUSED || \
			isHandleRangeValid( iSigCheckKey ) );
	assert( isWritePtr( sigResult, sizeof( int ) ) );

	/* Clear return values */
	*outDataLength = 0;
	*sigResult = CRYPT_ERROR;
	if( iSigningCert != NULL )
		*iSigningCert = CRYPT_ERROR;
	if( iCmsAttributes != NULL )
		*iCmsAttributes = CRYPT_ERROR;

	/* Create an envelope to sig.check the data, push in the signed data and
	   sig.check key, and pop the result.  We also speculatively set the
	   attributes-only flag to let the enveloping code know that a signed
	   message with no content is a zero-data-length message rather than a
	   detached signature, which is what this type of message would normally
	   be */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_ATTRONLY );
	setMessageData( &msgData, ( void * ) inData, inDataLength );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) && msgData.length < inDataLength )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_OVERFLOW;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) && iSigCheckKey != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iSigCheckKey,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
								  sigResult, CRYPT_ENVINFO_SIGNATURE_RESULT );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		if( cryptStatusOK( status ) && msgData.length >= outDataMaxLength )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_OVERFLOW;
			}
		}
	if( cryptStatusOK( status ) && iSigningCert != NULL )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
								  iSigningCert,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) )
		{
		if( iCmsAttributes != NULL )
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
									  iCmsAttributes,
									  CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
		if( cryptStatusError( status ) && iSigningCert != NULL )
			{
			krnlSendNotifier( *iSigningCert, IMESSAGE_DECREFCOUNT );
			*iSigningCert = CRYPT_ERROR;
			}
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}
