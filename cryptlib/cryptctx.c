/****************************************************************************
*																			*
*					  cryptlib Encryption Context Routines					*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions"
												- Don Alvarez */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "context.h"
  #include "asn1.h"
#else
  #include "context/context.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* The default size of the salt for PKCS #5v2 key derivation, needed when we
   set the CRYPT_CTXINFO_KEYING_VALUE */

#define PKCS5_SALT_SIZE		8	/* 64 bits */

/* The number of bytes of data that we check to make sure the encryption
   operation succeeded (see the comment in encryptData() before changing 
   this) */

#define ENCRYPT_CHECKSIZE	16

/* Prototypes for functions in ctx_misc.c */

const CAPABILITY_INFO FAR_BSS *findCapabilityInfo(
					const CAPABILITY_INFO_LIST *capabilityInfoList,
					const CRYPT_ALGO_TYPE cryptAlgo );

/* Prototypes for functions in keyload.c */

void initKeyHandling( CONTEXT_INFO *contextInfoPtr );
int initKeyParams( CONTEXT_INFO *contextInfoPtr, const void *iv,
				   const int ivLength, const CRYPT_MODE_TYPE mode );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( CONTEXT_INFO *contextInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( contextInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( CONTEXT_INFO *contextInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( contextInfoPtr, errorLocus, 
					   CRYPT_ERRTYPE_ATTR_PRESENT, CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotInited( CONTEXT_INFO *contextInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( contextInfoPtr, errorLocus, 
					   CRYPT_ERRTYPE_ATTR_ABSENT, CRYPT_ERROR_NOTINITED ) );
	}

static int exitErrorNotFound( CONTEXT_INFO *contextInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( contextInfoPtr, errorLocus, 
					   CRYPT_ERRTYPE_ATTR_ABSENT, CRYPT_ERROR_NOTFOUND ) );
	}

/* Convert a key attribute type into a key format type */

static int attributeToFormatType( const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	switch( attribute )
		{
		case CRYPT_IATTRIBUTE_KEY_SSH1:
			return( KEYFORMAT_SSH1 );

		case CRYPT_IATTRIBUTE_KEY_SSH2:
			return( KEYFORMAT_SSH2 );

		case CRYPT_IATTRIBUTE_KEY_SSL:
			return( KEYFORMAT_SSL );

		case CRYPT_IATTRIBUTE_KEY_PGP:
		case CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL:
			return( KEYFORMAT_PGP );
		
		case CRYPT_IATTRIBUTE_KEY_SPKI:
		case CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL:
			return( KEYFORMAT_CERT );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Clear temporary bignum values used during PKC operations */

void clearTempBignums( PKC_INFO *pkcInfo )
	{
	BN_clear( &pkcInfo->tmp1 );
	BN_clear( &pkcInfo->tmp2 );
	BN_clear( &pkcInfo->tmp3 );
	BN_CTX_clear( &pkcInfo->bnCTX );
	}

/****************************************************************************
*																			*
*								Misc. Context Functions						*
*																			*
****************************************************************************/

/* Initialise pointers to context-specific storage areas */

static void initContextStorage( CONTEXT_INFO *contextInfoPtr, 
								const int storageSize )
	{
	switch( contextInfoPtr->type )
		{
		case CONTEXT_CONV:
			contextInfoPtr->ctxConv = ( CONV_INFO * ) contextInfoPtr->storage;
			contextInfoPtr->ctxConv->key = contextInfoPtr->storage + storageSize;
			break;

		case CONTEXT_HASH:
			contextInfoPtr->ctxHash = ( HASH_INFO * ) contextInfoPtr->storage;
			contextInfoPtr->ctxHash->hashInfo = contextInfoPtr->storage + storageSize;
			break;

		case CONTEXT_MAC:
			contextInfoPtr->ctxMAC = ( MAC_INFO * ) contextInfoPtr->storage;
			contextInfoPtr->ctxMAC->macInfo = contextInfoPtr->storage + storageSize;
			break;

		case CONTEXT_PKC:
			contextInfoPtr->ctxPKC = ( PKC_INFO * ) contextInfoPtr->storage;
			break;
		}
	}

/* Perform any context-specific checks that a context meets the given 
   requirements (general checks have already been performed by the kernel).  
   Although these checks are automatically performed by the kernel when we 
   try and use the context, they're duplicated here to allow for better 
   error reporting by catching problems when the context is first passed to 
   a cryptlib function rather than much later and at a lower level when the 
   kernel disallows the action */

static int checkContext( CONTEXT_INFO *contextInfoPtr,
						 const MESSAGE_CHECK_TYPE checkType )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;

	/* If it's a check that an object's ready for key generation (which is 
	   algorithm-type independent), we check it before performing any 
	   algorithm-specific checks */
	if( checkType == MESSAGE_CHECK_KEYGEN_READY )
		{
		if( !needsKey( contextInfoPtr ) )
			return( exitErrorInited( contextInfoPtr, CRYPT_CTXINFO_KEY ) );
		return( CRYPT_OK );
		}

	/* If it's a check for the (potential) ability to perform conventional 
	   encryption or MAC'ing at some point in the future, without currently
	   having a key loaded for the task, we're done */
	if( checkType == MESSAGE_CHECK_CRYPT_READY || \
		checkType == MESSAGE_CHECK_MAC_READY )
		return( CRYPT_OK );

	/* Perform general checks */
	if( contextInfoPtr->type != CONTEXT_HASH && needsKey( contextInfoPtr ) )
		return( exitErrorNotInited( contextInfoPtr, CRYPT_CTXINFO_KEY ) );

	/* If it's a hash, MAC, conventional encryption, or basic PKC check, 
	   we're done */
	if( checkType == MESSAGE_CHECK_CRYPT || \
		checkType == MESSAGE_CHECK_HASH || \
		checkType == MESSAGE_CHECK_MAC || \
		checkType == MESSAGE_CHECK_PKC )
		return( CRYPT_OK );

	/* Check for key-agreement algorithms */
	if( isKeyxAlgo( capabilityInfoPtr->cryptAlgo ) )
		/* DH can never be used for encryption or signatures (if it is then
		   we call it Elgamal) and KEA is explicitly for key agreement only.
		   Note that the status of DH is a bit ambiguous in that every DH key
		   is both a public and private key, in order to avoid confusion in 
		   situations where we're checking for real private keys we always 
		   denote a DH context as key-agreement only without taking a side 
		   about whether it's a public or private key */
		return( ( checkType == MESSAGE_CHECK_PKC_KA_EXPORT || \
				  checkType == MESSAGE_CHECK_PKC_KA_IMPORT ) ? \
				CRYPT_OK : CRYPT_ARGERROR_OBJECT );
	if( checkType == MESSAGE_CHECK_PKC_KA_EXPORT || \
		checkType == MESSAGE_CHECK_PKC_KA_IMPORT )
		return( CRYPT_ARGERROR_OBJECT );	/* Must be a key agreement algorithm */

	/* We're down to various public-key checks */
	assert( checkType == MESSAGE_CHECK_PKC_PRIVATE || \
			checkType == MESSAGE_CHECK_PKC_ENCRYPT || \
			checkType == MESSAGE_CHECK_PKC_DECRYPT || \
			checkType == MESSAGE_CHECK_PKC_SIGCHECK || \
			checkType == MESSAGE_CHECK_PKC_SIGN || \
			checkType == MESSAGE_CHECK_CA );

	/* Check that it's a private key if this is required */
	if( ( checkType == MESSAGE_CHECK_PKC_PRIVATE || \
		  checkType == MESSAGE_CHECK_PKC_DECRYPT || \
		  checkType == MESSAGE_CHECK_PKC_SIGN ) && \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		return( CRYPT_ARGERROR_OBJECT );

	return( CRYPT_OK );
	}

/* Derive a key into a context from a user-supplied keying value */

static int deriveKey( CONTEXT_INFO *contextInfoPtr, void *keyValue, 
					  const int keyValueLen )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( contextInfoPtr->type == CONTEXT_CONV || \
			contextInfoPtr->type == CONTEXT_MAC );
	assert( needsKey( contextInfoPtr ) );
	assert( isReadPtr( keyValue, keyValueLen ) );

	/* Set up various derivation parameters if they're not already set.  
	   Since there's only one MUST MAC algorithm for PKCS #5v2, we always 
	   force the key derivation algorithm to this value to avoid interop 
	   problems */
	if( contextInfoPtr->type == CONTEXT_CONV )
		{
		CONV_INFO *convInfo = contextInfoPtr->ctxConv;

		if( convInfo->saltLength <= 0 )
			{
			RESOURCE_DATA nonceMsgData;

			setMessageData( &nonceMsgData, convInfo->salt, PKCS5_SALT_SIZE );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &nonceMsgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusError( status ) )
				return( status );
			convInfo->saltLength = PKCS5_SALT_SIZE;
			}
		convInfo->keySetupAlgorithm = CRYPT_ALGO_HMAC_SHA;
		setMechanismDeriveInfo( &mechanismInfo, convInfo->userKey,
				capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE, 
									contextInfoPtr, convInfo->userKeyLength ),
				keyValue, keyValueLen, convInfo->keySetupAlgorithm,
				convInfo->salt, convInfo->saltLength, 
				convInfo->keySetupIterations );
		if( mechanismInfo.iterations <= 0 )
			{
			krnlSendMessage( contextInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE, 
							 &mechanismInfo.iterations, 
							 CRYPT_OPTION_KEYING_ITERATIONS );
			convInfo->keySetupIterations = mechanismInfo.iterations;
			}
		}
	else
		{
		MAC_INFO *macInfo = contextInfoPtr->ctxMAC;

		if( macInfo->saltLength <= 0 )
			{
			RESOURCE_DATA nonceMsgData;

			setMessageData( &nonceMsgData, macInfo->salt, PKCS5_SALT_SIZE );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &nonceMsgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusError( status ) )
				return( status );
			macInfo->saltLength = PKCS5_SALT_SIZE;
			}
		contextInfoPtr->ctxConv->keySetupAlgorithm = CRYPT_ALGO_HMAC_SHA;
		setMechanismDeriveInfo( &mechanismInfo, macInfo->userKey,
				capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE, 
									contextInfoPtr, macInfo->userKeyLength ),
				keyValue, keyValueLen, macInfo->keySetupAlgorithm,
				macInfo->salt, macInfo->saltLength,
				macInfo->keySetupIterations );
		if( mechanismInfo.iterations <= 0 )
			{
			krnlSendMessage( contextInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE, 
							 &mechanismInfo.iterations, 
							 CRYPT_OPTION_KEYING_ITERATIONS );
			macInfo->keySetupIterations = mechanismInfo.iterations;
			}
		}

	/* Turn the user key into an encryption context key and load the key 
	   into the context */
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
							  &mechanismInfo, MECHANISM_DERIVE_PKCS5 );
	if( cryptStatusOK( status ) )
		status = contextInfoPtr->loadKeyFunction( contextInfoPtr,
												  mechanismInfo.dataOut,
												  mechanismInfo.dataOutLength );
	if( cryptStatusOK( status ) )
		{
		contextInfoPtr->flags |= CONTEXT_KEY_SET | CONTEXT_EPHEMERAL;
		if( contextInfoPtr->type == CONTEXT_MAC )
			contextInfoPtr->flags |= CONTEXT_HASH_INITED;
		}
	return( status );
	}

/* Load an encoded composite key into a context.  This is used for two 
   purposes, to load public key components into native contexts and to save 
   encoded public-key values for use in certs associated with non-native 
   contexts held in a device.  The latter is necessary because there's no 
   key data stored with the context itself, however it's necessary to have 
   SubjectPublicKeyInfo available for certificate requests/certificates.  
   Normally this is sufficient because cryptlib always generates native 
   contexts for public keys/certs, and for private keys the data is generated 
   in the device with the encoded public components attached to the context 
   as described above.
			   
   For DH keys this gets a bit more complex, since although the private key 
   is generated in the device, in the case of the DH responder this is only 
   the DH x value, with the parameters (p and g) being supplied externally 
   by the initiator.  This means that it's necessary to decode at least some 
   of the public key data in order to create the y value after the x value 
   has been generated in the device.

   The only situation where this functionality is currently needed is for the 
   SSHv2 code, which at the moment always uses native DH contexts.  For this 
   reason we leave off resolving this issue until it's actually required */

static int setKey( CONTEXT_INFO *contextInfoPtr, 
				   const CRYPT_ATTRIBUTE_TYPE keyType, const void *keyData, 
				   const int keyDataLen )
	{
	static const int actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	static const int actionFlagsDH = ACTION_PERM_NONE_EXTERNAL_ALL;
	static const int actionFlagsPGP = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	STREAM stream;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( contextInfoPtr->type == CONTEXT_PKC );
	assert( needsKey( contextInfoPtr ) || \
			( contextInfoPtr->flags & CONTEXT_DUMMY ) );
	assert( keyType == CRYPT_IATTRIBUTE_KEY_SPKI || \
			keyType == CRYPT_IATTRIBUTE_KEY_PGP || \
			keyType == CRYPT_IATTRIBUTE_KEY_SSH1 || \
			keyType == CRYPT_IATTRIBUTE_KEY_SSH2 || \
			keyType == CRYPT_IATTRIBUTE_KEY_SSL || \
			keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL || \
			keyType == CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL );
	assert( isReadPtr( keyData, keyDataLen ) );

	/* If the keys are held externally (e.g. in a crypto device), copy the 
	   encoded public key data in and set up any other information that we 
	   may need from it.  This information is used when loading a context 
	   from a key contained in a device, where the actual key components 
	   aren't directly available in the context but may be needed in the 
	   future for things like cert requests and certs */
	if( contextInfoPtr->flags & CONTEXT_DUMMY )
		{
		assert( keyType == CRYPT_IATTRIBUTE_KEY_SPKI || \
				keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );

		if( ( contextInfoPtr->ctxPKC->publicKeyInfo = \
				clAlloc( "processSetAttributeS", keyDataLen ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( contextInfoPtr->ctxPKC->publicKeyInfo, keyData, keyDataLen );
		contextInfoPtr->ctxPKC->publicKeyInfoSize = keyDataLen;
		return( calculateKeyID( contextInfoPtr ) );
		}

	/* Read the appropriately-formatted key data into the context, applying 
	   a lowest-common-denominator set of usage flags to the loaded key 
	   (more specific usage restrictions will be set by higher-level code) */
	sMemConnect( &stream, keyData, keyDataLen );
	status = contextInfoPtr->ctxPKC->readPublicKeyFunction( &stream,
										contextInfoPtr, 
										attributeToFormatType( keyType ) );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a partial load of the initial public portions of a private 
	   key with further key component operations to follow, there's nothing 
	   more to do at this point and we're done */
	if( keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL || \
		keyType == CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL )
		return( calculateKeyID( contextInfoPtr ) );

	/* Perform an internal load that uses the key component values that 
	   we've just read into the context */
	contextInfoPtr->flags |= CONTEXT_ISPUBLICKEY;
	status = contextInfoPtr->loadKeyFunction( contextInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) )
		/* Map the status to a more appropriate code if necessary */
		return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
	contextInfoPtr->flags |= CONTEXT_KEY_SET;

	/* Restrict the key usage to public-key-only actions if necessary.  For 
	   PGP key loads (which, apart from the restrictions specified with the 
	   stored key data aren't constrained by the presence of ACLs in the 
	   form of certs) we allow external usage, for DH (whose keys can be 
	   both public and private keys even though technically it's a public 
	   key) we allow both encryption and decryption usage, and for public 
	   keys read from certs we  allow internal usage only */
	status = krnlSendMessage( contextInfoPtr->objectHandle,
						IMESSAGE_SETATTRIBUTE, 
						( keyType == CRYPT_IATTRIBUTE_KEY_PGP ) ? \
							( void * ) &actionFlagsPGP : \
						( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH ) ? \
							( void * ) &actionFlagsDH : \
							( void * ) &actionFlags,
						CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		return( status );
	contextInfoPtr->flags |= CONTEXT_KEY_SET;
	return( calculateKeyID( contextInfoPtr ) );
	}

/* Load a composite key into a context */

static int setKeyComponents( CONTEXT_INFO *contextInfoPtr, 
							 const void *keyData, const int keyDataLen )
	{
	static const int actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( contextInfoPtr->type == CONTEXT_PKC );
	assert( needsKey( contextInfoPtr ) );
	assert( isReadPtr( keyData, keyDataLen ) );
	assert( keyDataLen == sizeof( CRYPT_PKCINFO_RSA ) || \
			keyDataLen == sizeof( CRYPT_PKCINFO_DLP ) );

	/* We need to have a key label set before we can continue */
	if( contextInfoPtr->labelSize <= 0 )
		return( exitErrorNotInited( contextInfoPtr, CRYPT_CTXINFO_LABEL ) );

	/* Load the key components into the context */
	status = contextInfoPtr->loadKeyFunction( contextInfoPtr, keyData, 
											  keyDataLen );
	if( cryptStatusError( status ) )
		return( status );
	contextInfoPtr->flags |= CONTEXT_KEY_SET | CONTEXT_EPHEMERAL | CONTEXT_PBO;

	/* Restrict the key usage to public-key-only actions if it's a public 
	   key.  DH keys act as both public and private keys so we don't 
	   restrict their usage */
	if( ( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) && \
		( capabilityInfoPtr->cryptAlgo != CRYPT_ALGO_DH ) )
		status = krnlSendMessage( contextInfoPtr->objectHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( void * ) &actionFlags,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	return( status );
	}

/* Encrypt a block of data */

static int encryptData( CONTEXT_INFO *contextInfoPtr, void *data, 
						const int dataLength )
	{
	BYTE savedData[ ENCRYPT_CHECKSIZE ];
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	const int savedDataLength = min( dataLength, ENCRYPT_CHECKSIZE );
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( contextInfoPtr->type == CONTEXT_CONV || \
			contextInfoPtr->type == CONTEXT_PKC );
	assert( contextInfoPtr->encryptFunction != NULL );
	assert( isWritePtr( data, dataLength ) );

	if( contextInfoPtr->type == CONTEXT_PKC )
		{
		const BOOLEAN isDLP = isDlpAlgo( capabilityInfoPtr->cryptAlgo );

		/* Key agreement algorithms are treated as a special case since they 
		   don't actually encrypt the data */
		if( isKeyxAlgo( capabilityInfoPtr->cryptAlgo ) )
			{
			assert( dataLength == sizeof( KEYAGREE_PARAMS ) );

			status = contextInfoPtr->encryptFunction( contextInfoPtr, data, 
													  dataLength );
			clearTempBignums( contextInfoPtr->ctxPKC );
			return( status );
			}

		assert( !isDLP || dataLength == sizeof( DLP_PARAMS ) );

		memcpy( savedData, isDLP ? ( ( DLP_PARAMS * ) data )->inParam1 : \
								   data, ENCRYPT_CHECKSIZE );
		status = contextInfoPtr->encryptFunction( contextInfoPtr, data, 
												  dataLength );
		if( cryptStatusError( status ) )
			{
			zeroise( savedData, ENCRYPT_CHECKSIZE );
			clearTempBignums( contextInfoPtr->ctxPKC );
			return( status );
			}

		/* Check for a catastrophic failure of the encryption */
		if( isDLP )
			{
			DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) data;

			if( !memcmp( savedData, dlpParams->outParam, ENCRYPT_CHECKSIZE ) )
				{
				zeroise( dlpParams->outParam, dlpParams->outLen );
				status = CRYPT_ERROR_FAILED;
				}
			}
		else
			if( !memcmp( savedData, data, ENCRYPT_CHECKSIZE ) )
				{
				zeroise( data, dataLength );
				status = CRYPT_ERROR_FAILED;
				}
		zeroise( savedData, ENCRYPT_CHECKSIZE );
		return( status );
		}

	assert( isStreamCipher( capabilityInfoPtr->cryptAlgo ) || \
			!needsIV( contextInfoPtr->ctxConv->mode ) ||
			( contextInfoPtr->flags & CONTEXT_IV_SET ) );
	assert( contextInfoPtr->ctxConv->key == \
			contextInfoPtr->storage + sizeof( CONV_INFO ) );

	memcpy( savedData, data, savedDataLength );
	status = contextInfoPtr->encryptFunction( contextInfoPtr, data, 
											  dataLength );
	if( cryptStatusError( status ) || savedDataLength <= 6 )
		{
		zeroise( savedData, ENCRYPT_CHECKSIZE );
		return( status );
		}

	/* Check for a catastrophic failure of the encryption.  A check of
	   a single block unfortunately isn't completely foolproof for 64-bit
	   blocksize ciphers in CBC mode because of the way the IV is applied to 
	   the input.  For the CBC encryption operation:
					
		out = enc( in ^ IV )
						
	   if out == IV the operation turns into a no-op.  Consider the simple 
	   case where IV == in, so IV ^ in == 0.  Then out = enc( 0 ) == IV, 
	   with the input appearing again at the output.  In fact this can occur 
	   during normal operation once every 2^32 blocks (for a 64-bit block 
	   cipher).  Although the chances of this happening are fairly low (the 
	   collision would have to occur on the first encrypted block in a 
	   message, since that's the one we check), if possible we check the 
	   first two blocks if we're using a 64-bit block cipher in CBC mode in 
	   order to reduce false positives */
	if( !memcmp( savedData, data, savedDataLength ) )
		{
		zeroise( data, dataLength );
		status = CRYPT_ERROR_FAILED;
		}
	zeroise( savedData, ENCRYPT_CHECKSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*						Context Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a context */

static int processGetAttribute( CONTEXT_INFO *contextInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	const CONTEXT_TYPE contextType = contextInfoPtr->type;
	int *valuePtr = ( int * ) messageDataPtr, value;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = contextInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = contextInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_OPTION_MISC_SIDECHANNELPROTECTION:
			*valuePtr = ( contextInfoPtr->flags & \
						  CONTEXT_SIDECHANNELPROTECTION ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_ALGO:
			*valuePtr = capabilityInfoPtr->cryptAlgo;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_MODE:
			assert( contextType == CONTEXT_CONV );
			*valuePtr = contextInfoPtr->ctxConv->mode;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYSIZE:
			switch( contextType )
				{
				case CONTEXT_CONV:
					value = contextInfoPtr->ctxConv->userKeyLength;
					break;

				case CONTEXT_PKC:
					value = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
					break;

				case CONTEXT_MAC:
					value = contextInfoPtr->ctxMAC->userKeyLength;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			if( value <= 0 )
				/* If a key hasn't been loaded yet, we return the default
				   key size */
				value = capabilityInfoPtr->keySize;
			*valuePtr = value;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_BLOCKSIZE:
			if( contextType == CONTEXT_CONV && \
				( contextInfoPtr->ctxConv->mode == CRYPT_MODE_CFB || \
				  contextInfoPtr->ctxConv->mode == CRYPT_MODE_OFB ) )
				*valuePtr = 1;	/* Block cipher in stream mode */
			else
				*valuePtr = capabilityInfoPtr->blockSize;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_IVSIZE:
			assert( contextType == CONTEXT_CONV );
			if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
				isStreamCipher( capabilityInfoPtr->cryptAlgo ) )
				return( CRYPT_ERROR_NOTAVAIL );
			*valuePtr = capabilityInfoPtr->blockSize;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_ALGO:
		case CRYPT_OPTION_KEYING_ALGO:
			switch( contextType )
				{
				case CONTEXT_CONV:
					value = contextInfoPtr->ctxConv->keySetupAlgorithm;
					break;

				case CONTEXT_MAC:
					value = contextInfoPtr->ctxMAC->keySetupAlgorithm;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			if( value <= 0 )
				return( exitErrorNotInited( contextInfoPtr,
											CRYPT_CTXINFO_KEYING_ALGO ) );
			*valuePtr = value;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_ITERATIONS:
		case CRYPT_OPTION_KEYING_ITERATIONS:
			switch( contextType )
				{
				case CONTEXT_CONV:
					value = contextInfoPtr->ctxConv->keySetupIterations;
					break;

				case CONTEXT_MAC:
					value = contextInfoPtr->ctxMAC->keySetupIterations;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			if( value <= 0 )
				return( exitErrorNotInited( contextInfoPtr,
											CRYPT_CTXINFO_KEYING_ITERATIONS ) );
			*valuePtr = value;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_KEYFEATURES:
			assert( contextType == CONTEXT_PKC );
			*valuePtr = ( contextInfoPtr->flags & CONTEXT_PBO ) ? 1 : 0;
#ifdef USE_DEVICES
			*valuePtr |= ( contextInfoPtr->deviceObject > 0 ) ? 2 : 0;
#endif /* USE_DEVICES */
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_DEVICEOBJECT:
#ifdef USE_DEVICES
			if( contextInfoPtr->deviceObject < 0 )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = ( int ) contextInfoPtr->deviceObject;
			return( CRYPT_OK );
#else
			return( CRYPT_ERROR_NOTFOUND );
#endif /* USE_DEVICES */
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( CONTEXT_INFO *contextInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	const CONTEXT_TYPE contextType = contextInfoPtr->type;
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int status;

	switch( messageValue )
		{
		case CRYPT_CTXINFO_NAME_ALGO:
			return( attributeCopy( msgData, capabilityInfoPtr->algoName,
								   strlen( capabilityInfoPtr->algoName ) ) );

		case CRYPT_CTXINFO_NAME_MODE:
			assert( contextType == CONTEXT_CONV );
			switch( contextInfoPtr->ctxConv->mode )
				{
				case CRYPT_MODE_ECB:
					return( attributeCopy( msgData, "ECB", 3 ) );
				case CRYPT_MODE_CBC:
					return( attributeCopy( msgData, "CBC", 3 ) );
				case CRYPT_MODE_CFB:
					return( attributeCopy( msgData, "CFB", 3 ) );
				case CRYPT_MODE_OFB:
					return( attributeCopy( msgData, "OFB", 3 ) );
				}
			assert( NOTREACHED );
			return( CRYPT_ERROR );	/* Get rid of compiler warning */

		case CRYPT_CTXINFO_KEYING_SALT:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			if( contextType == CONTEXT_CONV )
				{
				if( contextInfoPtr->ctxConv->saltLength <= 0 )
					return( exitErrorInited( contextInfoPtr,
											 CRYPT_CTXINFO_KEYING_SALT ) );
				return( attributeCopy( msgData, contextInfoPtr->ctxConv->salt,
									   contextInfoPtr->ctxConv->saltLength ) );
				}
			if( contextInfoPtr->ctxMAC->saltLength <= 0 )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_KEYING_SALT ) );
			return( attributeCopy( msgData, contextInfoPtr->ctxMAC->salt,
								   contextInfoPtr->ctxMAC->saltLength ) );

		case CRYPT_CTXINFO_IV:
			assert( contextType == CONTEXT_CONV );
			if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
				isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
				return( CRYPT_ERROR_NOTAVAIL );
			if( !( contextInfoPtr->flags & CONTEXT_IV_SET ) )
				return( exitErrorNotInited( contextInfoPtr, CRYPT_CTXINFO_IV ) );
			return( attributeCopy( msgData, contextInfoPtr->ctxConv->iv,
								   contextInfoPtr->ctxConv->ivLength ) );

		case CRYPT_CTXINFO_HASHVALUE:
			assert( contextType == CONTEXT_HASH || \
					contextType == CONTEXT_MAC );
			if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
				return( CRYPT_ERROR_NOTINITED );
			if( !( contextInfoPtr->flags & CONTEXT_HASH_DONE ) )
				return( CRYPT_ERROR_INCOMPLETE );
			return( attributeCopy( msgData, ( contextType == CONTEXT_HASH ) ? \
										contextInfoPtr->ctxHash->hash : \
										contextInfoPtr->ctxMAC->mac,
								   capabilityInfoPtr->blockSize ) );

		case CRYPT_CTXINFO_LABEL:
			if( contextInfoPtr->labelSize <= 0 )
				return( exitErrorNotInited( contextInfoPtr,
											CRYPT_CTXINFO_LABEL ) );
			return( attributeCopy( msgData, contextInfoPtr->label,
								   contextInfoPtr->labelSize ) );

		case CRYPT_IATTRIBUTE_KEYID:
			assert( contextType == CONTEXT_PKC );
			return( attributeCopy( msgData, contextInfoPtr->ctxPKC->keyID,
								   KEYID_SIZE ) );

		case CRYPT_IATTRIBUTE_KEYID_PGP:
			assert( contextType == CONTEXT_PKC );
			if( contextInfoPtr->capabilityInfo->cryptAlgo != CRYPT_ALGO_RSA )
				return( CRYPT_ERROR_NOTFOUND );
			return( attributeCopy( msgData, contextInfoPtr->ctxPKC->pgpKeyID,
								   PGP_KEYID_SIZE ) );

		case CRYPT_IATTRIBUTE_KEYID_OPENPGP:
			assert( contextType == CONTEXT_PKC );
			assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA || \
					contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
					contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL );
			return( attributeCopy( msgData, contextInfoPtr->ctxPKC->openPgpKeyID,
								   PGP_KEYID_SIZE ) );

#ifdef USE_KEA
		case CRYPT_IATTRIBUTE_KEY_KEADOMAINPARAMS:
			assert( contextType == CONTEXT_PKC );
			return( attributeCopy( msgData, contextInfoPtr->ctxPKC->domainParamPtr,
								   contextInfoPtr->ctxPKC->domainParamSize ) );

		case CRYPT_IATTRIBUTE_KEY_KEAPUBLICVALUE:
			assert( contextType == CONTEXT_PKC );
			return( attributeCopy( msgData, contextInfoPtr->ctxPKC->publicValuePtr,
								   contextInfoPtr->ctxPKC->publicValueSize ) );
#else
		case CRYPT_IATTRIBUTE_KEY_KEADOMAINPARAMS:
		case CRYPT_IATTRIBUTE_KEY_KEAPUBLICVALUE:
			return( CRYPT_ERROR_NOTFOUND );
#endif /* USE_KEA */

		case CRYPT_IATTRIBUTE_KEY_SPKI:
			assert( contextType == CONTEXT_PKC );
			assert( contextInfoPtr->flags & CONTEXT_KEY_SET );
			if( contextInfoPtr->ctxPKC->publicKeyInfo != NULL )
				/* If the data is available in pre-encoded form, copy it
				   out */
				return( attributeCopy( msgData, contextInfoPtr->ctxPKC->publicKeyInfo,
									   contextInfoPtr->ctxPKC->publicKeyInfoSize ) );
			/* Drop through */

		case CRYPT_IATTRIBUTE_KEY_SSH1:
		case CRYPT_IATTRIBUTE_KEY_SSH2:
		case CRYPT_IATTRIBUTE_KEY_SSL:
			{
			STREAM stream;

			assert( contextType == CONTEXT_PKC );
			assert( contextInfoPtr->flags & CONTEXT_KEY_SET );

			/* Write the appropriately-formatted key data from the context */
			sMemOpen( &stream, msgData->data, msgData->length );
			status = contextInfoPtr->ctxPKC->writePublicKeyFunction( &stream,
							contextInfoPtr,
							attributeToFormatType( messageValue ), "public" );
			if( cryptStatusOK( status ) )
				msgData->length = stell( &stream );
			sMemDisconnect( &stream );
			return( status );
			}

		case CRYPT_IATTRIBUTE_PGPVALIDITY:
			assert( contextType == CONTEXT_PKC );
			*( ( time_t * ) msgData->data ) = \
									contextInfoPtr->ctxPKC->pgpCreationTime;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( CONTEXT_INFO *contextInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	const CONTEXT_TYPE contextType = contextInfoPtr->type;
	const int value = *( ( int * ) messageDataPtr );
	int *valuePtr;
	int status;

	switch( messageValue )
		{
		case CRYPT_OPTION_MISC_SIDECHANNELPROTECTION:
			if( value )
				contextInfoPtr->flags |= CONTEXT_SIDECHANNELPROTECTION;
			else
				contextInfoPtr->flags &= ~CONTEXT_SIDECHANNELPROTECTION;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_MODE:
			assert( contextType == CONTEXT_CONV );

			/* If the mode isn't set to the initial default, it's already
			   been explicitly set and we can't change it again */
			if( contextInfoPtr->ctxConv->mode != \
						( isStreamCipher( capabilityInfoPtr->cryptAlgo ) ? \
						CRYPT_MODE_OFB : CRYPT_MODE_CBC ) )
				return( exitErrorInited( contextInfoPtr, CRYPT_CTXINFO_MODE ) );

			/* Set the en/decryption mode */
			assert( capabilityInfoPtr->initKeyParamsFunction != NULL );
			return( capabilityInfoPtr->initKeyParamsFunction( contextInfoPtr,
													NULL, 0, value ) );

		case CRYPT_CTXINFO_KEYSIZE:
			assert( capabilityInfoPtr->getInfoFunction != NULL );
			switch( contextType )
				{
				case CONTEXT_CONV:
					valuePtr = &contextInfoPtr->ctxConv->userKeyLength;
					break;

				case CONTEXT_PKC:
					valuePtr = &contextInfoPtr->ctxPKC->keySizeBits;
					break;

				case CONTEXT_MAC:
					valuePtr = &contextInfoPtr->ctxMAC->userKeyLength;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			if( *valuePtr )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_KEYSIZE ) );

			/* Trim the user-supplied value to the correct shape, taking
			   into account various issues such as limitations with the
			   underlying crypto code/hardware and the (in)ability to export
			   overly long keys using short public keys */
			status = capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE,
														 contextInfoPtr, value );
			if( cryptStatusError( status ) )
				return( status );
			*valuePtr = ( contextType == CONTEXT_PKC ) ? \
						bytesToBits( status ) : status;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_ALGO:
		case CRYPT_OPTION_KEYING_ALGO:
			{
			CRYPT_ALGO_TYPE *algoValuePtr;

			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			algoValuePtr = ( contextType == CONTEXT_CONV ) ? \
						   &contextInfoPtr->ctxConv->keySetupAlgorithm : \
						   &contextInfoPtr->ctxMAC->keySetupAlgorithm;
			if( *algoValuePtr != CRYPT_ALGO_NONE )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_KEYING_ALGO ) );
			*algoValuePtr = value;
			return( CRYPT_OK );
			}

		case CRYPT_CTXINFO_KEYING_ITERATIONS:
		case CRYPT_OPTION_KEYING_ITERATIONS:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			valuePtr = ( contextType == CONTEXT_CONV ) ? \
					   &contextInfoPtr->ctxConv->keySetupIterations : \
					   &contextInfoPtr->ctxMAC->keySetupIterations;
			if( *valuePtr )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_KEYING_ITERATIONS ) );
			*valuePtr = value;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_INITIALISED:
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_KEYSIZE:
			/* If the key is held outside the context (e.g. in a device), we
			   need to manually supply the key-related information needed by 
			   the context, which in this case is the key size.  Once this 
			   is set, there is (effectively) a key loaded, although the 
			   actual keying values are held anderswhere */
			switch( contextType )
				{
				case CONTEXT_CONV:
					contextInfoPtr->ctxConv->userKeyLength = value;
					break;

				case CONTEXT_PKC:
					if( contextInfoPtr->labelSize <= 0 )
						/* PKC context must have a key label set */
						return( exitErrorNotInited( contextInfoPtr,
													CRYPT_CTXINFO_LABEL ) );
					contextInfoPtr->ctxPKC->keySizeBits = bytesToBits( value );
					break;

				case CONTEXT_MAC:
					contextInfoPtr->ctxMAC->userKeyLength = value;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			contextInfoPtr->flags |= CONTEXT_KEY_SET;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_DEVICEOBJECT:
#ifdef USE_DEVICES
			contextInfoPtr->deviceObject = value;
#endif /* USE_DEVICES */
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttributeS( CONTEXT_INFO *contextInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	const CONTEXT_TYPE contextType = contextInfoPtr->type;
	const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int status;

	switch( messageValue )
		{
		case CRYPT_CTXINFO_KEYING_SALT:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			if( contextType == CONTEXT_CONV )
				{
				if( contextInfoPtr->ctxConv->saltLength > 0 )
					return( exitErrorInited( contextInfoPtr,
											 CRYPT_CTXINFO_KEYING_SALT ) );
				memcpy( contextInfoPtr->ctxConv->salt, msgData->data,
						msgData->length );
				contextInfoPtr->ctxConv->saltLength = msgData->length;
				return( CRYPT_OK );
				}
			if( contextInfoPtr->ctxMAC->saltLength > 0 )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_KEYING_SALT ) );
			memcpy( contextInfoPtr->ctxMAC->salt, msgData->data,
					msgData->length );
			contextInfoPtr->ctxMAC->saltLength = msgData->length;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_VALUE:
			return( deriveKey( contextInfoPtr, msgData->data, 
							   msgData->length ) );

		case CRYPT_CTXINFO_KEY:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			assert( needsKey( contextInfoPtr ) );

			/* The kernel performs a general check on the size of this
			   attribute but doesn't know about context subtype-specific
			   limits, so we perform a context-specific check here */
			if( msgData->length < capabilityInfoPtr->minKeySize || \
				msgData->length > capabilityInfoPtr->maxKeySize )
				return( CRYPT_ARGERROR_NUM1 );

			/* Load the key into the context */
			status = contextInfoPtr->loadKeyFunction( contextInfoPtr,
										msgData->data, msgData->length );
			if( cryptStatusOK( status ) )
				{
				contextInfoPtr->flags |= CONTEXT_KEY_SET | CONTEXT_EPHEMERAL;
				if( contextType == CONTEXT_MAC )
					contextInfoPtr->flags |= CONTEXT_HASH_INITED;
				}
			return( status );

#ifndef USE_FIPS140
		case CRYPT_CTXINFO_KEY_COMPONENTS:
			return( setKeyComponents( contextInfoPtr, msgData->data, 
									  msgData->length ) );
#endif /* USE_FIPS140 */

		case CRYPT_CTXINFO_IV:
			assert( contextType == CONTEXT_CONV );

			/* If it's a mode that doesn't use an IV, the load IV operation
			   is meaningless */
			if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
				isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
				return( CRYPT_ERROR_NOTAVAIL );

			/* Make sure that the data size is valid */
			if( msgData->length != capabilityInfoPtr->blockSize )
				return( CRYPT_ARGERROR_NUM1 );

			/* Load the IV */
			assert( capabilityInfoPtr->initKeyParamsFunction != NULL );
			return( capabilityInfoPtr->initKeyParamsFunction( contextInfoPtr,
								msgData->data, msgData->length, CRYPT_MODE_NONE ) );

		case CRYPT_CTXINFO_LABEL:
			if( contextInfoPtr->labelSize > 0 )
				return( exitErrorInited( contextInfoPtr,
										 CRYPT_CTXINFO_LABEL ) );

			/* Check any device object that the context is associated with 
			   to ensure that nothing with that label already exists in the
			   device.  For keysets the check for duplicates is performed 
			   when the context is explicitly added to the keyset, but with 
			   devices the context will be implicitly created within the 
			   device at some future point that depends on the device (at 
			   context creation, on key load/generation, or at some other 
			   point).  Because of this we perform a pre-emptive check for 
			   duplicates to avoid a potentially confusing error condition 
			   at some point in the future.  In addition, we can't send the 
			   message to the context because the kernel won't forward this 
			   message type (sending a get-key message to a context doesn't 
			   make sense) so we have to explicitly get the dependent device 
			   and send the get-key directly to it */
			if( contextType == CONTEXT_PKC )
				{
				CRYPT_HANDLE cryptHandle;

				status = krnlSendMessage( contextInfoPtr->objectHandle,
										  IMESSAGE_GETDEPENDENT,
										  &cryptHandle, OBJECT_TYPE_DEVICE );
				if( cryptStatusOK( status ) )
					{
					MESSAGE_KEYMGMT_INFO getkeyInfo;

					setMessageKeymgmtInfo( &getkeyInfo,
										CRYPT_KEYID_NAME, msgData->data,
										msgData->length, NULL, 0,
										KEYMGMT_FLAG_CHECK_ONLY );
					status = krnlSendMessage( contextInfoPtr->objectHandle,
										MESSAGE_KEY_GETKEY, &getkeyInfo,
										KEYMGMT_ITEM_PUBLICKEY );
					if( cryptStatusError( status ) )
						{
						setMessageKeymgmtInfo( &getkeyInfo,
										CRYPT_KEYID_NAME, msgData->data,
										msgData->length, NULL, 0,
										KEYMGMT_FLAG_CHECK_ONLY );
						status = krnlSendMessage( contextInfoPtr->objectHandle,
										MESSAGE_KEY_GETKEY, &getkeyInfo,
										KEYMGMT_ITEM_PRIVATEKEY );
						}
					if( cryptStatusOK( status ) )
						/* We found something with this label already 
						   present, we can't use it again */
						return( CRYPT_ERROR_DUPLICATE );
					}
				}

			/* Set the label */
			memcpy( contextInfoPtr->label, msgData->data, msgData->length );
			contextInfoPtr->labelSize = msgData->length;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_KEYID_OPENPGP:
			assert( contextType == CONTEXT_PKC );
			assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA || \
					contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
					contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL );
			assert( msgData->length == PGP_KEYID_SIZE );
			memcpy( contextInfoPtr->ctxPKC->openPgpKeyID, msgData->data,
					msgData->length );
			contextInfoPtr->ctxPKC->openPgpKeyIDSet = TRUE;
			return( CRYPT_OK );

		case CRYPT_IATTRIBUTE_KEY_SPKI:
		case CRYPT_IATTRIBUTE_KEY_PGP:
		case CRYPT_IATTRIBUTE_KEY_SSH1:
		case CRYPT_IATTRIBUTE_KEY_SSH2:
		case CRYPT_IATTRIBUTE_KEY_SSL:
		case CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL:
		case CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL:
			return( setKey( contextInfoPtr, messageValue, msgData->data,
							msgData->length ) );

		case CRYPT_IATTRIBUTE_PGPVALIDITY:
			assert( contextType == CONTEXT_PKC );
			contextInfoPtr->ctxPKC->pgpCreationTime = \
									*( ( time_t * ) msgData->data );
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processDeleteAttribute( CONTEXT_INFO *contextInfoPtr,
								   const int messageValue )
	{
	const CONTEXT_TYPE contextType = contextInfoPtr->type;

	switch( messageValue )
		{
		case CRYPT_CTXINFO_KEYING_ALGO:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			if( contextType == CONTEXT_CONV )
				{
				if( contextInfoPtr->ctxConv->keySetupAlgorithm == CRYPT_ALGO_NONE )
					return( exitErrorNotFound( contextInfoPtr,
											   CRYPT_CTXINFO_KEYING_ALGO ) );
				contextInfoPtr->ctxConv->keySetupAlgorithm = CRYPT_ALGO_NONE;
				return( CRYPT_OK );
				}
			if( contextInfoPtr->ctxMAC->keySetupAlgorithm == CRYPT_ALGO_NONE )
				return( exitErrorNotFound( contextInfoPtr,
										   CRYPT_CTXINFO_KEYING_ALGO ) );
			contextInfoPtr->ctxMAC->keySetupAlgorithm = CRYPT_ALGO_NONE;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_ITERATIONS:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			if( contextType == CONTEXT_CONV )
				{
				if( contextInfoPtr->ctxConv->keySetupIterations == 0 )
					return( exitErrorNotFound( contextInfoPtr,
											   CRYPT_CTXINFO_KEYING_ITERATIONS ) );
				contextInfoPtr->ctxConv->keySetupIterations = 0;
				return( CRYPT_OK );
				}
			if( contextInfoPtr->ctxMAC->keySetupIterations == 0 )
				return( exitErrorNotFound( contextInfoPtr,
										   CRYPT_CTXINFO_KEYING_ITERATIONS ) );
			contextInfoPtr->ctxMAC->keySetupIterations = 0;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_KEYING_SALT:
			assert( contextType == CONTEXT_CONV || \
					contextType == CONTEXT_MAC );
			if( contextType == CONTEXT_CONV )
				{
				if( contextInfoPtr->ctxConv->saltLength == 0 )
					return( exitErrorNotFound( contextInfoPtr,
											   CRYPT_CTXINFO_KEYING_SALT ) );
				zeroise( contextInfoPtr->ctxConv->salt, CRYPT_MAX_HASHSIZE );
				contextInfoPtr->ctxConv->saltLength = 0;
				return( CRYPT_OK );
				}
			if( contextInfoPtr->ctxMAC->saltLength == 0 )
				return( exitErrorNotFound( contextInfoPtr,
										   CRYPT_CTXINFO_KEYING_SALT ) );
			zeroise( contextInfoPtr->ctxMAC->salt, CRYPT_MAX_HASHSIZE );
			contextInfoPtr->ctxMAC->saltLength = 0;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_IV:
			assert( contextType == CONTEXT_CONV );
			if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
				isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
				return( exitErrorNotFound( contextInfoPtr,
										   CRYPT_CTXINFO_IV ) );
			contextInfoPtr->ctxConv->ivLength = \
					contextInfoPtr->ctxConv->ivCount = 0;
			contextInfoPtr->flags &= ~CONTEXT_IV_SET;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_LABEL:
			if( contextInfoPtr->labelSize == 0 )
				return( exitErrorNotFound( contextInfoPtr,
										   CRYPT_CTXINFO_LABEL ) );
			zeroise( contextInfoPtr->label, contextInfoPtr->labelSize );
			contextInfoPtr->labelSize = 0;
			return( CRYPT_OK );

		case CRYPT_CTXINFO_HASHVALUE:
			switch( contextType )
				{
				case CONTEXT_HASH:
					zeroise( contextInfoPtr->ctxHash->hash, CRYPT_MAX_HASHSIZE );
					break;

				case CONTEXT_MAC:
					zeroise( contextInfoPtr->ctxMAC->mac, CRYPT_MAX_HASHSIZE );
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR );
				}
			contextInfoPtr->flags &= ~( CONTEXT_HASH_INITED | \
										CONTEXT_HASH_DONE );
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Context Message Handler						*
*																			*
****************************************************************************/

/* Handle a message sent to an encryption context */

static int contextMessageFunction( const void *objectInfoPtr,
								   const MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	CONTEXT_INFO *contextInfoPtr = ( CONTEXT_INFO * ) objectInfoPtr;
	const CAPABILITY_INFO *capabilityInfo = contextInfoPtr->capabilityInfo;
	int status;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		const CONTEXT_TYPE contextType = contextInfoPtr->type;

#if 0	/* 9/12/02 We can never get here because we can't send a message to a
				   busy object any more */
		/* If the context is busy, abort the async.operation.  We do this by
		   setting the abort flag (which is OK, since the context is about to
		   be destroyed anyway) and then waiting for the busy flag to be
		   cleared */
		contextInfoPtr->flags |= CONTEXT_ASYNC_ABORT;
		krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, &status,
						 CRYPT_IATTRIBUTE_STATUS );
		if( status & OBJECT_FLAG_BUSY )
			{
			/* Unlock the object so that the background thread can access it.
			   Nothing else will get in because the object is in the
			   signalled state */
			unlockResource( contextInfoPtr );

			/* Wait awhile and check whether we've left the busy state */
			do
				{
				THREAD_SLEEP( 250 );	/* Wait 1/4s */
				krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
								 &status, CRYPT_IATTRIBUTE_STATUS );
				}
			while( status & OBJECT_FLAG_BUSY );

			getCheckInternalResource( cryptContext, contextInfoPtr, OBJECT_TYPE_CONTEXT );
			}
#endif /* 0 */

		/* Perform any algorithm-specific shutdown */
		if( capabilityInfo->endFunction != NULL )
			capabilityInfo->endFunction( contextInfoPtr );

		/* Perform context-type-specific cleanup */
		if( contextType == CONTEXT_PKC )
			{
			PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

			BN_clear_free( &pkcInfo->param1 );
			BN_clear_free( &pkcInfo->param2 );
			BN_clear_free( &pkcInfo->param3 );
			BN_clear_free( &pkcInfo->param4 );
			BN_clear_free( &pkcInfo->param5 );
			BN_clear_free( &pkcInfo->param6 );
			BN_clear_free( &pkcInfo->param7 );
			BN_clear_free( &pkcInfo->param8 );
			if( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION )
				{
				BN_clear_free( &pkcInfo->blind1 );
				BN_clear_free( &pkcInfo->blind2 );
				}
			BN_clear_free( &pkcInfo->tmp1 );
			BN_clear_free( &pkcInfo->tmp2 );
			BN_clear_free( &pkcInfo->tmp3 );
			BN_MONT_CTX_free( &pkcInfo->montCTX1 );
			BN_MONT_CTX_free( &pkcInfo->montCTX2 );
			BN_MONT_CTX_free( &pkcInfo->montCTX3 );
			BN_CTX_free( &pkcInfo->bnCTX );
			if( pkcInfo->publicKeyInfo != NULL )
				clFree( "contextMessageFunction", pkcInfo->publicKeyInfo );
			}

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( contextInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( contextInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( contextInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( contextInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_DELETEATTRIBUTE )
			return( processDeleteAttribute( contextInfoPtr, messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process action messages */
	if( isActionMessage( message ) )
		{
		assert( message == MESSAGE_CTX_HASH || \
				isWritePtr( messageDataPtr, messageValue ) );

		switch( message )
			{
			case MESSAGE_CTX_ENCRYPT:
				status = encryptData( contextInfoPtr, messageDataPtr, 
									  messageValue );
				assert( cryptStatusOK( status ) );
				break;

			case MESSAGE_CTX_DECRYPT:
				assert( contextInfoPtr->decryptFunction != NULL );

				assert( contextInfoPtr->type == CONTEXT_PKC || \
						( isStreamCipher( capabilityInfo->cryptAlgo ) || \
						  !needsIV( contextInfoPtr->ctxConv->mode ) ||
						  ( contextInfoPtr->flags & CONTEXT_IV_SET ) ) );
				status = contextInfoPtr->decryptFunction( contextInfoPtr,
											messageDataPtr, messageValue );
				if( contextInfoPtr->type == CONTEXT_PKC )
					clearTempBignums( contextInfoPtr->ctxPKC );
				assert( cryptStatusOK( status ) );
				break;

			case MESSAGE_CTX_SIGN:
				assert( capabilityInfo->signFunction != NULL );

				status = capabilityInfo->signFunction( contextInfoPtr,
											messageDataPtr, messageValue );
				clearTempBignums( contextInfoPtr->ctxPKC );
				assert( cryptStatusOK( status ) );
				break;

			case MESSAGE_CTX_SIGCHECK:
				assert( capabilityInfo->sigCheckFunction != NULL );
				status = capabilityInfo->sigCheckFunction( contextInfoPtr,
											messageDataPtr, messageValue );
				clearTempBignums( contextInfoPtr->ctxPKC );
				break;

			case MESSAGE_CTX_HASH:
				assert( capabilityInfo->encryptFunction != NULL );
				assert( ( contextInfoPtr->type == CONTEXT_HASH && \
						  contextInfoPtr->ctxHash->hashInfo == \
								contextInfoPtr->storage + sizeof( HASH_INFO ) ) || \
						( contextInfoPtr->type == CONTEXT_MAC && \
						  contextInfoPtr->ctxMAC->macInfo == \
								contextInfoPtr->storage + sizeof( MAC_INFO ) ) );

				/* If we've already completed the hashing/MACing, we can't
				   continue */
				if( contextInfoPtr->flags & CONTEXT_HASH_DONE )
					return( CRYPT_ERROR_COMPLETE );

				status = capabilityInfo->encryptFunction( contextInfoPtr,
											messageDataPtr, messageValue );
				if( messageValue > 0 )
					/* Usually the MAC initialisation happens when we load 
					   the key, but if we've deleted the MAC value to process 
					   another piece of data it'll happen on-demand, so we 
					   have to set the flag here */
					contextInfoPtr->flags |= CONTEXT_HASH_INITED;
				else
					/* Usually a hash of zero bytes is used to wrap up an
					   ongoing hash operation, however it can also be the 
					   only operation if a zero-byte string is being hashed.
					   To handle this we have to set the inited flag as well
					   as the done flag */
					contextInfoPtr->flags |= CONTEXT_HASH_DONE | \
											 CONTEXT_HASH_INITED;
				assert( cryptStatusOK( status ) );
				break;

			default:
				assert( NOTREACHED );
			}
		return( status );
		}

	/* Process messages that compare object properties or clone the object */
	if( message == MESSAGE_COMPARE )
		{
		const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

		assert( messageValue == MESSAGE_COMPARE_HASH || \
				messageValue == MESSAGE_COMPARE_KEYID || \
				messageValue == MESSAGE_COMPARE_KEYID_PGP || \
				messageValue == MESSAGE_COMPARE_KEYID_OPENPGP );

		switch( messageValue )
			{
			case MESSAGE_COMPARE_HASH:
				/* If it's a hash or MAC context, compare the hash value */
				if( !( contextInfoPtr->flags & CONTEXT_HASH_DONE ) )
					return( CRYPT_ERROR_INCOMPLETE );
				if( contextInfoPtr->type == CONTEXT_HASH && \
					msgData->length == capabilityInfo->blockSize && \
					!memcmp( msgData->data, contextInfoPtr->ctxHash->hash,
							 msgData->length ) )
					return( CRYPT_OK );
				if( contextInfoPtr->type == CONTEXT_MAC && \
					msgData->length == capabilityInfo->blockSize && \
					!memcmp( msgData->data, contextInfoPtr->ctxMAC->mac,
							 msgData->length ) )
					return( CRYPT_OK );
				break;

			case MESSAGE_COMPARE_KEYID:
				/* If it's a PKC context, compare the key ID */
				if( contextInfoPtr->type == CONTEXT_PKC && \
					msgData->length == KEYID_SIZE && \
					!memcmp( msgData->data, contextInfoPtr->ctxPKC->keyID,
							 KEYID_SIZE ) )
					return( CRYPT_OK );
				break;

			case MESSAGE_COMPARE_KEYID_PGP:
				/* If it's a PKC context, compare the PGP key ID */
				if( contextInfoPtr->type == CONTEXT_PKC && \
					msgData->length == PGP_KEYID_SIZE && \
					!memcmp( msgData->data, contextInfoPtr->ctxPKC->pgpKeyID,
							 PGP_KEYID_SIZE ) )
					return( CRYPT_OK );
				break;

			case MESSAGE_COMPARE_KEYID_OPENPGP:
				/* If it's a PKC context, compare the OpenPGP key ID */
				if( contextInfoPtr->type == CONTEXT_PKC && \
					contextInfoPtr->ctxPKC->openPgpKeyIDSet && \
					msgData->length == PGP_KEYID_SIZE && \
					!memcmp( msgData->data, contextInfoPtr->ctxPKC->openPgpKeyID,
							 PGP_KEYID_SIZE ) )
					return( CRYPT_OK );
				break;

			default:
				assert( NOTREACHED );
			}

		/* The comparison failed */
		return( CRYPT_ERROR );
		}

	/* Process messages that check a context */
	if( message == MESSAGE_CHECK )
		return( checkContext( contextInfoPtr, messageValue ) );

	/* Process internal notification messages */
	if( message == MESSAGE_CHANGENOTIFY )
		{
		switch( messageValue )
			{
			case MESSAGE_CHANGENOTIFY_STATUS:
				/* If the context is still busy and we're trying to reset 
				   its status from CRYPT_ERROR_TIMEOUT back to CRYPT_OK, set 
				   the abort flag to indicate that the operation which is 
				   keeping it busy should be cancelled, and return an error 
				   so that the busy status is maintained until the context 
				   has processed the abort */
				if( !( contextInfoPtr->flags & CONTEXT_ASYNC_DONE ) )
					{
					contextInfoPtr->flags |= CONTEXT_ASYNC_ABORT;
					return( CRYPT_ERROR_TIMEOUT );
					}

				/* The context finished whatever it was doing, we're back to 
				   normal */
				break;

			case MESSAGE_CHANGENOTIFY_STATE:
				/* State-change reflected down from the controlling cert 
				   object, this doesn't affect us */
				break;

			case MESSAGE_CHANGENOTIFY_OBJHANDLE:
				assert( contextInfoPtr->type == CONTEXT_CONV || \
						contextInfoPtr->type == CONTEXT_HASH || \
						contextInfoPtr->type == CONTEXT_MAC );
				assert( contextInfoPtr->objectHandle != \
						*( ( int * ) messageDataPtr ) );
				assert( contextInfoPtr->ctxConv != \
						( CONV_INFO * ) contextInfoPtr->storage );

				/* We've been cloned, update the object handle and internal 
				   state pointers */
				contextInfoPtr->objectHandle = *( ( int * ) messageDataPtr );
				initContextStorage( contextInfoPtr, 
						( contextInfoPtr->type == CONTEXT_CONV ) ? \
							sizeof( CONV_INFO ) : \
						( contextInfoPtr->type == CONTEXT_HASH ) ? \
							sizeof( HASH_INFO ) : sizeof( MAC_INFO ) );
				break;

			case MESSAGE_CHANGENOTIFY_OWNERHANDLE:
				/* The second stage of a cloning, update the owner handle */
				contextInfoPtr->ownerHandle = *( ( int * ) messageDataPtr );
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR );	/* Get rid of compiler warning */
			}

		return( CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == MESSAGE_CTX_GENKEY )
		{
		assert( contextInfoPtr->type == CONTEXT_CONV || \
				contextInfoPtr->type == CONTEXT_MAC ||
				contextInfoPtr->type == CONTEXT_PKC );
		assert( needsKey( contextInfoPtr ) );

		/* If it's a private key context, we need to have a key label set
		   before we can continue */
		if( contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->labelSize <= 0 )
			{
			setErrorInfo( contextInfoPtr, CRYPT_CTXINFO_LABEL,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* Generate a new key into the context */
		status = contextInfoPtr->generateKeyFunction( contextInfoPtr,
													  messageValue );
		if( cryptStatusOK( status ) )
			/* There's now a key loaded */
			contextInfoPtr->flags |= CONTEXT_KEY_SET | CONTEXT_EPHEMERAL;
		else
			/* If the status is OK_SPECIAL, it's an async keygen that has
			   begun, but that hasn't resulted in the context containing a 
			   key yet */
			if( status == OK_SPECIAL )
				status = CRYPT_OK;
		if( cryptStatusOK( status ) )
			{
			static const int actionFlags = \
				MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
				MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL ) | \
				MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL ) | \
				MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
				MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );

			/* There's a key loaded, disable further key generation.  The
			   kernel won't allow a keygen anyway once the object is in the 
			   high state, but taking this additional step can't hurt */
			status = krnlSendMessage( contextInfoPtr->objectHandle,
									  IMESSAGE_SETATTRIBUTE, 
									  ( void * ) &actionFlags,
									  CRYPT_IATTRIBUTE_ACTIONPERMS );
			}
		return( status );
		}
	if( message == MESSAGE_CTX_GENIV )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ CRYPT_MAX_IVSIZE ];

		assert( contextInfoPtr->type == CONTEXT_CONV );

		/* If it's not a conventional encryption context, or a mode that
		   doesn't use an IV, the generate IV operation is meaningless */
		if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
			isStreamCipher ( capabilityInfo->cryptAlgo ) )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Generate a new IV and load it */
		setMessageData( &msgData, buffer, CRYPT_MAX_IVSIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			status = capabilityInfo->initKeyParamsFunction( contextInfoPtr,
									buffer, CRYPT_USE_DEFAULT, CRYPT_MODE_NONE );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Create an encryption context based on an encryption capability template.
   This is a common function called by devices to create a context once
   they've got the appropriate capability template */

int createContextFromCapability( CRYPT_CONTEXT *cryptContext,
								 const CRYPT_USER cryptOwner,
								 const CAPABILITY_INFO *capabilityInfoPtr,
								 const int objectFlags )
	{
	const CRYPT_ALGO_TYPE cryptAlgo = capabilityInfoPtr->cryptAlgo;
	const CONTEXT_TYPE contextType = \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) ) ? CONTEXT_CONV : \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_PKC ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_PKC ) ) ? CONTEXT_PKC : \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_HASH ) ) ? CONTEXT_HASH : CONTEXT_MAC;
	CONTEXT_INFO *contextInfoPtr;
	BOOLEAN useSideChannelProtection;
	const int createFlags = objectFlags | \
							( needsSecureMemory( contextType ) ? \
							CREATEOBJECT_FLAG_SECUREMALLOC : 0 );
	int actionFlags = 0, actionPerms = ACTION_PERM_ALL;
	int storageSize, stateStorageSize = 0, subType;
	int initStatus = CRYPT_OK, status;

	assert( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST_MAC );

	/* Clear the return values */
	*cryptContext = CRYPT_ERROR;

	/* Get general config information */
	status = krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE,
							  &useSideChannelProtection,
							  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up subtype-specific information */
	switch( contextType )
		{
		case CONTEXT_CONV:
			subType = SUBTYPE_CTX_CONV;
			storageSize = sizeof( CONV_INFO );
			stateStorageSize = \
				capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_STATESIZE,
													NULL, 0 );
			if( capabilityInfoPtr->encryptFunction != NULL || \
				capabilityInfoPtr->encryptCBCFunction != NULL || \
				capabilityInfoPtr->encryptCFBFunction != NULL || \
				capabilityInfoPtr->encryptOFBFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT,
											   ACTION_PERM_ALL );
			if( capabilityInfoPtr->decryptFunction != NULL || \
				capabilityInfoPtr->decryptCBCFunction != NULL || \
				capabilityInfoPtr->decryptCFBFunction != NULL || \
				capabilityInfoPtr->decryptOFBFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT,
											   ACTION_PERM_ALL );
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_GENKEY, ACTION_PERM_ALL );
			break;

		case CONTEXT_PKC:
			subType = SUBTYPE_CTX_PKC;
			storageSize = sizeof( PKC_INFO );
			if( isDlpAlgo( cryptAlgo ) )
				/* The DLP-based PKC's have somewhat specialised usage
				   requirements so we don't allow direct access by users */
				actionPerms = ACTION_PERM_NONE_EXTERNAL;
			if( capabilityInfoPtr->encryptFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT,
											   actionPerms );
			if( capabilityInfoPtr->decryptFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT,
											   actionPerms );
			if( capabilityInfoPtr->signFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN,
											   actionPerms );
			if( capabilityInfoPtr->sigCheckFunction != NULL )
				actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK,
											   actionPerms );
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_GENKEY, ACTION_PERM_ALL );
			break;

		case CONTEXT_HASH:
			subType = SUBTYPE_CTX_HASH;
			storageSize = sizeof( HASH_INFO );
			stateStorageSize = \
				capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_STATESIZE,
													NULL, 0 );
			actionFlags = MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );
			break;

		case CONTEXT_MAC:
			subType = SUBTYPE_CTX_MAC;
			storageSize = sizeof( MAC_INFO );
			stateStorageSize = \
				capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_STATESIZE,
													NULL, 0 );
			actionFlags = MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL ) | \
						  MK_ACTION_PERM( MESSAGE_CTX_GENKEY, ACTION_PERM_ALL );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}
	if( actionFlags == 0 )
		{
		/* There are no actions enabled for this capability, bail out rather 
		   than creating an unusable context */
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Create the context and initialise the variables in it */
	status = krnlCreateObject( ( void ** ) &contextInfoPtr,
							   sizeof( CONTEXT_INFO ) + storageSize + stateStorageSize, 
							   OBJECT_TYPE_CONTEXT, subType, createFlags, 
							   cryptOwner, actionFlags, 
							   contextMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*cryptContext = contextInfoPtr->objectHandle = status;
	contextInfoPtr->ownerHandle = cryptOwner;
	contextInfoPtr->capabilityInfo = capabilityInfoPtr;
	contextInfoPtr->type = contextType;
#ifdef USE_DEVICES
	contextInfoPtr->deviceObject = \
		contextInfoPtr->altDeviceObject = CRYPT_ERROR;
#endif /* USE_DEVICES */
	initContextStorage( contextInfoPtr, storageSize );
	contextInfoPtr->storageSize = storageSize + stateStorageSize;
	if( useSideChannelProtection )
		contextInfoPtr->flags |= CONTEXT_SIDECHANNELPROTECTION;
	if( contextInfoPtr->type == CONTEXT_PKC && \
		!( objectFlags & CREATEOBJECT_FLAG_DUMMY ) )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

		/* Initialise the bignum information */
		BN_init( &pkcInfo->param1 );
		BN_init( &pkcInfo->param2 );
		BN_init( &pkcInfo->param3 );
		BN_init( &pkcInfo->param4 );
		BN_init( &pkcInfo->param5 );
		BN_init( &pkcInfo->param6 );
		BN_init( &pkcInfo->param7 );
		BN_init( &pkcInfo->param8 );
		if( useSideChannelProtection )
			{
			BN_init( &pkcInfo->blind1 );
			BN_init( &pkcInfo->blind2 );
			}
		BN_init( &pkcInfo->tmp1 );
		BN_init( &pkcInfo->tmp2 );
		BN_init( &pkcInfo->tmp3 );
		BN_CTX_init( &pkcInfo->bnCTX );
		BN_MONT_CTX_init( &pkcInfo->montCTX1 );
		BN_MONT_CTX_init( &pkcInfo->montCTX2 );
		BN_MONT_CTX_init( &pkcInfo->montCTX3 );
		}
	if( contextInfoPtr->type == CONTEXT_CONV )
		{
		/* Set the default encryption mode, which is always CBC if possible,
		   and the corresponding en/decryption handler */
		if( capabilityInfoPtr->encryptCBCFunction != NULL )
			{
			contextInfoPtr->ctxConv->mode = CRYPT_MODE_CBC;
			contextInfoPtr->encryptFunction = \
									capabilityInfoPtr->encryptCBCFunction;
			contextInfoPtr->decryptFunction = \
									capabilityInfoPtr->decryptCBCFunction;
			}
		else
			/* There's no CBC mode available, fall back to increasingly
			   sub-optimal choices of mode.  For stream ciphers the only 
			   available mode is OFB so this isn't a problem, but for 
			   block ciphers it'll cause problems because most crypto 
			   protocols only allow CBC mode */
			if( capabilityInfoPtr->encryptCFBFunction != NULL )
				{
				contextInfoPtr->ctxConv->mode = CRYPT_MODE_CFB;
				contextInfoPtr->encryptFunction = \
									capabilityInfoPtr->encryptCFBFunction;
				contextInfoPtr->decryptFunction = \
									capabilityInfoPtr->decryptCFBFunction;
				}
			else
				if( capabilityInfoPtr->encryptOFBFunction != NULL )
					{
					contextInfoPtr->ctxConv->mode = CRYPT_MODE_OFB;
					contextInfoPtr->encryptFunction = \
									capabilityInfoPtr->encryptOFBFunction;
					contextInfoPtr->decryptFunction = \
									capabilityInfoPtr->decryptOFBFunction;
					}
				else
					{
					contextInfoPtr->ctxConv->mode = CRYPT_MODE_ECB;
					contextInfoPtr->encryptFunction = \
									capabilityInfoPtr->encryptFunction;
					contextInfoPtr->decryptFunction = \
									capabilityInfoPtr->decryptFunction;
					}
		}
	else
		{
		/* There's only one possible en/decryption handler */
		contextInfoPtr->encryptFunction = capabilityInfoPtr->encryptFunction;
		contextInfoPtr->decryptFunction = capabilityInfoPtr->decryptFunction;
		}
	if( contextInfoPtr->type != CONTEXT_HASH )
		/* Set up the key handling functions */
		initKeyHandling( contextInfoPtr );
	if( contextInfoPtr->type == CONTEXT_PKC )
		{
		/* Set up the key read/write functions */
		initKeyRead( contextInfoPtr );
		initKeyWrite( contextInfoPtr );
		}

	assert( contextInfoPtr->type == CONTEXT_HASH || \
			( contextInfoPtr->loadKeyFunction != NULL && \
			  contextInfoPtr->generateKeyFunction != NULL ) );
	assert( cryptAlgo == CRYPT_ALGO_DSA || \
			( contextInfoPtr->encryptFunction != NULL && \
			  contextInfoPtr->decryptFunction != NULL ) );
	assert( contextInfoPtr->type != CONTEXT_PKC || \
			( contextInfoPtr->ctxPKC->writePublicKeyFunction != NULL && \
			  contextInfoPtr->ctxPKC->writePrivateKeyFunction != NULL && \
			  contextInfoPtr->ctxPKC->readPublicKeyFunction != NULL && \
			  contextInfoPtr->ctxPKC->readPrivateKeyFunction != NULL ) );

	/* If this is a dummy object, remember that it's just a placeholder, 
	   with actions handled externally */
	if( objectFlags & CREATEOBJECT_FLAG_DUMMY )
		contextInfoPtr->flags |= CONTEXT_DUMMY;

	/* We've finished setting up the object type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( *cryptContext, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) )
		/* The initialisation failed, make the init error the returned status
		   value */
		status = initStatus;
	if( cryptStatusError( status ) )
		{
		*cryptContext = CRYPT_ERROR;
		return( status );
		}
	if( contextInfoPtr->type == CONTEXT_HASH )
		/* If it's a hash context there's no explicit keygen or load so we
		   need to send an "object initialised" message to get the kernel to
		   move it into the high state.  If this isn't done, any attempt to
		   use the object will be blocked */
		krnlSendMessage( *cryptContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	return( CRYPT_OK );
	}

/* Create an encryption context object */

int createContext( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_CONTEXT iCryptContext;
	const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr;
	int status;

	assert( auxDataPtr != NULL );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_ALGO_NONE || \
		createInfo->arg1 >= CRYPT_ALGO_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Find the capability corresponding to the algorithm */
	capabilityInfoPtr = findCapabilityInfo( auxDataPtr, createInfo->arg1 );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Pass the call on to the lower-level create function */
	status = createContextFromCapability( &iCryptContext,
										  createInfo->cryptOwner,
										  capabilityInfoPtr, auxValue );
	if( cryptStatusOK( status ) )
		createInfo->cryptHandle = iCryptContext;
	return( status );
	}
