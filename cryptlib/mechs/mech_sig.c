/****************************************************************************
*																			*
*					cryptlib Signature Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2004						*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_ALL
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in mech_enc.c */

int adjustPKCS1Data( BYTE *outData, const BYTE *inData, const int inLength, 
					 const int keySize );
BOOLEAN pgpCalculateChecksum( BYTE *dataPtr, const int length,
							  const BOOLEAN writeChecksum );
int pgpExtractKey( CRYPT_CONTEXT *iCryptContext, STREAM *stream,
				   const int length );

/****************************************************************************
*																			*
*								Signature Mechanisms 						*
*																			*
****************************************************************************/

/* Perform signing.  There are several variations of this that are handled 
   through common signature mechanism functions */

typedef enum { SIGN_PKCS1, SIGN_SSL } SIGN_TYPE;

/* Perform PKCS #1 signing/sig.checking */

static int sign( MECHANISM_SIGN_INFO *mechanismInfo, const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
	BYTE preSigData[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN useSideChannelProtection;
	int hashSize, hashSize2, length, i, status;

	/* Sanity check the input data */
	assert( ( mechanismInfo->signature == NULL && \
			  mechanismInfo->signatureLength == 0 ) || \
			( mechanismInfo->signatureLength >= 64 ) );

	/* Clear the return value */
	if( mechanismInfo->signature != NULL )
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );

	/* Get various algorithm and config parameters */
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE, &hashAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->signContext,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->signContext, 
								  IMESSAGE_GETATTRIBUTE, 
								  &useSideChannelProtection,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;
		return( CRYPT_OK );
		}

	/* Get the hash data and determine the encoded payload size */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		hashSize = msgData.length;
		if( type == SIGN_SSL )
			{
			setMessageData( &msgData, hash2, CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( mechanismInfo->hashContext2,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_HASHVALUE );
			if( cryptStatusOK( status ) )
				hashSize2 = msgData.length;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the payload as required */
	sMemOpen( &stream, mechanismInfo->signature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			{
			int payloadSize;

			/* Encode the payload using the PKCS #1 format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] */
			payloadSize = sizeofMessageDigest( hashAlgo, hashSize );
			sputc( &stream, 0 );
			sputc( &stream, 1 );
			for( i = 0; i < length - ( payloadSize + 3 ); i++ )
				sputc( &stream, 0xFF );
			sputc( &stream, 0 );
			status = writeMessageDigest( &stream, hashAlgo, hash, hashSize );
			break;
			}

		case SIGN_SSL:
			assert( hashAlgo == CRYPT_ALGO_MD5 );

			/* Encode the payload using the PKCS #1 SSL format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ MD5 hash ][ SHA1 hash ] */
			sputc( &stream, 0 );
			sputc( &stream, 1 );
			for( i = 0; i < length - ( hashSize + hashSize2 + 3 ); i++ )
				sputc( &stream, 0xFF );
			sputc( &stream, 0 );
			swrite( &stream, hash, hashSize );
			status = swrite( &stream, hash2, hashSize2 );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_NOTAVAIL;
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}

	/* If we're using side-channel protection, remember a copy of the 
	   signature data for later so we can check it against the recovered 
	   signature data */
	if( useSideChannelProtection )
		memcpy( preSigData, mechanismInfo->signature, length );

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	mechanismInfo->signatureLength = length;

	/* If we're using side-channel protection, check that the signature 
	   verifies */
	if( useSideChannelProtection )
		{
		BYTE recoveredSignature[ CRYPT_MAX_PKCSIZE + 8 ];

		/* Make sure that the recovered signature data matches what we 
		   signed, unless we're in the unlikely situation that the key
		   isn't valid for sig.checking.  The rationale behind this 
		   operation is covered (in great detail) in ctx_rsa.c */
		memcpy( recoveredSignature, mechanismInfo->signature, length );
		status = krnlSendMessage( mechanismInfo->signContext,
								  IMESSAGE_CTX_SIGCHECK, recoveredSignature,
								  length );
		if( status != CRYPT_ERROR_PERMISSION && \
			status != CRYPT_ERROR_NOTAVAIL && \
			memcmp( preSigData, recoveredSignature, length ) )
			{
			assert( NOTREACHED );
			zeroise( mechanismInfo->signature, length );
			mechanismInfo->signatureLength = 0;
			return( CRYPT_ERROR_FAILED );
			}
		zeroise( recoveredSignature, length );
		zeroise( preSigData, length );
		}

	return( CRYPT_OK );
	}

int sigcheck( MECHANISM_SIGN_INFO *mechanismInfo, const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE contextHashAlgo, hashAlgo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
	int length, hashSize, hashSize2 = 0, ch, i, status;

	/* Sanity check the input data */
	assert( mechanismInfo->signatureLength >= 60 );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE, &contextHashAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Format the input data as required for the sig check to work */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_GETATTRIBUTE, &length,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		status = adjustPKCS1Data( decryptedSignature,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );

	/* Decode the payload as required */
	sMemConnect( &stream, decryptedSignature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			/* Decode the payload using the PKCS #1 format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ]
			
			   Note that some implementations may have bignum code that 
			   zero-truncates the result, which would produce a 
			   CRYPT_ERROR_BADDATA error, it's the responsibility of the 
			   lower-level crypto layer to reformat the data to return a
			   correctly-formatted result if necessary */
			if( sgetc( &stream ) != 0 || sgetc( &stream ) != 1 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			for( i = 0; i < length - 3; i++ )
				if( ( ch = sgetc( &stream ) ) != 0xFF )
					break;
			if( ch != 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			status = readMessageDigest( &stream, &hashAlgo, hash, &hashSize );
			if( cryptStatusOK( status ) && contextHashAlgo != hashAlgo )
				status = CRYPT_ERROR_SIGNATURE;
			break;

		case SIGN_SSL:
			assert( contextHashAlgo == CRYPT_ALGO_MD5 );

			/* Decode the payload using the PKCS #1 SSL format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ MD5 hash ][ SHA1 hash ] */
			hashSize = 16; hashSize2 = 20;
			if( sgetc( &stream ) != 0 || sgetc( &stream ) != 1 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			for( i = 0; i < ( hashSize + hashSize2 - 3 ); i++ )
				if( ( ch = sgetc( &stream ) ) != 0xFF )
					break;
			if( ch != 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			status = sread( &stream, hash, hashSize );
			if( cryptStatusOK( status ) )
				status = sread( &stream, hash2, hashSize2 );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	sMemDisconnect( &stream );
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, make sure that the two hash values match */
	setMessageData( &msgData, hash, hashSize );
	status = krnlSendMessage( mechanismInfo->hashContext, IMESSAGE_COMPARE, 
							  &msgData, MESSAGE_COMPARE_HASH );
	if( cryptStatusOK( status ) && hashSize2 > 0 )
		{
		setMessageData( &msgData, hash2, hashSize2 );
		status = krnlSendMessage( mechanismInfo->hashContext2, 
								  IMESSAGE_COMPARE, &msgData, 
								  MESSAGE_COMPARE_HASH );
		}

	/* Clean up */
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	zeroise( hash2, CRYPT_MAX_HASHSIZE );
	return( cryptStatusError( status ) ? CRYPT_ERROR_SIGNATURE : status );
	}

int signPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( sign( mechanismInfo, SIGN_PKCS1 ) );
	}

int sigcheckPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( sigcheck( mechanismInfo, SIGN_PKCS1 ) );
	}

#ifdef USE_SSL

int signSSL( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( sign( mechanismInfo, SIGN_SSL ) );
	}

int sigcheckSSL( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( sigcheck( mechanismInfo, SIGN_SSL ) );
	}
#endif /* USE_SSL */
