/****************************************************************************
*																			*
*							Internal Signature Routines						*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "asn1.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Create a Signature							*
*																			*
****************************************************************************/

/* Common signature-creation routine, used by other sign_xxx.c modules */

int createSignature( void *signature, int *signatureLength,
					 const int sigMaxLength,
					 const CRYPT_CONTEXT iSignContext,
					 const CRYPT_CONTEXT iHashContext,
					 const CRYPT_CONTEXT iHashContext2,
					 const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO_TYPE signAlgo, hashAlgo;
	STREAM stream;
	const WRITESIG_FUNCTION writeSigFunction = getWriteSigFunction( signatureType );
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *bufPtr = ( signature == NULL ) ? NULL : buffer;
	const int bufSize = ( signature == NULL ) ? 0 : CRYPT_MAX_PKCSIZE;
	int length, status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isWritePtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isHandleRangeValid( iHashContext ) );
	assert( ( signatureType == SIGNATURE_SSL && \
			  isHandleRangeValid( iHashContext2 ) ) || \
			( ( signatureType == SIGNATURE_CMS || \
				signatureType == SIGNATURE_CRYPTLIB || \
				signatureType == SIGNATURE_PGP || \
				signatureType == SIGNATURE_RAW || \
				signatureType == SIGNATURE_SSH || \
				signatureType == SIGNATURE_X509 ) && \
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

	/* DLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) )
		{
		MESSAGE_DATA msgData;
		BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];

		/* Extract the hash value from the context.  If we're doing a length
		   check there's no hash value present yet, so we just fill in the
		   hash length value from the blocksize attribute */
		if( signature == NULL )
			status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
									  &msgData.length, 
									  CRYPT_CTXINFO_BLOCKSIZE );
		else
			{
			setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CTXINFO_HASHVALUE );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* DSA is only defined for hash algorithms with a block size of 160
		   bits */
		if( msgData.length != 20 )
			return( CRYPT_ARGERROR_NUM1 );

		/* If we're doing a length check and the signature is being written 
		   in cryptlib format the length is just an estimate since it can 
		   change by up to two bytes depending on whether the signature 
		   values have the high bit set or not, which requires zero-padding 
		   of the ASN.1-encoded integers (we use a worst-case estimate here 
		   and assume that both integers will be of the maximum size and 
		   need padding).  This is rather nasty because it means that we 
		   can't tell how large a signature will be without actually creating 
		   it */
		if( signature == NULL )
			length = ( signatureType == SIGNATURE_PGP ) ? \
						2 * ( 2 + 20 ) : \
						sizeofObject( ( 2 * sizeofObject( 20 + 1 ) ) );
		else
			{
			DLP_PARAMS dlpParams;

			/* Sign the data */
			setDLPParams( &dlpParams, hash, 20, bufPtr, bufSize );
			if( signatureType == SIGNATURE_PGP )
				dlpParams.formatType = CRYPT_FORMAT_PGP;
			if( signatureType == SIGNATURE_SSH )
				dlpParams.formatType = CRYPT_IFORMAT_SSH;
			status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGN, 
									  &dlpParams, sizeof( DLP_PARAMS ) );
			length = dlpParams.outLen;
			}
		}
	else
		{
		MECHANISM_SIGN_INFO mechanismInfo;

		/* It's a standard signature, process it as normal */
		setMechanismSignInfo( &mechanismInfo, bufPtr, bufSize, iHashContext, 
							  iHashContext2, iSignContext );
		status = krnlSendMessage( iSignContext, IMESSAGE_DEV_SIGN, &mechanismInfo,
								  ( signatureType == SIGNATURE_SSL ) ? \
									MECHANISM_SIG_SSL : MECHANISM_SIG_PKCS1 );
		length = mechanismInfo.signatureLength;
		clearMechanismInfo( &mechanismInfo );
		}
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the
		   hash context) first while the higher-level functions place the
		   signature context next to the signature data, in other words
		   before the hash context.  Because of this we have to reverse
		   parameter error values when translating from the mechanism to the
		   signature function level */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		zeroise( bufPtr, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Write the signature record to the output */
	sMemOpen( &stream, signature, sigMaxLength );
	status = writeSigFunction( &stream, iSignContext, hashAlgo, signAlgo,
							   buffer, length );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*								Check a Signature							*
*																			*
****************************************************************************/

/* Common signature-checking routine, used by other sign_xxx.c modules */

int checkSignature( const void *signature, const int signatureLength,
					const CRYPT_CONTEXT iSigCheckContext,
					const CRYPT_CONTEXT iHashContext,
					const CRYPT_CONTEXT iHashContext2,
					const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO_TYPE signAlgo, hashAlgo;
	MECHANISM_SIGN_INFO mechanismInfo;
	const READSIG_FUNCTION readSigFunction = getReadSigFunction( signatureType );
	QUERY_INFO queryInfo;
	STREAM stream;
	void *signatureData;
	int signatureDataLength, status;

	assert( isReadPtr( signature, signatureLength ) );
	assert( isHandleRangeValid( iSigCheckContext ) );
	assert( isHandleRangeValid( iHashContext ) );
	assert( ( signatureType == SIGNATURE_SSL && \
			  isHandleRangeValid( iHashContext2 ) ) || \
			( ( signatureType == SIGNATURE_CMS || \
				signatureType == SIGNATURE_CRYPTLIB || \
				signatureType == SIGNATURE_PGP || \
				signatureType == SIGNATURE_RAW || \
				signatureType == SIGNATURE_SSH || \
				signatureType == SIGNATURE_X509 ) && \
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

	/* Read and check the signature record */
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
	   is done at a higher level when we process the signature data */
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
	if( signatureType == SIGNATURE_CRYPTLIB || \
		signatureType == SIGNATURE_PGP )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE,
								  &msgData, 
								  ( signatureType == SIGNATURE_CRYPTLIB ) ? \
									MESSAGE_COMPARE_KEYID : \
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
	signatureData = ( BYTE * ) signature + queryInfo.dataStart;
	signatureDataLength = queryInfo.dataLength;
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	/* DLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) )
		{
		DLP_PARAMS dlpParams;
		MESSAGE_DATA msgData;
		BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];

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
		return( krnlSendMessage( iSigCheckContext, IMESSAGE_CTX_SIGCHECK,
								 &dlpParams, sizeof( DLP_PARAMS ) ) );
		}

	/* It's a standard signature, process it as normal */
	setMechanismSignInfo( &mechanismInfo, signatureData, signatureDataLength, 
						  iHashContext, iHashContext2, iSigCheckContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_SIGCHECK, 
							  &mechanismInfo,
							  ( signatureType == SIGNATURE_SSL ) ? \
								MECHANISM_SIG_SSL : MECHANISM_SIG_PKCS1 );
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the 
		   hash context) first while the higher-level functions place the 
		   signature context next to the signature data, in other words 
		   before the hash context.  Because of this we have to reverse 
		   parameter error values when translating from the mechanism to the 
		   signature function level */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		}
	clearMechanismInfo( &mechanismInfo );

	return( status );
	}
