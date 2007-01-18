/****************************************************************************
*																			*
*							PGP Signature Routines							*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#ifdef USE_PGP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Write a PGP signature packet header:

		-- Start of hashed data --
		byte	version = 4
		byte	sigType
		byte	sigAlgo
		byte	hashAlgo
		uint16	length of auth.attributes
		byte[]	authenticated attributes
		-- End of hashed data --
		uint16	length of unauth.attributes = 0
	  [	byte[2]	hash check ]
	  [	mpi(s)	signature  ]

   See the comment in createSignaturePGP() for the use of this function */

static int writePgpSigPacketHeader( void *dataBuffer, const int dataBufSize,
									const CRYPT_CONTEXT iSignContext,
									const CRYPT_CONTEXT iHashContext,
									const int iAndSlength )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE keyID[ PGP_KEYID_SIZE + 8 ];
	BYTE iAndSHeader[ 64 + 8 ];
	const time_t currentTime = getApproxTime();
	int pgpHashAlgo, pgpSignAlgo, length, iAndSHeaderLength = 0, status;

	assert( ( dataBuffer == NULL && dataBufSize == 0 ) || \
			isWritePtr( dataBuffer, dataBufSize ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isHandleRangeValid( iHashContext ) );
	assert( iAndSlength >= 0 );

	/* Get the signature information */
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );
	if( ( pgpHashAlgo = cryptlibToPgpAlgo( cryptAlgo ) ) == PGP_ALGO_NONE )
		return( CRYPT_ARGERROR_NUM2 );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	if( ( pgpSignAlgo = cryptlibToPgpAlgo( cryptAlgo ) ) == PGP_ALGO_NONE )
		return( CRYPT_ARGERROR_NUM1 );

	/* Write the issuerAndSerialNumber packet header if necessary.  Since
	   this is a variable-length packet we need to pre-encode it before we
	   can write the main packet data:

		byte[]		length
		byte		subpacketType
		uint32		flags = 0
		uint16		typeLength
		uint16		valueLength
		byte[]		type
		byte[]		value */
	if( iAndSlength > 0 )
		{
		STREAM headerStream;

		sMemOpen( &headerStream, iAndSHeader, 64 );
		pgpWriteLength( &headerStream, \
						1 + UINT32_SIZE + UINT16_SIZE + UINT16_SIZE + \
						21 + iAndSlength );
		sputc( &headerStream, PGP_SUBPACKET_TYPEANDVALUE );
		writeUint32( &headerStream, 0 );
		writeUint16( &headerStream, 21 );
		writeUint16( &headerStream, iAndSlength );
		swrite( &headerStream, "issuerAndSerialNumber", 21 );
		iAndSHeaderLength = stell( &headerStream );
		assert( sStatusOK( &headerStream ) );
		sMemDisconnect( &headerStream );
		}

	/* Write the general header information */
	sMemOpen( &stream, dataBuffer, dataBufSize );
	sputc( &stream, PGP_VERSION_OPENPGP );
	sputc( &stream, PGP_SIG_DATA );
	sputc( &stream, pgpSignAlgo );
	sputc( &stream, pgpHashAlgo );

	/* Write the authenticated attributes:

		uint16		authAttrLength
		byte		subpacketLength = 1 + UINT32_SIZE
		byte		ID = PGP_SUBPACKET_TIME
		uint32		time
		byte		subpacketLength = 1 + PGP_KEYID_SIZE
		byte		ID = PGP_SUBPACKET_KEYID
		byte[8]		signerID
	  [	byte[]		typeAndValue packet for iAndS ]
	
	   The signer ID is optional, but if we omit it GPG fails the signature 
	   check so we always include it */
	length = ( 1 + 1 + UINT32_SIZE ) + ( 1 + 1 + PGP_KEYID_SIZE );
	if( iAndSlength > 0 )
		length += iAndSHeaderLength + iAndSlength;
	writeUint16( &stream, length );
	sputc( &stream, 1 + UINT32_SIZE );		/* Time */
	sputc( &stream, PGP_SUBPACKET_TIME );
	writeUint32Time( &stream, currentTime );
	sputc( &stream, 1 + PGP_KEYID_SIZE );	/* Signer ID */
	sputc( &stream, PGP_SUBPACKET_KEYID );
	swrite( &stream, keyID, PGP_KEYID_SIZE );
	if( iAndSlength > 0 )					/* TypeAndValue */
		{
		swrite( &stream, iAndSHeader, iAndSHeaderLength );
		status = exportAttributeToStream( &stream, iSignContext,
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusError( status ) )
			{
			sMemClose( &stream );
			return( status );
			}
		}

	/* Write the unauthenticated attributes:

		uint16		unauthAttrLength = 0 */
	status = writeUint16( &stream, 0 );

	/* Clean up */
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( cryptStatusError( status ) ? status : length );
	}

/****************************************************************************
*																			*
*							Create/Check a PGP Signature					*
*																			*
****************************************************************************/

/* Create a PGP signature */

int createSignaturePGP( void *signature, int *signatureLength,
						const int sigMaxLength,
						const CRYPT_CONTEXT iSignContext,
						const CRYPT_CONTEXT iHashContext )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE signatureData[ CRYPT_MAX_PKCSIZE + 128 + 8 ];
	BYTE extraData[ 1024 + 8 ], *extraDataPtr = extraData;
	int extraDataLength = 1024, signatureDataLength, iAndSlength = 0, status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isWritePtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isHandleRangeValid( iHashContext ) );

	/* Check whether there's an issuerAndSerialNumber present */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		iAndSlength = msgData.length;

	/* If it's a length check only, determine how large the signature data
	   will be and exit */
	if( signature == NULL )
		{
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

	/* If there's an issuerAndSerialNumber present, allocate a larger buffer 
	   for it if necessary (this virtually never occurs, the iAndS would need
	   to be over 1kB long.  Note that we can't use a dynBuf for this 
	   because we're allocating a buffer larger than the attribute, not the 
	   same size as the attribute */
	if( iAndSlength > extraDataLength - 128 )
		{
		extraDataLength = 128 + iAndSlength;
		if( ( extraDataPtr = clDynAlloc( "createSignaturePGP", \
										 extraDataLength ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		}

	/* Complete the hashing and create the signature.  In theory this could
	   get ugly because there could be multiple one-pass signature packets
	   present, however PGP handles multiple signatures by nesting them so
	   this isn't a problem.

	   PGP processes the authenticated attributes in an odd way, first
	   hashing part of the packet from the version number to the end of the
	   authenticated attributes, then hashing some more (out-of-band) stuff, 
	   and finally signing the result of the overall hashing.  Because of 
	   this complex way of handling things, we can't write the signature 
	   packet in one go but instead have to write the part that we can 
	   create now, hash the portion that's hashed (all but the last 16 bits, 
	   the length of the unathenticated attributes), and then go back and 
	   assemble the whole thing including the length and signature later on 
	   from the pre-hashed data and the length, hash check, and signature */
	status = extraDataLength = \
		writePgpSigPacketHeader( extraData, extraDataLength, iSignContext,
								 iHashContext, iAndSlength );
	if( !cryptStatusError( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  extraData, extraDataLength - UINT16_SIZE );
		if( status == CRYPT_ERROR_COMPLETE )
			{
			/* Unlike standard signatures, PGP requires that the hashing
			   not be wrapped up before the signature is generated, since
			   it needs to hash in further data before it can generate
			   the signature.  Since completing the hashing is likely to be
			   a common error, we specifically check for this and return an
			   appropriate error code */
			status = CRYPT_ARGERROR_NUM2;
			}
		}
	if( cryptStatusOK( status ) )
		{
		BYTE buffer[ 8 + 8 ];
		int length;

		/* Hash in even more stuff at the end.  This is a complex jumble of
		   items constituting a version number, an 0xFF, and another length.
		   This was motivated by a concern that something that meant one
		   thing in a version n sig could mean something different when
		   interpreted as a version n+1 sig.  For this reason a hash-
		   convention version (v4) was added, along with a disambiguator
		   0xFF that will never be found at that position in older (v3)
		   hash-convention sigs (the 0x04 is in fact redundant, but may be
		   needed at some point if the hash convention moves to a v5
		   format).  The length has something to do with parsing the packet
		   from the end, so that out-of-band data doesn't run into payload
		   data, but no-one can quite remember why it's usually there */
		sMemOpen( &stream, buffer, 8 );
		sputc( &stream, 0x04 );
		sputc( &stream, 0xFF );
		writeUint32( &stream, extraDataLength - UINT16_SIZE );
		length = stell( &stream );
		sMemDisconnect( &stream );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  buffer, length );
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

int checkSignaturePGP( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT sigCheckContext,
					   const CRYPT_CONTEXT iHashContext )
	{
	const READSIG_FUNCTION readSigFunction = getReadSigFunction( SIGNATURE_PGP );
	QUERY_INFO queryInfo;
	STREAM stream;
	int status;

	assert( isReadPtr( signature, signatureLength ) );
	assert( isHandleRangeValid( sigCheckContext ) );
	assert( isHandleRangeValid( iHashContext ) );

	/* Make sure that the requested signature format is available */
	if( readSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Determine whether there are any authenticated attributes attached to
	   the signature */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, signature, signatureLength );
	status = readSigFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* After hashing the content, PGP also hashes in extra authenticated
	   attributes */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
							  ( BYTE * ) signature + queryInfo.attributeStart,
							  queryInfo.attributeLength );
	if( cryptStatusOK( status ) && queryInfo.attributeLength != 5 )
		{
		BYTE buffer[ 8 + 8 ];
		int length;

		/* In addition to the standard authenticated attributes, OpenPGP
		   hashes in even more stuff at the end */
		sMemOpen( &stream, buffer, 8 );
		sputc( &stream, 0x04 );
		sputc( &stream, 0xFF );
		writeUint32( &stream, queryInfo.attributeLength );
		length = stell( &stream );
		sMemDisconnect( &stream );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  buffer, length );
		}
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the signature */
	return( checkSignature( signature, signatureLength, sigCheckContext,
							iHashContext, CRYPT_UNUSED, SIGNATURE_PGP ) );
	}
#endif /* USE_PGP */
