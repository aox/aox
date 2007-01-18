/****************************************************************************
*																			*
*						  Signature Read/Write Routines						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "mech.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the SignerInfo record */

enum { CTAG_SI_SKI };

/****************************************************************************
*																			*
*							X.509 Signature Routines						*
*																			*
****************************************************************************/

/* Read/write raw signatures */

static int readRawSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the start of the signature */
	status = readBitStringHole( stream, &queryInfo->dataLength, 16 + 16,
								DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataStart = stell( stream ) - startPos;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength ) );
	}

static int writeRawSignature( STREAM *stream, const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo,
							  const CRYPT_ALGO_TYPE signAlgo,
							  const BYTE *signature,
							  const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	/* Write the BIT STRING wrapper and signature */
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}

/* Read/write X.509 signatures */

static int readX509Signature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the signature/hash algorithm information followed by the start
	   of the signature */
	status = readAlgoIDex( stream, &queryInfo->cryptAlgo,
						   &queryInfo->hashAlgo, NULL );
	if( cryptStatusOK( status ) )
		status = readBitStringHole( stream, &queryInfo->dataLength, 16 + 16,
									DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataStart = stell( stream ) - startPos;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength ) );
	}

static int writeX509Signature( STREAM *stream,
							   const CRYPT_CONTEXT iSignContext,
							   const CRYPT_ALGO_TYPE hashAlgo,
							   const CRYPT_ALGO_TYPE signAlgo,
							   const BYTE *signature,
							   const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	/* Write the hash+signature algorithm identifier followed by the BIT
	   STRING wrapper and signature */
	writeContextAlgoID( stream, iSignContext, hashAlgo,
						ALGOID_FLAG_ALGOID_ONLY );
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}

/****************************************************************************
*																			*
*							CMS Signature Routines							*
*																			*
****************************************************************************/

/* Read/write PKCS #7/CMS (issuerAndSerialNumber) signatures */

static int readCmsSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	long value, endPos;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	endPos = startPos + value;

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != SIGNATURE_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the issuer and serial number and hash algorithm ID */
	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	queryInfo->iAndSStart = stell( stream ) - startPos;
	queryInfo->iAndSLength = value;
	sSkip( stream, value );
	status = readAlgoID( stream, &queryInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the authenticated attributes if there are any present */
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		value = getStreamObjectLength( stream );
		if( cryptStatusError( value ) )
			return( value );
		queryInfo->attributeStart = stell( stream ) - startPos;
		queryInfo->attributeLength = value;
		status = sSkip( stream, value );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusOK( status ) )
		status = readOctetStringHole( stream, &queryInfo->dataLength, 16 + 16,
									  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		queryInfo->dataStart = stell( stream ) - startPos;
		status = sSkip( stream, queryInfo->dataLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the unauthenticated attributes if there are any present */
	if( stell( stream ) < endPos && peekTag( stream ) == MAKE_CTAG( 1 ) )
		{
		value = getStreamObjectLength( stream );
		if( cryptStatusError( value ) )
			return( value );
		queryInfo->unauthAttributeStart = stell( stream ) - startPos;
		queryInfo->unauthAttributeLength = value;
		status = sSkip( stream, value );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

static int writeCmsSignature( STREAM *stream,
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo,
							  const CRYPT_ALGO_TYPE signAlgo,
							  const BYTE *signature,
							  const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	/* Write the signature algorithm identifier and signature data.  The
	   handling of CMS signatures is non-orthogonal to readCmsSignature()
	   because creating a CMS signature involves adding assorted additional
	   data like iAndS and signed attributes that present too much
	   information to pass into a basic writeSignature() call */
	writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

/* Read/write cryptlib/CMS (keyID) signatures */

static int readCryptlibSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	long value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != SIGNATURE_EX_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and hash algorithm identifier */
	readOctetStringTag( stream, queryInfo->keyID, &queryInfo->keyIDlength,
						8, CRYPT_MAX_HASHSIZE, CTAG_SI_SKI );
	status = readAlgoID( stream, &queryInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusOK( status ) )
		status = readOctetStringHole( stream, &queryInfo->dataLength, 16 + 16,
									  DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataStart = stell( stream ) - startPos;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength ) );
	}

static int writeCryptlibSignature( STREAM *stream,
								   const CRYPT_CONTEXT iSignContext,
								   const CRYPT_ALGO_TYPE hashAlgo,
								   const CRYPT_ALGO_TYPE signAlgo,
								   const BYTE *signature,
								   const int signatureLength )
	{
	MESSAGE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];
	const int signAlgoIdSize = \
				sizeofContextAlgoID( iSignContext, CRYPT_ALGO_NONE, 
									 ALGOID_FLAG_ALGOID_ONLY );
	const int hashAlgoIdSize = sizeofAlgoID( hashAlgo );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( iSignContext ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	if( cryptStatusError( signAlgoIdSize ) )
		return( signAlgoIdSize );
	if( cryptStatusError( hashAlgoIdSize ) )
		return( hashAlgoIdSize );

	/* Get the key ID */
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the header */
	writeSequence( stream, ( int ) sizeofShortInteger( SIGNATURE_EX_VERSION ) + \
				   sizeofObject( msgData.length ) + \
				   signAlgoIdSize + hashAlgoIdSize + \
				   sizeofObject( signatureLength ) );

	/* Write the version, key ID and algorithm identifier */
	writeShortInteger( stream, SIGNATURE_EX_VERSION, DEFAULT_TAG );
	writeOctetString( stream, msgData.data, msgData.length, CTAG_SI_SKI );
	writeAlgoID( stream, hashAlgo );
	writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*							Misc Signature Routines							*
*																			*
****************************************************************************/

#ifdef USE_PGP

/* Read signature subpackets */

static int readSignatureSubpackets( STREAM *stream, QUERY_INFO *queryInfo,
									const int length, const int startPos,
									const BOOLEAN isAuthenticated )
	{
	const int endPos = stell( stream ) + length;
	int iterationCount = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );
	assert( length > 0 && length < 8192 );
	assert( startPos >= 0 );

	while( stell( stream ) < endPos && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		const int subpacketLength = pgpReadShortLength( stream,
														PGP_CTB_OPENPGP );
		const int type = sgetc( stream );
		int status;

		if( cryptStatusError( subpacketLength ) )
			return( subpacketLength );
		if( cryptStatusError( type ) )
			return( type );

		/* If it's an unrecognised subpacket with the critical flag set,
		   reject the signature.  The range check isn't complete since there
		   are a few holes in the range, but since the holes presumably exist
		   because of deprecated subpacket types, any new packets will be
		   added at the end so it's safe to use */
		if( ( type & 0x80 ) && ( ( type & 0x7F ) > PGP_SUBPACKET_LAST ) )
			return( CRYPT_ERROR_NOTAVAIL );

		switch( type )
			{
			case PGP_SUBPACKET_KEYID:
				assert( subpacketLength == PGP_KEYID_SIZE + 1 );

				/* If it's a key ID and we haven't already set this from a 
				   preceding one-pass signature packet (which can happen 
				   with detached sigs), set it now */
				if( queryInfo->keyIDlength <= 0 )
					{
					status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
					queryInfo->keyIDlength = PGP_KEYID_SIZE;
					}
				else
					/* We've already got the ID, skip it and continue (the 
					   -1 is for the packet type, which we've already read) */
					status = sSkip( stream, subpacketLength - 1 );
				break;

			case PGP_SUBPACKET_TYPEANDVALUE:
				{
				BYTE nameBuffer[ 32 + 8 ];
				static const char FAR_BSS *nameString = "issuerAndSerialNumber";
				int nameLength, valueLength;

				/* It's a type-and-value packet, check whether it's one of 
				   ours */
				sSkip( stream, UINT32_SIZE );	/* Flags */
				nameLength = readUint16( stream );
				valueLength = readUint16( stream );
				if( cryptStatusError( valueLength ) )
					return( valueLength );
				if( nameLength != strlen( nameString ) || \
					valueLength < 16 || valueLength > 2048 )
					{
					status = sSkip( stream, nameLength + valueLength );
					break;
					}
				status = sread( stream, nameBuffer, nameLength );
				if( cryptStatusError( status ) )
					return( status );
				if( !memcmp( nameBuffer, nameString, nameLength ) )
					{
					/* It's an issuerAndSerialNumber, remember it for 
					   later */
					queryInfo->iAndSStart = stell( stream ) - startPos;
					queryInfo->iAndSLength = valueLength;
					}
				status = sSkip( stream, valueLength );
				break;
				}

			default:
				/* It's something else, skip it and continue (the -1 is for 
				   the packet type, which we've already read) */
				status = sSkip( stream, subpacketLength - 1 );
			}

		if( cryptStatusError( status ) )
			return( status );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( CRYPT_OK );
	}

/* Signature info:

	byte	ctb = PGP_PACKET_SIGNATURE_ONEPASS
	byte[]	length
	byte	version = 3 (= OpenPGP, not the expected PGP3)
	byte	sigType
	byte	hashAlgo
	byte	sigAlgo
	byte[8]	keyID
	byte	1 */

int readOnepassSigPacket( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Make sure that the packet header is in order and check the packet
	   version.  This is an OpenPGP-only packet */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sgetc( stream ) != 3 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->version = PGP_VERSION_OPENPGP;

	/* Skip the sig.type, get the hash algorithm and check the signature
	   algorithm */
	sgetc( stream );
	if( ( queryInfo->hashAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	if( ( queryInfo->cryptAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	queryInfo->type = CRYPT_OBJECT_SIGNATURE;

	/* Get the PGP key ID and make sure that this isn't a nested signature */
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	return( ( sgetc( stream ) != 1 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

/* Read/write PGP signatures.

		byte	ctb = PGP_PACKET_SIGNATURE
		byte[]	length
	v3:	byte	version = PGP_2,3	v4: byte	version = PGP_VERSION_OPENPGP
		byte	infoLen = 5				byte	sigType
			byte	sigType				byte	sigAlgo
			byte[4]	sig.time			byte	hashAlgo
		byte[8]	keyID					uint16	length of auth.attributes
		byte	sigAlgo					byte[]	authenticated attributes
		byte	hashAlgo				uint16	length of unauth.attributes
		byte[2]	hash check				byte[]	unauthenticated attributes
		mpi(s)	signature				byte[2]	hash check
										mpi(s)	signature */

static int readPgpSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Make sure that the packet header is in order and check the packet
	   version.  For this packet type, a version number of 3 denotes PGP 2.x,
	   whereas for key transport it denotes OpenPGP */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	value = sgetc( stream );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
		value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->type = CRYPT_OBJECT_SIGNATURE;
	queryInfo->version = ( value == PGP_VERSION_OPENPGP ) ? \
						 PGP_VERSION_OPENPGP : PGP_VERSION_2;

	/* If it's not an OpenPGP packet, read it as a PGP 2.x-format
	   signature */
	if( value != PGP_VERSION_OPENPGP )
		{
		/* Read the additional signature information */
		if( sgetc( stream ) != 5 )
			return( CRYPT_ERROR_BADDATA );
		queryInfo->attributeStart = stell( stream ) - startPos;
		queryInfo->attributeLength = 5;
		sSkip( stream, 5 );

		/* Read the signer keyID, signature and hash algorithm */
		status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->keyIDlength = PGP_KEYID_SIZE;
		if( ( queryInfo->cryptAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		if( ( queryInfo->hashAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		}
	else
		{
		/* It's an OpenPGP packet, remember the extra data to be hashed (this
		   starts at the version byte, which we've already read, so we add a
		   -1 offset) and read the signature and hash algorithms */
		queryInfo->attributeStart = ( stell( stream ) - 1 ) - startPos;
		queryInfo->attributeLength = PGP_VERSION_SIZE + 1 + PGP_ALGOID_SIZE + \
									 PGP_ALGOID_SIZE + UINT16_SIZE;
		sgetc( stream );	/* Skip signature type */
		if( ( queryInfo->cryptAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		if( ( queryInfo->hashAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Process the authenticated attributes */
		value = readUint16( stream );
		if( value < 0 || value > 2048 )
			return( CRYPT_ERROR_BADDATA );
		if( sMemDataLeft( stream ) < value )
			return( CRYPT_ERROR_UNDERFLOW );
		if( value > 0 )
			{
			queryInfo->attributeLength += value;
			status = readSignatureSubpackets( stream, queryInfo, value,
											  startPos, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Skip the unauthenticated attributes */
		queryInfo->unauthAttributeStart = stell( stream ) - startPos;
		value = readUint16( stream );
		if( value < 0 || value > 2048 )
			return( CRYPT_ERROR_BADDATA );
		if( sMemDataLeft( stream ) < value )
			return( CRYPT_ERROR_UNDERFLOW );
		queryInfo->unauthAttributeLength = UINT16_SIZE + value;
		if( value > 0 )
			{
			status = readSignatureSubpackets( stream, queryInfo, value, 
											  startPos, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Skip the hash check and read the signature, recording the start of the
	   signature data */
	sSkip( stream, 2 );
	if( queryInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		queryInfo->dataStart = stell( stream ) - startPos;
		status = readInteger16Ubits( stream, NULL, &value, 16, 20 );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength = UINT16_SIZE + value;	/* Incl.size of MPI hdr.*/
		status = readInteger16Ubits( stream, NULL, &value, 16, 20 );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength += UINT16_SIZE + value;	/* Incl.size of MPI hdr.*/
		}
	else
		{
		queryInfo->dataStart = ( stell( stream ) + UINT16_SIZE )  - startPos;
		status = readInteger16Ubits( stream, NULL, &queryInfo->dataLength,
									 bitsToBytes( MIN_PKCSIZE_BITS ),
									 CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

static int writePgpSignature( STREAM *stream,
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo,
							  const CRYPT_ALGO_TYPE signAlgo,
							  const BYTE *signature,
							  const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( signAlgo >= CRYPT_ALGO_FIRST_PKC && \
			signAlgo <= CRYPT_ALGO_LAST_PKC );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	/* If it's a DLP algorithm, we've already specified the DLP output
	   format as PGP so there's no need for further processing.  The
	   handling of PGP signatures is non-orthogonal to readPgpSignature()
	   because creating a PGP signature involves adding assorted additional
	   data like key IDs and authenticated attributes, which present too 
	   much information to pass into a basic writeSignature() call */
	if( isDlpAlgo( signAlgo ) )
		return( swrite( stream, signature, signatureLength ) );

	/* Write the signature as a PGP MPI */
	return( writeInteger16Ubits( stream, signature, signatureLength ) );
	}
#endif /* USE_PGP */

#ifdef USE_SSH

/* Read/write SSH signatures.  SSH signature data is treated as a blob
   encoded as an SSH string rather than properly-formatted data, so we don't
   encode/decode it as SSH MPIs */

static int readSshSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	BYTE buffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the signature record size and algorithm information */
	readUint32( stream );
	status = readString32( stream, buffer, &length, CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 )
		return( CRYPT_ERROR_BADDATA );
	if( !memcmp( buffer, "ssh-rsa", 7 ) )
		queryInfo->cryptAlgo = CRYPT_ALGO_RSA;
	else
		if( !memcmp( buffer, "ssh-dss", 7 ) )
			queryInfo->cryptAlgo = CRYPT_ALGO_DSA;
		else
			return( CRYPT_ERROR_BADDATA );

	/* Read the start of the signature */
	length = readUint32( stream );
	if( cryptStatusError( length ) )
		return( length );
	if( queryInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		if( length != ( 20 + 20 ) )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		if( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
			length > CRYPT_MAX_PKCSIZE )
			return( CRYPT_ERROR_BADDATA );
		}
	queryInfo->dataStart = stell( stream ) - startPos;
	queryInfo->dataLength = length;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, length ) );
	}

static int writeSshSignature( STREAM *stream,
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo,
							  const CRYPT_ALGO_TYPE signAlgo,
							  const BYTE *signature,
							  const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( signAlgo == CRYPT_ALGO_RSA || signAlgo == CRYPT_ALGO_DSA );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	writeUint32( stream, sizeofString32( "ssh-Xsa", 7 ) + \
						 sizeofString32( NULL, signatureLength ) );
	writeString32( stream, ( signAlgo == CRYPT_ALGO_RSA ) ? \
						   "ssh-rsa" : "ssh-dss", 7 );
	return( writeString32( stream, signature, signatureLength ) );
	}
#endif /* USE_SSH */

#ifdef USE_SSL

/* Read/write SSL signatures.  This is just a raw signature without any
   encapsulation */

static int readSslSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the start of the signature */
	length = readUint16( stream );
	if( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
		length > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->dataStart = stell( stream ) - startPos;
	queryInfo->dataLength = length;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, length ) );
	}

static int writeSslSignature( STREAM *stream,
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo,
							  const CRYPT_ALGO_TYPE signAlgo,
							  const BYTE *signature,
							  const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( signature, signatureLength ) );
		/* Other parameters aren't used for this format */

	writeUint16( stream, signatureLength );
	return( swrite( stream, signature, signatureLength ) );
	}
#endif /* USE_SSL */

/****************************************************************************
*																			*
*					Signature Read/Write Access Functions					*
*																			*
****************************************************************************/

typedef struct {
	const SIGNATURE_TYPE type;
	const READSIG_FUNCTION function;
	} SIG_READ_INFO;
static const SIG_READ_INFO sigReadTable[] = {
	{ SIGNATURE_RAW, readRawSignature },
	{ SIGNATURE_X509, readX509Signature },
	{ SIGNATURE_CMS, readCmsSignature },
	{ SIGNATURE_CRYPTLIB, readCryptlibSignature },
#ifdef USE_PGP
	{ SIGNATURE_PGP, readPgpSignature },
#endif /* USE_PGP */
#ifdef USE_SSH
	{ SIGNATURE_SSH, readSshSignature },
#endif /* USE_SSH */
#ifdef USE_SSL
	{ SIGNATURE_SSL, readSslSignature },
#endif /* USE_SSL */
	{ SIGNATURE_NONE, NULL }, { SIGNATURE_NONE, NULL }
	};

typedef struct {
	const SIGNATURE_TYPE type;
	const WRITESIG_FUNCTION function;
	} SIG_WRITE_INFO;
static const SIG_WRITE_INFO sigWriteTable[] = {
	{ SIGNATURE_RAW, writeRawSignature },
	{ SIGNATURE_X509, writeX509Signature },
	{ SIGNATURE_CMS, writeCmsSignature },
	{ SIGNATURE_CRYPTLIB, writeCryptlibSignature },
#ifdef USE_PGP
	{ SIGNATURE_PGP, writePgpSignature },
#endif /* USE_PGP */
#ifdef USE_SSH
	{ SIGNATURE_SSH, writeSshSignature },
#endif /* USE_SSH */
#ifdef USE_SSL
	{ SIGNATURE_SSL, writeSslSignature },
#endif /* USE_SSH */
	{ SIGNATURE_NONE, NULL }, { SIGNATURE_NONE, NULL }
	};

READSIG_FUNCTION getReadSigFunction( const SIGNATURE_TYPE sigType )
	{
	int i;

	for( i = 0; 
		 sigReadTable[ i ].type != SIGNATURE_NONE && \
			i < FAILSAFE_ARRAYSIZE( sigReadTable, SIG_READ_INFO ); 
		 i++ )
		{
		if( sigReadTable[ i ].type == sigType )
			return( sigReadTable[ i ].function );
		}
	if( i >= FAILSAFE_ARRAYSIZE( sigReadTable, SIG_READ_INFO ) )
		retIntError_Null();

	return( NULL );
	}
WRITESIG_FUNCTION getWriteSigFunction( const SIGNATURE_TYPE sigType )
	{
	int i;

	for( i = 0; 
		 sigWriteTable[ i ].type != SIGNATURE_NONE && \
			i < FAILSAFE_ARRAYSIZE( sigWriteTable, SIG_WRITE_INFO ); 
		 i++ )
		{
		if( sigWriteTable[ i ].type == sigType )
			return( sigWriteTable[ i ].function );
		}
	if( i >= FAILSAFE_ARRAYSIZE( sigWriteTable, SIG_WRITE_INFO ) )
		retIntError_Null();

	return( NULL );
	}
