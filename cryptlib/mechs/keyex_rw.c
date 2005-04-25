/****************************************************************************
*																			*
*						Key Exchange Read/Write Routines					*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) 
  #include "pgp.h"
  #include "mechanism.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../envelope/pgp.h"
  #include "mechanism.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "../misc/misc_rw.h"
#else
  #include "envelope/pgp.h"
  #include "mechs/mechanism.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the KEK record */

enum { CTAG_KK_DA };

/* Context-specific tags for the KeyTrans record */

enum { CTAG_KT_SKI };

/* Context-specific tags for the KeyAgree/Fortezza record */

enum { CTAG_KA_ORIG, CTAG_KA_UKM };

/****************************************************************************
*																			*
*					Conventionally-Encrypted Key Routines					*
*																			*
****************************************************************************/

/* The OID for the PKCS #5 v2.0 key derivation function and the parameterised
   PWRI key wrap algorithm */

#define OID_PBKDF2	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C" )
#define OID_PWRIKEK	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x09" )

/* Write a PBKDF2 key derivation record */

static int writeKeyDerivationInfo( STREAM *stream, 
								   const CRYPT_CONTEXT iCryptContext )
	{
	RESOURCE_DATA msgData;
	BYTE salt[ CRYPT_MAX_HASHSIZE ];
	int keySetupIterations, derivationInfoSize, status;

	/* Get the key derivation information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &keySetupIterations, 
							  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, salt, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusError( status ) )
		return( status );
	derivationInfoSize = ( int ) sizeofObject( msgData.length ) + \
						 sizeofShortInteger( ( long ) keySetupIterations );

	/* Write the PBKDF2 information */
	writeConstructed( stream, sizeofOID( OID_PBKDF2 ) +
					  ( int ) sizeofObject( derivationInfoSize ), CTAG_KK_DA );
	writeOID( stream, OID_PBKDF2 );
	writeSequence( stream, derivationInfoSize );
	writeOctetString( stream, msgData.data, msgData.length, DEFAULT_TAG );
	status = writeShortInteger( stream, keySetupIterations, DEFAULT_TAG );
	zeroise( salt, CRYPT_MAX_HASHSIZE );
	return( status );
	}

/* Read a PBKDF2 key derivation record */

static int readKeyDerivationInfo( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long endPos, value;
	int length, status;

	/* Read the outer wrapper and key derivation algorithm OID */
	readConstructed( stream, NULL, CTAG_KK_DA );
	status = readFixedOID( stream, OID_PBKDF2 );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the PBKDF2 parameters, limiting the salt and iteration count to
	   sane values */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	readOctetString( stream, queryInfo->salt, &queryInfo->saltLength, 
					 CRYPT_MAX_HASHSIZE );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value > MAX_KEYSETUP_ITERATIONS )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->keySetupIterations = ( int ) value;
	queryInfo->keySetupAlgo = CRYPT_ALGO_HMAC_SHA;
	if( stell( stream ) < endPos )
		return( sseek( stream, endPos ) );

	return( CRYPT_OK );
	}

/* Read/write CMS KEK data */

static int readCmsKek( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* Read the header */
	readConstructed( stream, NULL, CTAG_RI_KEKRI );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEK_VERSION )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_ERROR_NOTAVAIL );
	}

static int writeCmsKek( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const BYTE *encryptedKey, const int encryptedKeyLength )
	{
	STREAM localStream;
	RESOURCE_DATA msgData;
	BYTE kekInfo[ 128 ], label[ CRYPT_MAX_TEXTSIZE ];
	int kekInfoSize, labelSize, status;

	/* Get the label */
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		return( status );
	labelSize = msgData.length;

	/* Determine the size of the KEK info.  To save evaluating it twice in a 
	   row and because it's short, we just write it to local buffers */
	sMemOpen( &localStream, kekInfo, 128 );
	writeSequence( &localStream, 
				   sizeofOID( OID_PWRIKEK ) + \
				   sizeofContextAlgoID( iCryptContext, CRYPT_ALGO_NONE,
										ALGOID_FLAG_NONE ) );
	writeOID( &localStream, OID_PWRIKEK );
	status = writeContextAlgoID( &localStream, iCryptContext, CRYPT_ALGO_NONE,
								 ALGOID_FLAG_NONE );
	kekInfoSize = stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the algorithm identifiers and encrypted key */
	writeConstructed( stream, ( int ) sizeofShortInteger( KEK_VERSION ) + \
					  sizeofObject( sizeofObject( labelSize ) ) + \
					  kekInfoSize + sizeofObject( encryptedKeyLength ), 
					  CTAG_RI_KEKRI );
	writeShortInteger( stream, KEK_VERSION, DEFAULT_TAG );
	writeSequence( stream, sizeofObject( labelSize ) );
	writeOctetString( stream, label, labelSize, DEFAULT_TAG );
	swrite( stream, kekInfo, kekInfoSize );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength, 
							  DEFAULT_TAG ) );
	}

/* Read/write cryptlib KEK data */

static int readCryptlibKek( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* If it's CMS KEK, read it as such */
	if( peekTag( stream ) == CTAG_RI_KEKRI )
		return( readCmsKek( stream, queryInfo ) );

	/* Read the header */
	readConstructed( stream, NULL, CTAG_RI_PWRI );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PWRI_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the optional KEK derivation info and KEK algorithm info */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_KK_DA ) )
		status = readKeyDerivationInfo( stream, queryInfo );
	if( cryptStatusOK( status ) )
		{
		const long position = stell( stream );

		/* Because of the last-minute change in the PWRI format before the 
		   RFC was published, older versions of cryptlib generate a slightly
		   different KEK algorithm info format.  To handle this, we read
		   part of the AlgorithmIdentifier and, if it's the newer format,
		   skip the extra level of wrapping */
		readSequence( stream, NULL );
		status = readFixedOID( stream, OID_PWRIKEK );
		if( cryptStatusError( status ) )
			{
			/* It's the original format, clear the stream error state caused 
			   by the failed PWRI KEK OID read and try again */
			sClearError( stream );
			sseek( stream, position );
			}
		status = readContextAlgoID( stream, NULL, queryInfo, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the decrypt function */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		queryInfo->dataStart = sMemBufPtr( stream );
		if( queryInfo->dataLength < bitsToBytes( MIN_KEYSIZE_BITS ) )
			/* We shouldn't be using a key this short, we can't actually 
			   load it anyway but a CRYPT_ERROR_BADDATA at this point 
			   provides more meaningful information to the caller */
			status = CRYPT_ERROR_BADDATA;
		}

	return( status );
	}

static int writeCryptlibKek( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
							 const BYTE *encryptedKey, const int encryptedKeyLength )
	{
	STREAM localStream;
	BYTE derivationInfo[ CRYPT_MAX_HASHSIZE + 32 ], kekInfo[ 128 ];
	BOOLEAN hasKeyDerivationInfo = TRUE;
	int derivationInfoSize = 0, kekInfoSize, value, status;

	/* If it's a non-password-derived key and there's a label attached, 
	   write it as a KEKRI with a PWRI algorithm identifier as the key
	   encryption algorithm */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( status == CRYPT_ERROR_NOTINITED )
		{
		RESOURCE_DATA msgData;

		/* There's no password-derivation information present, see if there's
		   a label present */
		hasKeyDerivationInfo = FALSE;
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusOK( status ) )
			/* There's a label present, write it as a PWRI within a KEKRI */
			return( writeCmsKek( stream, iCryptContext, encryptedKey, 
								 encryptedKeyLength ) );
		}

	/* Determine the size of the derivation info and KEK info.  To save
	   evaluating it twice in a row and because it's short, we just write
	   it to local buffers */
	if( hasKeyDerivationInfo )
		{
		sMemOpen( &localStream, derivationInfo, CRYPT_MAX_HASHSIZE + 32 );
		status = writeKeyDerivationInfo( &localStream, iCryptContext );
		derivationInfoSize = stell( &localStream );
		sMemDisconnect( &localStream );
		if( cryptStatusError( status ) )
			return( status );
		}
	sMemOpen( &localStream, kekInfo, 128 );
	writeSequence( &localStream, 
				   sizeofOID( OID_PWRIKEK ) + \
				   sizeofContextAlgoID( iCryptContext, CRYPT_ALGO_NONE,
										ALGOID_FLAG_NONE ) );
	writeOID( &localStream, OID_PWRIKEK );
	status = writeContextAlgoID( &localStream, iCryptContext, CRYPT_ALGO_NONE,
								 ALGOID_FLAG_NONE );
	kekInfoSize = stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the algorithm identifiers and encrypted key */
	writeConstructed( stream, sizeofShortInteger( PWRI_VERSION ) +
					  derivationInfoSize + kekInfoSize + 
					  ( int ) sizeofObject( encryptedKeyLength ), 
					  CTAG_RI_PWRI );
	writeShortInteger( stream, PWRI_VERSION, DEFAULT_TAG );
	if( derivationInfoSize )
		swrite( stream, derivationInfo, derivationInfoSize );
	swrite( stream, kekInfo, kekInfoSize );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength, 
							  DEFAULT_TAG ) );
	}

#ifdef USE_PGP

/* Read/write PGP KEK data.

	SKE:
		byte	ctb = PGP_PACKET_SKE
		byte[]	length
		byte	version = 4
		byte	cryptAlgo
		byte	stringToKey specifier:
		byte[]	stringToKey data
				0x00: byte		hashAlgo
				0x01: byte[8]	salt
				0x02: byte		iterations */

static int readPgpKek( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int value, status;

	/* Make sure that the packet header is in order and check the packet 
	   version.  This is an OpenPGP-only packet */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sgetc( stream ) != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->version = PGP_VERSION_OPENPGP;

	/* Get the password hash algorithm */
	if( ( queryInfo->cryptAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_PWCRYPT ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read the S2K specifier */
	value = sgetc( stream );
	if( value != 0 && value != 1 && value != 3 )
		return( cryptStatusError( value ) ? value : CRYPT_ERROR_BADDATA );
	if( ( queryInfo->keySetupAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ), 
							   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	if( value == 0 )
		/* It's a straight hash, we're done */
		return( CRYPT_OK );
	status = sread( stream, queryInfo->salt, PGP_SALTSIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->saltLength = PGP_SALTSIZE;
	if( value == 3 )
		{
		/* Salted iterated hash, get the iteration count, limited to a sane
		   value.  The "iteration count" is actually a count of how many
		   bytes are hashed, this is because the "iterated hashing" treats
		   the salt + password as an infinitely-repeated sequence of values
		   and hashes the resulting string for PGP-iteration-count bytes
		   worth.  The value we calculate here (to prevent overflow on 16-bit
		   machines) is the count without the base * 64 scaling, this also
		   puts the range within the value of the standard sanity check */
		value = sgetc( stream );
		if( cryptStatusError( value ) )
			return( value );
		queryInfo->keySetupIterations = \
				( 16 + ( ( long ) value & 0x0F ) ) << ( value >> 4 );
		if( queryInfo->keySetupIterations <= 0 || \
			queryInfo->keySetupIterations > MAX_KEYSETUP_ITERATIONS )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

static int writePgpKek( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const BYTE *encryptedKey, const int encryptedKeyLength )
	{
	CRYPT_ALGO_TYPE hashAlgo, cryptAlgo;
	BYTE salt[ CRYPT_MAX_HASHSIZE ];
	int keySetupIterations, count = 0, status;

	assert( encryptedKey == NULL );
	assert( encryptedKeyLength == 0 );

	/* Get the key derivation information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
						&keySetupIterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
						&hashAlgo, CRYPT_CTXINFO_KEYING_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
						&cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, salt, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
						&msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate the PGP "iteration count" from the value used to derive
	   the key.  The "iteration count" is actually a count of how many bytes 
	   are hashed, this is because the "iterated hashing" treats the salt + 
	   password as an infinitely-repeated sequence of values and hashes the 
	   resulting string for PGP-iteration-count bytes worth.  Instead of 
	   being written directly the count is encoded in a complex manner which
	   saves a whole byte, so before we can write it we have to encode it 
	   into the base + exponent form expected by PGP.  This has a default 
	   base of 16 + the user-supplied base value, we can set this to zero
	   since the iteration count used by cryptlib is always a multiple of
	   16, the remainder is just log2 of what's left of the iteration 
	   count */
	assert( keySetupIterations % 16 == 0 );
	keySetupIterations /= 32;	/* Remove fixed offset before log2 op.*/
	while( keySetupIterations )
		{
		count++;
		keySetupIterations >>= 1;
		}
	count <<= 4;				/* Exponent comes first */

	/* Write the SKE packet */
	pgpWritePacketHeader( stream, PGP_PACKET_SKE, 4 + PGP_SALTSIZE + 1 );
	sputc( stream, PGP_VERSION_OPENPGP );
	sputc( stream, cryptlibToPgpAlgo( cryptAlgo ) );
	sputc( stream, 3 );		/* S2K = salted, iterated hash */
	sputc( stream, cryptlibToPgpAlgo( hashAlgo ) );
	swrite( stream, salt, PGP_SALTSIZE );
	return( sputc( stream, count ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*						Public-key Encrypted Key Routines					*
*																			*
****************************************************************************/

/* Read/write CMS key transport data */

static int readCmsKeytrans( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* Read the header and version number */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEYTRANS_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and PKC algorithm information */
	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	queryInfo->iAndSStart = sMemBufPtr( stream );
	queryInfo->iAndSLength = value;
	readUniversal( stream );
	status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the PKC decrypt function */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		queryInfo->dataStart = sMemBufPtr( stream );

	return( status );
	}

static int writeCmsKeytrans( STREAM *stream, 
							 const CRYPT_CONTEXT iCryptContext,
							 const BYTE *buffer, const int length,
							 const void *auxInfo, const int auxInfoLength )
	{
	const int dataLength = \
				sizeofContextAlgoID( iCryptContext, CRYPT_ALGO_NONE,
									 ALGOID_FLAG_ALGOID_ONLY ) + \
				( int ) sizeofObject( length );

	writeSequence( stream, sizeofShortInteger( KEYTRANS_VERSION ) +
				   auxInfoLength + dataLength );
	writeShortInteger( stream, KEYTRANS_VERSION, DEFAULT_TAG );
	swrite( stream, auxInfo, auxInfoLength );
	writeContextAlgoID( stream, iCryptContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, buffer, length, DEFAULT_TAG ) );
	}

/* Read/write cryptlib key transport data */

static int writeCryptlibKeytrans( STREAM *stream, 
								  const CRYPT_CONTEXT iCryptContext,
								  const BYTE *buffer, const int length,
								  const void *auxInfo, 
								  const int auxInfoLength )
	{
	RESOURCE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];
	const int dataLength = \
				sizeofContextAlgoID( iCryptContext, CRYPT_ALGO_NONE,
									 ALGOID_FLAG_ALGOID_ONLY ) + \
				( int ) sizeofObject( length );

	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_IATTRIBUTE_KEYID );
	writeSequence( stream, sizeofShortInteger( KEYTRANS_EX_VERSION ) +
				   ( int ) sizeofObject( msgData.length ) + dataLength );
	writeShortInteger( stream, KEYTRANS_EX_VERSION, DEFAULT_TAG );
	writeOctetString( stream, msgData.data, msgData.length, CTAG_KT_SKI );
	writeContextAlgoID( stream, iCryptContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, buffer, length, DEFAULT_TAG ) );
	}

static int readCryptlibKeytrans( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* Read the header and version number */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEYTRANS_EX_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and PKC algorithm information */
	readOctetStringTag( stream, queryInfo->keyID, &queryInfo->keyIDlength, 
						CRYPT_MAX_HASHSIZE, CTAG_KT_SKI );
	status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the PKC decrypt function */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		queryInfo->dataStart = sMemBufPtr( stream );

	return( status );
	}

#ifdef USE_PGP

/* Read/write PGP key transport data:

	PKE:
		byte	ctb = PGP_PACKET_PKE
		byte[]	length
		byte	version = 2 or 3
		byte[8]	keyID
		byte	PKC algo
		mpi(s)	encrypted session key */

static int readPgpKeytrans( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int value, status;

	/* Make sure that the packet header is in order and check the packet 
	   version.  For this packet type, a version number of 3 denotes OpenPGP, 
	   whereas for signatures it denotes PGP 2.x, so we translate the value 
	   that we return to the caller */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	value = sgetc( stream );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->version = ( value == PGP_VERSION_2 ) ? \
						 PGP_VERSION_2 : PGP_VERSION_OPENPGP;

	/* Get the PGP key ID and algorithm */
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	if( ( queryInfo->cryptAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_PKCCRYPT ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read the encrypted key */
	if( queryInfo->cryptAlgo == CRYPT_ALGO_RSA )
		{
		queryInfo->dataStart = sMemBufPtr( stream ) + 2;
		status = pgpReadMPI( stream, NULL );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength = bitsToBytes( status );
		return( CRYPT_OK );
		}
	queryInfo->dataStart = sMemBufPtr( stream );
	status = pgpReadMPI( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataLength = bitsToBytes( status ) + 2;
	if( queryInfo->dataLength < 56 || \
		queryInfo->dataLength > CRYPT_MAX_PKCSIZE + 2 )
		return( CRYPT_ERROR_BADDATA );
	status = pgpReadMPI( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataLength += bitsToBytes( status ) + 2;
	if( queryInfo->dataLength < ( 56 * 2 ) || \
		queryInfo->dataLength > ( ( CRYPT_MAX_PKCSIZE + 2 ) * 2 ) )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

static int writePgpKeytrans( STREAM *stream, 
							 const CRYPT_CONTEXT iCryptContext,
							 const BYTE *buffer, const int length,
							 const void *auxInfo, const int auxInfoLength )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BYTE keyID[ PGP_KEYID_SIZE ];
	int status;

	/* Get the key information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the PKE packet */
	pgpWritePacketHeader( stream, PGP_PACKET_PKE, 
						  1 + PGP_KEYID_SIZE + 1 + \
						  ( ( cryptAlgo == CRYPT_ALGO_RSA ) ? \
							sizeofMPI( length ) : length ) );
	sputc( stream, 3 );		/* Version = 3 (OpenPGP) */
	swrite( stream, keyID, PGP_KEYID_SIZE );
	sputc( stream, cryptlibToPgpAlgo( cryptAlgo ) );
	return( ( cryptAlgo == CRYPT_ALGO_RSA ) ? \
			pgpWriteMPI( stream, buffer, length ) :
			swrite( stream, buffer, length ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*								Key Agreement Routines						*
*																			*
****************************************************************************/

#if 0	/* 24/11/02 Removed since Fortezza is effectively dead */

/* Read/write a KeyAgreeRecipientInfo (= FortezzaRecipientInfo) record */

int readKeyAgreeInfo( STREAM *stream, QUERY_INFO *queryInfo,
					  CRYPT_CONTEXT *iKeyAgreeContext )
	{
	CRYPT_CONTEXT iLocalKeyAgreeContext;
	long value;
	int status;

	/* Clear return value */
	if( iKeyAgreeContext != NULL )
		*iKeyAgreeContext = CRYPT_ERROR;

	/* Read the header and version number */
	readConstructed( stream, NULL, CTAG_RI_KEYAGREE );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != 3 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the public key information and encryption algorithm information */
	status = iCryptReadSubjectPublicKey( stream, &iLocalKeyAgreeContext, 
										 FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're doing a query we're not interested in the key agreement
	   context so we just copy out the information we need and destroy it */
	if( iKeyAgreeContext == NULL )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, queryInfo->keyID, 
						queryInfo->keyIDlength );
		status = krnlSendMessage( iLocalKeyAgreeContext, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iLocalKeyAgreeContext, 
									  IMESSAGE_GETATTRIBUTE, 
									  &queryInfo->cryptAlgo, 
									  CRYPT_CTXINFO_ALGO );
		krnlSendNotifier( iLocalKeyAgreeContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Make the key agreement context externally visible */
	*iKeyAgreeContext = iLocalKeyAgreeContext;
	return( CRYPT_OK );
	}

int writeKeyAgreeInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
					   const void *wrappedKey, const int wrappedKeyLength,
					   const void *ukm, const int ukmLength,
					   const void *auxInfo, const int auxInfoLength )
	{
	RESOURCE_DATA msgData;
	BYTE rKeyID[ 1024 ];
	int rKeyIDlength, recipientKeyInfoSize, status;

	/* Get the recipients key ID and determine how large the recipient key 
	   info will be */
	setMessageData( &msgData, rKeyID, 1024 );
	status = krnlSendMessage( iCryptContext, MESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	rKeyIDlength = msgData.length;
	recipientKeyInfoSize = ( int ) ( \
							sizeofObject( sizeofObject( rKeyIDlength ) ) + \
							sizeofObject( wrappedKeyLength ) );

	/* Write the FortezzaRecipientInfo header and version number */
	writeConstructed( stream, ( int ) sizeofShortInteger( 3 ) + \
					  sizeofObject( sizeofObject( auxInfoLength ) ) + \
					  sizeofObject( sizeofObject( ukmLength ) ) + \
					  sizeofOID( ALGOID_FORTEZZA_KEYWRAP ) + \
					  sizeofObject( sizeofObject( recipientKeyInfoSize ) ),
					  CTAG_RI_KEYAGREE );
	writeShortInteger( stream, 3, DEFAULT_TAG );
	
	/* Write the originator's keyIdentifier, UKM, and Fortezza key wrap OID */
	writeConstructed( stream, ( int ) sizeofObject( auxInfoLength ), 
					  CTAG_KA_ORIG );
	writeOctetString( stream, auxInfo, auxInfoLength, 0 );
	writeConstructed( stream, ( int ) sizeofObject( ukmLength ), 
					  CTAG_KA_UKM );
	writeOctetString( stream, ukm, ukmLength, DEFAULT_TAG );
	swrite( stream, ALGOID_FORTEZZA_KEYWRAP, 
			sizeofOID( ALGOID_FORTEZZA_KEYWRAP ) );

	/* Write the recipient keying info */
	writeSequence( stream, ( int ) sizeofObject( recipientKeyInfoSize ) );
	writeSequence( stream, recipientKeyInfoSize );
	writeConstructed( stream, ( int ) sizeofObject( rKeyIDlength ), 0 );
	writeOctetString( stream, rKeyID, rKeyIDlength, DEFAULT_TAG );
	return( writeOctetString( stream, wrappedKey, wrappedKeyLength, 
							  DEFAULT_TAG ) );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*			Key Exchange Read/Write Function Access Information				*
*																			*
****************************************************************************/

const READKEYTRANS_FUNCTION keytransReadTable[] = {
	NULL,					/* KEYEX_NONE */
	readCmsKeytrans,		/* KEYEX_CMS */
	readCryptlibKeytrans,	/* KEYEX_CRYPTLIB */
#ifdef USE_PGP
	readPgpKeytrans,		/* KEYEX_PGP */
#else
	NULL,					/* KEYEX_PGP */
#endif /* USE_PGP */
	NULL, NULL, NULL
	};

const WRITEKEYTRANS_FUNCTION keytransWriteTable[] = {
	NULL,					/* KEYEX_NONE */
	writeCmsKeytrans,		/* KEYEX_CMS */
	writeCryptlibKeytrans,	/* KEYEX_CRYPTLIB */
#ifdef USE_PGP
	writePgpKeytrans,		/* KEYEX_PGP */
#else
	NULL,					/* KEYEX_PGP */
#endif /* USE_PGP */
	NULL, NULL, NULL
	};

const READKEK_FUNCTION kekReadTable[] = {
	NULL,					/* KEYEX_NONE */
	readCryptlibKek,		/* KEYEX_CMS */
	readCryptlibKek,		/* KEYEX_CRYPTLIB */
#ifdef USE_PGP
	readPgpKek,				/* KEYEX_PGP */
#else
	NULL,					/* KEYEX_PGP */
#endif /* USE_PGP */
	NULL, NULL, NULL
	};

const WRITEKEK_FUNCTION kekWriteTable[] = {
	NULL,					/* KEYEX_NONE */
	writeCryptlibKek,		/* KEYEX_CMS */
	writeCryptlibKek,		/* KEYEX_CRYPTLIB */
#ifdef USE_PGP
	writePgpKek,			/* KEYEX_PGP */
#else
	NULL,					/* KEYEX_PGP */
#endif /* USE_PGP */
	NULL, NULL, NULL
	};
