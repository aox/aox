/****************************************************************************
*																			*
*						cryptlib PKCS #15 Write Routines					*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/****************************************************************************
*																			*
*							Write PKCS #15 Objects							*
*																			*
****************************************************************************/

/* Write the wrapping needed for individual objects */

static void writeObjectWrapper( STREAM *stream, const int length,
								const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( tag >= 0 && tag < 32 );
	assert( length > 0 && length < 16384 );

	writeConstructed( stream, sizeofObject( length ), tag );
	writeConstructed( stream, length, CTAG_OV_DIRECT );
	}

/* Write a data item */

static int sizeofDataItem( const PKCS15_INFO *pkcs15infoPtr )
	{
	const int dataSize = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				sizeofObject( pkcs15infoPtr->dataDataSize );
	const int labelSize = \
			( pkcs15infoPtr->labelLength > 0 ) ? \
				sizeofObject( pkcs15infoPtr->labelLength ) : 0;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( labelSize >= 0 );
	assert( dataSize > 0 );

	return( ( int ) \
		sizeofObject( \
			sizeofObject( labelSize ) + \
			sizeofObject( sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
			sizeofObject( \
				sizeofObject( \
					sizeofOID( OID_CRYPTLIB_CONFIGDATA ) + dataSize ) ) ) );
	}

static int writeDataItem( STREAM *stream, const PKCS15_INFO *pkcs15infoPtr )
	{
	const BYTE *oid = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA ) ? \
				OID_CRYPTLIB_CONFIGDATA : \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX ) ? \
				OID_CRYPTLIB_USERINDEX : OID_CRYPTLIB_USERINFO;
	const int labelSize = \
			( pkcs15infoPtr->labelLength ) ? \
				sizeofObject( pkcs15infoPtr->labelLength ) : 0;
	const int contentSize = sizeofOID( oid ) + \
			( ( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				sizeofObject( pkcs15infoPtr->dataDataSize ) );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
			pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX || \
			pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO );
	assert( labelSize >= 0 );
	assert( contentSize > 0 );

	writeConstructed( stream, \
			sizeofObject( labelSize ) + \
			sizeofObject( sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
			sizeofObject( sizeofObject( contentSize ) ),
			CTAG_DO_OIDDO );
	writeSequence( stream, labelSize );
	if( labelSize > 0 )
		writeCharacterString( stream, ( BYTE * ) pkcs15infoPtr->label,
							  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
	writeSequence( stream, sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) );
	writeOID( stream, OID_CRYPTLIB_CONTENTTYPE );
	writeConstructed( stream, ( int ) sizeofObject( contentSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( stream, contentSize );
	writeOID( stream, oid );
	if( pkcs15infoPtr->dataType != CRYPT_IATTRIBUTE_USERINFO )
		/* UserInfo is a straight object, the others are SEQUENCEs of
		   objects */
		writeSequence( stream, pkcs15infoPtr->dataDataSize );
	return( swrite( stream, pkcs15infoPtr->dataData, \
					pkcs15infoPtr->dataDataSize ) );
	}

/* Flush a PKCS #15 collection to a stream */

int pkcs15Flush( STREAM *stream, const PKCS15_INFO *pkcs15info,
				 const int noPkcs15objects )
	{
	int pubKeySize = 0, privKeySize = 0, certSize = 0, dataSize = 0;
	int objectsSize = 0, i, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( noPkcs15objects >= 1 );

	/* Determine the overall size of the objects */
	for( i = 0; i < noPkcs15objects; i++ )
		{
		switch( pkcs15info[ i ].type )
			{
			case PKCS15_SUBTYPE_NONE:
				break;

			case PKCS15_SUBTYPE_NORMAL:
				pubKeySize += pkcs15info[ i ].pubKeyDataSize;
				privKeySize += pkcs15info[ i ].privKeyDataSize;
				/* Drop through */

			case PKCS15_SUBTYPE_CERT:
				certSize += pkcs15info[ i ].certDataSize;
				break;

			case PKCS15_SUBTYPE_SECRETKEY:
				assert( NOTREACHED );
				break;

			case PKCS15_SUBTYPE_DATA:
				dataSize += sizeofDataItem( &pkcs15info[ i ] );
				break;

			default:
				assert( NOTREACHED );
			}
		}

	/* Determine how much data there is to write.  If there's no data
	   present, let the caller know that the keyset is empty */
	if( pubKeySize > 0 )
		objectsSize += sizeofObject( sizeofObject( pubKeySize ) );
	if( privKeySize > 0 )
		objectsSize += sizeofObject( sizeofObject( privKeySize ) );
	if( certSize > 0 )
		objectsSize += sizeofObject( sizeofObject( certSize ) );
	if( dataSize > 0 )
		objectsSize += sizeofObject( sizeofObject( dataSize ) );
	if( objectsSize <= 0 )
		return( OK_SPECIAL );	/* Keyset is empty */

	/* Write the header information and each public key, private key, and
	   cert */
	writeCMSheader( stream, OID_PKCS15_CONTENTTYPE,
					sizeofShortInteger( 0 ) + sizeofObject( objectsSize ),
					FALSE );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	status = writeSequence( stream, objectsSize );
	if( cryptStatusOK( status ) && privKeySize > 0 )
		{
		writeObjectWrapper( stream, privKeySize, CTAG_PO_PRIVKEY );
		for( i = 0; cryptStatusOK( status ) && i < noPkcs15objects; i++ )
			{
			if( pkcs15info[ i ].privKeyDataSize > 0 )
				status = swrite( stream, pkcs15info[ i ].privKeyData,
								 pkcs15info[ i ].privKeyDataSize );
			}
		}
	if( cryptStatusOK( status ) && pubKeySize > 0 )
		{
		writeObjectWrapper( stream, pubKeySize, CTAG_PO_PUBKEY );
		for( i = 0; cryptStatusOK( status ) && i < noPkcs15objects; i++ )
			{
			if( pkcs15info[ i ].pubKeyDataSize > 0 )
				status = swrite( stream, pkcs15info[ i ].pubKeyData,
								 pkcs15info[ i ].pubKeyDataSize );
			}
		}
	if( cryptStatusOK( status ) && certSize > 0 )
		{
		writeObjectWrapper( stream, certSize, CTAG_PO_CERT );
		for( i = 0; cryptStatusOK( status ) && i < noPkcs15objects; i++ )
			{
			if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_NORMAL && \
				  pkcs15info[ i ].certDataSize > 0 ) || \
				( pkcs15info[ i ].type == PKCS15_SUBTYPE_CERT ) )
				status = swrite( stream, pkcs15info[ i ].certData,
								 pkcs15info[ i ].certDataSize );
			}
		}
	if( cryptStatusOK( status ) && dataSize > 0 )
		{
		writeObjectWrapper( stream, dataSize, CTAG_PO_DATA );
		for( i = 0; cryptStatusOK( status ) && i < noPkcs15objects; i++ )
			{
			if( pkcs15info[ i ].dataDataSize > 0 )
				status = writeDataItem( stream, &pkcs15info[ i ] );
			}
		}
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}

	return( sflush( stream ) );
	}
#endif /* USE_PKCS15 */
