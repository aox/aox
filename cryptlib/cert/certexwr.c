/****************************************************************************
*																			*
*						Certificate Attribute Write Routines				*
*						 Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Attribute Write Routines					*
*																			*
****************************************************************************/

/* When we write the attributes as a SET OF Attribute (as CMS does), we have
   to sort them by encoded value.  This is an incredible nuisance since it
   requires that each value be encoded and stored in encoded form, then the
   encoded forms sorted and emitted in that order.  To avoid this hassle, we
   keep a record of the current lowest encoded form and then find the next
   one by encoding enough information (the SEQUENCE and OID, CMS attributes
   don't have critical flags) on the fly to distinguish them.  This is
   actually less overhead than storing the encoded form because there are
   only a small total number of attributes (usually 3) and we don't have to
   malloc() storage for each one and manage the stored form if we do things
   on the fly */

#define ATTR_ENCODED_SIZE	( 16 + MAX_OID_SIZE )

static ATTRIBUTE_LIST *getNextEncodedAttribute( ATTRIBUTE_LIST *attributeListPtr,
												BYTE *prevEncodedForm )
	{
	ATTRIBUTE_LIST *currentAttributeListPtr = NULL;
	STREAM stream;
	BYTE currentEncodedForm[ ATTR_ENCODED_SIZE ], buffer[ ATTR_ENCODED_SIZE ];

	/* Connect the output stream and give the current encoded form the
	   maximum possible value */
	sMemOpen( &stream, buffer, ATTR_ENCODED_SIZE );
	currentEncodedForm[ 0 ] = 0xFF;

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	while( attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int attributeDataSize;

		/* Determine the size of the attribute payload */
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			attributeDataSize = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			attributeDataSize = attributeListPtr->encodedSize;

		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeInfoPtr->oid ) + \
					   ( int ) sizeofObject( attributeDataSize ) );
		swrite( &stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it */
		if( memcmp( prevEncodedForm, buffer, ATTR_ENCODED_SIZE ) < 0 && \
			memcmp( buffer, currentEncodedForm, ATTR_ENCODED_SIZE ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, ATTR_ENCODED_SIZE );
			currentAttributeListPtr = attributeListPtr;
			}

		/* Move on to the next attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID )
			attributeListPtr = attributeListPtr->next;
		}

	/* Write the blob-type attributes */
	while( attributeListPtr != NULL )
		{
		assert( isBlobAttribute( attributeListPtr ) );

		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeListPtr->oid ) + \
					   ( int ) sizeofObject( attributeListPtr->valueLength ) );
		swrite( &stream, attributeListPtr->oid,
				sizeofOID( attributeListPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it */
		if( memcmp( prevEncodedForm, buffer, ATTR_ENCODED_SIZE ) < 0 && \
			memcmp( buffer, currentEncodedForm, ATTR_ENCODED_SIZE ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, ATTR_ENCODED_SIZE );
			currentAttributeListPtr = attributeListPtr;
			}
		}

	sMemDisconnect( &stream );

	/* Remember the encoded form of the attribute and return a pointer to
	   it */
	memcpy( prevEncodedForm, currentEncodedForm, ATTR_ENCODED_SIZE );
	return( currentAttributeListPtr );
	}

/* Determine the size of a set of attributes and validate and preprocess the
   attribute information */

int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr )
	{
	int signUnrecognised, attributeSize = 0;

	/* If there's nothing to write, return now */
	if( attributeListPtr == NULL )
		return( 0 );

	assert( isReadPtr( attributeListPtr, ATTRIBUTE_LIST ) );

	/* Determine the size of the recognised attributes */
	while( attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int length = sizeofOID( attributeInfoPtr->oid );

		/* Determine the size of this attribute */
		if( attributeInfoPtr->flags & FL_CRITICAL )
			length += sizeofBoolean();
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			length += ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			length += attributeListPtr->encodedSize;
		attributeSize += ( int ) sizeofObject( sizeofObject( length ) );

		/* Skip everything else in the current attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID )
			attributeListPtr = attributeListPtr->next;
		}

	/* If we're not going to be signing the blob-type attributes, return */
	krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
					 &signUnrecognised, 
					 CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
	if( !signUnrecognised )
		return( attributeSize );

	/* Determine the size of the blob-type attributes */
	while( attributeListPtr != NULL )
		{
		assert( isBlobAttribute( attributeListPtr ) );

		attributeSize += ( int ) \
						 sizeofObject( sizeofOID( attributeListPtr->oid ) + \
						 sizeofObject( attributeListPtr->valueLength ) );
		if( attributeListPtr->flags & ATTR_FLAG_CRITICAL )
			attributeSize += sizeofBoolean();
		attributeListPtr = attributeListPtr->next;
		}

	return( attributeSize );
	}

/* Write an attribute field */

int writeAttributeField( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr )
	{
	const BOOLEAN isSpecial = ( attributeListPtr->fifoPos ) ? TRUE : FALSE;
	const ATTRIBUTE_INFO *attributeInfoPtr = ( isSpecial ) ? \
		attributeListPtr->encodingFifo[ --attributeListPtr->fifoPos ] : \
		attributeListPtr->attributeInfoPtr;
	const void *dataPtr = attributeListPtr->value;
	int tag, size, payloadSize, fieldType = attributeInfoPtr->fieldType;

	assert( isWritePtr( attributeListPtr, ATTRIBUTE_LIST ) );

	/* If this is just a marker for a series of CHOICE alternatives, return
	   without doing anything */
	if( fieldType == FIELDTYPE_CHOICE )
		return( CRYPT_OK );

	/* If this is a special-case object, determine the size of the data
	   payload */
	if( isSpecial )
		payloadSize = attributeListPtr->sizeFifo[ attributeListPtr->fifoPos ];

	/* Calculate the size of the encoded data */
	if( isSpecial )
		{
		/* If it's a special-case field, the data size is taken from
		   somewhere other than the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				/* Fixed-value blob (as opposed to user-supplied one) */
				size = ( int ) attributeInfoPtr->defaultValue;
				break;

			case FIELDTYPE_IDENTIFIER:
				size = sizeofOID( attributeInfoPtr->oid );
				break;

			case BER_INTEGER:
				size = sizeofShortInteger( attributeInfoPtr->defaultValue );
				break;

			case BER_SEQUENCE:
			case BER_SET:
				size = ( int ) sizeofObject( payloadSize );
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR );
			}
		}
	else
		/* It's a standard object, take the size from the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
			case BER_OBJECT_IDENTIFIER:
				size = attributeListPtr->valueLength;
				break;

			case FIELDTYPE_DN:
				size = sizeofDN( attributeListPtr->value );
				break;

			case FIELDTYPE_IDENTIFIER:
				size = sizeofOID( attributeInfoPtr->oid );
				break;

			case BER_BITSTRING:
				size = sizeofBitString( attributeListPtr->intValue );
				break;

			case BER_BOOLEAN:
				size = sizeofBoolean();
				break;

			case BER_ENUMERATED:
				size = sizeofEnumerated( attributeListPtr->intValue );
				break;

			case BER_INTEGER:
				size = sizeofShortInteger( attributeListPtr->intValue );
				break;

			case BER_NULL:
				/* This is stored as a pseudo-numeric value CRYPT_UNUSED so
				   we can't fall through to the default handler */
				size = sizeofNull();
				break;

			case BER_OCTETSTRING:
				/* If it's an integer equivalent to an OCTET STRING hole, we
				   need to make sure we encode it correctly if the high bit
				   is set */
				if( attributeInfoPtr->fieldEncodedType == BER_INTEGER )
					size = sizeofInteger( dataPtr, 
										  attributeListPtr->valueLength );
				else
					size = ( int ) sizeofObject( attributeListPtr->valueLength );
				break;

			case BER_TIME_GENERALIZED:
				size = sizeofGeneralizedTime();
				break;

			case BER_TIME_UTC:
				size = sizeofUTCTime();
				break;

			default:
				size = ( int ) sizeofObject( attributeListPtr->valueLength );
			}

	/* If we're just calculating the attribute size, don't write any data */
	if( stream == NULL )
		return( ( attributeInfoPtr->flags & FL_EXPLICIT ) ? \
				( int ) sizeofObject( size ) : size );

	/* If the field is explicitly tagged, add another layer of wrapping */
	if( attributeInfoPtr->flags & FL_EXPLICIT )
		writeConstructed( stream, size, attributeInfoPtr->fieldEncodedType );

	/* If the encoded field type differs from the actual field type (because
	   if implicit tagging), and we're not specifically using explicit
	   tagging, and it's not a DN in a GeneralName (which is a tagged IMPLICIT
	   SEQUENCE overridden to make it EXPLICIT because of the tagged CHOICE
	   encoding rules), set the tag to the encoded field type rather than the
	   actual field type */
	if( attributeInfoPtr->fieldEncodedType && \
		!( attributeInfoPtr->flags & FL_EXPLICIT ) && \
		attributeInfoPtr->fieldType != FIELDTYPE_DN )
		tag = attributeInfoPtr->fieldEncodedType;
	else
		tag = DEFAULT_TAG;

	/* Write the data as appropriate */
	if( isSpecial )
		{
		/* If it's a special-case field, the data is taken from somewhere
		   other than the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				/* Fixed-value blob (as opposed to user-supplied one) */
				return( swrite( stream, attributeInfoPtr->extraData, size ) );

			case FIELDTYPE_IDENTIFIER:
				return( swrite( stream, attributeInfoPtr->oid, size ) );

			case BER_INTEGER:
				return( writeShortInteger( stream, attributeInfoPtr->defaultValue, 
										   tag ) );

			case BER_SEQUENCE:
			case BER_SET:
				if( tag != DEFAULT_TAG )
					return( writeConstructed( stream, payloadSize, tag ) );
				return( ( fieldType == BER_SET ) ? \
						writeSet( stream, payloadSize ) : \
						writeSequence( stream, payloadSize ) );
			}
		
		assert( NOTREACHED );
		return( CRYPT_ERROR );
		}

	/* It's a standard object, take the data from the user-supplied data */
	switch( fieldType )
		{
		case FIELDTYPE_BLOB:
			return( swrite( stream, dataPtr, attributeListPtr->valueLength ) );

		case FIELDTYPE_DN:
			return( writeDN( stream, attributeListPtr->value, tag ) );

		case FIELDTYPE_IDENTIFIER:
			return( swrite( stream, attributeInfoPtr->oid, size ) );

		case BER_BITSTRING:
			return( writeBitString( stream, ( int ) attributeListPtr->intValue, tag ) );

		case BER_BOOLEAN:
			return( writeBoolean( stream, ( BOOLEAN ) attributeListPtr->intValue, tag ) );

		case BER_ENUMERATED:
			return( writeEnumerated( stream, ( int ) attributeListPtr->intValue, tag ) );

		case BER_INTEGER:
			return( writeShortInteger( stream, attributeListPtr->intValue, tag ) );

		case BER_NULL:
			return( writeNull( stream, tag ) );

		case BER_OBJECT_IDENTIFIER:
			if( tag != DEFAULT_TAG )
				{
				/* This gets a bit messy because the OID is stored in 
				   encoded form in the attribute, to write it as a tagged 
				   value we have to write a different first byte */
				sputc( stream, tag );
				return( swrite( stream, ( ( BYTE * ) dataPtr ) + 1,
								attributeListPtr->valueLength - 1 ) );
				}
			return( swrite( stream, dataPtr, attributeListPtr->valueLength ) );

		case BER_OCTETSTRING:
			/* If it's an integer equivalent to an OCTET STRING hole, we
			   need to use the INTEGER encoding rules rather than the
			   OCTET STRING ones */
			if( attributeInfoPtr->fieldEncodedType == BER_INTEGER )
				return( writeInteger( stream, dataPtr, 
									  attributeListPtr->valueLength, DEFAULT_TAG ) );
			return( writeOctetString( stream, dataPtr, 
									  attributeListPtr->valueLength, tag ) );

		case BER_STRING_BMP:
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_UTF8:
			return( writeCharacterString( stream, dataPtr, attributeListPtr->valueLength,
										  ( tag == DEFAULT_TAG ) ? fieldType : tag ) );

		case BER_TIME_GENERALIZED:
			return( writeGeneralizedTime( stream, *( time_t * ) dataPtr, tag ) );

		case BER_TIME_UTC:
			return( writeUTCTime( stream, *( time_t * ) dataPtr, tag ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Write an attribute */

static int writeAttribute( STREAM *stream, 
						   ATTRIBUTE_LIST **attributeListPtrPtr,
						   const int wrapperTagSet )
	{
	ATTRIBUTE_LIST *attributeListPtr = *attributeListPtrPtr;
	int flagSize, status;

	assert( isWritePtr( attributeListPtrPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( *attributeListPtrPtr, ATTRIBUTE_LIST ) );

	/* If it's a non-blob attribute, write it field by field */
	if( !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int dataLength, length = sizeofOID( attributeInfoPtr->oid );

		assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

		/* Determine the size of the attribute payload */
		flagSize = ( attributeInfoPtr->flags & FL_CRITICAL ) ? \
				   sizeofBoolean() : 0;
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			dataLength = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			dataLength = attributeListPtr->encodedSize;

		/* Write the outer SEQUENCE, OID, critical flag (if it's set) and
		   appropriate wrapper for the attribute payload */
		writeSequence( stream, length + flagSize + \
					   ( int ) sizeofObject( dataLength ) );
		swrite( stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );
		if( flagSize )
			writeBoolean( stream, TRUE, DEFAULT_TAG );
		if( wrapperTagSet )
			status = writeSet( stream, dataLength );
		else
			status = writeOctetStringHole( stream, dataLength, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the current attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID )
			{
			/* Write any encapsulating SEQUENCEs if necessary, followed by
			   the field itself.  In some rare instances we may have a zero-
			   length SEQUENCE (if all the member(s) of the sequence have
			   default values), so we only try to write the member if there's
			   encoding information for it present */
			attributeListPtr->fifoPos = attributeListPtr->fifoEnd;
			while( cryptStatusOK( status ) && attributeListPtr->fifoPos )
				status = writeAttributeField( stream, 
									( ATTRIBUTE_LIST * ) attributeListPtr );
			if( cryptStatusOK( status ) && \
				attributeListPtr->attributeInfoPtr != NULL )
				status = writeAttributeField( stream, 
									( ATTRIBUTE_LIST * ) attributeListPtr );
			if( cryptStatusError( status ) )
				return( status );

			/* Move on to the next attribute field */
			attributeListPtr = attributeListPtr->next;
			}

		*attributeListPtrPtr = attributeListPtr;
		return( CRYPT_OK );
		}

	/* It's a blob attribute, write the header, OID, critical flag (if 
	   present), and payload wrapped up as appropriate */
	flagSize = ( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ? \
			   sizeofBoolean() : 0;
	writeSequence( stream, sizeofOID( attributeListPtr->oid ) + flagSize + \
				   ( int ) sizeofObject( attributeListPtr->valueLength ) );
	swrite( stream, attributeListPtr->oid,
			sizeofOID( attributeListPtr->oid ) );
	if( flagSize )
		writeBoolean( stream, TRUE, DEFAULT_TAG );
	if( wrapperTagSet )
		writeSet( stream, attributeListPtr->valueLength );
	else
		writeOctetStringHole( stream, attributeListPtr->valueLength, 
							  DEFAULT_TAG );
	status = swrite( stream, attributeListPtr->value,
					 attributeListPtr->valueLength );
	if( cryptStatusOK( status ) )
		*attributeListPtrPtr = attributeListPtr->next;
	return( status );
	}

/* Write a set of attributes */

int writeAttributes( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr,
					 const CRYPT_CERTTYPE_TYPE type, const int attributeSize )
	{
	int signUnrecognised, status = CRYPT_OK;

	/* If there's nothing to write, return now */
	if( attributeSize == 0 )
		return( CRYPT_OK );

	assert( isWritePtr( attributeListPtr, ATTRIBUTE_LIST ) );

	/* CMS attributes work somewhat differently from normal attributes in 
	   that, since they're encoded as a SET OF Attribute, they have to be 
	   sorted according to their encoded form before being written.  For 
	   this reason we don't write them sorted by OID as with the other 
	   attributes, but keep writing the next-lowest attribute until they've 
	   all been written */
	if( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES || \
		type == CRYPT_CERTTYPE_RTCS_REQUEST || \
		type == CRYPT_CERTTYPE_RTCS_RESPONSE )
		{
		ATTRIBUTE_LIST *currentAttributePtr;
		BYTE currentEncodedForm[ ATTR_ENCODED_SIZE ];

		/* Write the wrapper, depending on the object type */
		if( type == CRYPT_CERTTYPE_RTCS_REQUEST )
			writeSet( stream, attributeSize );
		else
			writeConstructed( stream, attributeSize, 
							  ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
								CTAG_SI_AUTHENTICATEDATTRIBUTES : \
								CTAG_RP_EXTENSIONS );

		/* Write the attributes in sorted form */
		memset( currentEncodedForm, 0, ATTR_ENCODED_SIZE );	/* Set lowest encoded form */
		currentAttributePtr = getNextEncodedAttribute( attributeListPtr,
													   currentEncodedForm );
		while( currentAttributePtr != NULL && cryptStatusOK( status ) )
			{
			status = writeAttribute( stream, &currentAttributePtr, TRUE );
			currentAttributePtr = getNextEncodedAttribute( attributeListPtr,
														   currentEncodedForm );
			}
		return( status );
		}

	/* Write the appropriate extensions tag for the certificate object and 
	   determine how far we can read.  CRLs and OCSP requests/responses have 
	   two extension types that have different tagging, per-entry extensions 
	   and entire-CRL/request extensions.  To differentiate between the two, 
	   we write per-entry extensions with a type of CRYPT_CERTTYPE_NONE */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_CRL:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ),
							  ( type == CRYPT_CERTTYPE_CERTIFICATE ) ? \
							  CTAG_CE_EXTENSIONS : CTAG_CL_EXTENSIONS );
			writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			writeSequence( stream, sizeofOID( OID_PKCS9_EXTREQ ) + \
						   ( int ) sizeofObject( sizeofObject( attributeSize ) ) );
			swrite( stream, OID_PKCS9_EXTREQ, sizeofOID( OID_PKCS9_EXTREQ ) );
			writeSet( stream, ( int ) sizeofObject( attributeSize ) );
			writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* No wrapper, extensions are written directly */
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_PKIUSER:
		case CRYPT_CERTTYPE_NONE:
			writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ), 
							  CTAG_OR_EXTENSIONS );
			writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ), 
							  CTAG_OP_EXTENSIONS );
			writeSequence( stream, attributeSize );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	while( attributeListPtr != NULL && \
		   !isBlobAttribute( attributeListPtr ) && cryptStatusOK( status ) )
		status = writeAttribute( stream, &attributeListPtr, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're signing the blob-type attributes, write those as well */
	krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
					 &signUnrecognised,
					 CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
	if( signUnrecognised )
		{
		/* Write the blob-type attributes */
		while( attributeListPtr != NULL && cryptStatusOK( status ) )
			status = writeAttribute( stream, &attributeListPtr, FALSE );
		}
	return( status );
	}
