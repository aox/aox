/****************************************************************************
*																			*
*						Certificate Validity Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*					Add/Delete/Check Validity Information					*
*																			*
****************************************************************************/

/* Find an entry in a validity info list */

static VALIDITY_INFO *findValidityEntry( const VALIDITY_INFO *listPtr, 
										 const void *value, 
										 const int valueLength )
	{
	const int vCheck = checksumData( value, valueLength );

	assert( isReadPtr( listPtr, VALIDITY_INFO ) );

	/* Check whether this entry is present in the list */
	while( listPtr != NULL )
		{
		if( listPtr->dCheck == vCheck && \
			!memcmp( listPtr->data, value, valueLength ) )
			return( CRYPT_OK );
		listPtr = listPtr->next;
		}

	return( NULL );
	}

/* Check whether a cert is valid */

int checkValidity( const CERT_INFO *certInfoPtr, 
				   CERT_INFO *validityInfoPtr )
	{
	VALIDITY_INFO *validityEntry;
	BYTE certHash[ CRYPT_MAX_HASHSIZE ];
	int certHashLength, status;

	assert( isReadPtr( certInfoPtr, CERT_INFO ) );
	assert( isWritePtr( validityInfoPtr, CERT_INFO ) );
	assert( validityInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE );

	/* If there's no validity information present, we can't say anything 
	   about the cert */
	if( validityInfoPtr->validityInfo == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Get the cert hash and use it to check whether there's an entry for 
	   this cert in the list.  We read the cert hash indirectly since it's 
	   computed on demand and may not have been evaluated yet */
	status = getCertComponent( ( CERT_INFO * ) certInfoPtr, 
							   CRYPT_CERTINFO_FINGERPRINT_SHA,
							   certHash, &certHashLength );
	if( cryptStatusError( status ) )
		return( status );
	validityEntry = findValidityEntry( validityInfoPtr->validityInfo, 
									   certHash, certHashLength );
	if( validityEntry == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Select the entry that contains the validity info and return the 
	   cert's status */
	validityInfoPtr->currentValidity = validityEntry;
	return( ( validityEntry->status == TRUE ) ? \
			CRYPT_OK : CRYPT_ERROR_INVALID );
	}

/* Add an entry to a revocation list */

int addValidityEntry( VALIDITY_INFO **listHeadPtr, 
					  VALIDITY_INFO **newEntryPosition,
					  const void *value, const int valueLength )
	{
	VALIDITY_INFO *newElement;

	assert( isWritePtr( listHeadPtr, VALIDITY_INFO * ) );
	assert( newEntryPosition == NULL || \
			isWritePtr( newEntryPosition, VALIDITY_INFO * ) );

	/* Find the insertion point for the new entry, unless we're reading data
	   from a pre-encoded CRL, in which case we just drop it in at the start.
	   The absence of checking for data from a  existing CRL is necessary in 
	   order to provide same-day service for large CRLs */
	if( *listHeadPtr != NULL && \
		findValidityEntry( *listHeadPtr, value, valueLength ) != NULL )
		/* If we found an entry that matches the one being added, we can't 
		   add it again */
		return( CRYPT_ERROR_DUPLICATE );

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement = ( VALIDITY_INFO * ) \
			clAlloc( "addValidityEntry", sizeof( VALIDITY_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( VALIDITY_INFO ) );
	memcpy( newElement->data, value, valueLength );
	newElement->dCheck = checksumData( value, valueLength );

	/* Insert the new element into the list */
	insertSingleListElement( listHeadPtr, *listHeadPtr, newElement );
	if( newEntryPosition != NULL )
		*newEntryPosition = newElement;
	return( CRYPT_OK );
	}

/* Delete a validity info list */

void deleteValidityEntries( VALIDITY_INFO **listHeadPtr )
	{
	VALIDITY_INFO *entryListPtr = *listHeadPtr;

	assert( isWritePtr( listHeadPtr, VALIDITY_INFO * ) );

	*listHeadPtr = NULL;

	/* Destroy any remaining list items */
	while( entryListPtr != NULL )
		{
		VALIDITY_INFO *itemToFree = entryListPtr;

		entryListPtr = entryListPtr->next;
		if( itemToFree->attributes != NULL )
			deleteAttributes( &itemToFree->attributes );
		zeroise( itemToFree, sizeof( VALIDITY_INFO ) );
		clFree( "deleteValidityEntries", itemToFree );
		}
	}

/* Copy a validity info list */

int copyValidityEntries( VALIDITY_INFO **destListHeadPtr,
						 const VALIDITY_INFO *srcListPtr,
						 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						 CRYPT_ERRTYPE_TYPE *errorType )
	{
	const VALIDITY_INFO *srcListCursor;
	VALIDITY_INFO *destListCursor;

	assert( isWritePtr( destListHeadPtr, REVOCATION_INFO * ) );
	assert( *destListHeadPtr == NULL );	/* Dest.should be empty */

	/* Copy all revocation entries from source to destination */
	for( srcListCursor = srcListPtr; srcListCursor != NULL;
		 srcListCursor = srcListCursor->next )
		{
		VALIDITY_INFO *newElement;

		/* Allocate the new entry and copy the data from the existing one 
		   across.  We don't copy the attributes because there aren't any
		   that should be carried from request to response */
		if( ( newElement = ( VALIDITY_INFO * ) \
					clAlloc( "copyValidityEntries", \
							 sizeof( VALIDITY_INFO ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( newElement, srcListCursor, sizeof( VALIDITY_INFO ) );
		newElement->attributes = NULL;
		newElement->next = NULL;

		/* Set the status to invalid/unknown by default, this means that any 
		   entries that we can't do anything with automatically get the 
		   correct status associated with them */
		newElement->status = FALSE;
		newElement->extStatus = CRYPT_CERTSTATUS_UNKNOWN;

		/* Link the new element into the list */
		if( *destListHeadPtr == NULL )
			*destListHeadPtr = destListCursor = newElement;
		else
			{
			destListCursor->next = newElement;
			destListCursor = newElement;
			}
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/write RTCS Information						*
*																			*
****************************************************************************/

/* Read/write an RTCS resquest entry:

	Entry ::= SEQUENCE {
		certHash		OCTET STRING SIZE(20),
		legacyID		IssuerAndSerialNumber OPTIONAL
		} */

int sizeofRtcsRequestEntry( VALIDITY_INFO *rtcsEntry )
	{
	assert( isWritePtr( rtcsEntry, VALIDITY_INFO ) );

	return( ( int ) sizeofObject( sizeofObject( KEYID_SIZE ) ) );
	}

int readRtcsRequestEntry( STREAM *stream, VALIDITY_INFO **listHeadPtr,
						  CERT_INFO *certInfoPtr )
	{
	BYTE idBuffer[ CRYPT_MAX_HASHSIZE ];
	int endPos, length, status;

	assert( isWritePtr( listHeadPtr, VALIDITY_INFO * ) );
	assert( isWritePtr( certInfoPtr, CERT_INFO ) );

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Read the cert ID and add it to the validity information list */
	status = readOctetString( stream, idBuffer, &length, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusOK( status ) )
		{
		if( length != KEYID_SIZE )
			status = CRYPT_ERROR_BADDATA;
		else
			if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
			/* Skip the legacy ID */
			status = readUniversal( stream );
		}
	if( cryptStatusOK( status ) )
		status = addValidityEntry( listHeadPtr, NULL, idBuffer, KEYID_SIZE );
	return( status );
	}

int writeRtcsRequestEntry( STREAM *stream, const VALIDITY_INFO *rtcsEntry )
	{
	assert( isReadPtr( rtcsEntry, VALIDITY_INFO ) );

	/* Write the header and ID information */
	writeSequence( stream, sizeofObject( KEYID_SIZE ) );
	return( writeOctetString( stream, rtcsEntry->data, KEYID_SIZE, 
							  DEFAULT_TAG ) );
	}

/* Read/write an RTCS response entry:

	Entry ::= SEQUENCE {				-- basic response
		certHash		OCTET STRING SIZE(20),
		status			BOOLEAN
		}
	
	Entry ::= SEQUENCE {				-- Full response
		certHash		OCTET STRING SIZE(20),
		status			ENUMERATED,
		statusInfo		ANY DEFINED BY status OPTIONAL,
		extensions	[0]	Extensions OPTIONAL
		} */

int sizeofRtcsResponseEntry( VALIDITY_INFO *rtcsEntry, 
							 const BOOLEAN isFullResponse )
	{
	assert( isWritePtr( rtcsEntry, VALIDITY_INFO ) );

	/* If it's a basic response the size is fairly easy to calculate */
	if( !isFullResponse )
		return( ( int ) sizeofObject( sizeofObject( KEYID_SIZE ) + \
									  sizeofBoolean() ) );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	rtcsEntry->attributeSize = sizeofAttributes( rtcsEntry->attributes );

	return( ( int ) \
			sizeofObject( sizeofObject( KEYID_SIZE ) + sizeofEnumerated( 1 ) + \
						  ( ( rtcsEntry->attributeSize ) ? \
							( int ) sizeofObject( rtcsEntry->attributeSize ) : 0 ) ) );
	}

int readRtcsResponseEntry( STREAM *stream, VALIDITY_INFO **listHeadPtr,
						   CERT_INFO *certInfoPtr, 
						   const BOOLEAN isFullResponse )
	{
	VALIDITY_INFO *newEntry;
	BYTE idBuffer[ CRYPT_MAX_HASHSIZE ];
	int endPos, length, status;

	assert( isWritePtr( listHeadPtr, VALIDITY_INFO * ) );
	assert( isWritePtr( certInfoPtr, CERT_INFO ) );

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Read the ID information */
	status = readOctetString( stream, idBuffer, &length, KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( length != KEYID_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Add the entry to the validity information list */
	status = addValidityEntry( listHeadPtr, &newEntry, idBuffer, KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the status information and record the valid/not-valid status  */
	if( isFullResponse )
		{
		status = readEnumerated( stream, &newEntry->extStatus );
		newEntry->status = ( newEntry->extStatus == CRYPT_CERTSTATUS_VALID ) ? \
						   TRUE : FALSE;
		}
	else
		{
		status = readBoolean( stream, &newEntry->status );
		newEntry->extStatus = newEntry->status ? \
					CRYPT_CERTSTATUS_VALID : CRYPT_CERTSTATUS_NOTVALID;
		}
	if( cryptStatusError( status ) || \
		stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
		return( status );

	/* Read the extensions.  Since these are per-entry extensions we read 
	   the wrapper here and read the extensions themselves as 
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_RTCS to make sure 
	   that they're processed as required */
	status = readConstructed( stream, &length, 0 );
	if( cryptStatusError( status ) )
		return( status );
	return( readAttributes( stream, &newEntry->attributes,
							CRYPT_CERTTYPE_NONE, length,
							&certInfoPtr->errorLocus, 
							&certInfoPtr->errorType ) );
	}

int writeRtcsResponseEntry( STREAM *stream, const VALIDITY_INFO *rtcsEntry,
							const BOOLEAN isFullResponse )
	{
	int status;

	assert( isReadPtr( rtcsEntry, VALIDITY_INFO ) );
	assert( rtcsEntry->extStatus >= CRYPT_CERTSTATUS_VALID && \
			rtcsEntry->extStatus <= CRYPT_CERTSTATUS_UNKNOWN );

	/* If it's a basic response, it's a straightforward fixed-length 
	   object */
	if( !isFullResponse )
		{
		writeSequence( stream, sizeofObject( KEYID_SIZE ) + 
							   sizeofBoolean() );
		writeOctetString( stream, rtcsEntry->data, KEYID_SIZE, DEFAULT_TAG );
		return( writeBoolean( stream, rtcsEntry->status, DEFAULT_TAG ) );
		}

	/* Write an extended response */
	writeSequence( stream, sizeofObject( KEYID_SIZE ) + sizeofEnumerated( 1 ) );
	writeOctetString( stream, rtcsEntry->data, KEYID_SIZE, DEFAULT_TAG );
	status = writeEnumerated( stream, rtcsEntry->extStatus, DEFAULT_TAG );
	if( cryptStatusError( status ) || rtcsEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions 
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_RTCS 
	   to make sure that they're processed as required */
	return( writeAttributes( stream, rtcsEntry->attributes, 
							 CRYPT_CERTTYPE_NONE, rtcsEntry->attributeSize ) );
	}
