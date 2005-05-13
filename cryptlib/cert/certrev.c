/****************************************************************************
*																			*
*						Certificate Revocation Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The maximum length of ID that can be stored in a REVOCATION_INFO entry.
   Larger IDs require external storage */

#define MAX_ID_SIZE		128

/* Usually when we add revocation information we perform various checks such 
   as making sure we're not adding duplicate information, however when 
   processing the mega-CRLs from some CAs this becomes prohibitively 
   expensive.  To solve this problem, we perform checking up to a certain
   number of entries and after that just drop in any further entries as is
   in order to provide same-day service.  The following value defines the
   CRL threshold size in bytes at which we stop performing checks when we
   add new entries */

#define CRL_SORT_LIMIT	8192

/* Context-specific tags for OCSP certificate identifier types */

enum { CTAG_OI_CERTIFICATE, CTAG_OI_CERTIDWITHSIG, CTAG_OI_RTCS };

/* OCSP cert status values */

enum { OCSP_STATUS_NOTREVOKED, OCSP_STATUS_REVOKED, OCSP_STATUS_UNKNOWN };

/****************************************************************************
*																			*
*					Add/Delete/Check Revocation Information					*
*																			*
****************************************************************************/

/* Find an entry in a revocation list.  This is done using a linear search, 
   which isn't very optimal but anyone trying to do anything useful with 
   mega-CRLs (or with CRLs in general) is in more trouble than basic search 
   algorithm choice.  In other words it doesn't really make much difference 
   whether we have an optimal or suboptimal implementation of a 
   fundamentally broken mechanism like CRLs.
   
   The value is either a serialNumber or a hash of some form (issuerID, 
   certHash), we don't bother distinguishing the exact type since the 
   chances of a hash collision are virtually nonexistant */

static int findRevocationEntry( const REVOCATION_INFO *listPtr, 
								REVOCATION_INFO **insertPoint,
								const void *value, const int valueLength,
								const BOOLEAN sortEntries )
	{
	const REVOCATION_INFO *prevElement = NULL;
	const int dCheck = checksumData( value, valueLength );

	assert( isReadPtr( listPtr, sizeof( REVOCATION_INFO ) ) );
	assert( insertPoint == NULL || \
			isWritePtr( insertPoint, sizeof( REVOCATION_INFO * ) ) );

	/* Clear the return value */
	if( insertPoint != NULL )
		*insertPoint = NULL;

	/* Find the correct place in the list to insert the new element and check
	   for duplicates.  If requested we sort the entries by serial number 
	   (or, more generally, data value) for no adequately explored reason 
	   (some implementations can optimise the searching of CRLs based on 
	   this, but since there's no agreement on whether to do it or not you 
	   can't tell whether it's safe to rely on it) */
	while( listPtr != NULL )
		{
		if( ( sortEntries || dCheck == listPtr->dCheck ) && \
			listPtr->dataLength == valueLength )
			{
			const int compareStatus = memcmp( listPtr->data,
											  value, valueLength );

			if( !compareStatus )
				{
				/* We found a matching entry, tell the caller which one it 
				   is if required */
				if( insertPoint != NULL )
					*insertPoint = ( REVOCATION_INFO * ) listPtr;
				return( CRYPT_OK );
				}
			if( sortEntries && compareStatus > 0 )
				break;					/* Insert before this point */
			}
		else
			if( sortEntries && listPtr->dataLength > valueLength )
				break;					/* Insert before this point */

		prevElement = listPtr;
		listPtr = listPtr->next;
		}

	/* We can't find a matching entry, return the revocation entry after 
	   which we should insert the new value */
	if( insertPoint != NULL )
		*insertPoint = ( REVOCATION_INFO * ) prevElement;
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Check whether a cert has been revoked */

int checkRevocation( const CERT_INFO *certInfoPtr, 
					 CERT_INFO *revocationInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = revocationInfoPtr->cCertRev;
	REVOCATION_INFO *revocationEntry;
	int status;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( revocationInfoPtr, sizeof( CERT_INFO ) ) );

	/* If there's no revocation information present, the cert can't have been
	   revoked */
	if( certRevInfo->revocations == NULL )
		return( CRYPT_OK );

	/* Check whether the cert is present in the revocation list */
	if( revocationInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		/* If the issuers differ, the cert can't be in this CRL */
		if( ( revocationInfoPtr->issuerDNsize != certInfoPtr->issuerDNsize || \
			memcmp( revocationInfoPtr->issuerDNptr, certInfoPtr->issuerDNptr,
					revocationInfoPtr->issuerDNsize ) ) )
			return( CRYPT_OK );

		/* Check whether there's an entry for this cert in the list */
		status = findRevocationEntry( certRevInfo->revocations, 
									  &revocationEntry, 
									  certInfoPtr->cCertCert->serialNumber, 
									  certInfoPtr->cCertCert->serialNumberLength,
									  FALSE );
		if( status == CRYPT_ERROR_NOTFOUND )
			/* No CRL entry, the certificate is OK */
			return( CRYPT_OK );
		}
	else
		{
		BYTE certHash[ CRYPT_MAX_HASHSIZE ];
		int certHashLength;

		assert( revocationInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

		/* Get the cert hash and use it to check whether there's an entry
		   for this cert in the list.  We read the cert hash indirectly 
		   since it's computed on demand and may not have been evaluated 
		   yet */
		status = getCertComponent( ( CERT_INFO * ) certInfoPtr, 
								   CRYPT_CERTINFO_FINGERPRINT_SHA,
								   certHash, &certHashLength );
		if( cryptStatusOK( status ) )
			status = findRevocationEntry( certRevInfo->revocations, 
										  &revocationEntry, certHash, 
										  certHashLength, FALSE );
		if( cryptStatusError( status ) )
			/* No entry, either good or bad, we can't report anything about
			   the cert */
			return( status );
		}

	/* Select the entry that contains the revocation information and return 
	   the cert's status.  For CRLs the presence of an entry means that the 
	   cert is invalid, for OCSP the validity information is contained in 
	   the entry.  The unknown status is a bit difficult to report, the best 
	   we can do is report notfound, although the notfound occurred at the 
	   responder rather than here */
	certRevInfo->currentRevocation = revocationEntry;
	if( revocationInfoPtr->type == CRYPT_CERTTYPE_CRL )
		return( CRYPT_ERROR_INVALID );
	return( ( revocationEntry->status == CRYPT_OCSPSTATUS_NOTREVOKED ) ? \
				CRYPT_OK : \
			( revocationEntry->status == CRYPT_OCSPSTATUS_REVOKED ) ? \
				CRYPT_ERROR_INVALID : CRYPT_ERROR_NOTFOUND );
	}

/* Add an entry to a revocation list */

int addRevocationEntry( REVOCATION_INFO **listHeadPtr, 
						REVOCATION_INFO **newEntryPosition,
						const CRYPT_KEYID_TYPE valueType,
						const void *value, const int valueLength,
						const BOOLEAN noCheck )
	{
	REVOCATION_INFO *newElement, *insertPoint;

	assert( isWritePtr( listHeadPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( newEntryPosition, sizeof( REVOCATION_INFO * ) ) );
	assert( sizeof( newElement->data ) == MAX_ID_SIZE );
	assert( valueType == CRYPT_KEYID_NONE || \
			valueType == CRYPT_IKEYID_CERTID || \
			valueType == CRYPT_IKEYID_ISSUERID || \
			valueType == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	assert( isReadPtr( value, valueLength ) );

	/* Find the insertion point for the new entry, unless we're reading data
	   from a pre-encoded CRL, in which case we just drop it in at the start.
	   The absence of checking for data from an existing CRL is necessary in 
	   order to provide same-day service for large CRLs */
	if( !noCheck && *listHeadPtr != NULL && \
		cryptStatusOK( \
			findRevocationEntry( *listHeadPtr, &insertPoint, value, 
								  valueLength, TRUE ) ) )
		/* If we get an OK status it means that we've found an existing 
		   entry that matches the one being added, we can't add it again */
		return( CRYPT_ERROR_DUPLICATE );

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement = ( REVOCATION_INFO * ) \
			clAlloc( "addRevocationEntry", sizeof( REVOCATION_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( REVOCATION_INFO ) );
	if( valueLength > 128 )
		{
		if( ( newElement->dataPtr = clDynAlloc( "addRevocationEntry", 
												valueLength ) ) == NULL )
			{
			clFree( "addRevocationEntry", newElement );
			return( CRYPT_ERROR_MEMORY );
			}
		}
	else
		newElement->dataPtr = newElement->data;
	newElement->type = valueType;
	memcpy( newElement->dataPtr, value, valueLength );
	newElement->dataLength = valueLength;
	newElement->dCheck = checksumData( value, valueLength );

	/* Insert the new element into the list */
	if( noCheck )
		{
		/* If we're adding data from an existing CRL, drop it in at the 
		   quickest insert point.  This is necessary for quick operation 
		   when handling mega-CRLs */
		newElement->next = *listHeadPtr;
		*listHeadPtr = newElement;
		}
	else
		insertSingleListElement( listHeadPtr, insertPoint, newElement );
	*newEntryPosition = newElement;
	return( CRYPT_OK );
	}

/* Delete a revocation list */

void deleteRevocationEntries( REVOCATION_INFO **listHeadPtr )
	{
	REVOCATION_INFO *entryListPtr = *listHeadPtr;

	assert( isWritePtr( listHeadPtr, sizeof( REVOCATION_INFO * ) ) );

	*listHeadPtr = NULL;

	/* Destroy any remaining list items */
	while( entryListPtr != NULL )
		{
		REVOCATION_INFO *itemToFree = entryListPtr;

		entryListPtr = entryListPtr->next;
		if( itemToFree->dataPtr != itemToFree->data )
			{
			zeroise( itemToFree->dataPtr, itemToFree->dataLength );
			clFree( "deleteRevocationEntries", itemToFree->dataPtr );
			}
		if( itemToFree->attributes != NULL )
			deleteAttributes( &itemToFree->attributes );
		zeroise( itemToFree, sizeof( REVOCATION_INFO ) );
		clFree( "deleteRevocationEntries", itemToFree );
		}
	}

/* Copy a revocation list */

int copyRevocationEntries( REVOCATION_INFO **destListHeadPtr,
						   const REVOCATION_INFO *srcListPtr )
	{
	const REVOCATION_INFO *srcListCursor;
	REVOCATION_INFO *destListCursor;

	assert( isWritePtr( destListHeadPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( *destListHeadPtr == NULL );	/* Dest.should be empty */

	/* Copy all revocation entries from source to destination */
	for( srcListCursor = srcListPtr; srcListCursor != NULL;
		 srcListCursor = srcListCursor->next )
		{
		REVOCATION_INFO *newElement;

		/* Allocate the new entry and copy the data from the existing one 
		   across.  We don't copy the attributes because there aren't any
		   that should be carried from request to response */
		if( ( newElement = ( REVOCATION_INFO * ) \
					clAlloc( "copyRevocationEntries", 
							 sizeof( REVOCATION_INFO ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( newElement, srcListCursor, sizeof( REVOCATION_INFO ) );
		if( srcListCursor->dataLength > 128 )
			{
			/* If the ID information doesn't fit into the fixed buffer, 
			   allocate a variable-length one and copy it across */
			if( ( newElement->dataPtr = \
					clDynAlloc( "copyRevocationEntries",
								srcListCursor->dataLength ) ) == NULL )
				{
				clFree( "copyRevocationEntries", newElement );
				return( CRYPT_ERROR_MEMORY );
				}
			memcpy( newElement->dataPtr, srcListCursor->data,
					srcListCursor->dataLength );
			}
		else
			newElement->dataPtr = newElement->data;
		newElement->attributes = NULL;
		newElement->next = NULL;

		/* Set the status to 'unknown' by default, this means that any 
		   entries that we can't do anything with automatically get the
		   correct status associated with them */
		newElement->status = CRYPT_OCSPSTATUS_UNKNOWN;

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
*							Read/write CRL Information						*
*																			*
****************************************************************************/

/* Read/write CRL entries:

	RevokedCert ::= SEQUENCE {
			userCertificate		CertificalSerialNumber,
			revocationDate		UTCTime
			extensions			Extensions OPTIONAL,
			} */

int sizeofCRLentry( REVOCATION_INFO *crlEntry )
	{
	assert( isWritePtr( crlEntry, sizeof( REVOCATION_INFO ) ) );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	crlEntry->attributeSize = sizeofAttributes( crlEntry->attributes );

	return( ( int ) sizeofObject( \
						sizeofInteger( crlEntry->data, crlEntry->dataLength ) + \
						sizeofUTCTime() + \
						( ( crlEntry->attributeSize > 0 ) ? \
							( int ) sizeofObject( crlEntry->attributeSize ) : 0 ) ) );
	}

int readCRLentry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
				  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
				  CRYPT_ERRTYPE_TYPE *errorType )
	{
	REVOCATION_INFO *currentEntry;
	BYTE serialNumber[ MAX_SERIALNO_SIZE ];
	int serialNumberLength, endPos, length, status;
	time_t revocationTime;

	assert( isWritePtr( listHeadPtr, sizeof( REVOCATION_INFO * ) ) );

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Read the integer component of the serial number (limited to a sane
	   length) and the revocation time */
	readInteger( stream, serialNumber, &serialNumberLength, 
				 MAX_SERIALNO_SIZE );
	status = readUTCTime( stream, &revocationTime );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list.  The ID type isn't 
	   quite an issueAndSerialNumber, but the checking code eventually
	   converts it into this form using the supplied issuer cert DN */
	status = addRevocationEntry( listHeadPtr, &currentEntry, 
								 CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								 serialNumber, serialNumberLength, 
								 ( endPos > CRL_SORT_LIMIT ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );
	currentEntry->revocationTime = revocationTime;

	/* Read the extensions if there are any present.  Since these are per-
	   entry extensions we read the extensions themselves as 
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_CRL to make sure 
	   that they're processed as required */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &currentEntry->attributes,
								 CRYPT_CERTTYPE_NONE, length, 
								 errorLocus, errorType );

	return( status );
	}

int writeCRLentry( STREAM *stream, const REVOCATION_INFO *crlEntry )
	{
	const int revocationLength = \
				sizeofInteger( crlEntry->data, crlEntry->dataLength ) + \
				sizeofUTCTime() + \
				( ( crlEntry->attributeSize > 0 ) ? \
					( int ) sizeofObject( crlEntry->attributeSize ) : 0 );
	int status;

	assert( isReadPtr( crlEntry, sizeof( REVOCATION_INFO ) ) );

	/* Write the CRL entry */
	writeSequence( stream, revocationLength );
	writeInteger( stream, crlEntry->data, crlEntry->dataLength, DEFAULT_TAG );
	status = writeUTCTime( stream, crlEntry->revocationTime, DEFAULT_TAG );
	if( cryptStatusError( status ) || crlEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions 
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_CRL to 
	   make sure that they're processed as required  */
	return( writeAttributes( stream, crlEntry->attributes, 
							 CRYPT_CERTTYPE_NONE, crlEntry->attributeSize ) );
	}

/****************************************************************************
*																			*
*							Read/write OCSP Information						*
*																			*
****************************************************************************/

/* Read/write an OCSP cert ID:

	CertID ::=	CHOICE {
		certID			SEQUENCE {
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,	-- Hash of issuerName
			iKeyHash	OCTET STRING,	-- Hash of issuer SPKI w/o tag+len
			serialNo	INTEGER
				},
		certificate	[0]	EXPLICIT [0] EXPLICIT Certificate,
		certIdWithSignature	
					[1]	EXPLICIT SEQUENCE {
			iAndS		IssuerAndSerialNumber,
			tbsCertHash	BIT STRING,
			certSig		SEQUENCE {
				sigAlgo	AlgorithmIdentifier,
				sigVal	BIT STRING
				}
			}
		} */

static int sizeofOcspID( const REVOCATION_INFO *ocspEntry )
	{
	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );
	assert( ocspEntry->type == CRYPT_KEYID_NONE );

	/* For now we don't try and handle anything except the v1 ID, since the
	   status of v2 is uncertain (it doesn't add anything to v1 except even
	   more broken IDs) */
	return( ocspEntry->dataLength );
	}

static int readOcspID( STREAM *stream, CRYPT_KEYID_TYPE *idType, 
					   BYTE *idBuffer, int *idLen, const int idMaxLen )
	{
	HASHFUNCTION hashFunction;
	int length, status;

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	*idType = CRYPT_KEYID_NONE;
	*idLen = 0;
	switch( peekTag( stream ) )
		{
		case BER_SEQUENCE:
			/* We can't really do anything with v1 IDs since the one-way
			   hashing process destroys any chance of being able to work 
			   with them, and the fact that no useful cert info is hashed 
			   means that we can't use them to identify a cert.  As a
			   result, the following ID type will always produce a result
			   of "unknown" */
			*idType = CRYPT_KEYID_NONE;
			length = getStreamObjectLength( stream );
			if( cryptStatusError( length ) )
				return( length );
			if( length > idMaxLen )
				return( CRYPT_ERROR_OVERFLOW );
			*idLen = length;
			return( sread( stream, idBuffer, length ) );

		case MAKE_CTAG( CTAG_OI_CERTIFICATE ):
			/* Convert the cert to a certID */
			*idType = CRYPT_IKEYID_CERTID;
			*idLen = KEYID_SIZE;
			readConstructed( stream, NULL, CTAG_OI_CERTIFICATE );
			status = readConstructed( stream, &length, 0 );
			if( cryptStatusError( status ) )
				return( status );
			hashFunction( NULL, idBuffer, sMemBufPtr( stream ), length, 
						  HASH_ALL );
			return( readUniversal( stream ) );
		
		case MAKE_CTAG( CTAG_OI_CERTIDWITHSIG ):
			{
			void *iAndSPtr;

			/* A bizarro ID dreamed up by Denis Pinkas that manages to carry 
			   over all the problems of the v1 ID without being compatible 
			   with it.  It's almost as unworkable as the v1 original, but 
			   we can convert the iAndS to an issuerID and use that */
			*idType = CRYPT_IKEYID_ISSUERID;
			*idLen = KEYID_SIZE;
			readConstructed( stream, NULL, CTAG_OI_CERTIDWITHSIG );
			readSequence( stream, NULL );
			iAndSPtr = sMemBufPtr( stream );
			status = readSequence( stream, &length );
			if( cryptStatusError( status ) )
				return( status );
			hashFunction( NULL, idBuffer, iAndSPtr, sizeofObject( length ), 
						  HASH_ALL );
			sSkip( stream, length );			/* issuerAndSerialNumber */
			readUniversal( stream );			/* tbsCertificateHash */
			return( readUniversal( stream ) );	/* certSignature */
			}
		}

	return( CRYPT_ERROR_BADDATA );
	}

static int writeOcspID( STREAM *stream, const REVOCATION_INFO *ocspEntry )
	{
	return( swrite( stream, ocspEntry->data, ocspEntry->dataLength ) );
	}

/* Read/write an OCSP request entry:

	Entry ::= SEQUENCE {				-- Request
		certID			CertID,
		extensions	[0]	EXPLICIT Extensions OPTIONAL
		} */

int sizeofOcspRequestEntry( REVOCATION_INFO *ocspEntry )
	{
	assert( isWritePtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );
	assert( ocspEntry->type == CRYPT_KEYID_NONE );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	ocspEntry->attributeSize = sizeofAttributes( ocspEntry->attributes );

	return( ( int ) \
			sizeofObject( sizeofOcspID( ocspEntry ) + \
						  ( ( ocspEntry->attributeSize ) ? \
							( int ) sizeofObject( ocspEntry->attributeSize ) : 0 ) ) );
	}

int readOcspRequestEntry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
						  CERT_INFO *certInfoPtr )
	{
	REVOCATION_INFO *currentEntry;
	BYTE idBuffer[ MAX_ID_SIZE ];
	CRYPT_KEYID_TYPE idType;
	int endPos, length, status;

	assert( isWritePtr( listHeadPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Read the ID information */
	status = readOcspID( stream, &idType, idBuffer, &length, MAX_ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list */
	status = addRevocationEntry( listHeadPtr, &currentEntry, idType, 
								 idBuffer, length, FALSE );
	if( cryptStatusError( status ) || \
		stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
		return( status );

	/* Read the extensions.  Since these are per-entry extensions we read 
	   the wrapper here and read the extensions themselves as 
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP to make sure that 
	   they're processed as required */
	status = readConstructed( stream, &length, CTAG_OR_EXTENSIONS );
	if( cryptStatusError( status ) )
		return( status );
	return( readAttributes( stream, &currentEntry->attributes,
							CRYPT_CERTTYPE_NONE, length,
							&certInfoPtr->errorLocus, 
							&certInfoPtr->errorType ) );
	}

int writeOcspRequestEntry( STREAM *stream, const REVOCATION_INFO *ocspEntry )
	{
	const int attributeSize = ( ocspEntry->attributeSize ) ? \
					( int ) sizeofObject( ocspEntry->attributeSize ) : 0;
	int status;

	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Write the header and ID information */
	writeSequence( stream, sizeofOcspID( ocspEntry ) + attributeSize );
	status = writeOcspID( stream, ocspEntry );
	if( cryptStatusError( status ) || ocspEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions 
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP 
	   to make sure that they're processed as required */
	return( writeAttributes( stream, ocspEntry->attributes, 
							 CRYPT_CERTTYPE_NONE, ocspEntry->attributeSize ) );
	}

/* Read/write an OCSP response entry:

	Entry ::= SEQUENCE {
		certID			CertID,
		certStatus		CHOICE {
			notRevd	[0]	IMPLICIT NULL,
			revd	[1]	SEQUENCE {
				revTime	GeneralizedTime, 
				revReas	[0] EXPLICIT CRLReason Optional
							},
			unknown	[2] IMPLICIT NULL 
						}, 
		thisUpdate		GeneralizedTime, 
		extensions	[1]	EXPLICIT Extensions OPTIONAL 
		} */

int sizeofOcspResponseEntry( REVOCATION_INFO *ocspEntry )
	{
	int certStatusSize = 0;

	assert( isWritePtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	ocspEntry->attributeSize = sizeofAttributes( ocspEntry->attributes );

	/* Determine the size of the cert status field */
	certStatusSize = ( ocspEntry->status != CRYPT_OCSPSTATUS_REVOKED ) ? \
					 sizeofNull() : ( int ) sizeofObject( sizeofGeneralizedTime() );

	return( ( int ) \
			sizeofObject( sizeofOcspID( ocspEntry ) + \
						  certStatusSize + sizeofGeneralizedTime() ) + \
						  ( ( ocspEntry->attributeSize ) ? \
							( int ) sizeofObject( ocspEntry->attributeSize ) : 0 ) );
	}

int readOcspResponseEntry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
						   CERT_INFO *certInfoPtr )
	{
	REVOCATION_INFO *currentEntry;
	BYTE idBuffer[ MAX_ID_SIZE ];
	CRYPT_KEYID_TYPE idType;
	int endPos, length, crlReason = 0, status;

	assert( isWritePtr( listHeadPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Read the ID information */
	status = readOcspID( stream, &idType, idBuffer, &length, MAX_ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list */
	status = addRevocationEntry( listHeadPtr, &currentEntry, idType, 
								 idBuffer, length, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the status information */
	switch( peekTag( stream ) )
		{
		case MAKE_CTAG_PRIMITIVE( OCSP_STATUS_NOTREVOKED ):
			currentEntry->status = CRYPT_OCSPSTATUS_NOTREVOKED;
			readUniversal( stream );
			break;

		case MAKE_CTAG( OCSP_STATUS_REVOKED ):
			currentEntry->status = CRYPT_OCSPSTATUS_REVOKED;
			readConstructed( stream, NULL, OCSP_STATUS_REVOKED );
			readGeneralizedTime( stream, &currentEntry->revocationTime );
			if( peekTag( stream ) == MAKE_CTAG( 0 ) )
				{
				/* Remember the crlReason for later */
				readConstructed( stream, NULL, 0 );
				readEnumerated( stream, &crlReason );
				}
			break;

		case MAKE_CTAG_PRIMITIVE( OCSP_STATUS_UNKNOWN ):
			currentEntry->status = CRYPT_OCSPSTATUS_UNKNOWN;
			readUniversal( stream );
			break;

		default:
			return( CRYPT_ERROR_BADDATA );
		}
	status = readGeneralizedTime( stream, &certInfoPtr->startTime );
	if( cryptStatusOK( status ) && peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		readConstructed( stream, NULL, 0 );
		status = readGeneralizedTime( stream, &certInfoPtr->endTime );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the extensions if there are any present.  Since these are per-
	   entry extensions we read the wrapper here and read the extensions
	   themselves as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP to 
	   make sure that they're processed as required */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		status = readConstructed( stream, &length, CTAG_OP_EXTENSIONS );
		if( cryptStatusOK( status ) )
			status = readAttributes( stream, &currentEntry->attributes,
						CRYPT_CERTTYPE_NONE, length,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's a crlReason present in the response and none as an 
	   extension, add it as an extension (OCSP allows the same information 
	   to be specified in two different places, to make it easier we always 
	   return it as a crlReason extension, however some implementations 
	   return it in both places so we have to make sure that we don't try and 
	   add it a second time) */
	if( findAttributeField( currentEntry->attributes, 
							CRYPT_CERTINFO_CRLREASON, 
							CRYPT_ATTRIBUTE_NONE ) == NULL )
		status = addAttributeField( &currentEntry->attributes,
						CRYPT_CERTINFO_CRLREASON, CRYPT_ATTRIBUTE_NONE, 
						&crlReason, CRYPT_UNUSED, ATTR_FLAG_NONE, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	return( status );
	}

int writeOcspResponseEntry( STREAM *stream, const REVOCATION_INFO *ocspEntry,
							const time_t entryTime )
	{
	int certStatusSize, status;

	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Determine the size of the cert status field */
	certStatusSize = ( ocspEntry->status != CRYPT_OCSPSTATUS_REVOKED ) ? \
					 sizeofNull() : ( int ) sizeofObject( sizeofGeneralizedTime() );

	/* Write the header and ID information */
	writeSequence( stream, sizeofOcspID( ocspEntry ) + \
				   certStatusSize + sizeofGeneralizedTime() + \
				   ( ( ocspEntry->attributeSize ) ? \
						( int ) sizeofObject( ocspEntry->attributeSize ) : 0 ) );
	writeOcspID( stream, ocspEntry );

	/* Write the cert status */
	if( ocspEntry->status == CRYPT_OCSPSTATUS_REVOKED )
		{
		writeConstructed( stream, sizeofGeneralizedTime(), 
						  CRYPT_OCSPSTATUS_REVOKED );
		writeGeneralizedTime( stream, ocspEntry->revocationTime, 
							  DEFAULT_TAG );
		}
	else
		/* An other-than-revoked status is communicated as a tagged NULL 
		   value.  For no known reason this portion of OCSP uses implicit
		   tagging, since it's the one part of the PDU in which an
		   explicit tag would actually make sense */
		writeNull( stream, ocspEntry->status );

	/* Write the current update time, which should be the current time. 
	   Since new status information is always available, we don't write a 
	   nextUpdate time (in fact there is some disagreement over whether these
	   times are based on CRL info, responder info, the response dispatch
	   time, or a mixture of the above, implementations can be found that
	   return all manner of peculiar values here) */
	status = writeGeneralizedTime( stream, entryTime, DEFAULT_TAG );
	if( cryptStatusError( status ) || ocspEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions 
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP 
	   to make sure that they're processed as required */
	return( writeAttributes( stream, ocspEntry->attributes, 
							 CRYPT_CERTTYPE_NONE, ocspEntry->attributeSize ) );
	}
