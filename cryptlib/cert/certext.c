/****************************************************************************
*																			*
*					Certificate Attribute Management Routines				*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1_rw.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in certdn.c */

int convertEmail( CERT_INFO *certInfoPtr, void **dnListHead,
				  const CRYPT_ATTRIBUTE_TYPE altNameType );

/* Prototypes for functions in cryptcrt.c */

int textToOID( const char *oid, const int oidLength, BYTE *binaryOID );

/****************************************************************************
*																			*
*								Attribute Type Mapping						*
*																			*
****************************************************************************/

/* Get the attribute information for a given OID */

const ATTRIBUTE_INFO *oidToAttribute( const ATTRIBUTE_TYPE attributeType,
									  const BYTE *oid )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
							selectAttributeInfo( attributeType );
	const int length = sizeofOID( oid );

	assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

	while( attributeInfoPtr->fieldID != CRYPT_ERROR )
		{
		if( attributeInfoPtr->oid != NULL && \
			sizeofOID( attributeInfoPtr->oid ) == length && \
			!memcmp( attributeInfoPtr->oid, oid, length ) )
			return( attributeInfoPtr );
		attributeInfoPtr++;
		}

	/* It's an unknown attribute */
	return( NULL );
	}

/* Get the attribute and attributeID for a field ID */

static const ATTRIBUTE_INFO *fieldIDToAttribute( const ATTRIBUTE_TYPE attributeType,
		const CRYPT_ATTRIBUTE_TYPE fieldID, const CRYPT_ATTRIBUTE_TYPE subFieldID,
		CRYPT_ATTRIBUTE_TYPE *attributeID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
							selectAttributeInfo( attributeType );
	int i;

	assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

	/* Clear the return value */
	if( attributeID != NULL )
		*attributeID = CRYPT_ERROR;

	/* Find the information on this attribute field */
	for( i = 0; attributeInfoPtr[ i ].fieldID != CRYPT_ERROR; i++ )
		{
		/* If the previous entry doesn't have more data following it, the
		   current entry is the start of a complete attribute and therefore
		   contains the attribute ID */
		if( attributeID != NULL && \
			( !i || !( attributeInfoPtr[ i - 1 ].flags & FL_MORE ) ) )
			{
			int j;

			/* Usually the attribute ID is the fieldID for the first entry,
			   however in some cases the attributeID is the same as the
			   fieldID and isn't specified until later on (denoted by the
			   fieldID being FIELDID_FOLLOWS), so we have to look ahead to
			   find it */
			*attributeID = attributeInfoPtr[ i ].fieldID;
			for( j = i + 1; *attributeID == FIELDID_FOLLOWS; j++ )
				*attributeID = attributeInfoPtr[ j ].fieldID;
			}

		/* Check whether the field ID for this entry matches the one we want */
		if( attributeInfoPtr[ i ].fieldID == fieldID )
			{
			ATTRIBUTE_INFO *altEncodingTable = \
						( ATTRIBUTE_INFO * ) attributeInfoPtr[ i ].extraData;

			/* If we're after a subfield match as well, try and match the
			   subfield */
			if( subFieldID != CRYPT_ATTRIBUTE_NONE && altEncodingTable != NULL )
				{
				for( i = 0; altEncodingTable[ i ].fieldID != CRYPT_ERROR; i++ )
					if( altEncodingTable[ i ].fieldID == subFieldID )
						return( &altEncodingTable[ i ] );

				return( NULL );
				}

			return( &attributeInfoPtr[ i ] );
			}
		}

	return( NULL );
	}

/****************************************************************************
*																			*
*					Attribute Location/Cursor Movement Routines				*
*																			*
****************************************************************************/

/* Find the start and end of an attribute from a field within the
   attribute */

static ATTRIBUTE_LIST *findAttributeStart( const ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;

	if( attributeListPtr == NULL )
		return( NULL );
	attributeID = attributeListPtr->attributeID;

	/* Move backwards until we find the start of the attribute */
	while( attributeListPtr->prev != NULL && \
		   attributeListPtr->prev->attributeID == attributeID )
		attributeListPtr = attributeListPtr->prev;

	return( ( ATTRIBUTE_LIST * ) attributeListPtr );
	}

static ATTRIBUTE_LIST *findAttributeEnd( const ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;

	if( attributeListPtr == NULL )
		return( NULL );
	attributeID = attributeListPtr->attributeID;

	/* Move forwards until we're just before the start of the next 
	   attribute */
	while( attributeListPtr->next != NULL && \
		   attributeListPtr->next->attributeID > 0 && \
		   attributeListPtr->next->attributeID == attributeID )
		attributeListPtr = attributeListPtr->next;

	return( ( ATTRIBUTE_LIST * ) attributeListPtr );
	}

/* Find an attribute in a list of certificate attributes by object identifier
   (for blob-type attributes) or by field and subfield ID (for known
   attributes), with extended handling for fields with default values */

ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *attributeListPtr,
									const BYTE *oid )
	{
	/* Find the position of this component in the list */
	while( attributeListPtr != NULL && \
		   ( !isBlobAttribute( attributeListPtr ) || \
			 sizeofOID( attributeListPtr->oid ) != sizeofOID( oid ) || \
			 memcmp( attributeListPtr->oid, oid, sizeofOID( oid ) ) ) )
		 attributeListPtr = attributeListPtr->next;

	return( ( ATTRIBUTE_LIST * ) attributeListPtr );
	}

ATTRIBUTE_LIST *findAttributeField( const ATTRIBUTE_LIST *attributeListPtr,
									const CRYPT_ATTRIBUTE_TYPE fieldID,
									const CRYPT_ATTRIBUTE_TYPE subFieldID )
	{
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );

	/* Find the position of this component in the list */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attributeID > 0 && \
		   attributeListPtr->fieldID != fieldID )
		attributeListPtr = attributeListPtr->next;
	if( subFieldID == CRYPT_ATTRIBUTE_NONE )
		return( ( attributeListPtr != NULL && \
				  attributeListPtr->attributeID > 0 ) ? \
				( ATTRIBUTE_LIST * ) attributeListPtr : NULL );

	/* Find the subfield in the field */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attributeID > 0 && \
		   attributeListPtr->fieldID == fieldID )
		{
		if( attributeListPtr->subFieldID == subFieldID )
			return( ( ATTRIBUTE_LIST * ) attributeListPtr );
		attributeListPtr = attributeListPtr->next;
		}

	return( NULL );
	}

ATTRIBUTE_LIST *findAttributeFieldEx( const ATTRIBUTE_LIST *attributeListPtr,
									  const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	static const ATTRIBUTE_LIST defaultField = DEFAULTFIELD_VALUE;
	static const ATTRIBUTE_LIST completeAttribute = COMPLETEATTRIBUTE_VALUE;
	const ATTRIBUTE_LIST *attributeListCursor = attributeListPtr;
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const ATTRIBUTE_TYPE attributeType = \
							( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;

	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );

	/* Find the position of this component in the list */
	while( attributeListCursor != NULL && \
		   attributeListCursor->attributeID > 0 && \
		   attributeListCursor->fieldID != fieldID )
		attributeListCursor = attributeListCursor->next;
	if( attributeListCursor != NULL )
		return( attributeListCursor->attributeID > 0 ? \
				( ATTRIBUTE_LIST * ) attributeListCursor : NULL );

	/* The field isn't present in the list of attributes, check whether
	   the attribute itself is present and whether this field has a default
	   value */
	attributeInfoPtr = fieldIDToAttribute( attributeType, fieldID, 
										   CRYPT_ATTRIBUTE_NONE, &attributeID );
	if( attributeInfoPtr == NULL )
		/* There's no attribute containing this field, exit */
		return( NULL );

	/* Check whether any part of the attribute that contains the given 
	   field is present in the list of attribute fields */
	for( attributeListCursor = ( ATTRIBUTE_LIST * ) attributeListPtr;
		 attributeListCursor != NULL && \
			attributeListCursor->attributeID > 0 && \
			attributeListCursor->attributeID != attributeID;
		 attributeListCursor = attributeListCursor->next );
	if( attributeListCursor == NULL )
		return( NULL );

	/* Some other part of the attribute containing the given field is present 
	   in the list.  If this field wasn't found that could either be a 
	   default value (in which case we return an entry that denotes that 
	   this field is absent but has a default setting) or a field that 
	   denotes an entire constructed attribute (in which case we return an 
	   entry that denotes this) */
	if( attributeInfoPtr->flags & FL_DEFAULT )
		return( ( ATTRIBUTE_LIST * ) &defaultField );
	if( attributeInfoPtr->fieldType == BER_SEQUENCE )
		return( ( ATTRIBUTE_LIST * ) &completeAttribute );

	return( NULL );
	}

/* Find an overall attribute in a list of attributes.  This is almost always
   used as a check for the presence of an overall attribute, so we provide
   a separate function to make this explicit */

ATTRIBUTE_LIST *findAttribute( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE attributeID,
							   const BOOLEAN isFieldID )
	{
	const ATTRIBUTE_LIST *attributeListCursor = attributeListPtr;
	CRYPT_ATTRIBUTE_TYPE localAttributeID = attributeID;

	assert( attributeID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			attributeID <= CRYPT_CERTINFO_LAST );
	
	/* If this is a (potential) fieldID rather than an attributeID, find the
	   attributeID for the attribute containing this field */
	if( isFieldID )
		{
		if( fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, 
								attributeID, CRYPT_ATTRIBUTE_NONE, 
								&localAttributeID ) == NULL )
			/* There's no attribute containing this field, exit */
			return( NULL );
		}
	else
		/* Make sure that we're searching on an attribute ID rather than a 
		   field ID */
		assert( \
			fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, 
								attributeID, CRYPT_ATTRIBUTE_NONE, 
								&localAttributeID ) != NULL && \
			attributeID == localAttributeID );

	/* Check whether this attribute is present in the list of attribute 
	   fields */
	while( attributeListCursor != NULL && \
		   attributeListCursor->attributeID > 0 )
		{
		if( attributeListCursor->attributeID == localAttributeID )
			return( ( ATTRIBUTE_LIST * ) attributeListCursor );
		attributeListCursor = attributeListCursor->next;
		}
	return( NULL );
	}


BOOLEAN checkAttributePresent( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	return( findAttribute( attributeListPtr, fieldID, FALSE ) != NULL ? \
			TRUE : FALSE );
	}

/* Get the default value for an optional field of an attribute */

int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
			fieldIDToAttribute( ( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
								fieldID, CRYPT_ATTRIBUTE_NONE, NULL );

	assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

	return( ( int ) attributeInfoPtr->defaultValue );
	}

/* Move the attribute cursor relative to the current cursor position.  This
   moves as far as possible in the direction given and then returns an
   appropriate return code, either CRYPT_OK or CRYPT_ERROR_NOTFOUND if no
   movement is possible */

int moveAttributeCursor( ATTRIBUTE_LIST **currentCursor,
						 const CRYPT_ATTRIBUTE_TYPE certInfoType, 
						 const int position )
	{
	const ATTRIBUTE_LIST *newCursor = *currentCursor, *lastCursor = NULL;
	const BOOLEAN absMove = ( position == CRYPT_CURSOR_FIRST || \
							  position == CRYPT_CURSOR_LAST ) ? TRUE : FALSE;
	int count;

	assert( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION || \
			certInfoType == CRYPT_CERTINFO_CURRENT_FIELD || \
			certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT );
	assert( position <= CRYPT_CURSOR_FIRST && \
			position >= CRYPT_CURSOR_LAST );

	/* Positioning in null attribute lists is always unsuccessful */
	if( currentCursor == NULL || *currentCursor == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Set the amount we want to move by based on the position code.  This
	   means we can handle the movement in a simple while loop instead of
	   having to special-case it for moves by one item */
	count = absMove ? INT_MAX : 1;

	/* Moving by field or component is relatively simple.  For fields we move
	   backwards or forwards until we either run out of fields or the next 
	   field belongs to a different attribute.  For components we move 
	   similarly, except that we stop when we reach a field whose attribute
	   type, field type, and subfield type don't match the current one */
	if( certInfoType == CRYPT_CERTINFO_CURRENT_FIELD )
		{
		const CRYPT_ATTRIBUTE_TYPE attributeID = ( *currentCursor )->attributeID;

		if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_PREVIOUS )
			while( count-- && newCursor->prev != NULL && \
				   newCursor->prev->attributeID == attributeID )
				newCursor = newCursor->prev;
		else
			while( count-- && newCursor->next != NULL && \
				   newCursor->next->attributeID == attributeID )
				newCursor = newCursor->next;

		if( !absMove && *currentCursor == newCursor )
			return( CRYPT_ERROR_NOTFOUND );
		*currentCursor = ( ATTRIBUTE_LIST * ) newCursor;
		return( CRYPT_OK );
		}
	if( certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT )
		{
		const CRYPT_ATTRIBUTE_TYPE attributeID = ( *currentCursor )->attributeID;
		const CRYPT_ATTRIBUTE_TYPE fieldID = ( *currentCursor )->fieldID;
		const CRYPT_ATTRIBUTE_TYPE subFieldID = ( *currentCursor )->subFieldID;

		if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_PREVIOUS )
			while( count-- && newCursor->prev != NULL && \
				   newCursor->prev->attributeID == attributeID && \
				   newCursor->prev->fieldID == fieldID && \
				   newCursor->prev->subFieldID == subFieldID )
				newCursor = newCursor->prev;
		else
			while( count-- && newCursor->next != NULL && \
				   newCursor->next->attributeID == attributeID && \
				   newCursor->next->fieldID == fieldID && \
				   newCursor->next->subFieldID == subFieldID )
				newCursor = newCursor->next;

		if( !absMove && *currentCursor == newCursor )
			return( CRYPT_ERROR_NOTFOUND );
		*currentCursor = ( ATTRIBUTE_LIST * ) newCursor;
		return( CRYPT_OK );
		}

	/* Moving by attribute is a bit more complex.  First we find the start or
	   end of the current attribute.  Then we move to the start of the 
	   previous (via findAttributeStart())/start of the next (via the 'next' 
	   pointer) attribute beyond that.  This has the effect of moving us from 
	   anywhere in the current attribute to the start of the preceding or 
	   following attribute.  Finally, we repeat this as required */
	while( count-- && newCursor != NULL )
		{
		lastCursor = newCursor;
		if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_PREVIOUS )
			newCursor = findAttributeStart( findAttributeStart( newCursor )->prev );
		else
			newCursor = findAttributeEnd( newCursor )->next;
		}
	assert( lastCursor != NULL );	/* We went through loop at least once */

	/* If the new cursor is NULL, we've reached the start or end of the 
	   attribute list */
	if( newCursor == NULL )
		{
		/* Move to the start of the first or last attribute we got to before 
		   we ran out of attributes to make sure that we don't fall off the 
		   start/end of the list */
		*currentCursor = findAttributeStart( lastCursor );

		/* If it's an absolute move we've reached our destination, otherwise
		   there's nowhere left to move to */
		return( absMove ? CRYPT_OK : CRYPT_ERROR_NOTFOUND );
		}

	/* We've found what we were looking for */
	*currentCursor = ( ATTRIBUTE_LIST * ) newCursor;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Misc. Attribute Routines					*
*																			*
****************************************************************************/

/* Fix up certificate attributes, mapping from incorrect values to standards-
   compliant ones */

int fixAttributes( CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int complianceLevel, status;

	/* Try and locate email addresses wherever they might be stashed and move
	   them to the cert altNames */
	status = convertEmail( certInfoPtr, &certInfoPtr->subjectName,
						   CRYPT_CERTINFO_SUBJECTALTNAME );
	if( cryptStatusOK( status ) )
		status = convertEmail( certInfoPtr, &certInfoPtr->issuerName,
							   CRYPT_CERTINFO_ISSUERALTNAME );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're running at a compliance level of 
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL or above, don't try and fiddle any
	   dubious attributes */
	status = krnlSendMessage( certInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );
	if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If the only key usage info present is the Netscape one, convert it 
	   into the X.509 equivalent */
	if( findAttributeField( certInfoPtr->attributes, CRYPT_CERTINFO_KEYUSAGE, 
							CRYPT_ATTRIBUTE_NONE ) == NULL && \
		( attributeListPtr = findAttributeField( certInfoPtr->attributes, 
										CRYPT_CERTINFO_NS_CERTTYPE, 
										CRYPT_ATTRIBUTE_NONE ) ) != NULL )
		{
		int keyUsage = 0;

		/* There's a Netscape cert usage present but no X.509 one, map the
		   Netscape usage to the X.509 one */
		if( attributeListPtr->intValue & CRYPT_NS_CERTTYPE_SSLCLIENT )
			keyUsage |= CRYPT_KEYUSAGE_DIGITALSIGNATURE;
		if( attributeListPtr->intValue & CRYPT_NS_CERTTYPE_SSLSERVER )
			keyUsage |= CRYPT_KEYUSAGE_KEYENCIPHERMENT;
		if( attributeListPtr->intValue & CRYPT_NS_CERTTYPE_SMIME )
			{
			keyUsage |= CRYPT_KEYUSAGE_DIGITALSIGNATURE;
			if( certInfoPtr->iPubkeyContext != CRYPT_ERROR )
				{
				int cryptAlgo;

				krnlSendMessage( certInfoPtr->iPubkeyContext, 
								 IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
								 CRYPT_CTXINFO_ALGO );
				if( isCryptAlgo( cryptAlgo ) )
					keyUsage |= CRYPT_KEYUSAGE_KEYENCIPHERMENT;
				}
			}
		if( attributeListPtr->intValue & ( CRYPT_NS_CERTTYPE_SSLCA | \
										   CRYPT_NS_CERTTYPE_SMIMECA | \
										   CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA ) )
			keyUsage |= CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN;
		status = addAttributeField( &certInfoPtr->attributes,
							CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE,
							&keyUsage, CRYPT_UNUSED, ATTR_FLAG_NONE, 
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Attribute Management Routines					*
*																			*
****************************************************************************/

/* Add a blob-type attribute to a list of attributes */

int addAttribute( const ATTRIBUTE_TYPE attributeType,
				  ATTRIBUTE_LIST **listHeadPtr, const BYTE *oid,
				  const BOOLEAN criticalFlag, const void *data,
				  const int dataLength, const int flags )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint = NULL;
	const int storageSize = dataLength + sizeofOID( oid );

	assert( isWritePtr( listHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( oid, 3 ) );
	assert( criticalFlag == TRUE || criticalFlag == FALSE );
	assert( !checkBadPtrRead( data, dataLength ) );
	assert( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE );
	assert( flags == ATTR_FLAG_NONE || flags == ATTR_FLAG_BLOB );

	/* If this attribute type is already handled as a non-blob attribute,
	   don't allow it to be added as a blob as well.  This avoids problems
	   with the same attribute being added twice, once as a blob and once as
	   a non-blob.  In addition it forces the caller to use the (recommended)
	   normal attribute handling mechanism, which allows for proper type
	   checking */
	if( !( flags & ATTR_FLAG_BLOB ) && \
		oidToAttribute( attributeType, oid ) != NULL )
		return( CRYPT_ERROR_PERMISSION );

	/* Find the correct place in the list to insert the new element */
	if( *listHeadPtr != NULL )
		{
		ATTRIBUTE_LIST *prevElement = NULL;

		for( insertPoint = *listHeadPtr; insertPoint != NULL;
			 insertPoint = insertPoint->next )
			{
			/* Make sure that this blob attribute isn't already present */
			if( isBlobAttribute( insertPoint ) && \
				sizeofOID( insertPoint->oid ) == sizeofOID( oid ) && \
				!memcmp( insertPoint->oid, oid, sizeofOID( oid ) ) )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
		insertPoint = prevElement;
		}

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addAttribute", sizeof( ATTRIBUTE_LIST ) + \
												storageSize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, storageSize );
	newElement->oid = newElement->storage + dataLength;
	memcpy( newElement->oid, oid, sizeofOID( oid ) );
	newElement->flags = criticalFlag ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE;
	memcpy( newElement->value, data, dataLength );
	newElement->valueLength = dataLength;
	insertDoubleListElements( listHeadPtr, insertPoint, newElement, newElement );

	return( CRYPT_OK );
	}

/* Check the validity of an attribute field */

static int checkAttributeField( const ATTRIBUTE_LIST *attributeListPtr,
								const ATTRIBUTE_INFO *attributeInfoPtr,
								const CRYPT_ATTRIBUTE_TYPE fieldID,
								const CRYPT_ATTRIBUTE_TYPE subFieldID,
								const void *data, const int dataLength,
								const int flags, 
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListSearchPtr;

	assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );
	assert( dataLength == CRYPT_UNUSED || \
			( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
	assert( dataLength == CRYPT_UNUSED || \
			!checkBadPtrRead( data, dataLength ) );
	assert( !( flags & ATTR_FLAG_INVALID ) );

	/* Make sure that a valid field has been specified, and that this field
	   isn't already present as a non-default entry unless it's a field for
	   which multiple values are allowed */
	if( attributeInfoPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	attributeListSearchPtr = findAttributeField( attributeListPtr, fieldID,
												 subFieldID );
	if( attributeListSearchPtr != NULL )
		{
		/* If it's not multivalued, we can't have any duplicate fields */
		if( !( ( attributeInfoPtr->flags & FL_MULTIVALUED ) || \
			   ( flags & ATTR_FLAG_MULTIVALUED ) ) )
			{
			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_INITED );
			}
		}

	/* If it's a blob field, don't do any type checking.  This is a special
	   case that differs from FIELDTYPE_BLOB in that it corresponds to an
	   ASN.1 value that's mis-encoded by one or more implementations, so we
	   have to accept absolutely anything at this point */
	if( flags & ATTR_FLAG_BLOB )
		return( CRYPT_OK );

	switch( attributeInfoPtr->fieldType )
		{
		case FIELDTYPE_IDENTIFIER:
			/* It's an identifier, make sure that all parameters are correct */
			assert( dataLength == CRYPT_UNUSED );
			if( *( ( int * ) data ) != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM1 );

			return( CRYPT_OK );

		case FIELDTYPE_DN:
			/* It's a special-case field used as a placeholder when creating 
			   a new cert to indicate that a DN structure is being 
			   instantiated.  When reading an encoded cert, this is the 
			   decoded DN structure */
			assert( dataLength == CRYPT_UNUSED );
			return( CRYPT_OK );

		case BER_OBJECT_IDENTIFIER:
			{
			const BYTE *oidPtr = data;
			BYTE binaryOID[ MAX_OID_SIZE ];

			/* If it's a BER/DER-encoded OID, make sure that it's valid 
			   ASN.1 */
			if( oidPtr[ 0 ] == BER_OBJECT_IDENTIFIER )
				{
				if( oidPtr[ 1 ] == dataLength - 2 )
					return( CRYPT_OK );
				}
			else
				/* It's a text OID, check the syntax and make sure that the 
				   length is valid */
				if( textToOID( data, dataLength, binaryOID ) )
					return( CRYPT_OK );

			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ARGERROR_STR1 );
			}

		case BER_BOOLEAN:
			assert( dataLength == CRYPT_UNUSED );

			/* BOOLEAN data is accepted as zero/nonzero so it's always 
			   valid, however we let the caller know via an alternative
			   return code that this is non-string data */
			return( OK_SPECIAL );

		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_NULL:
		case FIELDTYPE_CHOICE:
			{
			int value = *( ( int * ) data );

			/* Check that the data size and range is valid */
			if( value < attributeInfoPtr->lowRange || \
				value > attributeInfoPtr->highRange )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_NUM1 );
				}

			/* Let the caller know that this is non-string data */
			return( OK_SPECIAL );
			}

		}

	/* It's some sort of string value, perform a general type check */
	if( dataLength < attributeInfoPtr->lowRange || \
		dataLength > attributeInfoPtr->highRange )
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* If we're not checking the payload in order to handle CAs who stuff 
	   any old rubbish into the fields, exit now unless it's a blob field, 
	   for which we need to find at least valid ASN.1 data */
	if( ( flags & ATTR_FLAG_BLOB_PAYLOAD ) && \
		( attributeInfoPtr->fieldType != FIELDTYPE_BLOB ) )
		return( CRYPT_OK );

	switch( attributeInfoPtr->fieldType )
		{
		case FIELDTYPE_BLOB:
			/* It's a blob field, make sure that it's a valid ASN.1 object */
			if( cryptStatusError( getObjectLength( data, dataLength ) ) )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
			return( CRYPT_OK );

		case BER_STRING_NUMERIC:
			{
			const char *dataPtr = data;
			int i;

			/* Make sure it's a numeric string */
			for( i = 0; i < dataLength; i++ )
				if( !isDigit( dataPtr[ i ] ) )
					{
					if( errorType != NULL )
						*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
					return( CRYPT_ARGERROR_STR1 );
					}
			return( CRYPT_OK );
			}

		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_PRINTABLE:
			/* Make sure it's an ASCII string of the correct type */
			if( !checkTextStringData( data, dataLength, 
					( attributeInfoPtr->fieldType == BER_STRING_PRINTABLE ) ? \
					TRUE : FALSE ) )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
			return( CRYPT_OK );
		}

	return( CRYPT_OK );
	}

/* Add an attribute field to a list of attributes at the appropriate 
   location */

int addAttributeField( ATTRIBUTE_LIST **attributeListPtr,
					   const CRYPT_ATTRIBUTE_TYPE fieldID,
					   const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   const void *data, const int dataLength,
					   const int flags, CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					   CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = \
							( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;
	const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
										fieldID, subFieldID, &attributeID );
	ATTRIBUTE_LIST *newElement, *insertPoint, *prevElement = NULL;
	BOOLEAN isNumeric = FALSE;
	int storageSize, status;

	assert( isWritePtr( attributeListPtr, ATTRIBUTE_LIST * ) );
	assert( dataLength == CRYPT_UNUSED || \
			( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
	assert( dataLength == CRYPT_UNUSED || \
			!checkBadPtrRead( data, dataLength ) );
	assert( !( flags & ATTR_FLAG_INVALID ) );
	assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

	/* Check the field's validity */
	status = checkAttributeField( *attributeListPtr, attributeInfoPtr, 
								  fieldID, subFieldID, data, dataLength, 
								  flags, errorType );
	if( cryptStatusError( status ) )
		{
		if( status == OK_SPECIAL )
			/* Special indicator to tell us that the value is non-string
			   numeric data */
			isNumeric = TRUE;
		else
			{
			if( errorType != NULL && cryptStatusError( *errorType ) )
				/* If we encountered an error that sets the error type, 
				   record the locus */
				*errorLocus = fieldID;
			return( status );
			}
		}
	assert( isNumeric || \
			( ( attributeInfoPtr->fieldType == FIELDTYPE_DN || \
				attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER ) && \
			  dataLength == CRYPT_UNUSED ) || \
			dataLength > 0 );

	/* Find the location at which to insert this attribute field (this 
	   assumes that the fieldIDs are defined in sorted order) */
	insertPoint = *attributeListPtr;
	while( insertPoint != NULL && \
		   insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE && \
		   insertPoint->fieldID <= fieldID )
		{
		/* If it's a composite field that can have multiple fields with the 
		   same field ID (e.g.a GeneralName), exit if the overall field ID is 
		   greater (the component belongs to a different field entirely) or 
		   if the field ID is the same and the subfield ID is greater (if 
		   the component belongs to the same field) */
		if( subFieldID != CRYPT_ATTRIBUTE_NONE && \
			insertPoint->fieldID == fieldID && \
			insertPoint->subFieldID > subFieldID )
			break;

		prevElement = insertPoint;
		insertPoint = insertPoint->next;
		}
	insertPoint = prevElement;

	/* Allocate memory for the new element and copy the information across.
	   If it's a simple type we can assign it to the simple value in the
	   element itself, otherwise we either copy it into the storage in the
	   element or allocate seperate storage and copy it into that.  Something
	   that encodes to NULL isn't really a numeric type, but we class it as
	   such so that any attempt to read it returns CRYPT_UNUSED as the value */
	storageSize = ( isNumeric || \
					attributeInfoPtr->fieldType == FIELDTYPE_DN || \
					attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER ) ? \
				  0 : dataLength; 
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addAttributeField", sizeof( ATTRIBUTE_LIST ) + \
													 storageSize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, storageSize );
	newElement->attributeID = attributeID;
	newElement->fieldID = fieldID;
	newElement->subFieldID = subFieldID;
	newElement->flags = flags;
	newElement->fieldType = attributeInfoPtr->fieldType;
	switch( attributeInfoPtr->fieldType )
		{
		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_BOOLEAN:
		case BER_NULL:
		case FIELDTYPE_CHOICE:
			newElement->intValue = *( ( int * ) data );
			if( attributeInfoPtr->fieldType == BER_BOOLEAN )
				/* Force it to the correct type if it's a boolean */
				newElement->intValue = ( newElement->intValue ) ? TRUE : FALSE;
			if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
				/* For encoding purposes the subfield ID is set to the ID of 
				   the CHOICE selection */
				newElement->subFieldID = newElement->intValue;
			break;

		case BER_OBJECT_IDENTIFIER:
			/* If it's a BER/DER-encoded OID copy it in as is, otherwise 
			   convert it from the text form */
			if( ( ( BYTE * ) data )[ 0 ] == BER_OBJECT_IDENTIFIER )
				{
				memcpy( newElement->value, data, dataLength );
				newElement->valueLength = dataLength;
				}
			else
				newElement->valueLength = textToOID( data, dataLength,
													 newElement->value );
			break;

		case FIELDTYPE_DN:
			/* When creating a new cert, this is a placeholder to indicate 
			   that a DN structure is being instantiated.  When reading an 
			   encoded cert, this is the decoded DN structure */
			newElement->value = ( *( ( int * ) data ) == CRYPT_UNUSED ) ? \
								NULL : ( void * ) data;
			break;

		case FIELDTYPE_IDENTIFIER:
			/* This is a placeholder entry with no explicit value */
			newElement->intValue = CRYPT_UNUSED;
			break;

		default:
			assert( dataLength > 0 );
			memcpy( newElement->value, data, dataLength );
			newElement->valueLength = dataLength;
			break;
		}
	insertDoubleListElement( attributeListPtr, insertPoint, newElement );

	return( CRYPT_OK );
	}

/* Copy an attribute from one attribute list to another.  This is an all-or-
   nothing copy in that it either copies a complete attribute or nothing at
   all */

static int copyAttributeField( ATTRIBUTE_LIST **destAttributeField,
							   const ATTRIBUTE_LIST *srcAttributeField )
	{
	ATTRIBUTE_LIST *newElement;
	int status = CRYPT_OK;

	assert( isWritePtr( destAttributeField, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcAttributeField, ATTRIBUTE_LIST ) );

	/* Allocate memory for the new element and copy the information across */
	*destAttributeField = NULL;
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "copyAttributeField", \
								sizeofVarStruct( srcAttributeField, \
												 ATTRIBUTE_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	copyVarStruct( newElement, srcAttributeField, ATTRIBUTE_LIST );
	if( srcAttributeField->fieldType == FIELDTYPE_DN )
		{
		/* If the field contains a DN, copy the DN across */
		status = copyDN( ( void ** ) &newElement->value,
						 srcAttributeField->value );
		if( cryptStatusError( status ) )
			{
			endVarStruct( newElement, ATTRIBUTE_LIST );
			clFree( "copyAttributeField", newElement );
			return( status );
			}
		}
	newElement->next = newElement->prev = NULL;
	*destAttributeField = newElement;

	return( CRYPT_OK );
	}

static int copyAttribute( ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  const BOOLEAN subjectToIssuer )
	{
	const CRYPT_ATTRIBUTE_TYPE attributeID = srcListPtr->attributeID;
	CRYPT_ATTRIBUTE_TYPE newAttributeID = attributeID, newFieldID = attributeID;
	ATTRIBUTE_LIST *newAttributeListHead = NULL, *newAttributeListTail;
	ATTRIBUTE_LIST *insertPoint, *prevElement = NULL;

	assert( isWritePtr( destListHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcListPtr, ATTRIBUTE_LIST ) );

	/* If we're copying from an issuer to a subject attribute list and the
	   field is an altName or keyIdentifier, change the field type from
	   issuer.subjectAltName to subject.issuerAltName or
	   issuer.subjectKeyIdentifier to subject.authorityKeyIdentifier */
	if( subjectToIssuer )
		{
		if( attributeID == CRYPT_CERTINFO_SUBJECTALTNAME )
			newAttributeID = newFieldID = CRYPT_CERTINFO_ISSUERALTNAME;
		if( attributeID == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER )
			{
			newAttributeID = CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER;
			newFieldID = CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER;
			}
		}

	/* Find the location at which to insert this attribute.  For now we
	   assume that the fieldIDs are defined in sorted order, we may need to
	   change this and add internal mapping if new fieldIDs are added out of
	   order */
	for( insertPoint = *destListHeadPtr;
		 insertPoint != NULL && insertPoint->attributeID < newAttributeID && \
			insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE;
		 insertPoint = insertPoint->next )
		prevElement = insertPoint;
	insertPoint = prevElement;

	/* Build a new attribute list containing the attribute fields */
	while( srcListPtr != NULL && srcListPtr->attributeID == attributeID )
		{
		ATTRIBUTE_LIST *newAttributeField;
		int status;

		/* Copy the field across, append it to the new attribute list, and
		   adjust the type for issuer->subject copying if necessary */
		status = copyAttributeField( &newAttributeField, srcListPtr );
		if( cryptStatusError( status ) )
			{
			deleteAttributes( &newAttributeListHead );
			return( CRYPT_ERROR_MEMORY );
			}
		if( newAttributeListHead == NULL )
			newAttributeListHead = newAttributeListTail = newAttributeField;
		else
			{
			newAttributeListTail->next = newAttributeField;
			newAttributeField->prev = newAttributeListTail;
			newAttributeListTail = newAttributeField;
			}
		if( newAttributeID != attributeID )
			{
			newAttributeField->attributeID = newAttributeID;
			newAttributeField->fieldID = newFieldID;
			}

		/* Move on to the next field */
		srcListPtr = srcListPtr->next;
		}

	/* Link the new list into the existing list at the appropriate position */
	insertDoubleListElements( destListHeadPtr, insertPoint, 
							  newAttributeListHead, newAttributeListTail );

	return( CRYPT_OK );
	}

/* Copy a complete attribute list */

int copyAttributes( ATTRIBUTE_LIST **destListHeadPtr,
					ATTRIBUTE_LIST *srcListPtr,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListCursor = srcListPtr;

	assert( isWritePtr( destListHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcListPtr, ATTRIBUTE_LIST ) );

	/* Make a first pass down the list checking that the attribute to copy
	   isn't already present, first for recognised attributes and then for
	   unrecognised ones.  We have to do this separately since once we begin
	   the copy process it's rather hard to undo it.  Note that in theory 
	   there are some attributes that can have multiple instances of a field
	   present, which means we could allow them to appear in both the source
	   and destination lists, however if this occurs it's more likely to be 
	   an error than a desire to merge two disparate collections of 
	   attributes */
	while( attributeListCursor != NULL && \
		   !isBlobAttribute( attributeListCursor ) )
		{
		if( findAttributeField( *destListHeadPtr,
				attributeListCursor->fieldID, CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = attributeListCursor->fieldID;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		attributeListCursor = attributeListCursor->next;
		}
	while( attributeListCursor != NULL )
		{
		assert( isBlobAttribute( attributeListCursor ) );
		if( findAttributeByOID( *destListHeadPtr, attributeListCursor->oid ) != NULL )
			{
			/* We can't set the locus for blob-type attributes since it's not
			   a known attribute */
			*errorLocus = CRYPT_ATTRIBUTE_NONE;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		attributeListCursor = attributeListCursor->next;
		}

	/* Make a second pass copying everything across */
	while( srcListPtr != NULL && !isBlobAttribute( srcListPtr ) )
		{
		CRYPT_ATTRIBUTE_TYPE attributeID = srcListPtr->attributeID;
		const ATTRIBUTE_INFO *attributeInfoPtr = \
				( srcListPtr->attributeInfoPtr != NULL ) ? \
				srcListPtr->attributeInfoPtr : \
				fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
										ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
									attributeID, CRYPT_ATTRIBUTE_NONE, NULL );
		int status;

		assert( isReadPtr( attributeInfoPtr, ATTRIBUTE_INFO ) );

		/* Copy the complete attribute across unless it's one that we 
		   explicitly don't propagate from source to destination */
		if( !( attributeInfoPtr->flags & FL_NOCOPY ) )
			{
			status = copyAttribute( destListHeadPtr, srcListPtr, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Move on to the next attribute */
		while( srcListPtr != NULL && srcListPtr->attributeID == attributeID )
			srcListPtr = srcListPtr->next;
		}

	/* If there are blob-type attributes left at the end of the list, copy
	   them across last */
	if( srcListPtr != NULL )
		{
		ATTRIBUTE_LIST *insertPoint;

		/* Find the end of the destination list */
		for( insertPoint = *destListHeadPtr;
			 insertPoint != NULL && insertPoint->next != NULL;
			 insertPoint = insertPoint->next );

		/* Copy all remaining attributes across */
		while( srcListPtr != NULL )
			{
			ATTRIBUTE_LIST *newAttribute;
			int status;

			status = copyAttributeField( &newAttribute, srcListPtr );
			if( cryptStatusError( status ) )
				return( status );
			insertDoubleListElement( destListHeadPtr, insertPoint, 
									 newAttribute );
			srcListPtr = srcListPtr->next;
			}
		}

	return( CRYPT_OK );
	}

/* Copy attributes that are propagated down cert chains from an issuer to a
   subject cert, changing the field types from subject to issuer at the same
   time if required */

int copyIssuerAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType,
						  const CRYPT_CERTTYPE_TYPE type )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status = CRYPT_OK;

	assert( isWritePtr( destListHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcListPtr, ATTRIBUTE_LIST ) );

	/* If the destination is a CA cert and the source has name constraints,
	   copy them over to the destination */
	attributeListPtr = findAttributeField( *destListHeadPtr, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue )
		{
		ATTRIBUTE_LIST *srcPermittedSubtrees, *srcExcludedSubtrees;

		srcPermittedSubtrees = findAttributeField( srcListPtr,
												   CRYPT_CERTINFO_PERMITTEDSUBTREES,
												   CRYPT_ATTRIBUTE_NONE );
		srcExcludedSubtrees = findAttributeField( srcListPtr,
												  CRYPT_CERTINFO_EXCLUDEDSUBTREES,
												  CRYPT_ATTRIBUTE_NONE );

		/* If we're copying permitted or excluded subtrees, they can't 
		   already be present. We check the two separately rather than just 
		   checking for the overall presence of name constraints since in 
		   theory it's possible to merge permitted and excluded constraints,
		   so that permitted constraints in the destination don't clash with
		   excluded constraints in the source (yet another one of X.509's 
		   semantic holes) */
		if( srcPermittedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr, \
								CRYPT_CERTINFO_PERMITTEDSUBTREES,
								CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_PERMITTEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		if( srcExcludedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr, \
								CRYPT_CERTINFO_EXCLUDEDSUBTREES,
								CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_EXCLUDEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}

		/* Copy the fields across */
		if( srcPermittedSubtrees != NULL )
			status = copyAttribute( destListHeadPtr, srcPermittedSubtrees, FALSE );
		if( cryptStatusOK( status ) && srcExcludedSubtrees != NULL )
			status = copyAttribute( destListHeadPtr, srcExcludedSubtrees, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's an attribute certificate, that's all we can copy */
	if( type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		return( CRYPT_OK );

	/* Copy the altName and keyIdentifier if these are present.  We don't
	   have to check for their presence in the destination cert since they're
	   read-only fields and can't be added by the user */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_SUBJECTALTNAME, FALSE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, FALSE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Copy the authorityInfoAccess if it's present.  This one is a bit 
	   tricky both because it's a multi-valued attribute and some values 
	   may already be present in the destination cert and because it's not 
	   certain that the issuer cert's AIA should be the same as the subject 
	   cert's AIA.  At the moment with monolithic CAs (i.e.ones that control 
	   all the certs down to the EE) this is always the case, and if it isn't
	   it's assumed that the CA will set the EE's AIA to the appropriate 
	   value before trying to sign the cert.  Because of this we copy the 
	   issuer AIA if there's no subject AIA present, otherwise we assume that 
	   the CA has set the subject AIA to its own choice of value and don't 
	   try and copy anything */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_AUTHORITYINFOACCESS, FALSE );
	if( attributeListPtr != NULL && \
		findAttribute( *destListHeadPtr, 
					   CRYPT_CERTINFO_AUTHORITYINFOACCESS, FALSE ) == NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Copy attributes that are propagated from an OCSP request to a response */

int copyRequestAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						   const ATTRIBUTE_LIST *srcListPtr,
						   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						   CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status = CRYPT_OK;

	assert( isWritePtr( destListHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcListPtr, ATTRIBUTE_LIST ) );

	/* If the nonce attribute is already present in the destination, delete
	   it */
	attributeListPtr = findAttributeField( *destListHeadPtr,
							CRYPT_CERTINFO_OCSP_NONCE, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		deleteAttributeField( destListHeadPtr, NULL, attributeListPtr, NULL );

	/* Copy the nonce attribute from the source to the destination.  We don't
	   copy anything else (i.e. we default to deny-all) to prevent the 
	   requester from being able to insert arbitrary attributes into the 
	   response */
	attributeListPtr = findAttributeField( srcListPtr,
							CRYPT_CERTINFO_OCSP_NONCE, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		status = copyAttribute( destListHeadPtr, attributeListPtr, FALSE );

	return( status );
	}

/* Copy attributes that are propagated from a revocation request to a CRL */

int copyRevocationAttributes( ATTRIBUTE_LIST **destListHeadPtr,
							  const ATTRIBUTE_LIST *srcListPtr,
							  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							  CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status = CRYPT_OK;

	assert( isWritePtr( destListHeadPtr, ATTRIBUTE_LIST * ) );
	assert( isReadPtr( srcListPtr, ATTRIBUTE_LIST ) );

	/* Copy the CRL reason and invalidity date attributes from the source to 
	   the destination.  We don't copy anything else (i.e.default to deny-all)
	   to prevent the requester from being able to insert arbitrary 
	   attributes into the CRL */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_CRLREASON, FALSE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_INVALIDITYDATE, FALSE );
	if( attributeListPtr != NULL )
		status = copyAttribute( destListHeadPtr, attributeListPtr, FALSE );

	return( status );
	}

/* Delete an attribute/attribute field from a list of attributes, updating
   the list cursor at the same time.  This is a somewhat ugly kludge, it's
   not really possible to do this cleanly since deleting attributes affects
   the attribute cursor */

int deleteAttributeField( ATTRIBUTE_LIST **attributeListPtr,
						  ATTRIBUTE_LIST **listCursorPtr,
						  ATTRIBUTE_LIST *listItem,
						  const void *dnDataPtr )
	{
	ATTRIBUTE_LIST *listPrevPtr = listItem->prev;
	ATTRIBUTE_LIST *listNextPtr = listItem->next;
	BOOLEAN deletedDN = FALSE;

	assert( isWritePtr( attributeListPtr, ATTRIBUTE_LIST * ) );
	assert( isWritePtr( *attributeListPtr, ATTRIBUTE_LIST ) );
	assert( isWritePtr( listItem, ATTRIBUTE_LIST ) );

	/* If we're about to delete the field that's pointed to by the attribute 
	   cursor, advance the cursor to the next field.  If there's no next 
	   field, move it to the previous field.  This behaviour is the most
	   logically consistent, it means we can do things like deleting an
	   entire attribute list by repeatedly deleting a field */
	if( listCursorPtr != NULL && *listCursorPtr == listItem )
		*listCursorPtr = ( listNextPtr != NULL ) ? listNextPtr : listPrevPtr;

	/* Remove the item from the list */
	if( listItem == *attributeListPtr )
		{
		/* Special case for first item */
		*attributeListPtr = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		listPrevPtr->next = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = listPrevPtr;
		}

	/* Clear all data in the item and free the memory */
	if( listItem->fieldType == FIELDTYPE_DN )
		{
		if( dnDataPtr != NULL && dnDataPtr == &listItem->value )
			deletedDN = TRUE;
		deleteDN( ( void ** ) &listItem->value );
		}
	endVarStruct( listItem, ATTRIBUTE_LIST );
	clFree( "deleteAttributeField", listItem );

	return( deletedDN ? OK_SPECIAL : CRYPT_OK );
	}

int deleteAttribute( ATTRIBUTE_LIST **attributeListPtr,
					 ATTRIBUTE_LIST **listCursorPtr,
					 ATTRIBUTE_LIST *listItem,
					 const void *dnDataPtr )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;
	ATTRIBUTE_LIST *attributeListCursor;
	int status = CRYPT_OK;

	assert( isWritePtr( attributeListPtr, ATTRIBUTE_LIST * ) );
	assert( isWritePtr( *attributeListPtr, ATTRIBUTE_LIST ) );
	assert( isWritePtr( listItem, ATTRIBUTE_LIST ) );

	/* If it's a blob-type attribute, everything is contained in this one
	   list item so we only need to destroy that */
	if( isBlobAttribute( listItem ) )
		return( deleteAttributeField( attributeListPtr, listCursorPtr, 
									  listItem, NULL ) );

	/* If it's a field that denotes an entire (constructed) attribute, it
	   won't have an entry in the list, so we find the first field of the
	   constructed attribute that's present in the list and start deleting
	   from that point */
	if( isCompleteAttribute( listItem ) )
		{
		for( attributeListCursor = *attributeListPtr; 
			 attributeListCursor != NULL && \
				attributeListCursor->attributeID != listItem->intValue;
			 attributeListCursor = attributeListCursor->next );
		}
	else
		/* The list item is a field in the attribute, find the start of the
		   fields in this attribute */
		attributeListCursor = findAttributeStart( listItem );
	assert( isWritePtr( attributeListCursor, ATTRIBUTE_LIST ) );
	attributeID = attributeListCursor->attributeID;

	/* It's an item with multiple fields, destroy each field separately */
	while( attributeListCursor != NULL && \
		   attributeListCursor->attributeID == attributeID )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;
		int localStatus;

		attributeListCursor = attributeListCursor->next;
		localStatus = deleteAttributeField( attributeListPtr, listCursorPtr, 
											itemToFree, dnDataPtr );
		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}

	return( status );
	}

/* Delete a complete set of attributes */

void deleteAttributes( ATTRIBUTE_LIST **attributeListPtr )
	{
	ATTRIBUTE_LIST *attributeListCursor = *attributeListPtr;

	/* If the list was empty, return now */
	if( attributeListCursor == NULL )
		return;

	/* Destroy any remaining list items */
	while( attributeListCursor != NULL )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;

		attributeListCursor = attributeListCursor->next;
		deleteAttributeField( attributeListPtr, NULL, itemToFree, NULL );
		}
	}
