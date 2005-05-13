/****************************************************************************
*																			*
*					Certificate Attribute Add/Delete Routines				*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in cryptcrt.c */

int textToOID( const char *oid, const int oidLength, BYTE *binaryOID );

/* Prototypes for functions in ext.c */

ATTRIBUTE_LIST *findAttributeStart( const ATTRIBUTE_LIST *attributeListPtr );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check the validity of an attribute field */

static int checkAttributeField( const ATTRIBUTE_LIST *attributeListPtr,
								const ATTRIBUTE_INFO *attributeInfoPtr,
								const CRYPT_ATTRIBUTE_TYPE fieldID,
								const CRYPT_ATTRIBUTE_TYPE subFieldID,
								const void *data, const int dataLength,
								const int flags, 
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );
	assert( dataLength == CRYPT_UNUSED || \
			( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
	assert( dataLength == CRYPT_UNUSED || isReadPtr( data, dataLength ) );
	assert( !( flags & ATTR_FLAG_INVALID ) );

	/* Make sure that a valid field has been specified, and that this field
	   isn't already present as a non-default entry unless it's a field for
	   which multiple values are allowed */
	if( attributeInfoPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	if( attributeListPtr != NULL && \
		findAttributeField( attributeListPtr, fieldID, subFieldID ) != NULL )
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
			/* When creating a new cert, this is a special-case field that's 
			   used as a placeholder to indicate that a DN structure is being 
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
				if( dataLength >= 3 && sizeofOID( oidPtr ) == dataLength )
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
			   valid, however we let the caller know that this is non-string 
			   data */
			return( OK_SPECIAL );

		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_NULL:
		case FIELDTYPE_CHOICE:
			{
			int value = *( ( int * ) data );

			/* Check that the range is valid */
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

	/* It's some sort of string value, perform a general data size check */
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
			if( cryptStatusError( checkObjectEncoding( data, dataLength ) ) )
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

			/* Make sure that it's a numeric string */
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
			/* Make sure that it's an ASCII string of the correct type */
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

/****************************************************************************
*																			*
*								Add Attribute Data							*
*																			*
****************************************************************************/

/* Add a blob-type attribute to a list of attributes */

int addAttribute( const ATTRIBUTE_TYPE attributeType,
				  ATTRIBUTE_LIST **listHeadPtr, const BYTE *oid,
				  const BOOLEAN criticalFlag, const void *data,
				  const int dataLength, const int flags )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint = NULL;
	const int oidLength = sizeofOID( oid );

	assert( isWritePtr( listHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( oid, oidLength ) );
	assert( criticalFlag == TRUE || criticalFlag == FALSE );
	assert( isReadPtr( data, dataLength ) );
	assert( ( flags & ( ATTR_FLAG_IGNORED | ATTR_FLAG_BLOB ) ) || \
			!cryptStatusError( checkObjectEncoding( data, dataLength ) ) );
	assert( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE );
	assert( flags == ATTR_FLAG_NONE || flags == ATTR_FLAG_BLOB || \
			flags == ( ATTR_FLAG_BLOB | ATTR_FLAG_IGNORED ) );

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
				sizeofOID( insertPoint->oid ) == oidLength && \
				!memcmp( insertPoint->oid, oid, oidLength ) )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
		insertPoint = prevElement;
		}

	/* Allocate memory for the new element and copy the information across.  
	   The data is stored in storage ... storage + dataLength, the OID in
	   storage + dataLength ... storage + dataLength + oidLength */
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addAttribute", sizeof( ATTRIBUTE_LIST ) + \
												dataLength + oidLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, dataLength + oidLength );
	newElement->oid = newElement->storage + dataLength;
	memcpy( newElement->oid, oid, oidLength );
	newElement->flags = ( flags & ATTR_FLAG_IGNORED ) | \
						( criticalFlag ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE );
	memcpy( newElement->value, data, dataLength );
	newElement->valueLength = dataLength;
	insertDoubleListElements( listHeadPtr, insertPoint, newElement, newElement );

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

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );
	assert( dataLength == CRYPT_UNUSED || \
			( dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
	assert( dataLength == CRYPT_UNUSED || isReadPtr( data, dataLength ) );
	assert( !( flags & ATTR_FLAG_INVALID ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

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
			if( errorType != NULL && *errorType != CRYPT_ERRTYPE_NONE )
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
		assert( !isValidAttributeField( insertPoint->next ) || \
				insertPoint->attributeID <= insertPoint->next->attributeID );

		/* If it's a composite field that can have multiple fields with the 
		   same field ID (e.g. a GeneralName), exit if the overall field ID 
		   is greater (the component belongs to a different field entirely) 
		   or if the field ID is the same and the subfield ID is greater (if 
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
	   element itself, otherwise we copy it into the storage in the element.  
	   Something that encodes to NULL isn't really a numeric type, but we 
	   class it as such so that any attempt to read it returns CRYPT_UNUSED 
	   as the value */
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

/****************************************************************************
*																			*
*								Delete Attribute Data						*
*																			*
****************************************************************************/

/* Delete an attribute/attribute field from a list of attributes, updating
   the list cursor at the same time.  This is a somewhat ugly kludge, it's
   not really possible to do this cleanly since deleting attributes affects
   the attribute cursor */

int deleteAttributeField( ATTRIBUTE_LIST **attributeListPtr,
						  ATTRIBUTE_LIST **listCursorPtr,
						  ATTRIBUTE_LIST *listItem,
						  const void *dnCursor )
	{
	ATTRIBUTE_LIST *listPrevPtr = listItem->prev;
	ATTRIBUTE_LIST *listNextPtr = listItem->next;
	BOOLEAN deletedDN = FALSE;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( *attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( listCursorPtr == NULL || \
			isWritePtr( listCursorPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( listItem, sizeof( ATTRIBUTE_LIST ) ) );

	/* If we're about to delete the field that's pointed to by the attribute 
	   cursor, advance the cursor to the next field.  If there's no next 
	   field, move it to the previous field.  This behaviour is the most
	   logically consistent, it means that we can do things like deleting an
	   entire attribute list by repeatedly deleting a field */
	if( listCursorPtr != NULL && *listCursorPtr == listItem )
		*listCursorPtr = ( listNextPtr != NULL ) ? listNextPtr : listPrevPtr;

	/* Remove the item from the list */
	deleteDoubleListElement( attributeListPtr, listItem );

	/* Clear all data in the item and free the memory */
	if( listItem->fieldType == FIELDTYPE_DN )
		{
		/* If we've deleted the DN at the current cursor position, remember
		   this so that we can warn the caller */
		if( dnCursor != NULL && dnCursor == &listItem->value )
			deletedDN = TRUE;
		deleteDN( ( void ** ) &listItem->value );
		}
	endVarStruct( listItem, ATTRIBUTE_LIST );
	clFree( "deleteAttributeField", listItem );

	/* If we deleted the DN at the current cursor position, return a 
	   special-case code to let the caller know */
	return( deletedDN ? OK_SPECIAL : CRYPT_OK );
	}

int deleteAttribute( ATTRIBUTE_LIST **attributeListPtr,
					 ATTRIBUTE_LIST **listCursorPtr,
					 ATTRIBUTE_LIST *listItem,
					 const void *dnCursor )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;
	ATTRIBUTE_LIST *attributeListCursor;
	int status = CRYPT_OK;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( *attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( listItem, sizeof( ATTRIBUTE_LIST ) ) );

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
	assert( isWritePtr( attributeListCursor, sizeof( ATTRIBUTE_LIST ) ) );
	attributeID = attributeListCursor->attributeID;

	/* It's an item with multiple fields, destroy each field separately */
	while( attributeListCursor != NULL && \
		   attributeListCursor->attributeID == attributeID )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;
		int localStatus;

		attributeListCursor = attributeListCursor->next;
		localStatus = deleteAttributeField( attributeListPtr, listCursorPtr, 
											itemToFree, dnCursor );
		if( cryptStatusError( localStatus ) && status != OK_SPECIAL )
			/* Remember the error code, giving priority to DN cursor-
			   modification notifications */
			status = localStatus;
		}

	return( status );
	}

/* Delete a complete set of attributes */

void deleteAttributes( ATTRIBUTE_LIST **attributeListPtr )
	{
	ATTRIBUTE_LIST *attributeListCursor = *attributeListPtr;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );

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

	assert( *attributeListPtr == NULL );
	}
