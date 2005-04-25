/****************************************************************************
*																			*
*					Certificate Attribute Management Routines				*
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

/* Prototypes for functions in certdn.c */

int convertEmail( CERT_INFO *certInfoPtr, void **dnListHead,
				  const CRYPT_ATTRIBUTE_TYPE altNameType );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used to provide external access to attribute list-
   internal fields */

static const void *getAttrFunction( const void *attributePtr, 
									CRYPT_ATTRIBUTE_TYPE *groupID, 
									CRYPT_ATTRIBUTE_TYPE *attributeID, 
									CRYPT_ATTRIBUTE_TYPE *instanceID,
									const ATTR_TYPE attrGetType )
	{
	const ATTRIBUTE_LIST *attributeListPtr = attributePtr;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Clear return values */
	if( groupID != NULL )
		*groupID = CRYPT_ATTRIBUTE_NONE;
	if( attributeID != NULL )
		*attributeID = CRYPT_ATTRIBUTE_NONE;
	if( instanceID != NULL )
		*instanceID = CRYPT_ATTRIBUTE_NONE;

	/* Move to the next or previous attribute if required */
	if( !isValidAttributeField( attributeListPtr ) )
		return( NULL );
	if( attrGetType == ATTR_PREV )
		attributeListPtr = attributeListPtr->prev;
	else
		if( attrGetType == ATTR_NEXT )
			attributeListPtr = attributeListPtr->next;
	if( !isValidAttributeField( attributeListPtr ) )
		return( NULL );

	/* Return ID information to the caller */
	if( groupID != NULL )
		*groupID = attributeListPtr->attributeID;
	if( attributeID != NULL )
		*attributeID = attributeListPtr->fieldID;
	if( instanceID != NULL )
		*instanceID = attributeListPtr->subFieldID;
	return( attributeListPtr );
	}

/****************************************************************************
*																			*
*								Attribute Type Mapping						*
*																			*
****************************************************************************/

/* Get the attribute information for a given OID */

const ATTRIBUTE_INFO *oidToAttribute( const ATTRIBUTE_TYPE attributeType,
									  const BYTE *oid )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const int length = sizeofOID( oid );

	assert( isReadPtr( selectAttributeInfo( attributeType ), 
					   sizeof( ATTRIBUTE_INFO ) ) );
	assert( isReadPtr( oid, sizeofOID( oid ) ) );

	for( attributeInfoPtr = selectAttributeInfo( attributeType );
		 attributeInfoPtr->fieldID != CRYPT_ERROR;
		 attributeInfoPtr++ )
		{
		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		if( attributeInfoPtr->oid != NULL && \
			sizeofOID( attributeInfoPtr->oid ) == length && \
			!memcmp( attributeInfoPtr->oid, oid, length ) )
			return( attributeInfoPtr );
		}

	/* It's an unknown attribute */
	return( NULL );
	}

/* Get the attribute and attributeID for a field ID */

const ATTRIBUTE_INFO *fieldIDToAttribute( const ATTRIBUTE_TYPE attributeType,
										  const CRYPT_ATTRIBUTE_TYPE fieldID, 
										  const CRYPT_ATTRIBUTE_TYPE subFieldID,
										  CRYPT_ATTRIBUTE_TYPE *attributeID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
							selectAttributeInfo( attributeType );
	int i;

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );
	assert( attributeID == NULL || \
			isWritePtr( attributeID, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );

	/* Clear the return value */
	if( attributeID != NULL )
		*attributeID = CRYPT_ATTRIBUTE_NONE;

	/* Find the information on this attribute field */
	for( i = 0; attributeInfoPtr[ i ].fieldID != CRYPT_ERROR; i++ )
		{
		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		/* If we're looking for an attribute ID and the previous entry 
		   doesn't have more data following it, the current entry is the 
		   start of a complete attribute and therefore contains the 
		   attribute ID */
		if( attributeID != NULL && \
			( i == 0 || !( attributeInfoPtr[ i - 1 ].flags & FL_MORE ) ) )
			{
			int offset;

			/* Usually the attribute ID is the fieldID for the first entry,
			   however in some cases the attributeID is the same as the
			   fieldID and isn't specified until later on.  For example when
			   the attribute consists of a SEQUENCE OF field the first
			   entry is the SEQUENCE and the fieldID isn't given until the
			   second entry.  This case is denoted by the fieldID being 
			   FIELDID_FOLLOWS, if this happens we have to look ahead to 
			   find the fieldID */
			for( offset = 0; 
				 attributeInfoPtr[ i + offset ].fieldID == FIELDID_FOLLOWS;
				 offset++ );
			*attributeID = attributeInfoPtr[ i + offset ].fieldID;
			}

		/* Check whether the field ID for this entry matches the one that we 
		   want */
		if( attributeInfoPtr[ i ].fieldID == fieldID )
			{
			const ATTRIBUTE_INFO *altEncodingTable = \
											attributeInfoPtr[ i ].extraData;

			/* If we're after a subfield match as well, try and match the
			   subfield */
			if( subFieldID != CRYPT_ATTRIBUTE_NONE && altEncodingTable != NULL )
				{
				for( i = 0; altEncodingTable[ i ].fieldID != CRYPT_ERROR; i++ )
					if( altEncodingTable[ i ].fieldID == subFieldID )
						return( &altEncodingTable[ i ] );

				assert( NOTREACHED );
				return( NULL );
				}

			return( &attributeInfoPtr[ i ] );
			}
		}

	assert( NOTREACHED );
	return( NULL );
	}

/****************************************************************************
*																			*
*					Attribute Location/Cursor Movement Routines				*
*																			*
****************************************************************************/

/* Find the start and end of an attribute from a field within the
   attribute */

ATTRIBUTE_LIST *findAttributeStart( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFindStart( attributeListPtr, getAttrFunction ) );
	}

static ATTRIBUTE_LIST *findAttributeEnd( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFindEnd( attributeListPtr, getAttrFunction ) );
	}

/* Find an attribute in a list of certificate attributes by object identifier
   (for blob-type attributes) or by field and subfield ID (for known
   attributes), with extended handling for fields with default values */

ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *attributeListPtr,
									const BYTE *oid )
	{
	const int length = sizeofOID( oid );

	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( oid, sizeofOID( oid ) ) );

	/* Find the position of this component in the list */
	while( attributeListPtr != NULL && \
		   ( !isBlobAttribute( attributeListPtr ) || \
			 sizeofOID( attributeListPtr->oid ) != length || \
			 memcmp( attributeListPtr->oid, oid, length ) ) )
		 attributeListPtr = attributeListPtr->next;

	return( ( ATTRIBUTE_LIST * ) attributeListPtr );
	}

ATTRIBUTE_LIST *findAttributeField( const ATTRIBUTE_LIST *attributeListPtr,
									const CRYPT_ATTRIBUTE_TYPE fieldID,
									const CRYPT_ATTRIBUTE_TYPE subFieldID )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );

	return( attributeFind( attributeListPtr, getAttrFunction,
						   fieldID, subFieldID ) );
	}

ATTRIBUTE_LIST *findAttributeFieldEx( const ATTRIBUTE_LIST *attributeListPtr,
									  const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	static const ATTRIBUTE_LIST defaultField = DEFAULTFIELD_VALUE;
	static const ATTRIBUTE_LIST completeAttribute = COMPLETEATTRIBUTE_VALUE;
	const ATTRIBUTE_LIST *attributeListCursor;
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const ATTRIBUTE_TYPE attributeType = \
							( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			fieldID <= CRYPT_CERTINFO_LAST );

	if( attributeListPtr == NULL )
		return( NULL );

	/* Find the position of this component in the list */
	attributeListCursor = attributeFind( attributeListPtr, 
										 getAttrFunction, fieldID, 
										 CRYPT_ATTRIBUTE_NONE );
	if( attributeListCursor != NULL )
		return( ( ATTRIBUTE_LIST * ) attributeListCursor );

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
	for( attributeListCursor = attributeListPtr;
		 isValidAttributeField( attributeListCursor ) && \
			attributeListCursor->attributeID != attributeID;
		 attributeListCursor = attributeListCursor->next );
	if( !isValidAttributeField( attributeListCursor ) )
		return( NULL );

	/* Some other part of the attribute containing the given field is 
	   present in the list.  If this field wasn't found it could either be a 
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

/* Find the next instance of an attribute field in an attribute.  This is 
   used to step through multiple instances of a field, for example where the
   attribute is defined as containing a SEQUENCE OF <field> */

ATTRIBUTE_LIST *findNextFieldInstance( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFindNextInstance( attributeListPtr, 
									   getAttrFunction ) );
	}

/* Find an overall attribute in a list of attributes.  This is almost always
   used as a check for the presence of an overall attribute, so we provide
   a separate function to make this explicit */

ATTRIBUTE_LIST *findAttribute( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE attributeID,
							   const BOOLEAN isFieldID )
	{
	CRYPT_ATTRIBUTE_TYPE localAttributeID = attributeID;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( attributeID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			attributeID <= CRYPT_CERTINFO_LAST );
	
	if( attributeListPtr == NULL )
		return( NULL );

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
	while( isValidAttributeField( attributeListPtr ) )
		{
		if( attributeListPtr->attributeID == localAttributeID )
			return( ( ATTRIBUTE_LIST * ) attributeListPtr );
		attributeListPtr = attributeListPtr->next;
		}

	return( NULL );
	}

BOOLEAN checkAttributePresent( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	return( findAttribute( attributeListPtr, fieldID, FALSE ) != NULL ? \
			TRUE : FALSE );
	}

/* Move the attribute cursor relative to the current cursor position */

ATTRIBUTE_LIST *moveAttributeCursor( const ATTRIBUTE_LIST *currentCursor,
									 const CRYPT_ATTRIBUTE_TYPE certInfoType, 
									 const int position )
	{
	assert( currentCursor == NULL || \
			isReadPtr( currentCursor, sizeof( ATTRIBUTE_LIST ) ) );
	assert( certInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			certInfoType == CRYPT_ATTRIBUTE_CURRENT || \
			certInfoType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	assert( position <= CRYPT_CURSOR_FIRST && \
			position >= CRYPT_CURSOR_LAST );

	return( ( ATTRIBUTE_LIST * ) \
			attributeMoveCursor( currentCursor, getAttrFunction,
								 certInfoType, position ) );
	}

/****************************************************************************
*																			*
*								Misc. Attribute Routines					*
*																			*
****************************************************************************/

/* Get the default value for an optional field of an attribute */

int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
			fieldIDToAttribute( ( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
								fieldID, CRYPT_ATTRIBUTE_NONE, NULL );

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	return( ( attributeInfoPtr == NULL ) ? \
			CRYPT_ERROR : ( int ) attributeInfoPtr->defaultValue );
	}

/* Fix up certificate attributes, mapping from incorrect values to standards-
   compliant ones */

int fixAttributes( CERT_INFO *certInfoPtr )
	{
	int complianceLevel, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

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
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL or above, don't try and compensate
	   for dubious attributes */
	status = krnlSendMessage( certInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );
	if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If the only key usage info present is the Netscape one, convert it 
	   into the X.509 equivalent */
	if( !checkAttributePresent( certInfoPtr->attributes, 
								CRYPT_CERTINFO_KEYUSAGE ) && \
		findAttributeField( certInfoPtr->attributes, 
							CRYPT_CERTINFO_NS_CERTTYPE, 
							CRYPT_ATTRIBUTE_NONE ) != NULL )
		{
		status = getKeyUsageFromExtKeyUsage( certInfoPtr, 
											 &certInfoPtr->errorLocus, 
											 &certInfoPtr->errorType );
		if( !cryptStatusError( status ) )
			status = addAttributeField( &certInfoPtr->attributes,
							CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE,
							&status, CRYPT_UNUSED, ATTR_FLAG_NONE, 
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
