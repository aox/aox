/****************************************************************************
*																			*
*						Certificate Attribute Read Routines					*
*						 Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Define the following to print a trace of the cert fields being parsed,
   useful for debugging broken certs */

#if !defined( NDEBUG ) && 0
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos ) \
		  { \
		  int i; \
		  \
		  for( i = 0; i < stackPos; i++ ) \
			  printf( "  " ); \
		  if( ( attributeInfoPtr ) != NULL && \
			  ( attributeInfoPtr )->description != NULL ) \
			  puts( ( attributeInfoPtr )->description ); \
		  }
#else
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos )
#endif /* NDEBUG */

/* Prototypes for functions in certcomp.c */

int oidToText( const BYTE *binaryOID, char *oid );

/****************************************************************************
*																			*
*								Attribute Read Routines						*
*																			*
****************************************************************************/

/* Find the end of an item (either primitive or constructed) in the attribute
   table.  Sometimes we may have already entered a constructed object (for
   example when an attribute has a version number so we don't know until we've
   started processing it that we can't do anything with it), if this is the
   case the depth parameter indicates how many nesting levels we have to
   undo */

static const ATTRIBUTE_INFO *findItemEnd( const ATTRIBUTE_INFO *attributeInfoPtr,
										  const int depth )
	{
	BOOLEAN attributeContinues;
	int currentDepth = depth;

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( depth >= 0 && depth < 3 );

	/* Skip to the end of the (potentially) constructed item by recording the
	   nesting level and continuing until either it reaches zero or we reach
	   the end of the item */
	do
		{
		/* If it's a sequence/set, increment the depth; if it's an end-of-
		   constructed-item marker, decrement it by the appropriate amount */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			currentDepth++;
		currentDepth -= decodeNestingLevel( attributeInfoPtr->flags );

		/* Move to the next entry */
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeInfoPtr++;
		}
	while( currentDepth > 0 && attributeContinues );

	/* Return the previous entry, since we're going to move on to the next
	   entry once we return */
	return( attributeInfoPtr - 1 );
	}

/* Given a pointer to a set of SEQUENCE { type, value } entries, return a
   pointer to the value entry appropriate for the data in the stream.  If the
   entry contains user data in the { value } portion then the returned pointer
   points to this, if it contains a fixed value or isn't present at all then
   the returned pointer points to the { type } portion */

static const ATTRIBUTE_INFO *findIdentifiedItem( STREAM *stream,
									const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	BYTE oid[ MAX_OID_SIZE ];
	int oidLength, sequenceLength, status;

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( attributeInfoPtr->flags & FL_IDENTIFIER );

	/* Skip the header and read the OID.  We only check for a sane total
	   length in the debug version since this isn't a fatal error */
	readSequence( stream, &sequenceLength );
	status = readRawObject( stream, oid, &oidLength, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( NULL );
	sequenceLength -= oidLength;
	assert( sequenceLength >= 0 );

	/* Walk down the list of entries trying to match it to an allowed value */
	while( attributeInfoPtr->flags & FL_IDENTIFIER )
		{
		const BYTE *oidPtr;

		/* Skip the SEQUENCE and OID */
		attributeInfoPtr++;
		oidPtr = attributeInfoPtr->oid;
		if( !( attributeInfoPtr->flags & FL_NONENCODING ) )
			attributeInfoPtr++;
		else
			/* If this is a blob field, we've hit a don't-care value (usually
			   the last in a series of type-and-value pairs) which ensures
			   that new additions don't get processed as errors */
			if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
				{
				/* If there's a { value } attached to the type, skip it */
				if( sequenceLength > 0 )
					sSkip( stream, sequenceLength );
				return( attributeInfoPtr );
				}

		/* In case there's an error in the encoding table, make sure that we
		   don't die during parsing */
		if( oidPtr == NULL )
			{
			assert( NOTREACHED );
			return( NULL );
			}

		/* If the OID matches, return a pointer to the value entry */
		if( oidLength == sizeofOID( oidPtr ) && \
			!memcmp( oidPtr, oid, sizeofOID( oidPtr ) ) )
			{
			/* If this is a fixed field and there's a value attached, skip
			   it */
			if( ( attributeInfoPtr->flags & FL_NONENCODING ) && \
				sequenceLength > 0 )
				sSkip( stream, sequenceLength );

			return( attributeInfoPtr );
			}

		/* The OID doesn't match, skip the value entry and continue.  We set
		   the current nesting depth parameter to 1 since we've already
		   entered the SEQUENCE above */
		attributeInfoPtr = findItemEnd( attributeInfoPtr, 1 ) + 1;
		}

	/* We reached the end of the set of entries without matching the OID */
	return( NULL );
	}

/* Read a sequence of identifier fields of the form
   SEQUENCE OF { oid, value OPTIONAL } */

static int readIdentifierFields( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO **attributeInfoPtrPtr, const int flags,
			const CRYPT_ATTRIBUTE_TYPE fieldID, CRYPT_ATTRIBUTE_TYPE *errorLocus,
			CRYPT_ERRTYPE_TYPE *errorType )
	{
	int count = 0;

	assert( !( flags & ATTR_FLAG_INVALID ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	while( peekTag( stream ) == BER_OBJECT_IDENTIFIER )
		{
		const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
		BYTE oid[ MAX_OID_SIZE ];
		static const int dummy = CRYPT_UNUSED;
		int oidLength, status;

		/* Make sure that we don't die during parsing if there's an error in
		   the encoding table */
		if( attributeInfoPtr->oid == NULL )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}

		/* Read the OID and walk down the list of possible OIDs up to the end
		   of the group of alternatives trying to match it to an allowed
		   value */
		status = readRawObject( stream, oid, &oidLength, MAX_OID_SIZE,
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );
		while( oidLength != sizeofOID( attributeInfoPtr->oid ) || \
			   memcmp( attributeInfoPtr->oid, oid, oidLength ) )
			{
			/* If we've reached the end of the list and the OID wasn't
			   matched, exit */
			if( ( attributeInfoPtr->flags & FL_SEQEND_MASK ) || \
				!( attributeInfoPtr->flags & FL_MORE ) )
				return( CRYPT_ERROR_BADDATA );

			attributeInfoPtr++;

			/* Make sure that we don't die during parsing if there's an error
			   in the encoding table */
			if( attributeInfoPtr->oid == NULL )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}

		/* The OID matches, add this field as an identifier field (this
		   will catch duplicate OIDs since we can't add the same identifier
		   field twice) */
		TRACE_FIELDTYPE( attributeInfoPtr, 0 );
		if( fieldID != CRYPT_ATTRIBUTE_NONE )
			/* If there's a field value present then this is a CHOICE of
			   attributes whose value is the field value, so we add it with
			   this value */
			status = addAttributeField( attributeListPtrPtr,
									fieldID, CRYPT_ATTRIBUTE_NONE,
									&attributeInfoPtr->fieldID, CRYPT_UNUSED,
									flags, errorLocus, errorType );
		else
			/* It's a standard field */
			status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, flags, errorLocus,
							errorType );
		if( cryptStatusError( status ) )
			return( status );
		count++;

		/* If there's more than one OID present in a CHOICE, it's an error */
		if( fieldID != CRYPT_ATTRIBUTE_NONE && count > 1 )
			{
			*errorLocus = attributeInfoPtr->fieldID,
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* We've processed the non-data field(s), move on to the next field.
	   We move to the last valid non-data field rather than the start of the
	   field following it since the caller needs to be able to check whether
	   there are more fields to follow using the current fields flags */
	while( !( ( *attributeInfoPtrPtr )->flags & FL_SEQEND_MASK ) && \
			( ( *attributeInfoPtrPtr )->flags & FL_MORE ) )
		( *attributeInfoPtrPtr )++;

	return( CRYPT_OK );
	}

/* Read the contents of attribute field.  This uses the readXXXData() 
   variants of the read functions because the field we're reading may be
   tagged, so we process the tag at a higher level and only read the 
   contents here */

static int fieldErrorReturn( CRYPT_ATTRIBUTE_TYPE *errorLocus,
							 CRYPT_ERRTYPE_TYPE *errorType, const int status,
							 const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	/* Since some fields are internal-use only (e.g. meaningless blob data,
	   version numbers, and other paraphernalia) we only set the locus if
	   it has a meaningful value */
	*errorLocus = ( fieldID > CRYPT_CERTINFO_FIRST && \
					fieldID < CRYPT_CERTINFO_LAST ) ? \
				  fieldID : CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
	return( status );
	}

static int readAttributeField( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO *attributeInfoPtr,
			const CRYPT_ATTRIBUTE_TYPE subtypeParent, const int flags,
			CRYPT_ATTRIBUTE_TYPE *errorLocus, CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRYPT_ATTRIBUTE_TYPE fieldID, subFieldID;
	int length, status;

	assert( !( flags & ATTR_FLAG_INVALID ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	/* Set up the field identifiers depending on whether it's a normal field
	   or a subfield of a parent field */
	if( subtypeParent == CRYPT_ATTRIBUTE_NONE )
		{
		fieldID = attributeInfoPtr->fieldID;
		subFieldID = CRYPT_ATTRIBUTE_NONE;
		}
	else
		{
		fieldID = subtypeParent;
		subFieldID = attributeInfoPtr->fieldID;
		}

	/* If it's an integer or time type, read it */
	if( attributeInfoPtr->fieldType == BER_INTEGER || \
		attributeInfoPtr->fieldType == BER_ENUMERATED || \
		attributeInfoPtr->fieldType == BER_BITSTRING || \
		attributeInfoPtr->fieldType == BER_BOOLEAN || \
		attributeInfoPtr->fieldType == BER_NULL )
		{
		BOOLEAN boolean;
		long longValue;
		int value;

		/* Read the data as appropriate */
		switch( attributeInfoPtr->fieldType )
			{
			case BER_BITSTRING:
				status = readBitStringData( stream, &value );
				break;

			case BER_BOOLEAN:
				status = readBooleanData( stream, &boolean );
				value = boolean;
				break;

			case BER_ENUMERATED:
				status = readEnumeratedData( stream, &value );
				break;

			case BER_INTEGER:
				status = readShortIntegerData( stream, &longValue );
				value = ( int ) longValue;
				break;

			case BER_NULL:
				/* NULL values have no associated data so we explicitly set
				   the value to CRYPT_UNUSED to ensure that this is returned
				   on any attempt to read it */
				value = CRYPT_UNUSED;
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR );
			}
		if( cryptStatusError( status ) )
			return( fieldErrorReturn( errorLocus, errorType, status,
									  attributeInfoPtr->fieldID ) );

		/* Add the data for this attribute field */
		return( addAttributeField( attributeListPtrPtr, fieldID, subFieldID,
								   &value, CRYPT_UNUSED, flags, errorLocus,
								   errorType ) );
		}
	if( attributeInfoPtr->fieldType == BER_TIME_GENERALIZED || \
		attributeInfoPtr->fieldType == BER_TIME_UTC )
		{
		time_t timeVal;

		if( attributeInfoPtr->fieldType == BER_TIME_GENERALIZED )
			status = readGeneralizedTimeData( stream, &timeVal );
		else
			status = readUTCTimeData( stream, &timeVal );
		if( cryptStatusError( status ) )
			return( fieldErrorReturn( errorLocus, errorType, status,
									  attributeInfoPtr->fieldID ) );

		/* Add the data for this attribute field */
		return( addAttributeField( attributeListPtrPtr, fieldID, subFieldID,
								   &timeVal, sizeof( time_t ), flags,
								   errorLocus, errorType ) );
		}

	/* If it's a string type or a blob, read it in as a blob (the only
	   difference being that for a true blob we read the tag + length as
	   well) */
	if( attributeInfoPtr->fieldType == BER_STRING_BMP || \
		attributeInfoPtr->fieldType == BER_STRING_IA5 || \
		attributeInfoPtr->fieldType == BER_STRING_ISO646 || \
		attributeInfoPtr->fieldType == BER_STRING_NUMERIC || \
		attributeInfoPtr->fieldType == BER_STRING_PRINTABLE || \
		attributeInfoPtr->fieldType == BER_STRING_T61 || \
		attributeInfoPtr->fieldType == BER_STRING_UTF8 || \
		attributeInfoPtr->fieldType == BER_OCTETSTRING || \
		attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
		{
		BYTE buffer[ 256 ];

		/* Read in the string to a maximum length of 256 bytes.  Anything
		   longer is quietly truncated, strings in certs shouldn't be this
		   long anyway */
		if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
			status = readRawObjectTag( stream, buffer, &length, 256, CRYPT_UNUSED );
		else
			status = readOctetStringData( stream, buffer, &length, 256 );
		if( cryptStatusError( status ) )
			return( fieldErrorReturn( errorLocus, errorType, status,
									  attributeInfoPtr->fieldID ) );

		/* There are enough broken certs out there with enormously long
		   disclaimers in the cert policy explicit text field that we
		   have to specifically check for them here and truncate the text
		   at a valid length in order to get it past the extension
		   validity checking code */
		if( fieldID == CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT && \
			length > 200 )
			length = 200;

		/* Add the data for this attribute field, setting the payload-blob
		   flag to disable type-checking of the payload data so users can
		   cram any old rubbish into the strings */
		return( addAttributeField( attributeListPtrPtr, fieldID, subFieldID,
								   buffer, length, flags | ATTR_FLAG_BLOB_PAYLOAD,
								   errorLocus, errorType ) );
		}

	/* If it's an OID, we need to reassemble the entire OID since this is the
	   form expected by addAttributeField() */
	if( attributeInfoPtr->fieldType == BER_OBJECT_IDENTIFIER )
		{
		BYTE oid[ MAX_OID_SIZE ];

		oid[ 0 ] = BER_OBJECT_IDENTIFIER;	/* Add skipped tag */
		status = readRawObjectData( stream, oid + 1, &length,
									MAX_OID_SIZE - 1 );
		if( cryptStatusError( status ) )
			return( fieldErrorReturn( errorLocus, errorType, status,
									  attributeInfoPtr->fieldID ) );
		return( addAttributeField( attributeListPtrPtr, fieldID, subFieldID,
								   oid, length + 1, flags, errorLocus,
								   errorType ) );
		}

	/* If it's a special-case field, read it */
	if( attributeInfoPtr->fieldType == FIELDTYPE_DN )
		{
		void *dnPtr = NULL;

		/* Read the DN */
		status = readDN( stream, &dnPtr );
		if( cryptStatusError( status ) )
			return( fieldErrorReturn( errorLocus, errorType, status,
									  attributeInfoPtr->fieldID ) );

		/* Some buggy certs can include zero-length DNs, which we skip */
		if( dnPtr == NULL )
			return( CRYPT_OK );

		/* We're being asked to instantiate the field containing the DN,
		   create the attribute field and fill in the DN value */
		status = addAttributeField( attributeListPtrPtr, fieldID, subFieldID,
									dnPtr, CRYPT_UNUSED, flags, errorLocus,
									errorType );
		if( cryptStatusError( status ) )
			deleteDN( &dnPtr );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* When we're processing SETs/SEQUENCEs (generically referred to as a SET
   OF), we need to maintain a stack of state information in case we
   encounter a nested SET OF.  The following code implements the state
   stack */

#define SETOF_STATE_STACKSIZE	16

typedef struct {
	const ATTRIBUTE_INFO *infoStart;	/* Start of SET OF attribute info */
	int endPos, endEOC;		/* End position of SET OF and optional EOC */
	CRYPT_ATTRIBUTE_TYPE subtypeParent;	/* Parent type if this is subtyped */
	int inheritedFlags;		/* Flags inherited from parent if subtyped */
	BOOLEAN restartPoint;	/* Info is a SET OF (rather than SET) */
	BOOLEAN subTyped;		/* SET ends on a subtyped value */
	} SETOF_STATE_INFO;

static SETOF_STATE_INFO *stackSetofState( SETOF_STATE_INFO *setofStack,
										  int *stackPos )
	{
	const int newPos = *stackPos + 1;

	/* Increment the stack pointer and make sure we don't overflow */
	if( newPos >= SETOF_STATE_STACKSIZE )
		{
		assert( NOTREACHED );
		return( &setofStack[ 0 ] );
		}
	*stackPos = newPos;

	/* Initialise the new entry */
	memset( &setofStack[ newPos ], 0, sizeof( SETOF_STATE_INFO ) );
	return( &setofStack[ newPos ] );
	}

static SETOF_STATE_INFO *unstackSetofState( SETOF_STATE_INFO *setofStack,
											int *stackPos )
	{
	const int newPos = *stackPos - 1;

	if( newPos < 0 )
		{
		assert( NOTREACHED );
		return( &setofStack[ 0 ] );
		}
	*stackPos = newPos;
	return( &setofStack[ newPos ] );
	}

/* Read an attribute */

static int readAttribute( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO *attributeInfoPtr, const int attributeLength,
			const BOOLEAN criticalFlag, CRYPT_ATTRIBUTE_TYPE *errorLocus,
			CRYPT_ERRTYPE_TYPE *errorType )
	{
	SETOF_STATE_INFO setofStack[ SETOF_STATE_STACKSIZE ];
	SETOF_STATE_INFO *setofInfoPtr;
	const int endPos = stell( stream ) + attributeLength;
	BOOLEAN attributeContinues = TRUE;
	int flags = criticalFlag ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE;
	int setofStackPos = 0, status = CRYPT_OK;

	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( criticalFlag == TRUE || criticalFlag == FALSE );
	assert( attributeLength >= 0 );

	/* Clear the top of the SET OF state stack.  This entry is always all-
	   zero to represent an empty stack */
	memset( &setofStack[ 0 ], 0, sizeof( SETOF_STATE_INFO ) );
	setofInfoPtr = &setofStack[ 0 ];

	/* Process each field in the attribute.  This is a simple FSM driven by
	   the encoding table and the data we encounter.  The various states and
	   associated actions are indicated by the comment tags */
	do
		{
		BOOLEAN isTagged;
		int tag;

		/* Inside a SET/SET OF/SEQUENCE/SEQUENCE OF: Check for the end of the
		   item/collection of items.  This must be the first action taken
		   since reaching the end of a SET/SEQUENCE pre-empts all other
		   parsing actions */
		if( setofInfoPtr->endPos > 0 )
			{
			const ATTRIBUTE_INFO *oldAttributeInfoPtr = attributeInfoPtr;

			/* If we've reached the end of the collection of items, exit */
			while( setofStackPos > 0 && \
				   stell( stream ) >= setofInfoPtr->endPos )
				{
#if 0		/* 22/11/03 Removed since these Verisign certs have now expired */
				/* If the extension drops into BER, make sure that the EOC
				   is present */
				if( setofInfoPtr->endEOC > 0 && checkEOC( stream ) != TRUE )
					return( CRYPT_ERROR_BADDATA );
#endif /* 0 */

				/* Pop one level of parse state.  If it's a restart point
				   (SET OF/SEQUENCE OF), restart from here */
				if( !setofInfoPtr->restartPoint || \
					stell( stream ) >= setofInfoPtr->endPos )
					/* It's a straight SET/SEQUENCE, find what follows it */
					attributeInfoPtr = findItemEnd( setofInfoPtr->infoStart, 0 );
				else
					/* It's a SET OF/SEQUENCE OF and there are more entries
					   present, restart from the start of the SET OF */
					attributeInfoPtr = setofInfoPtr->infoStart;
				setofInfoPtr = unstackSetofState( setofStack,
												  &setofStackPos );

				assert( setofInfoPtr->endPos > 0 && \
						setofInfoPtr->endPos < 65536L );
				}
			if( attributeInfoPtr != oldAttributeInfoPtr )
				goto continueDecoding;

			/* If we're looking for a new item, find the table entry that it
			   corresponds to.  This takes a pointer to the start of a set of
			   SEQUENCE { type, value } entries and returns a pointer to the
			   appropriate value entry.

			   The test for the start of a new item is a bit complex since we
			   could be at the end of the previous item (i.e. on the next item
			   flagged as an identifier) or at the end of the attribute (i.e.
			   on the start of the next attribute) */
			if( !( attributeInfoPtr[ -1 ].flags & FL_MORE ) || \
				attributeInfoPtr->flags & FL_IDENTIFIER )
				{
				const CRYPT_ATTRIBUTE_TYPE oldFieldID = \
									attributeInfoPtr->fieldID;

				/* Search for the identified item from the start of the
				   set of items.  The 0-th value is the SET OF/SEQUENCE OF,
				   so we start the search at the next entry which is the
				   first FL_IDENTIFIER */
				assert( setofInfoPtr->infoStart->flags & FL_SETOF );
				attributeInfoPtr = findIdentifiedItem( stream,
											setofInfoPtr->infoStart + 1 );
				if( attributeInfoPtr == NULL )
					return( fieldErrorReturn( errorLocus, errorType,
											  CRYPT_ERROR_BADDATA,
											  oldFieldID ) );

				/* If it's a subtyped field, continue from a new encoding
				   table */
				if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
					continue;

				/* If the { type, value } pair has a fixed value then the
				   information being conveyed is its presence, not its
				   contents, so we add an attribute corresponding to its ID
				   and continue.  The addition of the attribute is a bit
				   tricky, some of the fixed type-and-value pairs can have
				   multiple entries denoting things like { algorithm, weak
				   key }, { algorithm, average key }, { algorithm, strong
				   key }, however all we're interested in is the strong key
				   so we ignore the value and only use the type (in his ordo 
				   est ordinem non servare).  Since the same type can be 
				   present multiple times (with different { value }s), we 
				   ignore data duplicate errors and continue */
				if( attributeInfoPtr->flags & FL_NONENCODING )
					{
					const int dummy = CRYPT_UNUSED;

					/* If it's a blob field type, we've ended up at a
					   generic catch-any value and can't do much with it */
					if( attributeInfoPtr->fieldType != FIELDTYPE_BLOB )
						{
						/* Add the field type, discarding warnings about dups */
						TRACE_FIELDTYPE( attributeInfoPtr, setofStackPos );
						status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, flags, errorLocus,
							errorType );
						if( status == CRYPT_ERROR_INITED )
							status = CRYPT_OK;
						if( cryptStatusError( status ) )
							return( fieldErrorReturn( errorLocus,
											errorType, CRYPT_ERROR_BADDATA,
											attributeInfoPtr->fieldID ) );
						}

					/* Reset the attribute info position in preparation for
					   the next value and continue */
					attributeInfoPtr = setofInfoPtr->infoStart + 1;
					continue;
					}
				}
			}

		/* Subtyped field: Switch to the new encoding table */
		if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
			{
			setofInfoPtr->subtypeParent = attributeInfoPtr->fieldID;
			setofInfoPtr->inheritedFlags = \
							( attributeInfoPtr->flags & FL_MULTIVALUED ) ? \
								ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;

			/* If the subtype ends once the current SET/SEQUENCE ends,
			   remember this so that we return to the main type when
			   appropriate */
			if( ( attributeInfoPtr->flags & FL_SEQEND_MASK ) || \
				!( attributeInfoPtr->flags & FL_MORE ) )
				setofInfoPtr->subTyped = TRUE;

			/* Switch to the new state */
			attributeInfoPtr = ( ATTRIBUTE_INFO * ) attributeInfoPtr->extraData;
			}

		/* CHOICE (of object identifiers): Read a single OID from a
		   selection */
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
			{
			const ATTRIBUTE_INFO *extraDataPtr = attributeInfoPtr->extraData;
						/* Needed because ->extraData is read-only */

			status = readIdentifierFields( stream, attributeListPtrPtr,
						&extraDataPtr, flags, attributeInfoPtr->fieldID,
						errorLocus, errorType );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType,
										  CRYPT_ERROR_BADDATA,
										  attributeInfoPtr->fieldID ) );
			goto continueDecoding;
			}

		/* Identifier field: Read a sequence of one or more { oid, value }
		   fields and continue */
		if( attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER )
			{
			status = readIdentifierFields( stream, attributeListPtrPtr,
								&attributeInfoPtr, flags,
								CRYPT_ATTRIBUTE_NONE, errorLocus, errorType );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType,
										  CRYPT_ERROR_BADDATA,
										  attributeInfoPtr->fieldID ) );
			goto continueDecoding;
			}

		/* Non-encoding field: Check that it matches the required value and
		   continue */
		if( attributeInfoPtr->flags & FL_NONENCODING )
			{
			BYTE data[ 64 ];
			int dataLength;

			/* Read the data and continue.  We don't check its value or set
			   specific error information for reasons given under the SET-OF
			   handling code above (value check) and optional field code below
			   (error locus set) */
			TRACE_FIELDTYPE( attributeInfoPtr, setofStackPos );
			status = readRawObject( stream, data, &dataLength, 64, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( status );
			goto continueDecoding;
			}

		/* Extract various pieces of information from the attribute field
		   definition */
		isTagged = ( attributeInfoPtr->fieldEncodedType ) ? TRUE : FALSE;
		tag = ( isTagged ) ? attributeInfoPtr->fieldEncodedType : \
							 attributeInfoPtr->fieldType;
		if( isTagged && ( attributeInfoPtr->fieldType == BER_SEQUENCE ||
						  attributeInfoPtr->fieldType == BER_SET ||
						  attributeInfoPtr->fieldType == FIELDTYPE_DN ||
						  ( attributeInfoPtr->flags & FL_EXPLICIT ) ) )
			/* If it's an implictly tagged sequence/set then it's constructed */
			tag |= BER_CONSTRUCTED;

		/* Optional field: Check whether it's present and if it isn't, move
		   on to the next field */
		if( ( attributeInfoPtr->flags & FL_OPTIONAL ) && \
			peekTag( stream ) != tag )
			{
			/* If it's a field with a default value, add that value.  This
			   isn't needed for cryptlib's own use since it knows the default
			   values for fields, but can cause confusion for the caller if
			   all fields in an attribute have default values because the
			   attribute will appear to disappear when it's read in as no
			   fields are ever added */
			if( attributeInfoPtr->flags & FL_DEFAULT )
				{
				const int value = ( int ) attributeInfoPtr->defaultValue;

				status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&value, CRYPT_UNUSED, flags, NULL, NULL );
				if( cryptStatusError( status ) )
					/* This is a field contributed from internal data so we
					   don't try and get an error locus or value for it
					   since this would only confuse the caller */
					return( CRYPT_ERROR_BADDATA );
				}

			/* Skip to the end of the item and continue */
			attributeInfoPtr = findItemEnd( attributeInfoPtr, 0 );
			goto continueDecoding;
			}

		/* Print a trace of what we're processing.  Everything before this
		   point does its own special-case tracing if required, so we don't
		   trace before we get here to prevent displaying duplicate/
		   misleading information */
		TRACE_FIELDTYPE( attributeInfoPtr, setofStackPos );

		/* Explicitly tagged field: Read the explicit wrapper and make sure
		   that it matches what we're expecting */
		if( attributeInfoPtr->flags & FL_EXPLICIT )
			{
			assert( isTagged );
			assert( MAKE_CTAG( tag ) == tag );	/* Always constructed */
			status = readConstructed( stream, NULL, tag );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* We've processed the explicit wrappper, we're now on the actual
			   tag */
			tag = attributeInfoPtr->fieldType;
			}

		/* Blob field or DN: We don't try and interpret blobs in any way, and
		   DNs are a composite structure read as a complete unit by the lower-
		   level code */
		if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB || \
			attributeInfoPtr->fieldType == FIELDTYPE_DN )
			{
			status = readAttributeField( stream, attributeListPtrPtr,
										 attributeInfoPtr,
										 setofInfoPtr->subtypeParent,
										 flags | setofInfoPtr->inheritedFlags,
										 errorLocus, errorType );
			if( cryptStatusError( status ) )
				/* Adding complex attributes such as DNs can return detailed
				   error codes that report the exact parameter that was wrong,
				   we don't need this much detail so we convert a parameter
				   error into a more general bad data status */
				return( fieldErrorReturn( errorLocus, errorType,
										  cryptArgError( status ) ? \
											CRYPT_ERROR_BADDATA : status,
										  attributeInfoPtr->fieldID ) );
			goto continueDecoding;
			}


		/* Standard field: Read the tag for the field and make sure that it
		   matches what we're expecting */
		if( peekTag( stream ) != tag )
			return( fieldErrorReturn( errorLocus, errorType,
									  CRYPT_ERROR_BADDATA,
									  attributeInfoPtr->fieldID ) );

		/* SET/SET OF/SEQUENCE/SEQUENCE OF start: Record its end position,
		   stack the current processing state, and continue */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET || \
			( attributeInfoPtr->flags & FL_SETOF ) )
			{
			int setofLength, setEndEOC = 0;

			assert( !( attributeInfoPtr->flags & FL_EXPLICIT ) );

			/* Determine the length and start position of the SET OF items.
			   Some broken Verisign certs suddenly break into BER inside the
			   cert policy extension, so if the length evaluates to zero we
			   have to determine it by burrowing into the ASN.1 */
#if 0		/* 22/11/03 Removed since these Verisign certs have now expired */
			objectPtr = sMemBufPtr( stream );
#endif /* 0 */
			if( attributeInfoPtr->fieldEncodedType )
				status = readConstructed( stream, &setofLength,
										  attributeInfoPtr->fieldEncodedType );
			else
				if( attributeInfoPtr->fieldType == BER_SET )
					status = readSet( stream, &setofLength );
				else
					status = readSequence( stream, &setofLength );
#if 0		/* 22/11/03 Removed since these Verisign certs have now expired */
			if( cryptStatusOK( status ) && setofLength == CRYPT_UNUSED )
				{
				/* Get the overall length without the tag + indef.length */
				status = setofLength = \
					getObjectLength( objectPtr, sMemDataLeft( stream ) );
				setofLength -= 2;
				setEndEOC = 2;		/* Two bytes of EOC at end of object */
				}
#endif /* 0 */
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* When processing a SET/SEQUENCE with default values for the
			   elements, the result may be a zero-length object, in which
			   case we don't take any action */
			if( setofLength > 0 )
				{
				const CRYPT_ATTRIBUTE_TYPE oldSubtypeParent = \
												setofInfoPtr->subtypeParent;
				const int oldInheritedFlags = setofInfoPtr->inheritedFlags;

				/* Remember where the SET/SEQUENCE ends.  In addition if
				   this is a SET OF/SEQUENCE OF, remember this as a restart
				   point for when we're parsing the next item in the
				   SET/SEQUENCE OF */
				setofInfoPtr = stackSetofState( setofStack, &setofStackPos );
				setofInfoPtr->infoStart = attributeInfoPtr;
				if( attributeInfoPtr->flags & FL_SETOF )
					setofInfoPtr->restartPoint = TRUE;
				setofInfoPtr->subtypeParent = oldSubtypeParent;
				setofInfoPtr->inheritedFlags = oldInheritedFlags;
				setofInfoPtr->endPos = stell( stream ) + setofLength - \
														 setEndEOC;
#if 0		/* 22/11/03 Removed since these Verisign certs have now expired */
				setofInfoPtr->endEOC = setEndEOC ? TRUE : FALSE;
#endif /* 0 */
				}

			goto continueDecoding;
			}

		/* We've checked the tag, skip it.  We do this at this level rather
		   than in readAttributeField() because it doesn't know about 
		   context-specific tagging requirements */
		readTag( stream );

		/* Standard field, read the field data */
		status = readAttributeField( stream, attributeListPtrPtr,
									 attributeInfoPtr,
									 setofInfoPtr->subtypeParent,
									 flags | setofInfoPtr->inheritedFlags,
									 errorLocus, errorType );
		if( cryptStatusError( status ) )
			/* Adding invalid attribute data can return detailed error codes
			   that report the exact parameter that was wrong, we don't
			   need this much detail so we convert a parameter error into a
			   more general bad data status */
			return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );

		/* Move on to the next field */
continueDecoding:
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeInfoPtr++;

		/* If this is the end of the attribute encoding info but we're
		   inside a SET OF and there's more attribute data present, go
		   back to the restart point and try again */
		if( !attributeContinues && setofInfoPtr->endPos > 0 && \
			stell( stream ) < setofInfoPtr->endPos )
			{
			assert( setofInfoPtr->restartPoint || \
					setofInfoPtr->infoStart[ 1 ].fieldType == FIELDTYPE_IDENTIFIER );
			attributeInfoPtr = setofInfoPtr->infoStart + 1;
			attributeContinues = TRUE;
			}
		}
	while( ( attributeContinues || setofStackPos > 1 ) && \
		   stell( stream ) < endPos );

	/* Handle the special case of (a) the encoded data ending but fields with
	   default values being present, or (b) the encoded data continuing but
	   no more decoding information being present */
	if( attributeContinues )
		{
		/* If there are default fields to follow, add the default value - see
		   the comment on the handling of default fields above.  For now we
		   only add the first field since the only attributes where this
		   case can occur have a single default value as the next possible
		   entry, burrowing down further causes complications due to default
		   values present in optional sequences.  As usual, we don't set any
		   specific error information for the default fields */
		if( attributeInfoPtr->flags & FL_DEFAULT )
			{
			const int value = ( int ) attributeInfoPtr->defaultValue;

			status = addAttributeField( attributeListPtrPtr,
						attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
						&value, CRYPT_UNUSED, flags, NULL, NULL );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	else
		/* Some attributes have a SEQUENCE OF fields of no great use (e.g.
		   Microsoft's extensive crlDistributionPoints lists providing
		   redundant pointers to the same inaccessible site-internal
		   servers, although these are already handled above), if there's
		   any extraneous data left we just skip it */
		while( stell( stream ) < endPos && cryptStatusOK( status ) && \
			   peekTag( stream ) )
			{
			assert( NOTREACHED );
			status = readUniversal( stream );
			}

#if 0	/* 22/11/03 Removed since these Verisign certs have now expired */
	/* More Verisign braindamage: There may be arbitrary levels of EOC's
	   at the end of an attribute, so we sit in a loop skipping them.
	   Eventually we'll run into the SEQUENCE for the signature
	   AlgorithmIdentifier that always follows attributes in certs, cert
	   requests, and CMS attributes.  Per varios casus... */
	while( cryptStatusOK( status ) && peekTag( stream ) == BER_EOC )
		{
		status = checkEOC( stream );
		if( status == TRUE )
			/* checkEOC returns TRUE/FALSE for EOC */
			status = CRYPT_OK;
		}
#endif /* 0 */

	return( status );
	}

/* Read a set of attributes */

int readAttributes( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
					const CRYPT_CERTTYPE_TYPE type, const int attributeSize,
					CRYPT_ATTRIBUTE_TYPE *errorLocus,
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES || \
										   type == CRYPT_CERTTYPE_RTCS_REQUEST || \
										   type == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? \
										 ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const BOOLEAN wrapperTagSet = ( attributeType == ATTRIBUTE_CMS ) ? \
								  TRUE : FALSE;
	int length, endPos, complianceLevel, status;

	/* Many certificates are invalid but are accepted by existing software
	   that does little or no checking.  In order to be able to process
	   these certs, the user can disable various levels of processing in
	   order to be able to handle the cert */
	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the appropriate extensions tag for the certificate object and
	   determine how far we can read.  CRLs and OCSP requests/responses have
	   two extension types that have different tagging, per-entry extensions
	   and entire-CRL/request extensions.  To differentiate between the two,
	   we read per-entry extensions with a type of CRYPT_CERTTYPE_NONE */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			readConstructed( stream, NULL, CTAG_CE_EXTENSIONS );
			status = readSequence( stream, &length );
			break;

		case CRYPT_CERTTYPE_CRL:
			readConstructed( stream, NULL, CTAG_CL_EXTENSIONS );
			status = readSequence( stream, &length );
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_PKIUSER:
		case CRYPT_CERTTYPE_NONE:
			/* Any outer wrapper for per-entry CRL/OCSP extensions has
			   already been read by the caller so there's only the inner
			   SEQUENCE left to read */
			status = readSequence( stream, &length );
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			/* The read of cert request extensions isn't as simple as it
			   should be because alongside their incompatible request
			   extension OID, Microsoft also invented other values
			   containing God knows what sort of data (long Unicode strings
			   describing the Windows module that created it (as if you'd
			   need that to know where it came from), the scripts from
			   "Gilligan's Island", every "Brady Bunch" episode ever made,
			   dust from under somebody's bed from the 1930s, etc).
			   Because of this, the following code skips over unknown
			   garbage until it finds a valid extension.

			   Unfortunately this simple solution is complicated by the fact
			   that SET also defines non-CMMF-style attributes, however
			   unlike MS's stuff these are documented and stable, so if we
			   find SET-style attributes (or more generally any attributes
			   that we know about) we process them normally.  Finally, since
			   all attributes may be either skipped or processed at this
			   stage, we include provisions for bailing out if we exhaust
			   the available attributes */
			endPos = stell( stream ) + attributeSize;
			while( sStatusOK( stream ) )
				{
				const ATTRIBUTE_INFO *attributeInfoPtr;
				BYTE oid[ MAX_OID_SIZE ];
				int oidLength;

				/* If we've run out of attributes without finding anything
				   useful, exit */
				if( stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
					return( CRYPT_OK );

				/* Read the wrapper SEQUENCE and OID */
				readSequence( stream, NULL );
				status = readRawObject( stream, oid, &oidLength,
										MAX_OID_SIZE, BER_OBJECT_IDENTIFIER );
				if( cryptStatusError( status ) )
					return( status );

				/* Check for a known attribute, which can happen with SET
				   cert requests.  If it's a known attribute, process it */
				attributeInfoPtr = oidToAttribute( attributeType, oid );
				if( attributeInfoPtr != NULL )
					{
					status = readSet( stream, &length );
					if( cryptStatusOK( status ) )
						status = readAttribute( stream, attributeListPtrPtr,
												attributeInfoPtr, length,
												FALSE, errorLocus, errorType );
					if( cryptStatusError( status ) )
						return( status );
					}
				else
					/* It's not a known attribute, check whether it's a CMMF
					   or MS wrapper attribute */
					if( !memcmp( oid, OID_PKCS9_EXTREQ, oidLength ) || \
						!memcmp( oid, OID_MS_EXTREQ, oidLength ) )
						break;
					else
						/* It's unknown MS garbage, skip it */
						readUniversal( stream );
				}
			readSet( stream, NULL );
			status = readSequence( stream, &length );
			break;

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
			status = readConstructed( stream, &length,
									  CTAG_SI_AUTHENTICATEDATTRIBUTES );
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* CRMF/CMP attributes don't contain any wrapper so there's
			   nothing to read */
			length = attributeSize;
			status = CRYPT_OK;
			break;

		case CRYPT_CERTTYPE_RTCS_REQUEST:
			status = readSet( stream, &length );
			break;

		case CRYPT_CERTTYPE_RTCS_RESPONSE:
			status = readConstructed( stream, &length, CTAG_RP_EXTENSIONS );
			break;

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			readConstructed( stream, &length, CTAG_OR_EXTENSIONS );
			status = readSequence( stream, &length );
			break;

		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			readConstructed( stream, &length, CTAG_OP_EXTENSIONS );
			status = readSequence( stream, &length );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the collection of attributes.  We allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	while( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		const ATTRIBUTE_INFO *attributeInfoPtr;
		BYTE oid[ MAX_OID_SIZE ];
		BOOLEAN criticalFlag = FALSE, ignoreAttribute = FALSE;
		int attributeLength;

		/* Read the outer wrapper and determine the attribute type based on
		   the OID */
		readSequence( stream, NULL );
		status = readRawObject( stream, oid, &length, MAX_OID_SIZE,
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );
		attributeInfoPtr = oidToAttribute( attributeType, oid );
		if( attributeInfoPtr != NULL && \
			complianceLevel < decodeComplianceLevel( attributeInfoPtr->flags ) )
			{
			/* If we're running at a lower compliance level than that
			   required for the attribute, ignore it by treating it as a
			   blob-type attribute */
			attributeInfoPtr = NULL;
			ignoreAttribute = TRUE;
			}

		/* Read the optional critical flag if it's a certificate.  If the
		   extension is marked critical and we don't recognise it, we don't 
		   reject it at this point because that'd make it impossible to 
		   examine the contents of the cert or display it to the user.  
		   Instead, we reject the cert when we try and check it */
		if( attributeType != ATTRIBUTE_CMS && \
			peekTag( stream ) == BER_BOOLEAN )
			{
			status = readBoolean( stream, &criticalFlag );
			if( cryptStatusError( status ) )
				{
				*errorLocus = ( attributeInfoPtr != NULL ) ? \
							  attributeInfoPtr->fieldID : CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( status );
				}
			}

		/* Read the wrapper around the attribute payload */
		if( wrapperTagSet )
			status = readSet( stream, &attributeLength );
		else
			status = readOctetStringHole( stream, &attributeLength,
										  DEFAULT_TAG );
		if( cryptStatusError( status ) )
			{
			*errorLocus = ( attributeInfoPtr != NULL ) ? \
						  attributeInfoPtr->fieldID : CRYPT_ATTRIBUTE_NONE;
			*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( status );
			}

		/* Thawte certs for a period of about 6 months incorrectly encoded
		   the authorityKeyIdentifier (containing a SHA-1 hash) with an
		   EXPLICIT SEQUENCE so we check for this here.  These were at one
		   time common enough that we provide a special-case workaround
		   rather than using a compliance level reduction as a fix */
		if( attributeInfoPtr != NULL && \
			attributeInfoPtr->fieldID == CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER && \
			attributeLength == 26 )
			{
			BYTE buffer[ 32 ];
			long offset = stell( stream );
			int length2, length3;

			/* Burrow down into the encoding to see if it's an incorrectly
			   encoded authorityKeyIdentifier.  There's a second type of
			   incorrect encoding that still uses an explicit tag but that
			   makes the contents the octet string data, this is rare and
			   isn't checked for here */
			readSequence( stream, &length );
			readConstructed( stream, &length2, 0 );
			status = readOctetString( stream, buffer, &length3, 32 );
			if( cryptStatusOK( status ) && \
				length == 24 && length2 == 22 && length3 == 20 )
				{
				/* It's a SEQUENCE { [0] EXPLICIT SEQUENCE { ..., add the
				   data as a keyIdentifier */
				status = addAttributeField( attributeListPtrPtr,
							CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
							CRYPT_ATTRIBUTE_NONE, buffer, 20,
							criticalFlag ? \
								( ATTR_FLAG_CRITICAL | ATTR_FLAG_BLOB ) : \
								ATTR_FLAG_BLOB, errorLocus, errorType );
				if( cryptStatusError( status ) )
					return( status );
				continue;
				}

			/* It's a correctly-encoded authorityKeyIdentifier, read it
			   normally */
			sClearError( stream );
			sseek( stream, offset );
			}

		/* If it's a known attribute, parse the payload */
		if( attributeInfoPtr != NULL )
			{
			status = readAttribute( stream, attributeListPtrPtr,
									attributeInfoPtr, attributeLength,
									criticalFlag, errorLocus, errorType );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* If it's a zero-length unrecognised attribute, don't add anything.
		   A zero length indicates that the attribute contains all default
		   values, however since we don't recognise the attribute we can't
		   fill these in so the attribute is in effect not present */
		if( attributeLength <= 0 )
			continue;

		/* It's an unrecognised or ignored attribute type, add the raw data
		   to the list of attributes */
		status = addAttribute( attributeType, attributeListPtrPtr, oid,
							   criticalFlag, sMemBufPtr( stream ),
							   attributeLength, ignoreAttribute ? \
									ATTR_FLAG_BLOB | ATTR_FLAG_IGNORED : \
									ATTR_FLAG_NONE );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_INITED )
				{
				/* If there's a duplicate attribute present, set error
				   information for it and flag it as a bad data error.  We
				   can't set an error locus since it's an unknown blob */
				*errorLocus = CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				status = CRYPT_ERROR_BADDATA;
				}
			return( status );
			}
		sSkip( stream, attributeLength );	/* Skip the attribute data */
		}

	return( CRYPT_OK );
	}
