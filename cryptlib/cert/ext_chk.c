/****************************************************************************
*																			*
*					Certificate Attribute Checking Routines					*
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

/****************************************************************************
*																			*
*							Attribute Field Type Checking					*
*																			*
****************************************************************************/

/* Validate and preprocess a set of attributes in preparation for writing
   them to a certificate or CRL and set up links to the information in the
   attribute information table prior to encoding the attributes.  This is a
   rather complex process that relies on stepping through the list of
   attribute fields and the attribute information table in sync and making
   sure the list of fields is consistent with the attribute information
   table.  In addition we set up sync points between the list and table that
   are used during the encoding process.  For example assume we have the
   following attribute:

	attribute ::= SEQUENCE {
		foo		BOOLEAN DEFAULT TRUE,
		bar		SEQUENCE OF OBJECT IDENTIFIER
		}

   The attribute information table would encode this attribute as:

	t1:	OID	SEQUENCE	MORE
	t2:		BOOLEAN		MORE	OPTIONAL
	t3:		SEQUENCE	MORE
	t4:		OID

   The first table entry t1 contains the OID, the SEQUENCE wrapper, and a
   continuation flag.  For the purposes of comparison with the list, this is
   a nop and can be skipped since it's only used for encoding purposes.  The
   next table entry t2 contains the first attribute field, an optional
   boolean and a continuation flag.  The next table entry t3 contains another
   SEQUENCE wrapper that again is only used for encoding and can be skipped
   for comparing with the list, and a continuation flag.  Finally, the last
   table entry t4 contains the second attribute field, an OID.

   Assuming the attribute list contains the following:

	BOOLEAN	FALSE	-> t1
	OID		xxx		-> t3

   The attribute validation process sets the sync point for the first
   attribute list entry to point to t1, and the second one to point to t3.
   When we encode the attribute, we encode t1 (the OID, critical flag, and
   SEQUENCE wrapper), since the field IDs won't match we step to t2 and use
   that to encode the boolean.  We then do the same for t3 with the SEQUENCE
   and OID.

   If the attribute list instead contained only:

	OID		xxx		-> t1

   then this time the attribute validation process sets the sync point to t1.
   When encoding we encode t1 as before, step to t2, the field IDs won't
   match but t2 is optional so we skip it, then encode t3 as for t1 and
   finally encode the OID using t4.

   At this point we also evaluate the encoded size of each attribute.  For
   invidual fields, we just store their encoded size.  For constructed
   objects, we stack the attribute list entry where the constructed object
   starts and, until we reach the end of the constructed object, accumulate
   the total size of the fields that make up the object.  When we reach the
   end of the object, we unstack the pointer to the attribute list and store
   the total size in it.

   To handle nested constructed objects, we only update the size of the
   topmost item on the stack.  When this is unstacked, we add the size of
   that entry, plus the size of its tag and length information, to the next
   entry on the stack.

   In addition to updating the size, we also record the sequence of table
   entries that are required to encode the constructed item.  A worst-case
   sequence of entries would be:

	SEQUENCE {
		SEQUENCE OPTIONAL { ... }		| Not encoded
		SEQUENCE {
			SEQUENCE OPTIONAL { ... }	| Not encoded
			SEQUENCE {
				value
				}
			}
		}

   which contains an alternating sequence of encoded and non-encoded fields.
   Because of this, the validation check performs the complex task of
   recording which table entries are used for the encoding by stacking and
   unstacking them and discarding the ones that evaluate to a zero size
   during the unstacking process.

   Each entry in the stack contains the list item it applies to, the table
   entry which is used to encode the stacked item, and the size of the item */

#define ATTRIBUTE_STACKSIZE		10

typedef struct {
	ATTRIBUTE_LIST *attributeListPtr;	/* List entry that this applies to */
	ATTRIBUTE_INFO *attributeInfoPtr;	/* Encoding point for sequence */
	int size;							/* Size of sequence */
	} ATTRIBUTE_STACK;

/* Once we reach the end of the constructed item, we need to unwind the stack
   and update everything we've gone past.  If it's an optional item (so that
   nothing gets encoded), we don't do anything.  The count argument specifies
   the level of unwinding to perform, this can be relative (in which case we
   undo 'count' levels of nesting, which may be more than count stack
   positions if non-nested data was stacked) or absolute (in which case we
   undo 'count' stack positions */

static void updateStackedInfo( ATTRIBUTE_STACK *stack, int *stackPosPtr,
							   int count, const BOOLEAN isRelative )
	{
	int stackPos = *stackPosPtr;

	assert( isWritePtr( stack, sizeof( ATTRIBUTE_STACK ) ) );
	assert( isWritePtr( stackPosPtr, sizeof( int ) ) );
	assert( count <= stackPos );

	while( count-- )
		{
		ATTRIBUTE_LIST *attributeFifoPtr = stack[ --stackPos ].attributeListPtr;
		const ATTRIBUTE_INFO *attributeInfoPtr = stack[ stackPos ].attributeInfoPtr;
		const int size = stack[ stackPos ].size;

		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
		assert( size >= 0 );
		assert( count >= 0 );
		assert( stackPos >= 0 );

		/* Safety check in case of an invalid encoding table */
		if( count < 0 || stackPos < 0 )
			{
			assert( NOTREACHED );
			return;
			}

		/* If there's nothing to encode, continue.  There are a few special
		   cases here where even if the sequence is of zero length, we may
		   have to encode something.  Firstly, if there's a member with a
		   default value present (resulting in nothing being encoded) we still
		   have to encode a zero-length sequence.  In addition if all of the
		   members have non-encoding values (e.g. OIDs and fixed attributes,
		   none of which are specified by the user) we have to encode these
		   even though there's no actual value associated with them since
		   their mere presence conveys the necessary information.

		   In addition sometimes we can reach the end of the attribute list
		   but there are further actions defined in the encoding table (for
		   example cleanup actions in nested sequences).  In this case the
		   stacked attributeFifoPtr is NULL and the size is zero, so we
		   perform an additional check to make sure that the pointer is non-
		   null */
		if( !( size || ( attributeFifoPtr != NULL && \
						 ( ( attributeFifoPtr->flags & ATTR_FLAG_DEFAULTVALUE ) || \
						   ( attributeInfoPtr->flags & FL_NONENCODING ) ) ) ) )
			continue;

		assert( isWritePtr( attributeFifoPtr, sizeof( ATTRIBUTE_LIST ) ) );

		/* Remember the size and table entry used to encode this stack entry */
		attributeFifoPtr->sizeFifo[ attributeFifoPtr->fifoEnd ] = size;
		attributeFifoPtr->encodingFifo[ attributeFifoPtr->fifoEnd++ ] = \
										stack[ stackPos ].attributeInfoPtr;

		/* If there are no further items on the stack, continue */
		if( stackPos <= 0 )
			continue;

		/* If it's a non-constructed field, add the length of the existing and
		   new fields */
		if( attributeInfoPtr->fieldType != BER_SEQUENCE && \
			attributeInfoPtr->fieldType != BER_SET )
			{
			const int newLength = \
					( attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER ) ? \
					sizeofOID( attributeInfoPtr->oid ) : \
					( int ) attributeInfoPtr->defaultValue;

			/* Add the new length to the existing data size.  Since this is a
			   non-constructed field, it doesn't count as a reduction in the
			   nesting level, so if we're unnesting by a relative amount we
			   adjust the nesting count to give a net change of zero for this
			   item */
			stack[ stackPos - 1 ].size += size + newLength;
			if( isRelative )
				count++;
			}
		else
			/* It's a constructed field, percolate the encapsulated content
			   size up the stack */
			stack[ stackPos - 1 ].size += ( int ) sizeofObject( size );
		}

	*stackPosPtr = stackPos;
	}

/* Some attributes contain a sequence of items of the attributeTypeAndValue
   form (i.e. OID, ANY DEFINED BY OID).  To process these, a check is made to
   determine whether the named value component in the attribute list is
   present in the current attributeTypeAndValue definition.  If it isn't, the
   item is given a zero length, which means that it's never encoded since the 
   field is marked as optional.  The following function checks whether a 
   named value component is present in the item */

static BOOLEAN checkComponentPresent( const CRYPT_ATTRIBUTE_TYPE fieldID,
									  ATTRIBUTE_INFO **attributeInfoPtrPtr )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
	int nestLevel = 0;

	assert( isWritePtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	/* Check each field we find until we find the end of the
	   attributeTypeAndValue */
	while( TRUE )
		{
		/* Sanity check to make sure we don't fall off the end of the 
		   table */
		if( attributeInfoPtr->fieldID == CRYPT_ERROR )
			{
			assert( NOTREACHED );
			return( FALSE );
			}

		/* Adjust the nesting level depending on whether we're entering or
		   leaving a sequence */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE )
			nestLevel++;
		nestLevel -= decodeNestingLevel( attributeInfoPtr->flags );

		/* If the field is present in this attributeTypeAndValue, return */
		if( attributeInfoPtr->fieldID == fieldID )
			return( TRUE );

		/* If we're at the end of the attribute or the attributeTypeAndValue,
		   exit the loop before adjusting the attributeInfoPtr so that we're
		   still pointing at the end-of-attribute field */
		if( nestLevel <= 0 || !( attributeInfoPtr->flags & FL_MORE ) )
			break;

		attributeInfoPtr++;
		}

	/* The field isn't present, update the pointer to the next
	   attributeTypeAndValue or the end of the attribute */
	*attributeInfoPtrPtr = ( ATTRIBUTE_INFO * ) attributeInfoPtr;
	return( FALSE );
	}

/* State machine for checking a CHOICE.  When we get to the start of a
   CHOICE, we move from CHOICE_NONE to CHOICE_START.  Once we've checked one
   of the CHOICE options, we move to CHOICE_DONE.  If a further option is
   found in the CHOICE_DONE state, we record an error.  This is a somewhat
   crude mechanism that works because the only CHOICE fields that can't be
   handled by rewriting them as alternative representations are complete
   attributes so that the CHOICE applies over the entire attribute.  If a
   CHOICE is ever present as an attribute subfield, the checking would be
   handled by recursively checking it as a subtyped field */

typedef enum { CHOICE_NONE, CHOICE_START, CHOICE_DONE } CHOICE_STATE;

/* Check an entry in the attribute table.  While we're performing the check
   we need to pass a lot of state information around, this is contained in
   the following structure */

typedef struct {
	/* State information.  When we're encoding a subtyped field (using an
	   alternative encoding table), we need to remember the field ID of the
	   parent to both tell the encoding routines that we're using an
	   alternative encoding table, and to remember the overall field ID so we
	   don't treat two adjacent field subfields as though they were part of
	   the same parent field.  If we're not currently encoding a subtyped
	   field, this field is set to CRYPT_ATTRIBUTE_NONE */
	ATTRIBUTE_LIST *attributeListPtr;	/* Position in attribute list */
	ATTRIBUTE_INFO *attributeInfoPtr;	/* Position in attribute table */
	CRYPT_ATTRIBUTE_TYPE subtypeParent;	/* Parent of subtype being processed */
	CHOICE_STATE choiceState;			/* State of CHOICE processing */

	/* Encoding stack.  When we're encoding subfields, the stack contains
	   items from both the subfield and the encapsulating field, so we also
	   record the current stack top to make sure that we don't go past this 
	   level when popping items after we've finished encoding a subfield */
	ATTRIBUTE_STACK stack[ ATTRIBUTE_STACKSIZE ];
	int stackPos;					/* Encoding stack position */
	int stackTop;

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	int errorType;					/* Error type */
	} ATTRIBUTE_CHECK_INFO;

static int stackInfo( ATTRIBUTE_CHECK_INFO *attributeCheckInfo,
					  ATTRIBUTE_LIST *attributeListPtr,
					  ATTRIBUTE_INFO *attributeInfoPtr )
	{
	ATTRIBUTE_STACK *stack = attributeCheckInfo->stack;

	if( attributeCheckInfo->stackPos >= ATTRIBUTE_STACKSIZE - 1 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}
	stack[ attributeCheckInfo->stackPos ].size = 0;
	stack[ attributeCheckInfo->stackPos ].attributeListPtr = attributeListPtr;
	stack[ attributeCheckInfo->stackPos++ ].attributeInfoPtr = attributeInfoPtr;

	return( CRYPT_OK );
	}

static int checkAttribute( ATTRIBUTE_CHECK_INFO *attributeCheckInfo );	/* Fwd.dec for fn.*/

static int checkAttributeEntry( ATTRIBUTE_CHECK_INFO *attributeCheckInfo )
	{
	ATTRIBUTE_LIST *attributeListPtr = attributeCheckInfo->attributeListPtr;
	ATTRIBUTE_INFO *attributeInfoPtr = attributeCheckInfo->attributeInfoPtr;
	ATTRIBUTE_STACK *stack = attributeCheckInfo->stack;
	CRYPT_ATTRIBUTE_TYPE fieldID;

	assert( isWritePtr( attributeCheckInfo, sizeof( ATTRIBUTE_CHECK_INFO ) ) );

	/* Determine the fieldID for the current attribute field */
	if( attributeListPtr == NULL || attributeListPtr->fieldID == CRYPT_ATTRIBUTE_NONE )
		/* If we've reached the end of the list of recognised attributes, 
		   use a non-ID that doesn't match any table entry */
		fieldID = CRYPT_UNUSED;
	else
		/* If we're encoding a subtyped field, the fieldID is the field ID
		   within the parent field, or the subFieldID */
		if( attributeCheckInfo->subtypeParent == attributeListPtr->fieldID )
			fieldID = attributeListPtr->subFieldID;
		else
			/* It's a standard attribute field */
			fieldID = attributeListPtr->fieldID;

	/* If the field in the attribute list matches the one in the table,
	   process it and move on to the next one */
	if( attributeListPtr != NULL && attributeInfoPtr->fieldID == fieldID )
		{
		/* If it's a subtyped or CHOICE field, check the components using
		   their own encoding table */
		if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED || \
			attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
			{
			int status;

			/* Switch to the new encoding table and record the fact that
			   we've done this, and set the new stack top to the level at
			   which we start encoding the subtype */
			if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
				{
				/* Stack the value start position in the attribute list and
				   record the fact that we're processing a CHOICE */
				status = stackInfo( attributeCheckInfo, attributeListPtr,
									attributeInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				attributeCheckInfo->choiceState = CHOICE_START;
				}
			attributeCheckInfo->attributeInfoPtr = \
							( ATTRIBUTE_INFO * ) attributeInfoPtr->extraData;
			attributeCheckInfo->subtypeParent = attributeListPtr->fieldID;
			attributeCheckInfo->stackTop = attributeCheckInfo->stackPos;
			status = checkAttribute( attributeCheckInfo );
			attributeCheckInfo->attributeInfoPtr = attributeInfoPtr;
			attributeCheckInfo->subtypeParent = CRYPT_ATTRIBUTE_NONE;
			attributeCheckInfo->stackTop = 0;
			if( !( attributeInfoPtr->flags & FL_OPTIONAL ) && \
				attributeCheckInfo->attributeListPtr == attributeListPtr )
				{
				/* The subtyped field was non-optional but we failed to match
				   anything in it against the current attribute list entry, 
				   there's a problem with the encoding table.  This check is 
				   used to catch situations where a subtyped field is used to
				   encode a CHOICE, where each CHOICE field is optional but 
				   at least one component of the CHOICE must be present */
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			return( status );
			}

		/* If there's an extended validation function attached to this field,
		   call it */
		if( attributeInfoPtr->extraData != NULL )
			{
			VALIDATION_FUNCTION validationFunction = \
						( VALIDATION_FUNCTION ) attributeInfoPtr->extraData;

			attributeCheckInfo->errorType = validationFunction( attributeListPtr );
			if( attributeCheckInfo->errorType != CRYPT_OK )
				return( CRYPT_ERROR_INVALID );
			}

		/* If this is an optional field and the value is the same as the
		   default value, remember that it doesn't get encoded */
		if( ( attributeInfoPtr->flags & FL_DEFAULT ) && \
			( attributeInfoPtr->defaultValue == attributeListPtr->intValue ) )
			{
			attributeListPtr->flags |= ATTR_FLAG_DEFAULTVALUE;
			attributeCheckInfo->attributeListPtr = attributeListPtr->next;
			return( CRYPT_OK );
			}

		/* Remember the encoded size of this field */
		attributeListPtr->attributeInfoPtr = attributeInfoPtr;
		attributeListPtr->encodedSize = writeAttributeField( NULL, attributeListPtr );
		if( attributeCheckInfo->stackPos )
			stack[ attributeCheckInfo->stackPos - 1 ].size += attributeListPtr->encodedSize;

		/* If this is a CHOICE field, update the choice state */
		if( attributeCheckInfo->choiceState != CHOICE_NONE )
			{
			if( attributeCheckInfo->choiceState == CHOICE_DONE )
				{
				/* If we've already processed one of the CHOICE options, there
				   can't be another one present */
				attributeCheckInfo->errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				return( CRYPT_ERROR_INVALID );
				}
			if( attributeCheckInfo->choiceState == CHOICE_START )
				/* Remember that we've seen a CHOICE option */
				attributeCheckInfo->choiceState = CHOICE_DONE;
			}

		/* Move on to the next attribute field */
		attributeCheckInfo->attributeListPtr = attributeListPtr->next;
		return( CRYPT_OK );
		}

	/* If it's an attributeTypeAndValue sequence, check whether it contains
	   the field we want */
	if( attributeInfoPtr->flags & FL_IDENTIFIER )
		{
		BOOLEAN endOfAttributeField = FALSE;
		int status;

		if( !checkComponentPresent( fieldID, &attributeInfoPtr ) )
			{
			/* Since we've jumped over several items we may be pointing at an
			   end-of-sequence flag for which no sequence start was stacked,
			   so we skip the stack update step */
			attributeCheckInfo->attributeInfoPtr = attributeInfoPtr;
			return( OK_SPECIAL );
			}

		/* Stack the position of the sequence start and the following OID */
		status = stackInfo( attributeCheckInfo, attributeListPtr, 
							attributeInfoPtr++ );
		if( cryptStatusOK( status ) )
			status = stackInfo( attributeCheckInfo, attributeListPtr, 
								attributeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* If the OID entry is marked as the end-of-sequence, there are no
		   parameters attached so we move on to the next entry */
		if( attributeInfoPtr->flags & FL_SEQEND_MASK )
			endOfAttributeField = TRUE;

		/* Sometimes the OID is followed by a fixed-value blob field that
		   constitutes parameters for the OID, if this is present we stack it
		   as well */
		if( attributeInfoPtr[ 1 ].flags & FL_NONENCODING )
			{
			attributeInfoPtr++;
			status = stackInfo( attributeCheckInfo, attributeListPtr, 
								attributeInfoPtr );
			if( cryptStatusError( status ) )
				return( status );

			/* If the fields are fixed-value, we always move on to the next
			   entry since there are no user-supplied parameters present */
			endOfAttributeField = TRUE;
			}

		attributeCheckInfo->attributeInfoPtr = attributeInfoPtr;
		if( endOfAttributeField )
			/* If this is all that needs to be encoded, move on to the next
			   attribute field */
			attributeCheckInfo->attributeListPtr = attributeListPtr->next;
		return( CRYPT_OK );
		}

	/* If it's a sequence/set or a non-encoding value then it's a nop entry
	   used only for encoding purposes and can be skipped, however we need to
	   remember it for later encoding */
	if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
		attributeInfoPtr->fieldType == BER_SET || \
		attributeInfoPtr->flags & FL_NONENCODING )
		/* Stack the sequence or value start position in the attribute list */
		return( stackInfo( attributeCheckInfo, attributeListPtr, 
						   attributeInfoPtr ) );

	/* If it's a non-optional field and the attribute field doesn't match,
	   it's an error - attribute attributeID is missing field
	   attributeInfoPtr->fieldID (optional subfield
	   attributeInfoPtr->subFieldID) (set by the error handler in the calling
	   code) */
	if( !( attributeInfoPtr->flags & FL_OPTIONAL ) )
		{
		attributeCheckInfo->errorType = CRYPT_ERRTYPE_ATTR_ABSENT;
		return( CRYPT_ERROR_NOTINITED );
		}

	return( CRYPT_OK );
	}

/* Check an individual attribute */

static int checkAttribute( ATTRIBUTE_CHECK_INFO *attributeCheckInfo )
	{
	ATTRIBUTE_LIST *restartEntry = NULL;
	ATTRIBUTE_INFO *restartPoint;
	int restartStackPos, iterationCount = 0;
	BOOLEAN attributeContinues;

	assert( isWritePtr( attributeCheckInfo, sizeof( ATTRIBUTE_CHECK_INFO ) ) );

	/* Step through the attribute comparing the fields that are present in
	   the attribute list with the fields that should be present according
	   to the table, and set encoding sync points as required */
	do
		{
		int status;

		/* Sanity check to make sure we don't fall off the end of the 
		   table */
		if( attributeCheckInfo->attributeInfoPtr->fieldID == CRYPT_ERROR )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_OVERFLOW );
			}

		/* Check whether this is a repeated instance of the same attribute
		   and if it is, remember the encoding restart point.  We have to do
		   this before we check the attribute info because it usually
		   updates the info after the check */
		if( restartEntry == NULL && \
			attributeCheckInfo->attributeListPtr != NULL && \
			attributeCheckInfo->attributeListPtr->next != NULL && \
			( attributeCheckInfo->attributeListPtr->fieldID == \
			  attributeCheckInfo->attributeListPtr->next->fieldID ) && \
			( attributeCheckInfo->attributeListPtr->subFieldID == \
			  attributeCheckInfo->attributeListPtr->next->subFieldID ) )
			{
			restartEntry = attributeCheckInfo->attributeListPtr;
			restartPoint = attributeCheckInfo->attributeInfoPtr + 1;
			restartStackPos = attributeCheckInfo->stackPos + 1;
			}

		/* Check the current encoding table entry */
		status = checkAttributeEntry( attributeCheckInfo );
		if( status != OK_SPECIAL )
			{
			if( cryptStatusError( status ) )
				{
				attributeCheckInfo->errorLocus = attributeCheckInfo->attributeInfoPtr->fieldID;
				return( status );
				}

			/* If this is the end of a constructed item, unstack it and
			   update the attribute list entry with the length information.
			   If it's a sequence with all fields optional (so that nothing
			   gets encoded), we don't do anything */
			updateStackedInfo( attributeCheckInfo->stack,
				&attributeCheckInfo->stackPos,
				decodeNestingLevel( attributeCheckInfo->attributeInfoPtr->flags ),
				TRUE );
			}

		/* If there's another instance of the same item, don't move on to
		   the next table entry */
		if( restartEntry != NULL && \
			restartEntry != attributeCheckInfo->attributeListPtr )
			{
#if 0
			/* Currently we don't allow the creation of multivalued
			   instances of fields, although we can read certs that contain
			   them */
			assert( NOTREACHED );
#endif /* 0 */

			/* Restart at the table entry for the previous instance of the 
			   item, and adjust the stack to match */
			restartEntry = NULL;
			attributeCheckInfo->attributeInfoPtr = restartPoint;
			attributeContinues = TRUE;
			if( attributeCheckInfo->stackPos > restartStackPos )
				updateStackedInfo( attributeCheckInfo->stack,
							&attributeCheckInfo->stackPos,
							attributeCheckInfo->stackPos - restartStackPos,
							TRUE );

			continue;
			}

		/* Move on to the next table entry.  We have to check the
		   continuation flag before we move to the next table entry in order
		   to include processing of the last field in an attribute */
		attributeContinues = ( attributeCheckInfo->attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeCheckInfo->attributeInfoPtr++;
		}
	while( attributeContinues && iterationCount++ < 1000 );
	attributeCheckInfo->choiceState = CHOICE_NONE;

	/* Safety check in case of an invalid encoding table */
	if( iterationCount >= 1000 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );
		}
	
	/* We've reached the end of the attribute, if there are still constructed
	   objects stacked, unstack them and update their length information.  If
	   it's a sequence with all fields optional (so that nothing gets
	   encoded), we don't do anything */
	updateStackedInfo( attributeCheckInfo->stack, &attributeCheckInfo->stackPos,
					   attributeCheckInfo->stackPos - attributeCheckInfo->stackTop,
					   FALSE );

	return( CRYPT_OK );
	}

/* Check the entire list of attributes */

int checkAttributes( const ATTRIBUTE_TYPE attributeType,
					 const ATTRIBUTE_LIST *listHeadPtr,
					 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					 CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_CHECK_INFO attributeCheckInfo;
	const ATTRIBUTE_INFO *attributeInfoStartPtr = \
							selectAttributeInfo( attributeType );
	ATTRIBUTE_LIST *attributeListPtr;

	/* If we've already done a validation pass, some of the fields will
	   contain values that were previously set, so before we begin we walk
	   down the list resetting the fields that are updated by this
	   function */
	for( attributeListPtr = ( ATTRIBUTE_LIST * ) listHeadPtr;
		 isValidAttributeField( attributeListPtr );
		 attributeListPtr = attributeListPtr->next )
		{
		if( isValidAttributeField( attributeListPtr->next ) && \
			attributeListPtr->attributeID > \
						attributeListPtr->next->attributeID )
			{
			/* Safety check in case of an invalid attribute list */
			assert( NOTREACHED );
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr->attributeInfoPtr = NULL;
		attributeListPtr->encodedSize = attributeListPtr->fifoPos = \
			attributeListPtr->fifoEnd = 0;
		attributeListPtr->flags &= ~ATTR_FLAG_DEFAULTVALUE;
		}

	/* Set up the attribute-checking state information */
	memset( &attributeCheckInfo, 0, sizeof( ATTRIBUTE_CHECK_INFO ) );
	attributeCheckInfo.attributeListPtr = ( ATTRIBUTE_LIST * ) listHeadPtr;
	attributeCheckInfo.attributeInfoPtr = ( ATTRIBUTE_INFO * ) attributeInfoStartPtr;

	/* Walk down the list of known attributes checking each one for
	   consistency */
	while( attributeCheckInfo.attributeListPtr != NULL && \
		   attributeCheckInfo.attributeListPtr->fieldID != CRYPT_ATTRIBUTE_NONE )
		{
		int status;

		/* Find the start of this attribute in the attribute info table and
		   remember it as an encoding sync point.  Comparing the field ID
		   with the attribute ID is usually valid because the attribute info
		   table always begins the series of entries for an attribute with
		   the attribute ID.  The one exception is where the attribute ID is
		   the same as the field ID but they're separate entries in the
		   table, in which case the first entries will contain a
		   FIELDID_FOLLOWS code to indicate that a following field contains
		   the attribute/fieldID */
		while( ( attributeCheckInfo.attributeInfoPtr->fieldID != \
				 attributeCheckInfo.attributeListPtr->attributeID ) && \
			   attributeCheckInfo.attributeInfoPtr->fieldID != CRYPT_ERROR )
			attributeCheckInfo.attributeInfoPtr++;
		if( attributeCheckInfo.attributeInfoPtr->fieldID == CRYPT_ERROR )
			{
			/* Safety check in case of an invalid encoding table */
			assert( NOTREACHED );
			return( CRYPT_ERROR_OVERFLOW );
			}
		while( attributeCheckInfo.attributeInfoPtr != attributeInfoStartPtr && \
			   attributeCheckInfo.attributeInfoPtr[ -1 ].fieldID == FIELDID_FOLLOWS )
			attributeCheckInfo.attributeInfoPtr--;

		/* Check this attribute */
		status = checkAttribute( &attributeCheckInfo );
		if( cryptStatusError( status ) )
			{
			*errorLocus = attributeCheckInfo.errorLocus;
			*errorType = attributeCheckInfo.errorType;
			return( status );
			}
		}

	return( CRYPT_OK );
	}
