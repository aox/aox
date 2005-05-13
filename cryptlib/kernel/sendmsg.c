/****************************************************************************
*																			*
*							Kernel Message Dispatcher						*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* A pointer to the kernel data block */

static KERNEL_DATA *krnlData = NULL;

/* The ACL used to check objects passed as message parameters, in this case
   for cert sign/sig-check messages */

static const FAR_BSS MESSAGE_ACL messageParamACLTbl[] = {
	/* Certs can only be signed by (private-key) PKC contexts */
	{ MESSAGE_CRT_SIGN,
	  { ST_CTX_PKC,
		ST_NONE } },

	/* Signatures can be checked with a raw PKC context or a cert or cert
	   chain.  The object being checked can also be checked against a CRL,
	   against revocation data in a cert store, or against an RTCS or OCSP
	   responder */
	{ MESSAGE_CRT_SIGCHECK,
	  { ST_CTX_PKC | ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL | \
					 ST_KEYSET_DBMS,
		ST_SESS_RTCS | ST_SESS_OCSP } },

	{ MESSAGE_NONE, ST_NONE, ST_NONE }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sometimes a message is explicitly non-routable (i.e. it has to be sent
   directly to the appropriate target object).  The following function checks
   that the target object is one of the required types */

int checkTargetType( const int objectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget = targets >> 8;
	OBJECT_INFO *objectTable = krnlData->objectTable;

	/* Precondition: Source is a valid object, destination(s) are valid
	   target(s) */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget == OBJECT_TYPE_NONE || isValidType( altTarget ) );

	/* Check whether the object matches the required type.  We don't have to
	   check whether the alternative target has a value or not since the
	   object can never be a OBJECT_TYPE_NONE */
	if( !isValidObject( objectHandle ) || \
		( objectTable[ objectHandle ].type != target && \
		  objectTable[ objectHandle ].type != altTarget ) )
		return( CRYPT_ERROR );

	/* Postcondition */
	POST( objectTable[ objectHandle ].type == target || \
		  objectTable[ objectHandle ].type == altTarget );

	return( objectHandle );
	}

/* Find the ACL for a parameter object */

static const MESSAGE_ACL *findParamACL( const MESSAGE_TYPE message )
	{
	int i;

	/* Precondition: It's a message that takes an object parameter */
	PRE( isParamMessage( message ) );

	/* Find the ACL entry for this message type */
	for( i = 0; messageParamACLTbl[ i ].type != MESSAGE_NONE; i++ )
		if( messageParamACLTbl[ i ].type == message )
			return( &messageParamACLTbl[ i ] );

	/* Postcondition: We found a matching ACL entry */
	POST( NOTREACHED );

	/* Return a no-permission ACL in case of error */
	return( &messageParamACLTbl[ i ] );
	}

/* Wait for an object to become available so that we can use it, with a
   timeout for blocked objects.  This is an internal function which is used
   when mapping an object handle to object data, and is never called
   directly.  As an aid in identifying objects acting as bottlenecks, we
   provide a function to warn about excessive waiting, along with information
   on the object that was waited on, in debug mode.  A wait count threshold
   of 100 is generally high enough to avoid false positives caused by (for
   example) network subsystem delays */

#define MAX_WAITCOUNT				10000
#define WAITCOUNT_WARN_THRESHOLD	100

#ifndef NDEBUG

#include <stdio.h>

static void waitWarn( const int objectHandle, const int waitCount )
	{
	static const char *objectTypeNames[] = {
		"None", "Context", "Keyset", "Envelope", "Certificate", "Device",
		"Session", "User", "None", "None"
		};
	const OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];
	char buffer[ 128 ];

	if( objectHandle == SYSTEM_OBJECT_HANDLE )
		strcpy( buffer, "system object" );
	else
		if( objectHandle == DEFAULTUSER_OBJECT_HANDLE )
			strcpy( buffer, "default user object" );
		else
			sPrintf( buffer, "object %d (%s, subtype %lX)",
					 objectHandle, objectTypeNames[ objectInfoPtr->type ],
					 objectInfoPtr->subType );
	fprintf( stderr, "\nWarning: Thread %X waited %d iteration%s for %s.\n",
			 THREAD_SELF(), waitCount, ( waitCount == 1 ) ? "" : "s",
			 buffer );
	}
#endif /* Debug mode only */

int waitForObject( const int objectHandle, OBJECT_INFO **objectInfoPtrPtr )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	const unsigned int uniqueID = objectTable[ objectHandle ].uniqueID;
	int waitCount = 0;

	/* Preconditions: The object is in use by another thread */
	PRE( isValidObject( objectHandle ) );
	PRE( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) );

	/* While the object is busy, put the thread to sleep.  This is the
	   optimal portable way to wait on the resource, since it gives up this
	   thread's timeslice to allow other threads (including the one using
	   the object) to run.  Other methods such as mutexes with timers are
	   difficult to manage portably across different platforms */
	while( objectTable[ objectHandle ].uniqueID == uniqueID && \
		   isInUse( objectHandle ) && waitCount < MAX_WAITCOUNT && \
		   !krnlData->isClosingDown )
		{
		MUTEX_UNLOCK( objectTable );
		waitCount++;
		THREAD_YIELD();
		MUTEX_LOCK( objectTable );
		}
#ifndef NDEBUG
	if( waitCount > WAITCOUNT_WARN_THRESHOLD )
		/* If we waited more than WAITCOUNT_WARN_THRESHOLD iterations for
		   something this could be a sign of a resource usage bottleneck
		   (typically caused by users who don't understand threading), warn
		   the user that there's a potential problem */
		waitWarn( objectHandle, waitCount );
#endif /* NDEBUG */

	/* If cryptlib is shutting down, exit */
	if( krnlData->isClosingDown )
		return( CRYPT_ERROR_PERMISSION );

	/* If we timed out waiting for the object, return a timeout error */
	if( waitCount >= MAX_WAITCOUNT )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_TIMEOUT );
		}

	/* Make sure that nothing happened to the object while we were waiting
	   on it */
	if( objectTable[ objectHandle ].uniqueID != uniqueID )
		return( CRYPT_ERROR_SIGNALLED );

	/* Update the object info pointer in case the object table was updated
	   while we had yielded control */
	*objectInfoPtrPtr = &objectTable[ objectHandle ];

	/* Postconditions: The object is available for use */
	POST( isValidObject( objectHandle ) );
	POST( !isInUse( objectHandle ) );

	return( CRYPT_OK );
	}

#if 0	/* 18/2/04 No need for copy-on-write any more since we can just copy
				   across the instance data referenced in the object table */

/* Handle an object that has been cloned and is subject to copy-on-write */

static int handleAliasedObject( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *messageDataPtr,
								const int messageValue )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr =  &objectTable[ objectHandle ];
	CRYPT_CONTEXT originalObject = objectHandle;
	CRYPT_CONTEXT clonedObject = objectInfoPtr->clonedObject;
	int status;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) && \
		 objectHandle >= NO_SYSTEM_OBJECTS );
	PRE( isValidObject( clonedObject ) && \
		 clonedObject >= NO_SYSTEM_OBJECTS );
	PRE( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( objectTable[ clonedObject ].type == OBJECT_TYPE_CONTEXT );
	PRE( objectHandle != clonedObject );
	PRE( isAliasedObject( objectHandle ) && isAliasedObject( clonedObject ) );
	PRE( isClonedObject( objectHandle ) || isClonedObject( clonedObject ) );

	/* If it's a destroy-object message, make sure that the (incomplete)
	   clone is the one that gets destroyed rather than the original */
	if( message == MESSAGE_DESTROY )
		{
		OBJECT_INFO *originalObjectInfoPtr, *clonedObjectInfoPtr;
		OBJECT_INFO tempObjectInfo;

		/* If we're destroying the clone, we're done */
		if( isClonedObject( objectHandle ) )
			return( CRYPT_OK );

		/* We're trying to destroy the original, switch it with the clone */
		memcpy( &tempObjectInfo, &objectTable[ objectHandle ],
				sizeof( OBJECT_INFO ) );
		memcpy( &objectTable[ objectHandle ], &objectTable[ clonedObject ],
				sizeof( OBJECT_INFO ) );
		memcpy( &objectTable[ clonedObject ], &tempObjectInfo,
				sizeof( OBJECT_INFO ) );

		/* Inner precondition: Now the original is the clone and the clone is
		   the original */
		PRE( isClonedObject( objectHandle ) );
		PRE( !isClonedObject( clonedObject ) );

		/* We've now swapped the clone and the original, mark them as normal
		   (non-aliased) objects since we're about to destroy the clone */
		originalObjectInfoPtr =  &objectTable[ clonedObject ];
		clonedObjectInfoPtr = &objectTable[ objectHandle ];
		originalObjectInfoPtr->flags &= ~OBJECT_FLAG_ALIASED;
		clonedObjectInfoPtr->flags &= ~( OBJECT_FLAG_ALIASED | OBJECT_FLAG_CLONE );
		originalObjectInfoPtr->clonedObject = \
			clonedObjectInfoPtr->clonedObject = CRYPT_ERROR;

		/* Postconditions: The two objects are back to being normal objects */
		POST( !isAliasedObject( objectHandle ) && !isClonedObject( objectHandle ) );
		POST( !isAliasedObject( clonedObject ) && !isClonedObject( clonedObject ) );

		return( CRYPT_OK );
		}

	/* If it's not a message that modifies the object's state, we're done */
	if( !isActionMessage( message ) && \
		!( message == MESSAGE_SETATTRIBUTE || \
		   message == MESSAGE_SETATTRIBUTE_S || \
		   message == MESSAGE_DELETEATTRIBUTE ) && \
		!( message == MESSAGE_CTX_GENIV || message == MESSAGE_CLONE ) )
		return( CRYPT_OK );

	/* If the object that we've been passed is the clone, get the original
	   and clone into their correct roles */
	if( isClonedObject( objectHandle ) )
		{
		clonedObject = objectHandle;
		originalObject = objectInfoPtr->clonedObject;
		objectInfoPtr = &objectTable[ originalObject ];
		}

	/* Inner precondition: We've sorted out the original vs.the clone, and
	   the two are distinct */
	PRE( isClonedObject( clonedObject ) );
	PRE( clonedObject != originalObject );

	/* We're about to modify one of the two aliased objects, create distinct
	   objects to enforce copy-on-write semantics and reset the cloned/
	   aliased status.  We also create two distinct objects if a second
	   attempt is made to clone the original rather than allowing the
	   creation of multiple aliased objects.  This is done for two reasons,
	   firstly because handling arbitrarily large collections of cloned
	   objects, while possible, complicates the kernel since it's no longer
	   a straighforward message filter that needs to add relatively complex
	   processing to manage chains of cloned objects.  Secondly, having
	   multiple aliased objects is exceedingly rare (it can only happen if a
	   user, for some reason, pushes the same session key or hash into
	   multiple envelopes), so the extra overhead of a forced clone is
	   negligible */
	status = cloneContext( clonedObject, originalObject );
	if( cryptStatusOK( status ) )
		{
		OBJECT_INFO *clonedObjectInfoPtr = &objectTable[ clonedObject ];

		objectInfoPtr->clonedObject = \
			clonedObjectInfoPtr->clonedObject = CRYPT_ERROR;
		objectInfoPtr->flags &= ~OBJECT_FLAG_ALIASED;
		clonedObjectInfoPtr->flags &= ~( OBJECT_FLAG_ALIASED | OBJECT_FLAG_CLONE );
		clonedObjectInfoPtr->flags |= OBJECT_FLAG_HIGH;
		}
	return( status );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*									Message Routing							*
*																			*
****************************************************************************/

/* Find the ultimate target of an object attribute manipulation message by
   walking down the chain of controlling -> dependent objects.  For example
   a message targeted at a device and sent to a certificate would be routed
   to the cert's dependent object (which would typically be a context).
   The device message targeted at the context would in turn be routed to the
   context's dependent device, which is its final destination */

int findTargetType( const int originalObjectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget1 = ( targets >> 8 ) & 0xFF;
	const OBJECT_TYPE altTarget2 = ( targets >> 16 ) & 0xFF;
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_TYPE type = objectTable[ originalObjectHandle ].type;
	int objectHandle = originalObjectHandle, iterations;

	/* Preconditions: Source is a valid object, destination(s) are valid
	   target(s) */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget1 == OBJECT_TYPE_NONE || isValidType( altTarget1 ) );
	PRE( altTarget2 == OBJECT_TYPE_NONE || isValidType( altTarget2 ) );

	/* Route the request through any dependent objects as required until we
	   reach the required target object type.  "And thou shalt make
	   loops..." -- Exodus 26:4 */
	for( iterations = 0; \
		 iterations < 3 && isValidObject( objectHandle ) && \
		   !( target == type || \
			  ( altTarget1 != OBJECT_TYPE_NONE && altTarget1 == type ) || \
			  ( altTarget2 != OBJECT_TYPE_NONE && altTarget2 == type ) ); \
		 iterations++ )
		{
		/* Loop invariants.  "Fifty loops thou shalt make" -- Exodus 26:5
		   (some of the OT verses shouldn't be taken too literally,
		   apparently the 50 used here merely means "many" as in "more than
		   one or two" in the same way that "40 days and nights" is now
		   generally taken as meaning "Lots, but that's as far as we're
		   prepared to count") */
		INV( isValidObject( objectHandle ) );
		INV( iterations < 3 );

		/* Find the next potential target object */
		if( target == OBJECT_TYPE_DEVICE && \
			objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
			objectHandle = objectTable[ objectHandle ].dependentDevice;
		else
			if( target == OBJECT_TYPE_USER )
				objectHandle = objectTable[ objectHandle ].owner;
			else
				objectHandle = objectTable[ objectHandle ].dependentObject;
		if( isValidObject( objectHandle ) )
			type = objectTable[ objectHandle ].type;

		/* If we've got a new object, it has the same owner as the original
		   target candidate */
		POST( !isValidObject( objectHandle ) || \
			  isSameOwningObject( originalObjectHandle, objectHandle ) || \
			  objectTable[ originalObjectHandle ].owner == objectHandle );
		}
	if( iterations >= 3 )
		{
		/* The object table has been corrupted in some way, bail out */
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Postcondition: We ran out of options or we reached the target object */
	POST( iterations < 3 );
	POST( objectHandle == CRYPT_ERROR || \
		  ( isValidObject( objectHandle ) && \
		    ( isSameOwningObject( originalObjectHandle, objectHandle ) || \
			  objectTable[ originalObjectHandle ].owner == objectHandle ) && \
			( target == type || \
			  ( altTarget1 != OBJECT_TYPE_NONE && altTarget1 == type ) || \
			  ( altTarget2 != OBJECT_TYPE_NONE && altTarget2 == type ) ) ) );

	return( isValidObject( objectHandle ) ? \
			objectHandle : CRYPT_ARGERROR_OBJECT );
	}

/* Find the ultimate target of a compare message by walking down the chain
   of controlling -> dependent objects.  For example a message targeted at a
   device and sent to a certificate would be routed to the cert's dependent
   object (which would typically be a context).  The device message targeted
   at the context would be routed to the context's dependent device, which
   is its final destination */

static int routeCompareMessageTarget( const int originalObjectHandle,
									  const int messageValue )
	{
	OBJECT_TYPE targetType = OBJECT_TYPE_NONE;
	int objectHandle = originalObjectHandle;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( messageValue == MESSAGE_COMPARE_HASH || \
		 messageValue == MESSAGE_COMPARE_KEYID || \
		 messageValue == MESSAGE_COMPARE_KEYID_PGP || \
		 messageValue == MESSAGE_COMPARE_KEYID_OPENPGP || \
		 messageValue == MESSAGE_COMPARE_SUBJECT || \
		 messageValue == MESSAGE_COMPARE_ISSUERANDSERIALNUMBER || \
		 messageValue == MESSAGE_COMPARE_FINGERPRINT || \
		 messageValue == MESSAGE_COMPARE_CERTOBJ );

	/* Determine the ultimate target type for the message.  We don't check for
	   keysets, envelopes and sessions as dependent objects since this never
	   occurs */
	switch( messageValue )
		{
		case MESSAGE_COMPARE_HASH:
		case MESSAGE_COMPARE_KEYID:
		case MESSAGE_COMPARE_KEYID_PGP:
		case MESSAGE_COMPARE_KEYID_OPENPGP:
			targetType = OBJECT_TYPE_CONTEXT;
			break;

		case MESSAGE_COMPARE_SUBJECT:
		case MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
		case MESSAGE_COMPARE_FINGERPRINT:
		case MESSAGE_COMPARE_CERTOBJ:
			targetType = OBJECT_TYPE_CERTIFICATE;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_OBJECT );
		}

	/* Route the message through to the appropriate object */
	objectHandle = findTargetType( objectHandle, targetType );

	/* Postcondition */
	POST( objectHandle == CRYPT_ARGERROR_OBJECT || \
		  ( isValidObject( objectHandle ) && \
			isSameOwningObject( originalObjectHandle, objectHandle ) ) );

	return( objectHandle );
	}

/****************************************************************************
*																			*
*							Message Dispatch ACL							*
*																			*
****************************************************************************/

/* Each message type has certain properties such as whether it's routable,
   which object types it applies to, what checks are performed on it, whether
   it's processed by the kernel or dispatched to an object, etc etc.  These
   are all defined in the following table.

   In addition to the usual checks, we also make various assertions about the
   parameters we're passed.  Note that these don't check user data (that's
   checked programmatically and an error code returned) but values passed by
   cryptlib code */

typedef enum {
	PARAMTYPE_NONE_NONE,	/* Data = 0, value = 0 */
	PARAMTYPE_NONE_ANY,		/* Data = 0, value = any */
	PARAMTYPE_NONE_BOOLEAN,	/* Data = 0, value = boolean */
	PARAMTYPE_NONE_CHECKTYPE,/* Data = 0, value = check type */
	PARAMTYPE_DATA_NONE,	/* Data, value = 0 */
	PARAMTYPE_DATA_ANY,		/* Data, value = any */
	PARAMTYPE_DATA_BOOLEAN,	/* Data, value = boolean */
	PARAMTYPE_DATA_LENGTH,	/* Data, value >= 0 */
	PARAMTYPE_DATA_OBJTYPE,	/* Data, value = object type */
	PARAMTYPE_DATA_MECHTYPE,/* Data, value = mechanism type */
	PARAMTYPE_DATA_ITEMTYPE,/* Data, value = keymgmt.item type */
	PARAMTYPE_DATA_FORMATTYPE,/* Data, value = cert format type */
	PARAMTYPE_DATA_COMPARETYPE,/* Data, value = compare type */
	PARAMTYPE_LAST			/* Last possible parameter check type */
	} PARAMCHECK_TYPE;

/* Symbolic defines for message handling types, used to make it clearer
   what's going on

	PRE_DISPATCH	- Action before message is dispatched
	POST_DISPATCH	- Action after message is dispatched
	HANDLE_INTERNAL	- Message handled by the kernel */

#define PRE_DISPATCH( function )	preDispatch##function, NULL
#define POST_DISPATCH( function )	NULL, postDispatch##function
#define PRE_POST_DISPATCH( preFunction, postFunction ) \
		preDispatch##preFunction, postDispatch##postFunction
#define HANDLE_INTERNAL( function )	NULL, NULL, function

/* The handling information, declared in the order in which it's applied */

typedef struct {
	/* The message type, used for consistency checking */
	const MESSAGE_TYPE messageType;

	/* Message routing information if the message is routable.  If the target
	   is implicitly determined via the message value, the routing target is
	   OBJECT_TYPE_NONE; if the target is explicitly determined, the routing
	   target is identified in the target.  If the routing function is null,
	   the message isn't routed */
	const OBJECT_TYPE routingTarget;	/* Target type if routable */
	int ( *routingFunction )( const int objectHandle, const int arg );

	/* Object type checking information: Object subtypes for which this
	   message is valid (for object-type-specific message) */
	const int subTypeA, subTypeB;		/* Object subtype for which msg.valid */

	/* Message type checking information used to assertion-check the function
	   preconditions */
	const PARAMCHECK_TYPE paramCheck;	/* Parameter check assertion type */

	/* Pre- and post-message-dispatch handlers.  These perform any additional
	   checking and processing that may be necessary before and after a
	   message is dispatched to an object */
	int ( *preDispatchFunction )( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue, const void *auxInfo );
	int ( *postDispatchFunction )( const int objectHandle,
								   const MESSAGE_TYPE message,
								   const void *messageDataPtr,
								   const int messageValue, const void *auxInfo );

	/* Message processing information.  If the internal handler function is
	   non-null, it's handled by the  kernel */
	int ( *internalHandlerFunction )( const int objectHandle, const int arg1,
									  const void *arg2,
									  const BOOLEAN isInternal );
	} MESSAGE_HANDLING_INFO;

static const FAR_BSS MESSAGE_HANDLING_INFO messageHandlingInfo[] = {
	{ MESSAGE_NONE, ROUTE_NONE, 0, PARAMTYPE_NONE_NONE },

	/* Control messages.  These messages aren't routed, are valid for all
	   object types and subtypes, take no (or minimal) parameters, and are
	   handled by the kernel */
	{ MESSAGE_DESTROY,				/* Destroy the object */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_NONE_NONE,
	  PRE_DISPATCH( SignalDependentObjects ) },
	{ MESSAGE_INCREFCOUNT,			/* Increment object ref.count */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( incRefCount ) },
	{ MESSAGE_DECREFCOUNT,			/* Decrement object ref.count */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( decRefCount ) },
	{ MESSAGE_GETDEPENDENT,			/* Get dependent object */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_OBJTYPE,
	  HANDLE_INTERNAL( getDependentObject ) },
	{ MESSAGE_SETDEPENDENT,			/* Set dependent object (e.g. ctx->dev) */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_BOOLEAN,
	  HANDLE_INTERNAL( setDependentObject ) },
	{ MESSAGE_CLONE,				/* Clone the object (only valid for ctxs) */
	  ROUTE_FIXED( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_HASH, ST_NONE,
	  PARAMTYPE_NONE_ANY,
	  HANDLE_INTERNAL( cloneObject ) },

	/* Attribute messages.  These messages are implicitly routed by attribute
	   type, more specific checking is performed using the attribute ACL's */
	{ MESSAGE_GETATTRIBUTE,			/* Get numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, MakeObjectExternal ) },
	{ MESSAGE_GETATTRIBUTE_S,		/* Get string object attribute */
	  ROUTE_IMPLICIT, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },
	{ MESSAGE_SETATTRIBUTE,			/* Set numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ MESSAGE_SETATTRIBUTE_S,		/* Set string object attribute */
	  ROUTE_IMPLICIT, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ MESSAGE_DELETEATTRIBUTE,		/* Delete object attribute */
	  ROUTE_IMPLICIT, ST_CTX_ANY | ST_CERT_ANY, ST_SESS_ANY | ST_USER_NORMAL | ST_USER_SO,
	  PARAMTYPE_NONE_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },

	/* General messages to objects */
	{ MESSAGE_COMPARE,				/* Compare objs.or obj.properties */
	  ROUTE_SPECIAL( CompareMessageTarget ), ST_CTX_ANY | ST_CERT_ANY, ST_NONE,
	  PARAMTYPE_DATA_COMPARETYPE,
	  PRE_DISPATCH( CheckCompareParam ) },
	{ MESSAGE_CHECK,				/* Check object info */
	  ROUTE_NONE, ST_ANY_A, ST_ANY_B,
	  PARAMTYPE_NONE_CHECKTYPE,
	  PRE_POST_DISPATCH( CheckCheckParam, ForwardToDependentObject ) },

	/* Messages sent from the kernel to object message handlers.  These
	   messages are sent directly to the object from inside the kernel in
	   response to a control message, so we set the checking to disallow
	   everything to catch any that arrive from outside */
	{ MESSAGE_CHANGENOTIFY,			/* Notification of obj.status chge.*/
	  ROUTE_NONE, ST_NONE, ST_NONE, PARAMTYPE_NONE_NONE },

	/* Object-type-specific messages: Contexts */
	{ MESSAGE_CTX_ENCRYPT,			/* Context: Action = encrypt */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC, ST_NONE,
	  PARAMTYPE_DATA_LENGTH,
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ MESSAGE_CTX_DECRYPT,			/* Context: Action = decrypt */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC, ST_NONE,
	  PARAMTYPE_DATA_LENGTH,
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ MESSAGE_CTX_SIGN,				/* Context: Action = sign */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_PKC, ST_NONE,
	  PARAMTYPE_DATA_LENGTH,
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ MESSAGE_CTX_SIGCHECK,			/* Context: Action = sigcheck */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_PKC, ST_NONE,
	  PARAMTYPE_DATA_LENGTH,
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ MESSAGE_CTX_HASH,				/* Context: Action = hash */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_HASH | ST_CTX_MAC, ST_NONE,
	  PARAMTYPE_DATA_LENGTH,
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ MESSAGE_CTX_GENKEY,			/* Context: Generate a key */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE,
	  PARAMTYPE_NONE_BOOLEAN,
	  PRE_POST_DISPATCH( CheckState, ChangeState ) },
	{ MESSAGE_CTX_GENIV,			/* Context: Generate an IV */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV, ST_NONE,
	  PARAMTYPE_NONE_NONE },

	/* Object-type-specific messages: Certificates */
	{ MESSAGE_CRT_SIGN,				/* Cert: Action = sign cert */
	  ROUTE( OBJECT_TYPE_CERTIFICATE ),
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
		ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP, ST_NONE,
	  PARAMTYPE_NONE_ANY,
	  PRE_POST_DISPATCH( CheckStateParamHandle, ChangeState ) },
	{ MESSAGE_CRT_SIGCHECK,			/* Cert: Action = check/verify cert */
	  ROUTE( OBJECT_TYPE_CERTIFICATE ),
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
		ST_CERT_RTCS_RESP | ST_CERT_OCSP_RESP, ST_NONE,
	  PARAMTYPE_NONE_ANY,
	  PRE_DISPATCH( CheckParamHandleOpt ) },
	{ MESSAGE_CRT_EXPORT,			/* Cert: Export encoded cert data */
	  ROUTE( OBJECT_TYPE_CERTIFICATE ), ST_CERT_ANY, ST_NONE,
	  PARAMTYPE_DATA_FORMATTYPE,
	  PRE_DISPATCH( CheckExportAccess ) },

	/* Object-type-specific messages: Devices */
	{ MESSAGE_DEV_QUERYCAPABILITY,	/* Device: Query capability */
	  ROUTE_FIXED( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_ANY },
	{ MESSAGE_DEV_EXPORT,			/* Device: Action = export key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismWrapAccess ) },
	{ MESSAGE_DEV_IMPORT,			/* Device: Action = import key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismWrapAccess ) },
	{ MESSAGE_DEV_SIGN,				/* Device: Action = sign */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismSignAccess ) },
	{ MESSAGE_DEV_SIGCHECK,			/* Device: Action = sig.check */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismSignAccess ) },
	{ MESSAGE_DEV_DERIVE,			/* Device: Action = derive key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismDeriveAccess ) },
	{ MESSAGE_DEV_CREATEOBJECT,		/* Device: Create object */
	  ROUTE_FIXED( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_OBJTYPE,
	  PRE_POST_DISPATCH( SetObjectOwner, MakeObjectExternal ) },
	{ MESSAGE_DEV_CREATEOBJECT_INDIRECT,/* Device: Create obj.from data */
	  ROUTE_FIXED( OBJECT_TYPE_DEVICE ), ST_DEV_ANY, ST_NONE,
	  PARAMTYPE_DATA_OBJTYPE,
	  PRE_POST_DISPATCH( SetObjectOwner, MakeObjectExternal ) },

	/* Object-type-specific messages: Envelopes */
	{ MESSAGE_ENV_PUSHDATA,			/* Envelope: Push data */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		ST_NONE, ST_ENV_ANY | ST_SESS_ANY_DATA,
	  PARAMTYPE_DATA_NONE,
	  PRE_DISPATCH( CheckData ) },
	{ MESSAGE_ENV_POPDATA,			/* Envelope: Pop data */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		ST_NONE, ST_ENV_ANY | ST_SESS_ANY_DATA,
	  PARAMTYPE_DATA_NONE,
	  PRE_DISPATCH( CheckData ) },

	/* Object-type-specific messages: Keysets */
	{ MESSAGE_KEY_GETKEY,			/* Keyset: Instantiate ctx/cert */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ),
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE,
	  PARAMTYPE_DATA_ITEMTYPE,
	  PRE_POST_DISPATCH( CheckKeysetAccess, MakeObjectExternal ) },
	{ MESSAGE_KEY_SETKEY,			/* Keyset: Add ctx/cert */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ),
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE,
	  PARAMTYPE_DATA_ITEMTYPE,
	  PRE_DISPATCH( CheckKeysetAccess ) },
	{ MESSAGE_KEY_DELETEKEY,		/* Keyset: Delete key */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ),
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE,
	  PARAMTYPE_DATA_ITEMTYPE,
	  PRE_DISPATCH( CheckKeysetAccess ) },
	{ MESSAGE_KEY_GETFIRSTCERT,		/* Keyset: Get first cert in sequence */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ),
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE,
	  PARAMTYPE_DATA_ITEMTYPE,
	  PRE_DISPATCH( CheckKeysetAccess ) },
	{ MESSAGE_KEY_GETNEXTCERT,		/* Keyset: Get next cert in sequence */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ),
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE,
	  PARAMTYPE_DATA_ITEMTYPE,
	  PRE_POST_DISPATCH( CheckKeysetAccess, MakeObjectExternal ) },
	{ MESSAGE_KEY_CERTMGMT,			/* Keyset: Cert management */
	  ROUTE_FIXED( OBJECT_TYPE_KEYSET ),
		ST_KEYSET_DBMS_STORE, ST_NONE,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckCertMgmtAccess, MakeObjectExternal ) }
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

int initSendMessage( KERNEL_DATA *krnlDataPtr )
	{
	int i;

	/* Perform a consistency check on various things that need to be set
	   up in a certain way for things to work properly */
	assert( MESSAGE_CTX_DECRYPT == MESSAGE_CTX_ENCRYPT + 1 );
	assert( MESSAGE_CTX_SIGN == MESSAGE_CTX_DECRYPT + 1 );
	assert( MESSAGE_CTX_SIGCHECK == MESSAGE_CTX_SIGN + 1 );
	assert( MESSAGE_CTX_HASH == MESSAGE_CTX_SIGCHECK + 1 );
	assert( MESSAGE_CTX_GENKEY == MESSAGE_CTX_HASH + 1 );
	assert( MESSAGE_GETATTRIBUTE_S == MESSAGE_GETATTRIBUTE + 1 );
	assert( MESSAGE_SETATTRIBUTE == MESSAGE_GETATTRIBUTE_S + 1 );
	assert( MESSAGE_SETATTRIBUTE_S == MESSAGE_SETATTRIBUTE + 1 );
	assert( MESSAGE_DELETEATTRIBUTE == MESSAGE_SETATTRIBUTE_S + 1 );

	/* Perform a consistency check on various internal values and constants */
	assert( ACTION_PERM_COUNT == 6 );

	/* Perform a consistency check on the parameter ACL */
	for( i = 0; messageParamACLTbl[ i ].type != MESSAGE_NONE; i++ )
		{
		const MESSAGE_ACL *messageParamACL = &messageParamACLTbl[ i ];

		if( !isParamMessage( messageParamACL->type ) || \
			( messageParamACL->objectACL.subTypeA & SUBTYPE_CLASS_B ) || \
			( messageParamACL->objectACL.subTypeB & SUBTYPE_CLASS_A ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}

	/* Perform a consistency check on the message handling information */
	for( i = 0; i < MESSAGE_LAST; i++ )
		{
		const MESSAGE_HANDLING_INFO *messageInfo = &messageHandlingInfo[ i ];

		if( messageInfo->messageType != i || \
			messageInfo->paramCheck < PARAMTYPE_NONE_NONE || \
			messageInfo->paramCheck >= PARAMTYPE_LAST || \
			( messageInfo->subTypeA & SUBTYPE_CLASS_B ) || \
			( messageInfo->subTypeB & SUBTYPE_CLASS_A ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}

	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	return( CRYPT_OK );
	}

void endSendMessage( void )
	{
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*								Message Queue								*
*																			*
****************************************************************************/

/* Enqueue a message */

static int enqueueMessage( const int objectHandle,
						   const MESSAGE_HANDLING_INFO *handlingInfoPtr,
						   const MESSAGE_TYPE message,
						   const void *messageDataPtr,
						   const int messageValue )
	{
	MESSAGE_QUEUE_DATA *messageQueue = krnlData->messageQueue;
	int queuePos, i;

	/* Precondition: It's a valid message being sent to a valid object */
	PRE( isValidObject( objectHandle ) );
	PRE( isReadPtr( handlingInfoPtr, sizeof( MESSAGE_HANDLING_INFO ) ) );
	PRE( isValidMessage( message & MESSAGE_MASK ) );

	/* Make sure that we don't overflow the queue (this object is not
	   responding to messages... now all we need is GPF's).  We return a
	   timeout error to indicate that there are too many messages queued
	   for this (or other) objects */
	if( krnlData->queueEnd < 0 || \
		krnlData->queueEnd >= MESSAGE_QUEUE_SIZE - 1 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_TIMEOUT );
		}

	/* Precondition: There's room to enqueue the message */
	PRE( krnlData->queueEnd >= 0 && \
		 krnlData->queueEnd < MESSAGE_QUEUE_SIZE );

	/* Check whether a message to this object is already present in the
	   queue */
	for( queuePos = krnlData->queueEnd - 1; queuePos >= 0; queuePos-- )
		if( messageQueue[ queuePos ].objectHandle == objectHandle )
			break;

	/* Postcondition: queuePos = -1 if not present, position in queue if
	   present */
	POST( queuePos == -1 || \
		  ( queuePos >= 0 && queuePos < krnlData->queueEnd ) );

	/* Enqueue the message */
	queuePos++;		/* Insert after current position */
	for( i = krnlData->queueEnd - 1; i >= queuePos; i-- )
		messageQueue[ i + 1 ] = messageQueue[ i ];
	messageQueue[ queuePos ].objectHandle = objectHandle;
	messageQueue[ queuePos ].handlingInfoPtr = handlingInfoPtr;
	messageQueue[ queuePos ].message = message;
	messageQueue[ queuePos ].messageDataPtr = messageDataPtr;
	messageQueue[ queuePos ].messageValue = messageValue;
	krnlData->queueEnd++;
	if( queuePos )
		/* A message for this object is already present, tell the caller to
		   defer processing */
		return( OK_SPECIAL );

	return( CRYPT_OK );
	}

/* Dequeue a message */

static void dequeueMessage( const int messagePosition )
	{
	MESSAGE_QUEUE_DATA *messageQueue = krnlData->messageQueue;
	int i;

	/* Precondition: We're deleting a valid queue position */
	PRE( messagePosition >= 0 && messagePosition < krnlData->queueEnd );

	/* Move the remaining messages down and clear the last entry */
	for( i = messagePosition; i < krnlData->queueEnd - 1; i++ )
		messageQueue[ i ] = messageQueue[ i + 1 ];
	zeroise( &messageQueue[ krnlData->queueEnd - 1 ],
			 sizeof( MESSAGE_QUEUE_DATA ) );
	krnlData->queueEnd--;

	/* Postcondition: all queue entries are valid, all non-queue entries are
	   empty */
	FORALL( i, 0, krnlData->queueEnd,
			messageQueue[ i ].handlingInfoPtr != NULL );
	FORALL( i, krnlData->queueEnd, MESSAGE_QUEUE_SIZE,
			messageQueue[ i ].handlingInfoPtr == NULL );
	}

/* Get the next message in the queue */

static BOOLEAN getNextMessage( const int objectHandle,
							   MESSAGE_QUEUE_DATA *messageQueueInfo )
	{
	MESSAGE_QUEUE_DATA *messageQueue = krnlData->messageQueue;
	int i;

	PRE( messageQueueInfo == NULL || \
		 isWritePtr( messageQueueInfo, sizeof( MESSAGE_QUEUE_DATA ) ) );

	/* Find the next message for this object.  Since other messages can have
	   come and gone in the meantime, we have to scan from the start each
	   time */
	for( i = 0; i < krnlData->queueEnd; i++ )
		{
		if( messageQueue[ i ].objectHandle == objectHandle )
			{
			if( messageQueueInfo != NULL )
				*messageQueueInfo = messageQueue[ i ];
			dequeueMessage( i );
			return( TRUE );
			}
		}

	/* Postcondition: There are no more messages for this object present in
	   the queue */
	FORALL( i, 0, krnlData->queueEnd,
			messageQueue[ i ].objectHandle != objectHandle );

	return( FALSE );
	}

/* Dequeue all messages for an object in the queue */

static void dequeueAllMessages( const int objectHandle )
	{
	/* Dequeue all messages for a given object */
	while( getNextMessage( objectHandle, NULL ) );

	/* Postcondition: There are no more messages for this object present in
	   the queue */
	FORALL( i, 0, krnlData->queueEnd,
			krnlData->messageQueue[ i ].objectHandle != objectHandle );
	}

/****************************************************************************
*																			*
*							Message Dispatcher								*
*																			*
****************************************************************************/

/* Dispatch a message to an object */

static int dispatchMessage( const int localObjectHandle,
							const MESSAGE_QUEUE_DATA *messageQueueData,
							OBJECT_INFO *objectInfoPtr,
							const void *aclPtr )
	{
	const MESSAGE_HANDLING_INFO *handlingInfoPtr = \
									messageQueueData->handlingInfoPtr;
	const MESSAGE_FUNCTION messageFunction = objectInfoPtr->messageFunction;
	const MESSAGE_TYPE localMessage = messageQueueData->message & MESSAGE_MASK;
	void *objectPtr = objectInfoPtr->objectPtr;
	const int lockCount = objectInfoPtr->lockCount + 1;
	int status;

	PRE( isValidHandle( localObjectHandle ) );
	PRE( isReadPtr( messageQueueData, sizeof( MESSAGE_QUEUE_DATA ) ) );
	PRE( isWritePtr( objectInfoPtr, sizeof( OBJECT_INFO ) ) );

	/* If there's a pre-dispatch handler present, apply it */
	if( handlingInfoPtr->preDispatchFunction != NULL )
		{
		status = handlingInfoPtr->preDispatchFunction( localObjectHandle,
										messageQueueData->message,
										messageQueueData->messageDataPtr,
										messageQueueData->messageValue,
										aclPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Mark the object as busy so that we have it available for our
	   exclusive use and further messages to it will be enqueued, dispatch
	   the message with the object table unlocked, and mark the object as
	   non-busy again */
	objectInfoPtr->lockCount++;
#ifdef USE_THREADS
	objectInfoPtr->lockOwner = THREAD_SELF();
#endif /* USE_THREADS */
	MUTEX_UNLOCK( objectTable );
	status = messageFunction( objectPtr, localMessage,
							  ( void * ) messageQueueData->messageDataPtr,
							  messageQueueData->messageValue );
	MUTEX_LOCK( objectTable );
	objectInfoPtr = &krnlData->objectTable[ localObjectHandle ];
	assert( localObjectHandle == SYSTEM_OBJECT_HANDLE || \
			( objectInfoPtr->type == OBJECT_TYPE_USER && \
			  localMessage == MESSAGE_SETATTRIBUTE && \
			    messageQueueData->messageValue == \
					localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
			objectInfoPtr->lockCount == lockCount );

	/* The system object and to a lesser extent the user object may unlock
	   themselves while processing a message when they forward the message
	   elsewhere or perform non-object-specific processing, so we only
	   decrement the lock count if it's unchanged and we still own the
	   object.  We have to perform the ownership check to avoid the
	   situation where we unlock the object and another thread locks it,
	   leading to an (apparently) unchanged lock count */
	if( objectInfoPtr->lockCount == lockCount && \
		isObjectOwner( localObjectHandle ) )
		objectInfoPtr->lockCount--;

	/* Postcondition: The lock count is non-negative and, if it's not the
	   system object or a user object, has been reset to its previous
	   value */
	POST( objectInfoPtr->lockCount >= 0 && \
		  ( localObjectHandle == SYSTEM_OBJECT_HANDLE ||
		    ( objectInfoPtr->type == OBJECT_TYPE_USER && \
			  localMessage == MESSAGE_SETATTRIBUTE && \
			  messageQueueData->messageValue == \
				localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
			objectInfoPtr->lockCount == lockCount - 1 ) );

	/* If there's a post-dispatch handler present, apply it.  Since a
	   destroy object message always succeeds but can return an error code
	   (typically CRYPT_ERROR_INCOMPLETE), we don't treat an error return as
	   a real error status for the purposes of further processing */
	if( ( cryptStatusOK( status ) || localMessage == MESSAGE_DESTROY ) && \
		handlingInfoPtr->postDispatchFunction != NULL )
		status = handlingInfoPtr->postDispatchFunction( localObjectHandle,
												messageQueueData->message,
												messageQueueData->messageDataPtr,
												messageQueueData->messageValue,
												aclPtr );
	return( status );
	}

/* Send a message to an object */

int krnlSendMessage( const int objectHandle, const MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue )
	{
	const ATTRIBUTE_ACL *attributeACL = NULL;
	const MESSAGE_HANDLING_INFO *handlingInfoPtr;
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;
	MESSAGE_QUEUE_DATA enqueuedMessageData;
	const BOOLEAN isInternalMessage = \
						( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;
	const void *aclPtr = NULL;
	MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	int localObjectHandle = objectHandle, status = CRYPT_OK;

	/* Preconditions.  For external messages we don't provide any assertions
	   at this point since they're coming straight from the user and could
	   contain any values, and for internal messages we only trap on
	   programming errors (thus for example isValidHandle() vs.
	   isValidObject(), since this would trap if a message is sent to a
	   destroyed object) */
	PRE( isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) );
	PRE( isValidMessage( localMessage ) );
	PRE( !isInternalMessage || isValidHandle( objectHandle ) );

	/* Enforce the precondition at runtime as well */
	if( !isValidMessage( localMessage ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Get the information that we need to handle this message */
	handlingInfoPtr = &messageHandlingInfo[ localMessage ];

	/* Inner preconditions now that we have the handling information: Message
	   parameters must be within the allowed range (again, this traps on
	   programming errors only).  This is done as a large number of
	   individual assertions rather than a single huge check so that a failed
	   assertion can provide more detailed information than just "it broke" */
	PRE( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_NONE ||
		 handlingInfoPtr->paramCheck == PARAMTYPE_NONE_ANY || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_NONE_BOOLEAN || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_NONE_CHECKTYPE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_NONE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_ANY || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_BOOLEAN || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_LENGTH || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_OBJTYPE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_MECHTYPE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_ITEMTYPE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_FORMATTYPE || \
		 handlingInfoPtr->paramCheck == PARAMTYPE_DATA_COMPARETYPE );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_NONE_NONE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_NONE && \
		   messageDataPtr == NULL && messageValue == 0 ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_NONE_ANY || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_ANY && \
		   messageDataPtr == NULL ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_NONE_BOOLEAN || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_BOOLEAN && \
		   messageDataPtr == NULL && \
		   ( messageValue == FALSE || messageValue == TRUE ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_NONE_CHECKTYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_CHECKTYPE && \
		   messageDataPtr == NULL && \
		   ( messageValue > MESSAGE_CHECK_NONE && \
			 messageValue < MESSAGE_CHECK_LAST ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_NONE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_NONE && \
		   messageDataPtr != NULL && messageValue == 0 ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_ANY || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_ANY && \
		   messageDataPtr != NULL ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_BOOLEAN || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_BOOLEAN && \
		   messageDataPtr != NULL && \
		   ( messageValue == FALSE || messageValue == TRUE ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_LENGTH || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_LENGTH && \
		   messageDataPtr != NULL && messageValue >= 0 ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_OBJTYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_OBJTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > OBJECT_TYPE_NONE && messageValue < OBJECT_TYPE_LAST ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_MECHTYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_MECHTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > MECHANISM_NONE && messageValue < MECHANISM_LAST ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_ITEMTYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_ITEMTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > KEYMGMT_ITEM_NONE && messageValue < KEYMGMT_ITEM_LAST ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_FORMATTYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_FORMATTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > CRYPT_CERTFORMAT_NONE && messageValue < CRYPT_CERTFORMAT_LAST ) ) );
	PRE( handlingInfoPtr->paramCheck != PARAMTYPE_DATA_COMPARETYPE || \
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_COMPARETYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > MESSAGE_COMPARE_NONE && \
			 messageValue < MESSAGE_COMPARE_LAST ) ) );

	/* If it's an object-manipulation message get the attribute's mandatory
	   ACL; if it's an object-parameter message get the parameter's mandatory
	   ACL.  Since these doesn't require access to any object information, we
	   can do it before we lock the object table */
	if( isAttributeMessage( localMessage ) )
		{
		attributeACL = findAttributeACL( messageValue, isInternalMessage );
		if( attributeACL == NULL )
			return( CRYPT_ARGERROR_VALUE );
		aclPtr = attributeACL;
		}
	if( isParamMessage( localMessage ) )
		aclPtr = findParamACL( localMessage );

	/* Inner precondition: If it's an attribute-manipulation message, we have
	   a valid ACL for the attribute present */
	PRE( !isAttributeMessage( localMessage ) || attributeACL != NULL );

	/* If we're in the middle of a shutdown, don't allow any further
	   messages except ones related to object destruction (the status read
	   is needed for objects capable of performing async ops, since the
	   shutdown code needs to determine whether they're currently busy).
	   The check outside the object-table lock is done in order to have any
	   remaining active objects exit quickly without tying up the object
	   table, since we don't want them to block the shutdown */
	if( krnlData->isClosingDown && \
		!( localMessage == MESSAGE_DESTROY || \
		   localMessage == MESSAGE_DECREFCOUNT || \
		   ( localMessage == MESSAGE_GETATTRIBUTE && \
			 messageValue == CRYPT_IATTRIBUTE_STATUS ) ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	MUTEX_LOCK( objectTable );

	/* The first line of defence: Make sure that the message is being sent
	   to a valid object and that the object is externally visible and
	   accessible to the caller if required by the message.  The checks
	   performed are:

		if( handle does not correspond to an object )
			error;
		if( message is external )
			{
			if( object is internal )
				error;
			if( object isn't owned by calling thread )
				error;
			}

	   This is equivalent to the shorter form fullObjectCheck() that used
	   elsewhere.  The error condition reported in all of these cases is
	   that the object handle isn't valid */
	if( !isValidObject( objectHandle ) )
		status = CRYPT_ARGERROR_OBJECT;
	else
		if( !isInternalMessage && \
			( isInternalObject( objectHandle ) || \
			  !checkObjectOwnership( objectTable[ objectHandle ] ) ) )
			status = CRYPT_ARGERROR_OBJECT;
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( objectTable );
		return( status );
		}

	/* Inner precondition now that the outer check has been passed: It's a
	   valid, accessible object and not a system object that can never be
	   explicitly destroyed or have its refCount altered */
	PRE( isValidObject( objectHandle ) );
	PRE( isInternalMessage || ( !isInternalObject( objectHandle ) && \
		 checkObjectOwnership( objectTable[ objectHandle ] ) ) );
	PRE( fullObjectCheck( objectHandle, message ) );
	PRE( objectHandle >= NO_SYSTEM_OBJECTS || \
		 ( localMessage != MESSAGE_DESTROY && \
		   localMessage != MESSAGE_DECREFCOUNT && \
		   localMessage != MESSAGE_INCREFCOUNT ) );

	/* If this message is routable, find its target object */
	if( handlingInfoPtr->routingFunction != NULL )
		{
		/* If it's implicitly routed, route it based on the attribute type */
		if( isImplicitRouting( handlingInfoPtr->routingTarget ) )
			{
			if( attributeACL->routingFunction != NULL )
				localObjectHandle = attributeACL->routingFunction( objectHandle,
											attributeACL->routingTarget );
			}
		else
			/* It's explicitly or directly routed, route it based on the
			   message type or fixed-target type */
			localObjectHandle = handlingInfoPtr->routingFunction( objectHandle,
						isExplicitRouting( handlingInfoPtr->routingTarget ) ? \
						messageValue : handlingInfoPtr->routingTarget );
		if( cryptStatusError( localObjectHandle ) )
			{
			MUTEX_UNLOCK( objectTable );
			return( CRYPT_ARGERROR_OBJECT );
			}
		}

	/* Inner precodition: It's a valid destination object */
	PRE( isValidObject( localObjectHandle ) );

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ localObjectHandle ];

	/* Now that the message has been routed to its intended target, make sure
	   that it's valid for the target object subtype */
	if( !isValidSubtype( handlingInfoPtr->subTypeA, objectInfoPtr->subType ) && \
		!isValidSubtype( handlingInfoPtr->subTypeB, objectInfoPtr->subType ) )
		{
		MUTEX_UNLOCK( objectTable );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Inner precondition: The message is valid for this object subtype */
	PRE( isValidSubtype( handlingInfoPtr->subTypeA, objectInfoPtr->subType ) || \
		 isValidSubtype( handlingInfoPtr->subTypeB, objectInfoPtr->subType ) );

	/* If this message is processed internally, handle it now.  These
	   messages aren't affected by the object's state so they're always
	   processed */
	if( handlingInfoPtr->internalHandlerFunction != NULL || \
		( attributeACL != NULL && \
		  attributeACL->flags & ATTRIBUTE_FLAG_PROPERTY ) )
		{
		if( handlingInfoPtr->preDispatchFunction != NULL )
			status = handlingInfoPtr->preDispatchFunction( localObjectHandle,
									message, messageDataPtr, messageValue,
									aclPtr );
		if( cryptStatusOK( status ) )
			{
			/* Precondition: Either the message as a whole is internally
			   handled or it's a property attribute */
			PRE( handlingInfoPtr->internalHandlerFunction == NULL || \
				 attributeACL == NULL );

			/* If it's an object property attribute (which is handled by the
			   kernel), get or set its value */
			if( handlingInfoPtr->internalHandlerFunction == NULL )
				{
				/* Precondition: Object properties are always numeric
				   attributes */
				PRE( handlingInfoPtr->messageType == MESSAGE_GETATTRIBUTE || \
					 handlingInfoPtr->messageType == MESSAGE_SETATTRIBUTE );

				if( handlingInfoPtr->messageType == MESSAGE_GETATTRIBUTE )
					status = getPropertyAttribute( localObjectHandle,
											messageValue, messageDataPtr );
				else
					status = setPropertyAttribute( localObjectHandle,
											messageValue, messageDataPtr );
				}
			else
				/* It's a kernel-handled message, process it */
				status = handlingInfoPtr->internalHandlerFunction( \
										localObjectHandle, messageValue,
										messageDataPtr, isInternalMessage );
			if( cryptStatusOK( status ) && \
				handlingInfoPtr->postDispatchFunction != NULL )
				status = handlingInfoPtr->postDispatchFunction( localObjectHandle,
										message, messageDataPtr, messageValue, aclPtr );
			}
		if( status != OK_SPECIAL )
			{
			/* The message was processed normally, exit */
			MUTEX_UNLOCK( objectTable );
			return( status );
			}

		/* The object has entered an invalid state (for example it was
		   signalled while it was being initialised) and can't be used any
		   more, destroy it, convert the (local copy of the) message into a
		   destroy object message */
		localMessage = MESSAGE_DESTROY;
		status = CRYPT_OK;
		}

#if 0	/* 18/2/04 No need for copy-on-write any more since we can just copy
				   across the instance data referenced in the object table */
	/* If this is an aliased object (one that's been cloned and is subject
	   to copy-on-write), handle it specially */
	if( isAliasedObject( localObjectHandle ) )
		{
		status = handleAliasedObject( localObjectHandle, localMessage,
									  messageDataPtr, messageValue );
		if( cryptStatusError( status ) )
			{
			MUTEX_UNLOCK( objectTable );
			return( status );
			}
		}
#else
	/* We shouldn't have aliased objects since we don't use copy-on-write
	   any more */
	assert( !isAliasedObject( localObjectHandle ) );
#endif /* 0 */

	/* If the object isn't already processing a message and the message isn't
	   a special type such as MESSAGE_DESTROY, dispatch it immediately rather
	   than enqueueing it for later dispatch.  This scoreboard mechanism
	   greatly reduces the load on the queue */
	if( !isInUse( localObjectHandle ) && localMessage != MESSAGE_DESTROY )
		{
		CONST_INIT_STRUCT_5( MESSAGE_QUEUE_DATA messageQueueData, \
							 localObjectHandle, handlingInfoPtr, message, \
							 messageDataPtr, messageValue );

		CONST_SET_STRUCT( messageQueueData.objectHandle = localObjectHandle; \
						  messageQueueData.handlingInfoPtr = handlingInfoPtr; \
						  messageQueueData.message = message; \
						  messageQueueData.messageDataPtr = messageDataPtr; \
						  messageQueueData.messageValue = messageValue );

		/* If the object isn't in a valid state, we can't do anything with it.
		   There are no messages that can be sent to it at this point, get/
		   set property messages have already been handled earlier and the
		   destroy message isn't handled here */
		if( isInvalidObjectState( localObjectHandle ) )
			{
			status = getObjectStatusValue( objectInfoPtr->flags );
			MUTEX_UNLOCK( objectTable );
			return( status );
			}

		/* In case a shutdown was signalled while we were performing other
		   processing, exit now before we try and do anything with the
		   object.  It's safe to perform the check at this point since no
		   message sent during shutdown will get here */
		if( krnlData->isClosingDown )
			{
			MUTEX_UNLOCK( objectTable );
			return( CRYPT_ERROR_PERMISSION );
			}

		/* Inner precondition: The object is in a valid state */
		PRE( !isInvalidObjectState( localObjectHandle ) );

		/* Dispatch the message to the object */
		status = dispatchMessage( localObjectHandle, &messageQueueData,
								  objectInfoPtr, aclPtr );
		MUTEX_UNLOCK( objectTable );

		/* Postcondition: The return status is valid */
		POST( ( status >= CRYPT_ENVELOPE_RESOURCE && status <= CRYPT_OK ) || \
			  cryptArgError( status ) || status == OK_SPECIAL );

		return( status );
		}

	/* Inner precondition: The object is in use or it's a destroy object
	   message, we have to enqueue it */
	PRE( isInUse( localObjectHandle ) || localMessage == MESSAGE_DESTROY );

	/* If we're stuck in a loop processing recursive messages, bail out.
	   This would happen automatically anyway once we fill the message queue,
	   but this early-out mechanism prevents a single object from filling the
	   queue to the detriment of other objects */
	if( objectInfoPtr->lockCount > MESSAGE_QUEUE_SIZE / 2 )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_TIMEOUT );
		}

	/* If the object is in use by another thread, wait for it to become
	   available */
	if( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) )
		status = waitForObject( objectHandle, &objectInfoPtr );
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( objectTable );
		return( status );
		}

	/* Enqueue the message */
	if( ( message & MESSAGE_MASK ) != localMessage )
		{
		/* The message was converted during processing, this can only happen
		   when a message sent to an invalid-state object is converted into
		   a destroy-object message.  What we therefore enqueue is a
		   destroy-object message, but with the messageValue parameter set
		   to TRUE to indicate that it's a converted destroy message */
		PRE( localMessage == MESSAGE_DESTROY );

		status = enqueueMessage( localObjectHandle,
								 &messageHandlingInfo[ MESSAGE_DESTROY ],
								 MESSAGE_DESTROY, messageDataPtr, TRUE );
		}
	else
		status = enqueueMessage( localObjectHandle, handlingInfoPtr, message,
								 messageDataPtr, messageValue );
	if( cryptStatusError( status ) )
		{
		/* A message for this object is already present in the queue, defer
		   processing until later */
		MUTEX_UNLOCK( objectTable );
		return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
		}

	/* While there are more messages for this object present, dequeue them
	   and dispatch them.  Since messages will only be enqueued if
	   krnlSendMessage() is called recursively, we only dequeue messages for
	   the current object in this loop.  Queued messages for other objects
	   will be handled at a different level of recursion */
	while( getNextMessage( localObjectHandle, &enqueuedMessageData ) )
		{
		const BOOLEAN isDestroy = \
			( ( enqueuedMessageData.message & MESSAGE_MASK ) == MESSAGE_DESTROY );

		/* If there's a problem with the object, initiate special processing.
		   There are two exceptions to this, one is a destroy message sent to
		   a busy object, the other is a destroy message that started out as
		   a different type of message (that is, it was converted into a
		   destroy object message due to the object being in an invalid
		   state, indicated by the messageValue parameter being set to TRUE
		   when it's normally zero for a destroy message).  Both of these
		   types are let through */
		if( isInvalidObjectState( localObjectHandle ) && \
			!( isDestroy && \
			   ( objectInfoPtr->flags & OBJECT_FLAG_BUSY ) || \
			   ( enqueuedMessageData.messageValue == TRUE ) ) )
			{
			/* If it's a destroy object message being sent to an object in
			   the process of being created, set the state to signalled and
			   continue.  The object will be destroyed when the caller
			   notifies the kernel that the init is complete */
			if( isDestroy && ( objectInfoPtr->flags & OBJECT_FLAG_NOTINITED ) )
				{
				objectInfoPtr->flags |= OBJECT_FLAG_SIGNALLED;
				status = CRYPT_OK;
				}
			else
				{
				/* Remove all further messages for this object and return
				   to the caller */
				dequeueAllMessages( localObjectHandle );
				status = getObjectStatusValue( objectInfoPtr->flags );
				}
			continue;
			}

		/* Inner precondition: The object is in a valid state or it's a
		   destroy message to a busy object or a destroy message that was
		   converted from a different message type */
		PRE( !isInvalidObjectState( localObjectHandle ) || \
			 ( isDestroy && \
				( objectInfoPtr->flags & OBJECT_FLAG_BUSY ) || \
				( enqueuedMessageData.messageValue == TRUE ) ) );

		/* Dispatch the message to the object */
		status = dispatchMessage( localObjectHandle, &enqueuedMessageData,
								  objectInfoPtr, aclPtr );

		/* If the message is a destroy object message, we have to explicitly
		   remove it from the object table and dequeue all further messages
		   for it since the object's message handler can't do this itself.
		   Since a destroy object message always succeeds but can return an
		   error code (typically CRYPT_ERROR_INCOMPLETE), we don't treat an
		   error return as a real error status for the purposes of further
		   processing */
		if( isDestroy )
			{
			destroyObjectData( localObjectHandle );
			dequeueAllMessages( localObjectHandle );
			}
		else
			/* If we ran into a problem, dequeue all further messages for
			   this object.  This causes getNextMessage() to fail and we
			   drop out of the loop */
			if( cryptStatusError( status ) )
				dequeueAllMessages( localObjectHandle );
		}

	/* Unlock the object table to allow access by other threads */
	MUTEX_UNLOCK( objectTable );

	/* Postcondition: The return status is valid */
	POST( ( status >= CRYPT_ENVELOPE_RESOURCE && status <= CRYPT_OK ) || \
		  cryptArgError( status ) || status == OK_SPECIAL );

	return( status );
	}
