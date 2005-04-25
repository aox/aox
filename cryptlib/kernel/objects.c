/****************************************************************************
*																			*
*							Kernel Object Management						*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
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

/* The initial allocation size of the object table.  In memory-starved
   environments we limit the size, in general these are embedded systems or
   single-tasking OSes that aren't going to need many objects anyway */

#ifdef CONFIG_CONSERVE_MEMORY
  #define OBJECT_TABLE_ALLOCSIZE	128
  #define INITIAL_LFSRPOLY			0x83
#else
  #define OBJECT_TABLE_ALLOCSIZE	1024
  #define INITIAL_LFSRPOLY			0x409
#endif /* Memory-starved environments */

/* A pointer to the kernel data block */

static KERNEL_DATA *krnlData = NULL;

/* A template used to initialise object table entries.  Some of the entries
   are either object handles that have to be set to CRYPT_ERROR or values
   for which 0 is significant (so they're set to CRYPT_UNUSED), because of
   this we can't just memset the entry to all zeroes */

static const OBJECT_INFO OBJECT_INFO_TEMPLATE = {
	OBJECT_TYPE_NONE, 0,		/* Type, subtype */
	NULL, 0,					/* Object data and size */
	OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED,	/* Flags */
	0,							/* Action flags */
	0, 0,						/* Ref.count, lock count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Lock owner */
#endif /* USE_THREADS */
	0,							/* Unique ID */
	CRYPT_UNUSED, CRYPT_UNUSED,	/* Forward count, usage count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Owner */
#endif /* USE_THREADS */
	NULL,						/* Message function */
	CRYPT_ERROR, CRYPT_ERROR,
	CRYPT_ERROR					/* Owning/dependent objects */
	};

/* A template used to initialise the object allocation state data */

static const OBJECT_STATE_INFO OBJECT_STATE_INFO_TEMPLATE = {
	OBJECT_TABLE_ALLOCSIZE,		/* Mask for LFSR output */
	INITIAL_LFSRPOLY,			/* LFSR polynomial */
	-1							/* Initial-1'th object handle */
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Create and destroy the object table.  The destroy process is handled in
   two stages, the first of which is called fairly early in the shutdown
   process to destroy any remaining objects, and the second which is called
   at the end of the shutdown when the kernel data is being deleted.  This
   is because some of the objects are tied to things like external devices,
   and deleting them at the end when everything else has been shut down
   isn't possible */

int initObjects( KERNEL_DATA *krnlDataPtr )
	{
	int i;

	/* Perform a consistency check on various things that need to be set
	   up in a certain way for things to work properly */
	assert( OBJECT_TABLE_ALLOCSIZE >= 64 );
	assert( OBJECT_INFO_TEMPLATE.type == OBJECT_TYPE_NONE );
	assert( OBJECT_INFO_TEMPLATE.subType == 0 );
	assert( OBJECT_INFO_TEMPLATE.objectPtr == NULL );
	assert( OBJECT_INFO_TEMPLATE.objectSize == 0 );
	assert( OBJECT_INFO_TEMPLATE.flags == \
			( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ) );
	assert( OBJECT_INFO_TEMPLATE.actionFlags == 0 );
	assert( OBJECT_INFO_TEMPLATE.forwardCount == CRYPT_UNUSED );
	assert( OBJECT_INFO_TEMPLATE.usageCount == CRYPT_UNUSED );
	assert( OBJECT_INFO_TEMPLATE.owner == CRYPT_ERROR );
	assert( OBJECT_INFO_TEMPLATE.dependentDevice == CRYPT_ERROR );
	assert( OBJECT_INFO_TEMPLATE.dependentObject == CRYPT_ERROR );
	assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2 );
	assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1 );

	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	/* Allocate and initialise the object table */
	krnlData->objectTable = \
			clAlloc( "initObjectTable",
					 OBJECT_TABLE_ALLOCSIZE * sizeof( OBJECT_INFO ) );
	if( krnlData->objectTable == NULL )
		return( CRYPT_ERROR_MEMORY );
	for( i = 0; i < OBJECT_TABLE_ALLOCSIZE; i++ )
		krnlData->objectTable[ i ] = OBJECT_INFO_TEMPLATE;
	krnlData->objectTableSize = OBJECT_TABLE_ALLOCSIZE;
	krnlData->objectStateInfo = OBJECT_STATE_INFO_TEMPLATE;

	/* Initialise object-related information.  This isn't strictly part of
	   the object table but is used to assign unique ID values to objects
	   within the table, since table entries (object handles) may be reused
	   as objects are destroyed and new ones created in their place */
	krnlData->objectUniqueID = 0;

	/* Initialize any data structures required to make the object table
	   thread-safe */
	MUTEX_CREATE( objectTable );

	/* Postconditions */
	POST( krnlData->objectTable != NULL );
	POST( krnlData->objectTableSize == OBJECT_TABLE_ALLOCSIZE );
	FORALL( i, 0, OBJECT_TABLE_ALLOCSIZE,
			!memcmp( &krnlData->objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );
	POST( krnlData->objectStateInfo.lfsrMask == OBJECT_TABLE_ALLOCSIZE && \
		  krnlData->objectStateInfo.lfsrPoly == INITIAL_LFSRPOLY && \
		  krnlData->objectStateInfo.objectHandle == SYSTEM_OBJECT_HANDLE - 1 );
	POST( krnlData->objectUniqueID == 0 );

	return( CRYPT_OK );
	}

void endObjects( void )
	{
	/* Hinc igitur effuge */
	MUTEX_LOCK( objectTable );
	zeroise( krnlData->objectTable, 
			 krnlData->objectTableSize * sizeof( OBJECT_INFO ) );
	clFree( "endObjectTable", krnlData->objectTable );
	krnlData->objectTable = NULL;
	krnlData->objectTableSize = 0;
	krnlData->objectUniqueID = 0;
	MUTEX_UNLOCK( objectTable );
	MUTEX_DESTROY( objectTable );
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*							Object Table Management							*
*																			*
****************************************************************************/

/* Destroy an object's instance data and object table entry */

void destroyObjectData( const int objectHandle )
	{
	OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ objectHandle ];

	assert( isWritePtr( objectInfoPtr->objectPtr,
						objectInfoPtr->objectSize ) );

	/* Destroy the object's data and clear the object table entry */
	if( objectInfoPtr->flags & OBJECT_FLAG_SECUREMALLOC )
		krnlMemfree( &objectInfoPtr->objectPtr );
	else
		{
		zeroise( objectInfoPtr->objectPtr, objectInfoPtr->objectSize );
		clFree( "destroyObjectData", objectInfoPtr->objectPtr );
		}
	krnlData->objectTable[ objectHandle ] = OBJECT_INFO_TEMPLATE;
	}

/* Destroy an object.  This is only called when cryptlib is shutting down,
   normally objects are destroyed directly in response to messages */

static void destroyObject( const int objectHandle )
	{
	const MESSAGE_FUNCTION messageFunction = \
					krnlData->objectTable[ objectHandle ].messageFunction;

	/* If there's no object present at this position, just clear the 
	   entry (it should be cleared anyway) */
	if( messageFunction == NULL )
		{
		krnlData->objectTable[ objectHandle ] = OBJECT_INFO_TEMPLATE;
		return;
		}

	/* Destroy the object and its object table entry */
	messageFunction( krnlData->objectTable[ objectHandle ].objectPtr, 
					 MESSAGE_DESTROY, NULL, 0 );
	destroyObjectData( objectHandle );
	}

/* Destroy all objects at a given nesting level */

static int destroySelectedObjects( const int currentDepth )
	{
	const OBJECT_INFO *objectTable = krnlData->objectTable;
	int objectHandle, status = CRYPT_OK;

	for( objectHandle = NO_SYSTEM_OBJECTS; \
		 objectHandle < krnlData->objectTableSize; \
		 objectHandle++ )
		{
		const int dependentObject = \
						objectTable[ objectHandle ].dependentObject;
		int depth = 1;

		/* If there's nothing there, continue */
		if( objectTable[ objectHandle ].objectPtr == NULL )
			continue;

		/* There's an object still present, determine its nesting depth.
		   Dependent devices are terminal so we only follow the path down for
		   dependent objects */
		if( isValidObject( dependentObject ) )
			{
			if( isValidObject( objectTable[ dependentObject ].dependentObject ) )
				depth = 3;
			else
				if( isValidObject( objectTable[ dependentObject ].dependentDevice ) )
					depth = 2;
			}
		else
			if( isValidObject( objectTable[ objectHandle ].dependentDevice ) )
				depth = 2;

		/* If the nesting level of the object matches the current level,
		   destroy it.  We unlock the object table around the access to
		   prevent remaining active objects from blocking the shutdown (the
		   closingDown flag takes care of any other messages that may arrive
		   during this process).

		   "For death is come up into our windows, and it is entered into
		    our palaces, to cut off the children from the without"
			-- Jeremiah 9:21 */
		if( depth >= currentDepth )
			{
			MUTEX_UNLOCK( objectTable );
			krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
			status = CRYPT_ERROR_INCOMPLETE;
			MUTEX_LOCK( objectTable );
			}
		}

	return( status );
	}

/* Destroy all objects */

int destroyObjects( void )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	int depth, objectHandle, status = CRYPT_OK;

	/* Indicate that we're in the middle of a shutdown.  From now on all
	   messages other than object-destruction ones will be rejected by the
	   kernel.  This is needed in order to have any remaining active objects
	   exit quickly, since we don't want them to block the shutdown.  Note
	   that we do this before we lock the object table to encourage anything
	   that might have the table locked to exit quickly once we try and lock
	   the table */
	krnlData->isClosingDown = TRUE;

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	MUTEX_LOCK( objectTable );

	/* Destroy all system objects except the root system object ("The death 
	   of God left the angels in a strange position" - Donald Barthelme, "On
	   Angels").  We have to do this before we destroy any unclaimed 
	   leftover objects because some of them may depend on system objects, 
	   if the system objects aren't destroyed they'll be erroneously flagged 
	   as leftover objects.  The destruction is done explicitly by invoking 
	   the object's message function directly because the message dispatcher 
	   checks to make sure that they're never destroyed through a standard 
	   message, which would indicate a programming error */
	for( objectHandle = SYSTEM_OBJECT_HANDLE + 1;
		 objectHandle < NO_SYSTEM_OBJECTS; objectHandle++ )
		destroyObject( objectHandle );

	/* Postcondition: All system objects except the root system object have
	   been destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, NO_SYSTEM_OBJECTS,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Delete any unclaimed leftover objects.  This is rather more complex
	   than just rumbling through deleting each object we find since some
	   objects have dependent objects underneath them, and deleting the
	   lower-level object causes problems when we later delete their parents
	   (the code handles it cleanly, but we get a kernel trap warning us that
	   we're trying to delete a non-present object).  Because of this we have
	   to delete the objects in order of depth, first all three-level objects
	   (e.g. cert -> context -> device), then all two-level objects, and
	   finally all one-level objects.  This means that we can never delete 
	   another object out from under a dependent object */
	for( depth = 3; depth > 0; depth-- )
		{
		int localStatus = destroySelectedObjects( depth );

		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}

	/* Postcondition: All objects except the root system object have been
	   destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, krnlData->objectTableSize,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Finally, destroy the system root object */
	destroyObject( SYSTEM_OBJECT_HANDLE );

	/* Unlock the object table to allow access by other threads */
	MUTEX_UNLOCK( objectTable );

	return( status );
	}

/****************************************************************************
*																			*
*							Object Creation/Destruction						*
*																			*
****************************************************************************/

/* Create a new object.  This function has to be very careful about locking
   to ensure that another thread can't manipulate the newly-created object
   while it's in an indeterminate state.  To accomplish this it locks the
   object table and tries to create the new object.  If this succeeds it sets
   the OBJECT_FLAG_NOTINITED flag pending completion of the object's
   initialisation by the caller, unlocks the object table, and returns
   control to the caller.  While the object is in this state, the kernel
   will allow it to process only two message types, either a notification
   from the caller that the init stage is complete (which sets the object's
   state to OK), or a destroy object message, which sets the
   OBJECT_FLAG_SIGNALLED flag pending arrival of the init complete
   notification, whereupon the object is immediately destroyed.  The state
   diagram for this is:
									 State
						  Notinited			Signalled
			--------+-------------------+-----------------
			-> OK	| state -> OK,		| Msg -> Destroy
					| ret( OK )			|
	Msg.	Destroy	| state -> Sig'd,	| state -> Sig'd,
					| ret( OK )			| ret( OK )
			CtrlMsg	| process as usual	| process as usual
			NonCtrl	| ret( Notinited )	| ret( Sig'd )

   The initialisation process for an object is therefore:

	status = krnlCreateObject( ... );
	if( cryptStatusError( status ) )
		return( status );

	// Complete object-specific initialisation
	initStatus = ...;

	status = krnlSendMessage( ..., state -> CRYPT_OK );
	return( ( cryptStatusError( initStatus ) ? initStatus : status );

   If the object is destroyed during the object-specific initialisation
   (either by the init code when an error is encountered or due to an
   external signal), the destroy is deferred until the change state message
   at the end occurs.  If a destroy is pending, the change state is converted
   to a destroy and the newly-created object is destroyed.

   This mechanism ensures that the object table is only locked for a very
   short time (typically for only a few lines of executed code in the create
   object function) so that slow initialisation (for example of keyset
   objects associated with network links) can't block other objects.

   In addition to the locking, we need to be careful with how we create new
   objects because if we just allocate handles sequentially and reuse handles
   as soon as possible, an existing object could be signalled and a new one
   created in its place without the caller or owning object realizing that
   they're now working with a different object (although the kernel can tell
   them apart because it maintains an internal unique ID for each object).
   Unix systems handle this by always incrementing pids and assuming that 
   there won't be any problems when they wrap, we do the same thing but in
   addition allocate handles in a non-sequential manner using an LFSR to
   step through the object table.  There's no strong reason for this apart 
   from helping disabuse users of the notion that any cryptlib objects have 
   stdin/stdout-style fixed handles, but it only costs a few extra clocks so 
   we may as well do it */

static int findFreeResource( int value )
	{
	int oldValue = value, iterations;

	/* Preconditions: We're starting with a valid object handle, and it's not
	   a system object */
	PRE( isValidHandle( value ) );
	PRE( value >= NO_SYSTEM_OBJECTS );

	/* Step through the entire table looking for a free entry */
	for( iterations = 0; isValidHandle( value ) && \
						 iterations < krnlData->objectTableSize; \
		 iterations++ )
		{
		INV( iterations < krnlData->objectTableSize );

		/* Get the next value: Multiply by x and reduce by the polynomial */
		value <<= 1;
		if( value & krnlData->objectStateInfo.lfsrMask )
			value ^= krnlData->objectStateInfo.lfsrPoly;

		INV( isValidHandle( value ) );

		/* If we've found a free object or we've covered the entire table, 
		   exit.  We do this check after we update the value rather than as
		   part of the loop test to ensure that we always progress to a new
		   object handle whenever we call this function.  If we did the 
		   check as part of the loop test then deleting and creating an
		   object would result in the handle of the deleted object being
		   re-assigned to the new object */
		if( isFreeObject( value ) || value == oldValue )
			break;
		}
	if( value == oldValue || iterations >= krnlData->objectTableSize || \
		!isValidHandle( value ) )
		{
		/* Postcondition: We tried all locations and there are no free slots
		   available (or, vastly less likely, an internal error has 
		   occurred) */
		POST( iterations == krnlData->objectTableSize - 1 );
		FORALL( i, 0, krnlData->objectTableSize,
				krnlData->objectTable[ i ].objectPtr != NULL );

		return( CRYPT_ERROR );
		}

	/* Postconditions: We found a handle to a free slot */
	POST( isValidHandle( value ) );
	POST( isFreeObject( value ) );

	return( value );
	}

static int expandObjectTable( void )
	{
	static const int lfsrPolyTable[] = \
							{	  0x83,	   0x11D,	 0x211,	   0x409,
								 0x805,   0x1053,   0x201B,   0x402B,
								0x8003,  0x1002D,  0x20009,  0x40027,
							   0x80027, 0x100009, 0x200005, 0x400003 };
	OBJECT_INFO *newTable;
	int objectHandle, i;
	ORIGINAL_INT_VAR( oldLfsrPoly, krnlData->objectStateInfo.lfsrPoly );

	/* If we're already at the maximum number of allowed objects, don't
	   create any more.  This prevents both accidental runaway code that
	   creates huge numbers of objects and DoS attacks */
	if( krnlData->objectTableSize >= MAX_OBJECTS )
		return( CRYPT_ERROR_MEMORY );

	/* Precondition: We haven't exceeded the maximum number of objects */
	PRE( krnlData->objectTableSize < MAX_OBJECTS );

	/* Expand the table */
	newTable = clDynAlloc( "krnlCreateObject", \
						   ( krnlData->objectTableSize * 2 ) * \
								sizeof( OBJECT_INFO ) );
	if( newTable == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Copy the information across to the new table, set up the newly-
	   allocated entries, and clear the old table */
	memcpy( newTable, krnlData->objectTable,
			krnlData->objectTableSize * sizeof( OBJECT_INFO ) );
	for( i = krnlData->objectTableSize; \
		 i < krnlData->objectTableSize * 2; i++ )
		newTable[ i ] = OBJECT_INFO_TEMPLATE;
	zeroise( krnlData->objectTable, \
			 krnlData->objectTableSize * sizeof( OBJECT_INFO ) );
	clFree( "krnlCreateObject", krnlData->objectTable );
	krnlData->objectTable = newTable;
	krnlData->objectTableSize *= 2;

	/* Add the new object at the end of the existing table */
	krnlData->objectStateInfo.lfsrMask <<= 1;
	for( i = 0; i < 16; i++ )
		if( lfsrPolyTable[ i ] > krnlData->objectStateInfo.lfsrPoly )
			break;
	krnlData->objectStateInfo.lfsrPoly = lfsrPolyTable[ i ];
	objectHandle = findFreeResource( krnlData->objectStateInfo.objectHandle );

	/* Postcondition: We've moved on to the next LFSR polynomial value,
	   the LFSR output covers the entire table, and we now have roonm for 
	   the new object */
	POST( ( krnlData->objectStateInfo.lfsrPoly & ~0x7F ) == \
		  ( ORIGINAL_VALUE( oldLfsrPoly ) & ~0xFF ) << 1 );
	POST( krnlData->objectStateInfo.lfsrMask == \
		  ( krnlData->objectStateInfo.lfsrPoly & ~0x7F ) );
	POST( krnlData->objectTableSize == krnlData->objectStateInfo.lfsrMask );
	POST( isValidHandle( objectHandle ) );

	return( objectHandle );
	}

int krnlCreateObject( void **objectDataPtr, const int objectDataSize,
					  const OBJECT_TYPE type, const int subType,
					  const int createObjectFlags, const CRYPT_USER owner,
					  const int actionFlags,
					  MESSAGE_FUNCTION messageFunction )
	{
	OBJECT_INFO objectInfo;
	OBJECT_STATE_INFO *objectStateInfo = &krnlData->objectStateInfo;
	int objectHandle = objectStateInfo->objectHandle, bitCount;

	/* Preconditions (the subType check is just the standard hakmem bitcount
	   which ensures that we don't try and create multi-typed objects, the
	   sole exception to this rule is the default user object, which acts as
	   both a user and an SO object) */
	PRE( isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) );
	PRE( isWritePtr( objectDataPtr, sizeof( void * ) ) );
	PRE( objectDataSize > 16 && objectDataSize < 16384 );
	PRE( isValidType( type ) );
	PRE( ( bitCount = ( subType & ~SUBTYPE_CLASS_MASK ) - \
						( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 1 ) & 033333333333 ) - \
						( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 2 ) & 011111111111 ) ) != 0 );
	PRE( ( ( bitCount + ( bitCount >> 3 ) ) & 030707070707 ) % 63 == 1 );
	PRE( !( createObjectFlags & \
			~( CREATEOBJECT_FLAG_SECUREMALLOC | CREATEOBJECT_FLAG_DUMMY ) ) );
	PRE( owner == CRYPT_UNUSED || isValidHandle( owner ) );
	PRE( actionFlags >= 0 && actionFlags < ACTION_PERM_LAST );
	PRE( messageFunction != NULL );

	/* Enforce the parameter check explicitly at runtime as well */
	bitCount = ( subType & ~SUBTYPE_CLASS_MASK ) - \
			   ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 1 ) & 033333333333 ) - \
			   ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 2 ) & 011111111111 );
	if( !isWritePtr( objectDataPtr, sizeof( void * ) ) || \
		objectDataSize <= 16 || objectDataSize >= 16384 || \
		!isValidType( type ) || \
		( ( bitCount + ( bitCount >> 3 ) ) & 030707070707 ) % 63 != 1 || \
		( createObjectFlags & \
			~( CREATEOBJECT_FLAG_SECUREMALLOC | CREATEOBJECT_FLAG_DUMMY ) ) || \
		( owner != CRYPT_UNUSED && !isValidHandle( owner ) ) || \
		actionFlags < 0 || actionFlags >= ACTION_PERM_LAST || \
		messageFunction == NULL )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	*objectDataPtr = NULL;

	/* If we haven't been initialised yet or we're in the middle of a 
	   shutdown, we can't create any new objects */
	if( !isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) || \
		!krnlData->isInitialised )
		return( CRYPT_ERROR_NOTINITED );
	if( krnlData->isClosingDown )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Allocate memory for the object and set up the object table entry.  The
	   object is always created as an internal object, it's up to the caller
	   to make it externally visible.  Since this step doesn't access the
	   object table, we do it outside the locked section */
	if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
		{
		int status = krnlMemalloc( objectDataPtr, objectDataSize );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		if( ( *objectDataPtr = clAlloc( "krnlCreateObject", \
										objectDataSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
	memset( *objectDataPtr, 0, objectDataSize );
	objectInfo = OBJECT_INFO_TEMPLATE;
	objectInfo.objectPtr = *objectDataPtr;
	objectInfo.objectSize = objectDataSize;
	if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
		objectInfo.flags |= OBJECT_FLAG_SECUREMALLOC;
	objectInfo.owner = owner;
	objectInfo.type = type;
	objectInfo.subType = subType;
	objectInfo.actionFlags = actionFlags;
	objectInfo.uniqueID = krnlData->objectUniqueID;
	objectInfo.messageFunction = messageFunction;

	/* Make sure that the kernel has been initialised and lock the object 
	   table for exclusive access */
	MUTEX_LOCK( initialisation );
	MUTEX_LOCK( objectTable );
	MUTEX_UNLOCK( initialisation );

	/* The first objects created are internal objects with predefined
	   handles (spes lucis aeternae).  As we create these objects we ratchet
	   up through the fixed handles until we reach the last fixed object,
	   whereupon we allocate handles normally */
	if( objectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
		PRE( ( objectHandle == SYSTEM_OBJECT_HANDLE - 1 && \
			   owner == CRYPT_UNUSED && \
			   type == OBJECT_TYPE_DEVICE && \
			   subType == SUBTYPE_DEV_SYSTEM ) || \
			 ( objectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 && \
			   owner == SYSTEM_OBJECT_HANDLE && \
			   type == OBJECT_TYPE_USER && \
			   subType == SUBTYPE_USER_SO ) );
		objectHandle++;
		POST( isValidHandle( objectHandle ) && \
			  objectHandle < NO_SYSTEM_OBJECTS && \
			  objectHandle == objectStateInfo->objectHandle + 1 );
		}
	else
		{
		PRE( isValidHandle( owner ) );

		/* Search the table for a free entry */
		objectHandle = findFreeResource( objectHandle );
		}

	/* If the table is full, expand it */
	if( !isValidHandle( objectHandle ) )
		{
		objectHandle = expandObjectTable();
		if( cryptStatusError( objectHandle ) )
			{
			MUTEX_UNLOCK( objectTable );

			/* Free the object instance data storage that we allocated 
			   earlier */
			if( objectInfo.flags & OBJECT_FLAG_SECUREMALLOC )
				krnlMemfree( &objectInfo.objectPtr );
			else
				{
				zeroise( objectInfo.objectPtr, objectInfo.objectSize );
				clFree( "destroyObjectData", objectInfo.objectPtr );
				}
			return( objectHandle );
			}
		}

	/* Inner precondition: This object table slot is free */
	PRE( isFreeObject( objectHandle ) );

	/* Set up the new object entry in the table and update the object table
	   state */
	krnlData->objectTable[ objectHandle ] = objectInfo;
	if( objectHandle == NO_SYSTEM_OBJECTS - 1 )
		{
		/* If this is the last system object, we've been allocating handles
		   sequentially up to this point.  From now on we start allocating
		   handles starting from a randomised location in the table */
		objectStateInfo->objectHandle = \
			( ( int ) getTime() ) & ( objectStateInfo->lfsrMask - 1 );
		if( objectStateInfo->objectHandle < NO_SYSTEM_OBJECTS )
			/* Can occur with probability 
			   NO_SYSTEM_OBJECTS / OBJECT_TABLE_ALLOCSIZE */
			objectStateInfo->objectHandle = NO_SYSTEM_OBJECTS + 42;
		}
	else
		objectStateInfo->objectHandle = objectHandle;

	/* Update the object unique ID value */
	if( krnlData->objectUniqueID < 0 || \
		krnlData->objectUniqueID >= INT_MAX - 1 )
		krnlData->objectUniqueID = NO_SYSTEM_OBJECTS;
	else
		krnlData->objectUniqueID++;
	POST( krnlData->objectUniqueID > 0 && \
		  krnlData->objectUniqueID < INT_MAX );

	/* Postconditions: It's a valid object that's been set up as required */
	POST( isValidObject( objectHandle ) );
	POST( objectInfo.objectPtr == *objectDataPtr );
	POST( objectInfo.owner == owner );
	POST( objectInfo.type == type );
	POST( objectInfo.subType == subType );
	POST( objectInfo.actionFlags == actionFlags );
	POST( objectInfo.messageFunction == messageFunction );

	MUTEX_UNLOCK( objectTable );
	return( objectHandle );
	}
