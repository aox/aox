/****************************************************************************
*																			*
*							cryptlib Security Kernel						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#ifndef NDEBUG
#include <stdio.h>	/* Needed for POST macro on some systems */
#endif /* Debug version */
#include "crypt.h"
#include "cryptacd.h"

/* RAY and EGON look over code.

   EGON: The structure of this kernel is exactly like the kind of telemetry
         tracker that NASA uses to secure dead pulsars in deep space.

   RAY: All message dispatch mechanisms and callback functions.

   PETER (to other jailbirds): Everyone getting this so far?  So what?  I
         guess they just don't make them like they used to.

   RAY: No!  Nobody ever made them like this!  The architect was either a
        certified genius or an authentic wacko! */

/* "There is a fine line between genius and insanity.  I have erased this
    line" - Oscar Levant (or "Nullum magnum ingenium sine mixtura dementiae"
	if you want it in the usual style) */

/* The initialisation state and a lock to protect it.  The object
   management functions check the state before they do anything and return
   CRYPT_INITED if cryptlib hasn't been initialised.  Since everything in
   cryptlib depends on the creation of objects, any attempts to use cryptlib
   without it being properly initialised are caught.

   Reading the isInitialised flag presents something of a chicken-and-egg
   problem since the read should be protected by the intialisation mutex, but
   we can't try and grab it unless the mutex has been initialised.  If we
   just read the flag directly and rely on the object map mutex to protect
   access we run into a potential race condition on shutdown:

	thread1							thread2

	inited = T						read inited = T
	inited = F, destroy objects
									lock objects, die

   The usual way to avoid this is to perform an interlocked mutex lock, but
   this isn't possible here since the initialisation mutex may not be
   initialised.  Under Win32 it's set by DllMain() */

DECLARE_LOCKING_VARS( initialisation )
static BOOLEAN isInitialised = FALSE;
static BOOLEAN isClosingDown = FALSE;

/* Some messages communicate standard data values that are used again and
   again so we predefine values for these that can be used globally */

const int messageValueTrue = TRUE;
const int messageValueFalse = FALSE;
const int messageValueCryptOK = CRYPT_OK;
const int messageValueCryptError = CRYPT_ERROR;
const int messageValueCryptSignalled = CRYPT_ERROR_SIGNALLED;
const int messageValueCryptUnused = CRYPT_UNUSED;
const int messageValueCryptUseDefault = CRYPT_USE_DEFAULT;
const int messageValueCursorFirst = CRYPT_CURSOR_FIRST;
const int messageValueCursorNext = CRYPT_CURSOR_NEXT;
const int messageValueCursorPrevious = CRYPT_CURSOR_PREVIOUS;
const int messageValueCursorLast = CRYPT_CURSOR_LAST;

/****************************************************************************
*																			*
*						Object Definitions and Information					*
*																			*
****************************************************************************/

/* Macros to perform validity checks on objects and handles.  These checks
   are:

	isValidHandle(): Whether a handle is a valid index into the object table.
	isValidObject(): Whether a handle refers to an object in the table.
	isFreeObject(): Whether a handle refers to an empty entry in the table.
	isInternalObject(): Whether an object is an internal object.
	isInvalidObjectState(): Whether an object is in an invalid (error) state.
	isInUse(): Whether an object is currently in use (processing a message).
	isObjectOwner(): if inUse == TRUE, whether this thread is the one using
					 the object.
	isInHighState(): Whether an object is in the 'high' security state.
	isSameOwningObject(): Whether two objects have the same owner.  We also
						  have to handle the situation where the first object
						  is a user object, in which case it has to be the
						  owner of the second object.
	isAliasedObject(): Whether an object is an alias for another object and
					   subject to copy-on-write.
	isClonedObject(): Whether an aliased object is the original or the clone.
	isObjectAccessValid(): Internal/external object access check.
	isValidMessage(): Whether a message type is valid.
	isValidType(): Whether an object type is valid
	isValidSubtype(): Whether an object subtype is allowed based on access
					  bitflags */

#define isValidHandle( handle ) \
		( ( handle ) >= 0 && ( handle ) < objectTableSize )
#define isValidObject( handle ) \
		( isValidHandle( handle ) && objectTable[ ( handle ) ].objectPtr != NULL )
#define isFreeObject( handle ) \
		( isValidHandle( handle ) && objectTable[ ( handle ) ].objectPtr == NULL )
#define isInternalObject( handle ) \
		( objectTable[ handle ].flags & OBJECT_FLAG_INTERNAL )
#define isObjectAccessValid( objectHandle, message ) \
		!( isInternalObject( objectHandle ) && \
		   !( message & MESSAGE_FLAG_INTERNAL ) )
#define isInvalidObjectState( handle ) \
		( objectTable[ ( handle ) ].flags & OBJECT_FLAGMASK_STATUS )
#define isInUse( handle ) \
		( objectTable[ ( handle ) ].lockCount > 0 )
#define isObjectOwner( handle ) \
		THREAD_SAME( objectTable[ ( handle ) ].lockOwner, THREAD_SELF() )
#define isInHighState( handle ) \
		( objectTable[ ( handle ) ].flags & OBJECT_FLAG_HIGH )
#define isSameOwningObject( handle1, handle2 ) \
		( objectTable[ ( handle1 ) ].owner == CRYPT_UNUSED || \
		  objectTable[ ( handle2 ) ].owner == CRYPT_UNUSED || \
		  ( objectTable[ ( handle1 ) ].owner == objectTable[ ( handle2 ) ].owner ) || \
		  ( ( handle1 ) == objectTable[ ( handle2 ) ].owner ) )
#define isAliasedObject( handle ) \
		( objectTable[ handle ].flags & OBJECT_FLAG_ALIASED )
#define isClonedObject( handle ) \
		( objectTable[ handle ].flags & OBJECT_FLAG_CLONE )
#define isValidMessage( message ) \
		( ( message ) > MESSAGE_NONE && ( message ) < MESSAGE_LAST )
#define isValidType( type ) \
		( ( type ) > OBJECT_TYPE_NONE && ( type ) < OBJECT_TYPE_LAST )
#define isValidSubtype( subtypeMask, subtype ) \
		( ( ( subtypeMask ) & ( subtype ) ) == ( subtype ) )

/* Macros to test whether a message falls into a certain class.  These tests
   are:

	isParamMessage(): Whether a message contains an object as a parameter */

#define isParamMessage( message ) \
		( ( message ) == MESSAGE_CRT_SIGN || \
		  ( message ) == MESSAGE_CRT_SIGCHECK )

/* Macros to manage object ownership, if the OS supports it */

#define checkObjectOwnership( objectPtr ) \
		( !( ( objectPtr ).flags & OBJECT_FLAG_OWNED ) || \
		  THREAD_SAME( ( objectPtr ).objectOwner, THREAD_SELF() ) )

/* A macro to turn an abnormal status indicated in an object's flags into a
   status code.  The values are prioritised so notinited > signalled > busy */

#define getObjectStatusValue( flags ) \
		( ( flags & OBJECT_FLAG_NOTINITED ) ? CRYPT_ERROR_NOTINITED : \
		  ( flags & OBJECT_FLAG_SIGNALLED ) ? CRYPT_ERROR_SIGNALLED : \
		  ( flags & OBJECT_FLAG_BUSY ) ? CRYPT_ERROR_TIMEOUT : CRYPT_OK )

/* The initial allocation size of the object table.  In memory-starved
   environments we limit the size, in general these are embedded systems or
   single-tasking OSs that aren't going to need many objects anyway */

#ifdef CONFIG_CONSERVE_MEMORY
  #define OBJECT_TABLE_ALLOCSIZE	128
  #define INITIAL_LFSRPOLY			0x83
#else
  #define OBJECT_TABLE_ALLOCSIZE	1024
  #define INITIAL_LFSRPOLY			0x409
#endif /* Memory-starved environments */

/* The information maintained by the kernel for each object */

typedef struct {
	/* Object type and value */
	OBJECT_TYPE type;			/* Object type */
	int subType;				/* Object subtype */
	void *objectPtr;			/* Object data */

	/* Object properties */
	int flags;					/* Internal-only, locked, etc */
	int actionFlags;			/* Permitted actions */
	int referenceCount;			/* Number of references to this object */
	int lockCount;				/* Message-processing lock recursion count */
	THREAD_HANDLE lockOwner;	/* Lock owner if lockCount > 0 */
	unsigned int uniqueID;		/* Unique ID for this object */
/*	time_t lastAccess;			// Last access time */

	/* Object security properties */
	int forwardCount;			/* Number of times ownership can be transferred */
	int usageCount;				/* Number of times obj.can be used */
	THREAD_HANDLE objectOwner;	/* The object's owner */

	/* Object methods */
	MESSAGE_FUNCTION messageFunction;
								/* The object's message handler */
	/* Owning and dependent objects */
	CRYPT_USER owner;			/* Owner object handle */
	CRYPT_HANDLE dependentObject;	/* Dependent object (context or cert) */
	CRYPT_HANDLE dependentDevice;	/* Dependent crypto device */
	CRYPT_HANDLE clonedObject;	/* Cloned object if aliased */
	} OBJECT_INFO;

/* The flags that apply to each object in the table */

#define OBJECT_FLAG_NONE		0x0000	/* Non-flag */
#define OBJECT_FLAG_INTERNAL	0x0001	/* Internal-use only */
#define OBJECT_FLAG_NOTINITED	0x0002	/* Still being initialised */
#define OBJECT_FLAG_HIGH		0x0004	/* In 'high' security state */
#define OBJECT_FLAG_SIGNALLED	0x0008	/* In signalled state */
#define OBJECT_FLAG_BUSY		0x0010	/* Busy with async.op */
#define OBJECT_FLAG_ALIASED		0x0020	/* Object is alias for another object */
#define OBJECT_FLAG_CLONE		0x0040	/* Aliased object is the clone */
#define OBJECT_FLAG_OWNED		0x0080	/* Object is bound to a thread */
#define OBJECT_FLAG_ATTRLOCKED	0x0100	/* Security properties can't be modified */

/* The flags that convey information about an object's status */

#define OBJECT_FLAGMASK_STATUS \
		( OBJECT_FLAG_NOTINITED | OBJECT_FLAG_BUSY | OBJECT_FLAG_SIGNALLED )

/* The table to map external object handles to object data */

static OBJECT_INFO *objectTable;
static int objectTableSize;
DECLARE_LOCKING_VARS( objectTable )
static unsigned int objectUniqueID;

/* A template used to initialise object table entries.  Some of the entries
   are either object handles that have to be set to CRYPT_ERROR or values
   for which 0 is significant (so they're set to CRYPT_UNUSED), because of
   this we can't just memset the entry to all zeroes */

static const OBJECT_INFO OBJECT_INFO_TEMPLATE = {
	OBJECT_TYPE_NONE, 0, NULL,	/* Type, subtype, and data pointer */
	OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED,	/* Flags */
	0,							/* Action flags */
	0, 0, THREAD_INITIALISER, 	/* Ref.count, lock count, lock owner */
	0,							/* Unique ID */
	CRYPT_UNUSED, CRYPT_UNUSED,	THREAD_INITIALISER,
								/* Forward count, usage count, owner */
	NULL,						/* Message function */
	CRYPT_ERROR, CRYPT_ERROR,
	CRYPT_ERROR, CRYPT_ERROR	/* Owning/dependent objects */
	};

/* The object allocation state data and a template used to initialise it.
   This controls the allocation of handles to newly-created objects.  The
   first NO_SYSTEM_OBJECTS handles are system objects that exist with
   fixed handles, the remainder are allocated pseudorandomly under the
   control of an LFSR (see the comments further down for more details on
   this) */

typedef struct {
	int lfsrMask, lfsrPoly;		/* LFSR state values */
	int objectHandle;			/* Current object handle */
	} OBJECT_STATE_INFO;

static const OBJECT_STATE_INFO OBJECT_STATE_INFO_TEMPLATE = {
	OBJECT_TABLE_ALLOCSIZE,		/* Mask for LFSR output */
	INITIAL_LFSRPOLY,			/* LFSR polynomial */
	-1							/* Initial-1'th object handle */
	};
static OBJECT_STATE_INFO objectStateInfo;

/* Create and destroy the object table.  The destroy process is handled in
   two stages, the first of which is called fairly early in the shutdown
   process to destroy any remaining objects, and the second which is called
   at the end of the shutdown when the kernel data is being deleted.  This
   is because some of the objects are tied to things like external devices,
   and deleting them at the end when everything else has been shut down
   isn't possible */

static int initObjectTable( void )
	{
	int i;

	/* Allocate and initialise the object table */
	objectTable = clAlloc( "initObjectTable", 
						   OBJECT_TABLE_ALLOCSIZE * sizeof( OBJECT_INFO ) );
	if( objectTable == NULL )
		return( CRYPT_ERROR_MEMORY );
	for( i = 0; i < OBJECT_TABLE_ALLOCSIZE; i++ )
		objectTable[ i ] = OBJECT_INFO_TEMPLATE;
	objectTableSize = OBJECT_TABLE_ALLOCSIZE;
	objectStateInfo = OBJECT_STATE_INFO_TEMPLATE;

	/* Initialise object-related information.  This isn't strictly part of
	   the object table but is used to assing unique ID values to objects
	   within the table, since table entries (object handles) may be reused
	   as objects are destroyed and new ones created in their place */
	objectUniqueID = 0;

	/* Initialize any data structures required to make the object table
	   thread-safe */
	initResourceLock( objectTable );

	/* Postconditions */
	POST( objectTable != NULL );
	POST( objectTableSize == OBJECT_TABLE_ALLOCSIZE );
	FORALL( i, 0, OBJECT_TABLE_ALLOCSIZE,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );
	POST( objectStateInfo.lfsrMask == OBJECT_TABLE_ALLOCSIZE && \
		  objectStateInfo.lfsrPoly == INITIAL_LFSRPOLY && \
		  objectStateInfo.objectHandle == SYSTEM_OBJECT_HANDLE - 1 );
	POST( objectUniqueID == 0 );

	return( CRYPT_OK );
	}

static int destroySelectedObjects( const int currentDepth )
	{
	int objectHandle, status = CRYPT_OK;

	for( objectHandle = NO_SYSTEM_OBJECTS; objectHandle < objectTableSize;
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
		if( dependentObject != CRYPT_ERROR )
			depth = \
				( objectTable[ dependentObject ].dependentObject != CRYPT_ERROR || \
				  objectTable[ dependentObject ].dependentDevice != CRYPT_ERROR ) ? \
				3 : 2;
		else
			if( objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
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
			unlockResource( objectTable );
			krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
			status = CRYPT_ERROR_INCOMPLETE;
			lockResource( objectTable );
			}
		}

	return( status );
	}

int destroyObjects( void )
	{
	int depth, objectHandle, status = CRYPT_OK;

	/* Indicate that we're in the middle of a shutdown.  From now on all
	   messages other than object-destruction ones will be rejected by the
	   kernel.  This is needed in order to have any remaining active objects
	   exit quickly, since we don't want them to block the shutdown.  Note
	   that we do this before we lock the object table to encourage anything
	   that might have the table locked to exit quickly */
	isClosingDown = TRUE;

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	lockResource( objectTable );

	/* Destroy all system objects except the root system object ("The death of
	   God left the angels in a strange position" - Donald Barthelme, "On
	   Angels").  We have to do this before we destroy any unclaimed leftover
	   objects because some of them may depend on system objects, if the
	   system objects aren't destroyed they'll be erroneously flagged as
	   leftover objects.  The destruction is done explicitly by invoking the
	   object's message function directly because the dispatcher checks to
	   make sure that they're never destroyed through a standard message,
	   which indicates a programming error */
	for( objectHandle = SYSTEM_OBJECT_HANDLE + 1;
		 objectHandle < NO_SYSTEM_OBJECTS; objectHandle++ )
		{
		if( objectTable[ objectHandle ].messageFunction != NULL )
			objectTable[ objectHandle ].messageFunction( \
									objectTable[ objectHandle ].objectPtr,
									MESSAGE_DESTROY, NULL, 0 );
		objectTable[ objectHandle ] = OBJECT_INFO_TEMPLATE;
		}

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
	   finally all one-level objects.  This means we can never delete another
	   object out from under a dependent object */
	for( depth = 3; depth > 0; depth-- )
		{
		int localStatus = destroySelectedObjects( depth );

		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}

	/* Postcondition: All objects except the root system object have been
	   destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, objectTableSize,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Finally, destroy the root system object */
	objectTable[ SYSTEM_OBJECT_HANDLE ].messageFunction( \
								objectTable[ SYSTEM_OBJECT_HANDLE ].objectPtr,
								MESSAGE_DESTROY, NULL, 0 );
	objectTable[ SYSTEM_OBJECT_HANDLE ] = OBJECT_INFO_TEMPLATE;

	/* Unlock the object table to allow access by other threads */
	unlockResource( objectTable );

	return( status );
	}

static void endObjectTable( void )
	{
	/* Hinc igitur effuge */
	lockResource( objectTable );
	zeroise( objectTable, objectTableSize * sizeof( OBJECT_INFO ) );
	clFree( "endObjectTable", objectTable );
	objectTable = NULL;
	isClosingDown = FALSE;
	unlockResource( objectTable );
	deleteResourceLock( objectTable );
	}

/****************************************************************************
*																			*
*						Alternative Object Acquisition						*
*																			*
****************************************************************************/

/* Sending a message to an object only makes the one object which is the
   target of the message available for use.  When we need simultaneous
   access to two objects (for example when copying a collection of cert
   extensions from one cert to another), we have to use the krnlGetObject()/
   krnlReleaseObject() functions to obtain access to the second object's
   internals.  These two functions can only provide access to certificates
   (used when copying internal state such as cert extensions or CRL info
   from one cert object to another), crypt hardware devices other than the
   system object (used when a context tied to a device needs to perform an
   operation using the device), and user objects (when committing config
   data to persistent storage, we don't actually use the object data but
   merely unlock it to allow others access while performing the potentially
   lengthy update).

   There is a second situation in which we need access to an object's
   internals, and that occurs when we need to export/import a key from/to
   a context.  This is handled via the key extract functions at the end
   of this module, see the comments there for further information */

/* Wait for an object to become available so that we can use it, with a
   timeout for blocked objects.  This is an internal function which is used
   when mapping an object handle to object data, and is never called
   directly.  As an aid in identifying objects acting as bottlenecks, we
   provide a function to warn about excessive waiting, along with information
   on the object that was waited on, in debug mode */

#define MAX_WAITCOUNT				10000
#define WAITCOUNT_WARN_THRESHOLD	10

#ifndef NDEBUG

#include <stdio.h>

static void waitWarn( const int objectHandle, const int waitCount )
	{
	static const char *objectTypeNames[] = {
		"None", "Context", "Keyset", "Envelope", "Certificate", "Device",
		"Session", "User", "None", "None"
		};
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	char buffer[ 128 ];

	if( objectHandle == SYSTEM_OBJECT_HANDLE )
		strcpy( buffer, "system object" );
	else
		sPrintf( buffer, "%d (type %s, subtype %lX)",
				 objectHandle, objectInfoPtr->type, objectInfoPtr->subType );
	fprintf( stderr, "\nWarning: Thread %X waited %d iteration%s for %s.\n",
			 THREAD_SELF(), waitCount, ( waitCount == 1 ) ? "" : "s",
			 buffer );
	}
#endif /* Debug mode only */

static int waitForObject( const int objectHandle,
						  OBJECT_INFO **objectInfoPtrPtr )
	{
	const unsigned int uniqueID = objectTable[ objectHandle ].uniqueID;
	int waitCount = 0;

	/* Preconditions: The object is in use by another thread */
	PRE( isValidObject( objectHandle ) );
	PRE( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) );

	/* While the object is busy, put the thread to sleep.  This is the
	   optimal portable way to wait on the resource, since it gives up this
	   thread's timeslice to allow other threads (including the one using
	   the object) to run (other methods such as mutexes with timers are
	   difficult to manage portably across different platforms) */
	while( objectTable[ objectHandle ].uniqueID == uniqueID && \
		   isInUse( objectHandle ) && waitCount < MAX_WAITCOUNT && \
		   !isClosingDown )
		{
		unlockResource( objectTable );
		waitCount++;
		THREAD_YIELD();
		lockResource( objectTable );
		}
#ifndef NDEBUG
	if( waitCount > WAITCOUNT_WARN_THRESHOLD )
		/* If we waited more than WAITCOUNT_WARN_THRESHOLD iterations for
		   something this could be a sign of a resource usage bottleneck,
		   warn the user that there's a potential problem */
		waitWarn( objectHandle, waitCount );
#endif /* NDEBUG */

	/* If cryptlib is shutting down, exit */
	if( isClosingDown )
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

/* Release an object that we previously acquired directly.  Note that we can
   release the system object here (done when we don't need it any more but
   need to carry out further operations with other objects), but we can't
   ever acquire it */

static int releaseObject( const int objectHandle,
						  const BOOLEAN isNonKernelCall )
	{
	OBJECT_INFO *objectInfoPtr;
	DECLARE_ORIGINAL_INT( lockCount );

	lockResource( objectTable );

	/* Preconditions: The object is in use by the caller */
	PRE( isValidObject( objectHandle ) );
	PRE( isInUse( objectHandle ) && isObjectOwner( objectHandle ) );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(): It's a valid object owned by the calling
	   thread */
	if( !isValidObject( objectHandle ) || \
		!checkObjectOwnership( objectTable[ objectHandle ] ) )
		{
		unlockResource( objectTable );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];
	STORE_ORIGINAL_INT( lockCount, objectInfoPtr->lockCount );

	/* Inner precondition: The object is in use and is of the correct type */
	PRE( isInUse( objectHandle ) && isObjectOwner( objectHandle ) );
	PRE( ( isNonKernelCall && \
					( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE || \
					  objectInfoPtr->type == OBJECT_TYPE_DEVICE || \
					  objectInfoPtr->type == OBJECT_TYPE_USER ) ) || \
		 ( !isNonKernelCall && objectInfoPtr->type == OBJECT_TYPE_CONTEXT ) );

	/* Safety check: We should never be releasing an object that we don't
	   hold or which is of the incorrect type */
	if( !isInUse( objectHandle ) || !isObjectOwner( objectHandle ) )
		{
		unlockResource( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}
	if( ( isNonKernelCall && \
		  objectInfoPtr->type != OBJECT_TYPE_CERTIFICATE && \
		  objectInfoPtr->type != OBJECT_TYPE_DEVICE && \
		  objectInfoPtr->type != OBJECT_TYPE_USER ) || \
		( !isNonKernelCall && objectInfoPtr->type != OBJECT_TYPE_CONTEXT ) )
		{
		unlockResource( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	objectInfoPtr->lockCount--;

	/* Postcondition: The object's lock count has been decremented and is
	   non-negative */
	POST( objectInfoPtr->lockCount == \
							ORIGINAL_VALUE( lockCount ) - 1 );
	POST( objectInfoPtr->lockCount >= 0 );

	unlockResource( objectTable );
	return( CRYPT_OK );
	}

/* Acquire/release an object */

int krnlGetObject( const int objectHandle, const OBJECT_TYPE type,
				   void **objectPtr, const int errorCode )
	{
	OBJECT_INFO *objectInfoPtr;
	int status = CRYPT_OK;

	/* Preconditions: It's a valid object */
	PRE( isValidHandle( objectHandle ) && \
		 objectHandle != SYSTEM_OBJECT_HANDLE );
	PRE( isValidType( type ) && \
		 ( type == OBJECT_TYPE_CERTIFICATE || \
		   type == OBJECT_TYPE_DEVICE || type == OBJECT_TYPE_USER ) );
	PRE( isWritePtr( objectPtr, sizeof( void * ) ) );

	/* Clear the return value */
	*objectPtr = NULL;

	lockResource( objectTable );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(): It's a valid object of the correct type, and owned
	   by the calling thread */
	if( !isValidObject( objectHandle ) || \
		objectHandle == SYSTEM_OBJECT_HANDLE || \
		objectTable[ objectHandle ].type != type || \
		!checkObjectOwnership( objectTable[ objectHandle ] ) )
		{
		unlockResource( objectTable );
		return( errorCode );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];

	/* Inner precondition: The object is of the requested type */
	PRE( objectInfoPtr->type == type );

	/* This function can only be called on certificates (used when copying
	   internal state such as cert extensions or CRL info from one cert
	   object to another), crypto hardware devices other than the system
	   object (used when a context tied to a crypto hardware device needs to
	   perform an operation using the device), and user objects (used when
	   updating config data, which can take awhile) */
	if( objectInfoPtr->type != OBJECT_TYPE_CERTIFICATE && \
		objectInfoPtr->type != OBJECT_TYPE_DEVICE && \
		objectInfoPtr->type != OBJECT_TYPE_USER )
		{
		unlockResource( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Inner precondition: It's a certificate or a crypto device */
	PRE( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE || \
		 objectInfoPtr->type == OBJECT_TYPE_DEVICE || \
		 objectInfoPtr->type == OBJECT_TYPE_USER );

	/* If the object is busy, wait for it to become available */
	if( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) )
		status = waitForObject( objectHandle, &objectInfoPtr );
	if( cryptStatusOK( status ) )
		{
		objectInfoPtr->lockCount++;
		objectInfoPtr->lockOwner = THREAD_SELF();
		*objectPtr = objectInfoPtr->objectPtr;
		}

	unlockResource( objectTable );
	return( status );
	}

int krnlReleaseObject( const int objectHandle )
	{
	return( releaseObject( objectHandle, TRUE ) );
	}

/* Relinquish ownership of the system object to another thread.  This
   procedure is needed to allow a background polling thread to add entropy
   to the system device.  The way it works is that the calling thread hands
   ownership over to the polling thread and suspends itself until the
   polling thread completes.  When the polling thread has completed, it
   terminates, whereupon the original thread wakes up and reacquires
   ownership */

int krnlReleaseSystemObject( const THREAD_HANDLE objectOwner )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ SYSTEM_OBJECT_HANDLE ];
	int status = CRYPT_OK;

	/* Preconditions: The object is in use */
	PRE( isInUse( SYSTEM_OBJECT_HANDLE ) );

	lockResource( objectTable );

	/* Precondition: We're relinquishing ownership, we're currently the
	   owner */
	PRE( isObjectOwner( SYSTEM_OBJECT_HANDLE ) );

	objectInfoPtr->lockOwner = objectOwner;

	unlockResource( objectTable );
	return( status );
	}

int krnlReacquireSystemObject( void )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ SYSTEM_OBJECT_HANDLE ];
	int status = CRYPT_OK;

	/* Preconditions: The object is in use */
	PRE( isInUse( SYSTEM_OBJECT_HANDLE ) );

	lockResource( objectTable );

	/* Precondition: We're reacquiring ownership, we're not currently the
	   owner */
	PRE( !isObjectOwner( SYSTEM_OBJECT_HANDLE ) );

	objectInfoPtr->lockOwner = THREAD_SELF();

	unlockResource( objectTable );
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

   The locking is complicated by the fact that the object table and lock may
   not have been initialised yet, so we also need to check the initialisation
   lock before we try to lock or use the object table.  Even this can create
   problems since the initialisation lock may not have been set up yet, but
   we can't really fix that.  In any case under Win32 it's OK since the mutex
   is set up by DllMain(), and under most Unixen the storage for the mutex is
   set to all-zero which is equivalent to an initialised mutex.

   In addition to the locking, we need to be careful with how we create new
   objects because if we just allocate handles sequentially and reuse handles
   as soon as possible, an existing object could be signalled and a new one
   created in its place without the caller or owning object realizing that
   they're now working with a different object (although the kernel can tell
   them apart because it maintains an internal unique ID for each object).
   Unix systems handle this by always incrementing pids and assuming there
   won't be any problems when they wrap, we do the same thing but in
   addition allocate handles in a non-sequential manner using an LFSR to
   step through the object table.  There's no strong reason for this, but it
   only costs a few extra clocks so we may as well do it */

static int findFreeResource( int value )
	{
	int oldValue = value;
	TEMP_INT( iterations = 0 );

	/* Preconditions: We're starting with a valid object handle, and it's not
	   a system object */
	PRE( isValidHandle( value ) );
	PRE( value >= NO_SYSTEM_OBJECTS );

	/* Step through the entire table looking for a free entry */
	do
		{
		/* Get the next value: Multiply by x and reduce by the polynomial */
		value <<= 1;
		if( value & objectStateInfo.lfsrMask )
			value ^= objectStateInfo.lfsrPoly;

		INV( iterations++ < objectTableSize );
		}
	while( objectTable[ value ].objectPtr != NULL && \
		   value != oldValue );

	if( value == oldValue )
		{
		/* Postcondition: We tried all locations and there are no free slots
		   available */
		POST( iterations == objectTableSize - 1 );
		FORALL( i, 0, objectTableSize,
				objectTable[ i ].objectPtr != NULL );

		return( CRYPT_ERROR );
		}

	/* Postconditions: We found a handle to a free slot */
	POST( isValidHandle( value ) );
	POST( isFreeObject( value ) );

	return( value );
	}

int krnlCreateObject( void **objectDataPtr, const int objectDataSize,
					  const OBJECT_TYPE type, const int subType,
					  const int createObjectFlags, const CRYPT_USER owner,
					  const int actionFlags,
					  MESSAGE_FUNCTION messageFunction )
	{
	OBJECT_INFO objectInfo;
	int objectHandle = objectStateInfo.objectHandle;
	TEMP_INT( bitCount );

	/* Preconditions (the subType check is just the standard hakmem bitcount
	   which ensures that we don't try and create multi-typed objects, the
	   sole exception to this rule is the default user object that acts as
	   both a user and SO object) */
	PRE( objectDataPtr != NULL );
	PRE( objectDataSize > 16 && objectDataSize < 16384 );
	PRE( isValidType( type ) );
	PRE( ( bitCount = ( subType & ~SUBTYPE_CLASS_MASK ) - \
						( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 1 ) & 033333333333 ) - \
						( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 2 ) & 011111111111 ) ) != 0 );
	PRE( ( ( bitCount + ( bitCount >> 3 ) ) & 030707070707 ) % 63 == 1 );
	PRE( !( createObjectFlags & \
			~( CREATEOBJECT_FLAG_SECUREMALLOC | CREATEOBJECT_FLAG_DUMMY ) ) );
	PRE( owner == CRYPT_UNUSED || isValidHandle( owner ) );
	PRE( actionFlags < ACTION_PERM_LAST );
	PRE( messageFunction != NULL );

	*objectDataPtr = NULL;

	/* If we're in the middle of a shutdown, we can't create any new
	   objects */
	if( isClosingDown )
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
	objectInfo.owner = owner;
	objectInfo.type = type;
	objectInfo.subType = subType;
	objectInfo.actionFlags = actionFlags;
	objectInfo.uniqueID = objectUniqueID;
	objectInfo.messageFunction = messageFunction;

	/* Make sure that the kernel has been initialised, and if it has lock
	   the object table for exclusive access */
	lockResource( initialisation );
	if( !isInitialised )
		{
		unlockResource( initialisation );
		return( CRYPT_ERROR_NOTINITED );
		}
	lockResource( objectTable );
	unlockResource( initialisation );

	/* The first objects created are internal objects with predefined
	   handles (spes lucis aeternae).  As we create these objects we ratchet
	   up through the fixed handles until we reached the last fixed object,
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
			  objectHandle == objectStateInfo.objectHandle + 1 );
		}
	else
		{
		PRE( isValidHandle( owner ) );

		/* Search the table for a free entry */
		objectHandle = findFreeResource( objectHandle );
		}

	/* If the table is full, expand it */
	if( objectHandle == CRYPT_ERROR )
		{
		static const int lfsrPolyTable[] = \
							{	  0x83,	   0x11D,	 0x211,	   0x409,
								 0x805,   0x1053,   0x201B,   0x402B,
								0x8003,  0x1002D,  0x20009,  0x40027,
							   0x80027, 0x100009, 0x200005, 0x400003 };
		OBJECT_INFO *newTable;
		int i;
		ORIGINAL_INT_VAR( oldLfsrPoly, objectStateInfo.lfsrPoly );

		/* If we're already at the maximum number of allowed objects, don't
		   create any more.  This prevents both accidental runaway code
		   that creates huge numbers of objects and DOS attacks */
		if( objectTableSize >= MAX_OBJECTS )
			{
			unlockResource( objectTable );
			return( CRYPT_ERROR_MEMORY );
			}

		/* Precondition: We haven't exceeded the maximum number of objects */
		PRE( objectTableSize < MAX_OBJECTS );

		/* Expand the table */
		newTable = clDynAlloc( "krnlCreateObject", \
							   ( objectTableSize * 2 ) * sizeof( OBJECT_INFO ) );
		if( newTable == NULL )
			{
			unlockResource( objectTable );
			return( CRYPT_ERROR_MEMORY );
			}

		/* Copy the information across to the new table, set up the newly-
		   allocated entries, and clear the old table */
		memcpy( newTable, objectTable,
				objectTableSize * sizeof( OBJECT_INFO ) );
		for( i = objectTableSize; i < objectTableSize * 2; i++ )
			newTable[ i ] = OBJECT_INFO_TEMPLATE;
		zeroise( objectTable, objectTableSize * sizeof( OBJECT_INFO ) );
		clFree( "krnlCreateObject", objectTable );
		objectTable = newTable;
		objectTableSize *= 2;

		/* Add the new object at the end of the existing table */
		objectStateInfo.lfsrMask <<= 1;
		for( i = 0; i < 16; i++ )
			if( lfsrPolyTable[ i ] > objectStateInfo.lfsrPoly )
				break;
		objectStateInfo.lfsrPoly = lfsrPolyTable[ i ];
		objectHandle = findFreeResource( objectStateInfo.objectHandle );

		/* Postcondition: We've moved on to the next LFSR polynomial value,
		   and the LFSR output covers the entire table */
		POST( ( objectStateInfo.lfsrPoly & ~0x7F ) == \
			  ( ORIGINAL_VALUE( oldLfsrPoly ) & ~0xFF ) << 1 );
		POST( objectStateInfo.lfsrMask == \
			  ( objectStateInfo.lfsrPoly & ~0x7F ) );
		POST( objectTableSize == objectStateInfo.lfsrMask );
		}

	/* Set up the new object entry in the table and update the object table
	   state */
	objectTable[ objectHandle ] = objectInfo;
	if( objectHandle == NO_SYSTEM_OBJECTS - 1 )
		{
		/* If this is the last system object, we've been allocating handles
		   sequentially up to this point.  From now on we start allocating
		   handles starting from a randomised location in the table */
		objectStateInfo.objectHandle = \
			( ( int ) getTime() ) & ( objectStateInfo.lfsrMask - 1 );
		if( objectStateInfo.objectHandle < NO_SYSTEM_OBJECTS )
			/* Can occur with probability NO_SYSTEM_OBJECTS / 1024 */
			objectStateInfo.objectHandle = NO_SYSTEM_OBJECTS + 42;
		}
	else
		objectStateInfo.objectHandle = objectHandle;

	/* Update the object unique ID value */
	if( objectUniqueID >= INT_MAX - 1 )
		objectUniqueID = 0;
	else
		objectUniqueID++;
	POST( objectUniqueID >= 0 && objectUniqueID <= INT_MAX );

	/* Postconditions: It's a valid object set up as required */
	POST( isValidObject( objectHandle ) );
	POST( objectInfo.objectPtr == *objectDataPtr );
	POST( objectInfo.owner == owner );
	POST( objectInfo.type == type );
	POST( objectInfo.subType == subType );
	POST( objectInfo.actionFlags == actionFlags );
	POST( objectInfo.messageFunction == messageFunction );

	unlockResource( objectTable );
	return( objectHandle );
	}

/****************************************************************************
*																			*
*							Internal Message Handlers						*
*																			*
****************************************************************************/

/* Update an action permission.  This implements a ratchet that only allows
   permissions to be made more restrictive after they've initially been set,
   so once a permission is set to a given level it can't be set to a less
   restrictive level (i.e. it's a write-up policy) */

static int updateActionPerms( int currentPerm, const int newPerm )
	{
	int permMask = ACTION_PERM_MASK, i;

	/* For each permission, update its value if the new setting is more
	   restrictive than the current one.  Since smaller values are more
	   restrictive, we can do a simple range comparison and replace the
	   existing value if it's larger than the new one */
	for( i = 0; i < ACTION_PERM_COUNT; i++ )
		{
		if( ( newPerm & permMask ) < ( currentPerm & permMask ) )
			currentPerm = ( currentPerm & ~permMask ) | ( newPerm & permMask );
		permMask <<= ACTION_PERM_BITS;
		}

	/* Postcondition: The new permission is at least as restrictive (or more
	   so) than the old one */
	FORALL( i, 0, ACTION_PERM_COUNT,
			( currentPerm & ( ACTION_PERM_MASK << ( i * ACTION_PERM_BITS ) ) ) <= \
				( newPerm & ( ACTION_PERM_MASK << ( i * ACTION_PERM_BITS ) ) ) );

	return( currentPerm );
	}

/* Update the action permissions for an object based on the composite
   permissions for it and a dependent object.  This is a special-case
   function because it has to operate with the object table unlocked.  This
   is necessary because the dependent object may be owned by another thread,
   and if we were to leave the object table locked the two would deadlock if
   we were sending the object a message while owning the object table at the
   same time the other thread was sending a message while owning the object.

   There is one potential race condition possible here in which the object
   is destroyed and replaced by a new one while the object table is unlocked,
   so we end up updating the action permissions for a different object.  To
   protect against this, we check the unique ID after we re-lock the object
   table to make sure that it's the same object */

static int updateDependentObjectPerms( const CRYPT_HANDLE objectHandle,
									   const CRYPT_HANDLE dependentObject )
	{
	STATIC_FN int setPropertyAttribute( const int objectHandle,
										const CRYPT_ATTRIBUTE_TYPE attribute,
										void *messageDataPtr );
	const OBJECT_TYPE objectType = objectTable[ objectHandle ].type;
	const CRYPT_CONTEXT contextHandle = \
		( objectType == OBJECT_TYPE_CONTEXT ) ? objectHandle : dependentObject;
	const CRYPT_CERTIFICATE certHandle = \
		( objectType == OBJECT_TYPE_CERTIFICATE ) ? objectHandle : dependentObject;
	const unsigned int uniqueID = objectTable[ objectHandle ].uniqueID;
	int actionFlags = 0, status;
	ORIGINAL_INT_VAR( oldPerm, objectTable[ contextHandle ].actionFlags );

	/* Preconditions: Objects are valid, one is a cert and the other a
	   context, and they aren't dependent on each other (which would create
	   a dependency update loop) */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidHandle( dependentObject ) );
	PRE( ( objectTable[ objectHandle ].type == OBJECT_TYPE_CONTEXT && \
		   objectTable[ dependentObject ].type == OBJECT_TYPE_CERTIFICATE ) || \
		 ( objectTable[ objectHandle ].type == OBJECT_TYPE_CERTIFICATE && \
		   objectTable[ dependentObject ].type == OBJECT_TYPE_CONTEXT ) );
	PRE( objectTable[ objectHandle ].dependentObject != dependentObject || \
		 objectTable[ dependentObject ].dependentObject != objectHandle );

	/* Since we're about to send messages to the dependent object, we have to
	   unlock the object table */
	unlockResource( objectTable );

#if 0	/* Removed 12/6/03 since privKey contexts are no longer attached to
		   certs, instead pubKey components are copied over and/or a new
		   pure pubKey context is created if necessary */
	/* When we attach a cert to a context or a public-key context to a cert,
	   we have to find the way in which the cert constrains the context and
	   adjust the context's action ACL as appropriate.  In contrast when we
	   attach a private key context to a cert (done when adding a key to a
	   freshly-created cert) we don't change the context's action ACL until
	   the context/cert pair is re-instantiated (e.g. by writing it to a
	   keyset and then re-reading it, which instantiates it as a context
	   with a cert attached).  The reason for this is that the cert key
	   usage may constrain the context in a way that renders its use
	   impossible (for example creating an encryption-only self-signed cert
	   would be impossible), or the context may be associated with multiple
	   mutually-exclusive certs (one signature-only, one encryption-only),
	   or the key usage in the cert may not be set until after the context
	   is attached, or any number of other variations.  Because of this a
	   cert -> context attach (done when instantiating a context+cert object
	   pair) or a public key context -> cert attach (done when importing a
	   cert, which creates the cert as the primary object and attaches the
	   context for non-data-only certs) imposes the cert constraint on the
	   context, but a private key context -> cert attach (done when adding a
	   key to a new cert object) doesn't impose them.  However, we do make
	   the actions for the key internal-only to ensure that it's only used
	   in an approved manner */
	if( objectType == OBJECT_TYPE_CERTIFICATE && \
		cryptStatusOK( \
			krnlSendMessage( dependentObject, IMESSAGE_CHECK, NULL,
							 MESSAGE_CHECK_PKC_PRIVATE ) ) )
		{
		static const int actionFlags = ACTION_PERM_NONE_EXTERNAL_ALL;

		/* The dependent object is a private-key context being attached to
		   a cert, make the key actions internal-only but don't do anything
		   else */
		lockResource( objectTable );
		if( objectTable[ objectHandle ].uniqueID != uniqueID )
			return( CRYPT_ERROR_SIGNALLED );
		return( krnlSendMessage( contextHandle, IMESSAGE_SETATTRIBUTE,
								 ( void * ) &actionFlags,
								 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
		}
#else
	if( objectType == OBJECT_TYPE_CERTIFICATE && \
		cryptStatusOK( \
			krnlSendMessage( dependentObject, IMESSAGE_CHECK, NULL,
							 MESSAGE_CHECK_PKC_PRIVATE ) ) )
		{
		/* We can't make a private key dependent on a cert, which is a
		   public-key object */
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_OBJECT );
		}
	if( objectType == OBJECT_TYPE_CONTEXT && \
		isValidObject( ( objectTable[ dependentObject ].dependentObject ) ) )
		{
		/* We can't attach a cert that's already associated with a context to
		   another context */
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_OBJECT );
		}
#endif /* 0 */

	/* For each action type, enable its continued use only if the cert
	   allows it.  Because a key with a certificate attached indicates that
	   it's (probably) being used for some function that involves interaction
	   with a relying party (i.e. that it probably has more value than a raw
	   key with no strings attached), we set the action permission to
	   ACTION_PERM_NONE_EXTERNAL rather than allowing ACTION_PERM_ALL.  This
	   both ensures that it's only used in a safe manner via the cryptlib
	   internal mechanisms, and makes sure that it's not possible to utilize
	   the signature/encryption duality of some algorithms to create a
	   signature where it's been disallowed */
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_SIGN ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_NONE_EXTERNAL );
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_SIGCHECK ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL );
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_ENCRYPT ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_DECRYPT ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_KA_EXPORT ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( cryptStatusOK( krnlSendMessage( certHandle,
					IMESSAGE_CHECK, NULL, MESSAGE_CHECK_PKC_KA_IMPORT ) ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );

	/* We're done querying the dependent object, re-lock the object table and
	   make sure that the original object hasn't been touched */
	lockResource( objectTable );
	if( objectTable[ objectHandle ].uniqueID != uniqueID )
		return( CRYPT_ERROR_SIGNALLED );
	status = setPropertyAttribute( contextHandle, CRYPT_IATTRIBUTE_ACTIONPERMS,
								   &actionFlags );

	/* Postcondition: The new permission is at least as restrictive (or more
	   so) than the old one */
	FORALL( i, 0, ACTION_PERM_COUNT,
			( objectTable[ contextHandle ].actionFlags & ( ACTION_PERM_MASK << ( i * 2 ) ) ) <= \
			( ORIGINAL_VALUE( oldPerm ) & ( ACTION_PERM_MASK << ( i * 2 ) ) ) );

	return( status );
	}

/* Get/set object property attributes.  We differentiate between a small
   number of user-accessible properties such as the object's owner, and
   properties that are only accessible by cryptlib.  The user-accessible
   properties can be locked, which makes them immutable (at least to being
   explicitly set, they can still be implicitly altered, for example setting
   a new object owner decrements the forwardcount value) and also unreadable
   by the user */

static int getPropertyAttribute( const int objectHandle,
								 const CRYPT_ATTRIBUTE_TYPE attribute,
								 void *messageDataPtr )
	{
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	int *valuePtr = ( int * ) messageDataPtr;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( attribute == CRYPT_PROPERTY_OWNER || \
		 attribute == CRYPT_PROPERTY_FORWARDCOUNT || \
		 attribute == CRYPT_PROPERTY_LOCKED || \
		 attribute == CRYPT_PROPERTY_USAGECOUNT || \
		 attribute == CRYPT_IATTRIBUTE_TYPE || \
		 attribute == CRYPT_IATTRIBUTE_SUBTYPE || \
		 attribute == CRYPT_IATTRIBUTE_STATUS || \
		 attribute == CRYPT_IATTRIBUTE_INTERNAL || \
		 attribute == CRYPT_IATTRIBUTE_ACTIONPERMS );
	PRE( messageDataPtr != NULL );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_OWNER:
			/* We allow this to be read since its value can be determined
			   anyway with a trial access */
			if( !( objectInfoPtr->flags & OBJECT_FLAG_OWNED ) )
				return( CRYPT_ERROR_NOTINITED );
#if defined( __MVS__ ) || ( defined( __UNIX__ ) && defined( _MPRAS ) )
			/* A very small number of pthreads implementations use non-
			   scalar thread IDs, which we can't easily handle when all we
			   have is an integer handle.  However, the need to bind threads
			   to objects only exists because of Win32 security holes
			   arising from the ability to perform thread injection, so this
			   isn't a big issue */
			return( CRYPT_ERROR_FAILED );
#else
			*valuePtr = ( int ) objectInfoPtr->objectOwner;
#endif /* Non-scalar threading environments */
			break;

		case CRYPT_PROPERTY_FORWARDCOUNT:
			if( objectInfoPtr->flags & OBJECT_FLAG_ATTRLOCKED )
				return( CRYPT_ERROR_PERMISSION );
			*valuePtr = objectInfoPtr->forwardCount;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* We allow this to be read since its value can be determined
			   anyway with a trial write */
			*( ( BOOLEAN * ) messageDataPtr ) = \
						( objectInfoPtr->flags & OBJECT_FLAG_ATTRLOCKED ) ? \
						TRUE : FALSE;
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			*valuePtr = objectInfoPtr->usageCount;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_TYPE :
			*valuePtr = objectInfoPtr->type;
			break;

		case CRYPT_IATTRIBUTE_SUBTYPE :
			*valuePtr = objectInfoPtr->subType;
			break;

		case CRYPT_IATTRIBUTE_STATUS:
			*valuePtr = objectInfoPtr->flags & OBJECT_FLAGMASK_STATUS;
			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			*( ( BOOLEAN * ) messageDataPtr ) = \
					( objectInfoPtr->flags & OBJECT_FLAG_INTERNAL ) ? \
					TRUE : FALSE;
			break;

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			*valuePtr = objectInfoPtr->actionFlags;
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

static int setPropertyAttribute( const int objectHandle,
								 const CRYPT_ATTRIBUTE_TYPE attribute,
								 void *messageDataPtr )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const int value = *( ( int * ) messageDataPtr );

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( attribute == CRYPT_PROPERTY_HIGHSECURITY || \
		 attribute == CRYPT_PROPERTY_OWNER || \
		 attribute == CRYPT_PROPERTY_FORWARDCOUNT || \
		 attribute == CRYPT_PROPERTY_LOCKED || \
		 attribute == CRYPT_PROPERTY_USAGECOUNT || \
		 attribute == CRYPT_IATTRIBUTE_STATUS || \
		 attribute == CRYPT_IATTRIBUTE_INTERNAL || \
		 attribute == CRYPT_IATTRIBUTE_ACTIONPERMS || \
		 attribute == CRYPT_IATTRIBUTE_LOCKED );
	PRE( messageDataPtr != NULL );
	PRE( objectHandle >= NO_SYSTEM_OBJECTS || \
		 attribute == CRYPT_IATTRIBUTE_STATUS );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_HIGHSECURITY:
			/* This is a combination property that makes an object owned,
			   non-forwardable, and locked */
			objectInfoPtr->objectOwner = THREAD_SELF();
			objectInfoPtr->forwardCount = 0;
			objectInfoPtr->flags |= OBJECT_FLAG_ATTRLOCKED | OBJECT_FLAG_OWNED;
			break;

		case CRYPT_PROPERTY_OWNER:
			/* This property can still be changed (even if the object is
			   locked) until the forwarding count drops to zero, otherwise
			   locking the object would prevent any forwarding */
			if( objectInfoPtr->forwardCount != CRYPT_UNUSED )
				{
				if( objectInfoPtr->forwardCount <= 0 )
					return( CRYPT_ERROR_PERMISSION );
				objectInfoPtr->forwardCount--;
				}
			if( value == CRYPT_UNUSED )
				objectInfoPtr->flags &= ~OBJECT_FLAG_OWNED;
			else
				{
#if !( defined( __MVS__ ) || ( defined( __UNIX__ ) && defined( _MPRAS ) ) )
				objectInfoPtr->objectOwner = ( THREAD_HANDLE ) value;
				objectInfoPtr->flags |= OBJECT_FLAG_OWNED;
#endif /* Non-scalar threading environments */
				}
			break;

		case CRYPT_PROPERTY_FORWARDCOUNT:
			if( objectInfoPtr->flags & OBJECT_FLAG_ATTRLOCKED )
				return( CRYPT_ERROR_PERMISSION );
			objectInfoPtr->forwardCount = value;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* Precondition: This property can only be set to true */
			PRE( value );

			objectInfoPtr->flags |= OBJECT_FLAG_ATTRLOCKED;
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			if( ( objectInfoPtr->flags & OBJECT_FLAG_ATTRLOCKED ) || \
				( objectInfoPtr->usageCount != CRYPT_UNUSED ) )
				return( CRYPT_ERROR_PERMISSION );
			objectInfoPtr->usageCount = value;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_STATUS:
			/* We're clearing an error/abnormal state or setting the object
			   to the busy state */
			PRE( value == CRYPT_OK || value == CRYPT_ERROR_TIMEOUT );

			if( isInvalidObjectState( objectHandle ) )
				{
				/* If the object is in an abnormal state, we can only (try to)
				   return it back to the normal state after the problem is
				   resolved */
				PRE( value == CRYPT_OK );

				/* If we're resetting the object status from busy to OK,
				   notify the object in case there's any extra processing to
				   be done */
				if( objectInfoPtr->flags & OBJECT_FLAG_BUSY )
					{
					/* Precondition: Only contexts can be busy */
					PRE( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );

					/* If the notification returns an error, the object is
					   still performing some sort of processing (e.g. cleanup/
					   shutdown), don't reset the status (it'll be done later
					   when the object is ready) */
					if( objectInfoPtr->messageFunction( objectInfoPtr->objectPtr,
									MESSAGE_CHANGENOTIFY, messageDataPtr,
									CRYPT_IATTRIBUTE_STATUS ) == CRYPT_OK )
						objectInfoPtr->flags &= ~OBJECT_FLAG_BUSY;
					break;
					}

				/* If we're processing a notification from the caller that
				   the object init is complete and the object was destroyed
				   while it was being created (which sets its state to
				   CRYPT_ERROR_SIGNALLED), tell the caller to convert the
				   message to a destroy object message unless it's the system
				   object, which can't be explicitly destroyed.  In this case
				   we just return an error so the cryptlib init fails */
				if( objectInfoPtr->flags & OBJECT_FLAG_SIGNALLED )
					return( ( objectHandle < NO_SYSTEM_OBJECTS ) ?
							CRYPT_ERROR_SIGNALLED : OK_SPECIAL );

				/* We're transitioning the object to the initialised state */
				PRE( objectInfoPtr->flags & OBJECT_FLAG_NOTINITED );
				objectInfoPtr->flags &= ~OBJECT_FLAG_NOTINITED;
				POST( !( objectInfoPtr->flags & OBJECT_FLAG_NOTINITED ) );
				break;
				}

			/* Inner precondition: The object is in a valid state */
			PRE( !isInvalidObjectState( objectHandle ) );

			/* We're setting the object's busy flag because it's about to
			   perform an async op */
			if( value == CRYPT_ERROR_TIMEOUT )
				objectInfoPtr->flags |= OBJECT_FLAG_BUSY;
			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			if( value )
				objectInfoPtr->flags |= OBJECT_FLAG_INTERNAL;
			else
				objectInfoPtr->flags &= ~OBJECT_FLAG_INTERNAL;
			break;

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			objectInfoPtr->actionFlags = \
					updateActionPerms( objectInfoPtr->actionFlags, value );
			break;

		case CRYPT_IATTRIBUTE_LOCKED:
			/* Incremement or decrement the object's lock count depending on
			   whether we're locking or unlocking it */
			if( value )
				{
				objectInfoPtr->lockCount++;
				objectInfoPtr->lockOwner = THREAD_SELF();
				}
			else
				{
				/* Precondition: The lock count is positive */
				PRE( objectInfoPtr->lockCount > 0 );

				objectInfoPtr->lockCount--;
				}

			/* If it's a certificate, notify it to save/restore its internal
			   state */
			if( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE )
				objectInfoPtr->messageFunction( objectInfoPtr->objectPtr,
									MESSAGE_CHANGENOTIFY, messageDataPtr,
									CRYPT_IATTRIBUTE_LOCKED );
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

/* Increment/decrement the reference count for an object.  This adjusts the
   reference count as appropriate and sends destroy messages if the reference
   count goes negative */

static int incRefCount( const int objectHandle, const int dummy1,
						const void *dummy2 )
	{
	ORIGINAL_INT_VAR( refCt, objectTable[ objectHandle ].referenceCount );

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );

	/* Increment an object's reference count */
	objectTable[ objectHandle ].referenceCount++;

	/* Postcondition: We incremented the reference count and it's now greater
	   than zero (the ground state) */
	POST( objectTable[ objectHandle ].referenceCount >= 1 );
	POST( objectTable[ objectHandle ].referenceCount == \
		  ORIGINAL_VALUE( refCt ) + 1 );

	return( CRYPT_OK );
	}

static int decRefCount( const int objectHandle, const int dummy1,
						const void *dummy2 )
	{
	int status;
	ORIGINAL_INT_VAR( refCt, objectTable[ objectHandle ].referenceCount );

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );

	/* Decrement an object's reference count */
	if( objectTable[ objectHandle ].referenceCount > 0 )
		{
		objectTable[ objectHandle ].referenceCount--;

		/* Postconditions: We decremented the reference count and it's
		   greater than or equal to zero (the ground state) */
		POST( objectTable[ objectHandle ].referenceCount >= 0 );
		POST( objectTable[ objectHandle ].referenceCount == \
			  ORIGINAL_VALUE( refCt ) - 1 );

#if 0
	if( objectInfoPtr->dependentDevice != CRYPT_ERROR )
		/* Velisurmaaja */
		decRefCount( objectInfoPtr->dependentDevice, 0, NULL );
	if( objectInfoPtr->dependentObject != CRYPT_ERROR )
		decRefCount( objectInfoPtr->dependentObject, 0, NULL );
#endif

		return( CRYPT_OK );
		}

	/* We're already at a single reference, destroy the object.  Since this
	   may take some time, we unlock the object table around the call */
	unlockResource( objectTable );
	status = krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
	lockResource( objectTable );

	/* Postconditions - none.  We can't be sure that the object has been
	   destroyed at this point since the message will have been enqueued */

	return( status );
	}

/* Get/set dependent objects for an object */

static int getDependentObject( const int objectHandle,
							   const int targetType,
							   const void *messageDataPtr )
	{
	int *valuePtr = ( int * ) messageDataPtr, localObjectHandle;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( targetType ) );
	PRE( messageDataPtr != NULL );

	/* Clear return value */
	*valuePtr = CRYPT_ERROR;

	localObjectHandle = findTargetType( objectHandle, targetType );
	if( cryptStatusError( localObjectHandle ) )
		{
		/* Postconditions: No dependent object found */
		POST( *valuePtr == CRYPT_ERROR );

		return( CRYPT_ARGERROR_OBJECT );
		}
	*valuePtr = localObjectHandle;

	/* Postconditions: We found a dependent object */
	POST( isValidObject( *valuePtr ) && \
		  isSameOwningObject( objectHandle, *valuePtr ) );

	return( CRYPT_OK );
	}

static int setDependentObject( const int objectHandle,
							   const int incReferenceCount,
							   const void *messageDataPtr )
	{
	const int dependentObject = *( ( int * ) messageDataPtr );
	int *objectHandlePtr, status = CRYPT_OK;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( incReferenceCount == TRUE || incReferenceCount == FALSE );
	PRE( isValidHandle( dependentObject ) );

	/* Determine which dependent object value to update based on its type */
	if( !isValidObject( dependentObject ) )
		/* The object was signalled after the message was sent */
		return( CRYPT_ERROR_SIGNALLED );
	objectHandlePtr = \
		( objectTable[ dependentObject ].type == OBJECT_TYPE_DEVICE ) ? \
			&objectTable[ objectHandle ].dependentDevice : \
			&objectTable[ objectHandle ].dependentObject;
	if( *objectHandlePtr != CRYPT_ERROR )
		{
		/* There's already a dependent object present and we're trying to
		   overwrite it with a new one, something is seriously wrong */
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_VALUE );
		}
	if( ( ( objectTable[ objectHandle ].type == OBJECT_TYPE_DEVICE ) ? \
		  objectTable[ dependentObject ].dependentDevice : \
		  objectTable[ dependentObject ].dependentObject ) == objectHandle )
		{
		/* The object is already dependent on the dependent object so making
		   the dependent object dependent on the object would create a loop,
		   something is seriously wrong */
		assert( NOTREACHED );
		return( CRYPT_ARGERROR_VALUE );
		}

	/* Inner precondition */
	PRE( *objectHandlePtr == CRYPT_ERROR );
	PRE( isSameOwningObject( objectHandle, dependentObject ) );

	/* Update the dependent object's reference count if required and record
	   the new status in the object table.  Dependent objects can be
	   established in one of two ways, by taking an existing object and
	   attaching it to another object (which increments its reference count,
	   since it's now being referred to by the original owner and by the
	   object it's  attached to), or by creating a new object and attaching
	   it to another object (which doesn't increment the reference count
	   since it's only referred to by the controlling object).  An example of
	   the former operation is adding a context from a cert request to a cert
	   (the cert request is referenced by both the caller and the cert), an
	   example of the latter operation is attaching a data-only cert to a
	   context (the cert is only referenced by the context) */
	if( incReferenceCount )
		incRefCount( dependentObject, 0, NULL );
	*objectHandlePtr = dependentObject;

	/* Certs and contexts have special relationships in that the cert can
	   constrain the use of the context beyond its normal level.  If we're
	   performing this type of object attachment, we have to adjust one
	   object's behvaiour based on the permissions of the other one */
	if( ( objectTable[ objectHandle ].type == OBJECT_TYPE_CONTEXT && \
		  objectTable[ dependentObject ].type == OBJECT_TYPE_CERTIFICATE ) || \
		( objectTable[ objectHandle ].type == OBJECT_TYPE_CERTIFICATE && \
		  objectTable[ dependentObject ].type == OBJECT_TYPE_CONTEXT ) )
		status = updateDependentObjectPerms( objectHandle, dependentObject );

	/* Postconditions */
	POST( isValidObject( *objectHandlePtr ) && \
		  isSameOwningObject( objectHandle, *objectHandlePtr ) );

	return( status );
	}

/* Clone an object.  This is handled via copy-on-write so it doesn't
   actually do anything at this point except check that the access is valid
   and set the aliased and cloned flags to indicate that the object needs to
   be handled specially if a write access is made to it */

static int cloneObject( const int objectHandle, const int clonedObject,
						const void *dummy )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	OBJECT_INFO *clonedObjectInfoPtr = &objectTable[ clonedObject ];
	int actionFlags, status;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) && \
		 objectHandle >= NO_SYSTEM_OBJECTS );
	PRE( !isClonedObject( objectHandle ) && \
		 !isAliasedObject( objectHandle ) );
	PRE( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( isValidObject( clonedObject ) && \
		 clonedObject >= NO_SYSTEM_OBJECTS );
	PRE( !isClonedObject( clonedObject ) && \
		 !isAliasedObject( clonedObject ) );
	PRE( clonedObjectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( objectHandle != clonedObject );

	/* Make sure that the original object is in the high state.  This will
	   have been checked by the caller anyway, but we check again here to
	   make sure */
	if( !isInHighState( objectHandle ) )
		return( CRYPT_ERROR_NOTINITED );

	/* Cloning of non-native contexts is somewhat complex because we usually
	   can't clone a device object, so we have to detect requests to clone
	   these objects and increment their reference count instead.  This
	   isn't a major problem because cryptlib always creates native contexts
	   for clonable algorithms, if the user explicitly overrides this by
	   using their own device-specific context then the usage will usually
	   be create, add to envelope, destroy, so there's no need to clone the
	   context anyway.  The only that time there's a potential problem is if 
	   they override the use of native contexts by adding device contexts to
	   multiple envelopes, but in that case it's assumed that they'll be 
	   aware of potential problems with this approach */
	if( objectInfoPtr->dependentDevice != SYSTEM_OBJECT_HANDLE )
		return( incRefCount( objectHandle, 0, NULL ) );

	/* Propagate the action permissions from the source object to the
	   clone, making them internal-only */
	status = getPropertyAttribute( objectHandle,
								   CRYPT_IATTRIBUTE_ACTIONPERMS,
								   &actionFlags );
	if( cryptStatusOK( status ) )
		{
		actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		status = setPropertyAttribute( clonedObject,
									   CRYPT_IATTRIBUTE_ACTIONPERMS,
									   &actionFlags );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Postcondition: The cloned object can only be used internally */
	POST( ( clonedObjectInfoPtr->actionFlags & ~ACTION_PERM_NONE_EXTERNAL_ALL ) == 0 );

	/* Mark the two objects as being aliases, and the (incomplete) clone as
	   a cloned object */
	objectInfoPtr->flags |= OBJECT_FLAG_ALIASED;
	objectInfoPtr->clonedObject = clonedObject;
	clonedObjectInfoPtr->flags |= OBJECT_FLAG_ALIASED | OBJECT_FLAG_CLONE;
	clonedObjectInfoPtr->clonedObject = objectHandle;

/* Should do a shallow copy of object info to copy across algorithm, mode, etc etc? */

	/* Postconditions: The objects are marked as aliased objects and the
	   cloned object as a clone */
	POST( isAliasedObject( objectHandle ) && !isClonedObject( objectHandle ) );
	POST( isAliasedObject( clonedObject ) && isClonedObject( clonedObject ) );
	POST( !isClonedObject( clonedObjectInfoPtr->clonedObject ) );
	POST( isClonedObject( objectInfoPtr->clonedObject ) );
	POST( objectHandle != clonedObject );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Misc									*
*																			*
****************************************************************************/

/* Pull in the attribute ACL information */

#include "cryptacl.h"

/* Find the ACL for an object attribute */

static const ATTRIBUTE_ACL *findAttributeACL( const CRYPT_ATTRIBUTE_TYPE attribute,
											  const BOOLEAN isInternalMessage )
	{
	/* Precondition: If it's an internal message (i.e. not raw data from the
	   user) then the attribute is valid */
	PRE( !isInternalMessage || \
		 isAttribute( attribute ) || isInternalAttribute( attribute ) );

	/* Perform a hardcoded binary search for the attribute ACL, this minimises
	   the number of comparisons necessary to find a match */
	if( attribute < CRYPT_CTXINFO_LAST )
		{
		if( attribute < CRYPT_GENERIC_LAST )
			{
			if( attribute > CRYPT_PROPERTY_FIRST && \
				attribute < CRYPT_PROPERTY_LAST )
				{
				POST( propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ].attribute == attribute );
				return( &propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ] );
				}
			if( attribute > CRYPT_GENERIC_FIRST && \
				attribute < CRYPT_GENERIC_LAST )
				{
				POST( genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ].attribute == attribute );
				return( &genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ] );
				}
			}
		else
			{
			if( attribute > CRYPT_OPTION_FIRST && \
				attribute < CRYPT_OPTION_LAST )
				{
				POST( optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ].attribute == attribute );
				return( &optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ] );
				}
			if( attribute > CRYPT_CTXINFO_FIRST && \
				attribute < CRYPT_CTXINFO_LAST )
				{
				POST( contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ].attribute == attribute );
				return( &contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ] );
				}
			}
		}
	else
		{
		if( attribute < CRYPT_KEYINFO_LAST )
			{
			if( attribute > CRYPT_CERTINFO_FIRST && \
				attribute < CRYPT_CERTINFO_LAST )
				{
				/* Certificate attributes are split into subranges so we have
				   to adjust the offsets to get the right ACL.  The subrange
				   specifiers are inclusive ranges rather than bounding
				   values, so we use >= rather than > comparisons */
				if( attribute < CRYPT_CERTINFO_FIRST_EXTENSION )
					{
					if( attribute >= CRYPT_CERTINFO_FIRST_CERTINFO && \
						attribute <= CRYPT_CERTINFO_LAST_CERTINFO )
						{
						POST( certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ].attribute == attribute );
						return( &certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ] );
						}
					if( attribute >= CRYPT_CERTINFO_FIRST_NAME && \
						attribute <= CRYPT_CERTINFO_LAST_NAME )
						{
						POST( certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ].attribute == attribute );
						return( &certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ] );
						}
					}
				else
					{
					if( attribute >= CRYPT_CERTINFO_FIRST_EXTENSION && \
						attribute <= CRYPT_CERTINFO_LAST_EXTENSION )
						{
						POST( certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ].attribute == attribute );
						return( &certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ] );
						}
					if( attribute >= CRYPT_CERTINFO_FIRST_CMS && \
						attribute <= CRYPT_CERTINFO_LAST_CMS )
						{
						POST( certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ].attribute == attribute );
						return( &certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ] );
						}
					}
				}
			if( attribute > CRYPT_KEYINFO_FIRST && \
				attribute < CRYPT_KEYINFO_LAST )
				{
				POST( keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ].attribute == attribute );
				return( &keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ] );
				}
			}
		else
			{
			if( attribute > CRYPT_DEVINFO_FIRST && \
				attribute < CRYPT_DEVINFO_LAST )
				{
				POST( deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ].attribute == attribute );
				return( &deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_ENVINFO_FIRST && \
				attribute < CRYPT_ENVINFO_LAST )
				{
				POST( envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ].attribute == attribute );
				return( &envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_SESSINFO_FIRST && \
				attribute < CRYPT_SESSINFO_LAST )
				{
				POST( sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ].attribute == attribute );
				return( &sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_USERINFO_FIRST && \
				attribute < CRYPT_USERINFO_LAST )
				{
				POST( userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ].attribute == attribute );
				return( &userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ] );
				}

			/* If it's an external message then the internal attributes don't exist */
			if( isInternalMessage && \
				attribute > CRYPT_IATTRIBUTE_FIRST && \
				attribute < CRYPT_IATTRIBUTE_LAST )
				{
				POST( isInternalMessage );
				POST( internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ].attribute == attribute );
				return( &internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ] );
				}
			}
		}

	return( NULL );
	}

/* Find the ACL for a parameter object */

typedef struct {
	MESSAGE_TYPE type;
	OBJECT_ACL objectACL;
	} PARAMETER_ACL;

static const FAR_BSS PARAMETER_ACL paramACLTbl[] = {
	/* Certs can only be signed by (private-key) PKC contexts */
	{ MESSAGE_CRT_SIGN,
	  { ST_CTX_PKC, ST_NONE } },
	/* Signatures can be checked with a raw PKC context or a cert or cert
	   chain.  The object being checked can also be checked against a CRL,
	   against revocation data in a cert store, or against an RTCS or OCSP
	   responder */
	{ MESSAGE_CRT_SIGCHECK,
	  { ST_CTX_PKC | ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL | \
					 ST_KEYSET_DBMS, ST_SESS_RTCS | ST_SESS_OCSP } },
	{ MESSAGE_NONE }
	};

static const PARAMETER_ACL *findParamACL( const MESSAGE_TYPE message )
	{
	int paramACLindex = 0;

	/* Precondition: It's a message that takes an object parameter */
	PRE( isParamMessage( message ) );

	/* Find the ACL entry for this message type */
	do
		{
		if( paramACLTbl[ paramACLindex ].type == message )
			return( &paramACLTbl[ paramACLindex ] );
		paramACLindex++;
		}
	while( paramACLTbl[ paramACLindex ].type != MESSAGE_NONE );

	/* Postcondition: We found a matching ACL entry */
	POST( NOTREACHED );

	return( NULL );		/* Get rid of compiler warning */
	}

/* Check whether a numeric value falls within a special-case range type */

static BOOLEAN checkAttributeRangeSpecial( const RANGEVAL_TYPE rangeType,
										   const void *rangeInfo,
										   const int value )
	{
	/* Precondition: The range checking information is valid */
	PRE( rangeType > RANGEVAL_NONE && rangeType < RANGEVAL_LAST );
	PRE( rangeInfo != NULL );

	/* RANGEVAL_ALLOWEDVALUES contains an int [] of permitted values,
	   terminated by CRYPT_ERROR */
	if( rangeType == RANGEVAL_ALLOWEDVALUES )
		{
		const int *allowedValuesInfo = rangeInfo;
		int i;

		for( i = 0; allowedValuesInfo[ i ] != CRYPT_ERROR; i++ )
			{
			INV( i < 5 );
			if( value == allowedValuesInfo[ i ] )
				return( TRUE );
			}
		return( FALSE );
		}

	/* RANGEVAL_SUBRANGES contains a subrange [] of allowed subranges,
	   terminated by { CRYPT_ERROR, CRYPT_ERROR } */
	if( rangeType == RANGEVAL_SUBRANGES )
		{
		const RANGE_SUBRANGE_TYPE *allowedValuesInfo = rangeInfo;
		int i;

		for( i = 0; allowedValuesInfo[ i ].lowRange != CRYPT_ERROR; i++ )
			{
			/* Inner precondition: The range values are either both negative
			   or both positive.  This is needed for the range comparison to
			   work */
			PRE( ( allowedValuesInfo[ i ].lowRange < 0 && \
				   allowedValuesInfo[ i ].highRange < 0 ) || \
				 ( allowedValuesInfo[ i ].lowRange >= 0 && \
				   allowedValuesInfo[ i ].highRange >= 0 ) );
			INV( i < 5 );

			/* Check whether the value is within the allowed range.  Since
			   some values can be negative (e.g. cursor movement codes) we
			   have to reverse the range check for negative values */
			if( allowedValuesInfo[ i ].lowRange >= 0 )
				{
				if( value >= allowedValuesInfo[ i ].lowRange && \
					value <= allowedValuesInfo[ i ].highRange )
					return( TRUE );
				}
			else
				{
				PRE( allowedValuesInfo[ i ].highRange <= \
					 allowedValuesInfo[ i ].lowRange );
				if( value >= allowedValuesInfo[ i ].highRange && \
					value <= allowedValuesInfo[ i ].lowRange )
					return( TRUE );
				}
			}
		return( FALSE );
		}

	assert( NOTREACHED );
	return( FALSE );		/* Get rid of compiler warning */
	}

/* Check whether a string value falls within the given limits, with special
   handling for widechar strings.  This sort of thing really shouldn't be
   in the kernel, but not having it here makes string length range checking
   very difficult */

static BOOLEAN checkAttributeRangeWidechar( const void *value,
											const int valueLength,
											const int minLength,
											const int maxLength )
	{
#ifdef USE_WIDECHARS
	const wchar_t *wcString = value;

	/* If it's not a multiple of wchar_t in size or smaller than a
	   wchar_t, it can't be a widechar string */
	if( ( valueLength % WCSIZE ) || ( valueLength < WCSIZE ) )
		return( ( valueLength < minLength || valueLength > maxLength ) ? \
				FALSE : TRUE );

	/* If wchar_t is > 16 bits and the bits above 16 are all zero, it's
	   definitely a widechar string */
#if INT_MAX > 0xFFFFL
	if( WCSIZE > 2 && *wcString < 0xFFFF )
		return( ( valueLength < ( minLength * WCSIZE ) || \
				  valueLength > ( maxLength * WCSIZE ) ) ? \
				FALSE : TRUE );
#endif /* > 16-bit machines */

	/* Now it gets tricky.  The only thing that we can still safely check
	   for is something that has been bloated out into widechars from
	   ASCII */
	if( ( valueLength > WCSIZE * 2 ) && \
		( wcString[ 0 ] < 0xFF && wcString[ 1 ] < 0xFF ) )
		return( ( valueLength < ( minLength * WCSIZE ) || \
				  valueLength > ( maxLength * WCSIZE ) ) ? \
				FALSE : TRUE );
#endif /* USE_WIDECHARS */

	/* It's not a widechar string or we can't handle these, perform a
	   straight range check */
	return( ( valueLength < minLength || valueLength > maxLength ) ? \
			FALSE : TRUE );
	}

/* Handle an object that has been cloned and is subject to copy-on-write */

static int handleAliasedObject( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *messageDataPtr,
								const int messageValue )
	{
	STATIC_FN int cloneContext( const CRYPT_CONTEXT iDestContext,
								const CRYPT_CONTEXT iSrcContext );
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
	   objects to enforce copy-on-write semantics.  We also create two
	   distinct objects if a second attempt is made to clone the original
	   rather than allowing the creation of multiple aliased objects.  This
	   is done for two reasons, firstly because handling arbitrarily large
	   collections of cloned objects, while possible, complicates the kernel
	   since it's no longer a straighforward message filter that needs to
	   add relatively complex processing to manage chains of cloned objects.
	   Secondly, having multiple aliased objects is exceedingly rare (it can
	   only happen if a user, for some reason, pushes the same session key
	   or hash into multiple envelopes), so the extra overhead of a forced
	   clone is negligible */
	status = cloneContext( clonedObject, originalObject );
	if( cryptStatusOK( status ) )
		{
		OBJECT_INFO *clonedObjectInfoPtr = &objectTable[ clonedObject ];

		objectInfoPtr->flags &= ~OBJECT_FLAG_ALIASED;
		objectInfoPtr->clonedObject = CRYPT_ERROR;
		clonedObjectInfoPtr->flags &= ~( OBJECT_FLAG_ALIASED | OBJECT_FLAG_CLONE );
		clonedObjectInfoPtr->flags |= OBJECT_FLAG_HIGH;
		clonedObjectInfoPtr->clonedObject = CRYPT_ERROR;
		}
	return( status );
	}

/****************************************************************************
*																			*
*									Message Routing							*
*																			*
****************************************************************************/

/* Find the ultimate target of an object attribute manipulation message by
   walking down the chain of controlling->dependent objects.  For example a
   message targeted at a device and sent to a certificate would be routed to
   the cert's dependent object (which would typically be a context).  The
   device message targeted at the context would be routed to the context's
   dependent device, which is its final destination */

static int findTargetType( const int originalObjectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget1 = ( targets >> 8 ) & 0xFF;
	const OBJECT_TYPE altTarget2 = ( targets >> 16 ) & 0xFF;
	OBJECT_TYPE type = objectTable[ originalObjectHandle ].type;
	int objectHandle = originalObjectHandle;
	TEMP_INT( iterations = 0 );

	/* Preconditions: Source is a valid object, destination(s) are valid
	   target(s) */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget1 == OBJECT_TYPE_NONE || isValidType( altTarget1 ) );
	PRE( altTarget2 == OBJECT_TYPE_NONE || isValidType( altTarget2 ) );

	/* Route the request through any dependent objects as required until we
	   reach the required target object type.  "And thou shalt make
	   loops..." -- Exodus 24:6 */
	while( objectHandle != CRYPT_ERROR && \
		   !( target == type || \
			  ( altTarget1 != OBJECT_TYPE_NONE && altTarget1 == type ) || \
			  ( altTarget2 != OBJECT_TYPE_NONE && altTarget2 == type ) ) )
		{
		int newObjectHandle;

		/* Loop invariants.  "Fifty loops thou shalt make" -- Exodus 24:7
		   (some of the OT verses shouldn't be taken too literally,
		   apparently the 50 used here merely means "many" as in "more than
		   one or two" in the same way that "40 days and nights" is now
		   generally taken as meaning "Lots, but that's as far as we're
		   prepared to count") */
		INV( isValidObject( objectHandle ) );
		INV( iterations++ < 3 );

		/* Try sending the message to the primary target */
		if( target == OBJECT_TYPE_DEVICE && \
			objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
			newObjectHandle = objectTable[ objectHandle ].dependentDevice;
		else
			if( target == OBJECT_TYPE_USER )
				newObjectHandle = objectTable[ objectHandle ].owner;
			else
				newObjectHandle = objectTable[ objectHandle ].dependentObject;

		/* Try whatever we got as the new object handle */
		objectHandle = newObjectHandle;
		if( objectHandle != CRYPT_ERROR )
			type = objectTable[ objectHandle ].type;

		/* If we've got a new object, it has the same owner as the original
		   target candidate */
		POST( objectHandle == CRYPT_ERROR || \
			  isSameOwningObject( originalObjectHandle, objectHandle ) || \
			  objectTable[ originalObjectHandle ].owner == objectHandle );
		}

	/* Postcondition: We ran out of options or we reached the target object */
	POST( objectHandle == CRYPT_ERROR || \
		  ( isValidObject( objectHandle ) && \
		    ( isSameOwningObject( originalObjectHandle, objectHandle ) || \
			  objectTable[ originalObjectHandle ].owner == objectHandle ) && \
			( target == type || \
			  ( altTarget1 != OBJECT_TYPE_NONE && altTarget1 == type ) || \
			  ( altTarget2 != OBJECT_TYPE_NONE && altTarget2 == type ) ) ) );

	return( ( objectHandle == CRYPT_ERROR ) ? \
			CRYPT_ARGERROR_OBJECT : objectHandle );
	}

static int findCompareMessageTarget( const int originalObjectHandle,
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
		}

	/* Route the message through to the appropriate object */
	objectHandle = findTargetType( objectHandle, targetType );

	/* Postcondition */
	POST( objectHandle == CRYPT_ARGERROR_OBJECT || \
		  ( isValidObject( objectHandle ) && \
			isSameOwningObject( originalObjectHandle, objectHandle ) ) );

	return( objectHandle );
	}

/* Sometimes a message is explicitly non-routable (i.e. it has to be sent
   directly to the appropriate target object).  The following function checks
   that the target object is one of the required types */

static int checkTargetType( const int objectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget = targets >> 8;

	/* Precondition: Source is a valid object, destination(s) are valid
	   target(s) */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget == OBJECT_TYPE_NONE || isValidType( altTarget ) );

	/* Check whether the object matches the required type.  We don't have to
	   check whether the alternative target has a value or not since the
	   object can never be a OBJECT_TYPE_NONE */
	if( objectTable[ objectHandle ].type != target && \
		objectTable[ objectHandle ].type != altTarget )
		return( CRYPT_ERROR );

	/* Postcondition */
	POST( objectTable[ objectHandle ].type == target || \
		  objectTable[ objectHandle ].type == altTarget );

	return( objectHandle );
	}

/****************************************************************************
*																			*
*							Message Pre-dispatch Handlers					*
*																			*
****************************************************************************/

/* If it's a destroy object message, adjust the reference counts of any
   dependent objects and set the object's state to signalled.  We have to do
   this before we send the destroy message to the object in order that any
   further attempts to access it will fail.  This avoids a race condition
   where other threads may try to use the partially-destroyed object after
   the object handler unlocks it but before it and the kernel finish
   destroying it */

static int preDispatchSignalDependentObjects( const int objectHandle,
											  const MESSAGE_TYPE message,
											  const void *messageDataPtr,
											  const int messageValue,
											  const void *dummy )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];

	/* Precondition */
	PRE( isValidObject( objectHandle ) && \
		 objectHandle >= NO_SYSTEM_OBJECTS );

	if( objectInfoPtr->dependentDevice != CRYPT_ERROR )
		/* Velisurmaaja */
		decRefCount( objectInfoPtr->dependentDevice, 0, NULL );
	if( objectInfoPtr->dependentObject != CRYPT_ERROR )
		decRefCount( objectInfoPtr->dependentObject, 0, NULL );
	objectInfoPtr->flags |= OBJECT_FLAG_SIGNALLED;

	/* Postcondition: The object is now in the destroyed state as far as
	   other objects are concerned */
	POST( isInvalidObjectState( objectHandle ) );

	return( CRYPT_OK );
	}

/* If it's an attribute get/set/delete, check the access conditions for the
   object and the message parameters */

static int preDispatchCheckAttributeAccess( const int objectHandle,
											const MESSAGE_TYPE message,
											const void *messageDataPtr,
											const int messageValue,
											const void *auxInfo )
	{
	static const int accessTypeTbl[ 5 ][ 2 ] = {
		/* MESSAGE_GETATTRIBUTE */			/* MESSAGE_GETATTRIBUTE_S */
		{ ACCESS_FLAG_R, ACCESS_FLAG_H_R }, { ACCESS_FLAG_R, ACCESS_FLAG_H_R },
		/* MESSAGE_SETATTRIBUTE */			/* MESSAGE_SETATTRIBUTE_S */
		{ ACCESS_FLAG_W, ACCESS_FLAG_H_W }, { ACCESS_FLAG_W, ACCESS_FLAG_H_W },
		/* MESSAGE_DELETEATTRIBUTE */
		{ ACCESS_FLAG_D, ACCESS_FLAG_H_D }
		};
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;
	const OBJECT_ACL *objectACL = attributeACL->extendedInfo;
	const OBJECT_INFO *objectInfo = &objectTable[ objectHandle ];
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const int subType = objectInfo->subType;
	int accessType = \
			accessTypeTbl[ localMessage - MESSAGE_GETATTRIBUTE ]\
						 [ ( objectInfo->flags & OBJECT_FLAG_HIGH ) ? 1 : 0 ];
	const BOOLEAN isInternalMessage = \
			( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;
	const RESOURCE_DATA *msgData = messageDataPtr;
	const int *valuePtr = messageDataPtr;
	int objectParamHandle, objectParamSubType;

	/* Preconditions */
	PRE( isValidType( objectInfo->type ) );
	PRE( isAttributeMessage( localMessage ) );
	PRE( isAttribute( messageValue ) || isInternalAttribute( messageValue ) );
	PRE( localMessage == MESSAGE_DELETEATTRIBUTE || messageDataPtr != NULL );
	PRE( attributeACL != NULL && attributeACL->attribute == messageValue );

	/* If it's an internal message, use the internal access permssions */
	if( isInternalMessage )
		accessType = MK_ACCESS_INTERNAL( accessType );

	/* Make sure that the attribute is valid for this object subtype */
	if( !isValidSubtype( attributeACL->subTypeA, subType ) && \
		!isValidSubtype( attributeACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that this type of access is valid for this attribute */
	if( !( attributeACL->access & accessType ) )
		{
		/* If it's an internal-only attribute being accessed through an
		   external message, it isn't visible to the user so we return
		   an attribute value error */
		if( !( attributeACL->access & ACCESS_MASK_EXTERNAL ) && \
			!isInternalMessage )
			return( CRYPT_ARGERROR_VALUE );

		/* It is visible, return a standard permission error */
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Inner precondition: The attribute is valid for this subtype and is
	   externally visible or it's an internal message, and this type of
	   access is allowed */
	PRE( isValidSubtype( attributeACL->subTypeA, subType ) || \
		 isValidSubtype( attributeACL->subTypeB, subType ) );
	PRE( ( attributeACL->access & ACCESS_MASK_EXTERNAL ) || \
		 isInternalMessage );
	PRE( attributeACL->access & accessType );

	/* If it's a delete attribute message, there's no attribute data being
	   communicated so we can exit now */
	if( localMessage == MESSAGE_DELETEATTRIBUTE )
		{
		assert( messageDataPtr == NULL );
		return( CRYPT_OK );
		}

	/* Inner precondition: We're getting or setting the value of an attribute */
	PRE( localMessage == MESSAGE_GETATTRIBUTE || \
		 localMessage == MESSAGE_GETATTRIBUTE_S || \
		 localMessage == MESSAGE_SETATTRIBUTE || \
		 localMessage == MESSAGE_SETATTRIBUTE_S );

	/* Safety check for invalid pointers passed from an internal function.
	   Since isReadPtr() is a macro that evaluates to different things on
	   different OSes, we evaluate the size parameter into a variable to
	   sidestep problems with side-effects */
	if( attributeACL->valueType != ATTRIBUTE_VALUE_SPECIAL )
		{
		const int pointerDataSize = \
				( attributeACL->valueType == ATTRIBUTE_VALUE_BOOLEAN ) ? \
					sizeof( BOOLEAN ) : \
				( attributeACL->valueType == ATTRIBUTE_VALUE_STRING || \
				  attributeACL->valueType == ATTRIBUTE_VALUE_WCSTRING || \
				  attributeACL->valueType == ATTRIBUTE_VALUE_TIME ) ? \
					sizeof( RESOURCE_DATA ) : sizeof( int );

		if( !isReadPtr( messageDataPtr, pointerDataSize ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* Make sure that the attribute type matches the supplied value type.
	   We assert the preconditions for internal messages before the general
	   check to ensure that we throw an exception rather than just returning
	   an error code */
	switch( attributeACL->valueType )
		{
		case ATTRIBUTE_VALUE_BOOLEAN:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case ATTRIBUTE_VALUE_NUMERIC:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == MESSAGE_GETATTRIBUTE )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE );

			/* Make sure that the attribute value is within the allowed range.
			   We short-circuit the evaluation of open ranges and selection
			   values, which are simple to check and occur frequently */
			if( isSpecialRange( attributeACL ) )
				{
				const RANGEVAL_TYPE rangeType = \
							getSpecialRangeType( attributeACL );

				if( rangeType != RANGEVAL_ANY )
					{
					if( rangeType == RANGEVAL_SELECTVALUE )
						{
						if( *valuePtr != CRYPT_UNUSED )
							return( CRYPT_ARGERROR_NUM1 );
						}
					else
						if( !checkAttributeRangeSpecial( rangeType, \
										getSpecialRangeInfo( attributeACL ),
										*valuePtr ) )
							return( CRYPT_ARGERROR_NUM1 );
					}
				}
			else
				{
				/* Inner precondition: The range values are either both
				   negative or both positive.  This is needed for the range
				   comparison to work */
				PRE( ( attributeACL->lowRange < 0 && \
					   attributeACL->highRange < 0 ) || \
					 ( attributeACL->lowRange >= 0 && \
					   attributeACL->highRange >= 0 ) );

				/* Check whether the value is within the allowed range.
				   Since some values can be negative (e.g. cursor movement
				   codes) we have to reverse the range check for negative
				   values */
				if( attributeACL->lowRange >= 0 )
					{
					if( *valuePtr < attributeACL->lowRange || \
						*valuePtr > attributeACL->highRange )
						return( CRYPT_ARGERROR_NUM1 );
					}
				else
					{
					PRE( attributeACL->highRange <= attributeACL->lowRange );
					if( *valuePtr < attributeACL->highRange || \
						*valuePtr > attributeACL->lowRange )
						return( CRYPT_ARGERROR_NUM1 );
					}
				}
			break;

		case ATTRIBUTE_VALUE_OBJECT:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value */
			PRE( !isInternalMessage || \
				 localMessage == MESSAGE_GETATTRIBUTE || \
				 localMessage == MESSAGE_SETATTRIBUTE );

			/* Must be a numeric value */
			if( localMessage != MESSAGE_GETATTRIBUTE && \
				localMessage != MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == MESSAGE_GETATTRIBUTE )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE );

			/* Must contain a valid object handle */
			if( !isValidObject( *valuePtr ) || \
				!isObjectAccessValid( *valuePtr, message ) || \
				!checkObjectOwnership( objectTable[ *valuePtr ] ) || \
				!isSameOwningObject( objectHandle, *valuePtr ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Object must be of the correct type */
			if( objectACL->flags & ACL_FLAG_ROUTE_TO_CTX )
				objectParamHandle = findTargetType( *valuePtr,
													OBJECT_TYPE_CONTEXT );
			else
				if( objectACL->flags & ACL_FLAG_ROUTE_TO_CERT )
					objectParamHandle = findTargetType( *valuePtr,
														OBJECT_TYPE_CERTIFICATE );
				else
					objectParamHandle = *valuePtr;
			if( cryptStatusError( objectParamHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			objectParamSubType = objectTable[ objectParamHandle ].subType;
			if( !isValidSubtype( objectACL->subTypeA, objectParamSubType ) && \
				!isValidSubtype( objectACL->subTypeB, objectParamSubType ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( ( objectACL->flags & ACL_FLAG_STATE_MASK ) && \
				!checkObjectState( objectACL->flags, objectParamHandle ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Postcondition: Object parameter is valid and accessible,
			   object is of the correct type and state */
			POST( isValidObject( *valuePtr ) && \
				  isObjectAccessValid( *valuePtr, message ) && \
				  checkObjectOwnership( objectTable[ *valuePtr ] ) && \
				  isSameOwningObject( objectHandle, *valuePtr ) );
			POST( isValidSubtype( objectACL->subTypeA, objectParamSubType ) || \
				  isValidSubtype( objectACL->subTypeB, objectParamSubType ) );
			POST( !( objectACL->flags & ACL_FLAG_STATE_MASK ) || \
				  checkObjectState( objectACL->flags, objectParamHandle ) );
			break;

		case ATTRIBUTE_VALUE_STRING:
		case ATTRIBUTE_VALUE_WCSTRING:
			/* Inner precondition: If it's an internal message, it must be
			   a valid string value or a null value if we're obtaining a
			   length (polled entropy data can be arbitrarily large so we
			   don't check its length) */
			PRE( !isInternalMessage || \
				 ( localMessage == MESSAGE_GETATTRIBUTE_S && \
				   ( ( msgData->data == NULL && msgData->length == 0 ) || \
					 ( msgData->data != NULL && msgData->length >= 1 ) ) ) || \
				 ( localMessage == MESSAGE_SETATTRIBUTE_S && \
				   msgData->data != NULL && msgData->length >= 1 && \
				   ( msgData->length < 16384 || \
					 messageValue == CRYPT_IATTRIBUTE_ENTROPY ) ) );

			/* Must be a string value */
			if( localMessage != MESSAGE_GETATTRIBUTE_S && \
				localMessage != MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == MESSAGE_GETATTRIBUTE_S )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE_S );

			/* Make sure that the string length is within the allowed
			   range */
			if( isSpecialRange( attributeACL ) )
				{
				if( !checkAttributeRangeSpecial( \
									getSpecialRangeType( attributeACL ),
									getSpecialRangeInfo( attributeACL ),
									msgData->length ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			else
				if( attributeACL->valueType == ATTRIBUTE_VALUE_WCSTRING )
					{
					if( !checkAttributeRangeWidechar( msgData->data,
													  msgData->length,
													  attributeACL->lowRange,
													  attributeACL->highRange ) )
						return( CRYPT_ARGERROR_NUM1 );
					}
				else
					if( msgData->length < attributeACL->lowRange || \
						msgData->length > attributeACL->highRange )
						return( CRYPT_ARGERROR_NUM1 );
			break;

		case ATTRIBUTE_VALUE_TIME:
			/* Inner precondition: If it's an internal message, it must be
			   a string value corresponding to a time_t */
			PRE( !isInternalMessage || \
				 ( ( localMessage == MESSAGE_GETATTRIBUTE_S || \
					 localMessage == MESSAGE_SETATTRIBUTE_S ) && \
				   msgData->data != NULL && \
				   msgData->length == sizeof( time_t ) ) );

			/* Must be a string value */
			if( localMessage != MESSAGE_GETATTRIBUTE_S && \
				localMessage != MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == MESSAGE_GETATTRIBUTE_S )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == MESSAGE_SETATTRIBUTE_S );

			/* Must contain a time_t in a sensible range */
			if( *( ( time_t * ) msgData->data ) < MIN_TIME_VALUE )
				return( CRYPT_ARGERROR_STR1 );
			if( msgData->length != sizeof( time_t ) )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case ATTRIBUTE_VALUE_SPECIAL:
			/* It's an ACL with object-subtype-specific sub-ACL, find the
			   precise ACL for this object subtype */
			attributeACL = getSpecialRangeInfo( attributeACL );
			while( !( isValidSubtype( attributeACL->subTypeA, subType ) || \
					  isValidSubtype( attributeACL->subTypeB, subType ) ) )
				attributeACL++;

			/* Inner precondition: We've found a matching sub-ACL entry */
			PRE( attributeACL->valueType != ATTRIBUTE_VALUE_NONE );

			/* Recursively check the message aganist the sub-ACL */
			return( preDispatchCheckAttributeAccess( objectHandle, message,
							messageDataPtr, messageValue, attributeACL ) );

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

/* It's a compare message, make sure that the parameters are OK */

static int preDispatchCheckCompareParam( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	TEMP_VAR( const RESOURCE_DATA *msgData = messageDataPtr );

	/* Precondition: It's a valid compare message type */
	PRE( isValidObject( objectHandle ) );
	PRE( messageValue == MESSAGE_COMPARE_HASH || \
		 messageValue == MESSAGE_COMPARE_KEYID || \
		 messageValue == MESSAGE_COMPARE_KEYID_PGP || \
		 messageValue == MESSAGE_COMPARE_KEYID_OPENPGP || \
		 messageValue == MESSAGE_COMPARE_SUBJECT || \
		 messageValue == MESSAGE_COMPARE_ISSUERANDSERIALNUMBER || \
		 messageValue == MESSAGE_COMPARE_FINGERPRINT || \
		 messageValue == MESSAGE_COMPARE_CERTOBJ );

	/* Postconditions: The compare parameters are valid, either an object
	   handle or a string value at least as big as a minimal-length DN */
	POST( ( messageValue == MESSAGE_COMPARE_CERTOBJ && \
			isValidHandle( messageValue ) ) || \
		  ( messageValue != MESSAGE_COMPARE_CERTOBJ || \
			isReadPtr( msgData, RESOURCE_DATA ) && \
			msgData->data != NULL && msgData->length > 14 ) );

	return( CRYPT_OK );
	}

/* It's a context action message, check the access conditions for the object */

static int preDispatchCheckActionAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	int requiredLevel, actualLevel;

	PRE( isValidObject( objectHandle ) );
	PRE( isActionMessage( localMessage ) );

	/* If the object is in the low state, it can't be used for any action */
	if( !isInHighState( objectHandle ) )
		return( CRYPT_ERROR_NOTINITED );

	/* If the object is in the high state, it can't receive another message
	   of the kind that causes the state change */
	if( localMessage == MESSAGE_CTX_GENKEY )
		return( CRYPT_ERROR_INITED );

	/* If there's a usage count set for the object and it's gone to zero, it
	   can't be used any more */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED && \
		objectInfoPtr->usageCount <= 0 )
		return( CRYPT_ERROR_PERMISSION );

	/* Inner precondition: Object is in the high state and can process the
	   action message */
	PRE( isInHighState( objectHandle ) );
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount > 0 );

	/* Determine the required level for access.  Like protection rings, the
	   lower the value, the higher the privilege level.  Level 3 is all-access,
	   level 2 is internal-access only, level 1 is no access, and level 0 is
	   not-available (e.g. encryption for hash contexts) */
	requiredLevel = \
		objectInfoPtr->actionFlags & MK_ACTION_PERM( localMessage, ACTION_PERM_MASK );

	/* Make sure that the action is enabled at the required level */
	if( message & MESSAGE_FLAG_INTERNAL )
		/* It's an internal message, the minimal permissions will do */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_NONE_EXTERNAL );
	else
		/* It's an external message, we need full permissions for access */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_ALL );
	if( requiredLevel < actualLevel )
		{
		/* The required level is less than the actual level (e.g. level 2
		   access attempted from level 3), return more detailed information
		   about the problem */
		return( ( ( requiredLevel >> ACTION_PERM_SHIFT( localMessage ) ) == ACTION_PERM_NOTAVAIL ) ? \
				CRYPT_ERROR_NOTAVAIL : CRYPT_ERROR_PERMISSION );
		}

	/* Postcondition */
	POST( localMessage != MESSAGE_CTX_GENKEY );
	POST( isInHighState( objectHandle ) );
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount > 0 );
	POST( requiredLevel >= actualLevel );

	return( CRYPT_OK );
	}

/* If it's a state change trigger message, make sure that the object isn't
   already in the high state */

static int preDispatchCheckState( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue, const void *dummy )
	{
	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Postcondition: Object is in the low state so a state change message
	   is valid */
	POST( !isInHighState( objectHandle ) );

	return( CRYPT_OK );
	}

/* Check the access conditions for a message containing an optional handle
   as the message parameter */

static int preDispatchCheckParamHandleOpt( const int objectHandle,
										   const MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue,
										   const void *auxInfo )
	{
	const PARAMETER_ACL *paramACL = ( PARAMETER_ACL * ) auxInfo;
	const OBJECT_ACL *objectACL = &paramACL->objectACL;
	int subType;

	/* Preconditions */
	PRE( paramACL != NULL && paramACL->type == ( message & MESSAGE_MASK ) );

	/* If the object parameter is CRYPT_UNUSED (for example for a self-signed
	   cert), we're OK */
	if( messageValue == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Make sure that the object parameter is valid and accessible */
	if( !isValidObject( messageValue ) || \
		!isObjectAccessValid( messageValue, message ) || \
		!checkObjectOwnership( objectTable[ messageValue ] ) || \
		!isSameOwningObject( objectHandle, messageValue ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the object parameter subtype is correct */
	subType = objectTable[ messageValue ].subType;
	if( !isValidSubtype( objectACL->subTypeA, subType ) && \
		!isValidSubtype( objectACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Postcondition: Object parameter is valid, accessible, and of the
	   correct type */
	POST( isValidObject( messageValue ) && \
		  isObjectAccessValid( messageValue, message ) && \
		  checkObjectOwnership( objectTable[ messageValue ] ) && \
		  isSameOwningObject( objectHandle, messageValue ) );
	POST( isValidSubtype( objectACL->subTypeA, subType ) || \
		  isValidSubtype( objectACL->subTypeB, subType ) );

	return( CRYPT_OK );
	}

/* Perform a combined check of the object and the handle */

static int preDispatchCheckStateParamHandle( const int objectHandle,
											 const MESSAGE_TYPE message,
										 	 const void *messageDataPtr,
											 const int messageValue,
											 const void *auxInfo )
	{
	const PARAMETER_ACL *paramACL = ( PARAMETER_ACL * ) auxInfo;
	const OBJECT_ACL *objectACL = &paramACL->objectACL;
	int subType;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( paramACL != NULL && \
		 paramACL->type == ( message & MESSAGE_MASK ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Make sure that the object parameter is valid and accessible */
	if( !isValidObject( messageValue ) || \
		!isObjectAccessValid( messageValue, message ) || \
		!checkObjectOwnership( objectTable[ messageValue ] ) || \
		!isSameOwningObject( objectHandle, messageValue ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the object parameter subtype is correct */
	subType = objectTable[ messageValue ].subType;
	if( !isValidSubtype( objectACL->subTypeA, subType ) && \
		!isValidSubtype( objectACL->subTypeB, subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Postcondition: Object is in the low state so a state change message
	   is valid and the object parameter is valid, accessible, and of the
	   correct type */
	POST( !isInHighState( objectHandle ) );
	POST( isValidObject( messageValue ) && \
		  isObjectAccessValid( messageValue, message ) && \
		  checkObjectOwnership( objectTable[ messageValue ] ) && \
		  isSameOwningObject( objectHandle, messageValue ) );
	POST( isValidSubtype( objectACL->subTypeA, subType ) || \
		  isValidSubtype( objectACL->subTypeB, subType ) );

	return( CRYPT_OK );
	}

/* We're exporting a certificate, make sure that the format is valid for
   this cert type */

static int preDispatchCheckExportAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	static const FAR_BSS ATTRIBUTE_ACL formatPseudoACL[] = {
	MKACL_B( CRYPT_CERTFORMAT_NONE, 0, 0, 0, ROUTE( OBJECT_TYPE_NONE ) ),
	MKACL_S(	/* Encoded cert data */
		CRYPT_CERTFORMAT_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Encoded cert.chain */
		CRYPT_CERTFORMAT_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Base64-encoded certificate */
		CRYPT_CERTFORMAT_TEXT_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Base64-encoded cert.chain */
		CRYPT_CERTFORMAT_TEXT_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* XML-encoded certificate */
		CRYPT_CERTFORMAT_XML_CERTIFICATE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* XML-encoded cert.chain */
		CRYPT_CERTFORMAT_XML_CERTCHAIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* SET OF cert in chain */
		CRYPT_ICERTFORMAT_CERTSET,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* SEQUENCE OF cert in chain */
		CRYPT_ICERTFORMAT_CERTSEQUENCE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Encoded non-signed object data */
		/* We allow this attribute to be read for objects in the high as well
		   as the low state even though in theory it's only present for low
		   (non-signed) objects because the object can be in the high state
		   if it was imported from its external encoded form */
		CRYPT_ICERTFORMAT_DATA,
		ST_CERT_CMSATTR | ST_CERT_REQ_REV | ST_CERT_RTCS_REQ | \
			ST_CERT_RTCS_RESP | ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_B( CRYPT_CERTFORMAT_LAST, 0, 0, 0, ROUTE( OBJECT_TYPE_NONE ) ),
	};

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( messageDataPtr != NULL );
	PRE( messageValue > CRYPT_CERTFORMAT_NONE && \
		 messageValue < CRYPT_CERTFORMAT_LAST );

	/* The easiest way to handle this check is to use an ACL, treating the
	   format type as a pseudo-attribute type */
	FORALL( i, CRYPT_CERTFORMAT_NONE, CRYPT_CERTFORMAT_LAST,
			formatPseudoACL[ i ].attribute == i );
	if( messageValue <= CRYPT_CERTFORMAT_NONE || \
		messageValue >= CRYPT_CERTFORMAT_LAST )
		return( CRYPT_ARGERROR_VALUE );
	POST( formatPseudoACL[ messageValue ].attribute == messageValue );

	return( preDispatchCheckAttributeAccess( objectHandle,
							( message & MESSAGE_FLAG_INTERNAL ) ? \
							IMESSAGE_GETATTRIBUTE_S : MESSAGE_GETATTRIBUTE_S,
							messageDataPtr, messageValue,
							&formatPseudoACL[ messageValue ] ) );
	}

/* It's data being pushed or popped, make sure that it's a valid data
   quantity */

static int preDispatchCheckData( const int objectHandle,
								 const MESSAGE_TYPE message,
								 const void *messageDataPtr,
								 const int messageValue,
								 const void *dummy )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const RESOURCE_DATA *msgData = messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == 0 );

	/* Make sure that it's either a flush (buffer = NULL, length = 0)
	   or valid data */
	if( msgData->data == NULL )
		{
		if( localMessage != MESSAGE_ENV_PUSHDATA || msgData->length != 0 )
			return( CRYPT_ARGERROR_STR1 );
		}
	else
		if( msgData->length <= 0 )
			return( CRYPT_ARGERROR_STR1 );

	/* Postcondition: It's a flush or it's valid data */
	POST( ( localMessage == MESSAGE_ENV_PUSHDATA && \
			msgData->data == NULL && msgData->length == 0 ) || \
		  ( msgData->data != NULL && msgData->length > 0 ) );

	return( CRYPT_OK );
	}

/* We're creating a new object, set its owner to the owner of the object it's
   being created through */

static int preDispatchSetObjectOwner( const int objectHandle,
									  const MESSAGE_TYPE message,
									  const void *messageDataPtr,
									  const int messageValue,
									  const void *dummy )
	{
	MESSAGE_CREATEOBJECT_INFO *createInfo = \
					( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) && \
		 objectTable[ objectHandle ].type == OBJECT_TYPE_DEVICE );
	PRE( messageDataPtr != NULL );
	PRE( isValidType( messageValue ) );
	PRE( createInfo->cryptOwner == CRYPT_ERROR );

	/* Set the new object's owner to the owner of the object it's being
	   created through.  If it's being created through the system device
	   object (which has no owner), we set the owner to the default user
	   object */
	if( objectHandle == SYSTEM_OBJECT_HANDLE )
		createInfo->cryptOwner = DEFAULTUSER_OBJECT_HANDLE;
	else
		{
		const int ownerObject = objectTable[ objectHandle ].owner;

		/* Inner precondition: The owner is a valid user object */
		PRE( isValidObject( ownerObject ) && \
			 objectTable[ ownerObject ].type == OBJECT_TYPE_USER );

		createInfo->cryptOwner = ownerObject;
		}

	/* Postcondition: The new object's owner will be the user object it's
	   being created through or the default user if it's being done via the
	   system object */
	POST( ( objectHandle == SYSTEM_OBJECT_HANDLE && \
			createInfo->cryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
		  ( objectHandle != SYSTEM_OBJECT_HANDLE && \
			createInfo->cryptOwner == objectTable[ objectHandle ].owner ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Mechanism Pre-Dispatch Handlers					*
*																			*
****************************************************************************/

/* Pull in the mechanism and keyset ACL information */

#include "cryptacm.h"
#include "cryptack.h"

/* It's a cert management action message, check the access conditions for the
   mechanism objects */

static int preDispatchCheckCertMgmtAccess( const int objectHandle,
										   const MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue,
										   const void *dummy )
	{
	const MESSAGE_CERTMGMT_INFO *mechanismInfo = \
		  ( MESSAGE_CERTMGMT_INFO * ) messageDataPtr;
	TEMP_VAR( const MESSAGE_TYPE localMessage = message & MESSAGE_MASK );

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == MESSAGE_KEY_CERTMGMT );
	PRE( messageDataPtr != NULL );
	PRE( messageValue > CRYPT_CERTACTION_NONE && \
		 messageValue < CRYPT_CERTACTION_LAST );

	/* Non-user actions can never be initiated explicitly, with the exception
	   of the partial issue transactions required by some cert management
	   protocols, which can only be initiated from inside cryptlib */
	if( ( messageValue < CRYPT_CERTACTION_FIRST_USER || \
		  messageValue > CRYPT_CERTACTION_LAST_USER ) && \
		!( ( message & MESSAGE_FLAG_INTERNAL ) && \
		   ( messageValue == CRYPT_CERTACTION_CERT_CREATION || \
			 messageValue == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
			 messageValue == CRYPT_CERTACTION_CERT_CREATION_DROP || \
			 messageValue == CRYPT_CERTACTION_CERT_CREATION_REVERSE ) ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Check the mechanism parameters */
	switch( messageValue )
		{
		case CRYPT_CERTACTION_CERT_CREATION:
		case CRYPT_CERTACTION_ISSUE_CERT:
			if( !isValidObject( mechanismInfo->caKey ) || \
				!isObjectAccessValid( mechanismInfo->caKey, message ) || \
				!checkObjectOwnership( objectTable[ mechanismInfo->caKey ] ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->caKey ) )
				return( CRYPT_ARGERROR_NUM1 );

			if( !isValidObject( mechanismInfo->request ) || \
				!isObjectAccessValid( mechanismInfo->request, message ) || \
				!checkObjectOwnership( objectTable[ mechanismInfo->request ] ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->request ) )
				return( CRYPT_ARGERROR_NUM2 );
			break;

		case CRYPT_CERTACTION_CERT_CREATION_COMPLETE:
		case CRYPT_CERTACTION_CERT_CREATION_DROP:
		case CRYPT_CERTACTION_CERT_CREATION_REVERSE:
			if( !isValidObject( mechanismInfo->request ) || \
				!isObjectAccessValid( mechanismInfo->request, message ) || \
				!checkObjectOwnership( objectTable[ mechanismInfo->request ] ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->request ) )
				return( CRYPT_ARGERROR_NUM2 );
			PRE( mechanismInfo->caKey == CRYPT_UNUSED );
			break;

		case CRYPT_CERTACTION_ISSUE_CRL:
			if( !isValidObject( mechanismInfo->caKey ) || \
				!isObjectAccessValid( mechanismInfo->caKey, message ) || \
				!checkObjectOwnership( objectTable[ mechanismInfo->caKey ] ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->caKey ) )
				return( CRYPT_ARGERROR_NUM1 );
			PRE( mechanismInfo->request == CRYPT_UNUSED );
			break;

		case CRYPT_CERTACTION_REVOKE_CERT:
			if( !isValidObject( mechanismInfo->request ) || \
				!isObjectAccessValid( mechanismInfo->request, message ) || \
				!checkObjectOwnership( objectTable[ mechanismInfo->request ] ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->request ) )
				return( CRYPT_ARGERROR_NUM2 );
			PRE( mechanismInfo->caKey == CRYPT_UNUSED );
			break;

		case CRYPT_CERTACTION_EXPIRE_CERT:
		case CRYPT_CERTACTION_CLEANUP:
			PRE( mechanismInfo->caKey == CRYPT_UNUSED );
			PRE( mechanismInfo->request == CRYPT_UNUSED );
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Message Post-Dispatch Handlers					*
*																			*
****************************************************************************/

/* If we're fetching or creating an object, it won't be visible to an
   outside caller.  If it's an external message, we have to make the object
   externally visible before we return it */

static int postDispatchMakeObjectExternal( const int dummy,
										   const MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue,
										   const void *auxInfo )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const BOOLEAN isInternalMessage = \
					( message & MESSAGE_FLAG_INTERNAL ) ? TRUE : FALSE;
	CRYPT_HANDLE objectHandle;
	int status;

	/* Preconditions */
	PRE( localMessage == MESSAGE_GETATTRIBUTE || \
		 localMessage == MESSAGE_DEV_CREATEOBJECT || \
		 localMessage == MESSAGE_DEV_CREATEOBJECT_INDIRECT || \
		 localMessage == MESSAGE_KEY_GETKEY || \
		 localMessage == MESSAGE_KEY_GETNEXTCERT || \
		 localMessage == MESSAGE_KEY_CERTMGMT );
	PRE( messageDataPtr != NULL );

	/* If it's an internal message, there are no problems with object
	   visibility.  In addition most messages are internal, so performing
	   this check before anything else quickly weeds out the majority of
	   cases */
	if( isInternalMessage )
		return( CRYPT_OK );

	switch( localMessage )
		{
		case MESSAGE_GETATTRIBUTE:
			{
			const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;

			/* Inner precondition: Since it's an external message, we must
			   be reading a standard attribute */
			PRE( isAttribute( messageValue ) );
			PRE( attributeACL != NULL && \
				 attributeACL->attribute == messageValue );

			/* If it's not an object attribute read, we're done */
			if( attributeACL->valueType == ATTRIBUTE_VALUE_SPECIAL )
				attributeACL = getSpecialRangeInfo( attributeACL );
			if( attributeACL->valueType != ATTRIBUTE_VALUE_OBJECT )
				return( CRYPT_OK );

			/* Inner precondition: We're reading an object attribute and
			   sending the response to an external caller */
			PRE( attributeACL->valueType == ATTRIBUTE_VALUE_OBJECT );
			PRE( isValidObject( *( ( int * ) messageDataPtr ) ) );
			PRE( !isInternalMessage );

			objectHandle = *( ( int * ) messageDataPtr );
			break;
			}

		case MESSAGE_DEV_CREATEOBJECT:
		case MESSAGE_DEV_CREATEOBJECT_INDIRECT:
			{
			MESSAGE_CREATEOBJECT_INFO *createInfo = \
							( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr;

			objectHandle = createInfo->cryptHandle;
			break;
			}

		case MESSAGE_KEY_GETKEY:
		case MESSAGE_KEY_GETNEXTCERT:
			{
			MESSAGE_KEYMGMT_INFO *getkeyInfo = \
							( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

			objectHandle = getkeyInfo->cryptHandle;
			break;
			}

		case MESSAGE_KEY_CERTMGMT:
			{
			MESSAGE_CERTMGMT_INFO *certMgmtInfo = \
							( MESSAGE_CERTMGMT_INFO * ) messageDataPtr;

			/* If it's not a cert management action that can return an
			   object, there's no object to make visible */
			if( messageValue != CRYPT_CERTACTION_ISSUE_CERT && \
				messageValue != CRYPT_CERTACTION_CERT_CREATION && \
				messageValue != CRYPT_CERTACTION_ISSUE_CRL )
				return( CRYPT_OK );

			/* If the caller has indicated that they're not interested in the
			   newly-created object, it won't be present so we can't make it
			   externally visible */
			if( certMgmtInfo->cryptCert == CRYPT_UNUSED )
				return( CRYPT_OK );

			/* Inner precondition: It's an action that can return an object,
			   and there's an object present */
			PRE( messageValue == CRYPT_CERTACTION_ISSUE_CERT || \
				 messageValue == CRYPT_CERTACTION_CERT_CREATION || \
				 messageValue == CRYPT_CERTACTION_ISSUE_CRL );
			PRE( certMgmtInfo->cryptCert != CRYPT_UNUSED );

			objectHandle = certMgmtInfo->cryptCert;
			break;
			}

		default:
			assert( NOTREACHED );
		}

	/* Postcondition: We've got a valid internal object to make externally
	   visible */
	POST( isValidObject( objectHandle ) && \
		  isInternalObject( objectHandle ) );

	/* Make the object externally visible */
	status = krnlSendMessage( objectHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE,
							  CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) )
		return( status );

	/* Postcondition: The object is now externally visible */
	POST( isValidObject( objectHandle ) && \
		  !isInternalObject( objectHandle ) );

	return( CRYPT_OK );
	}

/* If there's a dependent object with a given relationship to the controlling
   object, forward the message.  In practice the only dependencies are those
   of PKC contexts paired with certs, for which a message sent to one (e.g. a
   check message such as "is this suitable for signing?") needs to be
   forwarded to the other */

static int postDispatchForwardToDependentObject( const int objectHandle,
												 const MESSAGE_TYPE message,
												 const void *dummy1,
												 const int messageValue,
												 const void *dummy2 )
	{
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const int dependentObject = objectInfoPtr->dependentObject;
	const OBJECT_TYPE objectType = objectTable[ objectHandle ].type;
	const OBJECT_TYPE dependentType = ( dependentObject != CRYPT_ERROR ) ? \
							objectTable[ dependentObject ].type : CRYPT_ERROR;
	int status;
	TEMP_VAR( const MESSAGE_TYPE localMessage = message & MESSAGE_MASK );

	/* Precondition: It's an appropriate message type being forwarded to a
	   dependent object */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == MESSAGE_CHECK );
	PRE( messageValue > MESSAGE_CHECK_NONE && \
		 messageValue < MESSAGE_CHECK_LAST );
	PRE( isValidObject( dependentObject ) || dependentObject == CRYPT_ERROR );

	/* If there's no relationship between the objects, don't do anything */
	if( !( objectType == OBJECT_TYPE_CONTEXT && \
		   dependentType == OBJECT_TYPE_CERTIFICATE ) && \
		!( objectType == OBJECT_TYPE_CERTIFICATE && \
		   dependentType == OBJECT_TYPE_CONTEXT ) )
		return( CRYPT_OK );

	/* Postcondition */
	POST( isValidObject( dependentObject ) );
	POST( isSameOwningObject( objectHandle, dependentObject ) );

	/* Forward the message to the dependent object.  We have to make the
	   message internal since the dependent objects may be internal-only.
	   In addition we have to unlock the object table since the dependent
	   object may currently be owned by another thread */
	unlockResource( objectTable );
	status = krnlSendMessage( dependentObject, IMESSAGE_CHECK, NULL,
							  messageValue );
	lockResource( objectTable );
	return( status );
	}

/* Some objects can only perform given number of actions before they self-
   destruct, if there's a usage count set we update it */

static int postDispatchUpdateUsageCount( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *dummy1,
										 const int messageValue,
										 const void *dummy2 )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	ORIGINAL_INT_VAR( usageCt, objectInfoPtr->usageCount );

	/* Precondition: It's a context with a nonzero usage count */
	PRE( isValidObject( objectHandle ) && \
		 objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		 objectInfoPtr->usageCount > 0 );

	/* If there's an active usage count present, update it */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED )
		objectInfoPtr->usageCount--;

	/* Postcondition: If there was a usage count it's been decremented and
	   is >= 0 (the ground state) */
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  ( objectInfoPtr->usageCount == ORIGINAL_VALUE( usageCt ) - 1 && \
			objectInfoPtr->usageCount >= 0 ) );
	return( CRYPT_OK );
	}

/* Certain messages can trigger changes in the object state from the low to
   the high security level.  These changes are enforced by the kernel and
   can't be bypassed or controlled by the object itself.  Once one of these
   messages is successfully processed, we change the object's state so that
   further accesses are handled by the kernel based on the new state
   established by the message being processed successfully.  Since the object
   is still marked as busy at this stage, other messages arriving before the
   following state change can't bypass the kernel checks since they won't be
   processed until the object is marked as non-busy later on */

static int postDispatchChangeState( const int objectHandle,
									const MESSAGE_TYPE message,
									const void *dummy1,
									const int messageValue,
									const void *dummy2 )
	{
	/* Precondition: Object is in the low state so a state change message is
	   valid */
	PRE( isValidObject( objectHandle ) );
	PRE( !isInHighState( objectHandle ) );

	/* The state change message was successfully processed, the object is now
	   in the high state */
	objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;

	/* Postcondition: Object is in the high state */
	POST( isInHighState( objectHandle ) );
	return( CRYPT_OK );
	}

static int postDispatchChangeStateOpt( const int objectHandle,
									   const MESSAGE_TYPE message,
									   const void *dummy1,
									   const int messageValue,
									   const void *auxInfo )
	{
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	/* If it's an attribute that triggers a state, change the state */
	if( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER )
		{
		/* Inner precondition: Object is in the low state so a state change
		   message is valid, or it's a retriggerable attribute that can be
		   added multiple times (in other words, it can be added in both
		   the low and high state, with the first add in the low state
		   triggering a transition into the high state and subsequent
		   additions augmenting the existing data) */
		PRE( !isInHighState( objectHandle ) || \
			 ( ( attributeACL->access & ACCESS_INT_xWx_xWx ) == ACCESS_INT_xWx_xWx ) );

		objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;

		/* Postcondition: Object is in the high state */
		POST( isInHighState( objectHandle ) );
		return( CRYPT_OK );
		}

	/* Postcondition: It wasn't a trigger message */
	POST( !( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Message Dispatching							*
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
	PARAMTYPE_DATA_COMPARETYPE/* Data, value = compare type */
	} PARAMCHECK_TYPE;

/* Symbolic defines for message handling types, used to make it clearer
   what's going on

	PRE_DISPATCH	- Action before message is dispatched
	POST_DISPATCH	- Action after message is dispatched
	HANDLE_INTERNAL	- Message handled by the kernel */

#define PRE_DISPATCH( function )	preDispatch##function
#define POST_DISPATCH( function )	NULL, postDispatch##function
#define PRE_POST_DISPATCH( preFunction, postFunction ) \
		preDispatch##preFunction, postDispatch##postFunction
#define HANDLE_INTERNAL( function )	NULL, NULL, function

/* The handling information, declared in the order in which it's applied */

typedef struct MH {
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
									  const void *arg2 );
	} MESSAGE_HANDLING_INFO;

static const FAR_BSS MESSAGE_HANDLING_INFO messageHandlingInfo[] = {
	{ MESSAGE_NONE, ROUTE_NONE, 0, PARAMTYPE_NONE_NONE },

	/* Control messages.  These messages aren't routed, are valid for all
	   object types and subtypes, take no (or minimal) parameters, and are
	   handled by the kernel */
	{ MESSAGE_DESTROY,				/* Destroy the object */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  PRE_DISPATCH( SignalDependentObjects ) },
	{ MESSAGE_INCREFCOUNT,			/* Increment object ref.count */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( incRefCount ) },
	{ MESSAGE_DECREFCOUNT,			/* Decrement object ref.count */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( decRefCount ) },
	{ MESSAGE_GETDEPENDENT,			/* Get dependent object */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_OBJTYPE,
	  HANDLE_INTERNAL( getDependentObject ) },
	{ MESSAGE_SETDEPENDENT,			/* Set dependent object (e.g. ctx->dev) */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_BOOLEAN,
	  HANDLE_INTERNAL( setDependentObject ) },
	{ MESSAGE_CLONE,				/* Clone the object (only valid for ctxs) */
	  ROUTE_FIXED( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_HASH, ST_NONE,
	  PARAMTYPE_NONE_ANY,
	  HANDLE_INTERNAL( cloneObject ) },

	/* Attribute messages.  These messages are implicitly routed by attribute
	   type, more specific checking is performed using the attribute ACL's */
	{ MESSAGE_GETATTRIBUTE,			/* Get numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, MakeObjectExternal ) },
	{ MESSAGE_GETATTRIBUTE_S,		/* Get string object attribute */
	  ROUTE_IMPLICIT, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },
	{ MESSAGE_SETATTRIBUTE,			/* Set numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ MESSAGE_SETATTRIBUTE_S,		/* Set string object attribute */
	  ROUTE_IMPLICIT, ST_ANY, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ MESSAGE_DELETEATTRIBUTE,		/* Delete object attribute */
	  ROUTE_IMPLICIT, ST_CTX_ANY | ST_CERT_ANY, ST_SESS_ANY | ST_USER_NORMAL | ST_USER_SO,
	  PARAMTYPE_NONE_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },

	/* General messages to objects */
	{ MESSAGE_COMPARE,				/* Compare objs.or obj.properties */
	  ROUTE_SPECIAL( findCompareMessageTarget ), ST_CTX_ANY | ST_CERT_ANY, ST_NONE,
	  PARAMTYPE_DATA_COMPARETYPE,
	  PRE_DISPATCH( CheckCompareParam ) },
	{ MESSAGE_CHECK,				/* Check object info */
	  ROUTE_NONE, ST_ANY, ST_ANY,
	  PARAMTYPE_NONE_CHECKTYPE,
	  POST_DISPATCH( ForwardToDependentObject ) },

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
	  ROUTE( OBJECT_TYPE_CONTEXT ),ST_CTX_CONV, ST_NONE,
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

/* To manage messages sent to objects we maintain a message queue to ensure
   that there are no problems if a message sent to an object results in it
   sending another message to itself.  If a message for a given object is
   already present in the queue, the new message is appended after the
   existing one and the function returns immediately.  This ensures that the
   message isn't processed until the earlier message(s) for that object have
   been processed.  If the message is for a different object, it is prepended
   to the queue and processed immediately.  This ensures that messages sent
   by objects to subordinate objects are processed before the messages for
   the objects themselves.  Overall, an object won't be sent a new message
   until the current one has been processed.

   The message processing algorithm is as follows:

	find pos in queue starting from the back;
	insert message at ( pos ) ? pos + 1 : 0;
	if( pos )
		return;
	do
		queue[ 0 ]->function();
		delete queue[ 0 ];
	while( qPos && queue[ 0 ].object == object );

   For a sequence of messages A1 -> B1, B1 -> A2, B2, C, the processing
   sequence is:

	A1
	A1->fn();
		B1,A1
		B1->fn();
			B1,A1,A2, return
			B1,B2,A1,A2, return
			C,B1,B2,A1,A2
			C->fn();
			dequeue C;
			B1,B2,A1,A1
			dequeue B1;
		B2,A1,A2
		B2->fn();
		dequeue B2;
		dequeue A1;
	A2->fn();

   This processing order ensures that messages to the same object are
   processed in the order sent, and messages to different objects are
   guaranteed to complete before the message for the sending object.  In
   effect the message handling is like SendMessage() for other objects, and
   PostMessage() for the same object, so the current object can queue a
   series of events for processing and guarantee execution in the order the
   events are posted.

   To avoid the bottleneck of a single message queue, we maintain a
   scoreboard of objects that are currently processing messages.  If an
   object isn't busy and the message isn't of a special type such as
   MESSAGE_DESTROY, we dispatch the message immediately rather than queueing
   it.

   In some cases an object (a controlling object) will receive a message
   that isn't directly intended for it but which is appropriate for a
   dependent object (for example a "read DN" message sent to a context would
   be appropriate for an attached certificate object).  Typically the
   controlling object would forward the message, however this ties up both
   the controlling and dependent object, and it gets worse with long chains
   of dependent objects (e.g. envelope -> context -> device).  To alleviate
   this problem, the kernel implements a stunt box (in the CDC6600, not the
   TTY, sense) which reroutes messages intended for dependent objects
   directly to them instead of having the controlling object do this itself.
   This means that instead of:

	msg -> krn
		   krn -> O1
				  O1  -> krn
						 krn -> O2
						 krn <-
				  O1  <-
		   krn <-

   which ties up both objects, the message would be:

    msg -> krn
		   krn => O1		// Get dependent object
		   krn <=
		   krn -> O2
		   krn <-

   which would only tie up one object at a time.  In fact we can do even
   better than this by storing the handles of dependent objects in the object
   table, bypassing the intermediate objects entirely.  This has the
   additional advantage that it won't block if an intermediate object is busy,
   which requires complex handling in order to resume the forwarding process
   at a later point.  The resulting message flow is:

	msg -> krn
		   krn -> O2
		   krn <- */

/* A structure to store the details of a message sent to an object */

typedef struct {
	int objectHandle;				/* Handle to send message to */
	const MESSAGE_HANDLING_INFO *handlingInfoPtr;/* Message handling info */
	MESSAGE_TYPE message;
	const void *messageDataPtr;
	int messageValue;				/* Message parameters */
	} MESSAGE_QUEUE_DATA;

/* The size of the message queue.  This defines the maximum nesting depth of
   messages sent by an object.  Because of the way krnlSendMessage() handles
   message processing, it's extremely difficult to ever have more than two or
   three messages in the queue unless an object starts recursively sending
   itself messages */

#define MESSAGE_QUEUE_SIZE	16

/* Message queue implementation */

static MESSAGE_QUEUE_DATA messageQueue[ MESSAGE_QUEUE_SIZE ];
static int queueEnd = 0;	/* Points past last queue element */

static int enqueueMessage( const int objectHandle,
						   const MESSAGE_HANDLING_INFO *handlingInfoPtr,
						   const MESSAGE_TYPE message,
						   const void *messageDataPtr,
						   const int messageValue )
	{
	int queuePos, i;

	/* Precondition: It's a valid message being sent to a valid object */
	PRE( isValidObject( objectHandle ) );
	PRE( handlingInfoPtr != NULL );
	PRE( isValidMessage( message & MESSAGE_MASK ) );

	/* Make sure that we don't overflow the queue (this object is not
	   responding to messages... now all we need is GPF's) */
	if( queueEnd >= MESSAGE_QUEUE_SIZE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_TIMEOUT );
		}

	/* Precondition: There's room to enqueue the message */
	PRE( queueEnd < MESSAGE_QUEUE_SIZE );

	/* Check whether a message to this object is already present in the
	   queue */
	for( queuePos = queueEnd - 1; queuePos >= 0; queuePos-- )
		if( messageQueue[ queuePos ].objectHandle == objectHandle )
			break;

	/* Postcondition: queuePos = -1 if not present, position in queue if
	   present */
	POST( queuePos == -1 || ( queuePos >= 0 && queuePos < queueEnd ) );

	/* Enqueue the message */
	queuePos++;		/* Insert after current position */
	for( i = queueEnd - 1; i >= queuePos; i-- )
		messageQueue[ i + 1 ] = messageQueue[ i ];
	messageQueue[ queuePos ].objectHandle = objectHandle;
	messageQueue[ queuePos ].handlingInfoPtr = handlingInfoPtr;
	messageQueue[ queuePos ].message = message;
	messageQueue[ queuePos ].messageDataPtr = messageDataPtr;
	messageQueue[ queuePos ].messageValue = messageValue;
	queueEnd++;
	if( queuePos )
		/* A message for this object is already present, tell the caller to
		   defer processing */
		return( OK_SPECIAL );

	return( CRYPT_OK );
	}

static void dequeueMessage( const int messagePosition )
	{
	int i;

	/* Precondition: We're deleting a valid queue position */
	PRE( messagePosition >= 0 && messagePosition < queueEnd );

	/* Move the remaining messages down and clear the last entry */
	for( i = messagePosition; i < queueEnd - 1; i++ )
		messageQueue[ i ] = messageQueue[ i + 1 ];
	zeroise( &messageQueue[ queueEnd - 1 ], sizeof( MESSAGE_QUEUE_DATA ) );
	queueEnd--;

	/* Postcondition: all queue entries are valid, all non-queue entries are
	   empty */
	FORALL( i, 0, queueEnd,
			messageQueue[ i ].handlingInfoPtr != NULL );
	FORALL( i, queueEnd, MESSAGE_QUEUE_SIZE,
			messageQueue[ i ].handlingInfoPtr == NULL );
	}

static void dequeueAllMessages( const int objectHandle )
	{
	int i;

	/* Dequeue all messages for a given object */
	for( i = 0; i < queueEnd; i++ )
		if( messageQueue[ i ].objectHandle == objectHandle )
			{
			dequeueMessage( i );
			i--;	/* Compensate for dequeued message */
			}

	/* Postcondition: There are no more messages for this object present in
	   the queue */
	FORALL( i, 0, queueEnd,
			messageQueue[ i ].objectHandle != objectHandle );
	}

static BOOLEAN getNextMessage( const int objectHandle,
							   MESSAGE_QUEUE_DATA *messageQueueInfo )
	{
	int i;

	/* Find the next message for this object.  Since other messages can have
	   come and gone in the meantime, we have to scan from the start each
	   time */
	for( i = 0; i < queueEnd; i++ )
		if( messageQueue[ i ].objectHandle == objectHandle )
			{
			*messageQueueInfo = messageQueue[ i ];
			dequeueMessage( i );
			return( TRUE );
			}

	/* Postcondition: There are no more messages for this object present in
	   the queue */
	FORALL( i, 0, queueEnd,
			messageQueue[ i ].objectHandle != objectHandle );

	return( FALSE );
	}

/* Send a message to an object */

int krnlSendMessage( const int objectHandle, const MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue )
	{
	const ATTRIBUTE_ACL *attributeACL = NULL;
	const MESSAGE_HANDLING_INFO *handlingInfoPtr;
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
	PRE( isValidMessage( localMessage ) );
	PRE( !isInternalMessage || isValidHandle( objectHandle ) );

	/* Get the information we need to handle this message */
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
	if( isClosingDown && \
		!( localMessage == MESSAGE_DESTROY || \
		   localMessage == MESSAGE_DECREFCOUNT || \
		   ( localMessage == MESSAGE_GETATTRIBUTE && \
			 messageValue == CRYPT_IATTRIBUTE_STATUS ) ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	lockResource( objectTable );

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

	   The error condition reported in all of these cases is that the object
	   handle isn't valid */
	if( !isValidObject( objectHandle ) )
		status = CRYPT_ARGERROR_OBJECT;
	else
		if( !isInternalMessage && \
			( isInternalObject( objectHandle ) || \
			  !checkObjectOwnership( objectTable[ objectHandle ] ) ) )
			status = CRYPT_ARGERROR_OBJECT;
	if( cryptStatusError( status ) )
		{
		unlockResource( objectTable );
		return( status );
		}

	/* Inner precondition now that the outer check is past: It's a valid,
	   accessible object and not a system object that can never be
	   explicitly destroyed or have its refCount altered */
	PRE( isValidObject( objectHandle ) );
	PRE( isInternalMessage || ( !isInternalObject( objectHandle ) && \
		 checkObjectOwnership( objectTable[ objectHandle ] ) ) );
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
			unlockResource( objectTable );
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
		unlockResource( objectTable );
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
							localObjectHandle, messageValue, messageDataPtr );
			}
		if( status != OK_SPECIAL )
			{
			/* The message was processed normally, exit */
			unlockResource( objectTable );
			return( status );
			}

		/* The object has entered an invalid state (for example it was
		   signalled while it was being initialised) and can't be used any
		   more, destroy it.  We do this by converting the message into a
		   destroy object message, but leaving the original message data in
		   place so later code can determine what triggered the event */
		localMessage = MESSAGE_DESTROY;
		handlingInfoPtr = &messageHandlingInfo[ MESSAGE_DESTROY ];
		status = CRYPT_OK;
		}

	/* If this is an aliased object (one that has been cloned and is subject
	   to copy-on-write), handle it specially */
	if( isAliasedObject( localObjectHandle ) )
		{
		status = handleAliasedObject( localObjectHandle, localMessage,
									  messageDataPtr, messageValue );
		if( cryptStatusError( status ) )
			{
			unlockResource( objectTable );
			return( status );
			}
		}

	/* If the object isn't already processing a message and the message isn't
	   a special type such as MESSAGE_DESTROY, dispatch it immediately rather
	   than enqueueing it for later dispatch.  This scoreboard mechanism
	   greatly reduces the load on the queue */
	if( !isInUse( localObjectHandle ) && localMessage != MESSAGE_DESTROY )
		{
		/* If the object isn't in a valid state, we can't do anything with it.
		   There are no messages that can be sent to it at this point, get/
		   set property messages have already been handled earlier and the
		   destroy message isn't handled here */
		if( isInvalidObjectState( localObjectHandle ) )
			{
			status = getObjectStatusValue( objectInfoPtr->flags );
			unlockResource( objectTable );
			return( status );
			}

		/* In case a shutdown was signalled while we were performing other
		   processing, exit now before we try and do anything with the
		   object.  It's safe to perform the check at this point since no
		   message sent during shutdown will get here */
		if( isClosingDown )
			{
			unlockResource( objectTable );
			return( CRYPT_ERROR_PERMISSION );
			}

		/* Inner precondition: The object is in a valid state */
		PRE( !isInvalidObjectState( localObjectHandle ) );

		if( handlingInfoPtr->preDispatchFunction != NULL )
			status = handlingInfoPtr->preDispatchFunction( localObjectHandle,
									message, messageDataPtr, messageValue,
									aclPtr );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_FUNCTION messageFunction = objectInfoPtr->messageFunction;
			void *objectPtr = objectInfoPtr->objectPtr;
			const int lockCount = objectInfoPtr->lockCount + 1;

			/* Mark the object as busy so that we have it available for our
			   exclusive use and further messages to it will be enqueued,
			   dispatch the message with the object table unlocked, and mark
			   the object as non-busy again */
			objectInfoPtr->lockCount++;
			objectInfoPtr->lockOwner = THREAD_SELF();
			unlockResource( objectTable );
			status = messageFunction( objectPtr, localMessage,
									  messageDataPtr, messageValue );
			lockResource( objectTable );
			objectInfoPtr = &objectTable[ localObjectHandle ];
			assert( localObjectHandle == SYSTEM_OBJECT_HANDLE || \
					( objectInfoPtr->type == OBJECT_TYPE_USER && \
					  localMessage == MESSAGE_SETATTRIBUTE && \
					    messageValue == localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
					objectInfoPtr->lockCount == lockCount );
			if( objectInfoPtr->lockCount == lockCount && \
				isObjectOwner( localObjectHandle ) )
				/* The system object and to a lesser extent the user object
				   may unlock themselves while processing a message when
				   they forward the message elsewhere or perform non-object-
				   specific processing, so we only decrement the lock count
				   if it's unchanged and we still own the object.  We have
				   to perform the ownership check to avoid the situation
				   where we unlock the object and another thread locks it,
				   leading to an (apparently) unchanged lock count */
				objectInfoPtr->lockCount--;

			/* Postcondition: The lock count is non-negative and, if it's
			   not the system object or a user object, has been reset to its
			   previous value */
			POST( objectInfoPtr->lockCount >= 0 && \
				  ( localObjectHandle == SYSTEM_OBJECT_HANDLE ||
				    ( objectInfoPtr->type == OBJECT_TYPE_USER && \
					  localMessage == MESSAGE_SETATTRIBUTE && \
					  messageValue == localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
					objectInfoPtr->lockCount == lockCount - 1 ) );
			}
		if( cryptStatusOK( status ) && \
			handlingInfoPtr->postDispatchFunction != NULL )
			status = handlingInfoPtr->postDispatchFunction( localObjectHandle,
									message, messageDataPtr, messageValue, aclPtr );

		/* Postcondition: The return status is valid */
		POST( ( status >= CRYPT_ENVELOPE_RESOURCE && status <= CRYPT_OK ) || \
			  cryptArgError( status ) || status == OK_SPECIAL );

		unlockResource( objectTable );
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
		unlockResource( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_TIMEOUT );
		}

	/* If the object is in use by another thread, wait for it to become
	   available */
	if( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) )
		status = waitForObject( objectHandle, &objectInfoPtr );
	if( cryptStatusError( status ) )
		{
		unlockResource( objectTable );
		return( status );
		}

	/* Enqueue the message */
	status = enqueueMessage( localObjectHandle, handlingInfoPtr, message,
							 messageDataPtr, messageValue );
	if( cryptStatusError( status ) )
		{
		/* A message for this object is already present in the queue, defer
		   processing until later */
		unlockResource( objectTable );
		return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
		}

	/* While there are more messages for this object present, dequeue them
	   and dispatch them.  Since messages will only be enqueued if
	   krnlSendMessage() is called recursively, we only dequeue messages for
	   the current object in this loop.  Queued messages for other objects
	   will be handled at a different level of recursion */
	while( getNextMessage( localObjectHandle, &enqueuedMessageData ) )
		{
		const MESSAGE_HANDLING_INFO *enqueuedHandlingInfoPtr = \
									enqueuedMessageData.handlingInfoPtr;
		MESSAGE_TYPE enqueuedMessage = enqueuedMessageData.message;
		const BOOLEAN isDestroy = \
					( enqueuedHandlingInfoPtr->messageType == MESSAGE_DESTROY );
		const void *enqueuedMessageDataPtr = enqueuedMessageData.messageDataPtr;
		const int enqueuedMessageValue = enqueuedMessageData.messageValue;

		/* If there's a problem with the object, initiate special processing.
		   There are two exceptions to this, one is a destroy message sent to
		   a busy object, the other is a destroy message that started out as
		   a different type of message (that is, it was converted into a
		   destroy object message due to the object being in an invalid
		   state).  Both of these types are let through */
		if( isInvalidObjectState( localObjectHandle ) && \
			!( isDestroy && ( enqueuedMessageDataPtr != NULL || \
					( objectInfoPtr->flags & OBJECT_FLAG_BUSY ) ) ) )
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
			 ( isDestroy && ( enqueuedMessageDataPtr != NULL || \
					( objectInfoPtr->flags & OBJECT_FLAG_BUSY ) ) ) );

		/* Dispatch the message with the object table unlocked.  Since a
		   destroy object message always succeeds but can return an error
		   code (typically CRYPT_ERROR_INCOMPLETE), we don't treat an error
		   return as a real error status for the purposes of further
		   processing */
		if( enqueuedHandlingInfoPtr->preDispatchFunction != NULL )
			status = enqueuedHandlingInfoPtr->preDispatchFunction( localObjectHandle,
									enqueuedMessage, enqueuedMessageDataPtr,
									enqueuedMessageValue, aclPtr );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_FUNCTION messageFunction = objectInfoPtr->messageFunction;
			void *objectPtr = objectInfoPtr->objectPtr;
			const int lockCount = objectInfoPtr->lockCount + 1;

			objectInfoPtr->lockCount++;
			objectInfoPtr->lockOwner = THREAD_SELF();
			unlockResource( objectTable );
			status = messageFunction( objectPtr,
									  enqueuedHandlingInfoPtr->messageType,
									  ( void * ) enqueuedMessageDataPtr,
									  enqueuedMessageValue );
			lockResource( objectTable );
			objectInfoPtr = &objectTable[ localObjectHandle ];
			assert( localObjectHandle == SYSTEM_OBJECT_HANDLE || \
					( objectInfoPtr->type == OBJECT_TYPE_USER && \
					  localMessage == MESSAGE_SETATTRIBUTE && \
					    messageValue == localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
					objectInfoPtr->lockCount == lockCount );
			if( objectInfoPtr->lockCount == lockCount && \
				isObjectOwner( localObjectHandle ) )
				/* The system object and to a lesser extent the user object
				   may unlock themselves while processing a message when
				   they forward the message elsewhere or perform non-object-
				   specific processing, so we only decrement the lock count
				   if it's unchanged and we still own the object.  We have
				   to perform the ownership check to avoid the situation
				   where we unlock the object and another thread locks it,
				   leading to an (apparently) unchanged lock count */
				objectInfoPtr->lockCount--;

			/* Postcondition: The lock count is non-negative and, if it's
			   not the system object or a user object, has been reset to its
			   previous value */
			POST( objectInfoPtr->lockCount >= 0 && \
				  ( localObjectHandle == SYSTEM_OBJECT_HANDLE ||
				    ( objectInfoPtr->type == OBJECT_TYPE_USER && \
					  localMessage == MESSAGE_SETATTRIBUTE && \
					  messageValue == localObjectHandle == SYSTEM_OBJECT_HANDLE ) || \
					objectInfoPtr->lockCount == lockCount - 1 ) );
			}
		if( ( cryptStatusOK( status ) || isDestroy ) && \
			enqueuedHandlingInfoPtr->postDispatchFunction != NULL )
			status = enqueuedHandlingInfoPtr->postDispatchFunction( localObjectHandle,
									enqueuedMessage, enqueuedMessageDataPtr,
									enqueuedMessageValue, aclPtr );

		/* If the message is a destroy object message, we have to explicitly
		   remove it from the object table and dequeue all further messages
		   for it since the object's message handler can't do this itself.
		   Note that this doesn't check the previous return status for the
		   reason mentioned earlier */
		if( isDestroy )
			{
			objectTable[ localObjectHandle ] = OBJECT_INFO_TEMPLATE;
			dequeueAllMessages( localObjectHandle );
			}
		else
			/* If we ran into a problem, dequeue all further messages for
			   this object (this causes getNextMessage() to fail and we drop
			   out of the loop) */
			if( cryptStatusError( status ) )
				dequeueAllMessages( localObjectHandle );
		}

	/* Unlock the object table to allow access by other threads */
	unlockResource( objectTable );

	/* Postcondition: The return status is valid */
	POST( ( status >= CRYPT_ENVELOPE_RESOURCE && status <= CRYPT_OK ) || \
		  cryptArgError( status ) || status == OK_SPECIAL );

	return( status );
	}

/****************************************************************************
*																			*
*						Semaphore and Mutex Functions						*
*																			*
****************************************************************************/

/* Under multithreaded OS's, we often need to wait for certain events before
   we can continue (for example when asynchronously accessing system
   objects anything that depends on the object being available needs to
   wait for the access to complete) or handle mutual exclusion when accessing
   a shared resource.  The following functions abstract this handling,
   providing a lightweight semaphore mechanism which is used before checking
   a system synchronisation object and a centrally-managed mutex mechanism
   that doesn't require each mutex user to initialise and shut down their
   own mutexes.  The semaphore function works a bit like the Win32 Enter/
   LeaveCriticalSection() routines, which perform a quick check on a user-
   level lock and only call the kernel-level handler if necessary (in most
   cases this isn't necessary).  A useful side-effect is that since they
   work with lightweight local locks instead of systemwide locking objects,
   they aren't vulnerable to security problems where (for example) another
   process can mess with a globally visible object handle.  This is
   particularly problematic under Windows, where (for example) CreateMutex()
   can return a handle to an already-existing object of the same name rather
   than a newly-created object (there's no O_EXCL functionality).

   Semaphores are one-shots, so that once set and cleared they can't be
   reset.  This is handled by enforcing the following state transitions:

	Uninited -> Set | Clear
	Set -> Set | Clear
	Clear -> Clear

   The handling is complicated somewhat by the fact that on some systems the
   semaphore has to be explicitly deleted, but only the last thread to use it
   can safely delete it.  In order to handle this, we reference-count the
   semaphore and let the last thread out delete it.  In order to do this we
   introduce an addition state, preClear, which indicates that while the
   semaphore object is still present, the last thread out should delete it,
   bringing it to the true clear state */

typedef enum {
	SEMAPHORE_STATE_UNINITED,
	SEMAPHORE_STATE_CLEAR,
	SEMAPHORE_STATE_PRECLEAR,
	SEMAPHORE_STATE_SET
	} SEMAPHORE_STATE;

typedef struct {
	SEMAPHORE_STATE state;	/* Semaphore state */
	SEMAPHORE_HANDLE object;/* Handle to system synchronisation object */
	int refCount;			/* Reference count for handle */
	} SEMAPHORE_INFO;

/* A template to initialise the semaphore table */

static const SEMAPHORE_INFO SEMAPHORE_INFO_TEMPLATE = \
				{ SEMAPHORE_STATE_UNINITED, 0, 0 };

/* The table to map external semaphore handles to semaphore information */

static SEMAPHORE_INFO semaphoreInfo[ SEMAPHORE_LAST ];
DECLARE_LOCKING_VARS( semaphore )

/* Create and destroy the semaphore table */

static void initSemaphores( void )
	{
	int i;

	/* Clear the semaphore table */
	for( i = 0; i < SEMAPHORE_LAST; i++ )
		semaphoreInfo[ i ] = SEMAPHORE_INFO_TEMPLATE;

	/* Initialize any data structures required to make the semaphore table
	   thread-safe */
	initResourceLock( semaphore );
	}

static void endSemaphores( void )
	{
	/* Destroy any data structures required to make the semaphore table
	   thread-safe */
	deleteResourceLock( semaphore );
	}

/* Set and clear a semaphore */

void setSemaphore( const SEMAPHORE_TYPE semaphore,
				   const SEMAPHORE_HANDLE object )
	{
	assert( semaphore > SEMAPHORE_NONE && \
			semaphore < SEMAPHORE_LAST );

	/* Lock the semaphore table to ensure that other threads don't try to
	   access it */
	lockResource( semaphore );

	/* The semaphore can only be set if it's currently in the uninited state */
	if( semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_UNINITED )
		{
		semaphoreInfo[ semaphore ] = SEMAPHORE_INFO_TEMPLATE;
		semaphoreInfo[ semaphore ].state = SEMAPHORE_STATE_SET;
		semaphoreInfo[ semaphore ].object = object;
		}

	/* Unlock the semaphore table to allow access by other threads */
	unlockResource( semaphore );
	}

void clearSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	assert( semaphore > SEMAPHORE_NONE && \
			semaphore < SEMAPHORE_LAST );

	/* Lock the semaphore table, clear the semaphore, and unlock it again */
	lockResource( semaphore );
	if( semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_SET )
		{
		/* Precondition: The reference count is valid */
		PRE( semaphoreInfo[ semaphore ].refCount >= 0 );

		/* If there are threads waiting on this semaphore, tell the last
		   thread out to turn out the lights */
		if( semaphoreInfo[ semaphore ].refCount > 0 )
			semaphoreInfo[ semaphore ].state = SEMAPHORE_STATE_PRECLEAR;
		else
			{
			/* No threads waiting on the semaphore, we can delete it */
			THREAD_CLOSE( semaphoreInfo[ semaphore ].object );
			semaphoreInfo[ semaphore ] = SEMAPHORE_INFO_TEMPLATE;
			}
		}
	unlockResource( semaphore );
	}

/* Wait for a semaphore.  This occurs in two phases, first we extract the
   information we need from the semaphore table, then we unlock it and wait
   on the semaphore if necessary.  This is necessary because the wait can
   take an indeterminate amount of time and we don't want to tie up the other
   semaphores while this occurs.  Note that this type of waiting on local
   (rather than system) semaphores where possible greatly improves
   performance, in some cases the wait on a signalled system semaphore can
   take several seconds whereas waiting on the local semaphore only takes a
   few ms.  Once the wait has completed, we update the semaphore state as
   per the longer description above */

void waitSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	SEMAPHORE_HANDLE object;
	BOOLEAN semaphoreSet = FALSE;

	/* Lock the semaphore table, extract the information we need, and unlock
	   it again */
	lockResource( semaphore );
	if( semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_SET )
		{
		/* Precondition: The reference count is valid */
		PRE( semaphoreInfo[ semaphore ].refCount >= 0 );

		/* The semaphore is set and not in use, extract the information we
		   require and mark is as being in use */
		object = semaphoreInfo[ semaphore ].object;
		semaphoreInfo[ semaphore ].refCount++;
		semaphoreSet = TRUE;
		}
	unlockResource( semaphore );

	/* If the semaphore wasn't set or is in use, exit now */
	if( !semaphoreSet )
		return;

	/* Wait on the object */
	assert( object != SEMAPHORE_INFO_TEMPLATE.object );
	THREAD_WAIT( object );

	/* Lock the semaphore table, update the information, and unlock it
	   again */
	lockResource( semaphore );
	if( semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_SET || \
		semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_PRECLEAR )
		{
		/* The semaphore is still set, update the reference count */
		semaphoreInfo[ semaphore ].refCount--;

		/* Inner precondition: The reference count is valid */
		PRE( semaphoreInfo[ semaphore ].refCount >= 0 );

		/* If the object owner has signalled that it's done with the object
		   and the reference count has reached zero, we can delete it */
		if( semaphoreInfo[ semaphore ].state == SEMAPHORE_STATE_PRECLEAR || \
			semaphoreInfo[ semaphore ].refCount <= 0 )
			{
			/* No threads waiting on the semaphore, we can delete it */
			THREAD_CLOSE( object );
			semaphoreInfo[ semaphore ] = SEMAPHORE_INFO_TEMPLATE;
			}
		}
	unlockResource( semaphore );
	}

/* Create and destroy the mutexes.  Since mutexes usually aren't scalar
   values and are declared and accessed via macros that manipulate various
   fields, we have to declare a pile of them individually rather than using
   an array of mutexes */

DECLARE_LOCKING_VARS( mutex1 )
DECLARE_LOCKING_VARS( mutex2 )
DECLARE_LOCKING_VARS( mutex3 )

static void initMutexes( void )
	{
	assert( MUTEX_LAST == 4 );

	/* Initialize the mutexes */
	initResourceLock( mutex1 );
	initResourceLock( mutex2 );
	initResourceLock( mutex3 );
	}

static void endMutexes( void )
	{
	/* Shut down the mutexes */
	deleteResourceLock( mutex3 );
	deleteResourceLock( mutex2 );
	deleteResourceLock( mutex1 );
	}

/* Enter and exit a mutex */

void enterMutex( const MUTEX_TYPE mutex )
	{
	PRE( mutex > MUTEX_NONE && mutex < MUTEX_LAST );

	switch( mutex )
		{
		case MUTEX_SESSIONCACHE:
			lockResource( mutex1 );
			break;

		case MUTEX_SOCKETPOOL:
			lockResource( mutex2 );
			break;

		case MUTEX_RANDOMPOLLING:
			lockResource( mutex3 );
			break;

		default:
			assert( NOTREACHED );
		}
	}

void exitMutex( const MUTEX_TYPE mutex )
	{
	PRE( mutex > MUTEX_NONE && mutex < MUTEX_LAST );

	switch( mutex )
		{
		case MUTEX_SESSIONCACHE:
			unlockResource( mutex1 );
			break;

		case MUTEX_SOCKETPOOL:
			unlockResource( mutex2 );
			break;

		case MUTEX_RANDOMPOLLING:
			unlockResource( mutex3 );
			break;

		default:
			assert( NOTREACHED );
		}
	}

/****************************************************************************
*																			*
*							Service Routine Functions						*
*																			*
****************************************************************************/

#if 0	/* 12/12/02 Only ever needed for handling older smart-card readers */

/* Under multithreaded OS's, we can have background service routines running
   that perform various tasks.  In order to avoid having (potentially)
   dozens of different threads all whirring away, we provide the ability to
   register a service routine that gets called from a single worker thread.
   This is like a Win32 fiber, except that we provide extra functionality to
   handle object and object locking when the service routine applies to a
   particular object or object */

typedef struct {
	void ( *serviceDispatchFunction )( const int object,
									   void ( *serviceFunction )( void *info ) );
	void ( *serviceFunction )( void *info );
	int object;						/* Handle to object */
	int serviceID;					/* Unique ID for this service */
	} SERVICE_INFO;

/* The time interval between service dispatching, and the total number of
   services */

#define SERVICE_DISPATCH_INTERVAL	5
#define MAX_SERVICES				16

/* The table to map external semaphore handles to semaphore information */

static SERVICE_INFO serviceInfo[ MAX_SERVICES ];
static int serviceInfoLast, serviceUniqueID;
DECLARE_LOCKING_VARS( service )

/* Create and destroy the service table */

static void initServices( void )
	{
	/* Clear the service table */
	memset( serviceInfo, 0, sizeof( serviceInfo ) );
	serviceInfoLast = 0;

	/* Initialize any data structures required to make the service table
	   thread-safe */
	initResourceLock( service );
	}

static void endServices( void )
	{
	/* Destroy any data structures required to make the service table
	   thread-safe */
	deleteResourceLock( service );
	}

/* Register and deregister a service function */

int registerServiceRoutine( void ( *serviceDispatchFunction )
	( const int object, void ( *serviceFunction )( void *info ) ),
	void ( *serviceFunction )( void *info ), const int object )
	{
	int retVal;

	/* Lock the service table to ensure that other threads don't try to
	   access it */
	lockResource( service );

	/* Preconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

	/* Add this service to the service table */
	serviceInfo[ serviceInfoLast ].serviceDispatchFunction = \
													serviceDispatchFunction;
	serviceInfo[ serviceInfoLast ].serviceFunction = serviceFunction;
	serviceInfo[ serviceInfoLast++ ].object = object;
	retVal = serviceUniqueID++;

	/* Postconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );
	POST( serviceUniqueID >= 0 && serviceUniqueID < INT_MAX );

	/* Unlock the service table to allow access by other threads */
	unlockResource( service );

	return( retVal );
	}

void deregisterServiceRoutine( const int serviceID )
	{
	int i;

	/* Lock the service table to ensure that other threads don't try to
	   access it */
	lockResource( service );

	/* Preconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

	/* Find this service in the service table */
	for( i = 0; i < serviceInfoLast; i++ )
		if( serviceID == serviceInfo[ i ].serviceID )
			break;
	assert( i < serviceInfoLast );

	/* Move everything else down, removing this service from the table */
	if( i == serviceInfoLast - 1 )
		/* This is the last entry, clear it */
		memset( &serviceInfo[ i ], 0, sizeof( SERVICE_INFO ) );
	else
		memmove( &serviceInfo[ i ], &serviceInfo[ i + 1 ], \
				 ( serviceInfoLast - i ) - 1 );
	serviceInfoLast--;

	/* Postconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

	/* Unlock the service table to allow access by other threads */
	unlockResource( service );
	}

/* Service dispatch function */

void serviceDispatch( void )
	{
	BOOLEAN doContinue = TRUE;
	int serviceIndex = 0;

	do
		{
		void ( *serviceDispatchFunction )( const int object,
										   void ( *serviceFunction )( void *info ) );
		void ( *serviceFunction )( void *info );
		int object;

		/* Obtain information on the next service routine to call.  We have
		   to release the lock on the service table before we can call the
		   service routine to avoid a potential deadlock situation when the
		   object is locked and tries to deregister the service, and the
		   service table is locked and the dispatch routine tries to access
		   the object */
		lockResource( service );
		if( serviceIndex >= serviceInfoLast )
			/* We've run out of service routines, exit */
			doContinue = FALSE;
		else
			{
			/* Remember the details on the service routine to call */
			serviceDispatchFunction = \
						serviceInfo[ serviceIndex ].serviceDispatchFunction;
			serviceFunction = serviceInfo[ serviceIndex ].serviceFunction;
			object = serviceInfo[ serviceIndex ].object;
			}
		unlockResource( service );

		/* If there is a service routine to call, call it */
		if( doContinue )
			serviceDispatchFunction( object, serviceFunction );
		}
	while( doContinue );

	/* "You hurt Al?" / "I'm hurt real bad.  Sleepy time?" / "Sleepy time" */
#ifdef __WIN32__
	Sleep( SERVICE_DISPATCH_INTERVAL * 1000 );
#endif /* __WIN32__ */
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						Secure Memory Allocation Functions					*
*																			*
****************************************************************************/

/* To support page locking we need to store some additional information with
   the memory block.  We do this by reserving an extra memory block at the
   start of the allocated block and saving the information there.

   The information stored in the extra block is a flag indicating whether the
   block is pagelocked (so we can call the unlock function when we free it),
   the size of the block, and pointers to the next and previous pointers in
   the list of allocated blocks (this is used by the thread that walks the
   block list touching each one).

   If it's a debug build we also insert a canary at the start and end of each
   block to detect memory overwrites, the block size is adjusted accordingly
   to handle this extra data */

#if INT_MAX <= 32767
  #define MEMLOCK_HEADERSIZE	16
#elif INT_MAX <= 0xFFFFFFFFUL
  #define MEMLOCK_HEADERSIZE	32
#else
  #define MEMLOCK_HEADERSIZE	64
#endif /* 16-bit systems */

#define CANARY_STARTVALUE	"\xC0\xED\xBA\xBE"	/* More fun than dead beef */
#define CANARY_ENDVALUE		"\x38\xDD\x24\x36"
#define CANARY_SIZE			4

#ifdef __BEOS__
  #define USE_AREAS					/* BeOS areas are somewhat flaky */
#endif /* __BEOS__ */

typedef struct {
	BOOLEAN isLocked;				/* Whether this block is locked */
	int size;						/* Size of the block (including the size
									   of the MEMLOCK_INFO) */
	void *next, *prev;				/* Next, previous memory block */
#if defined( __BEOS__ ) && defined( USE_AREAS )
	area_id areaID;					/* Needed for page locking under BeOS */
#endif /* BeOS and BeOS areas */
#ifndef NDEBUG
	BYTE canary[ CANARY_SIZE ];		/* Canary for spotting overwrites */
#endif /* NDEBUG */
	} MEMLOCK_INFO;

/* The start and end of the list of allocated blocks, and a lock to protect
   it */

DECLARE_LOCKING_VARS( allocation )
static MEMLOCK_INFO *allocatedListHead, *allocatedListTail;

#ifdef __UNIX__

/* Since the function prototypes for the SYSV/POSIX mlock() call are stored
   all over the place depending on the Unix version, we usually have to
   prototype it ourselves here rather than trying to guess its location */

#if defined( __osf__ ) || defined( __alpha__ )
  #include <sys/mman.h>
#elif defined( sun )
  #include <sys/types.h>
#else
  int mlock( void *address, size_t length );
  int munlock( void *address, size_t length );
#endif /* Unix-variant-specific includes */

/* Under many Unix variants the SYSV/POSIX mlock() call can be used, but only
   by the superuser.  OSF/1 has mlock(), but this is defined to the
   nonexistant memlk() so we need to special-case it out.  Aches, A/UX, PHUX,
   Linux < 1.3.something, and Ultrix don't even pretend to have mlock().
   Many systems also have plock(), but this is pretty crude since it locks
   all data, and also has various other shortcomings.  Finally, PHUX has
   datalock(), which is just a plock() variant */

#if ( defined( __osf__ ) || defined( __alpha__ ) || defined( _AIX ) || \
	  defined( __hpux ) || defined( _M_XENIX ) || defined( __ultrix ) || \
	  defined( __aux ) || ( defined( __linux__ ) && OSVERSION < 2 ) ) || \
	  defined( __CYGWIN__ )
  #define NO_MLOCK
#endif /* Unix OS-specific defines */

#endif /* __UNIX__ */

#if defined( __MSDOS__ ) && defined( __DJGPP__ )
  #include <dpmi.h>
  #include <go32.h>
#endif /* DOS-32 */

#if defined( __MAC__ )
  #include <Memory.h>
#endif /* __MAC__ */

#if defined( __WIN32__ ) && !defined( NDEBUG ) && !defined( NT_DRIVER )
  #include <crtdbg.h>	/* For heap checking in debug version */
#endif /* Win32 debug version */

/* A secure version of malloc() and free() that perform page locking if
   necessary and zeroise memory before it is freed */

int krnlMemalloc( void **pointer, int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
#if defined( __BEOS__ ) && defined( USE_AREAS )
	area_id areaID;
#endif /* __BEOS__ && BeOS areas */

	/* Try and allocate the memory */
#ifndef NDEBUG
	size += CANARY_SIZE;				/* For canary at end of block */
#endif /* NDEBUG */
#if defined( __BEOS__ ) && defined( USE_AREAS )
	/* Under BeOS we have to allocate a locked area, we can't lock it after
	   the event.  create_area(), like most of the low-level memory access
	   functions provided by different OS's, functions at the page level, so
	   we round the size up to the page size.  We can mitigate the
	   granularity somewhat by specifying lazy locking, which means that the
	   page isn't locked until it's committed.

	   In pre-open-source BeOS areas, are were bit of a security tradeoff
	   because they were globally visible(!!!) through the use of
	   find_area(), so any other process in the system could find them.
	   An attacker could always find the app's malloc() arena anyway because
	   of this, but putting data directly into areas made an attacker's task
	   somewhat easier.  Open-source BeOS fixed this (mostly because it would
	   have taken extra work to make areas explicitly globally visible, and
	   no-one could see a reason for this, so it's somewhat safer there.

	   However, the implementation of create_area() in the open-source BeOS
	   seems to be rather flaky (simply creating an area and then
	   immediately destroying it again causes a segmentation violation) so
	   we allow it to be turned off if required */
	areaID = create_area( "memory_block", ( void ** ) &memPtr, B_ANY_ADDRESS,
						  roundUp( size + MEMLOCK_HEADERSIZE, B_PAGE_SIZE ),
						  B_LAZY_LOCK, B_READ_AREA | B_WRITE_AREA );
	if( areaID < B_NO_ERROR )
#else
	if( ( memPtr = clAlloc( "krnlMemAlloc", \
							size + MEMLOCK_HEADERSIZE ) ) == NULL )
#endif /* __BEOS__ && BeOS areas */
		{
		*pointer = NULL;
		return( CRYPT_ERROR_MEMORY );
		}
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
#if defined( __BEOS__ ) && defined( USE_AREAS )
	memBlockPtr->areaID = areaID;
#endif /* __BEOS__ && BeOS areas */
#ifndef NDEBUG
	memcpy( memBlockPtr->canary, CANARY_STARTVALUE, CANARY_SIZE );
	memcpy( memPtr + memBlockPtr->size - CANARY_SIZE, CANARY_ENDVALUE,
			CANARY_SIZE );
#endif /* NDEBUG */
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* If the OS supports paging, try to lock the pages in memory */
#if defined( __WIN32__ ) && !defined( NT_DRIVER )
	/* Under Win95 the VirtualLock() function is implemented as
	   `return( TRUE )' ("Thank Microsoft kids" - "Thaaaanks Bill").  Under
	   NT the function does actually work, but with a number of caveats.
	   The main one is that it has been claimed that VirtualLock() only
	   guarantees that the memory won't be paged while a thread in the
	   process is running, and when all threads are preempted the memory is
	   still a target for paging.  This would mean that on a loaded system a
	   process that was idle for some time could have the memory unlocked by
	   the system and swapped out to disk (actually with NT's somewhat
	   strange paging strategy and gradual creeping takeover of free memory
	   for disk buffers, it can get paged even on a completely unloaded
	   system).  However, attempts to force data to be paged under Win2K
	   and XP under various conditions have been unsuccesful, so it may be
	   that the behaviour changed in post-NT versions of the OS.  In any
	   case, VirtualLock() under these newer OSes seems to be fairly
	   effective in keeping data off disk.

	   An additional concern is that although VirtualLock() takes arbitrary
	   memory pointers and a size parameter, the locking is actually done on
	   a per-page basis, so that unlocking a region that shares a page with
	   another locked region means that both reqions are unlocked.  Since
	   VirtualLock() doesn't do reference counting (emulating the underlying
	   MMU page locking even though it seems to implement an intermediate
	   layer above the MMU so it could in theory do this), the only way
	   around this is to walk the chain of allocated blocks and not unlock a
	   block if there's another block allocated on the same page.  Ick.

	   For the NT kernel driver, the memory is always allocated from the non-
	   paged pool so there's no need for these gyrations */
	if( VirtualLock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
#elif defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS use the DPMI-functions to lock the memory */
	if( _go32_dpmi_lock_data( memPtr, memBlockPtr->size ) == 0)
		memBlockPtr->isLocked = TRUE;
#elif defined( __UNIX__ ) && !defined( NO_MLOCK )
	if( !mlock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
#elif defined( __MAC__ ) && !defined CALL_NOT_IN_CARBON || CALL_NOT_IN_CARBON
	/* The Mac has two functions for locking memory, HoldMemory() (which
	   makes the memory ineligible for paging) and LockMemory() (which makes
	   it ineligible for paging and also immovable).  We use HoldMemory()
	   since it's slightly more friendly, but really critical applications
	   could use LockMemory() */
	if( HoldMemory( memPtr, memBlockPtr->size ) == noErr )
		memBlockPtr->isLocked = TRUE;
#endif /* Systems that support memory locking */

	/* Lock the allocation information to ensure that other threads don't
	   try to access it */
	lockResource( allocation );

	/* If the allocation list is empty, make this the new list */
	if( allocatedListHead == NULL )
		allocatedListHead = allocatedListTail = memBlockPtr;
	else
		{
		/* Insert the element in the end of the list */
		allocatedListTail->next = memBlockPtr;
		memBlockPtr->prev = allocatedListTail;
		allocatedListTail = memBlockPtr;
		}

#if defined( __WIN32__ ) && !defined( NDEBUG ) && !defined( NT_DRIVER )
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL );
	assert( allocatedListHead == allocatedListTail || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* __WIN32__ debug && !NT_DRIVER */

	/* Unlock the allocation table to allow access by other threads */
	unlockResource( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

void krnlMemfree( void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr, *nextBlockPtr, *prevBlockPtr;
	BYTE *memPtr = ( BYTE * ) *pointer;
#if defined( __BEOS__ ) && defined( USE_AREAS )
	area_id areaID;
#endif /* __BEOS__ && BeOS areas */

	/* Make sure that we're not trying to free unallocated memory */
	if( memPtr == NULL )
		return;

	/* Get a pointer to the blocks header */
	memPtr -= MEMLOCK_HEADERSIZE;
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;

	/* Lock the allocation object to ensure that other threads don't try to
	   access them */
	lockResource( allocation );

	/* Make sure that nothing's overwritten our memory */
	assert( !memcmp( memBlockPtr->canary, CANARY_STARTVALUE, CANARY_SIZE ) );
	assert( !memcmp( memPtr + memBlockPtr->size - CANARY_SIZE,
					 CANARY_ENDVALUE, CANARY_SIZE ) );

#if defined( __WIN32__ ) && !defined( NDEBUG ) && !defined( NT_DRIVER )
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->next ) );
	assert( memBlockPtr->prev == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* __WIN32__ debug && !NT_DRIVER */

	/* Unlink the block from the allocation list */
	nextBlockPtr = memBlockPtr->next;
	prevBlockPtr = memBlockPtr->prev;
	if( memBlockPtr == allocatedListHead )
		allocatedListHead = nextBlockPtr;	/* Delete from start */
	else
		prevBlockPtr->next = nextBlockPtr;	/* Delete from middle or end */
	if( nextBlockPtr != NULL )
		nextBlockPtr->prev = prevBlockPtr;
	if( memBlockPtr == allocatedListTail )
		allocatedListTail = prevBlockPtr;

#if defined( __WIN32__ ) && !defined( NT_DRIVER )
	/* Because VirtualLock() works on a per-page basis, we can't unlock a
	   memory block if there's another locked block on the same page.  The
	   only way to manage this is to walk the block list checking to see
	   whether there's another block allocated on the same page.  Although in
	   theory this could make freeing memory rather slow, in practice there
	   are only a small number of allocated blocks to check so it's
	   relatively quick, especially compared to the overhead imposed by the
	   lethargic VC++ allocator.  The only real disadvantage is that the
	   allocation objects remain locked while we do the free, but this
	   isn't any worse than the overhead of touchAllocatedPages().

	   Note that the following code is nonportable in that it assumes
	   sizeof( long ) == sizeof( void * ), but this is currently the case on
	   Wintel hardware.  It also assumes that an allocated block will never
	   cover more than two pages, which is also always the case */
	if( memBlockPtr->isLocked )
		{
		MEMLOCK_INFO *currentBlockPtr;
		long block1PageAddress, block2PageAddress;

		/* Calculate the addresses of the page(s) in which the memory block
		   resides */
		block1PageAddress = getPageStartAddress( memBlockPtr );
		block2PageAddress = getPageEndAddress( memBlockPtr, memBlockPtr->size );
		if( block1PageAddress == block2PageAddress )
			block2PageAddress = 0;

		/* Walk down the block list checking whether the page(s) contain
		   another locked block */
		for( currentBlockPtr = allocatedListHead; currentBlockPtr != NULL;
			 currentBlockPtr = currentBlockPtr->next )
			{
			const long currentPage1Address = getPageStartAddress( currentBlockPtr );
			long currentPage2Address = getPageEndAddress( currentBlockPtr, currentBlockPtr->size );

			if( currentPage1Address == currentPage2Address )
				currentPage2Address = 0;

			/* There's another block allocated on either of the pages, don't
			   unlock it */
			if( block1PageAddress == currentPage1Address || \
				block1PageAddress == currentPage2Address )
				{
				block1PageAddress = 0;
				if( !block2PageAddress )
					break;
				}
			if( block2PageAddress == currentPage1Address || \
				block2PageAddress == currentPage2Address )
				{
				block2PageAddress = 0;
				if( !block1PageAddress )
					break;
				}
			}

		/* Finally, if either page needs unlocking, do so.  The supplied size
		   is irrelevant since the entire page the memory is on is unlocked */
		if( block1PageAddress )
			VirtualUnlock( ( void * ) block1PageAddress, 16 );
		if( block2PageAddress )
			VirtualUnlock( ( void * ) block2PageAddress, 16 );
		}
#endif /* __WIN32__ && !NT_DRIVER */

	/* Unlock the allocation object to allow access by other threads */
	unlockResource( allocation );

	/* If the memory is locked, unlock it now */
#if defined( __UNIX__ ) && !defined( NO_MLOCK )
	if( memBlockPtr->isLocked )
		munlock( memPtr, memBlockPtr->size );
#elif defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS we *could* use the DPMI-functions to unlock the
	   memory, but as many DPMI hosts implement page locking in a binary form
	   (no lock count maintained), we don't actually unlock anything at all.
	   Note that this may lead to a shortage of virtual memory in long-
	   running applications */
#elif defined( __MAC__ )
  #if !defined CALL_NOT_IN_CARBON || CALL_NOT_IN_CARBON
	if( memBlockPtr->isLocked )
		UnholdMemory( memPtr, memBlockPtr->size );
  #endif /* Handling for Mac Carbon API */
#elif defined( __BEOS__ ) && defined( USE_AREAS )
	areaID = memBlockPtr->areaID;
	zeroise( memPtr, memBlockPtr->size );
	delete_area( areaID );
#endif /* Systems that support memory locking */

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
#if !( defined( __BEOS__ ) && defined( USE_AREAS ) )
	zeroise( memPtr, memBlockPtr->size );
	clFree( "krnlMemFree", memPtr );
#endif /* !( __BEOS__ && BeOS areas ) */
	*pointer = NULL;
	}

/* Determine the size of a krnlMemalloc()'d memory block */

int krnlMemsize( const void *pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr = ( BYTE * ) pointer;

	/* Make sure that it's a valid pointer */
	if( memPtr == NULL )
		return( 0 );

	/* Find out how big the memory block is */
	memPtr -= MEMLOCK_HEADERSIZE;
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;

	/* Make sure that nothing's overwritten our memory */
	assert( !memcmp( memBlockPtr->canary, CANARY_STARTVALUE, CANARY_SIZE ) );
	assert( !memcmp( memPtr + memBlockPtr->size - CANARY_SIZE,
					 CANARY_ENDVALUE, CANARY_SIZE ) );

	return( memBlockPtr->size - MEMLOCK_HEADERSIZE );
	}

#if 0	/* Currently unused, in practice would be called from a worker thread
		   that periodically touches all secure-data pages */
/* Walk the allocated block list touching each page.  In most cases we don't
   need to explicitly touch the page since the allocated blocks are almost
   always smaller than the MMU's page size and simply walking the list
   touches them, but in some rare cases we need to explicitly touch each
   page */

static void touchAllocatedPages( void )
	{
	MEMLOCK_INFO *memBlockPtr;

	/* Lock the allocation object to ensure that other threads don't try to
	   access them */
	lockResource( allocation );

	/* Walk down the list (which implicitly touches each page).  If the
	   allocated region is larger than 4K, explicitly touch each 4K page.
	   This assumes a page size of 4K which is usually true (and difficult
	   to determine otherwise), in any case it doesn't make much difference
	   since nothing ever allocates more than two 4K pages */
	for( memBlockPtr = allocatedListHead; memBlockPtr != NULL;
		 memBlockPtr = memBlockPtr->next )
		{
		if( memBlockPtr->size > 4096 )
			{
			BYTE *memPtr = ( BYTE * ) memBlockPtr + 4096;
			int memSize = memBlockPtr->size;

			/* Touch each page.  The rather convoluted expression is to try
			   and stop it from being optimised away - it always evaluates to
			   true since we only get here if allocatedListHead != NULL, but
			   hopefully the compiler won't be able to figure that out */
			while( memSize > 4096 )
				{
				if( *memPtr || allocatedListHead != NULL )
					memPtr += 4096;
				memSize -= 4096;
				}
			}
		}

	/* Unlock the allocation object to allow access by other threads */
	unlockResource( allocation );
	}
#endif /* 0 */

/* Create and destroy the secure allocation information */

static void initAllocation( void )
	{
	/* Clear the list head and tail pointers */
	allocatedListHead = allocatedListTail = NULL;

	/* Initialize any data structures required to make the allocation thread-
	   safe */
	initResourceLock( allocation );
	}

static void endAllocation( void )
	{
	/* Destroy any data structures required to make the allocation thread-
	   safe */
	deleteResourceLock( allocation );
	}

/****************************************************************************
*																			*
*							Key Extract Functions							*
*																			*
****************************************************************************/

/* The cryptlib equivalent of trusted downgraders in ohter security models:
   Functions that extract a key from a context.  These functions need to
   bypass the kernel's security checking in order to allow key export and
   are the only ones that can do this.  This is an unavoidable requirement
   in the complete-isolation model - some bypass mechanism needs to be
   present in order to allow a key to be exported from an encryption action
   object.  The three functions that perform the necessary operations are:

	extractKeyData: Extract a session key from a conventional/MAC context
					prior to encryption with a KEK.
	exportPrivateKey: Write private key data to a stream prior to encryption
					  with a KEK.
	importPrivateKey: Read private key data from a stream after decryption
					  with a KEK */

#ifdef INC_ALL
  #include "context.h"
#else
  #include "misc/context.h"
#endif /* Compiler-specific includes */

static int getContext( const int objectHandle, void **objectPtr )
	{
	OBJECT_INFO *objectInfoPtr;
	int status = CRYPT_OK;

	/* Preconditions: It's a valid object */
	PRE( isValidHandle( objectHandle ) );
	PRE( isWritePtr( objectPtr, sizeof( void * ) ) );

	/* Clear the return value */
	*objectPtr = NULL;

	lockResource( objectTable );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(): It's a valid object owned by the calling thread */
	if( !isValidObject( objectHandle ) || \
		!checkObjectOwnership( objectTable[ objectHandle ] ) )
		{
		unlockResource( objectTable );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];

	/* This function can only be called on contexts */
	if( objectInfoPtr->type != OBJECT_TYPE_CONTEXT )
		{
		unlockResource( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Inner precondition: It's a context */
	PRE( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );

	/* If the object is busy, wait for it to become available */
	if( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) )
		status = waitForObject( objectHandle, &objectInfoPtr );
	if( cryptStatusOK( status ) )
		{
		objectInfoPtr->lockCount++;
		objectInfoPtr->lockOwner = THREAD_SELF();
		*objectPtr = objectInfoPtr->objectPtr;
		}

	unlockResource( objectTable );
	return( status );
	}

int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData )
	{
	CONTEXT_INFO *contextInfoPtr;
	int status;

	status = getContext( iCryptContext, ( void ** ) &contextInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type == CONTEXT_CONV )
		memcpy( keyData, contextInfoPtr->ctxConv->userKey,
				contextInfoPtr->ctxConv->userKeyLength );
	else
		memcpy( keyData, contextInfoPtr->ctxMAC->userKey,
				contextInfoPtr->ctxMAC->userKeyLength );
	releaseObject( contextInfoPtr->objectHandle, FALSE );
	return( status );
	}

int exportPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE formatType )
	{
	CRYPT_CONTEXT iPrivateKeyContext;
	CONTEXT_INFO *contextInfoPtr;
	int status;

	/* We may have been passed something else with a context attached, get the
	   context itself */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETDEPENDENT,
							  &iPrivateKeyContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that we've been given a PKC context with a private key
	   loaded.  This has already been checked at a higher level, but we
	   perform a sanity check here to be safe */
	status = getContext( iPrivateKeyContext, ( void ** ) &contextInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type != CONTEXT_PKC ||
		!( contextInfoPtr->flags & CONTEXT_KEY_SET ) || \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		releaseObject( contextInfoPtr->objectHandle, FALSE );
		return( CRYPT_ARGERROR_OBJECT );
		}

	status = contextInfoPtr->ctxPKC->writePrivateKeyFunction( stream, 
										contextInfoPtr, formatType, "private" );
	releaseObject( contextInfoPtr->objectHandle, FALSE );
	return( status );
	}

int importPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE formatType )
	{
	CONTEXT_INFO *contextInfoPtr;
	int status;

	status = getContext( iCryptContext, ( void ** ) &contextInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	status = contextInfoPtr->ctxPKC->readPrivateKeyFunction( stream, 
										contextInfoPtr, formatType );
	if( cryptStatusOK( status ) )
		{
		/* If everything went OK, perform an internal load that uses the
		   values already present in the context */
		status = contextInfoPtr->loadKeyFunction( contextInfoPtr, NULL, 0 );
		if( cryptStatusOK( status ) )
			{
			krnlSendMessage( contextInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED,
							 CRYPT_IATTRIBUTE_INITIALISED );
			contextInfoPtr->flags |= CONTEXT_KEY_SET;
			}
		else
			if( cryptArgError( status ) )
				/* Map the status to a more appropriate code */
				status = CRYPT_ERROR_BADDATA;
		}
	releaseObject( contextInfoPtr->objectHandle, FALSE );
	return( status );
	}

/* Copy the contents of one context into another.  This code is used to
   implement copy-on-write of non-idempotent contexts */

static int cloneContext( const CRYPT_CONTEXT iDestContext,
						 const CRYPT_CONTEXT iSrcContext )
	{
	CRYPT_USER ownerHandle;
	CONTEXT_INFO *srcInfoPtr, *destInfoPtr;
	CONTEXT_TYPE contextType;
	int subType, actionFlags, status;

	PRE( iSrcContext != iDestContext );

	/* Get the source and destination objects */
	status = getContext( iSrcContext, ( void ** ) &srcInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	status = getContext( iDestContext, ( void ** ) &destInfoPtr );
	if( cryptStatusError( status ) )
		{
		releaseObject( srcInfoPtr->objectHandle, FALSE );
		return( status );
		}
	contextType = srcInfoPtr->type;
	subType = ( contextType == CONTEXT_CONV ) ? SUBTYPE_CTX_CONV : \
			  ( contextType == CONTEXT_HASH ) ? SUBTYPE_CTX_HASH : SUBTYPE_CTX_MAC;
	ownerHandle = destInfoPtr->ownerHandle;

	/* Precondition: The contexts are of the correct type, and the clone has
	   everything set up ready to go */
	PRE( contextType == CONTEXT_CONV || contextType == CONTEXT_HASH || \
		 contextType == CONTEXT_MAC );
	PRE( srcInfoPtr->type == destInfoPtr->type );
	PRE( srcInfoPtr->storageSize == destInfoPtr->storageSize );
	PRE( contextType != CONTEXT_CONV || srcInfoPtr->ctxConv->key != NULL );
	PRE( contextType != CONTEXT_HASH || srcInfoPtr->ctxHash->hashInfo != NULL );
	PRE( contextType != CONTEXT_MAC || srcInfoPtr->ctxMAC->macInfo != NULL );

	/* Copy across the context contents and reset any instance-specific 
	   information */
	memcpy( destInfoPtr, srcInfoPtr, 
			sizeofVarStruct( srcInfoPtr, CONTEXT_INFO ) );
	destInfoPtr->objectHandle = iDestContext;	/* Replace overwritten handle */
	destInfoPtr->ownerHandle = ownerHandle;		/* Replace overwritten owner */
	switch( contextType )
		{
		case CONTEXT_CONV:
			destInfoPtr->ctxConv = ( CONV_INFO * ) destInfoPtr->storage;
			break;

		case CONTEXT_HASH:
			destInfoPtr->ctxHash = ( HASH_INFO * ) destInfoPtr->storage;
			break;

		case CONTEXT_MAC:
			destInfoPtr->ctxMAC = ( MAC_INFO * ) destInfoPtr->storage;
			break;

		default:
			assert( NOTREACHED );
		}

	/* We've copied the state from one context to the other, we're done */
	releaseObject( srcInfoPtr->objectHandle, FALSE );
	releaseObject( destInfoPtr->objectHandle, FALSE );

	/* Since this is an internal-use-only object, lock down the action
	   permissions so that only encryption and hash actions from internal
	   sources are allowed (assuming they were allowed to begin with).
	   Keygen is disabled entirely (there should already be a key loaded),
	   and signing isn't possible with a non-PKC object anyway */
	actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_NONE_EXTERNAL );
	return( krnlSendMessage( iDestContext, IMESSAGE_SETATTRIBUTE, &actionFlags,
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

/****************************************************************************
*																			*
*						Initialisation Management Functions					*
*																			*
****************************************************************************/

/* Begin and end initialisation by locking or unlocking the initialisation
   mutex and checking or setting the flag that determines whether we're
   initialised or not */

BOOLEAN beginInitialisation( const BOOLEAN checkState )
	{
#if defined( USE_THREADS ) && \
	!( defined( __WIN32__ ) && !defined( STATIC_LIB ) )
	if( checkState && !isInitialised )
		{
		/* We're starting up, set up the initialisation lock if it's not
		   already set up */
		initResourceLock( initialisation );
		}
#endif /* USE_THREADS && !( Win32 DLL ) */

	/* Lock the initialisation mutex to make sure that other threads don't
	   try to access it */
	lockResource( initialisation );

	/* If we're already initialised or shut down, don't to anything */
	if( isInitialised == checkState )
		{
		unlockResource( initialisation );
		return( FALSE );
		}
	return( TRUE );
	}

void endInitialisation( const BOOLEAN newState )
	{
	isInitialised = newState;
	unlockResource( initialisation );
#if defined( USE_THREADS ) && \
	!( defined( __WIN32__ ) && !defined( STATIC_LIB ) )
	if( !newState && isInitialised )
		{
		/* We're shutting down, destroy the initialisation lock if it's not
		   already destroyed */
		deleteResourceLock( initialisation );
		}
#endif /* USE_THREADS && !( Win32 DLL ) */
	}

/* Before we can begin and end initialisation, we need to initialise the
   initialisation lock.  This gets a bit complex, and is handled in the
   following order of preference:

	A. Systems where the OS contacts a module to tell it to initialise itself
	   before it's called directly for the first time (Win32 DLLs).
	B. Systems where statically initialising the lock to an all-zero value is
	   equivalent to intialising it a runtime (most pthreads implementations).
	C. Systems where the lock must be statically initialised at runtime.

   A and B are thread-safe, C isn't thread-safe but unlikely to be a problem
   except in highly unusual situations (two different threads entering
   beginInitialisation() at the same time) and not something we can fix
   without OS support, e.g. under Win32.

   To handle this pre-initialisation, we provide the following functions for
   use with case A, statically initialise the lock to handle case B, and
   initialise it if required in beginInitialisation() to handle case C */

#if defined( __WIN32__ )

void preInit( void )
	{
	initResourceLock( initialisation );
	}

void postShutdown( void )
	{
	deleteResourceLock( initialisation );
	}
#endif /* Win32 DLL */

/* General internal function initialisation and shutdown */

#define ACCESS_RWx_xxx		0x6060	/* Special-case used for consistency check */

int initInternalFunctions( void )
	{
	const time_t currentTime = getTime();
	int i, status;

	/* Perform a consistency check on various things that need to be set
	   up in a certain way for things to work properly (the context message
	   sequencing is checked indirectly further down as well, but the check
	   done here is more explicit) */
	assert( OBJECT_INFO_TEMPLATE.type == OBJECT_TYPE_NONE );
	assert( OBJECT_INFO_TEMPLATE.flags == \
			( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ) );
	assert( OBJECT_INFO_TEMPLATE.actionFlags == 0 );
	assert( OBJECT_INFO_TEMPLATE.subType == 0 );
	assert( OBJECT_INFO_TEMPLATE.forwardCount == CRYPT_UNUSED );
	assert( OBJECT_INFO_TEMPLATE.usageCount == CRYPT_UNUSED );
	assert( OBJECT_INFO_TEMPLATE.owner == CRYPT_ERROR );
	assert( OBJECT_INFO_TEMPLATE.dependentDevice == CRYPT_ERROR );
	assert( OBJECT_INFO_TEMPLATE.dependentObject == CRYPT_ERROR );
	assert( MESSAGE_CTX_DECRYPT == MESSAGE_CTX_ENCRYPT + 1 );
	assert( MESSAGE_CTX_SIGN == MESSAGE_CTX_DECRYPT + 1 );
	assert( MESSAGE_CTX_SIGCHECK == MESSAGE_CTX_SIGN + 1 );
	assert( MESSAGE_CTX_HASH == MESSAGE_CTX_SIGCHECK + 1 );
	assert( MESSAGE_CTX_GENKEY == MESSAGE_CTX_HASH + 1 );
	assert( MESSAGE_GETATTRIBUTE_S == MESSAGE_GETATTRIBUTE + 1 );
	assert( MESSAGE_SETATTRIBUTE == MESSAGE_GETATTRIBUTE_S + 1 );
	assert( MESSAGE_SETATTRIBUTE_S == MESSAGE_SETATTRIBUTE + 1 );
	assert( MESSAGE_DELETEATTRIBUTE == MESSAGE_SETATTRIBUTE_S + 1 );
	assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2 );
	assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1 );

	/* Perform a consistency check on the attribute ACLs */
	for( i = 0; i < CRYPT_PROPERTY_LAST - CRYPT_PROPERTY_FIRST - 1; i++ )
		{
		assert( propertyACL[ i ].attribute == i + CRYPT_PROPERTY_FIRST + 1 );
		assert( propertyACL[ i ].subTypeA == ST_ANY || \
				!( propertyACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( propertyACL[ i ].subTypeB == ST_ANY || \
				!( propertyACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( propertyACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( propertyACL[ CRYPT_PROPERTY_LAST - \
						 CRYPT_PROPERTY_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_GENERIC_LAST - CRYPT_GENERIC_FIRST - 1; i++ )
		{
		assert( genericACL[ i ].attribute == i + CRYPT_GENERIC_FIRST + 1 );
		assert( genericACL[ i ].subTypeA == ST_ANY || \
				!( genericACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( genericACL[ i ].subTypeB == ST_ANY || \
				!( genericACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( genericACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( genericACL[ CRYPT_GENERIC_LAST - \
						CRYPT_GENERIC_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST - 1; i++ )
		{
		assert( optionACL[ i ].attribute == i + CRYPT_OPTION_FIRST + 1 );
		assert( !( optionACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( optionACL[ i ].attribute >= CRYPT_OPTION_KEYING_ALGO && \
				  optionACL[ i ].attribute <= CRYPT_OPTION_KEYING_ITERATIONS && \
				  optionACL[ i ].subTypeA == ST_CTX_CONV ) ||
				( optionACL[ i ].attribute >= CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS && \
				  optionACL[ i ].attribute <= CRYPT_OPTION_KEYS_LDAP_EMAILNAME && \
				  optionACL[ i ].subTypeA == ST_KEYSET_LDAP ) ||
				optionACL[ i ].subTypeA == ST_NONE );
		assert( !( optionACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( ( optionACL[ i ].attribute >= CRYPT_OPTION_ENCR_ALGO && \
				  optionACL[ i ].attribute <= CRYPT_OPTION_ENCR_MAC && \
				  ( optionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_ENV_ENV | \
												 ST_ENV_ENV_PGP | ST_USER_ANY ) ) == 0 ) ||
				( optionACL[ i ].attribute >= CRYPT_OPTION_NET_SOCKS_SERVER && \
				  optionACL[ i ].attribute <= CRYPT_OPTION_NET_TIMEOUT && \
				  optionACL[ i ].subTypeB == ( ST_SESS_ANY | ST_USER_ANY ) ) ||
				( optionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_USER_ANY ) ) == 0 );
		assert( optionACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( optionACL[ CRYPT_OPTION_LAST - \
					   CRYPT_OPTION_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CTXINFO_LAST - CRYPT_CTXINFO_FIRST - 1; i++ )
		{
		assert( contextACL[ i ].attribute == i + CRYPT_CTXINFO_FIRST + 1 );
		assert( !( contextACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( contextACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CTX_ANY ) ) == 0 );
		assert( contextACL[ i ].subTypeB == ST_NONE );
		assert( contextACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( contextACL[ CRYPT_CTXINFO_LAST - \
						CRYPT_CTXINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_CERTINFO - CRYPT_CERTINFO_FIRST_CERTINFO; i++ )
		{
		assert( certificateACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_CERTINFO );
		assert( !( certificateACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( certificateACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_ANY ) ) == 0 );
		assert( certificateACL[ i ].subTypeB == ST_NONE );
		assert( certificateACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( certificateACL[ CRYPT_CERTINFO_LAST_CERTINFO - \
							CRYPT_CERTINFO_FIRST_CERTINFO + 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_NAME - CRYPT_CERTINFO_FIRST_NAME; i++ )
		{
		assert( certNameACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_NAME );
		assert( !( certNameACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( certNameACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_ANY ) ) == 0 );
		assert( certNameACL[ i ].subTypeB == ST_NONE );
		assert( certNameACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		assert( certNameACL[ i ].attribute == CRYPT_CERTINFO_DIRECTORYNAME || \
				certNameACL[ i ].access == ACCESS_Rxx_RWD );
		}
	assert( certNameACL[ CRYPT_CERTINFO_LAST_NAME - \
						 CRYPT_CERTINFO_FIRST_NAME + 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_EXTENSION - CRYPT_CERTINFO_FIRST_EXTENSION; i++ )
		{
		assert( certExtensionACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_EXTENSION );
		assert( !( certExtensionACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( certExtensionACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_ANY ) ) == 0 );
		assert( certExtensionACL[ i ].subTypeB == ST_NONE );
		assert( ( certExtensionACL[ i ].access & ACCESS_RWD_xxx ) == \
				( ( certExtensionACL[ i ].lowRange == RANGE_EXT_MARKER && \
					certExtensionACL[ i ].highRange == RANGEVAL_SELECTVALUE ) ?
				  ACCESS_RWx_xxx : ACCESS_Rxx_xxx ) );
		assert( certExtensionACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( certExtensionACL[ CRYPT_CERTINFO_LAST_EXTENSION - \
							  CRYPT_CERTINFO_FIRST_EXTENSION + 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_CMS - CRYPT_CERTINFO_FIRST_CMS; i++ )
		{
		assert( certSmimeACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_CMS );
		assert( !( certSmimeACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( certSmimeACL[ i ].attribute == CRYPT_CERTINFO_CMS_NONCE && \
				  ( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR | \
													ST_CERT_RTCS_REQ ) ) == 0 ) || \
				( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR ) ) == 0 );
		assert( certSmimeACL[ i ].subTypeB == ST_NONE );
		assert( ( certSmimeACL[ i ].access & ACCESS_RWD_xxx ) == \
				( ( certSmimeACL[ i ].lowRange == RANGE_EXT_MARKER && \
					certSmimeACL[ i ].highRange == RANGEVAL_SELECTVALUE ) ?
				  ACCESS_RWx_xxx : ACCESS_Rxx_xxx ) );
		assert( certSmimeACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( certSmimeACL[ CRYPT_CERTINFO_LAST_CMS - \
						  CRYPT_CERTINFO_FIRST_CMS + 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_KEYINFO_LAST - CRYPT_KEYINFO_FIRST - 1; i++ )
		{
		assert( keysetACL[ i ].attribute == i + CRYPT_KEYINFO_FIRST + 1 );
		assert( !( keysetACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keysetACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_KEYSET_ANY ) ) == 0 );
		assert( keysetACL[ i ].subTypeB == ST_NONE );
		assert( keysetACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( keysetACL[ CRYPT_KEYINFO_LAST - \
					   CRYPT_KEYINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_DEVINFO_LAST - CRYPT_DEVINFO_FIRST - 1; i++ )
		{
		assert( deviceACL[ i ].attribute == i + CRYPT_DEVINFO_FIRST + 1 );
		assert( !( deviceACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( deviceACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_DEV_ANY_STD ) ) == 0 );
		assert( deviceACL[ i ].subTypeB == ST_NONE );
		assert( deviceACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( deviceACL[ CRYPT_DEVINFO_LAST - \
					   CRYPT_DEVINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_ENVINFO_LAST - CRYPT_ENVINFO_FIRST - 1; i++ )
		{
		assert( envelopeACL[ i ].attribute == i + CRYPT_ENVINFO_FIRST + 1 );
		assert( envelopeACL[ i ].subTypeA == ST_NONE );
		assert( !( envelopeACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( ( envelopeACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_ENV_ANY ) ) == 0 );
		assert( envelopeACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( envelopeACL[ CRYPT_ENVINFO_LAST - \
						 CRYPT_ENVINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_SESSINFO_LAST - CRYPT_SESSINFO_FIRST - 1; i++ )
		{
		assert( sessionACL[ i ].attribute == i + CRYPT_SESSINFO_FIRST + 1 );
		assert( sessionACL[ i ].subTypeA == ST_NONE );
		assert( !( sessionACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( ( sessionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_SESS_ANY ) ) == 0 );
		assert( sessionACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( sessionACL[ CRYPT_SESSINFO_LAST - \
						CRYPT_SESSINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_USERINFO_LAST - CRYPT_USERINFO_FIRST - 1; i++ )
		{
		assert( userACL[ i ].attribute == i + CRYPT_USERINFO_FIRST + 1 );
		assert( userACL[ i ].subTypeA == ST_NONE );
		assert( !( userACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( ( userACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_USER_ANY ) ) == 0 );
		assert( userACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( userACL[ CRYPT_USERINFO_LAST - \
					 CRYPT_USERINFO_FIRST - 1 ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_IATTRIBUTE_LAST - CRYPT_IATTRIBUTE_FIRST - 1; i++ )
		{
		assert( internalACL[ i ].attribute == i + CRYPT_IATTRIBUTE_FIRST + 1 );
		assert( internalACL[ i ].subTypeA == ST_ANY || \
				!( internalACL[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( internalACL[ i ].subTypeB == ST_ANY || \
				!( internalACL[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		assert( ( internalACL[ i ].access & ACCESS_MASK_EXTERNAL ) == 0 );
		assert( internalACL[ i ].flags < ATTRIBUTE_FLAG_LAST );
		}
	assert( internalACL[ CRYPT_IATTRIBUTE_LAST - \
						 CRYPT_IATTRIBUTE_FIRST - 1 ].attribute == CRYPT_ERROR );

	/* Perform a consistency check on the parameter ACLs */
	for( i = 0; paramACLTbl[ i ].type != MESSAGE_NONE; i++ )
		{
		assert( isParamMessage( paramACLTbl[ i ].type ) );
		assert( !( paramACLTbl[ i ].objectACL.subTypeA & SUBTYPE_CLASS_B ) );
		assert( !( paramACLTbl[ i ].objectACL.subTypeB & SUBTYPE_CLASS_A ) );
		}

	/* Perform a consistency check on the key management ACLs */
	for( i = KEYMGMT_ITEM_NONE; i < KEYMGMT_ITEM_LAST; i++ )
		{
		assert( keyManagementACL[ i ].itemType == i );
		assert( !( keyManagementACL[ i ].keysetR_subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].keysetR_subTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].keysetR_subTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].keysetW_subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].keysetW_subTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].keysetW_subTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].keysetD_subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].keysetD_subTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].keysetD_subTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].keysetFN_subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].keysetFN_subTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].keysetFN_subTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].keysetQ_subTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].keysetQ_subTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].keysetQ_subTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].objSubTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].objSubTypeA & \
				~( SUBTYPE_CLASS_A | ST_CERT_ANY | ST_CTX_PKC | ST_CTX_CONV ) ) == 0 );
		assert( keyManagementACL[ i ].objSubTypeB == ST_NONE );
		assert( keyManagementACL[ i ].allowedFlags >= KEYMGMT_FLAG_NONE && \
				keyManagementACL[ i ].allowedFlags < KEYMGMT_FLAG_LAST );
		assert( !( keyManagementACL[ i ].specificKeysetSubTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].specificKeysetSubTypeA & \
				~( SUBTYPE_CLASS_A | ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11 ) ) == 0 );
		assert( keyManagementACL[ i ].specificKeysetSubTypeB == ST_NONE );
		assert( !( keyManagementACL[ i ].specificObjSubTypeA & SUBTYPE_CLASS_B ) );
		assert( ( keyManagementACL[ i ].specificObjSubTypeA & \
				~( SUBTYPE_CLASS_A | ST_CERT_ANY ) ) == 0 );
		assert( keyManagementACL[ i ].specificObjSubTypeB == ST_NONE );
		}

	/* Perform a consistency check on the message handling information */
	for( i = 0; i < MESSAGE_LAST; i++ )
		{
		assert( messageHandlingInfo[ i ].messageType == i );
		assert( messageHandlingInfo[ i ].subTypeA == ST_ANY || \
				!( messageHandlingInfo[ i ].subTypeA & SUBTYPE_CLASS_B ) );
		assert( messageHandlingInfo[ i ].subTypeB == ST_ANY || \
				!( messageHandlingInfo[ i ].subTypeB & SUBTYPE_CLASS_A ) );
		}

	/* Perform a consistency check on values used to handle ACL subranges.
	   These are somewhat tricky to check automatically since they represent
	   variable start and end ranges, we hardcode in absolute values to
	   ensure that adding new attributes in the header file will trigger an
	   exception here to provide a reminder to change the range-end
	   definitions as well */
	assert( CRYPT_CERTINFO_FIRST_CERTINFO == 2001 );
	assert( CRYPT_CERTINFO_LAST_CERTINFO == 2034 );
	assert( CRYPT_CERTINFO_FIRST_PSEUDOINFO == 2001 );
	assert( CRYPT_CERTINFO_LAST_PSEUDOINFO == 2013 );
	assert( CRYPT_CERTINFO_FIRST_NAME == 2100 );
	assert( CRYPT_CERTINFO_LAST_NAME == 2115 );
	assert( CRYPT_CERTINFO_FIRST_DN == 2100 );
	assert( CRYPT_CERTINFO_LAST_DN == 2105 );
	assert( CRYPT_CERTINFO_FIRST_GENERALNAME == 2106 );
	assert( CRYPT_CERTINFO_LAST_GENERALNAME == 2115 );
	assert( CRYPT_CERTINFO_FIRST_EXTENSION == 2200 );
	assert( CRYPT_CERTINFO_FIRST_CMS == 2500 );
	assert( CRYPT_SESSINFO_FIRST_SPECIFIC == 6015 );
	assert( CRYPT_SESSINFO_LAST_SPECIFIC == 6023 );
	assert( CRYPT_CERTFORMAT_LAST == 10 );

	/* Perform a consistency check on various internal values and constants */
	assert( ACTION_PERM_COUNT == 6 );

	/* If the time is screwed up we can't safely do much since so many
	   protocols and operations depend on it */
	if( currentTime < MIN_TIME_VALUE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	initAllocation();
	initMutexes();
	initSemaphores();
	status = initObjectTable();
	if( cryptStatusError( status ) )
		{
		endSemaphores();
		endAllocation();
		}
	isInitialised = TRUE;
	return( status );
	}

void endInternalFunctions( void )
	{
	endObjectTable();
	endMutexes();
	endSemaphores();
	endAllocation();
	}
