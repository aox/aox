/****************************************************************************
*																			*
*							cryptlib Kernel Header File						*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#ifndef _KERNEL_DEFINED

#define _KERNEL_DEFINED

#if defined( INC_ALL )
  #include "thread.h"
#else
  #include "kernel/thread.h"
#endif /* Compiler-specific includes */

/* RAY and EGON look over code.

   EGON: The structure of this kernel is exactly like the kind of telemetry
         tracker that NASA uses to secure dead pulsars in deep space.

   RAY: All message dispatch mechanisms and callback functions.

   PETER (to other jailbirds): Everyone getting this so far?  So what?  I
         guess they just don't make them like they used to.

   RAY: No!  Nobody ever made them like this!  The architect was either a
        certified genius or an authentic wacko! */

/* "There is a fine line between genius and insanity.
    I have erased this line" - Oscar Levant
	(or "Nullum magnum ingenium sine mixtura dementiae" if you want it in
	the usual style) */

/****************************************************************************
*																			*
*							Parameter Checking Macros						*
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
	isObjectOwner(): If inUse == TRUE, whether this thread is the one using
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
		( ( handle ) >= 0 && ( handle ) < krnlData->objectTableSize )
#define isValidObject( handle ) \
		( isValidHandle( handle ) && \
		  krnlData->objectTable[ ( handle ) ].objectPtr != NULL )
#define isFreeObject( handle ) \
		( isValidHandle( handle ) && \
		  krnlData->objectTable[ ( handle ) ].objectPtr == NULL )
#define isInternalObject( handle ) \
		( krnlData->objectTable[ handle ].flags & OBJECT_FLAG_INTERNAL )
#define isObjectAccessValid( objectHandle, message ) \
		!( isInternalObject( objectHandle ) && \
		   !( message & MESSAGE_FLAG_INTERNAL ) )
#define isInvalidObjectState( handle ) \
		( krnlData->objectTable[ ( handle ) ].flags & OBJECT_FLAGMASK_STATUS )
#define isInUse( handle ) \
		( krnlData->objectTable[ ( handle ) ].lockCount > 0 )
#define isObjectOwner( handle ) \
		THREAD_SAME( krnlData->objectTable[ ( handle ) ].lockOwner, THREAD_SELF() )
#define isInHighState( handle ) \
		( krnlData->objectTable[ ( handle ) ].flags & OBJECT_FLAG_HIGH )
#define isSameOwningObject( handle1, handle2 ) \
		( krnlData->objectTable[ ( handle1 ) ].owner == CRYPT_UNUSED || \
		  krnlData->objectTable[ ( handle2 ) ].owner == CRYPT_UNUSED || \
		  ( krnlData->objectTable[ ( handle1 ) ].owner == \
							krnlData->objectTable[ ( handle2 ) ].owner ) || \
		  ( ( handle1 ) == krnlData->objectTable[ ( handle2 ) ].owner ) )
#define isAliasedObject( handle ) \
		( krnlData->objectTable[ handle ].flags & OBJECT_FLAG_ALIASED )
#define isClonedObject( handle ) \
		( krnlData->objectTable[ handle ].flags & OBJECT_FLAG_CLONE )
#define isValidMessage( message ) \
		( ( message ) > MESSAGE_NONE && ( message ) < MESSAGE_LAST )
#define isValidType( type ) \
		( ( type ) > OBJECT_TYPE_NONE && ( type ) < OBJECT_TYPE_LAST )
#define isValidSubtype( subtypeMask, subtype ) \
		( ( ( subtypeMask ) & ( subtype ) ) == ( subtype ) )

/* The set of object checks is used frequently enough that we combine them
   into a composite check that performs all of the checks in one place */

#define fullObjectCheck( objectHandle, message ) \
		( isValidObject( objectHandle ) && \
		  isObjectAccessValid( objectHandle, message ) && \
		  checkObjectOwnership( objectTable[ objectHandle ] ) )

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
   status code.  The values are prioritised so that notinited > signalled >
   busy */

#define getObjectStatusValue( flags ) \
		( ( flags & OBJECT_FLAG_NOTINITED ) ? CRYPT_ERROR_NOTINITED : \
		  ( flags & OBJECT_FLAG_SIGNALLED ) ? CRYPT_ERROR_SIGNALLED : \
		  ( flags & OBJECT_FLAG_BUSY ) ? CRYPT_ERROR_TIMEOUT : CRYPT_OK )

/****************************************************************************
*																			*
*						Object Definitions and Information					*
*																			*
****************************************************************************/

/* The information maintained by the kernel for each object */

typedef struct {
	/* Object type and value */
	OBJECT_TYPE type;			/* Object type */
	OBJECT_SUBTYPE subType;		/* Object subtype */
	void *objectPtr;			/* Object data */
	int objectSize;				/* Object data size */

	/* Object properties */
	int flags;					/* Internal-only, locked, etc */
	int actionFlags;			/* Permitted actions */
	int referenceCount;			/* Number of references to this object */
	int lockCount;				/* Message-processing lock recursion count */
#ifdef USE_THREADS
	THREAD_HANDLE lockOwner;	/* Lock owner if lockCount > 0 */
#endif /* USE_THREADS */
	int uniqueID;				/* Unique ID for this object */
/*	time_t lastAccess;			// Last access time */

	/* Object security properties */
	int forwardCount;			/* Number of times ownership can be transferred */
	int usageCount;				/* Number of times obj.can be used */
#ifdef USE_THREADS
	THREAD_HANDLE objectOwner;	/* The object's owner */
#endif /* USE_THREADS */

	/* Object methods */
	MESSAGE_FUNCTION messageFunction; /* The object's message handler */

	/* Owning and dependent objects */
	CRYPT_USER owner;			/* Owner object handle */
	CRYPT_HANDLE dependentObject;	/* Dependent object (context or cert) */
	CRYPT_HANDLE dependentDevice;	/* Dependent crypto device */
#if 0	/* 18/2/04 No need for copy-on-write any more */
	CRYPT_HANDLE clonedObject;	/* Cloned object if aliased */
#endif /* 0 */
	} OBJECT_INFO;

/* The flags that apply to each object in the table */

#define OBJECT_FLAG_NONE		0x0000	/* Non-flag */
#define OBJECT_FLAG_INTERNAL	0x0001	/* Internal-use only */
#define OBJECT_FLAG_NOTINITED	0x0002	/* Still being initialised */
#define OBJECT_FLAG_HIGH		0x0004	/* In 'high' security state */
#define OBJECT_FLAG_SIGNALLED	0x0008	/* In signalled state */
#define OBJECT_FLAG_BUSY		0x0010	/* Busy with async.op */
#define OBJECT_FLAG_SECUREMALLOC 0x0020	/* Uses secure memory */
#define OBJECT_FLAG_ALIASED		0x0040	/* Object is alias for another object */
#define OBJECT_FLAG_CLONE		0x0080	/* Aliased object is the clone */
#define OBJECT_FLAG_OWNED		0x0100	/* Object is bound to a thread */
#define OBJECT_FLAG_ATTRLOCKED	0x0200	/* Security properties can't be modified */

/* The flags that convey information about an object's status */

#define OBJECT_FLAGMASK_STATUS \
		( OBJECT_FLAG_NOTINITED | OBJECT_FLAG_BUSY | OBJECT_FLAG_SIGNALLED )

/****************************************************************************
*																			*
*							Kernel Data Structures							*
*																			*
****************************************************************************/

/* The object allocation state data.  This controls the allocation of
   handles to newly-created objects.  The first NO_SYSTEM_OBJECTS handles
   are system objects that exist with fixed handles, the remainder are
   allocated pseudorandomly under the control of an LFSR */

typedef struct {
	long lfsrMask, lfsrPoly;	/* LFSR state values */
	int objectHandle;			/* Current object handle */
	} OBJECT_STATE_INFO;

/* A structure to store the details of a message sent to an object, and the
   size of the message queue.  This defines the maximum nesting depth of
   messages sent by an object.  Because of the way krnlSendMessage() handles
   message processing, it's extremely difficult to ever have more than two
   or three messages in the queue unless an object starts recursively
   sending itself messages */

typedef struct {
	int objectHandle;			/* Handle to send message to */
	const void *handlingInfoPtr;/* Message handling info */
	MESSAGE_TYPE message;
	const void *messageDataPtr;
	int messageValue;			/* Message parameters */
	} MESSAGE_QUEUE_DATA;

#define MESSAGE_QUEUE_SIZE	16

/* Semaphores are one-shots, so that once set and cleared they can't be
   reset.  This is handled by enforcing the following state transitions:

	Uninited -> Set | Clear
	Set -> Set | Clear
	Clear -> Clear

   The handling is complicated somewhat by the fact that on some systems the
   semaphore has to be explicitly deleted, but only the last thread to use
   it can safely delete it.  In order to handle this, we reference-count the
   semaphore and let the last thread out delete it.  In order to do this we
   introduce an additional state, preClear, which indicates that while the
   semaphore object is still present, the last thread out should delete it,
   bringing it to the true clear state */

typedef enum {
	SEMAPHORE_STATE_UNINITED,
	SEMAPHORE_STATE_CLEAR,
	SEMAPHORE_STATE_PRECLEAR,
	SEMAPHORE_STATE_SET,
	SEMAPHORE_STATE_LAST
	} SEMAPHORE_STATE;

typedef struct {
	SEMAPHORE_STATE state;		/* Semaphore state */
	MUTEX_HANDLE object;		/* Handle to system synchronisation object */
	int refCount;				/* Reference count for handle */
	} SEMAPHORE_INFO;

/* A structure to store the details of a thread */

typedef struct {
	THREAD_FUNCTION threadFunction;	/* Function to call from thread */
	THREAD_PARAMS threadParams;		/* Thread function parameters */
	SEMAPHORE_TYPE semaphore;		/* Optional semaphore to set */
	MUTEX_HANDLE syncHandle;		/* Handle to use for thread sync */
	} THREAD_INFO;

/* When the kernel closes down, it does so in a multi-stage process that's
   equivalent to Unix runlevels.  At the first level, all internal worker
   threads/tasks must exist.  At the next level, all messages to objects
   except destroy messages fail.  At the final level, all kernel-managed
   primitives such as mutexes and semaphores are no longer available */

typedef enum {
	SHUTDOWN_LEVEL_NONE,		/* Normal operation */
	SHUTDOWN_LEVEL_THREADS,		/* Internal threads must exit */
	SHUTDOWN_LEVEL_MESSAGES,	/* Only destroy messages are valid */
	SHUTDOWN_LEVEL_MUTEXES,		/* Kernel objects become invalid */
	SHUTDOWN_LEVEL_ALL			/* Complete shutdown */
	} SHUTDOWN_LEVEL;

/* The information needed for each block of secure memory */

#define CANARY_SIZE		4		/* Size of canary used to spot overwrites */

typedef struct {
	BOOLEAN isLocked;			/* Whether this block is locked */
	int size;					/* Size of the block (including the size
								   of the MEMLOCK_INFO) */
	void *next, *prev;			/* Next, previous memory block */
#if defined( __BEOS__ )
	area_id areaID;				/* Needed for page locking under BeOS */
#endif /* BeOS and BeOS areas */
#ifndef NDEBUG
	BYTE canary[ CANARY_SIZE ];	/* Canary for spotting overwrites */
#endif /* NDEBUG */
	} MEMLOCK_INFO;

/* The kernel data block, containing all variables used by the kernel.  With
   the exception of the special-case values at the start, all values in this
   block should be set to use zero/NULL as their ground state (for example a
   boolean variable should have a ground state of FALSE (zero) rather than
   TRUE (nonzero)) */

typedef struct {
	/* The kernel initialisation state and a lock to protect it.  The
	   lock and shutdown level value are handled externally and aren't
	   cleared when the kernel data block as a whole is cleared */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( initialisation );
#endif /* USE_THREADS */
	SHUTDOWN_LEVEL shutdownLevel;		/* Kernel shutting level */
	/* Everything from this point on is cleared at init and shutdown */
	BOOLEAN isInitialised;				/* Whether kernel initialised */

	/* The kernel object table and object table management info */
	OBJECT_INFO *objectTable;			/* Pointer to object table */
	int objectTableSize;				/* Current table size */
	int objectUniqueID;					/* Unique ID for next object */
	OBJECT_STATE_INFO objectStateInfo;	/* Object allocation state */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( objectTable );
#endif /* USE_THREADS */

	/* The kernel message dispatcher queue */
	MESSAGE_QUEUE_DATA messageQueue[ MESSAGE_QUEUE_SIZE + 8 ];
	int queueEnd;						/* Points past last queue element */

	/* The kernel semaphores */
	SEMAPHORE_INFO semaphoreInfo[ SEMAPHORE_LAST + 8 ];
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( semaphore );
#endif /* USE_THREADS */

	/* The kernel mutexes.  Since mutexes usually aren't scalar values and
	   are declared and accessed via macros that manipulate various fields,
	   we have to declare a pile of them individually rather than using an
	   array of mutexes */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( mutex1 );
	MUTEX_DECLARE_STORAGE( mutex2 );
	MUTEX_DECLARE_STORAGE( mutex3);
#endif /* USE_THREADS */

	/* The kernel thread data */
#ifdef USE_THREADS
	THREAD_INFO threadInfo;
#endif /* USE_THREADS */

	/* The kernel secure memory list and a lock to protect it */
	MEMLOCK_INFO *allocatedListHead, *allocatedListTail;
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( allocation );
#endif /* USE_THREADS */

	/* A marker for the end of the kernel data, used during init/shutdown */
	int endMarker;
	} KERNEL_DATA;

/* When we start up and shut down the kernel, we need to clear the kernel
   data.  However, the init lock may have been set by an external management
   function, so we can't clear that part of the kernel data.  In addition,
   on shutdown the shutdown level value must stay set so that any threads
   still running will be forced to exit at the earliest possible instance,
   and remain set after the shutdown has completed.  To handle this, we use
   the following macro to clear only the appropriate area of the kernel data
   block */

#define CLEAR_KERNEL_DATA()	zeroise( ( void * ) ( &krnlDataBlock.isInitialised ), \
									 &krnlDataBlock.endMarker - &krnlDataBlock.isInitialised )

/****************************************************************************
*																			*
*								ACL Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in certm_acl.c */

int preDispatchCheckCertMgmtAccess( const int objectHandle,
									const MESSAGE_TYPE message,
									const void *messageDataPtr,
									const int messageValue,
									const void *dummy );

/* Prototypes for functions in key_acl.c */

int preDispatchCheckKeysetAccess( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy );

/* Prototypes for functions in mech_acl.c */

int preDispatchCheckMechanismWrapAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy );
int preDispatchCheckMechanismSignAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy );
int preDispatchCheckMechanismDeriveAccess( const int objectHandle,
										   const MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue,
										   const void *dummy );

/* Prototypes for functions in msg_acl.c */

int preDispatchSignalDependentObjects( const int objectHandle,
									   const MESSAGE_TYPE message,
									   const void *messageDataPtr,
									   const int messageValue,
									   const void *dummy );
int preDispatchCheckAttributeAccess( const int objectHandle,
									 const MESSAGE_TYPE message,
									 const void *messageDataPtr,
									 const int messageValue,
									 const void *auxInfo );
int preDispatchCheckCompareParam( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy );
int preDispatchCheckCheckParam( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *messageDataPtr,
								const int messageValue,
								const void *dummy );
int preDispatchCheckActionAccess( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy );
int preDispatchCheckState( const int objectHandle,
						   const MESSAGE_TYPE message,
						   const void *messageDataPtr,
						   const int messageValue, const void *dummy );
int preDispatchCheckParamHandleOpt( const int objectHandle,
									const MESSAGE_TYPE message,
									const void *messageDataPtr,
									const int messageValue,
									const void *auxInfo );
int preDispatchCheckStateParamHandle( const int objectHandle,
									  const MESSAGE_TYPE message,
									  const void *messageDataPtr,
									  const int messageValue,
									  const void *auxInfo );
int preDispatchCheckExportAccess( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *messageDataPtr,
								  const int messageValue,
								  const void *dummy );
int preDispatchCheckData( const int objectHandle,
						  const MESSAGE_TYPE message,
						  const void *messageDataPtr,
						  const int messageValue,
						  const void *dummy );
int preDispatchSetObjectOwner( const int objectHandle,
							   const MESSAGE_TYPE message,
							   const void *messageDataPtr,
							   const int messageValue,
							   const void *dummy );
int postDispatchMakeObjectExternal( const int dummy,
									const MESSAGE_TYPE message,
									const void *messageDataPtr,
									const int messageValue,
									const void *auxInfo );
int postDispatchForwardToDependentObject( const int objectHandle,
										  const MESSAGE_TYPE message,
										  const void *dummy1,
										  const int messageValue,
										  const void *dummy2 );
int postDispatchUpdateUsageCount( const int objectHandle,
								  const MESSAGE_TYPE message,
								  const void *dummy1,
								  const int messageValue,
								  const void *dummy2 );
int postDispatchChangeState( const int objectHandle,
							 const MESSAGE_TYPE message,
							 const void *dummy1,
							 const int messageValue,
							 const void *dummy2 );
int postDispatchChangeStateOpt( const int objectHandle,
								const MESSAGE_TYPE message,
								const void *dummy1,
								const int messageValue,
								const void *auxInfo );

/****************************************************************************
*																			*
*								Kernel Functions							*
*																			*
****************************************************************************/

/* Prototypes for functions in attr_acl.c */

const void *findAttributeACL( const CRYPT_ATTRIBUTE_TYPE attribute,
							  const BOOLEAN isInternalMessage );

/* Prototypes for functions in int_msg.c */

int getPropertyAttribute( const int objectHandle,
						  const CRYPT_ATTRIBUTE_TYPE attribute,
						  void *messageDataPtr );
int setPropertyAttribute( const int objectHandle,
						  const CRYPT_ATTRIBUTE_TYPE attribute,
						  void *messageDataPtr );
int incRefCount( const int objectHandle, const int dummy1,
				 const void *dummy2, const BOOLEAN dummy3 );
int decRefCount( const int objectHandle, const int dummy1,
				 const void *dummy2, const BOOLEAN isInternal );
int getDependentObject( const int objectHandle, const int targetType,
						const void *messageDataPtr,
						const BOOLEAN dummy );
int setDependentObject( const int objectHandle, const int incReferenceCount,
						const void *messageDataPtr,
						const BOOLEAN dummy );
int cloneObject( const int objectHandle, const int clonedObject,
				 const void *dummy1, const BOOLEAN dummy2 );

/* Prototypes for functions in sendmsg.c */

int checkTargetType( const int objectHandle, const long targets );
int findTargetType( const int originalObjectHandle, const long targets );
int waitForObject( const int objectHandle, OBJECT_INFO **objectInfoPtrPtr );

/* Prototypes for functions in objects.c */

void destroyObjectData( const int objectHandle );
int destroyObjects( void );

/* Prototypes for functions in semaphore.c */

void setSemaphore( const SEMAPHORE_TYPE semaphore,
				   const MUTEX_HANDLE object );
void clearSemaphore( const SEMAPHORE_TYPE semaphore );

/* Init/shutdown functions for each kernel module */

int initAllocation( KERNEL_DATA *krnlDataPtr );
void endAllocation( void );
int initAttributeACL( KERNEL_DATA *krnlDataPtr );
void endAttributeACL( void );
int initCertMgmtACL( KERNEL_DATA *krnlDataPtr );
void endCertMgmtACL( void );
int initInternalMsgs( KERNEL_DATA *krnlDataPtr );
void endInternalMsgs( void );
int initKeymgmtACL( KERNEL_DATA *krnlDataPtr );
void endKeymgmtACL( void );
int initMechanismACL( KERNEL_DATA *krnlDataPtr );
void endMechanismACL( void );
int initMessageACL( KERNEL_DATA *krnlDataPtr );
void endMessageACL( void );
int initObjects( KERNEL_DATA *krnlDataPtr );
void endObjects( void );
int initObjectAltAccess( KERNEL_DATA *krnlDataPtr );
void endObjectAltAccess( void );
int initSemaphores( KERNEL_DATA *krnlDataPtr );
void endSemaphores( void );
int initSendMessage( KERNEL_DATA *krnlDataPtr );
void endSendMessage( void );

#endif /* _KERNEL_DEFINED */
