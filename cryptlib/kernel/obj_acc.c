/****************************************************************************
*																			*
*							Object Alternative Access						*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

/* Sending a message to an object only makes the one object which is the
   target of the message available for use.  When we need simultaneous
   access to two objects (for example when copying a collection of cert
   extensions from one cert to another), we have to use the
   krnlAcquireObject()/krnlReleaseObject() functions to obtain access to
   the second object's internals.

   There is a second situation in which we need access to an object's
   internals, and that occurs when we need to export/import a key from/to
   a context.  This is handled via the key extract functions at the end
   of this module, see the comments there for further information */

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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* The type of checking that we perform for the object access.  The check 
   types are:

	CHECK_EXTERNAL
		Kernel-external call with a cert or user object.

	CHECK_EXTERNAL_RELEASE
		Kernel-external call, as CHECK_EXTERNAL except that we can also 
		release the system object when we don't need it any more but need to 
		carry out further operations with other objects.

	CHECK_KEYACCESS
		Kernel-internal call with a context for key export/import */

typedef enum {
	ACCESS_CHECK_NONE,		/* No access check type */
	ACCESS_CHECK_EXTERNAL,	/* Generic external call: Cert or user obj.*/
	ACCESS_CHECK_EXTERNAL_RELEASE,	/* Generic external call: Cert or user obj.*/
	ACCESS_CHECK_KEYACCESS,	/* Internal call: Context for key export */
	ACCESS_CHECK_LAST		/* Last access check type */
	} ACCESS_CHECK_TYPE;

/* Check that this is an object for which direct access is valid.  We can 
   only access the following object types:

	Contexts: Used when importing/exporting keys to/from contexts during
		key wrap/unwrap operations.

	Certificates: Used when copying internal state such as cert extensions 
		or CRL info from one cert object to another.
	
	Crypto hardware devices other than the system object: Used when a 
		context tied to a device needs to perform an operation using the 
		device.
	
	User objects: Used when committing config data to persistent storage, we 
		don't actually use the object data but merely unlock it to allow 
		others access while performing the potentially lengthy update */

static int checkAccessValid( const int objectHandle,
							 const ACCESS_CHECK_TYPE checkType,
							 const int errorCode )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;

	PRE( checkType > ACCESS_CHECK_NONE && checkType < ACCESS_CHECK_LAST );
	PRE( errorCode < 0 );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(): It's a valid object owned by the calling
	   thread */
	if( !isValidObject( objectHandle ) || \
		!checkObjectOwnership( objectTable[ objectHandle ] ) )
		return( errorCode );

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];

	/* Make sure that the object access is valid */
	switch( objectInfoPtr->type )
		{
		case OBJECT_TYPE_CONTEXT:
			/* Used when exporting/importing keying info, valid for contexts 
			   with keys when called from within the kernel */
			if( checkType != ACCESS_CHECK_KEYACCESS )
				return( errorCode );
			if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_CTX_CONV ) && \
				!isValidSubtype( objectInfoPtr->subType, SUBTYPE_CTX_MAC ) && \
				!isValidSubtype( objectInfoPtr->subType, SUBTYPE_CTX_PKC ) )
				return( errorCode );
			break;

		case OBJECT_TYPE_CERTIFICATE:
			/* Used when copying internal state such as cert extensions or
			   CRL info from one cert object to another.  This is valid for
			   all cert types when called from the cert code outside the 
			   kernel */
			if( checkType != ACCESS_CHECK_EXTERNAL && \
				checkType != ACCESS_CHECK_EXTERNAL_RELEASE )
				return( errorCode );
			break;

		case OBJECT_TYPE_DEVICE:
			/* Used when a context tied to a crypto hardware device needs to
			   perform an operation using the device.  This is valid for all 
			   devices other than the system object, however it can be used 
			   to release the system object during a lengthy operation */
			if( checkType != ACCESS_CHECK_EXTERNAL && \
				checkType != ACCESS_CHECK_EXTERNAL_RELEASE )
				return( CRYPT_ERROR );
			if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_FORTEZZA ) && \
				!isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_PKCS11 ) && \
				!isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_CRYPTOAPI ) && \
				!( checkType == ACCESS_CHECK_EXTERNAL_RELEASE && \
				   isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_SYSTEM ) ) )
				return( errorCode );

			/* Perform an additional explicit check for the system object */
			if( checkType != ACCESS_CHECK_EXTERNAL_RELEASE && \
				objectHandle == SYSTEM_OBJECT_HANDLE )
				return( errorCode );
			break;

		case OBJECT_TYPE_USER:
			/* Used when updating config data, which can take awhile.  The 
			   default user is an SO user, which is why we check for this 
			   user type */
			if( checkType != ACCESS_CHECK_EXTERNAL && \
				checkType != ACCESS_CHECK_EXTERNAL_RELEASE )
				return( errorCode );
			if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_USER_SO ) )
				return( errorCode );
			break;

		default:
			assert( NOTREACHED );
			return( errorCode );
		}

	/* Postcondition: The object is of the appropriate type for the access */
	POST( ( ( checkType == ACCESS_CHECK_EXTERNAL || \
			  checkType == ACCESS_CHECK_EXTERNAL_RELEASE ) && \
			( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE || \
			  objectInfoPtr->type == OBJECT_TYPE_DEVICE || \
			  objectInfoPtr->type == OBJECT_TYPE_USER ) ) || \
		  ( checkType == ACCESS_CHECK_KEYACCESS && \
		    objectInfoPtr->type == OBJECT_TYPE_CONTEXT ) );

	return( CRYPT_OK );
	}

/* Get a pointer to an object's data from its handle */

int getObject( const int objectHandle, const OBJECT_TYPE type,
			   const ACCESS_CHECK_TYPE checkType, void **objectPtr, 
			   const int errorCode )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;
	int status = CRYPT_OK;

	/* Preconditions: It's a valid object */
	PRE( isValidHandle( objectHandle ) && \
		 objectHandle != SYSTEM_OBJECT_HANDLE );
	PRE( isValidType( type ) && \
		 ( type == OBJECT_TYPE_CONTEXT || type == OBJECT_TYPE_CERTIFICATE || \
		   type == OBJECT_TYPE_DEVICE || type == OBJECT_TYPE_USER ) );
	PRE( checkType == ACCESS_CHECK_EXTERNAL || \
		 checkType == ACCESS_CHECK_KEYACCESS );
	PRE( isWritePtr( objectPtr, sizeof( void * ) ) );

	/* Clear the return value */
	*objectPtr = NULL;

	MUTEX_LOCK( objectTable );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(), as well as situation-specific additional checks 
	   for correct object types */
	status = checkAccessValid( objectHandle, checkType, errorCode );
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( status );
		}

	/* Perform additional checks for correct object types */
	if( objectHandle == SYSTEM_OBJECT_HANDLE || \
		objectTable[ objectHandle ].type != type )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( errorCode );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];

	/* Inner precondition: The object is of the requested type */
	PRE( objectInfoPtr->type == type && \
		 ( objectInfoPtr->type == OBJECT_TYPE_CONTEXT || \
		   objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE || \
		   objectInfoPtr->type == OBJECT_TYPE_DEVICE || \
		   objectInfoPtr->type == OBJECT_TYPE_USER ) );

	/* If the object is busy, wait for it to become available */
	if( isInUse( objectHandle ) && !isObjectOwner( objectHandle ) )
		status = waitForObject( objectHandle, &objectInfoPtr );
	if( cryptStatusOK( status ) )
		{
		objectInfoPtr->lockCount++;
#ifdef USE_THREADS
		objectInfoPtr->lockOwner = THREAD_SELF();
#endif /* USE_THREADS */
		*objectPtr = objectInfoPtr->objectPtr;
		}

	MUTEX_UNLOCK( objectTable );
	return( status );
	}

/* Release an object that we previously acquired directly.  Note that we can
   release the system object here (done when we don't need it any more but
   need to carry out further operations with other objects), but we can't
   ever acquire it */

static int releaseObject( const int objectHandle,
						  const ACCESS_CHECK_TYPE checkType )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;
	int status;
	DECLARE_ORIGINAL_INT( lockCount );

	MUTEX_LOCK( objectTable );

	/* Preconditions: It's a valid object in use by the caller */
	PRE( isValidObject( objectHandle ) );
	PRE( isInUse( objectHandle ) && isObjectOwner( objectHandle ) );
	PRE( checkType == ACCESS_CHECK_EXTERNAL_RELEASE || \
		 checkType == ACCESS_CHECK_KEYACCESS );

	/* Perform similar access checks to the ones performed in
	   krnlSendMessage(), as well as situation-specific additional checks 
	   for correct object types */
	status = checkAccessValid( objectHandle, checkType, 
							   CRYPT_ERROR_PERMISSION );
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( status );
		}

	/* Perform additional checks for correct object types.  The ownership 
	   check in checkAccessValid() checks whether the current thread is the
	   overall object owner, isObjectOwner() checks whether the current 
	   thread owns the current lock on the object */
	if( !isInUse( objectHandle ) || !isObjectOwner( objectHandle ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];
	STORE_ORIGINAL_INT( lockCount, objectInfoPtr->lockCount );

	objectInfoPtr->lockCount--;

	/* Postcondition: The object's lock count has been decremented and is
	   non-negative */
	POST( objectInfoPtr->lockCount == \
							ORIGINAL_VALUE( lockCount ) - 1 );
	POST( objectInfoPtr->lockCount >= 0 );

	MUTEX_UNLOCK( objectTable );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

int initObjectAltAccess( KERNEL_DATA *krnlDataPtr )
	{
	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	return( CRYPT_OK );
	}

void endObjectAltAccess( void )
	{
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*						Direct Object Access Functions						*
*																			*
****************************************************************************/

/* Acquire/release an object */

int krnlAcquireObject( const int objectHandle, const OBJECT_TYPE type,
					   void **objectPtr, const int errorCode )
	{
	return( getObject( objectHandle, type, ACCESS_CHECK_EXTERNAL, 
					   objectPtr, errorCode ) );
	}

int krnlReleaseObject( const int objectHandle )
	{
	return( releaseObject( objectHandle, ACCESS_CHECK_EXTERNAL_RELEASE ) );
	}

/* Relinquish ownership of the system object to another thread.  This
   procedure is needed to allow a background polling thread to add entropy
   to the system device.  The way it works is that the calling thread hands
   ownership over to the polling thread and suspends itself until the
   polling thread completes.  When the polling thread has completed, it
   terminates, whereupon the original thread wakes up and reacquires
   ownership.  The value passed to the release call is actually a thread ID,
   but since this type isn't visible outside the kernel we just us a generic
   int */

int krnlRelinquishSystemObject( const int /* THREAD_HANDLE */ objectOwner )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
#ifdef USE_THREADS
	OBJECT_INFO *objectInfoPtr = &objectTable[ SYSTEM_OBJECT_HANDLE ];
#endif /* USE_THREADS */

	/* Preconditions: The object is valid and in use */
	PRE( isValidObject( SYSTEM_OBJECT_HANDLE ) );
	PRE( isInUse( SYSTEM_OBJECT_HANDLE ) );

	MUTEX_LOCK( objectTable );

	/* Precondition: We're relinquishing ownership, we must currently be
	   the owner */
	PRE( isObjectOwner( SYSTEM_OBJECT_HANDLE ) );

	/* Check that the access is valid */
	if( !isValidObject( SYSTEM_OBJECT_HANDLE ) || \
		!isInUse( SYSTEM_OBJECT_HANDLE ) || \
		!checkObjectOwnership( objectTable[ SYSTEM_OBJECT_HANDLE ] ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

#ifdef USE_THREADS
	objectInfoPtr->lockOwner = ( THREAD_HANDLE ) objectOwner;
#endif /* USE_THREADS */

	MUTEX_UNLOCK( objectTable );
	return( CRYPT_OK );
	}

int krnlReacquireSystemObject( void )
	{
#ifdef USE_THREADS
	OBJECT_INFO *objectInfoPtr = &krnlData->objectTable[ SYSTEM_OBJECT_HANDLE ];
#endif /* USE_THREADS */

	/* Preconditions: The object is valid and in use */
	PRE( isValidObject( SYSTEM_OBJECT_HANDLE ) );
	PRE( isInUse( SYSTEM_OBJECT_HANDLE ) );

	MUTEX_LOCK( objectTable );

	/* Precondition: Since we're reacquiring ownership, we're not currently 
	   the owner  */
	PRE( !isObjectOwner( SYSTEM_OBJECT_HANDLE ) );

	/* Check that the access is valid */
	if( !isValidObject( SYSTEM_OBJECT_HANDLE ) || \
		!isInUse( SYSTEM_OBJECT_HANDLE ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

#ifdef USE_THREADS
	objectInfoPtr->lockOwner = THREAD_SELF();
#endif /* USE_THREADS */

	MUTEX_UNLOCK( objectTable );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Key Extract Functions							*
*																			*
****************************************************************************/

/* The cryptlib equivalent of trusted downgraders in other security models:
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

#if defined( INC_ALL )
  #include "context.h"
#elif defined( INC_CHILD )
  #include "../context/context.h"
#else
  #include "context/context.h"
#endif /* Compiler-specific includes */

int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData )
	{
	CONTEXT_INFO *contextInfoPtr;
	int status;

	/* Clear return value */
	memset( keyData, 0, bitsToBytes( MIN_KEYSIZE_BITS ) );

	/* Make sure that we've been given a conventional encryption or MAC 
	   context with a key loaded.  This has already been checked at a higher 
	   level, but we perform a sanity check here to be safe */
	status = getObject( iCryptContext, OBJECT_TYPE_CONTEXT,
						ACCESS_CHECK_KEYACCESS,
						( void ** ) &contextInfoPtr, CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( ( contextInfoPtr->type != CONTEXT_CONV && \
		  contextInfoPtr->type != CONTEXT_MAC ) || \
		!( contextInfoPtr->flags & CONTEXT_KEY_SET ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Export the key data from the context */
	switch( contextInfoPtr->type )
		{
		case CONTEXT_CONV:
			memcpy( keyData, contextInfoPtr->ctxConv->userKey,
					contextInfoPtr->ctxConv->userKeyLength );
			break;

		case CONTEXT_MAC:
			memcpy( keyData, contextInfoPtr->ctxMAC->userKey,
					contextInfoPtr->ctxMAC->userKeyLength );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ARGERROR_OBJECT;
		}
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
	return( status );
	}

int exportPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE formatType )
	{
	CONTEXT_INFO *contextInfoPtr;
	int status;

	/* Make sure that we've been given a PKC context with a private key
	   loaded.  This has already been checked at a higher level, but we
	   perform a sanity check here to be safe */
	status = getObject( iCryptContext, OBJECT_TYPE_CONTEXT, 
						ACCESS_CHECK_KEYACCESS,
						( void ** ) &contextInfoPtr, CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type != CONTEXT_PKC ||
		!( contextInfoPtr->flags & CONTEXT_KEY_SET ) || \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Export the key data from the context */
	status = contextInfoPtr->ctxPKC->writePrivateKeyFunction( stream, 
										contextInfoPtr, formatType, "private" );
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
	return( status );
	}

int importPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE formatType )
	{
	CONTEXT_INFO *contextInfoPtr;
	int status;

	/* Make sure that we've been given a PKC context with no private key
	   loaded.  This has already been checked at a higher level, but we
	   perform a sanity check here to be safe */
	status = getObject( iCryptContext, OBJECT_TYPE_CONTEXT, 
						ACCESS_CHECK_KEYACCESS,
						( void ** ) &contextInfoPtr, CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type != CONTEXT_PKC ||
		( contextInfoPtr->flags & CONTEXT_KEY_SET ) || \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Import the key data into the context */
	status = contextInfoPtr->ctxPKC->readPrivateKeyFunction( stream, 
										contextInfoPtr, formatType );
	if( cryptStatusOK( status ) )
		{
		/* If everything went OK, perform an internal load that uses the
		   values already present in the context */
		status = contextInfoPtr->loadKeyFunction( contextInfoPtr, NULL, 0 );
		if( cryptStatusOK( status ) )
			{
			krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED );
			contextInfoPtr->flags |= CONTEXT_KEY_SET;
			}
		else
			if( cryptArgError( status ) )
				/* Map the status to a more appropriate code */
				status = CRYPT_ERROR_BADDATA;
		}
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS );
	return( status );
	}
