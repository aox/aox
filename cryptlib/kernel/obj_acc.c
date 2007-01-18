/****************************************************************************
*																			*
*							Object Alternative Access						*
*						Copyright Peter Gutmann 1997-2005					*
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

	CHECK_EXTACCESS
		Kernel-external call with a cert or crypto device to allow access to
		object-internal data.

	CHECK_KEYACCESS
		Kernel-internal call with a context for key export/import.

	CHECK_SUSPEND
		Kernel-external call with a user or system object to temporarily
		suspend object use and allow others access, providing a (somewhat 
		crude) mechanism for making kernel calls interruptible */

typedef enum {
	ACCESS_CHECK_NONE,		/* No access check type */
	ACCESS_CHECK_EXTACCESS,	/* Generic external call: Cert or crypt.dev.*/
	ACCESS_CHECK_KEYACCESS,	/* Internal call: Context for key export */
	ACCESS_CHECK_SUSPEND,	/* Suspend object use: User or sys.obj.*/
	ACCESS_CHECK_LAST		/* Last access check type */
	} ACCESS_CHECK_TYPE;

/* Check that this is an object for which direct access is valid.  We can 
   only access the following object types:

	Certificates: EXTACCESS, used when copying internal state such as cert 
		extensions or CRL info from one cert object to another.

	Contexts: KEYACCESS, used when importing/exporting keys to/from contexts 
		during key wrap/unwrap operations.

	Crypto hardware devices other than the system object: EXTACCESS, used 
		when a context tied to a device needs to perform an operation using 
		the device.

	System object: ACCESS_CHECK_SUSPEND, used when performing a randomness 
		data read/write, which can take some time to complete.

	User objects: ACCESS_CHECK_SUSPEND, used when committing config data to 
		persistent storage.  We don't actually use the object data but 
		merely unlock it to allow others access while performing the 
		potentially lengthy update.  Also used when performing the self-
		test */

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
			   all cert types */
			if( checkType != ACCESS_CHECK_EXTACCESS )
				return( errorCode );
			break;

		case OBJECT_TYPE_DEVICE:
			/* If it's an external access operation, it's used when a 
			   context tied to a crypto hardware device needs to perform an 
			   operation using the device.  This is valid for all devices 
			   other than the system object */
			if( checkType == ACCESS_CHECK_EXTACCESS )
				{
				if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_FORTEZZA ) && \
					!isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_PKCS11 ) && \
					!isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_CRYPTOAPI ) )
					return( errorCode );
				}
			else
				{
				/* If it's a suspend operation, it's used to temporarily 
				   allow access to the system object while other operations
				   are being performed */
				if( checkType != ACCESS_CHECK_SUSPEND )
					return( errorCode );
				if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_DEV_SYSTEM ) )
					return( errorCode );
				}
			break;

		case OBJECT_TYPE_USER:
			/* Used when updating config data, which can take awhile.  The 
			   default user is an SO user, which is why we check for this 
			   user type */
			if( checkType != ACCESS_CHECK_SUSPEND )
				return( errorCode );
			if( !isValidSubtype( objectInfoPtr->subType, SUBTYPE_USER_SO ) )
				return( errorCode );
			break;

		default:
			assert( NOTREACHED );
			return( errorCode );
		}

	/* Postcondition: The object is of the appropriate type for the access */
	POST( ( ( checkType == ACCESS_CHECK_EXTACCESS ) && \
			( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE || \
			  objectInfoPtr->type == OBJECT_TYPE_DEVICE ) ) || \
		  ( checkType == ACCESS_CHECK_KEYACCESS && \
		    objectInfoPtr->type == OBJECT_TYPE_CONTEXT ) || \
		  ( checkType == ACCESS_CHECK_SUSPEND && \
		    ( objectInfoPtr->type == OBJECT_TYPE_DEVICE || \
			  objectInfoPtr->type == OBJECT_TYPE_USER ) ) );


	return( CRYPT_OK );
	}

/* Get a pointer to an object's data from its handle */

int getObject( const int objectHandle, const OBJECT_TYPE type,
			   const ACCESS_CHECK_TYPE checkType, void **objectPtr, 
			   const int refCount, const int errorCode )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;
	int status = CRYPT_OK;

	/* Preconditions: It's a valid object */
	PRE( isValidHandle( objectHandle ) );
	PRE( isValidType( type ) && \
		 ( type == OBJECT_TYPE_CONTEXT || type == OBJECT_TYPE_CERTIFICATE || \
		   type == OBJECT_TYPE_DEVICE || type == OBJECT_TYPE_USER ) );
	PRE( checkType > ACCESS_CHECK_NONE && \
		 checkType < ACCESS_CHECK_LAST );
	PRE( ( ( objectHandle == SYSTEM_OBJECT_HANDLE || \
			 objectHandle == DEFAULTUSER_OBJECT_HANDLE ) && \
		   objectPtr == NULL && refCount > 0 ) || \
		 ( !( objectHandle == SYSTEM_OBJECT_HANDLE || \
			  objectHandle == DEFAULTUSER_OBJECT_HANDLE ) && \
		   isWritePtr( objectPtr, sizeof( void * ) ) && \
		   refCount == CRYPT_UNUSED ) );

	/* Clear the return value */
	if( objectPtr != NULL )
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
	if( ( ( objectHandle == SYSTEM_OBJECT_HANDLE || \
			objectHandle == DEFAULTUSER_OBJECT_HANDLE ) && \
		  objectPtr != NULL ) || \
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
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( objectTable );
		return( status );
		}

	/* If it's an external access to certificate/device info or an internal 
	   access to access the object's keying data, increment the object's 
	   reference count to reserve it for our exclusive use */
	if( checkType == ACCESS_CHECK_EXTACCESS || \
		checkType == ACCESS_CHECK_KEYACCESS )
		objectInfoPtr->lockCount++;
	else
		{
		/* If we're resuming use of an object that we suspended to allow 
		   others access, reset the reference count */
		PRE( checkType == ACCESS_CHECK_SUSPEND );
		PRE( objectInfoPtr->lockCount == 0 );
		PRE( refCount > 0 && refCount < 100 );

		objectInfoPtr->lockCount = refCount;
		}
#ifdef USE_THREADS
	objectInfoPtr->lockOwner = THREAD_SELF();
#endif /* USE_THREADS */
	if( objectPtr != NULL )
		*objectPtr = objectInfoPtr->objectPtr;

	MUTEX_UNLOCK( objectTable );
	return( status );
	}

/* Release an object that we previously acquired directly */

static int releaseObject( const int objectHandle,
						  const ACCESS_CHECK_TYPE checkType,
						  int *refCount )
	{
	OBJECT_INFO *objectTable = krnlData->objectTable;
	OBJECT_INFO *objectInfoPtr;
	int status;
	DECLARE_ORIGINAL_INT( lockCount );

	MUTEX_LOCK( objectTable );

	/* Preconditions: It's a valid object in use by the caller */
	PRE( isValidObject( objectHandle ) );
	PRE( isInUse( objectHandle ) && isObjectOwner( objectHandle ) );
	PRE( checkType > ACCESS_CHECK_NONE && \
		 checkType < ACCESS_CHECK_LAST );

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
	   check in checkAccessValid() simply checks whether the current thread 
	   is the overall object owner, isObjectOwner() checks whether the 
	   current thread owns the lock on the object */
	if( !isInUse( objectHandle ) || !isObjectOwner( objectHandle ) )
		{
		MUTEX_UNLOCK( objectTable );
		assert( NOTREACHED );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* It's a valid object, get its info */
	objectInfoPtr = &objectTable[ objectHandle ];

	/* If it was an external access to certificate/device info or an 
	   internal access to the object's keying data, decrement the object's 
	   reference count to allow others access again */
	if( checkType == ACCESS_CHECK_EXTACCESS || \
		checkType == ACCESS_CHECK_KEYACCESS )
		{
		STORE_ORIGINAL_INT( lockCount, objectInfoPtr->lockCount );

		objectInfoPtr->lockCount--;

		/* Postcondition: The object's lock count has been decremented and 
		   is non-negative */
		POST( objectInfoPtr->lockCount == \
								ORIGINAL_VALUE( lockCount ) - 1 );
		POST( objectInfoPtr->lockCount >= 0 );
		}
	else
		{
		/* It's an external access to free the object for access by others, 
		   clear the reference count */
		PRE( checkType == ACCESS_CHECK_SUSPEND );

		*refCount = objectInfoPtr->lockCount;
		objectInfoPtr->lockCount = 0;

		/* Postcondition: The object has been completely released */
		POST( !isInUse( objectHandle ) );
		}

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
	return( getObject( objectHandle, type, ACCESS_CHECK_EXTACCESS, 
					   objectPtr, CRYPT_UNUSED, errorCode ) );
	}

int krnlReleaseObject( const int objectHandle )
	{
	return( releaseObject( objectHandle, ACCESS_CHECK_EXTACCESS, NULL ) );
	}

/* Temporarily suspend use of an object to allow other threads access, and
   resume object use afterwards */

int krnlSuspendObject( const int objectHandle, int *refCount )
	{
	return( releaseObject( objectHandle, ACCESS_CHECK_SUSPEND, refCount ) );
	}

int krnlResumeObject( const int objectHandle, const int refCount )
	{
	return( getObject( objectHandle, 
					   ( objectHandle == SYSTEM_OBJECT_HANDLE ) ? \
						 OBJECT_TYPE_DEVICE : OBJECT_TYPE_USER, 
					   ACCESS_CHECK_SUSPEND, NULL, refCount, 
					   CRYPT_ERROR_FAILED ) );
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
					  with a KEK.  We use this rather than a generic 
					  external private key load to avoid having the key 
					  marked as an untrusted user-set key, and also because
					  it's easier to read the key data directly into the
					  context's bignum storage rather than adding indirection
					  via a CRYPT_PKCINFO_xxx structure */

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "context.h"
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
						( void ** ) &contextInfoPtr, CRYPT_UNUSED, 
						CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( ( contextInfoPtr->type != CONTEXT_CONV && \
		  contextInfoPtr->type != CONTEXT_MAC ) || \
		!( contextInfoPtr->flags & CONTEXT_KEY_SET ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
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
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
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
						( void ** ) &contextInfoPtr, CRYPT_UNUSED, 
						CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type != CONTEXT_PKC || \
		!( contextInfoPtr->flags & CONTEXT_KEY_SET ) || \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Export the key data from the context */
	status = contextInfoPtr->ctxPKC->writePrivateKeyFunction( stream, 
										contextInfoPtr, formatType, "private" );
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
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
						( void ** ) &contextInfoPtr, CRYPT_UNUSED, 
						CRYPT_ARGERROR_OBJECT );
	if( cryptStatusError( status ) )
		return( status );
	if( contextInfoPtr->type != CONTEXT_PKC || \
		( contextInfoPtr->flags & CONTEXT_KEY_SET ) || \
		( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
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
			/* If the problem was indicated as a function argument error, 
			   map it to a more appropriate code */
			if( cryptArgError( status ) )
				status = CRYPT_ERROR_BADDATA;
		}
	releaseObject( iCryptContext, ACCESS_CHECK_KEYACCESS, NULL );
	return( status );
	}
