/****************************************************************************
*																			*
*						 cryptlib Crypto Device Routines					*
*						Copyright Peter Gutmann 1997-2002					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "device.h"
#else
  #include "device/device.h"
#endif /* Compiler-specific includes */

/* When we get random data from a device, we run the (practical) FIPS 140
   tests over the output to make sure that it's really random (at least as 
   far as the tests can tell us).  If the data fails the test, we get more 
   and try again.  The following value defines how many times we retry 
   before giving up.  In test runs, a count of 2 failures is reached every 
   ~50,000 iterations, 5 is never reached (in fact with 1M tests, 3 is never
   reached) */

#define NO_ENTROPY_FAILURES	5

/* Prototypes for functions in ctx_misc.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO_TYPE cryptAlgo );
void getCapabilityInfo( CRYPT_QUERY_INFO *cryptQueryInfo,
						const void FAR_BSS *capabilityInfoPtr );

/* Prototypes for functions in cryptmis.c */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength );

/* Prototypes for functions in cryptcrt.c */

int createCertificateIndirect( MESSAGE_CREATEOBJECT_INFO *createInfo,
							   const void *auxDataPtr, const int auxValue );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get a random data block with FIPS 140 checking */

static int getRandomData( DEVICE_INFO *deviceInfoPtr, void *data,
						  const int length )
	{
	int i;

	/* Get random data from the device and check it using the FIPS 140
	   tests.  If it's less than 64 bits we let it pass since the sample
	   size is too small to be useful, samples this small are only ever
	   drawn from the generator for use as padding with crypto keys that
	   are always >= 64 bits, so a problem with the generator will be
	   detected even if we don't check small samples */
	for( i = 0; i < NO_ENTROPY_FAILURES; i++ )
		{
		int status;

		status = deviceInfoPtr->getRandomFunction( deviceInfoPtr, data,
												   length );
		if( cryptStatusOK( status ) && \
			( length < 8 || checkEntropy( data, length ) ) )
			return( CRYPT_OK );
		}

	/* We couldn't get anything that passed the FIPS 140 tests, we can't
	   go any further */
	zeroise( data, length );
	assert( NOTREACHED );
	return( CRYPT_ERROR_RANDOM );
	}

/****************************************************************************
*																			*
*						Device Attribute Handling Functions					*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( DEVICE_INFO *deviceInfoPtr, 
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( deviceInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( DEVICE_INFO *deviceInfoPtr, 
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( deviceInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT, 
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotFound( DEVICE_INFO *deviceInfoPtr, 
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( deviceInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Handle data sent to or read from a device object */

static int processGetAttribute( DEVICE_INFO *deviceInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = deviceInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = deviceInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:
			switch( deviceInfoPtr->type )
				{
				case CRYPT_DEVICE_PKCS11:
					*valuePtr = deviceInfoPtr->devicePKCS11->errorCode;
					break;

				case CRYPT_DEVICE_FORTEZZA:
					*valuePtr = deviceInfoPtr->devicePKCS11->errorCode;
					break;

				case CRYPT_DEVICE_CRYPTOAPI:
					*valuePtr = deviceInfoPtr->devicePKCS11->errorCode;
					break;

				default:
					*valuePtr = CRYPT_OK;
				}
			return( CRYPT_OK );

		case CRYPT_DEVINFO_LOGGEDIN:
			if( deviceInfoPtr->flags & DEVICE_REMOVABLE )
				{
				int status;

				/* If it's a removable device, the user could implicitly log
				   out by removing it, so we have to perform an explicit
				   check to see whether it's still there */
				status = deviceInfoPtr->controlFunction( deviceInfoPtr, 
													messageValue, NULL, 0 );
				if( cryptStatusError( status ) )
					return( status );
				}
			*valuePtr = ( deviceInfoPtr->flags & DEVICE_LOGGEDIN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( DEVICE_INFO *deviceInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			{
			const char *errorMessagePtr;

			switch( deviceInfoPtr->type )
				{
				case CRYPT_DEVICE_PKCS11:
					errorMessagePtr = deviceInfoPtr->devicePKCS11->errorMessage;
					break;

				case CRYPT_DEVICE_FORTEZZA:
					errorMessagePtr = deviceInfoPtr->deviceFortezza->errorMessage;
					break;

				case CRYPT_DEVICE_CRYPTOAPI:
					errorMessagePtr = deviceInfoPtr->deviceCryptoAPI->errorMessage;
					break;

				default:
					errorMessagePtr = "";
				}
			if( !*errorMessagePtr )
				return( exitErrorNotFound( deviceInfoPtr, 
									CRYPT_ATTRIBUTE_INT_ERRORMESSAGE ) );
			return( attributeCopy( msgData, errorMessagePtr,
								   strlen( errorMessagePtr ) ) );
			}

		case CRYPT_DEVINFO_LABEL:
			if( deviceInfoPtr->label == NULL )
				return( exitErrorNotFound( deviceInfoPtr, 
										   CRYPT_DEVINFO_LABEL ) );
			return( attributeCopy( msgData, deviceInfoPtr->label,
								   strlen( deviceInfoPtr->label ) ) );

		case CRYPT_IATTRIBUTE_RANDOM:
			if( deviceInfoPtr->getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );
			return( getRandomData( deviceInfoPtr, msgData->data,
								   msgData->length ) );

		case CRYPT_IATTRIBUTE_RANDOM_NZ:
			{
			BYTE randomBuffer[ 128 ], *outBuffer = msgData->data;
			int count = msgData->length, status = CRYPT_OK;

			if( deviceInfoPtr->getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );

			/* The extraction of data is a little complex because we don't 
			   know how much data we'll need (as a rule of thumb it'll be 
			   size + ( size / 256 ) bytes, but in a worst-case situation we 
			   could need to draw out megabytes of data), so we copy out 128 
			   bytes worth at a time (a typical value for a 1K bit key) and 
			   keep going until we've filled the output requirements */
			while( count > 0 )
				{
				int i;

				/* Copy as much as we can from the randomness pool */
				status = getRandomData( deviceInfoPtr, randomBuffer, 128 );
				if( cryptStatusError( status ) )
					break;
				for( i = 0; count && i < 128; i++ )
					if( randomBuffer[ i ] )
						{
						*outBuffer++ = randomBuffer[ i ];
						count--;
						}
				}
			zeroise( randomBuffer, 128 );
			if( cryptStatusError( status ) )
				zeroise( msgData->data, msgData->length );
			return( status );
			}

		case CRYPT_IATTRIBUTE_RANDOM_NONCE:
			if( deviceInfoPtr->getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );

			assert( deviceInfoPtr->controlFunction != NULL );

			return( deviceInfoPtr->controlFunction( deviceInfoPtr, 
													CRYPT_IATTRIBUTE_RANDOM_NONCE,
													msgData->data, 
													msgData->length ) );

		case CRYPT_IATTRIBUTE_TIME:
			{
			int status;

			/* If the device doesn't contain a time source, we can't provide
			   time information */
			if( !( deviceInfoPtr->flags & DEVICE_TIME ) )
				return( CRYPT_ERROR_NOTAVAIL );

			/* Get the time from the device */
			status = deviceInfoPtr->controlFunction( deviceInfoPtr, 
													 CRYPT_IATTRIBUTE_TIME,
													 msgData->data, 
													 msgData->length );
			if( cryptStatusOK( status ) )
				{
				time_t *timePtr = msgData->data;

				/* Perform a sanity check on the returned value.  If it's
				   too far out, we don't trust it */
				if( *timePtr < MIN_TIME_VALUE )
					{
					*timePtr = 0;
					return( CRYPT_ERROR_NOTAVAIL );
					}
				}

			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( DEVICE_INFO *deviceInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	/* If it's an initialisation message, there's nothing to do */
	if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
		return( CRYPT_OK );

	assert( deviceInfoPtr->controlFunction != NULL );

	/* Send the control information to the device */
	return( deviceInfoPtr->controlFunction( deviceInfoPtr, messageValue, NULL, 
											*( ( int * ) messageDataPtr ) ) );
	}

static int processSetAttributeS( DEVICE_INFO *deviceInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	const BOOLEAN isAuthent = \
			( messageValue == CRYPT_DEVINFO_AUTHENT_USER || \
			  messageValue == CRYPT_DEVINFO_AUTHENT_SUPERVISOR ) ? TRUE : FALSE;
	const BOOLEAN isSetPIN = \
			( messageValue == CRYPT_DEVINFO_SET_AUTHENT_USER || \
			  messageValue == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR ) ? TRUE : FALSE;
	int status;

	assert( deviceInfoPtr->controlFunction != NULL );

	/* If it's a PIN attribute, make sure that a login is actually required 
	   for the device */
	if( isAuthent && !( deviceInfoPtr->flags & DEVICE_NEEDSLOGIN ) )
		return( exitErrorInited( deviceInfoPtr, messageValue ) );

	/* If it's a PIN attribute, make sure that the supplied PIN is valid */
	if( isAuthent || isSetPIN || \
		messageValue == CRYPT_DEVINFO_INITIALISE || \
		messageValue == CRYPT_DEVINFO_ZEROISE )
		switch( deviceInfoPtr->type )
			{
			case CRYPT_DEVICE_PKCS11:
				if( msgData->length < \
							deviceInfoPtr->devicePKCS11->minPinSize || \
					msgData->length > \
							deviceInfoPtr->devicePKCS11->maxPinSize )
					return( CRYPT_ARGERROR_NUM1 );

			case CRYPT_DEVICE_FORTEZZA:
				if( msgData->length < \
							deviceInfoPtr->deviceFortezza->minPinSize || \
					msgData->length > \
							deviceInfoPtr->deviceFortezza->maxPinSize )
					return( CRYPT_ARGERROR_NUM1 );
			}

	/* Send the control information to the device */
	status = deviceInfoPtr->controlFunction( deviceInfoPtr, messageValue,
											 msgData->data, msgData->length );
	if( cryptStatusError( status ) )
		return( status );

	/* If the user has logged in and the token has a hardware RNG, grab 256 
	   bits of entropy and send it to the system device.  Since we have no
	   idea how good this entropy is (it could be just a DES-based PRNG using
	   a static key or even an LFSR, which some smart cards use), we don't
	   set any entropy quality indication */
	if( isAuthent && deviceInfoPtr->getRandomFunction != NULL )
		{
		BYTE buffer[ 32 ];

		status = deviceInfoPtr->getRandomFunction( deviceInfoPtr, 
												   buffer, 32 );
		if( cryptStatusOK( status ) )
			{
			RESOURCE_DATA msgData;

			setMessageData( &msgData, buffer, 32 );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S, 
							 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
			}
		zeroise( buffer, 32 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Device API Functions						*
*																			*
****************************************************************************/

/* Default object creation routines used when the device code doesn't set
   anything up */

int createContext( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue );

static const CREATEOBJECT_FUNCTION_INFO defaultCreateFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Handle a message sent to a device object */

static int deviceMessageFunction( const void *objectInfoPtr,
								  const MESSAGE_TYPE message,
								  void *messageDataPtr,
								  const int messageValue )
	{
	DEVICE_INFO *deviceInfoPtr = ( DEVICE_INFO * ) objectInfoPtr;

	/* Process the destroy object message */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the device if required */
		if( deviceInfoPtr->flags & DEVICE_ACTIVE && \
			deviceInfoPtr->shutdownFunction != NULL )
			deviceInfoPtr->shutdownFunction( deviceInfoPtr );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		assert( message == MESSAGE_GETATTRIBUTE || \
				message == MESSAGE_GETATTRIBUTE_S || \
				message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S );

		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( deviceInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( deviceInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( deviceInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( deviceInfoPtr, messageDataPtr,
										  messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process action messages */
	if( isMechanismActionMessage( message ) )
		{
		CRYPT_DEVICE localCryptDevice = deviceInfoPtr->objectHandle;
		MECHANISM_FUNCTION mechanismFunction = NULL;
		int status;

		/* Find the function to handle this action and mechanism */
		if( deviceInfoPtr->mechanismFunctions != NULL )
			{
			int i = 0;

			while( deviceInfoPtr->mechanismFunctions[ i ].action != MESSAGE_NONE )
				{
				if( deviceInfoPtr->mechanismFunctions[ i ].action == message && \
					deviceInfoPtr->mechanismFunctions[ i ].mechanism == messageValue )
					{
					mechanismFunction = \
						deviceInfoPtr->mechanismFunctions[ i ].function;
					break;
					}
				i++;
				}
			}
		if( mechanismFunction == NULL && \
			localCryptDevice != SYSTEM_OBJECT_HANDLE )
			{
			int i = 0;

			/* This isn't the system object, fall back to the system object
			   and see if it can handle the mechanism.  We do it this way
			   rather than sending the message through the kernel a second
			   time because all the kernel checking of message parameters has
			   already been done (in terms of access control checks, we can
			   always send the message to the system object so this isn't a
			   problem), this saves the overhead of a second, redundant
			   kernel pass.  This code is currently only ever used with 
			   Fortezza devices, with PKCS #11 devices the support for 
			   various mechanisms is too patchy to allow us to rely on it, 
			   so we always use system mechanisms which we know will get it
			   right.  Because it should never be used in normal use, we 
			   throw an exception if we get here inadvertently (if this 
			   doesn't stop execution, the krnlAcquireObject() will since it 
			   will refuse to allocate the system object) */
			assert( NOTREACHED );
			krnlReleaseObject( deviceInfoPtr->objectHandle );
			localCryptDevice = SYSTEM_OBJECT_HANDLE;
			status = krnlAcquireObject( localCryptDevice, OBJECT_TYPE_DEVICE, 
										( void ** ) &deviceInfoPtr, 
										CRYPT_ERROR_SIGNALLED );
			if( cryptStatusError( status ) )
				return( status );
			assert( deviceInfoPtr->mechanismFunctions != NULL );
			while( deviceInfoPtr->mechanismFunctions[ i ].action != MESSAGE_NONE )
				{
				if( deviceInfoPtr->mechanismFunctions[ i ].action == message && \
					deviceInfoPtr->mechanismFunctions[ i ].mechanism == messageValue )
					{
					mechanismFunction = \
							deviceInfoPtr->mechanismFunctions[ i ].function;
					break;
					}
				i++;
				}
			}
		if( mechanismFunction == NULL )
			{
			krnlReleaseObject( deviceInfoPtr->objectHandle );
			return( CRYPT_ERROR_NOTAVAIL );
			}

		/* If the message has been sent to the system object, unlock it to
		   allow it to be used by others and dispatch the message */
		if( localCryptDevice == SYSTEM_OBJECT_HANDLE )
			{
			krnlReleaseObject( deviceInfoPtr->objectHandle );
			return( mechanismFunction( NULL, messageDataPtr ) );
			}

		/* Send the message to the device */
		return( mechanismFunction( deviceInfoPtr, messageDataPtr ) );
		}

	/* Process messages that check a device */
	if( message == MESSAGE_CHECK )
		{
		/* The check for whether this device type can contain an object that 
		   can perform the requested operation has already been performed by 
		   the kernel, so there's nothing further to do here */
		assert( ( messageValue == MESSAGE_CHECK_PKC_ENCRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_DECRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGCHECK_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGN_AVAIL ) && \
				( deviceInfoPtr->type == CRYPT_DEVICE_FORTEZZA || \
				  deviceInfoPtr->type == CRYPT_DEVICE_PKCS11 || \
				  deviceInfoPtr->type == CRYPT_DEVICE_CRYPTOAPI ) );

		return( CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == MESSAGE_KEY_GETKEY )
		{
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		assert( deviceInfoPtr->getItemFunction != NULL );

		/* Create a context via an object in the device */
		return( deviceInfoPtr->getItemFunction( deviceInfoPtr,
								&getkeyInfo->cryptHandle, messageValue,
								getkeyInfo->keyIDtype, getkeyInfo->keyID,
								getkeyInfo->keyIDlength, getkeyInfo->auxInfo, 
								&getkeyInfo->auxInfoLength, 
								getkeyInfo->flags ) );
		}
	if( message == MESSAGE_KEY_SETKEY )
		{
		MESSAGE_KEYMGMT_INFO *setkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		assert( deviceInfoPtr->setItemFunction != NULL );

		/* Update the device with the cert */
		return( deviceInfoPtr->setItemFunction( deviceInfoPtr,
												setkeyInfo->cryptHandle ) );
		}
	if( message == MESSAGE_KEY_DELETEKEY )
		{
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		assert( deviceInfoPtr->deleteItemFunction != NULL );

		/* Delete an object in the device */
		return( deviceInfoPtr->deleteItemFunction( deviceInfoPtr,
						messageValue, deletekeyInfo->keyIDtype,
						deletekeyInfo->keyID, deletekeyInfo->keyIDlength ) );
		}
	if( message == MESSAGE_KEY_GETFIRSTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		assert( getnextcertInfo->auxInfoLength == sizeof( int ) );
		assert( messageValue == KEYMGMT_ITEM_PUBLICKEY );
		assert( deviceInfoPtr->getFirstItemFunction != NULL );

		/* Fetch a cert in a cert chain from the device */
		return( deviceInfoPtr->getFirstItemFunction( deviceInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->keyIDtype, getnextcertInfo->keyID,
						getnextcertInfo->keyIDlength, messageValue,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_KEY_GETNEXTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		assert( getnextcertInfo->auxInfoLength == sizeof( int ) );
		assert( deviceInfoPtr->getNextItemFunction != NULL );

		/* Fetch a cert in a cert chain from the device */
		return( deviceInfoPtr->getNextItemFunction( deviceInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_DEV_QUERYCAPABILITY )
		{
		const void FAR_BSS *capabilityInfoPtr;
		CRYPT_QUERY_INFO *queryInfo = ( CRYPT_QUERY_INFO * ) messageDataPtr;

		/* Find the information for this algorithm and return the appropriate
		   information */
		capabilityInfoPtr = findCapabilityInfo( deviceInfoPtr->capabilityInfoList,
												messageValue );
		if( capabilityInfoPtr == NULL )
			return( CRYPT_ERROR_NOTAVAIL );
		getCapabilityInfo( queryInfo, capabilityInfoPtr );

		return( CRYPT_OK );
		}
	if( message == MESSAGE_DEV_CREATEOBJECT )
		{
		CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
		CREATEOBJECT_FUNCTION createObjectFunction = NULL;
		const void *auxInfo = NULL;
		int status;

		assert( messageValue > OBJECT_TYPE_NONE && \
				messageValue < OBJECT_TYPE_LAST );

		/* If the device can't have objects created within it, complain */
		if( deviceInfoPtr->flags & DEVICE_READONLY )
			return( CRYPT_ERROR_PERMISSION );

		/* Find the function to handle this object */
		if( deviceInfoPtr->createObjectFunctions != NULL )
			{
			int i = 0;

			while( deviceInfoPtr->createObjectFunctions[ i ].type != OBJECT_TYPE_NONE )
				{
				if( deviceInfoPtr->createObjectFunctions[ i ].type == messageValue )
					{
					createObjectFunction  = \
						deviceInfoPtr->createObjectFunctions[ i ].function;
					break;
					}
				i++;
				}
			}
		if( createObjectFunction  == NULL )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Get any auxiliary info that we may need to create the object */
		if( messageValue == OBJECT_TYPE_CONTEXT )
			auxInfo = deviceInfoPtr->capabilityInfoList;

		/* If the message has been sent to the system object, unlock it to
		   allow it to be used by others and dispatch the message.  This is 
		   safe because the auxInfo for the system device is in a static,
		   read-only segment and persists even if the system device is
		   destroyed */
		if( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE )
			{
			krnlReleaseObject( deviceInfoPtr->objectHandle );
			status = createObjectFunction( messageDataPtr, auxInfo, 
										   CREATEOBJECT_FLAG_NONE );
			}
		else
			/* Create a dummy object, with all details handled by the device.
			   Unlike the system device, we don't unlock the device info 
			   before we call the create object function because there may be 
			   auxiliary info held in the device object that we need in order 
			   to create the object.  This is OK since we're not tying up the 
			   system device but only some auxiliary crypto device */
			status = createObjectFunction( messageDataPtr, auxInfo,
										   CREATEOBJECT_FLAG_DUMMY );
		if( cryptStatusError( status ) )
			return( status );

		/* Make the newly-created object a dependent object of the device */
		return( krnlSendMessage( \
					( ( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr )->cryptHandle,
					IMESSAGE_SETDEPENDENT, ( void * ) &iCryptDevice,
					SETDEP_OPTION_INCREF ) );
		}
	if( message == MESSAGE_DEV_CREATEOBJECT_INDIRECT )
		{
		CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
		int status;

		/* At the moment the only objects where can be created in this manner
		   are certificates */
		assert( messageValue == OBJECT_TYPE_CERTIFICATE );
		assert( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE );

		/* Unlock the system object to allow it to be used by others and 
		   dispatch the message */
		krnlReleaseObject( deviceInfoPtr->objectHandle );
		status = createCertificateIndirect( messageDataPtr, NULL, 0 );
		if( cryptStatusError( status ) )
			return( status );

		/* Make the newly-created object a dependent object of the device */
		return( krnlSendMessage( \
					( ( MESSAGE_CREATEOBJECT_INFO * ) messageDataPtr )->cryptHandle,
					IMESSAGE_SETDEPENDENT, ( void * ) &iCryptDevice,
					SETDEP_OPTION_INCREF ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a device.  This is a common function called to create both the
   internal system device object and general devices */

static int openDevice( CRYPT_DEVICE *device,
					   const CRYPT_USER cryptOwner,
					   const CRYPT_DEVICE_TYPE deviceType,
					   const char *name, const int nameLength,
					   DEVICE_INFO **deviceInfoPtrPtr )
	{
	DEVICE_INFO *deviceInfoPtr;
	const int subType = \
			( deviceType == CRYPT_DEVICE_NONE ) ? SUBTYPE_DEV_SYSTEM : \
			( deviceType == CRYPT_DEVICE_FORTEZZA ) ? SUBTYPE_DEV_FORTEZZA : \
			( deviceType == CRYPT_DEVICE_PKCS11 ) ? SUBTYPE_DEV_PKCS11 : \
			( deviceType == CRYPT_DEVICE_CRYPTOAPI ) ? SUBTYPE_DEV_CRYPTOAPI : 0;
	int storageSize, status;

	assert( deviceInfoPtrPtr != NULL );
	assert( subType != 0 );

	/* Clear the return values */
	*device = CRYPT_ERROR;
	*deviceInfoPtrPtr = NULL;

	/* Set up subtype-specific information */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			storageSize = sizeof( SYSTEMDEV_INFO );
			break;

		case CRYPT_DEVICE_FORTEZZA:
			storageSize = sizeof( FORTEZZA_INFO );
			break;

		case CRYPT_DEVICE_PKCS11:
			storageSize = sizeof( PKCS11_INFO );
			break;

		case CRYPT_DEVICE_CRYPTOAPI:
			storageSize = sizeof( CRYPTOAPI_INFO );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Create the device object and connect it to the device */
	status = krnlCreateObject( ( void ** ) &deviceInfoPtr, 
							   sizeof( DEVICE_INFO ) + storageSize, 
							   OBJECT_TYPE_DEVICE, subType, 
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, deviceMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*deviceInfoPtrPtr = deviceInfoPtr;
	*device = deviceInfoPtr->objectHandle = status;
	deviceInfoPtr->ownerHandle = cryptOwner;
	deviceInfoPtr->type = deviceType;
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			deviceInfoPtr->deviceSystem = \
							( SYSTEMDEV_INFO * ) deviceInfoPtr->storage;
			break;

		case CRYPT_DEVICE_FORTEZZA:
			deviceInfoPtr->deviceFortezza = \
							( FORTEZZA_INFO * ) deviceInfoPtr->storage;
			break;

		case CRYPT_DEVICE_PKCS11:
			deviceInfoPtr->devicePKCS11 = \
							( PKCS11_INFO * ) deviceInfoPtr->storage;
			break;

		case CRYPT_DEVICE_CRYPTOAPI:
			deviceInfoPtr->deviceCryptoAPI = \
							( CRYPTOAPI_INFO * ) deviceInfoPtr->storage;
			break;
		}
	deviceInfoPtr->storageSize = storageSize;

	/* Set up the access information for the device and connect to it */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			status = setDeviceSystem( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_FORTEZZA:
			status = setDeviceFortezza( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_PKCS11:
			status = setDevicePKCS11( deviceInfoPtr, name, nameLength );
			break;

		case CRYPT_DEVICE_CRYPTOAPI:
			status = setDeviceCryptoAPI( deviceInfoPtr, name, nameLength );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusOK( status ) )
		status = deviceInfoPtr->initFunction( deviceInfoPtr, name, 
											  nameLength );
	if( cryptStatusOK( status ) && \
		deviceInfoPtr->createObjectFunctions == NULL )
		/* The device-specific code hasn't set up anything, use the default
		   create-object functions (which just create encryption contexts
		   using the device capability information) */
		deviceInfoPtr->createObjectFunctions = defaultCreateFunctions;
	return( status );
	}

/* Create a (non-system) device object */

int createDevice( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking.  This also catches any attempts to 
	   create a second system device object, which has an (external) type of 
	   CRYPT_DEVICE_NONE */
	if( createInfo->arg1 <= CRYPT_DEVICE_NONE || \
		createInfo->arg1 >= CRYPT_DEVICE_LAST )
		return( CRYPT_ARGERROR_NUM1 );
	if( ( createInfo->arg1 == CRYPT_DEVICE_PKCS11 || \
		  createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI ) && \
		createInfo->strArgLen1 <= MIN_NAME_LENGTH )
		return( CRYPT_ARGERROR_STR1 );

	/* Wait for any async device driver binding to complete */
	krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Pass the call on to the lower-level open function */
	initStatus = openDevice( &iCryptDevice, createInfo->cryptOwner,
							 createInfo->arg1, createInfo->strArg1,
							 createInfo->strArgLen1, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) && \
		createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI )
		{
		/* If it's a device that doesn't require an explicit login, move it 
		   into the initialised state */
		status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE, 
								  MESSAGE_VALUE_UNUSED, 
								  CRYPT_IATTRIBUTE_INITIALISED );
		if( cryptStatusError( status ) )
			krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );
		}
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptDevice;
	return( CRYPT_OK );
	}

/* Create the internal system device object.  This is somewhat special in
   that it can't be destroyed through a normal message (it can only be done
   from one place in the kernel) so if the open fails we don't use the normal
   signalling mechanism to destroy it but simply return an error code to the
   caller (the cryptlib init process).  This causes the init to fail and 
   destroys the object when the kernel shuts down */

static int createSystemDeviceObject( void )
	{
	CRYPT_DEVICE iSystemObject;
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Pass the call on to the lower-level open function.  This device is
	   unique and has no owner or type */
	status = openDevice( &iSystemObject, CRYPT_UNUSED, CRYPT_DEVICE_NONE,
						 NULL, 0, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( status );	/* Create object failed, return immediately */
	if( cryptStatusError( status ) )
		/* The device open failed, we'd normally have to signal the device
		   object to destroy itself when the init completes, however we don't
		   have the privileges to do this so we just pass the error code back
		   to the caller which causes the cryptlib init to fail */
		return( status );
	assert( iSystemObject == SYSTEM_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel the object is ready for use and move it into the initialised
	   state */
	status = krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE, 
								  MESSAGE_VALUE_UNUSED, 
								  CRYPT_IATTRIBUTE_INITIALISED );
		if( cryptStatusError( status ) )
			krnlSendNotifier( iSystemObject, IMESSAGE_DESTROY );
		}
	return( status );
	}

/* Generic management function for this class of object.  Unlike the usual 
   multilevel init process which is followed for other objects, the devices 
   have an OR rather than an AND relationship since the devices are 
   logically independent, so we set a flag for each device type that is 
   successfully initialised rather than recording an init level */

#define DEV_NONE_INITED			0x00
#define DEV_FORTEZZA_INITED		0x01
#define DEV_PKCS11_INITED		0x02
#define DEV_CRYPTOAPI_INITED	0x04

int deviceManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	static int initFlags = DEV_NONE_INITED;

	assert( action == MANAGEMENT_ACTION_PRE_INIT || \
			action == MANAGEMENT_ACTION_INIT || \
			action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			action == MANAGEMENT_ACTION_SHUTDOWN );
	
	switch( action )
		{
		case MANAGEMENT_ACTION_PRE_INIT:
			return( createSystemDeviceObject() );

		case MANAGEMENT_ACTION_INIT:
			if( cryptStatusOK( deviceInitFortezza() ) )
				initFlags |= DEV_FORTEZZA_INITED;
			if( cryptStatusOK( deviceInitPKCS11() ) )
				initFlags |= DEV_PKCS11_INITED;
			if( cryptStatusOK( deviceInitCryptoAPI() ) )
				initFlags |= DEV_CRYPTOAPI_INITED;
			return( CRYPT_OK );
		
		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* In theory we could signal the background entropy poll to 
			   start wrapping up at this point, however this background 
			   polling only occurs in two instances, on Unix systems it's 
			   done by forking off a process with which there's no easy way 
			   to communicate, so the shutdown function kill()'s it, and on 
			   Windows systems it's done as a background thread that 
			   periodically checks a semaphore, however without adding a 
			   special-case object interface for this there's no direct way 
			   to access it, and in any case all we're doing is saving half 
			   a ms or so since the shutdown function sets it anyway.  
			   Because of this we don't try and do anything here, although 
			   this call is left in place as a no-op in case it's needed in 
			   the future */
			return( CRYPT_OK );
		
		case MANAGEMENT_ACTION_SHUTDOWN:
			if( initFlags & DEV_FORTEZZA_INITED )
				deviceEndFortezza();
			if( initFlags & DEV_PKCS11_INITED )
				deviceEndPKCS11();
			if( initFlags & DEV_CRYPTOAPI_INITED )
				deviceEndCryptoAPI();
			initFlags = DEV_NONE_INITED;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
