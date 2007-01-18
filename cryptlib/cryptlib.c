/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#include "crypt.h"

/* Prototypes for functions in init.c */

int krnlBeginInit( void );
void krnlCompleteInit( void );
int krnlBeginShutdown( void );
int krnlCompleteShutdown( void );

/* Temporary kludge for functions that have to be performed mid-startup or 
   mid-shutdown */

int destroyObjects( void );
int testKernel( void );

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
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* The initialisation and shutdown actions performed for various object
   types.  The pre-init actions are used to handle various preparatory
   actions that are required before the actual init can be performed, for
   example to create the system device and user object, which are needed by
   the init routines.  The pre-shutdown actions are used to signal to various
   subsystems that a shutdown is about to occur, for example to allow the
   networking subsystem to gracefully exit from any currently occurring 
   network I/O.

   The order of the init/shutdown actions is:

					Object type		Action
					-----------		------
	Pre-init:		Device			Create system object

	Init:			User			Create default user object
					Keyset			Drivers - keysets			| Done 
					Device			Drivers - devices			| async if
					Session			Drivers - networking		| available
				   [Several]		Kernel self-test

	Pre-shutdown:	Session			Networking - signal socket close
					Device			System object - signal entropy poll end

	Shutdown:		User			Destroy default user object	| Done by
					Device			Destroy system object		| kernel
					Keyset			Drivers - keysets
					Device			Drivers - devices
					Session			Drivers - networking

   The init order is determined by the following object dependencies:

	All -> Device
			(System object handles many message types).
	User -> Keyset, Cert 
			(Default user object reads config data from the default keyset 
			 to init drivers for keysets, devices, and networking, and 
			 trusted certs.  The default keyset isn't read via a loadable 
			 keyset driver so it doesn't require the keyset driver init).
	Self-test -> Several
			(Kernel self-test creates several ephemeral objects in order to 
			 test the kernel mechanisms).

   The shutdown order is determined by the following dependencies:

	Session (Networking needs to shut down to release any objects that are 
			 blocked waiting on network I/O)
	Device (System object needs to shut down ongoing entropy poll)

   After this the shutdown proper can take place.  The shutdown order is
   noncritical, provided that the pre-shutdown actions have occurred.

   In theory the user and system objects are destroyed as part of the 
   standard shutdown, however the kernel prevents these objects from ever
   being explicitly destroyed so they're destroyed implicitly by the
   destroyObjects() cleanup call */

int certManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int deviceManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int keysetManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int sessionManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int userManagementFunction( const MANAGEMENT_ACTION_TYPE action );

typedef int ( *MANAGEMENT_FUNCTION )( const MANAGEMENT_ACTION_TYPE action );

static const MANAGEMENT_FUNCTION preInitFunctions[] = {
	deviceManagementFunction, NULL 
	};
static const MANAGEMENT_FUNCTION initFunctions[] = {
	userManagementFunction, NULL 
	};
static const MANAGEMENT_FUNCTION asyncInitFunctions[] = {
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION preShutdownFunctions[] = {
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	deviceManagementFunction, 
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION shutdownFunctions[] = {
	/*userManagementFunction,*/ /*deviceManagementFunction,*/ 
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};

/* Dispatch a set of management actions */

static int dispatchManagementAction( const MANAGEMENT_FUNCTION *mgmtFunctions,
									 const MANAGEMENT_ACTION_TYPE action )
	{
	int i, status = CRYPT_OK;

	/* If we're performing a startup and the kernel is shutting down, bail 
	   out now */
	if( ( action == MANAGEMENT_ACTION_INIT ) && krnlIsExiting() )
		return( CRYPT_ERROR_PERMISSION );

	/* Dispatch each management action in turn */
	for( i = 0; mgmtFunctions[ i ] != NULL && \
				i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		const int localStatus = mgmtFunctions[ i ]( action );
		if( cryptStatusError( localStatus ) && cryptStatusOK( status ) )
			status = localStatus;

		/* If we're performing a startup and the kernel is shutting down, 
		   bail out now */
		if( ( action == MANAGEMENT_ACTION_INIT ) && krnlIsExiting() )
			return( CRYPT_ERROR_PERMISSION );
		}
	if( i >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( status );
	}

/* Under various OSes we bind to a number of drivers at runtime.  We can
   either do this sychronously or asynchronously depending on the setting of 
   a config option.  By default we use the async init since it speeds up the 
   startup.  Synchronisation is achieved by having the open/init functions 
   in the modules that require the drivers call krnlWaitSemaphore() on the 
   driver binding semaphore, which blocks until the drivers are bound if an 
   async bind is in progress, or returns immediately if no bind is in 
   progress */

#ifdef USE_THREADS

void threadedBind( const THREAD_PARAMS *threadParams )
	{
	dispatchManagementAction( threadParams->ptrParam, 
							  threadParams->intParam );
	}
#endif /* USE_THREADS */

/* Initialise and shut down the system */

int initCryptlib( void )
	{
	int initLevel = 0, status;

	/* Perform OS-specific additional initialisation */
#if ( defined( __WIN32__ ) || defined( __WINCE__ ) ) && defined( STATIC_LIB )
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	if( dwPlatform == CRYPT_ERROR )
		{
		OSVERSIONINFO osvi = { sizeof( OSVERSIONINFO ) };

		/* Figure out which version of Windows we're running under */
		GetVersionEx( &osvi );
		dwPlatform = osvi.dwPlatformId;
		isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? TRUE : FALSE;

		/* Check for Win32s just in case someone ever tries to load cryptlib 
		   under it */
		if( dwPlatform == VER_PLATFORM_WIN32s )
			return( CRYPT_ERROR );
		}
#endif /* Win32/WinCE && STATIC_LIB */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	/* VisualAge C++ doesn't set the TZ correctly */
	tzset();
#endif /* VisualAge C++ */
#if defined( CONFIG_DATA_LITTLEENDIAN ) || defined( CONFIG_DATA_BIGENDIAN )
	/* If we're using a user-defined endianness override (i.e. it's a cross-
	   compile from a difference architecture), perform a sanity check to 
	   make sure that the endianness was set right.  Since this will 
	   typically be running on an embedded system, there's not much that we 
	   can (safely) do in terms of user I/O except to return a special-case 
	   return code and hope that the user checks the embedded systems section 
	   of  the manual for more details.  The crypto self-test that's 
	   performed a few lines further down will catch this problem as well, 
	   but it's better to do an explicit check here that catches the 
	   endianness problem, rather than just returning a generic self-test 
	   fail error */
  #ifdef DATA_LITTLEENDIAN
		if( *( ( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" ) < 0 )
  #else
		if( *( ( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" ) >= 0 )
  #endif /* DATA_LITTLEENDIAN */
			{
			/* We should probably sound klaxons as well at this point */
			retIntError();
			}
#endif /* Big/little-endian override check */

	/* Initiate the kernel startup */
	status = krnlBeginInit();
	if( cryptStatusError( status ) )
		return( status );

	/* Perform the multi-phase bootstrap */
	status = dispatchManagementAction( preInitFunctions, 
									   MANAGEMENT_ACTION_PRE_INIT );
	assert( cryptStatusOK( status ) );
	if( cryptStatusOK( status ) )
		{
		initLevel = 1;
		status = dispatchManagementAction( initFunctions, 
										   MANAGEMENT_ACTION_INIT );
		assert( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
#ifdef USE_THREADS
		BOOLEAN asyncInit = FALSE;
#endif /* USE_THREADS */

		initLevel = 2;

		/* Perform the final init phase asynchronously or synchronously 
		   depending on the config option setting.  We always send this 
		   query to the default user object since no other user objects 
		   exist at this time */
#ifdef USE_THREADS
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, &asyncInit, 
								  CRYPT_OPTION_MISC_ASYNCINIT );
		if( cryptStatusOK( status ) && asyncInit )
			{
			/* We use the kernel's thread storage for this thread, so we 
			   specify the thread data storage as NULL */
			status = krnlDispatchThread( threadedBind, NULL, 
										 asyncInitFunctions, 
										 MANAGEMENT_ACTION_INIT,
										 SEMAPHORE_DRIVERBIND );
			if( cryptStatusError( status ) )
				/* The thread couldn't be started, try again with a 
				   synchronous init */
				asyncInit = FALSE;
			}
		if( !asyncInit )
#endif /* USE_THREADS */
		status = dispatchManagementAction( asyncInitFunctions, 
										   MANAGEMENT_ACTION_INIT );
		assert( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
		/* Everything's set up, verify that the core crypto algorithms and 
		   kernel security mechanisms are working as required */
		status = testKernel();
		assert( cryptStatusOK( status ) );
		}

	/* If anything failed, shut down the internal functions and services
	   before we exit */
	if( cryptStatusError( status ) )
		{
		if( initLevel >= 1 )
			{
			/* Shut down any external interfaces */
			dispatchManagementAction( preShutdownFunctions, 
									  MANAGEMENT_ACTION_PRE_SHUTDOWN );
			destroyObjects();
			dispatchManagementAction( shutdownFunctions, 
									  MANAGEMENT_ACTION_SHUTDOWN );
			}
		krnlCompleteShutdown();
		return( status );
		}

	/* Complete the kernel startup */
	krnlCompleteInit();
	return( CRYPT_OK );
	}

int endCryptlib( void )
	{
	int status;

	/* Initiate the kernel shutdown */
	status = krnlBeginShutdown();
	if( cryptStatusError( status ) )
		return( status );

	/* Reverse the process carried out in the multi-phase bootstrap */
	dispatchManagementAction( preShutdownFunctions, 
							  MANAGEMENT_ACTION_PRE_SHUTDOWN );
	status = destroyObjects();
	dispatchManagementAction( shutdownFunctions, 
							  MANAGEMENT_ACTION_SHUTDOWN );

	/* Complete the kernel shutdown */
	krnlCompleteShutdown();
	return( status );
	}
