/****************************************************************************
*																			*
*							cryptlib OS-specific Macros  					*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifndef _CRYPTOS_DEFINED

#define _CRYPTOS_DEFINED

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best we can do is check that it's not null, but some OSes allow for
   better checking than this, for example that it points to a block of
   readable or writeable memory.  Under Windows IsBadReadPtr() will always
   succeed if the size is 0, so we have to add a separate check to make sure
   it's non-NULL */

#if defined( __WIN32__ )
  #define checkBadPtrRead( ptr, size )	( ( ptr ) == NULL || \
										  IsBadReadPtr( ( ptr ), ( size ) ) )
  #define checkBadPtrWrite( ptr, size )	( ( ptr ) == NULL || \
										  IsBadWritePtr( ( ptr ), ( size ) ) )
#else
  #define checkBadPtrRead( ptr, size )	( ( ptr ) == NULL )
  #define checkBadPtrWrite( ptr, size )	( ( ptr ) == NULL )
#endif /* Pointer check macros */
#define isReadPtr( ptr, dataType ) \
		!checkBadPtrRead( ptr, sizeof( dataType ) )
#define isReadPtrEx( ptr, dataType, count ) \
		!checkBadPtrRead( ptr, sizeof( dataType ) * count )
#define isWritePtr( ptr, dataType ) \
		!checkBadPtrWrite( ptr, sizeof( dataType ) )
#define isWritePtrEx( ptr, dataType, count ) \
		!checkBadPtrWrite( ptr, sizeof( dataType ) * count )

/* When working with secure memory we need to take the OS page size into
   account.  The following macro obtains the OS page size */

#if defined( __WIN32__ )
  /* This assumes Intel hardware, which is virtually always the case */
  #define getPageSize()			4096
#elif defined( __UNIX__ )
  #if defined( __hpux ) || defined( _M_XENIX ) || defined( __aux )
	#define getPageSize()		4096
  #else
	#define getPageSize()		getpagesize()
  #endif /* Unix variant-specific brokenness */
#endif /* OS-specifc page size determination */

/* Under OSF/1 pthread.h includes c_asm.h which contains a declaration

	long asm( const char *,...);

   which conflicts with the gcc asm keyword.  This asm stuff is only used
   when inline asm alternatives to the Posix threading functions are enabled,
   which isn't done by default so in theory we could also fix this by
   defining asm to something else before including pthread.h, but it's safer
   to just disable inclusion of c_asm.h by pre-defining the guard define,
   which should result in a more useful warning if for some reason inline
   threading functions with asm are enabled */

#if defined( __osf__ ) || defined( __alpha__ )
  #define __C_ASM_H
#endif /* Alpha */

/* Get the start address of a page and, given an address in a page and a
   size, determine on which page the data ends.  These are used to determine
   which pages a memory block covers.

   These macros have portability problems since they assume that
   sizeof( long ) == sizeof( void * ), but there's no easy way to avoid this
   since for some strange reason C doesn't allow the perfectly sensible use
   of logical operations on addresses */

#define getPageStartAddress( address ) \
			( ( long ) ( address ) & ~( getPageSize() - 1 ) )
#define getPageEndAddress( address, size ) \
			getPageStartAddress( ( long ) address + ( size ) - 1 )

/****************************************************************************
*																			*
*								Object Handling Macros						*
*																			*
****************************************************************************/

/* In multithreaded environments we need to protect the information inside
   cryptlib data structures from access by other threads while we use it.
   The following macros handle this object protection when we enter and
   exit cryptlib functions.  The initResourceLock() and deleteResourceLock()
   macros initialise the data structure needed to perform the object
   locking.  Note the before deleting the resource lock we lock and unlock
   it again to ensure that if some other thread is holding the resource,
   they'll release it before we delete the lock */

#if defined( __WIN32__ ) && !defined( NT_DRIVER )

#include <process.h>

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		static CRITICAL_SECTION name##CriticalSection; \
		static BOOLEAN name##CriticalSectionInitialised = FALSE;
#define initResourceLock( name ) \
		if( !name##CriticalSectionInitialised ) \
			{ \
			InitializeCriticalSection( &name##CriticalSection ); \
			name##CriticalSectionInitialised = TRUE; \
			}
#define deleteResourceLock( name ) \
		if( name##CriticalSectionInitialised ) \
			{ \
			EnterCriticalSection( &name##CriticalSection ); \
			LeaveCriticalSection( &name##CriticalSection ); \
			DeleteCriticalSection( &name##CriticalSection ); \
			name##CriticalSectionInitialised = FALSE; \
			}
#define lockResource( name ) \
		EnterCriticalSection( &name##CriticalSection )
#define unlockResource( name ) \
		LeaveCriticalSection( &name##CriticalSection )

/* Handles to threads and system synchronisation objects */

#define THREAD_HANDLE			HANDLE
#define SEMAPHORE_HANDLE		HANDLE

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
								unsigned __stdcall name( void *arg )

/* Thread management functions.  There are two functions that we can call to
   get the current thread ID, GetCurrentThread() and GetCurrentThreadId().
   These are actually implemented as the same function (once you get past
   the outer wrapper), and the times for calling either are identical - a
   significant 10 us per call on a P5/166.  The only difference between the
   two is that GetCurrentThread() returns a per-process pseudohandle while
   GetCurrentThreadId() returns a systemwide, unique handle.

   Note that after we wait for the thread, we need to close the handle.
   This is complicated by the fact that we can only close it once all
   threads have exited the wait, which requires further calisthenics in
   the function that uses it to ensure that the last thread out closes the
   handle */

#define THREAD_CREATE( function, arg, handle ) \
								( !( handle = ( HANDLE ) _beginthreadex( NULL, 0, \
													( function ), ( arg ), 0, \
													( unsigned * ) &dummy ) ) ? \
									CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			_endthreadex( 0 ); return( 0 )
#define THREAD_CREATE_VARS		int dummy
#define THREAD_INITIALISER		0
#define THREAD_SELF()			( THREAD_HANDLE ) GetCurrentThreadId()
#define THREAD_SAME( thread1, thread2 ) \
								( ( thread1 ) == ( thread2 ) )
#define THREAD_SLEEP( ms )		Sleep( ms )
#define THREAD_YIELD()			Sleep( 0 )
#define THREAD_WAIT( thread )	WaitForSingleObject( thread, INFINITE );
#define THREAD_CLOSE( thread )	CloseHandle( thread )

/* Remember that we're using threaded functions */

#define USE_THREADS

#elif defined( __WIN32__ ) && defined( NT_DRIVER )

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		static KMUTEX name##CriticalSection; \
		static BOOLEAN name##CriticalSectionInitialised = FALSE;
#define initResourceLock( name ) \
		if( !name##CriticalSectionInitialised ) \
			{ \
			KeInitializeMutex( &name##CriticalSection, 1 ); \
			name##CriticalSectionInitialised = TRUE; \
			}
#define deleteResourceLock( name )

#define lockResource( name ) \
		KeWaitForMutexObject( &name##CriticalSection, Executive, \
							  KernelMode, FALSE, NULL )
#define unlockResource( name ) \
		KeReleaseMutex( &name##CriticalSection, FALSE )

/* Handles to threads and system synchronisation objects */

#define THREAD_HANDLE				HANDLE
#define SEMAPHORE_HANDLE			HANDLE

#elif defined( __OS2__ )

#define INCL_DOSSEMAPHORES
#define INCL_DOSMISC
#define INCL_DOSFILEMGR
#define INCL_DOSMISC
#define INCL_DOSDATETIME
#define INCL_DOSPROCESS
#define INCL_WINWINDOWMGR
#define INCL_WINSYS
#include <os2.h>
ULONG DosGetThreadID( void );

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		static HMTX name##Mutex; \
		static BOOLEAN name##MutexInitialised = FALSE;
#define initResourceLock( name ) \
		if( !name##MutexInitialised ) \
			{ \
			DosCreateMutexSem( NULL, &name##Mutex, 0L, FALSE ); \
			name##MutexInitialised = TRUE; \
			}
#define deleteResourceLock( name ) \
		if( name##MutexInitialised ) \
			{ \
			DosRequestMutexSem( name##Mutex, ( ULONG ) SEM_INDEFINITE_WAIT ); \
			DosReleaseMutexSem( name##Mutex ); \
			DosCloseMutexSem( name##Mutex ); \
			name##MutexInitialised = FALSE; \
			}
#define lockResource( name ) \
		DosRequestMutexSem( name##Mutex, ( ULONG ) SEM_INDEFINITE_WAIT )
#define unlockResource( name ) \
		DosReleaseMutexSem( name##Mutex )

/* Handles to threads and system synchronisation objects */

#define THREAD_HANDLE			TID
#define SEMAPHORE_HANDLE		HEV

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
									void _Optlink name( void *arg )

/* Thead management functions */

#define THREAD_CREATE( function, arg, handle ) \
								( ( handle = _beginthread( ( function ), NULL, 8192, \
														 ( arg ) ) ) == -1 ? \
									CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			_endthread()
#define THREAD_CREATE_VARS
#define THREAD_INITIALISER		0
#define THREAD_SELF()			DosGetThreadID()
#define THREAD_SAME( thread1, thread2 ) \
								( ( thread1 ) == ( thread2 ) )
#define THREAD_SLEEP( ms )		DosWait( ms )
#define THREAD_YIELD()			DosWait( 0 )
#define THREAD_WAIT( thread )	DosWaitThread( thread, INFINITE )
#define THREAD_CLOSE( thread )

/* Remember that we're using threaded functions */

#define USE_THREADS

#elif defined( __UNIX__ ) && defined( USE_THREADS )

/* Handles to threads and system synchronisation objects */

#define THREAD_HANDLE			THREAD
#define SEMAPHORE_HANDLE		THREAD

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
									void *name( void *arg )

/* Thead management functions.  Most Unix mutex implementations are non-
   re-entrant, which means that re-locking a mutex leads to deadlock (nice
   design, guys).  Some implementations can fix this by setting a mutex
   attribute to ensure that it doesn't deadlock:

	pthread_mutexattr_settype( attr, PTHREAD_MUTEX_RECURSIVE );

   but this isn't universal.  To fix the problem, we implement our own
   re-entrant mutexes on top of the Posix ones using mutex_trylock(), which
   doesn't re-lock the mutex if it's already locked (as a side-benefit,
   trylock() is roughly twice as fast as lock(), depending on the OS).  This
   works as follows:

	// Try and lock the mutex
	if( mutex_trylock( mutex ) == error )
		{
		// The mutex is already locked, see who owns it
		if( thread_self() != mutex_owner )
			// Someone else has it locked, wait for it to become available
			mutex_lock( mutex );
		else
			// We have it locked, increment its lock count
			mutex_lockcount++;
		}
	mutex_owner = thread_self();

	// ....

	// Decrement the lock count and if we reach zero, unlock the mutex
	if( mutex_lockcount > 0 )
		mutex_lockcount--;
	else
		mutex_unlock( mutex );

   Putting a thread to sleep for a number of milliseconds can be done with
   select() because it should be a thread-safe one in the presence of
   pthreads.  Yielding a thread's timeslice is rather more tricky and is done
   further on.  In addition there are some system-specific quirks, these are
   handled by re-defining the macros below in a system-specific manner further
   on */

#include <pthread.h>
#include <sys/time.h>

#define MUTEX					pthread_mutex_t
#define MUTEX_INIT( mutex )		pthread_mutex_init( mutex, NULL )
#define MUTEX_DESTROY			pthread_mutex_destroy
#define MUTEX_LOCK				pthread_mutex_lock
#define MUTEX_TRYLOCK			pthread_mutex_trylock
#define MUTEX_UNLOCK			pthread_mutex_unlock

#define THREAD					pthread_t
#define THREAD_CREATE( function, arg, handle ) \
								( pthread_create( &handle, NULL, function, arg ) ? \
									CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			pthread_exit( ( void * ) 0 )
#define THREAD_CREATE_VARS
#define THREAD_INITIALISER		0
#define THREAD_SELF()			pthread_self()
#define THREAD_SAME( thread1, thread2 ) \
								pthread_equal( ( thread1 ), ( thread2 ) )
#define THREAD_SLEEP( ms )		{ \
								struct timeval tv = { 0 }; \
								\
								tv.tv_usec = ( ms ) * 1000; \
								select( 1, NULL, NULL, NULL, &tv ); \
								}
#define THREAD_WAIT( thread )	pthread_join( thread, NULL )
#define THREAD_CLOSE( thread )

/* Yield a thread's timeslice.  This gets rather complex due to a confusion
   of non-portable "portable" Posix functions.  Initially there was
   pthread_yield() from draft 4 of the Posix thread standard in 1990,
   popularised in the DCE threading code and picked up by a number of
   other implementations.  Eventually this was deprecated in favour of
   sched_yield(), however some implementations still do pthread_yield()
   and some implementations use sched_yield() to yield the processes'
   timeslice rather than the thread's timeslice.  The whole is further
   confused by the fact that in some implementations, threads are processes
   (sort of, e.g. Linux's clone()'d threads and Sun LWPs).  In addition Sun
   have their own thr_yield which is part of their UI threads interface and
   that you have to fall back to occasionally.

   Because of this mess, we try for pthread_yield() if possible (since that
   yields the thread's timeslice), fall back to sched_yield() if necessary,
   and add a special workaround for Sun systems.

   "Posix is portable in the sense that you can use a forklift to move the
    printed volumes around" */

#if defined( __osf__ ) || defined( __alpha__ ) || defined( __APPLE__ )
  #define THREAD_YIELD()		pthread_yield_np()
#elif defined( __MVS__ )
  #define THREAD_YIELD()		pthread_yield( NULL )
#elif defined( sun )
  /* Slowaris gets a bit complex, SunOS 4.x always returns -1 and sets errno
     to ENOSYS when sched_yield() is called, so we use this to fall back to
	 the UI interface if necessary */
  #define THREAD_YIELD()		{ if( sched_yield() ) thr_yield(); }
#elif defined( _AIX ) || defined( USE_SCHED_YIELD )
  #define THREAD_YIELD()		sched_yield()
#else
  #define  THREAD_YIELD()		pthread_yield()
#endif /* Not-very-portable Posix portability */

/* OSF1 includes some ghastly kludgery to handle binary compatibility from
   1003.4a to 1003.1c threading functions and inline asm functions with all
   sorts of name mangling and translation of function names and types.
   Unfortunately a straight vanilla compile leaves pthread_self() un-
   prototyped, which means it's implicitly prototyped as returned an int.
   This generates hundreds of warnings of int <-> pointer casting problems,
   so if pthread_self() isn't redefined into one of a dozen different
   mangled versions we prototype it ourselves here */

#if ( defined( __osf__ ) || defined( __alpha__ ) ) && \
	!defined( pthread_self )
  #ifdef _PTHREAD_USE_MANGLED_NAMES_
	#define pthread_self __pthread_self
  #endif /* Name mangling */
  extern pthread_t pthread_self( void );
#endif /* OSF1 pthread_self function prototyping bug */

/* The pthreads implementation on MP-RAS (NCR User Space Threads based on
   CMA threads for DCE) doesn't accept NULL for several of the attribute
   arguments so we have to supply pthread_mutexattr_default attributes */

#ifdef _MPRAS
  #undef MUTEX_INIT
  #define MUTEX_INIT( mutex )	pthread_mutex_init( mutex, \
													pthread_mutexattr_default )
  #undef THREAD_CREATE
  #define THREAD_CREATE( function, arg, handle ) \
								( pthread_create( &handle, pthread_attr_default, \
												  function, arg ) ? CRYPT_ERROR : CRYPT_OK )
#endif /* _MPRAS */

/* Some systems (notable MVS and MP-RAS) use non-scalar pthread_t's, so we
   have to handle initialisation of these specially */

#if defined( __MVS__ ) || defined( _MPRAS )
  #undef THREAD_INITIALISER
  #define THREAD_INITIALISER	{ 0 }
#endif /* Non-scalar pthread_t's */

/* UnixWare/SCO uses a default thread stack size so tiny that almost nothing
   can run with it, so we have to use a custom thread-creation function that
   sets the stack size to something reasonable */

#ifdef __SCO_VERSION__
  #undef THREAD_CREATE
  #define THREAD_CREATE( function, arg, handle ) \
		  createThread( function, arg, &handle )

  int createThread( void *( *function )( void * ), void *arg, pthread_t *handle );
#endif /* UnixWare/SCO */

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so that they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability.

   In some very unusual cases (see the initialistion handling code for
   details) it's possible that an attempt might be made to lock a mutex
   before it's been initialised (this can only happen due to a programming
   error by the caller, unfortunately it can't always be caught reliably).
   Setting the mutex to { 0 } is, in most threading implementations,
   equivalent to initialising it normally, so we do this to catch most
   occurences of the problem.

   Due to the complexity of the locking process using pthreads' non-reentrant
   mutexes, we don't try and lock+unlock the mutex before we destroy it.
   This isn't a major issue since it's just a safety precaution, the kernel
   should have forced any remaining threads to exit by the time the shutdown
   occurs anyway */

#define DECLARE_LOCKING_VARS( name ) \
		static MUTEX name##Mutex = { 0 }; \
		static BOOLEAN name##MutexInitialised = FALSE; \
		static THREAD name##MutexOwner; \
		static int name##MutexLockcount = 0;
#define initResourceLock( name ) \
		if( !name##MutexInitialised ) \
			{ \
			MUTEX_INIT( &name##Mutex ); \
			name##MutexInitialised = TRUE; \
			}
#define deleteResourceLock( name ) \
		if( name##MutexInitialised ) \
			{ \
			MUTEX_DESTROY( &name##Mutex ); \
			name##MutexInitialised = FALSE; \
			}
#define lockResource( name ) \
		if( MUTEX_TRYLOCK( &name##Mutex ) ) \
			{ \
			if( !THREAD_SAME( name##MutexOwner, THREAD_SELF() ) ) \
				MUTEX_LOCK( &name##Mutex ); \
			else \
				name##MutexLockcount++; \
			} \
		name##MutexOwner = THREAD_SELF();
#define unlockResource( name ) \
		if( name##MutexLockcount > 0 ) \
			name##MutexLockcount--; \
		else \
			MUTEX_UNLOCK( &name##Mutex );

#elif defined( __BEOS__ )

#include <kernel/OS.h>

/* Handles to threads and system synchronisation objects */

#define THREAD_HANDLE			THREAD
#define SEMAPHORE_HANDLE		THREAD

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg )	thread_id name( void *arg )

/* Thead management functions.  The re-entrancy of BeOS semaphores is
   unclear, if they aren't re-entrant it would be necessary to emulate them
   as for Posix threads

   BeOS threads are created in the suspended state, so after we create the
   thread we have to resume it to start it running */

#define MUTEX					sem_id
#define MUTEX_INIT( mutex )		mutex = create_sem( 1, NULL )
#define MUTEX_DESTROY			delete_sem
#define MUTEX_LOCK				acquire_sem
#define MUTEX_TRYLOCK( mutex)	( acquire_sem_etc( mutex, 1, \
												   B_RELATIVE_TIMEOUT, 0 ) == B_WOULD_BLOCK )
#define MUTEX_UNLOCK			release_sem

#define THREAD					thread_id
#define THREAD_CREATE( function, arg, handle ) \
								( ( handle = \
										spawn_thread( function, NULL, \
													  B_NORMAL_PRIORITY, arg ) ) < B_NO_ERROR ? \
									CRYPT_ERROR : \
									resume_thread( handle ) )
#define THREAD_EXIT()			exit_thread( 0 )
#define THREAD_CREATE_VARS
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 ) \
								( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			find_thread( NULL )
#define THREAD_SLEEP( ms )		snooze( ms )
#define THREAD_YIELD()			snooze( estimate_max_scheduling_latency( -1 ) + 1 )
#define THREAD_WAIT( thread )	{ \
								status_t dummy; \
								\
								wait_for_thread( thread, &dummy ); \
								}
#define THREAD_CLOSE( thread )

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability.

   In some very unusual cases (see the initialistion handling code for
   details) it's possible that an attempt might be made to lock a mutex
   before it's been initialised (this can only happen due to a programming
   error by the caller, unfortunately it can't always be caught reliably).
   Setting the mutex to { 0 } is, in most threading implementations,
   equivalent to initialising it normally, so we do this to catch most
   occurences of the problem */

#define DECLARE_LOCKING_VARS( name ) \
		static MUTEX name##Mutex = { 0 }; \
		static BOOLEAN name##MutexInitialised = FALSE; \
		static THREAD name##MutexOwner; \
		static int name##MutexLockcount = 0;
#define initResourceLock( name ) \
		if( !name##MutexInitialised ) \
			{ \
			MUTEX_INIT( name##Mutex ); \
			name##MutexInitialised = TRUE; \
			}
#define deleteResourceLock( name ) \
		if( name##MutexInitialised ) \
			{ \
			MUTEX_LOCK( name##Mutex ); \
			MUTEX_UNLOCK( name##Mutex ); \
			MUTEX_DESTROY( name##Mutex ); \
			name##MutexInitialised = FALSE; \
			}
#define lockResource( name ) \
		if( MUTEX_TRYLOCK( name##Mutex ) ) \
			{ \
			if( !THREAD_SAME( name##MutexOwner, THREAD_SELF() ) ) \
				MUTEX_LOCK( name##Mutex ); \
			else \
				name##MutexLockcount++; \
			} \
		name##MutexOwner = THREAD_SELF();
#define unlockResource( name ) \
		if( name##MutexLockcount > 0 ) \
			name##MutexLockcount--; \
		else \
			MUTEX_UNLOCK( name##Mutex );

/* Remember that we're using threaded functions */

#define USE_THREADS

#elif defined( __IBM4758__ )

#include <cpqlib.h>

/* Some variables are protected by locks.  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   can't be accessed or modified by other threads while we're using them.
   The following macros provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		static long name##Semaphore; \
		static BOOLEAN name##SemaphoreInitialised = FALSE;
#define initResourceLock( name ) \
		if( !name##SemaphoreInitialised ) \
			{ \
			CPCreateSerSem( NULL, 0, 0, &name##Semaphore ); \
			name##SemaphoreInitialised = TRUE; \
			}
#define deleteResourceLock( name ) \
		if( name##SemaphoreInitialised ) \
			{ \
			CPSemClaim( name##Semaphore, SVCWAITFOREVER ); \
			CPSemRelease( name##Semaphore ); \
			CPDelete( name##Semaphore, 0 ); \
			name##SemaphoreInitialised = FALSE; \
			}
#define lockResource( name ) \
		CPSemClaim( name##Semaphore, SVCWAITFOREVER )
#define unlockResource( name ) \
		CPSemRelease( name##Semaphore )

/* Some objects are owned by one thread (called a task in CP/Q) and can't
   be accessed by any other threads.  The following macros provide facilities
   to declare the thread ID variables and check that the current thread is
   allowed to access this object.

   Since the 4758 access control model differs somewhat from the standard one,
   this facility isn't currently used */

/* Define a thread function:  CP/Q tasks function in a somewhat peculiar
   manner, this facility isn't currently used */

#endif /* OS-specific object locking and ownership handling */

/* Generic or NOP versions of functions and types declared for those OS's
   that don't support extended functionality.  The DECLARE_xxx macros are
   expanded into dummy variable declarations to avoid problems with zero-
   size entries in cases where they're the only element in a struct or
   incomplete declarations where they're preceded by the static keyword or
   various other, similar situations.  In addition for the (global) locking
   variable names we append the actual name to prevent name space
   collisions */

#ifndef USE_THREADS
  #define DECLARE_LOCKING_VARS( name )			int dummy##name;
  #define initResourceLock( name )
  #define deleteResourceLock( name )
  #define lockResource( name )
  #define unlockResource( name )

  #define THREAD_HANDLE							int
  #define SEMAPHORE_HANDLE						int
  #define THREAD_INITIALISER					0
  #define THREAD_SELF()							0
  #define THREAD_SAME( thread1, thread2 )		TRUE
  #define THREAD_YIELD()
  #define THREAD_WAIT( thread )
  #define THREAD_CLOSE( thread )
#endif /* Resource ownership macros */

/****************************************************************************
*																			*
*							Misc.OS-specific Functions						*
*																			*
****************************************************************************/

/* WinNT and its derivatives support ACL-based access control mechanisms for
   system objects (modulo a great many holes), the following functions return
   the security info needed to restrict access to owner-only when creating an
   object */

#ifdef __WIN32__
void *initACLInfo( const int access );
void *getACLInfo( void *securityInfoPtr );
void freeACLInfo( void *securityInfoPtr );
#endif /* __WIN32__ */

#endif /* _CRYPTOS_DEFINED */
