/****************************************************************************
*																			*
*						  cryptlib Thread/Mutex Handling  					*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#ifndef _THREAD_DEFINED

#define _THREAD_DEFINED

/* In multithreaded environments we need to use mutexes to protect the
   information inside cryptlib data structures from access by other threads
   while we use it.  In most cases (mutexes not taken) mutexes are extremely
   quick, being implemented using compare-and-swap on x86 or load/store
   conditional on most RISC CPUs.

   The types and macros that are needed to handle mutexes are:

	MUTEX_HANDLE			-- Handle for mutexes/semaphores

	MUTEX_DECLARE_STORAGE	-- Declare storage for mutex
	MUTEX_CREATE			-- Initialise mutex
	MUTEX_DESTROY			-- Delete mutex
	MUTEX_LOCK				-- Acquire mutex
	MUTEX_UNLOCK			-- Release mutex

   Before deleting a mutex we lock and unlock it again to ensure that if
   some other thread is holding it they'll release it before we delete it.

   Many systems don't provide re-entrant semaphores/mutexes.  To handle this
   we implement our own re-entrant mutexes on top of the OS ones.  Using
   the Posix terminology, what we do is use mutex_trylock(), which doesn't
   re-lock the mutex if it's already locked, and as a side-benefit can be up
   to twice as fast as mutex_lock(), depending on the OS.  This works as
   follows:

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

   The types and macros that need to be declared to handle threading are:

	THREAD_HANDLE			-- Handle for threads

	THREADFUNC_DEFINE		-- Define thread function

	THREAD_CREATE			-- Create thread
	THREAD_EXIT				-- Exit from thread
	THREAD_INITIALISER		-- Value to initialise thread handle
	THREAD_SELF				-- Get handle of current thread
	THREAD_SAME				-- Compare two thread handles
	THREAD_SLEEP			-- Sleep for n milliseconds
	THREAD_YIELD			-- Yield thread's timeslice
	THREAD_WAIT				-- Wait for thread to terminate
	THREAD_CLOSE			-- Clean up thread after THREAD_WAIT

   Some systems allow a thread/task handle to be used as a synchronisation
   object while others require a separate semaphore object for
   synchronisation.  To handle this we create a synchronisation semaphore in
   the non-signalled state when we create a thread/task, signal it when the
   task exits, and wait on it in the calling thread/task:

	Parent:									Child:

	syncSem = createSem( 1 );
	thread = createThread( syncSem );
											signal( syncSem );
											exit();
	wait( syncSem );
	destroySem( syncSem );

   If the thread/task handle can be used as a synchronisation object, these
   additional operations are turned into no-ops */

/****************************************************************************
*																			*
*									AMX										*
*																			*
****************************************************************************/

#if defined( __AMX__ )

/* AMX is extremely difficult to work with because the kernel performs 
   little memory (or, in general, resource) management of its own, assuming 
   that all memory will be allocated by the caller.  This means that the 
   caller has to manually allocate state data for threads rather than having 
   the OS do it for them.  This significantly complicates things like thread 
   handling because the thread that creates a worker thread has to be around 
   later on to clean up after it when it terminates, and the state data has 
   to be maintained in external (non-thread) storage.  We handle this in one 
   of two ways, either by not using cryptlib-internal threads (they're only 
   used for initialisation and keygen, neither of which will benefit much 
   from the ability to run them in the background in an embedded system), or 
   by wrapping the AMX functions in our own ones which allocate memory as 
   required and access the information via a scalar handle.

   To use resource-management wrappers for the AMX thread functions,
   undefine the following */

/* #define AMX_THREAD_WRAPPERS */

#include <cjzzz.h>

/* Object handles */

#define THREAD_HANDLE			CJ_ID
#define MUTEX_HANDLE			CJ_ID

/* Mutex management functions.  AMX resource semaphores are re-entrant so we 
   don't have to jump through the hoops that are necessary with most other 
   OSes */

#define MUTEX_DECLARE_STORAGE( name ) \
		CJ_ID name##Mutex; \
		BOOLEAN name##MutexInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			cjrmcreate( &krnlData->name##Mutex, NULL ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			cjrmrsv( krnlData->name##Mutex, threadPriority(), 0 ); \
			cjrmrls( krnlData->name##Mutex ); \
			cjrmdelete( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		cjrmrsv( krnlData->name##Mutex, x, 0 )
#define MUTEX_UNLOCK( name ) \
		cjrmrls( krnlData->name##Mutex )

/* Thread management functions.  AMX threads require that the user allocate
   the stack space for them, unlike virtually every other embedded OS, which
   make this at most a rarely-used option.  To handle this, we use our own
   wrappers which hide this mess.  A second problem with AMX threads is that
   there's no obvious way to pass an argument to a thread.  In theory we 
   could convey the information by sending it via a mailbox, but this 
   requires first conveying the mailbox ID to the new task, which has the 
   same problem.

   We create the thread with the same priority as the calling thread, AMX 
   threads are created in the suspended state so after we create the thread 
   we have to trigger it to start it running.

   The 4096 byte storage area provides enough space for the task control
   block and about half a dozen levels of function nesting (if no large on-
   stack arrays are used), this should be enough for background init but 
   probably won't be sufficient for the infinitely-recursive OpenSSL bignum 
   code, so the value may need to be adjusted if background keygen is being 
   used */

#define THREADFUNC_DEFINE( name, arg )	void name( cyg_addrword_t arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			BYTE *threadData = malloc( 4096 ); \
			\
			cjsmcreate( &syncHandle, NULL, CJ_SMBINARY ); \
			if( cjtkcreate( &threadHandle, NULL, function, threadData, \
							4096, 0, threadPriority(), 0 ) != CJ_EROK ) \
				{ \
				free( threadData ); \
				status = CRYPT_ERROR; \
				} \
			else \
				{ \
				cjtktrigger( threadHandle ); \
				status = CRYPT_OK; \
				} \
			}
#define THREAD_EXIT( sync )		cjsmsignal( sync ); \
								return
#define THREAD_INITIALISER		CJ_IDNULL
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			cjtkid()
#define THREAD_SLEEP( ms )		cjtkdelay( cjtmconvert( ms ) )
#define THREAD_YIELD()			cjtkdelay( 1 )
#define THREAD_WAIT( sync )		cjsmwait( sync, threadPriority(), 0 ); \
								cjsmdelete( sync )
#define THREAD_CLOSE( sync )

/* Because of the problems with resource management of AMX tasks and
   related metadata, we no-op them out unless we're using wrappers by
   ensuring that any attempt to spawn a thread inside cryptlib fails,
   falling back to the non-threaded alternative.  Note that cryptlib itself
   is still thread-safe, it just can't do its init or keygen in an internal
   background thread */

#ifndef AMX_THREAD_WRAPPERS
  #undef THREAD_CREATE
  #undef THREAD_EXIT
  #undef THREAD_CLOSE
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
								status = CRYPT_ERROR
  #define THREAD_EXIT( sync )
  #define THREAD_CLOSE( sync )
#endif /* !AMX_THREAD_WRAPPERS */

/* The AMX task-priority function returns the priority via a reference
   parameter.  Because of this we have to provide a wrapper that returns 
   it as a return value */

int threadPriority( void );

/****************************************************************************
*																			*
*									BeOS									*
*																			*
****************************************************************************/

#elif defined( __BEOS__ )

#include <kernel/OS.h>

/* Object handles */

#define THREAD_HANDLE			thread_id
#define MUTEX_HANDLE			thread_id

/* Mutex management functions */

#define MUTEX_DECLARE_STORAGE( name ) \
		sem_id name##Mutex; \
		BOOLEAN name##MutexInitialised; \
		thread_id name##MutexOwner; \
		int name##MutexLockcount
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			krnlData->name##Mutex = create_sem( 1, NULL ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			acquire_sem( krnlData->name##Mutex ); \
			release_sem( krnlData->name##Mutex ); \
			delete_sem( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		if( acquire_sem_etc( krnlData->name##Mutex, 1, \
							 B_RELATIVE_TIMEOUT, 0 ) == B_WOULD_BLOCK ) \
			{ \
			if( !THREAD_SAME( krnlData->name##MutexOwner, THREAD_SELF() ) ) \
				acquire_sem( krnlData->name##Mutex ); \
			else \
				krnlData->name##MutexLockcount++; \
			} \
		krnlData->name##MutexOwner = THREAD_SELF();
#define MUTEX_UNLOCK( name ) \
		if( krnlData->name##MutexLockcount > 0 ) \
			krnlData->name##MutexLockcount--; \
		else \
			release_sem( krnlData->name##Mutex );

/* Thread management functions.  BeOS threads are created in the suspended
   state, so after we create the thread we have to resume it to start it
   running */

#define THREADFUNC_DEFINE( name, arg )	thread_id name( void *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			threadHandle = syncHandle = \
				spawn_thread( ( function ), NULL, B_NORMAL_PRIORITY, \
							  ( arg ) ); \
			if( threadHandle < B_NO_ERROR ) \
				status = CRYPT_ERROR; \
			else \
				resume_thread( threadHandle ); \
			}
#define THREAD_EXIT( sync )		exit_thread( 0 )
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			find_thread( NULL )
#define THREAD_SLEEP( ms )		snooze( ms )
#define THREAD_YIELD()			snooze( estimate_max_scheduling_latency( -1 ) + 1 )
#define THREAD_WAIT( sync )		{ \
								status_t dummy; \
								\
								wait_for_thread( sync, &dummy ); \
								}
#define THREAD_CLOSE( sync )

/****************************************************************************
*																			*
*									eCOS									*
*																			*
****************************************************************************/

#elif defined( __ECOS__ )

/* eCOS is extremely difficult to work with because the kernel performs no
   memory (or, in general, resource) management of its own, assuming that
   all memory will be allocated by the caller.  This means that every
   variable that's normally a simple scalar value in other OSes is a
   composite non-scalar type in eCOS.  As an extension of this, the caller
   has to manually allocate state data for threads, mutexes, and semaphores,
   rather than having the OS do it for them.  This significantly complicates
   things like thread handling because the thread that creates a worker
   thread has to be around later on to clean up after it when it terminates,
   and the state data has to be maintained in external (non-thread) storage.
   We handle this in one of two ways, either by not using cryptlib-internal
   threads (they're only used for initialisation and keygen, neither of
   which will benefit much from the ability to run them in the background in
   an embedded system), or by wrapping the eCOS functions in our own ones
   which allocate memory as required and access the information via a scalar
   handle.

   To use resource-management wrappers for the eCOS thread functions,
   undefine the following */

/* #define ECOS_THREAD_WRAPPERS */

#include <cyg/hal/hal_arch.h>
#include <cyg/kernel/kapi.h>

/* Object handles */

#define THREAD_HANDLE			cyg_handle_t
#define MUTEX_HANDLE			cyg_sem_t

/* Mutex management functions */

#define MUTEX_DECLARE_STORAGE( name ) \
		cyg_mutex_t name##Mutex; \
		BOOLEAN name##MutexInitialised; \
		cyg_handle_t name##MutexOwner; \
		int name##MutexLockcount
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			cyg_mutex_init( &krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			cyg_mutex_lock( &krnlData->name##Mutex ); \
			cyg_mutex_unlock( &krnlData->name##Mutex ); \
			cyg_mutex_destroy( &krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		if( cyg_mutex_trylock( &krnlData->name##Mutex ) ) \
			{ \
			if( !THREAD_SAME( krnlData->name##MutexOwner, THREAD_SELF() ) ) \
				cyg_mutex_lock( &krnlData->name##Mutex ); \
			else \
				krnlData->name##MutexLockcount++; \
			} \
		krnlData->name##MutexOwner = THREAD_SELF();
#define MUTEX_UNLOCK( name ) \
		if( krnlData->name##MutexLockcount > 0 ) \
			krnlData->name##MutexLockcount--; \
		else \
			cyg_mutex_unlock( &krnlData->name##Mutex );

/* Thread management functions.  eCOS threads require that the user allocate
   the stack space for them, unlike virtually every other embedded OS, which
   make this at most a rarely-used option.  To handle this, we use our own
   wrappers, which hide this mess and provide access via a single scalar
   variable.  For synchronisation we use semaphores, eCOS also provides
   condition variables for this purpose but they require a user-managed
   mutex to synchronise access to them, making them (at best) a primitive
   DIY semaphore.

   We create the thread with the same priority as the calling thread, note
   that this precludes the use of the bitmap scheduler (but not the lottery
   scheduler).  There doesn't seem to be any way to tell whether a thread
   has been successfully created/started or not (!!), the best that we can
   do is assume that if the thread handle is zero or negative then there's
   been a problem.  eCOS threads are created in the suspended state, so
   after we create the thread we have to resume it to start it running.

   The CYGNUM_HAL_STACK_SIZE_TYPICAL provides enough stack space for about
   half a dozen levels of function nesting (if no large on-stack arrays are
   used), this should be enough for background init but probably won't be
   sufficient for the infinitely-recursive OpenSSL bignum code, so the value
   may need to be adjusted if background keygen is being used.

   Thread sleep times are measured in implementation-specific ticks rather
   than ms, but the default is 100Hz so we divide by 10 to convert ms to
   ticks */

#define THREADFUNC_DEFINE( name, arg )	void name( cyg_addrword_t arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			BYTE *threadData = malloc( sizeof( cyg_thread ) + \
									   CYGNUM_HAL_STACK_SIZE_TYPICAL ); \
			\
			cyg_semaphore_init( &syncHandle, 0 ); \
			cyg_thread_create( cyg_thread_get_priority( cyg_thread_self() ), \
							   function, ( cyg_addrword_t ) arg, NULL, \
							   threadData + sizeof( cyg_thread ), \
							   CYGNUM_HAL_STACK_SIZE_TYPICAL, \
							   &threadHandle, ( cyg_thread * ) threadData ); \
			if( threadHandle <= 0 ) \
				{ \
				free( threadData ); \
				status = CRYPT_ERROR; \
				} \
			else \
				{ \
				cyg_thread_resume( threadHandle ); \
				status = CRYPT_OK; \
				} \
			}
#define THREAD_EXIT( sync )		cyg_semaphore_post( &sync ); \
								cyg_thread_exit()
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			cyg_thread_self()
#define THREAD_SLEEP( ms )		cyg_thread_delay( ( ms ) / 10 )
#define THREAD_YIELD()			cyg_thread_yield()
#define THREAD_WAIT( sync )		cyg_semaphore_wait( &sync ); \
								cyg_semaphore_destroy( &sync )
#define THREAD_CLOSE( sync )	cyg_thread_delete( &sync )

/* Because of the problems with resource management of eCOS threads and
   related metadata, we no-op them out unless we're using wrappers by
   ensuring that any attempt to spawn a thread inside cryptlib fails,
   falling back to the non-threaded alternative.  Note that cryptlib itself
   is still thread-safe, it just can't do its init or keygen in an internal
   background thread */

#ifndef ECOS_THREAD_WRAPPERS
  #undef THREAD_CREATE
  #undef THREAD_EXIT
  #undef THREAD_CLOSE
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
								status = CRYPT_ERROR
  #define THREAD_EXIT( sync )
  #define THREAD_CLOSE( sync )
#endif /* !ECOS_THREAD_WRAPPERS */

/****************************************************************************
*																			*
*									IBM 4758								*
*																			*
****************************************************************************/

#elif defined( __IBM4758__ )

#include <cpqlib.h>

/* Object handles */

#define THREAD_HANDLE			long
#define MUTEX_HANDLE			long

/* Mutex management functions */

#define MUTEX_DECLARE_STORAGE( name ) \
		long name##Semaphore; \
		BOOLEAN name##SemaphoreInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##SemaphoreInitialised ) \
			{ \
			CPCreateSerSem( NULL, 0, 0, &krnlData->name##Semaphore ); \
			krnlData->name##SemaphoreInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##SemaphoreInitialised ) \
			{ \
			CPSemClaim( krnlData->name##Semaphore, SVCWAITFOREVER ); \
			CPSemRelease( krnlData->name##Semaphore ); \
			CPDelete( krnlData->name##Semaphore, 0 ); \
			krnlData->name##SemaphoreInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		CPSemClaim( krnlData->name##Semaphore, SVCWAITFOREVER )
#define MUTEX_UNLOCK( name ) \
		CPSemRelease( krnlData->name##Semaphore )

/* Thread management functions.  CP/Q doesn't use threads but only supports
   CP/Q tasks.  These function in a somewhat peculiar manner, so this
   facility isn't currently used */

/****************************************************************************
*																			*
*									uITRON									*
*																			*
****************************************************************************/

#elif defined( __ITRON__ )

/* In the following includes, kernel.h is the uITRON kernel.h, not the
   cryptlib one */

#include <itron.h>
#include <kernel.h>

/* Object handles */

#define THREAD_HANDLE			ID
#define MUTEX_HANDLE			ID

/* Mutex management functions.  We could use either semaphores or mutexes
   for this, semaphores are supported under uITRON 3.0 but since we're
   using automatic assignment of handles (which requires uITRON 4.0) we may
   as well use mutexes */

#define MUTEX_DECLARE_STORAGE( name ) \
		ID name##Mutex; \
		BOOLEAN name##MutexInitialised; \
		ID name##MutexOwner; \
		int name##MutexLockcount
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			static const T_CMTX pk_cmtx = { 0, 0 }; \
			\
			krnlData->name##Mutex = acre_mtx( ( T_CMTX  * ) &pk_cmtx ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			loc_mtx( krnlData->name##Mutex ); \
			unl_mtx( krnlData->name##Mutex ); \
			del_mtx( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		if( ploc_mtx( krnlData->name##Mutex ) == E_ILUSE ) \
			{ \
			if( !THREAD_SAME( krnlData->name##MutexOwner, THREAD_SELF() ) ) \
				loc_mtx( krnlData->name##Mutex ); \
			else \
				krnlData->name##MutexLockcount++; \
			} \
		krnlData->name##MutexOwner = threadSelf();
#define MUTEX_UNLOCK( name ) \
		if( krnlData->name##MutexLockcount > 0 ) \
			krnlData->name##MutexLockcount--; \
		else \
			unl_mtx( krnlData->name##Mutex );

/* Thread management functions.  The attributes for task creation are:

	TA_HLNG | TA_ACT	-- C interface, create task in the active rather
						   than suspended state (otherwise we'd have to use
						   act_tsk() to activate it a la BeOS).
	arg					-- Task extended info.
	function			-- Task function.
	TPRI_SELF			-- Same priority as invoking task.
	16384				-- Stack size.
	NULL				-- Auto-allocate stack.  This is given as 0 rather
						   than NULL since some uITRON headers define their
						   own NULL as 0, leading to compiler warnings.

   uITRON status values are 8:8 bit pairs with the actual status in the
   low 8 bits.  The sub-values can be extracted with the MERCD() and SERCD()
   (main- and sub-error-code) macros, however simply using the MERCD()
   result isn't safe because it could be the (negative) low 8 bits of a
   (positive overall) return value.  When creating a task we therefore
   consider a status < E_OK as being an error, without trying to pick apart
   the overall value.

   The handling of initialisers is a bit dodgy since TSK_NONE == TSK_SELF
   (== 0) and it isn't even safe to use negative values since in some cases
   these can be valid system task handles.  In general however uITRON
   numbers IDs from 1...n, so using 0 as a non-value is safe.

   Handling of task sleep is also somewhat dodgy, time is measured in clock
   ticks of an implementation-specific duration, the best that we can do is
   to assume that it's close enough to ms.

   In theory we don't really need to use exd_tsk() since returning from a
   task ends it, but we make it explicit to be neat */

#define THREADFUNC_DEFINE( name, arg )	void name( VP_INT *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			static const T_CSEM pk_csem = { TA_TFIFO, 1, 64 }; \
			T_CTSK pk_ctsk = { TA_HLNG | TA_ACT, ( arg ), ( function ), \
							   TPRI_SELF, 16384, 0 }; \
			\
			syncHandle = acre_sem( ( T_CSEM  * ) &pk_csem ); \
			threadHandle = acre_tsk( &pk_ctsk ); \
			if( threadHandle < E_OK ) \
				{ \
				del_sem( syncHandle ); \
				status = CRYPT_ERROR; \
				} \
			else \
				status = CRYPT_OK; \
			}
#define THREAD_EXIT( sync )		sig_sem( sync ); \
								exd_tsk()
#define THREAD_INITIALISER		TSK_NONE
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			threadSelf()
#define THREAD_SLEEP( ms )		dly_tsk( ms )
#define THREAD_YIELD()			dly_tsk( 0 )
#define THREAD_WAIT( sync )		wai_sem( sync ); \
								del_sem( sync )
#define THREAD_CLOSE( sync )

/* The uITRON thread-self function returns the thread ID via a reference
   parameter since uITRON IDs can be negative and there'd be no way to
   differentiate a thread ID from an error code.  Because of this we have
   to provide a wrapper that returns it as a return value */

ID threadSelf( void );

/****************************************************************************
*																			*
*									OS/2									*
*																			*
****************************************************************************/

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

/* Object handles */

#define THREAD_HANDLE			TID
#define MUTEX_HANDLE			HEV

/* Mutex management functions */

#define MUTEX_DECLARE_STORAGE( name ) \
		HMTX name##Mutex; \
		BOOLEAN name##MutexInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			DosCreateMutexSem( NULL, &krnlData->name##Mutex, 0L, FALSE ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			DosRequestMutexSem( krnlData->name##Mutex, ( ULONG ) SEM_INDEFINITE_WAIT ); \
			DosReleaseMutexSem( krnlData->name##Mutex ); \
			DosCloseMutexSem( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		DosRequestMutexSem( krnlData->name##Mutex, ( ULONG ) SEM_INDEFINITE_WAIT )
#define MUTEX_UNLOCK( name ) \
		DosReleaseMutexSem( krnlData->name##Mutex )

/* Thread management functions */

#define THREADFUNC_DEFINE( name, arg )	void _Optlink name( void *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			threadHandle = syncHandle = \
				_beginthread( ( function ), NULL, 8192, ( arg ) ); \
			status = ( threadHandle == -1 ) ? CRYPT_ERROR : CRYPT_OK ); \
			}
#define THREAD_EXIT( sync )		_endthread()
#define THREAD_INITIALISER		0
#define THREAD_SELF()			DosGetThreadID()
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SLEEP( ms )		DosWait( ms )
#define THREAD_YIELD()			DosWait( 0 )
#define THREAD_WAIT( sync )		DosWaitThread( sync, INFINITE )
#define THREAD_CLOSE( sync )

/****************************************************************************
*																			*
*									PalmOS									*
*																			*
****************************************************************************/

#elif defined( __PALMOS__ )

#include <CmnErrors.h>
#include <SysThread.h>

/* Object handles */

#define THREAD_HANDLE			SysHandle
#define MUTEX_HANDLE			SysHandle

/* Mutex management functions.  These are just initialised in a slightly
   odd manner, there isn't any function to explicitly initialise them but
   instead they're statically initialised to a fixed value (NULL), when
   the lock/unlock functions are passed this value they perform the
   initialisation on-demand.  This means that if the underlying hardware
   supports it they can be implemented using atomic operations directly
   on the critical-section value without having to allocate memory for
   a struct to contain the critical-section data */

#define MUTEX_DECLARE_STORAGE( name ) \
		SysCriticalSectionType name##Mutex; \
		BOOLEAN name##MutexInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			krnlData->name##Mutex = sysCriticalSectionInitializer; \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			SysCriticalSectionEnter( &krnlData->name##Mutex ); \
			SysCriticalSectionExit( &krnlData->name##Mutex ); \
			krnlData->name##Mutex = sysCriticalSectionInitializer; \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		SysCriticalSectionEnter( &krnlData->name##Mutex )
#define MUTEX_UNLOCK( name ) \
		SysCriticalSectionExit( &krnlData->name##Mutex )

/* Thread management functions.  PalmOS threads are created in the suspended
   state, so after we create the thread we have to explicitly start it to
   get it running.  The default stack size (via SysThreadCreateEZ()) is a
   pathetic 4K for standard threads or 8K for UI threads, to avoid this we
   have to use the full SysThreadCreate() and specify our own stack size */

#define THREADFUNC_DEFINE( name, arg )	void name( void *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			SysSemaphoreCreateEZ( 0, ( SysHandle * ) &syncHandle ); \
			if( SysThreadCreate( sysThreadNoGroup, "", \
								 sysThreadPriorityNormal, 32768, function, \
								 arg, &threadHandle ) != errNone ) \
				{ \
				SysSemaphoreDestroy( syncHandle ); \
				status = CRYPT_ERROR; \
				} \
			else \
				{ \
				SysThreadStart( threadHandle ); \
				status = CRYPT_OK; \
				} \
			}
#define THREAD_EXIT( sync )		SysSemaphoreSignal( sync ); \
								SysThreadExit()
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			SysCurrentThread()
#define THREAD_SLEEP( ms )		SysThreadDelay( ( ms ) * 1000000L, P_ABSOLUTE_TIMEOUT )
#define THREAD_YIELD()			SysThreadDelay( 0, P_POLL )
#define THREAD_WAIT( sync )		SysSemaphoreWait( sync, P_WAIT_FOREVER, 0 ); \
								SysSemaphoreDestroy( sync )
#define THREAD_CLOSE( sync )

/****************************************************************************
*																			*
*									RTEMS									*
*																			*
****************************************************************************/

#elif defined( __RTEMS__ )

#include <rtems.h>

/* Object handles.  These are actually multi-component object IDs, but they
   act like standard handles */

#define THREAD_HANDLE			rtems_id
#define MUTEX_HANDLE			rtems_id

/* Mutex management functions.  RTEMS semaphores (or at least standard
   counting semaphores, which is what we're using here) are re-entrant so
   we don't have to jump through the hoops that are necessary with most
   other OSes.

   We specify the priority ceiling as zero since it's not used for the
   semaphore type that we're creating */

#define MUTEX_DECLARE_STORAGE( name ) \
		rtems_id name##Mutex; \
		BOOLEAN name##MutexInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			rtems_semaphore_create( NULL, 1, RTEMS_DEFAULT_ATTRIBUTES, 0, \
									&krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			rtems_semaphore_obtain( krnlData->name##Mutex, RTEMS_WAIT, 0 ); \
			rtems_semaphore_release( krnlData->name##Mutex ); \
			rtems_semaphore_delete( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		rtems_semaphore_obtain( krnlData->name##Mutex, RTEMS_WAIT, 0 );
#define MUTEX_UNLOCK( name ) \
		rtems_semaphore_release( krnlData->name##Mutex );

/* Thread management functions.  RTEMS tasks are created in the suspended
   state, so after we create the task we have to resume it to start it
   running.  The attributes for task creation are:

	NULL					-- Task name.
	RTEMS_CURRENT_PRIORITY	-- Task priority.  The documentation is unclear
							   as to whether we can specify this directly as
							   the priority or have to obtain it via a call,
							   we use the call to be safe.
	RTEMS_STACK_SIZE		-- Task stack size.  We use the default size for
							   RTEMS tasks.
	RTEMS_ASR | \			-- Task mode: Enable async signal processing
		RTEMS_INT_LEVEL(0) | \ (default), all interrupts enabled (default),
		RTEMS_PREEMPT | \	   preemptive scheduling (default), timeslicing
		RTEMS_TIMESLICE		   for tasks of the same priority.
	RTEMS_DEFAULT_ATTRIBUTES-- Task attributes: Local task, no FP regs.

   Specifying the default values for the task mode is optional, but we do it
   anyway to make the behaviour explicit.

   We could make the synchronisation semaphore a binary semaphore, but
   there's no indication that this is any more efficient than a counting
   semaphore, and it saves having to create a long list of (non-default)
   attributes to specify this.

   Task sleep times are measured in implementation-specific ticks rather
   than ms, but the default is 10ms so we divide by 10.  If necessary the
   absolute value can be calculated from the microseconds_per_tick field in
   the RTEMS configuration table or from CONFIGURE_MICROSECONDS_PER_TICK in
   confdefs.h */

#define TASK_MODE	( RTEMS_ASR | RTEMS_INTERRUPT_LEVEL(0) | \
					  RTEMS_PREEMPT | RTEMS_TIMESLICE )

#define THREADFUNC_DEFINE( name, arg )	rtems_task name( rtems_task_argument arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			rtems_status_code rtemsStatus; \
			rtems_task_priority rtemsPriority; \
			\
			rtems_task_set_priority( RTEMS_SELF, RTEMS_CURRENT_PRIORITY, \
									 &rtemsPriority ); \
			rtems_semaphore_create( NULL, rtemsPriority, \
									RTEMS_DEFAULT_ATTRIBUTES, 0, \
									&syncHandle ); \
			rtemsStatus = rtems_task_create( NULL, 16, RTEMS_STACK_SIZE, \
											 TASK_MODE, \
											 RTEMS_DEFAULT_ATTRIBUTES, \
											 &threadHandle ); \
			if( rtemsStatus == RTEMS_SUCCESSFUL ) \
				rtemsStatus = rtems_task_start( threadHandle, function, arg ); \
			if( rtemsStatus == RTEMS_SUCCESSFUL ) \
				status = CRYPT_OK; \
			else \
				{ \
				rtems_semaphore_delete( syncHandle ); \
				status = CRYPT_ERROR; \
				} \
			}
#define THREAD_EXIT( sync )		rtems_semaphore_release( sync ); \
								rtems_task_delete( RTEMS_SELF );
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			threadSelf()
#define THREAD_SLEEP( ms )		rtems_task_wake_after( ( ms ) / 10 )
#define THREAD_YIELD()			rtems_task_wake_after( RTEMS_YIELD_PROCESSOR )
#define THREAD_WAIT( sync )		rtems_semaphore_obtain( sync, RTEMS_WAIT, 0 ); \
								rtems_semaphore_release( sync ); \
								rtems_semaphore_delete( sync )
#define THREAD_CLOSE( sync )

/* The RTEMS thread-self function returns the task ID via a reference
   parameter, because of this we have to provide a wrapper that returns it
   as a return value */

rtems_id threadSelf( void );

/****************************************************************************
*																			*
*								Unix/MVS/XMK								*
*																			*
****************************************************************************/

#elif ( defined( __UNIX__ ) || defined( __XMK__ ) ) && defined( USE_THREADS )

/* Under OSF/1 pthread.h includes c_asm.h which contains a declaration

	long asm( const char *,...);

   that conflicts with the gcc asm keyword.  This asm stuff is only used
   when inline asm alternatives to the Posix threading functions are enabled,
   which isn't done by default so in theory we could also fix this by
   defining asm to something else before including pthread.h, but it's safer
   to just disable inclusion of c_asm.h by pre-defining the guard define.
   This will result in a more useful warning if for some reason inline
   threading functions with asm are enabled */

#if defined( __osf__ ) || defined( __alpha__ )
  #define __C_ASM_H
#endif /* Alpha */

#include <pthread.h>
#include <sys/time.h>
#ifdef __XMK__
  #include <sys/process.h>
  #include <sys/timer.h>
#endif /* Xilinx XMK */

/* Object handles */

#define THREAD_HANDLE			pthread_t
#define MUTEX_HANDLE			pthread_t

/* Mutex management functions.  Most Unix mutex implementations are non-
   re-entrant, which means that re-locking a mutex leads to deadlock
   (charming).  Some implementations can fix this by setting a mutex
   attribute to ensure that it doesn't deadlock using:

	pthread_mutexattr_settype( attr, PTHREAD_MUTEX_RECURSIVE );

   or:

	pthread_mutex_setrecursive();

   but this isn't universal.  To fix the problem, we implement our own
   re-entrant mutexes on top of the Posix ones.

   Due to the complexity of the locking process using pthreads' (usually)
   non-reentrant mutexes, we don't try and lock+unlock the mutex before we
   destroy it.  This isn't a major issue since it's just a safety precaution,
   the kernel should have forced any remaining threads to exit by the time
   the shutdown occurs anyway */

#define MUTEX_DECLARE_STORAGE( name ) \
		pthread_mutex_t name##Mutex; \
		BOOLEAN name##MutexInitialised; \
		pthread_t name##MutexOwner; \
		int name##MutexLockcount
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			pthread_mutex_init( &krnlData->name##Mutex, NULL ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			pthread_mutex_destroy( &krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		if( pthread_mutex_trylock( &krnlData->name##Mutex ) ) \
			{ \
			if( !THREAD_SAME( krnlData->name##MutexOwner, THREAD_SELF() ) ) \
				pthread_mutex_lock( &krnlData->name##Mutex ); \
			else \
				krnlData->name##MutexLockcount++; \
			} \
		krnlData->name##MutexOwner = THREAD_SELF();
#define MUTEX_UNLOCK( name ) \
		if( krnlData->name##MutexLockcount > 0 ) \
			krnlData->name##MutexLockcount--; \
		else \
			pthread_mutex_unlock( &krnlData->name##Mutex );

/* Putting a thread to sleep for a number of milliseconds can be done with
   select() because it should be a thread-safe one in the presence of
   pthreads.  In addition there are some system-specific quirks, these are
   handled by re-defining the macros below in a system-specific manner
   further on.

   Yielding a thread's timeslice gets rather complex due to a confusion of
   non-portable "portable" Posix functions.  Initially there was
   pthread_yield() from draft 4 of the Posix thread standard in 1990,
   popularised in the DCE threading code and picked up by a number of other
   implementations.  At about that time the realtime (1003.1b) and thread
   (1003.1c) standardisation was proceeding independently, with neither side
   knowing which one would make it to standards status first.  As it turned
   out this was 1003.1b with sched_yield().  When the 1003.1c folks were
   looking for every place where the text said "process" but should say
   "thread" once 1003.1c was in effect, they noticed that sched_yield() and
   pthread_yield() were now identical.  Since sched_yield() was already in
   the standard, there was no need for pthread_yield() so it was removed.
   However, some older implementations still do pthread_yield() and some
   (also older) implementations use sched_yield() to yield the processes'
   timeslice rather than the thread's timeslice, further complicated by the
   fact that some implementations like PHUX 10.x/11.x have buggy manpages
   that claim sched_yield() is per-process when in fact it's per-thread
   (PHUX 10.x still had pthread_yield() while 11.x only has sched_yield()).
   The whole is further confused by the fact that in some implementations,
   threads are processes (sort of, e.g. Linux's clone()'d threads and Sun
   LWPs).  In addition Sun have their own thr_yield which is part of their
   UI threads interface and that you have to fall back to occasionally.

   Because of this mess, we try for pthread_yield() if possible (since that
   definitely yields the thread's timeslice), fall back to sched_yield() if
   necessary, and add a special workaround for Sun systems.

   "Posix is portable in the sense that you can use a forklift to move the
    printed volumes around" */

#define THREADFUNC_DEFINE( name, arg )	void *name( void *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			status = pthread_create( &threadHandle, NULL, function, arg ) ? \
					 CRYPT_ERROR : CRYPT_OK; \
			syncHandle = ( long ) threadHandle; \
			}
#define THREAD_EXIT( sync )		pthread_exit( ( void * ) 0 )
#define THREAD_INITIALISER		0
#define THREAD_SELF()			pthread_self()
#define THREAD_SAME( thread1, thread2 )	pthread_equal( ( thread1 ), ( thread2 ) )
#if defined( __osf__ ) || defined( __alpha__ ) || defined( __APPLE__ )
  #define THREAD_YIELD()		pthread_yield_np()
#elif defined( __MVS__ )
  #define THREAD_YIELD()		pthread_yield( NULL )
#elif defined( sun )
  /* Slowaris gets a bit complex, SunOS 4.x always returns -1 and sets errno
     to ENOSYS when sched_yield() is called, so we use this to fall back to
	 the UI interface if necessary */
  #define THREAD_YIELD()		{ if( sched_yield() ) thr_yield(); }
#elif defined( _AIX ) || ( defined( __hpux ) && ( OSVERSION >= 11 ) ) || \
	  defined( __NetBSD__ ) || defined( __QNX__ )
  #define THREAD_YIELD()		sched_yield()
#elif defined( __XMK__ )
  /* The XMK underlying scheduling object is the process context, for which 
     the user-visible interface is the thread.  Therefore yielding the
	 underlying process context should yield the associated thread */
  #define THREAD_YIELD()		yield()
#else
  #define  THREAD_YIELD()		pthread_yield()
#endif /* Not-very-portable Posix portability */
#define THREAD_SLEEP( ms )		{ \
								struct timeval tv = { 0 }; \
								\
								tv.tv_usec = ( ms ) * 1000; \
								select( 1, NULL, NULL, NULL, &tv ); \
								}
#define THREAD_WAIT( sync )		pthread_join( sync, NULL )
#define THREAD_CLOSE( sync )

/* OSF1 includes some ghastly kludgery to handle binary compatibility from
   1003.4a to 1003.1c threading functions and inline asm functions with all
   sorts of name mangling and translation of function names and types.
   Unfortunately a straight vanilla compile leaves pthread_self() un-
   prototyped, which means that it's then implicitly prototyped as returned
   an int.  This generates hundreds of warnings of int <-> pointer casting
   problems, so if pthread_self() isn't redefined into one of a dozen
   different mangled versions we prototype it ourselves here */

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
  #undef MUTEX_CREATE
  #define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			pthread_mutex_init( &krnlData->name##Mutex, \
								pthread_mutexattr_default ); \
			krnlData->name##MutexInitialised = TRUE; \
			}

  #undef THREAD_CREATE
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			status = pthread_create( &threadHandle, pthread_attr_default, \
									 function, arg ) ? \
					 CRYPT_ERROR : CRYPT_OK ); \
			syncHandle = ( long ) threadHandle; \
			}
#endif /* _MPRAS */

/* Some systems (notably MVS and MP-RAS) use non-scalar pthread_t's, so we
   have to handle initialisation of these specially */

#if defined( __MVS__ ) || defined( _MPRAS )
  #define NONSCALAR_THREADS
  #undef THREAD_INITIALISER
  #define THREAD_INITIALISER	{ 0 }
#endif /* Non-scalar pthread_t's */

/* XMK doesn't have a select(), however it has a sleep() as part of the timer
   package that performs the same function.  Note that there's a second 
   sleep() that takes an argument in seconds rather than ms and that sleeps
   the overall process in the PPC BSP library, but presumably this won't be
   used if the sleep() in the timer package is enabled */

#ifdef __XMK__
  #undef THREAD_SLEEP
  #define THREAD_SLEEP( ms )	sleep( ms )
#endif /* Xilinx XMK */

/* UnixWare/SCO creates threads with a ridiculously small default stack size
   of a few KB or so, which means that the thread can't even start.  To work
   around this we have to use a custom thread-creation function that sets
   the stack size to something reasonable */

#ifdef __SCO_VERSION__
  #undef THREAD_CREATE
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			pthread_attr_t attr; \
			\
			pthread_attr_init( &attr ); \
			pthread_attr_setstacksize( &attr, 32768 ); \
			status = pthread_create( &threadHandle, &attr, function, arg ); \
			pthread_attr_destroy( &attr ); \
			if( status ) \
				status = CRYPT_ERROR; \
			else \
				{ \
				status = CRYPT_OK; \
				syncHandle = ( long ) threadHandle; \
				} \
			}
#endif /* UnixWare/SCO */

/****************************************************************************
*																			*
*									VxWorks									*
*																			*
****************************************************************************/

#elif defined( __VXWORKS__ )

#include <vxWorks.h>
#include <semLib.h>
#include <taskLib.h>

/* Object handles */

#define THREAD_HANDLE			int
#define MUTEX_HANDLE			SEM_ID

/* Mutex management functions.  VxWorks mutual exclusion semaphores (and
   only mutex semaphores) are re-entrant, so we don't have to jump through
   the hoops that are necessary with most other OSes */

#define MUTEX_DECLARE_STORAGE( name ) \
		SEM_ID name##Mutex; \
		BOOLEAN name##MutexInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##MutexInitialised ) \
			{ \
			krnlData->name##Mutex = semMCreate( SEM_Q_FIFO ); \
			krnlData->name##MutexInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##MutexInitialised ) \
			{ \
			semTake( krnlData->name##Mutex, WAIT_FOREVER ); \
			semGive( krnlData->name##Mutex ); \
			semDelete( krnlData->name##Mutex ); \
			krnlData->name##MutexInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		semTake( krnlData->name##Mutex, WAIT_FOREVER ); \
#define MUTEX_UNLOCK( name ) \
		semGive( krnlData->name##Mutex );

/* Thread management functions.  Some PPC compilers use the FP registers for
   non-FP operations such as working with long long data types (used for
   example in PKC key generation), so if we're building for the PPC we
   create tasks with FP register saving enabled */

#ifdef __ppc__
  #define TASK_ATTRIBUTES	VX_FP_TASK
#else
  #define TASK_ATTRIBUTES	0
#endif /* PPC vs.non-PPC register saves */

/* VxWorks tasks are exited using the standard ANSI exit() function rather
   than any OS-specific exit mechanism.

   Task sleep times are measured in implementation-specific ticks rather
   than ms, but it's usually close enough to allow us to treat them as being
   identical.  If we need truly accurate timing we could call a helper
   function that scales the time based on sysClkRateGet(), but at the moment
   it's only used for general short delays rather than any fixed amount of
   time so this isn't necessary */

#define THREADFUNC_DEFINE( name, arg )	thread_id name( void *arg )
#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
			{ \
			syncHandle = semBCreate( SEM_Q_FIFO, SEM_EMPTY ); \
			threadHandle = taskSpawn( NULL, T_PRIORITY, TASK_ATTRIBUTES, 16384, \
									  function, ( int ) arg, 0, 0, 0, 0, \
									  0, 0, 0, 0, 0 ); \
			if( threadHandle == ERROR ) \
				{ \
				semDelete( syncHandle ); \
				status = CRYPT_ERROR; \
				} \
			else \
				status = CRYPT_OK; \
			}
#define THREAD_EXIT( sync )		semGive( sync ); \
								exit( 0 )
#define THREAD_INITIALISER		0
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SELF()			taskIdSelf()
#define THREAD_SLEEP( ms )		taskDelay( ms )
#define THREAD_YIELD()			taskDelay( NO_WAIT )
#define THREAD_WAIT( sync )		semTake( sync, WAIT_FOREVER ); \
								semGive( sync ); \
								semDelete( sync )
#define THREAD_CLOSE( sync )

/****************************************************************************
*																			*
*									Win32/WinCE								*
*																			*
****************************************************************************/

#elif ( defined( __WIN32__ ) && !defined( NT_DRIVER ) ) || \
	  defined( __WINCE__ )

#ifndef __WINCE__
  #include <process.h>
#endif /* __WINCE__ */

/* Object handles */

#define THREAD_HANDLE			HANDLE
#define MUTEX_HANDLE			HANDLE

/* Mutex management functions.  InitializeCriticalSection() doesn't return
   an error code but can throw a STATUS_NO_MEMORY exception in certain low-
   memory situations, however this exception isn't raised in an exception-
   safe manner (the critical section object is left in a corrupted state) so
   it can't be safely caught and recovered from.  The result is that there's
   no point in trying to catch it (this is a known design flaw in the
   function) */

#define MUTEX_DECLARE_STORAGE( name ) \
		CRITICAL_SECTION name##CriticalSection; \
		BOOLEAN name##CriticalSectionInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##CriticalSectionInitialised ) \
			{ \
			InitializeCriticalSection( &krnlData->name##CriticalSection ); \
			krnlData->name##CriticalSectionInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name ) \
		if( krnlData->name##CriticalSectionInitialised ) \
			{ \
			EnterCriticalSection( &krnlData->name##CriticalSection ); \
			LeaveCriticalSection( &krnlData->name##CriticalSection ); \
			DeleteCriticalSection( &krnlData->name##CriticalSection ); \
			krnlData->name##CriticalSectionInitialised = FALSE; \
			}
#define MUTEX_LOCK( name ) \
		EnterCriticalSection( &krnlData->name##CriticalSection )
#define MUTEX_UNLOCK( name ) \
		LeaveCriticalSection( &krnlData->name##CriticalSection )

/* Thread management functions.  Win32 requires a C library-aware wrapper
   around the OS native CreateThread()/ExitThread() calls, with WinCE
   after 2.0 the C runtime is integrated into the OS so we can call them
   directly.

   There are two functions that we can call to get the current thread ID,
   GetCurrentThread() and GetCurrentThreadId().  These are actually
   implemented as the same function (once you get past the outer wrapper),
   and the times for calling either are identical.  The only difference
   between the two is that GetCurrentThread() returns a per-process
   pseudohandle while GetCurrentThreadId() returns a systemwide, unique
   handle.

   An alternative to Sleep( 0 ) is SwitchToThread(), however this is only
   available under the NT code base for NT 4.0 and later, so it wouldn't
   work under the Win95 code base.

   After we wait for the thread, we need to close the handle.  This is
   complicated by the fact that we can only close it once all threads have
   exited the wait, which requires further calisthenics in the function that
   uses it to ensure that the last thread out closes the handle. This also
   means that we can't combine the close with the wait as for other OSes,
   since we can only perform the close once all waits have exited */

#if defined( __WIN32__ )
  #define THREADFUNC_DEFINE( name, arg ) \
				unsigned __stdcall name( void *arg )
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
				{ \
				ULONG ulDummy; \
				\
				threadHandle = ( HANDLE ) \
					_beginthreadex( NULL, 0, ( function ), ( arg ), 0, &ulDummy ); \
				syncHandle = ( long ) threadHandle; \
				status = !threadHandle ? CRYPT_ERROR : CRYPT_OK; \
				}
  #define THREAD_EXIT( sync )	_endthreadex( 0 ); return( 0 )
#elif defined( __WINCE__ )
  #define THREADFUNC_DEFINE( name, arg ) \
				DWORD WINAPI name( void *arg )
  #define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
				{ \
				ULONG ulDummy; \
				\
				threadHandle = ( HANDLE ) \
					CreateThread( NULL, 0, ( function ), ( arg ), 0, &ulDummy ); \
				syncHandle = ( long ) threadHandle; \
				status = !threadHandle ? CRYPT_ERROR : CRYPT_OK; \
				}
  #define THREAD_EXIT( sync )	ExitThread( 0 ); return( 0 )
#endif /* Win32 vs. WinCE */
#define THREAD_INITIALISER		0
#define THREAD_SELF()			( THREAD_HANDLE ) GetCurrentThreadId()
#define THREAD_SAME( thread1, thread2 )	( ( thread1 ) == ( thread2 ) )
#define THREAD_SLEEP( ms )		Sleep( ms )
#define THREAD_YIELD()			Sleep( 0 )
#define THREAD_WAIT( sync )		WaitForSingleObject( sync, INFINITE );
#define THREAD_CLOSE( sync )	CloseHandle( sync )

#elif defined( __WIN32__ ) && defined( NT_DRIVER )

/* Object handles */

#define THREAD_HANDLE				HANDLE
#define MUTEX_HANDLE				HANDLE

/* Mutex management functions */

#define MUTEX_DECLARE_STORAGE( name ) \
		KMUTEX name##CriticalSection; \
		BOOLEAN name##CriticalSectionInitialised
#define MUTEX_CREATE( name ) \
		if( !krnlData->name##CriticalSectionInitialised ) \
			{ \
			KeInitializeMutex( &krnlData->name##CriticalSection, 1 ); \
			krnlData->name##CriticalSectionInitialised = TRUE; \
			}
#define MUTEX_DESTROY( name )
#define MUTEX_LOCK( name ) \
		KeWaitForMutexObject( &krnlData->name##CriticalSection, Executive, \
							  KernelMode, FALSE, NULL )
#define MUTEX_UNLOCK( name ) \
		KeReleaseMutex( &krnlData->name##CriticalSection, FALSE )

/****************************************************************************
*																			*
*								Non-threaded OSes							*
*																			*
****************************************************************************/

#else

/* Generic or NOP versions of functions and types declared for those OSes
   that don't support threading */

#define THREAD_HANDLE							int
#define MUTEX_HANDLE							int

#define MUTEX_DECLARE_STORAGE( name )
#define MUTEX_CREATE( name )
#define MUTEX_DESTROY( name )
#define MUTEX_LOCK( name )
#define MUTEX_UNLOCK( name )

#define THREAD_CREATE( function, arg, threadHandle, syncHandle, status ) \
												status = CRYPT_ERROR
#define THREAD_EXIT( sync )
#define THREAD_INITIALISER						0
#define THREAD_SAME( thread1, thread2 )			TRUE
#define THREAD_SELF()							0
#define THREAD_SLEEP( ms )
#define THREAD_YIELD()
#define THREAD_WAIT( sync )
#define THREAD_CLOSE( sync )

#endif /* Resource ownership macros */

#endif /* _THREAD_DEFINED */
