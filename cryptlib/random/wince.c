/****************************************************************************
*																			*
*						WinCE Randomness-Gathering Code						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom number
   generator.  For usage conditions, see random.c */

/* General includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_CHILD
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* OS-specific includes */

#include <tlhelp32.h>

/* The size of the intermediate buffer used to accumulate polled data */

#define RANDOM_BUFSIZE	4096

/* When we're running a background poll, the main thread can ask it to
   terminate if cryptlib is shutting down.  The following macro checks
   whether the background thread should exit prematurely */

#define checkPollExit()	\
		{ \
		BOOLEAN exitFlag; \
		\
		krnlEnterMutex( MUTEX_RANDOMPOLLING ); \
		exitFlag = exitNow; \
		krnlExitMutex( MUTEX_RANDOMPOLLING ); \
		if( exitFlag ) \
			return; \
		}

/* A flag telling the randomness polling thread to exit.  This is set on
   shutdown to indicate that it should bail out as quickly as possible so as
   not to hold up the shutdown */

static BOOLEAN exitNow;

/* Handles to various randomness objects */

static HANDLE hToolHelp32;	/* Handle to Toolhelp.library */
static HANDLE hThread;		/* Background polling thread handle */
static DWORD threadID;		/* Background polling thread ID */

/****************************************************************************
*																			*
*									Fast Poll								*
*																			*
****************************************************************************/

/* Type definitions for function pointers to call CE native functions */

typedef BOOL ( *CEGENRANDOM )( DWORD dwLen, BYTE *pbBuffer );
typedef DWORD ( *GETSYSTEMPOWERSTATUS )( PSYSTEM_POWER_STATUS_EX2 pSystemPowerStatusEx2,
										 DWORD dwLen, BOOL fUpdate );

/* The shared Win32 fast poll routine */

void fastPoll( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	static BOOLEAN hasAdvFeatures = FALSE, hasHardwareRNG = FALSE;
	static CEGENRANDOM pCeGenRandom = NULL;
	static GETSYSTEMPOWERSTATUS pGetSystemPowerStatusEx2 = NULL;
	FILETIME  creationTime, exitTime, kernelTime, userTime;
	LARGE_INTEGER performanceCount;
	SYSTEM_POWER_STATUS_EX2 powerStatus;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];
	int bufIndex = 0, length;

	checkPollExit();

	/* Initialize the native function pointers if necessary.  CeGetRandom()
	   is only available in relatively new versions of WinCE, so we have to
	   link it dynamically */
	if( pCeGenRandom == NULL )
		{
		HANDLE hCoreDLL;

		if( ( hCoreDLL = GetModuleHandle( TEXT( "Coredll.dll" ) ) ) != NULL )
			pCeGenRandom = ( CEGENRANDOM ) GetProcAddress( hCoreDLL, TEXT( "CeGenRandom" ) );
		}
	if( pGetSystemPowerStatusEx2 == NULL )
		{
		HANDLE hGetpower;

		if( ( hGetpower = GetModuleHandle( TEXT( "Getpower.dll" ) ) ) != NULL )
			pGetSystemPowerStatusEx2 = ( GETSYSTEMPOWERSTATUS ) \
							GetProcAddress( hGetpower, TEXT( "GetSystemPowerStatusEx2" ) );
		}

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );

	/* Get various basic pieces of system information: Handle of active
	   window, handle of window with mouse capture, handle of clipboard owner
	   handle of start of clpboard viewer list, pseudohandle of current
	   process, current process ID, pseudohandle of current thread, current
	   thread ID, handle of desktop window, handle  of window with keyboard
	   focus, whether system queue has any events, cursor position for last
	   message, 1 ms time for last message, handle of window with clipboard
	   open, handle of process heap, handle of procs window station, types of
	   events in input queue, and milliseconds since Windows was started */
	addRandomValue( randomState, GetActiveWindow() );
	addRandomValue( randomState, GetCapture() );
	addRandomValue( randomState, GetCaretBlinkTime() );
	addRandomValue( randomState, GetClipboardOwner() );
	addRandomValue( randomState, GetCurrentProcess() );
	addRandomValue( randomState, GetCurrentProcessId() );
	addRandomValue( randomState, GetCurrentThread() );
	addRandomValue( randomState, GetCurrentThreadId() );
	addRandomValue( randomState, GetDesktopWindow() );
	addRandomValue( randomState, GetDC( NULL ) );
	addRandomValue( randomState, GetDoubleClickTime() );
	addRandomValue( randomState, GetFocus() );
	addRandomValue( randomState, GetForegroundWindow() );
	addRandomValue( randomState, GetMessagePos() );
	addRandomValue( randomState, GetOpenClipboardWindow() );
	addRandomValue( randomState, GetProcessHeap() );
	addRandomValue( randomState, GetQueueStatus( QS_ALLINPUT ) );
	addRandomValue( randomState, GetTickCount() );
	checkPollExit();

	/* Get multiword system information: Current caret position, current
	   mouse cursor position */
	GetCaretPos( &point );
	addRandomData( randomState, &point, sizeof( POINT ) );
	GetCursorPos( &point );
	addRandomData( randomState, &point, sizeof( POINT ) );

	/* Get percent of memory in use, bytes of physical memory, bytes of free
	   physical memory, bytes in paging file, free bytes in paging file, user
	   bytes of address space, and free user bytes */
	memoryStatus.dwLength = sizeof( MEMORYSTATUS );
	GlobalMemoryStatus( &memoryStatus );
	addRandomData( randomState, &memoryStatus, sizeof( MEMORYSTATUS ) );

	/* Get thread and process creation time, exit time, time in kernel mode,
	   and time in user mode in 100ns intervals */
	handle = GetCurrentThread();
	GetThreadTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomData( randomState, &creationTime, sizeof( FILETIME ) );
	addRandomData( randomState, &exitTime, sizeof( FILETIME ) );
	addRandomData( randomState, &kernelTime, sizeof( FILETIME ) );
	addRandomData( randomState, &userTime, sizeof( FILETIME ) );

	/* Get extended battery/power status information.  We set the fUpdate
	   flag to force a re-read of fresh data rather than a re-use of cached
	   information */
	if( pGetSystemPowerStatusEx2 != NULL && \
		( length = \
				pGetSystemPowerStatusEx2( &powerStatus,
										  sizeof( SYSTEM_POWER_STATUS_EX2 ),
										  TRUE ) ) > 0 )
		addRandomData( randomState, &powerStatus, length );

	/* Get random data provided by the OS.  Since this is expected to be
	   provided by the system vendor, it's quite likely to be the usual
	   process ID + time */
	if( pCeGenRandom != NULL )
		{
		BYTE randomBuffer[ 32 ];

		if( pCeGenRandom( 32, randomBuffer ) )
			addRandomData( randomState, randomBuffer, 32 );
		}

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		SYSTEM_INFO systemInfo;

		GetSystemInfo( &systemInfo );
		addRandomData( randomState, &systemInfo, sizeof( SYSTEM_INFO ) );
		addedFixedItems = TRUE;
		}

	/* The performance of QPC varies depending on the architecture it's
	   running on, and is completely platform-dependant.  If there's no
	   hardware performance counter available, it uses the 1ms system timer,
	   although usually there's some form of hardware timer available.
	   Since there may be no correlation, or only a weak correlation,
	   between the performance counter and the system clock, we get the
	   time from both sources */
	if( QueryPerformanceCounter( &performanceCount ) )
		addRandomData( randomState, &performanceCount,
					   sizeof( LARGE_INTEGER ) );
	addRandomValue( randomState, GetTickCount() );

	/* Flush any remaining data through.  Quality = int( 33 1/3 % ) */
	endRandomData( randomState, 34 );
	}

/****************************************************************************
*																			*
*									Slow Poll								*
*																			*
****************************************************************************/

/* Type definitions for function pointers to call Toolhelp32 functions */

typedef BOOL ( WINAPI *MODULEWALK )( HANDLE hSnapshot, LPMODULEENTRY32 lpme );
typedef BOOL ( WINAPI *THREADWALK )( HANDLE hSnapshot, LPTHREADENTRY32 lpte );
typedef BOOL ( WINAPI *PROCESSWALK )( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL ( WINAPI *HEAPLISTWALK )( HANDLE hSnapshot, LPHEAPLIST32 lphl );
typedef BOOL ( WINAPI *HEAPFIRST )( HANDLE hSnapshot, LPHEAPENTRY32 lphe,
									DWORD th32ProcessID, DWORD th32HeapID );
typedef BOOL ( WINAPI *HEAPNEXT )( HANDLE hSnapshot, LPHEAPENTRY32 lphe );
typedef HANDLE ( WINAPI *CREATESNAPSHOT )( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL ( WINAPI *CLOSESNAPSHOT )( HANDLE hSnapshot );

/* Global function pointers. These are necessary because the functions need to
   be dynamically linked since only some WinCE builds contain them */

static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
static CLOSESNAPSHOT pCloseToolhelp32Snapshot = NULL;
static MODULEWALK pModule32First = NULL;
static MODULEWALK pModule32Next = NULL;
static PROCESSWALK pProcess32First = NULL;
static PROCESSWALK pProcess32Next = NULL;
static THREADWALK pThread32First = NULL;
static THREADWALK pThread32Next = NULL;
static HEAPLISTWALK pHeap32ListFirst = NULL;
static HEAPLISTWALK pHeap32ListNext = NULL;
static HEAPFIRST pHeap32First = NULL;
static HEAPNEXT pHeap32Next = NULL;

/* Since there are a significant number of ToolHelp data blocks, we use a
   larger-than-usual intermediate buffer to cut down on kernel traffic */

#define BIG_RANDOM_BUFSIZE	( RANDOM_BUFSIZE * 4 )

static void slowPollWinCE( void )
	{
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	HANDLE hSnapshot;
	RANDOM_STATE randomState;
	BYTE buffer[ BIG_RANDOM_BUFSIZE ];
	int bufIndex = 0, listCount = 0;

	/* Initialize the Toolhelp32 function pointers if necessary.  The
	   Toolhelp DLL isn't always present (some OEMs omit it) so we have to
	   link it dynamically */
	if( hToolHelp32 == NULL )
		{
		/* Obtain the module handle of the kernel to retrieve the addresses
		   of the ToolHelp32 functions */
		if( ( hToolHelp32 = LoadLibrary( TEXT( "Toolhelp.dll" ) ) ) == NULL )
			{
			/* There's no ToolHelp32 available, now we're in a bit of a
			   bind.  Try for at least a fast poll */
			fastPoll();
			return;
			}

		/* Now get pointers to the functions */
		pCreateToolhelp32Snapshot = ( CREATESNAPSHOT ) GetProcAddress( hToolHelp32, TEXT( "CreateToolhelp32Snapshot" ) );
		pCloseToolhelp32Snapshot = ( CLOSESNAPSHOT ) GetProcAddress( hToolHelp32, TEXT( "CloseToolhelp32Snapshot" ) );
		pModule32First = ( MODULEWALK ) GetProcAddress( hToolHelp32, TEXT( "Module32First" ) );
		pModule32Next = ( MODULEWALK ) GetProcAddress( hToolHelp32, TEXT( "Module32Next" ) );
		pProcess32First = ( PROCESSWALK ) GetProcAddress( hToolHelp32, TEXT( "Process32First" ) );
		pProcess32Next = ( PROCESSWALK ) GetProcAddress( hToolHelp32, TEXT( "Process32Next" ) );
		pThread32First = ( THREADWALK ) GetProcAddress( hToolHelp32, TEXT( "Thread32First" ) );
		pThread32Next = ( THREADWALK ) GetProcAddress( hToolHelp32, TEXT( "Thread32Next" ) );
		pHeap32ListFirst = ( HEAPLISTWALK ) GetProcAddress( hToolHelp32, TEXT( "Heap32ListFirst" ) );
		pHeap32ListNext = ( HEAPLISTWALK ) GetProcAddress( hToolHelp32, TEXT( "Heap32ListNext" ) );
		pHeap32First = ( HEAPFIRST ) GetProcAddress( hToolHelp32, TEXT( "Heap32First" ) );
		pHeap32Next = ( HEAPNEXT ) GetProcAddress( hToolHelp32, TEXT( "Heap32Next" ) );

		/* Make sure we got valid pointers for every Toolhelp32 function */
		if( pModule32First == NULL || pModule32Next == NULL || \
			pProcess32First == NULL || pProcess32Next == NULL || \
			pThread32First == NULL || pThread32Next == NULL || \
			pHeap32ListFirst == NULL || pHeap32ListNext == NULL || \
			pHeap32First == NULL || pHeap32Next == NULL || \
			pCreateToolhelp32Snapshot == NULL )
			{
			/* Mark the main function as unavailable in case for future
			   reference */
			pCreateToolhelp32Snapshot = NULL;
			return;
			}
		}
	checkPollExit();

	initRandomData( randomState, buffer, BIG_RANDOM_BUFSIZE );

	/* Take a snapshot of everything we can get to that's currently in the
	   system */
	hSnapshot = pCreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
	if( !hSnapshot )
		return;

	/* Walk through the local heap.  We have to be careful to not spend
	   excessive amounts of time on this if we're linked into a large
	   application with a great many heaps and/or heap blocks, since the
	   heap-traversal functions are rather slow.  Fortunately this is
	   quite rare under WinCE since it implies a large/long-running server
	   app, which we're unlikely to run into.

	   Ideally in order to prevent excessive delays we'd count the number
	   of heaps and ensure that no_heaps * no_heap_blocks doesn't exceed
	   some maximum value, however this requires two passes of (slow) heap
	   traversal rather than one, which doesn't help the situation much.
	   To provide at least some protection, we limit the total number of
	   heaps and heap entries traversed, although this leads to slightly
	   suboptimal performance if we have a small number of deep heaps
	   rather than the current large number of shallow heaps.

	   There is however a second consideration that needs to be taken into
	   account when doing this, which is that the heap-management functions
	   aren't completely thread-safe, so that under (very rare) conditions
	   of heavy allocation/deallocation this can cause problems when calling
	   HeapNext().  By limiting the amount of time that we spend in each
	   heap, we can reduce our exposure somewhat */
	hl32.dwSize = sizeof( HEAPLIST32 );
	if( pHeap32ListFirst( hSnapshot, &hl32 ) )
		do
			{
			HEAPENTRY32 he32;
			int entryCount = 0;

			/* First add the information from the basic Heaplist32
			   structure */
			checkPollExit();
			addRandomData( randomState, &hl32, sizeof( HEAPLIST32 ) );

			/* Now walk through the heap blocks getting information
			   on each of them */
			he32.dwSize = sizeof( HEAPENTRY32 );
			if( pHeap32First( hSnapshot, &he32, hl32.th32ProcessID, hl32.th32HeapID ) )
				do
					{
					checkPollExit();
					addRandomData( randomState, &he32,
								   sizeof( HEAPENTRY32 ) );
					}
				while( entryCount++ < 20 && pHeap32Next( hSnapshot, &he32 ) );
			}
		while( listCount++ < 20 && pHeap32ListNext( hSnapshot, &hl32 ) );

	/* Walk through all processes */
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if( pProcess32First( hSnapshot, &pe32 ) )
		do
			{
			checkPollExit();
			addRandomData( randomState, &pe32, sizeof( PROCESSENTRY32 ) );
			}
		while( pProcess32Next( hSnapshot, &pe32 ) );

	/* Walk through all threads */
	te32.dwSize = sizeof( THREADENTRY32 );
	if( pThread32First( hSnapshot, &te32 ) )
		do
			{
			checkPollExit();
			addRandomData( randomState, &te32, sizeof( THREADENTRY32 ) );
			}
	while( pThread32Next( hSnapshot, &te32 ) );

	/* Walk through all modules associated with the process */
	me32.dwSize = sizeof( MODULEENTRY32 );
	if( pModule32First( hSnapshot, &me32 ) )
		do
			{
			checkPollExit();
			addRandomData( randomState, &me32, sizeof( MODULEENTRY32 ) );
			}
	while( pModule32Next( hSnapshot, &me32 ) );

	/* Clean up the snapshot */
	pCloseToolhelp32Snapshot( hSnapshot );
	checkPollExit();

	/* Flush any remaining data through */
	endRandomData( randomState, 100 );
	}

/* Perform a thread-safe slow poll for Windows CE */

DWORD WINAPI threadSafeSlowPoll( void *dummy )
	{
	UNUSED( dummy );

	slowPollWinCE();
	ExitThread( 0 );
	return( 0 );
	}

/* Perform a generic slow poll.  This starts the OS-specific poll in a
   separate thread */

void slowPoll( void )
	{
	checkPollExit();

	/* Start a threaded slow poll.  If a slow poll is already running, we
	   just return since there isn't much point in running two of them at the
	   same time */
	if( hThread )
		return;
	hThread = CreateThread( NULL, 0, threadSafeSlowPoll, NULL, 0, &threadID );
	assert( hThread );
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   waitforRandomCompletion(), which will block until the background process
   completes */

void waitforRandomCompletion( const BOOLEAN force )
	{
	/* If there's not polling thread running, there's nothing to do */
	if( !hThread )
		return;

	/* If this is a forced shutdown, tell the polling thread to exit */
	if( force )
		{
		krnlEnterMutex( MUTEX_RANDOMPOLLING );
		exitNow = TRUE;
		krnlExitMutex( MUTEX_RANDOMPOLLING );

		/* Wait for the polling thread to terminate.  Since this is a forced
		   shutdown, we only wait a fixed amount of time (2s) before we bail
		   out */
		WaitForSingleObject( hThread, 2000 );
		CloseHandle( hThread );
		hThread = NULL;

		return;
		}

	/* Sign the system object over to the polling thread to allow it to
	   update the entropy data */
	krnlRelinquishSystemObject( threadID );

	/* Wait for the polling thread to terminate */
	WaitForSingleObject( hThread, INFINITE );
	CloseHandle( hThread );
	hThread = NULL;

	/* Return the system object to the calling thread */
	krnlReacquireSystemObject();
	}

/* Initialise and clean up any auxiliary randomness-related objects */

void initRandomPolling( void )
	{
	/* Reset the various object handles and status info */
	hToolHelp32 = hThread = NULL;
	exitNow = FALSE;
	}

void endRandomPolling( void )
	{
	assert( hThread == NULL );
	if( hToolHelp32 )
		{
		FreeLibrary( hToolHelp32 );
		hToolHelp32 = NULL;
		}
	}
