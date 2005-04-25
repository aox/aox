/****************************************************************************
*																			*
*						  Win32 Randomness-Gathering Code					*
*	Copyright Peter Gutmann, Matt Thomlinson and Blake Coverett 1996-2004	*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom number
   generator.  For usage conditions, see random.c.

   From the "Peter giveth and Microsoft taketh away" department: The default
   NT setup has Everyone:Read permissions for the
   \\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\PerfLib
   key, which is the key for the performance counters.  This means that
   everyone on the network can read your machine's performance counters,
   significantly reducing their usefulness (although since they only contain
   a snapshot, network users should never see exactly what you're seeing).
   If you're worried about the native API call that's normally used failing
   (which falls back to using the registry performance counters), delete the
   Everyone:Read ACL and replace it with Interactive:Read, which only allows
   access to locally logged on users.  This means that an attacker will have
   to go to the effort of planting a trojan to get your crypto keys rather
   than getting them over the net.

   "Windows NT is a thing of genuine beauty, if you're seriously into genuine
	ugliness.  It's like a woman with a history of insanity in the family,
	only worse" -- Hans Chloride, "Why I Love Windows NT" */

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
#include <winperf.h>
#include <winioctl.h>
#include <process.h>

/* Some new CPU opcodes aren't supported by all compiler versions, if
   they're not available we define them here */

#if defined( _MSC_VER ) && ( _MSC_VER <= 1100 )
  #define cpuid		__asm _emit 0x0F __asm _emit 0xA2
  #define rdtsc		__asm _emit 0x0F __asm _emit 0x31
#endif /* VC++ 5.0 or earlier */
#define xstore_rng	__asm _emit 0x0F __asm _emit 0xA7 __asm _emit 0xC0

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

static HANDLE hAdvAPI32;	/* Handle to misc.library */
static HANDLE hNetAPI32;	/* Handle to networking library */
static HANDLE hNTAPI;		/* Handle to NT kernel library */
static HANDLE hThread;		/* Background polling thread handle */
static DWORD threadID;		/* Background polling thread ID */

/****************************************************************************
*																			*
*							Misc Randomness Sources							*
*																			*
****************************************************************************/

/* The number of bytes to read from the PIII RNG on each slow poll */

#define PIIIRNG_BYTES		64

/* Intel Chipset CSP type and name */

#define PROV_INTEL_SEC	22
#define INTEL_DEF_PROV	"Intel Hardware Cryptographic Service Provider"

/* A mapping from CryptoAPI to standard data types */

#define HCRYPTPROV			HANDLE

/* Type definitions for function pointers to call CryptoAPI functions */

typedef BOOL ( WINAPI *CRYPTACQUIRECONTEXT )( HCRYPTPROV *phProv,
											  LPCTSTR pszContainer,
											  LPCTSTR pszProvider, DWORD dwProvType,
											  DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTGENRANDOM )( HCRYPTPROV hProv, DWORD dwLen,
										 BYTE *pbBuffer );
typedef BOOL ( WINAPI *CRYPTRELEASECONTEXT )( HCRYPTPROV hProv, DWORD dwFlags );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since older versions of Win95 and NT don't contain
   them */

static CRYPTACQUIRECONTEXT pCryptAcquireContext = NULL;
static CRYPTGENRANDOM pCryptGenRandom = NULL;
static CRYPTRELEASECONTEXT pCryptReleaseContext = NULL;

/* Handle to the RNG CSP */

static HCRYPTPROV hProv;	/* Handle to Intel RNG CSP */

/* Try and connect to the PIII RNG CSP.  The AMD 768 southbridge (from the
   760 MP chipset) also has a hardware RNG, but there doesn't appear to be
   any driver support for this as there is for the Intel RNG so we can't do
   much with it.  OTOH the Intel RNG is also effectively dead as well,
   mostly due to virtually nonexistant support/marketing by Intel, it's
   included here mostly for form's sake */

static void initPIIIRng( void )
	{
	hProv = NULL;
	if( ( hAdvAPI32 = GetModuleHandle( "AdvAPI32.dll" ) ) == NULL )
		return;

	/* Get pointers to the CSP functions.  Although the acquire context
	   function looks like a standard function, it's actually a macro which
	   is mapped to (depending on the build type) CryptAcquireContextA or
	   CryptAcquireContextW, so we access it under the straight-ASCII-
	   function name */
	pCryptAcquireContext = ( CRYPTACQUIRECONTEXT ) GetProcAddress( hAdvAPI32,
													"CryptAcquireContextA" );
	pCryptGenRandom = ( CRYPTGENRANDOM ) GetProcAddress( hAdvAPI32,
													"CryptGenRandom" );
	pCryptReleaseContext = ( CRYPTRELEASECONTEXT ) GetProcAddress( hAdvAPI32,
													"CryptReleaseContext" );

	/* Make sure we got valid pointers for every CryptoAPI function and that
	   the required CSP is present */
	if( pCryptAcquireContext == NULL || \
		pCryptGenRandom == NULL || pCryptReleaseContext == NULL || \
		pCryptAcquireContext( &hProv, NULL, INTEL_DEF_PROV,
							  PROV_INTEL_SEC, 0 ) == FALSE )
		{
		hAdvAPI32 = NULL;
		hProv = NULL;
		}
	}

/* Read data from the PIII hardware RNG */

static void readPIIIRng( void )
	{
	BYTE buffer[ PIIIRNG_BYTES ];

	if( hProv == NULL )
		return;

	/* Read 128 bytes from the PIII RNG.  We don't rely on this for all our
	   randomness requirements in case it's broken in some way */
	if( pCryptGenRandom( hProv, PIIIRNG_BYTES, buffer ) )
		{
		RESOURCE_DATA msgData;
		static const int quality = 90;

		setMessageData( &msgData, buffer, PIIIRNG_BYTES );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
						 ( void * ) &quality,
						 CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
		zeroise( buffer, PIIIRNG_BYTES );
		}
	}

/* MBM data structures, originally by Alexander van Kaam, converted to C by
   Anders@Majland.org, finally updated by Chris Zahrt <techn0@iastate.edu> */

#define BusType		char
#define SMBType		char
#define SensorType	char

typedef struct {
	SensorType iType;			/* Type of sensor */
	int Count;					/* Number of sensor for that type */
	} SharedIndex;

typedef struct {
	SensorType ssType;			/* Type of sensor */
	unsigned char ssName[ 12 ];	/* Name of sensor */
	char sspadding1[ 3 ];		/* Padding of 3 bytes */
	double ssCurrent;			/* Current value */
	double ssLow;				/* Lowest readout */
	double ssHigh;				/* Highest readout */
	long ssCount;				/* Total number of readout */
	char sspadding2[ 4 ];		/* Padding of 4 bytes */
	long double ssTotal;		/* Total amout of all readouts */
	char sspadding3[ 6 ];		/* Padding of 6 bytes */
	double ssAlarm1;			/* Temp & fan: high alarm; voltage: % off */
	double ssAlarm2;			/* Temp: low alarm */
	} SharedSensor;

typedef struct {
	short siSMB_Base;			/* SMBus base address */
	BusType siSMB_Type;			/* SMBus/Isa bus used to access chip */
	SMBType siSMB_Code;			/* SMBus sub type, Intel, AMD or ALi */
	char siSMB_Addr;			/* Address of sensor chip on SMBus */
	unsigned char siSMB_Name[ 41 ];	/* Nice name for SMBus */
	short siISA_Base;			/* ISA base address of sensor chip on ISA */
	int siChipType;				/* Chip nr, connects with Chipinfo.ini */
	char siVoltageSubType;		/* Subvoltage option selected */
	} SharedInfo;

typedef struct {
	double sdVersion;			/* Version number (example: 51090) */
	SharedIndex sdIndex[ 10 ];	/* Sensor index */
	SharedSensor sdSensor[ 100 ];	/* Sensor info */
	SharedInfo sdInfo;			/* Misc.info */
	unsigned char sdStart[ 41 ];	/* Start time */
	/* We don't use the next two fields both because they're not random and
	   because it provides a nice safety margin in case of data size mis-
	   estimates (we always under-estimate the buffer size) */
/*	unsigned char sdCurrent[ 41 ];	/* Current time */
/*	unsigned char sdPath[ 256 ];	/* MBM path */
	} SharedData;

/* Read data from MBM.  This communicates via shared memory, so all we need
   to do is map a file and read the data out */

static void readMBMData( void )
	{
	HANDLE hMBMData;
	SharedData *mbmDataPtr;

	if( ( hMBMData = OpenFileMapping( FILE_MAP_READ, FALSE,
									  "$M$B$M$5$S$D$" ) ) != NULL )
		{
		if( ( mbmDataPtr = ( SharedData * ) \
				MapViewOfFile( hMBMData, FILE_MAP_READ, 0, 0, 0 ) ) != NULL )
			{
			RESOURCE_DATA msgData;
			static const int quality = 20;

			setMessageData( &msgData, mbmDataPtr, sizeof( SharedData ) );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
							 ( void * ) &quality,
							 CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
			UnmapViewOfFile( mbmDataPtr );
			}
		CloseHandle( hMBMData );
		}
	}

/* Read PnP configuration data.  This is mostly static per machine, but
   differs somewhat across machines.  We have to define the values ourselves
   here due to a combination of some of the values and functions not
   existing at the time VC++ 6.0 was released and */

typedef void * HDEVINFO;

#define DIGCF_PRESENT		0x02
#define DIGCF_ALLCLASSES	0x04

#define SPDRP_HARDWAREID	0x01

typedef struct _SP_DEVINFO_DATA {
	DWORD cbSize;
	GUID classGuid;
	DWORD devInst;
	ULONG *reserved;
	} SP_DEVINFO_DATA, *PSP_DEVINFO_DATA;

typedef BOOL ( WINAPI *SETUPDIDESTROYDEVICEINFOLIST )( HDEVINFO DeviceInfoSet );
typedef BOOL ( WINAPI *SETUPDIENUMDEVICEINFO )( HDEVINFO DeviceInfoSet,
												DWORD MemberIndex,
												PSP_DEVINFO_DATA DeviceInfoData );
typedef HDEVINFO ( WINAPI *SETUPDIGETCLASSDEVS )( /*CONST LPGUID*/ void *ClassGuid,
												  /*PCTSTR*/ void *Enumerator,
												  HWND hwndParent, DWORD Flags );
typedef BOOL ( WINAPI *SETUPDIGETDEVICEREGISTRYPROPERTY )( HDEVINFO DeviceInfoSet,
												PSP_DEVINFO_DATA DeviceInfoData,
												DWORD Property, PDWORD PropertyRegDataType,
												PBYTE PropertyBuffer,
												DWORD PropertyBufferSize, PDWORD RequiredSize );

static void readPnPData( void )
	{
	HANDLE hSetupAPI;
	HDEVINFO hDevInfo;
	SETUPDIDESTROYDEVICEINFOLIST pSetupDiDestroyDeviceInfoList = NULL;
	SETUPDIENUMDEVICEINFO pSetupDiEnumDeviceInfo = NULL;
	SETUPDIGETCLASSDEVS pSetupDiGetClassDevs = NULL;
	SETUPDIGETDEVICEREGISTRYPROPERTY pSetupDiGetDeviceRegistryProperty = NULL;

	if( ( hSetupAPI = LoadLibrary( "SetupAPI.dll" ) ) == NULL )
		return;

	/* Get pointers to the PnP functions.  Although the get class-devs
	   and get device registry functions look like standard functions,
	   they're actually macros that are mapped to (depending on the build
	   type) xxxA or xxxW, so we access it under the straight-ASCII-function
	   name */
	pSetupDiDestroyDeviceInfoList = ( SETUPDIDESTROYDEVICEINFOLIST ) \
				GetProcAddress( hSetupAPI, "SetupDiDestroyDeviceInfoList" );
	pSetupDiEnumDeviceInfo = ( SETUPDIENUMDEVICEINFO ) \
				GetProcAddress( hSetupAPI, "SetupDiEnumDeviceInfo" );
	pSetupDiGetClassDevs = ( SETUPDIGETCLASSDEVS ) \
				GetProcAddress( hSetupAPI, "SetupDiGetClassDevsA" );
	pSetupDiGetDeviceRegistryProperty = ( SETUPDIGETDEVICEREGISTRYPROPERTY ) \
				GetProcAddress( hSetupAPI, "SetupDiGetDeviceRegistryPropertyA" );
	if( pSetupDiDestroyDeviceInfoList == NULL || \
		pSetupDiEnumDeviceInfo == NULL || pSetupDiGetClassDevs == NULL || \
		pSetupDiGetDeviceRegistryProperty == NULL )
		{
		FreeLibrary( hSetupAPI );
		return;
		}

	/* Get info on all PnP devices */
	hDevInfo = pSetupDiGetClassDevs( NULL, NULL, NULL,
									 DIGCF_PRESENT | DIGCF_ALLCLASSES );
	if( hDevInfo != INVALID_HANDLE_VALUE )
		{
		SP_DEVINFO_DATA devInfoData;
		RANDOM_STATE randomState;
		BYTE buffer[ RANDOM_BUFSIZE ];
		BYTE pnpBuffer[ 512 ];
		DWORD cbPnPBuffer;
		int deviceCount;

		/* Enumerate all PnP devices */
		initRandomData( randomState, buffer, RANDOM_BUFSIZE );
		memset( &devInfoData, 0, sizeof( devInfoData ) );
		devInfoData.cbSize = sizeof( SP_DEVINFO_DATA );
		for( deviceCount = 0;
			 pSetupDiEnumDeviceInfo( hDevInfo, deviceCount, &devInfoData );
			 deviceCount++ )
			{
			if( pSetupDiGetDeviceRegistryProperty( hDevInfo, &devInfoData,
												   SPDRP_HARDWAREID, NULL,
												   pnpBuffer, 512, &cbPnPBuffer ) )
				addRandomData( randomState, pnpBuffer, cbPnPBuffer );
			}
		pSetupDiDestroyDeviceInfoList( hDevInfo );
		endRandomData( randomState, 5 );
		}

	FreeLibrary( hSetupAPI );
	}

/****************************************************************************
*																			*
*									Fast Poll								*
*																			*
****************************************************************************/

/* The shared Win32 fast poll routine */

void fastPoll( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	static BOOLEAN hasAdvFeatures = FALSE, hasHardwareRNG = FALSE;
	FILETIME  creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;
	LARGE_INTEGER performanceCount;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];

	checkPollExit();

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
	addRandomValue( randomState, GetClipboardOwner() );
	addRandomValue( randomState, GetClipboardViewer() );
	addRandomValue( randomState, GetCurrentProcess() );
	addRandomValue( randomState, GetCurrentProcessId() );
	addRandomValue( randomState, GetCurrentThread() );
	addRandomValue( randomState, GetCurrentThreadId() );
	addRandomValue( randomState, GetDesktopWindow() );
	addRandomValue( randomState, GetFocus() );
	addRandomValue( randomState, GetInputState() );
	addRandomValue( randomState, GetMessagePos() );
	addRandomValue( randomState, GetMessageTime() );
	addRandomValue( randomState, GetOpenClipboardWindow() );
	addRandomValue( randomState, GetProcessHeap() );
	addRandomValue( randomState, GetProcessWindowStation() );
	addRandomValue( randomState, GetTickCount() );
	checkPollExit();

	/* Calling the following function can cause problems in some cases in
	   that a calling application eventually stops getting events from its
	   event loop, so we can't (safely) use it as an entropy source */
/*	addRandomValue( randomState, GetQueueStatus( QS_ALLEVENTS ) ); */

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
	handle = GetCurrentProcess();
	GetProcessTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomData( randomState, &creationTime, sizeof( FILETIME ) );
	addRandomData( randomState, &exitTime, sizeof( FILETIME ) );
	addRandomData( randomState, &kernelTime, sizeof( FILETIME ) );
	addRandomData( randomState, &userTime, sizeof( FILETIME ) );

	/* Get the minimum and maximum working set size for the current process */
	GetProcessWorkingSetSize( handle, &minimumWorkingSetSize,
							  &maximumWorkingSetSize );
	addRandomValue( randomState, minimumWorkingSetSize );
	addRandomValue( randomState, maximumWorkingSetSize );

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		STARTUPINFO startupInfo;
		char vendorID[ 12 ];
		unsigned long processorID, featureFlags;

		/* Get name of desktop, console window title, new window position and
		   size, window flags, and handles for stdin, stdout, and stderr */
		startupInfo.cb = sizeof( STARTUPINFO );
		GetStartupInfo( &startupInfo );
		addRandomData( randomState, &startupInfo, sizeof( STARTUPINFO ) );
		addedFixedItems = TRUE;

		/* Check whether the CPU supports extended features like CPUID and
		   RDTSC, and get any info we need related to this.  There is an
		   IsProcessorFeaturePresent() function, but all that this provides
		   is an indication of the availability of rdtsc (alongside some
		   stuff we don't care about, like MMX and 3DNow).  Since we still
		   need to check for the presence of other features, we do the whole
		   thing ourselves */
		_asm {
			/* Detect the CPU type */
			pushfd
			pop eax				/* Get EFLAGS in eax */
			mov ebx, eax		/* Save a copy for later */
			xor eax, 0x200000	/* Toggle the CPUID bit */
			push eax
			popfd				/* Update EFLAGS */
			pushfd
			pop eax				/* Get updated EFLAGS back in eax */
			push ebx
			popfd				/* Restore original EFLAGS */
			xor eax, ebx		/* Check if we could toggle CPUID bit */
			jz noCPUID			/* Nope, we can't do anything further */
			mov [hasAdvFeatures], 1	/* Remember that we have CPUID, RDTSC */

			/* We have CPUID, see what we've got */
			xor ecx, ecx
			xor edx, edx		/* Tell VC++ that ECX, EDX will be trashed */
			xor eax, eax		/* CPUID function 0: */
			cpuid
			mov dword ptr [vendorID], ebx
			mov dword ptr [vendorID+4], edx
			mov dword ptr [vendorID+8], ecx	/* Save vendor ID string */
			mov eax, 1			/* CPUID function 1:  */
			cpuid
			mov [processorID], eax	/* Save processor ID */
			mov [featureFlags], edx	/* Save processor feature info */
		noCPUID:
			}

		/* If there's a vendor ID present, check for vendor-specific
		   special features */
		if( hasAdvFeatures && !memcmp( vendorID, "CentaurHauls", 12 ) )
			{
		_asm {
			xor ebx, ebx
			xor ecx, ecx		/* Tell VC++ that EBX, ECX will be trashed */
			mov eax, 0xC0000000	/* Centaur extended CPUID info */
			cpuid
			cmp eax, 0xC0000001	/* Need at least release 2 ext.feature set */
			jb noRNG			/* No extended info available */
			mov eax, 0xC0000001	/* Centaur extended feature flags */
			cpuid
			and edx, 01100b
			cmp edx, 01100b		/* Check for RNG present + enabled flags */
			jne noRNG			/* No, RNG not present or enabled */
			mov [hasHardwareRNG], 1	/* Remember that we have a hardware RNG */
		noRNG:
			}
			}
		}

	/* The performance of QPC varies depending on the architecture it's
	   running on and on the OS, the MS documentation is vague about the
	   details because it varies so much.  Under Win9x/ME it reads the
	   1.193180 MHz PIC timer.  Under NT/Win2K/XP it may or may not read the
	   64-bit TSC depending on the HAL and assorted other circumstances,
	   generally on machines with a uniprocessor HAL
	   KeQueryPerformanceCounter() uses a 3.579545MHz timer and on machines
	   with a multiprocessor or APIC HAL it uses the TSC (the exact time
	   source is controlled by the HalpUse8254 flag in the kernel).  That
	   choice of time sources is somewhat peculiar because on a
	   multiprocessor machine it's theoretically possible to get completely
	   different TSC readings depending on which CPU you're currently
	   running on, while for uniprocessor machines it's not a problem.
	   However, the kernel appears to synchronise the TSCs across CPUs at
	   boot time (it resets the TSC as part of its system init), so this
	   shouldn't really be a problem.  Under WinCE it's completely platform-
	   dependant, if there's no hardware performance counter available, it
	   uses the 1ms system timer.

	   Another feature of the TSC (although it doesn't really affect us here)
	   is that mobile CPUs will turn off the TSC when they idle, Pentiums
	   will change the rate of the counter when they clock-throttle (to
	   match the current CPU speed), and hyperthreading Pentiums will turn
	   it off when both threads are idle (this more or less makes sense,
	   since the CPU will be in the halted state and not executing any
	   instructions to count).

	   To make things unambiguous, we detect a CPU new enough to call RDTSC
	   directly by checking for CPUID capabilities, and fall back to QPC if
	   this isn't present */
	if( hasAdvFeatures )
		{
		unsigned long value;

		__asm {
			xor eax, eax
			xor edx, edx		/* Tell VC++ that EDX:EAX will be trashed */
			rdtsc
			mov [value], eax	/* Ignore high 32 bits, which are > 1s res */
			}
		addRandomValue( randomState, &value );
		}
	else
		if( QueryPerformanceCounter( &performanceCount ) )
			addRandomData( randomState, &performanceCount,
						   sizeof( LARGE_INTEGER ) );
		else
			/* Millisecond accuracy at best... */
			addRandomValue( randomState, GetTickCount() );

	/* If there's a hardware RNG present, read data from it.  We check that
	   the RNG is still present on each fetch since it could (at least in
	   theory) be disabled by the OS between fetches.  We also read the data
	   into an explicitly dword-aligned buffer (which the standard buffer
	   should be anyway, but we make it explicit here just to be safe).  Note
	   that we have to force alignment using a LONGLONG rather than a #pragma
	   pack, since chars don't need alignment it would have no effect on the
	   BYTE [] member */
	if( hasHardwareRNG )
		{
		struct alignStruct {
			LONGLONG dummy1;		/* Force alignment of following member */
			BYTE buffer[ 64 ];
			};
		struct alignStruct *rngBuffer = ( struct alignStruct * ) buffer;
		void *bufPtr = rngBuffer->buffer;	/* Get it into a form asm can handle */
		int byteCount = 0;

		_asm {
			push es
			xor ecx, ecx		/* Tell VC++ that ECX will be trashed */
			mov eax, 0xC0000001	/* Centaur extended feature flags */
			cpuid
			and edx, 01100b
			cmp edx, 01100b		/* Check for RNG present + enabled flags */
			jne rngDisabled		/* RNG was disabled after our initial check */
			push ds
			pop es
			mov edi, bufPtr		/* ES:EDI = buffer */
			xor edx, edx		/* Fetch 8 bytes */
			xstore_rng
			and eax, 011111b	/* Get count of bytes returned */
			jz rngDisabled		/* Nothing read, exit */
			mov [byteCount], eax
		rngDisabled:
			pop es
			}
		if( byteCount > 0 )
			addRandomData( randomState, bufPtr, byteCount );
		}

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
typedef BOOL ( WINAPI *HEAPFIRST )( LPHEAPENTRY32 lphe, DWORD th32ProcessID, DWORD th32HeapID );
typedef BOOL ( WINAPI *HEAPNEXT )( LPHEAPENTRY32 lphe );
typedef HANDLE ( WINAPI *CREATESNAPSHOT )( DWORD dwFlags, DWORD th32ProcessID );

/* Global function pointers. These are necessary because the functions need to
   be dynamically linked since only the Win95 kernel currently contains them.
   Explicitly linking to them will make the program unloadable under NT */

static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
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

static void slowPollWin95( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	HANDLE hSnapshot;
	RANDOM_STATE randomState;
	BYTE buffer[ BIG_RANDOM_BUFSIZE ];
	int listCount = 0;

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		readPnPData();
		addedFixedItems = TRUE;
		}

	/* Initialize the Toolhelp32 function pointers if necessary */
	if( pCreateToolhelp32Snapshot == NULL )
		{
		HANDLE hKernel;

		/* Obtain the module handle of the kernel to retrieve the addresses
		   of the Toolhelp32 functions */
		if( ( hKernel = GetModuleHandle( "Kernel32.dll" ) ) == NULL )
			return;

		/* Now get pointers to the functions */
		pCreateToolhelp32Snapshot = ( CREATESNAPSHOT ) GetProcAddress( hKernel,
													"CreateToolhelp32Snapshot" );
		pModule32First = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32First" );
		pModule32Next = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32Next" );
		pProcess32First = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32First" );
		pProcess32Next = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32Next" );
		pThread32First = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32First" );
		pThread32Next = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32Next" );
		pHeap32ListFirst = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListFirst" );
		pHeap32ListNext = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListNext" );
		pHeap32First = ( HEAPFIRST ) GetProcAddress( hKernel,
													"Heap32First" );
		pHeap32Next = ( HEAPNEXT ) GetProcAddress( hKernel,
													"Heap32Next" );

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
	   quite rare under Win95/98, since it implies a large/long-running
	   server app that would be run under NT/Win2K/XP rather than Win95
	   (the performance of the mapped ToolHelp32 helper functions under
	   these OSes is even worse than under Win95, fortunately we don't
	   have to use them there).

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
			if( pHeap32First( &he32, hl32.th32ProcessID, hl32.th32HeapID ) )
				do
					{
					checkPollExit();
					addRandomData( randomState, &he32,
								   sizeof( HEAPENTRY32 ) );
					}
				while( entryCount++ < 20 && pHeap32Next( &he32 ) );
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
	CloseHandle( hSnapshot );
	checkPollExit();

	/* Flush any remaining data through */
	endRandomData( randomState, 100 );
	}

/* Perform a thread-safe slow poll for Windows 95 */

unsigned __stdcall threadSafeSlowPollWin95( void *dummy )
	{
	UNUSED( dummy );

	slowPollWin95();
	_endthreadex( 0 );
	return( 0 );
	}

/* Type definitions for function pointers to call NetAPI32 functions */

typedef DWORD ( WINAPI *NETSTATISTICSGET )( LPWSTR szServer, LPWSTR szService,
											DWORD dwLevel, DWORD dwOptions,
											LPBYTE *lpBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERSIZE )( LPVOID lpBuffer, LPDWORD cbBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERFREE )( LPVOID lpBuffer );

/* Type definitions for functions to call native NT functions */

typedef DWORD ( WINAPI *NTQUERYSYSTEMINFO )( DWORD dwType, DWORD dwData,
											 DWORD dwMaxSize, DWORD dwDataSize );

/* Global function pointers. These are necessary because the functions need to
   be dynamically linked since only the WinNT kernel currently contains them.
   Explicitly linking to them will make the program unloadable under Win95 */

static NETSTATISTICSGET pNetStatisticsGet = NULL;
static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
static NETAPIBUFFERFREE pNetApiBufferFree = NULL;
static NTQUERYSYSTEMINFO pNtQuerySystemInfo = NULL;

/* When we query the performance counters, we allocate an initial buffer and
   then reallocate it as required until RegQueryValueEx() stops returning
   ERROR_MORE_DATA.  The following values define the initial buffer size and
   step size by which the buffer is increased */

#define PERFORMANCE_BUFFER_SIZE		65536	/* Start at 64K */
#define PERFORMANCE_BUFFER_STEP		16384	/* Step by 16K */

static void slowPollWinNT( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	static int isWorkstation = CRYPT_ERROR;
	static int cbPerfData = PERFORMANCE_BUFFER_SIZE;
	RESOURCE_DATA msgData;
	PPERF_DATA_BLOCK pPerfData;
	HANDLE hDevice;
	LPBYTE lpBuffer;
	DWORD dwSize, status;
	int nDrive, iterations = 0;

	/* Find out whether this is an NT server or workstation if necessary */
	if( isWorkstation == CRYPT_ERROR )
		{
		HKEY hKey;

		if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						  "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
						  0, KEY_READ, &hKey ) == ERROR_SUCCESS )
			{
			BYTE szValue[ 32 ];
			dwSize = sizeof( szValue );

			isWorkstation = TRUE;
			status = RegQueryValueEx( hKey, "ProductType", 0, NULL,
									  szValue, &dwSize );
			if( status == ERROR_SUCCESS && stricmp( szValue, "WinNT" ) )
				/* Note: There are (at least) three cases for ProductType:
				   WinNT = NT Workstation, ServerNT = NT Server, LanmanNT =
				   NT Server acting as a Domain Controller */
				isWorkstation = FALSE;

			RegCloseKey( hKey );
			}
		}

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		readPnPData();
		addedFixedItems = TRUE;
		}

	/* Initialize the NetAPI32 function pointers if necessary */
	if( hNetAPI32 == NULL )
		{
		/* Obtain a handle to the module containing the Lan Manager functions */
		if( ( hNetAPI32 = LoadLibrary( "NetAPI32.dll" ) ) != NULL )
			{
			/* Now get pointers to the functions */
			pNetStatisticsGet = ( NETSTATISTICSGET ) GetProcAddress( hNetAPI32,
														"NetStatisticsGet" );
			pNetApiBufferSize = ( NETAPIBUFFERSIZE ) GetProcAddress( hNetAPI32,
														"NetApiBufferSize" );
			pNetApiBufferFree = ( NETAPIBUFFERFREE ) GetProcAddress( hNetAPI32,
														"NetApiBufferFree" );

			/* Make sure we got valid pointers for every NetAPI32 function */
			if( pNetStatisticsGet == NULL ||
				pNetApiBufferSize == NULL ||
				pNetApiBufferFree == NULL )
				{
				/* Free the library reference and reset the static handle */
				FreeLibrary( hNetAPI32 );
				hNetAPI32 = NULL;
				}
			}
		}

	/* Initialize the NT kernel native API function pointers if necessary */
	if( hNTAPI == NULL && \
		( hNTAPI = GetModuleHandle( "NTDll.dll" ) ) != NULL )
		{
		/* Get a pointer to the NT native information query function */
		pNtQuerySystemInfo = ( NTQUERYSYSTEMINFO ) GetProcAddress( hNTAPI,
												"NtQuerySystemInformation" );
		if( pNtQuerySystemInfo == NULL )
			hNTAPI = NULL;
		}
	checkPollExit();

	/* Get network statistics.  Note: Both NT Workstation and NT Server by
	   default will be running both the workstation and server services.  The
	   heuristic below is probably useful though on the assumption that the
	   majority of the network traffic will be via the appropriate service. In
	   any case the network statistics return almost no randomness */
	if( hNetAPI32 != NULL &&
		pNetStatisticsGet( NULL,
						   isWorkstation ? L"LanmanWorkstation" : L"LanmanServer",
						   0, 0, &lpBuffer ) == 0 )
		{
		pNetApiBufferSize( lpBuffer, &dwSize );
		setMessageData( &msgData, lpBuffer, dwSize );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
		pNetApiBufferFree( lpBuffer );
		}

	/* Get disk I/O statistics for all the hard drives */
	for( nDrive = 0;; nDrive++ )
		{
		BYTE diskPerformance[ 256 ];
		char szDevice[ 24 ];

		/* Check whether we can access this device */
		sprintf( szDevice, "\\\\.\\PhysicalDrive%d", nDrive );
		hDevice = CreateFile( szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
							  NULL, OPEN_EXISTING, 0, NULL );
		if( hDevice == INVALID_HANDLE_VALUE )
			break;

		/* Note: This only works if the user has turned on the disk
		   performance counters with 'diskperf -y'.  These counters are
		   usually disabled, although they appear to be enabled in newer
		   installs of Win2K and XP.  In addition using the documented
		   DISK_PERFORMANCE data structure to contain the returned data
		   returns ERROR_INSUFFICIENT_BUFFER (which is wrong) and doesn't
		   change dwSize (which is also wrong), so we pass in a larger
		   buffer and pre-set dwSize to a safe value.  Finally, there is a
		   bug in pre-SP4 Win2K in which enabling diskperf, installing a
		   file system filter driver, and then disabling diskperf, causes
		   diskperf to corrupt the registry key HKEY_LOCAL_MACHINE\SYSTEM\
		   CurrentControlSet\Control\Class\{71A27CDD-812A-11D0-BEC7-
		   08002BE2092F}\Upper Filters, resulting in a Stop 0x7B bugcheck */
		dwSize = sizeof( diskPerformance );
		if( DeviceIoControl( hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
							 &diskPerformance, sizeof( diskPerformance ),
							 &dwSize, NULL ) )
			{
			checkPollExit();
			setMessageData( &msgData, &diskPerformance, dwSize );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
			}
		CloseHandle( hDevice );
		}
	checkPollExit();

	/* In theory we should be using the Win32 performance query API to obtain
	   unpredictable data from the system, however this is so unreliable (see
	   the multiple sets of comments further down) that it's too risky to
	   rely on it except as a fallback in emergencies.  Instead, we rely
	   mostly on an NT native API function that has the dual advantages that
	   it doesn't have as many (known) problems as the Win32 equivalent, and
	   that it doesn't access the data indirectly via pseudo-registry keys,
	   which means that it's much faster.  Note that the Win32 equivalent
	   actually works almost all of the time, the problem is that on one or
	   two systems it can fail in strange ways that are never the same and
	   can't be reproduced on any other system, which is why we use the
	   native API here.  Microsoft officially documented this function in
	   early 2003, so it'll be fairly safe to use */
	if( hNTAPI != NULL )
		{
		void *buffer = clAlloc( "slowPollNT", PERFORMANCE_BUFFER_SIZE );

		if( buffer != NULL )
			{
			DWORD dwSize = PERFORMANCE_BUFFER_SIZE, dwType;
			int noResults = 0;

			/* Scan the first 64 possible information types (we don't bother
			   with increasing the buffer size as we do with the Win32 version
			   of the performance data read, we may miss a few classes but
			   it's no big deal).  In addition the returned size value for
			   some classes is wrong (e.g. 23 and 24 return a size of 0) so we
			   miss a few more things, but again it's no big deal.  This scan
			   typically yields around 20 pieces of data, there's nothing in
			   the range 65...128 so chances are there won't be anything above
			   there either */
			for( dwType = 0; dwType < 64; dwType++ )
				{
				status = pNtQuerySystemInfo( dwType, ( DWORD ) buffer,
											 32768, ( DWORD ) &dwSize );
				if( status == ERROR_SUCCESS && dwSize > 0 )
					{
					checkPollExit();
					setMessageData( &msgData, buffer, dwSize );
					status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										IMESSAGE_SETATTRIBUTE_S, &msgData,
										CRYPT_IATTRIBUTE_ENTROPY );
					if( cryptStatusOK( status ) )
						noResults++;
					}
				}
			clFree( "slowPollWinNT", buffer );

			/* If we got enough data, we can leave now without having to try
			   for a Win32-level performance information query */
			if( noResults > 15 )
				{
				static const int quality = 100;

				checkPollExit();
				krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
								 ( void * ) &quality,
								 CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
				return;
				}
			}
		}
	checkPollExit();

	/* Wait for any async keyset driver binding to complete.  You may be
	   wondering what this call is doing here... the reason it's necessary is
	   because RegQueryValueEx() will hang indefinitely if the async driver
	   bind is in progress.  The problem occurs in the dynamic loading and
	   linking of driver DLL's, which work as follows:

		hDriver = LoadLibrary( DRIVERNAME );
		pFunction1 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC1 );
		pFunction2 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC2 );

	   If RegQueryValueEx() is called while the GetProcAddress()'s are in
	   progress, it will hang indefinitely.  This is probably due to some
	   synchronisation problem in the NT kernel where the GetProcAddress()
	   calls affect something like a module reference count or function
	   reference count while RegQueryValueEx() is trying to take a snapshot of
	   the statistics, which include the reference counts.  Because of this,
	   we have to wait until any async driver bind has completed before we can
	   call RegQueryValueEx() */
	krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );
	checkPollExit();

	/* Get information from the system performance counters.  This can take a
	   few seconds to do.  In some environments the call to RegQueryValueEx()
	   can produce an access violation at some random time in the future, in
	   some cases adding a short delay after the following code block makes
	   the problem go away.  This problem is extremely difficult to
	   reproduce, I haven't been able to get it to occur despite running it
	   on a number of machines.  MS knowledge base article Q178887 covers
	   this type of problem, it's typically caused by an external driver or
	   other program that adds its own values under the
	   HKEY_PERFORMANCE_DATA key.  The NT kernel, via Advapi32.dll, calls the
	   required external module to map in the data inside an SEH try/except
	   block, so problems in the module's collect function don't pop up until
	   after it has finished, so the fault appears to occur in Advapi32.dll.
	   There may be problems in the NT kernel as well though, a low-level
	   memory checker indicated that ExpandEnvironmentStrings() in
	   Kernel32.dll, called an interminable number of calls down inside
	   RegQueryValueEx(), was overwriting memory (it wrote twice the
	   allocated size of a buffer to a buffer allocated by the NT kernel).
	   OTOH this could be coming from the external module calling back into
	   the kernel, which eventually causes the problem described above.

	   Possibly as an extension of the problem that the krnlWaitSemaphore()
	   call above works around, running two instances of cryptlib (e.g. two
	   applications that use it) under NT4 can result in one of them hanging
	   in the RegQueryValueEx() call.  This happens only under NT4 and is
	   hard to reproduce in any consistent manner.

	   One workaround that helps a bit is to read the registry as a remote
	   (rather than local) registry, it's possible that the use of a network
	   RPC call isolates the calling app from the problem in that whatever
	   service handles the RPC is taking the hit and not affecting the
	   calling app.  Since this would require another round of extensive
	   testing to verify and the NT native API call is working fine, we'll
	   stick with the native API call for now.

	   Some versions of NT4 had a problem where the amount of data returned
	   was mis-reported and would never settle down, because of this the code
	   below includes a safety-catch that bails out after 10 attempts have
	   been made, this results in no data being returned but at does ensure
	   that the thread will terminate.

	   In addition to these problems the code in RegQueryValueEx() that
	   estimates the amount of memory required to return the performance
	   counter information isn't very accurate (it's much worse than the
	   "slightly-inaccurate" level that the MS docs warn about, it's usually
	   wildly off) since it always returns a worst-case estimate which is
	   usually nowhere near the actual amount required.  For example it may
	   report that 128K of memory is required, but only return 64K of data.

	   Even worse than the registry-based performance counters is the
	   performance data helper (PDH) shim that tries to make the counters
	   look like the old Win16 API (which is also used by Win95).  Under NT
	   this can consume tens of MB of memory and huge amounts of CPU time
	   while it gathers its data, and even running once can still consume
	   about 1/2MB of memory */
	pPerfData = ( PPERF_DATA_BLOCK ) clAlloc( "slowPollNT", cbPerfData );
	while( pPerfData != NULL && iterations++ < 10 )
		{
		dwSize = cbPerfData;
		status = RegQueryValueEx( HKEY_PERFORMANCE_DATA, "Global", NULL,
								  NULL, ( LPBYTE ) pPerfData, &dwSize );
		if( status == ERROR_SUCCESS )
			{
			if( !memcmp( pPerfData->Signature, L"PERF", 8 ) )
				{
				static const int quality = 100;
				int status;

				setMessageData( &msgData, pPerfData, dwSize );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										  IMESSAGE_SETATTRIBUTE_S, &msgData,
										  CRYPT_IATTRIBUTE_ENTROPY );
				if( cryptStatusOK( status ) )
					krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									 IMESSAGE_SETATTRIBUTE,
									 ( void * ) &quality,
									 CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
				}
			clFree( "slowPollWinNT", pPerfData );
			pPerfData = NULL;
			}
		else
			if( status == ERROR_MORE_DATA )
				{
				cbPerfData += PERFORMANCE_BUFFER_STEP;
				pPerfData = ( PPERF_DATA_BLOCK ) realloc( pPerfData, cbPerfData );
				}
		}

	/* Although this isn't documented in the Win32 API docs, it's necessary to
	   explicitly close the HKEY_PERFORMANCE_DATA key after use (it's
	   implicitly opened on the first call to RegQueryValueEx()).  If this
	   isn't done then any system components that provide performance data
	   can't be removed or changed while the handle remains active */
	RegCloseKey( HKEY_PERFORMANCE_DATA );
	}

/* Perform a thread-safe slow poll for Windows NT */

unsigned __stdcall threadSafeSlowPollWinNT( void *dummy )
	{
#if 0
	typedef BOOL ( WINAPI *CREATERESTRICTEDTOKEN )( HANDLE ExistingTokenHandle,
								DWORD Flags, DWORD DisableSidCount,
								PSID_AND_ATTRIBUTES SidsToDisable,
								DWORD DeletePrivilegeCount,
								PLUID_AND_ATTRIBUTES PrivilegesToDelete,
								DWORD RestrictedSidCount,
								PSID_AND_ATTRIBUTES SidsToRestrict,
								PHANDLE NewTokenHandle );
	static CREATERESTRICTEDTOKEN pCreateRestrictedToken = NULL;
	static BOOLEAN isInited = FALSE;
#endif /* 0 */

	UNUSED( dummy );

	/* If the poll performed any kind of active operation like the Unix one
	   rather than just basic data reads it'd probably be a good idea to drop
	   privileges before we begin, something that can be performed by the
	   following code */
#if 0
	if( !isInited )
		{
		OSVERSIONINFO osvi = { sizeof( osvi ) };

		/* Since CreateRestrictedToken() is a Win2K function we can only use
		   it on a post-NT4 system, and have to bind it at runtime */
		GetVersionEx( &osvi );
		if( osvi.dwMajorVersion > 4 )
			{
			const HINSTANCE hAdvAPI32 = GetModuleHandle( "AdvAPI32.dll" );

			pCreateRestrictedToken = ( CREATERESTRICTEDTOKEN ) \
						GetProcAddress( hAdvAPI32, "CreateRestrictedToken" );
			}
		isInited = TRUE;
		}
	if( pCreateRestrictedToken != NULL )
		{
		HANDLE hToken, hNewToken;

		ImpersonateSelf( SecurityImpersonation );
		OpenThreadToken( GetCurrentThread(),
						 TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | \
						 TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | \
						 TOKEN_IMPERSONATE, TRUE, &hToken );
		CreateRestrictedToken( hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL,
							   0, NULL, &hNewToken );
		SetThreadToken( &hThread, hNewToken );
		}
#endif /* 0 */

	slowPollWinNT();
#if 0
	if( pCreateRestrictedToken != NULL )
		RevertToSelf();
#endif /* 0 */
	_endthreadex( 0 );
	return( 0 );
	}

/* Perform a generic slow poll.  This starts the OS-specific poll in a
   separate thread */

void slowPoll( void )
	{
	checkPollExit();

	/* Read data from the various hardware sources */
	readPIIIRng();
	readMBMData();

	/* Start a threaded slow poll.  If a slow poll is already running, we
	   just return since there isn't much point in running two of them at the
	   same time */
	if( hThread )
		return;
	if( isWin95 )
		hThread = ( HANDLE ) _beginthreadex( NULL, 0, &threadSafeSlowPollWin95,
											 NULL, 0, &threadID );
	else
		{
		/* In theory since the thread is gathering info used (eventually)
		   for crypto keys we could set an ACL on the thread to make it
		   explicit that no-one else can mess with it:

			void *aclInfo = initACLInfo( THREAD_ALL_ACCESS );

			hThread = ( HANDLE ) _beginthreadex( getACLInfo( aclInfo ),
												 0, &threadSafeSlowPollWinNT,
												 NULL, 0, &threadID );
			freeACLInfo( aclInfo );

		  However, although this is supposed to be the default access for
		  threads anyway, when used from a service (running under the
		  LocalSystem account) under Win2K SP4 and up, the thread creation
		  fails with error = 22 (invalid parameter).  Presumably MS patched
		  some security hole or other in SP4, which causes the thread
		  creation to fail.  Because of this problem, we don't set an ACL for
		  the thread */
		hThread = ( HANDLE ) _beginthreadex( NULL, 0,
											 &threadSafeSlowPollWinNT,
											 NULL, 0, &threadID );
		}
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
	/* Reset the various module and object handles and status info and
	   initialise the PIII/P4 hardware RNG interface if it's present */
	hAdvAPI32 = hNetAPI32 = hThread = NULL;
	exitNow = FALSE;
	initPIIIRng();
	}

void endRandomPolling( void )
	{
	assert( hThread == NULL );
	if( hNetAPI32 )
		{
		FreeLibrary( hNetAPI32 );
		hNetAPI32 = NULL;
		}
	if( hProv != NULL )
		{
		pCryptReleaseContext( hProv, 0 );
		hProv = NULL;
		}
	}
