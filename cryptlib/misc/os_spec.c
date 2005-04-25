/****************************************************************************
*																			*
*					cryptlib OS-specific Support Routines					*
*					  Copyright Peter Gutmann 1992-2004						*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*									BeOS									*
*																			*
****************************************************************************/

#if defined( __AMX__ )

/* The AMX task-priority function returns the priority via a reference
   parameter.  Because of this we have to provide a wrapper that returns 
   it as a return value */

int threadPriority( void )	
	{
	int priority = 0;

	cjtkpradjust( cjtkid(), &priority );
	return( priority );
	}
#endif /* AMX */

/****************************************************************************
*																			*
*									BeOS									*
*																			*
****************************************************************************/

/* Match a given substring against a string in a case-insensitive manner.
   If possible we use native calls to handle this since they deal with
   charset-specific issues such as collating sequences, however a few OSes
   don't provide this functionality so we have to do it ourselves */

#if defined( __BEOS__ ) || defined( __SYMBIAN32__ )

int strnicmp( const char *src, const char *dest, int length )
	{
	assert( isReadPtr( src, length ) );

	while( length-- )
		{
		char srcCh = *src++, destCh = *dest++;

		/* Need to be careful with toupper() side-effects */
		srcCh = toUpper( srcCh );
		destCh = toUpper( destCh );

		if( srcCh != destCh )
			return( srcCh - destCh );
		}

	return( 0 );
	}

int stricmp( const char *src, const char *dest )
	{
	const int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strnicmp( src, dest, length ) );
	}
#endif /* OSes without case-insensitive string compares */

/****************************************************************************
*																			*
*									uITRON									*
*																			*
****************************************************************************/

#if defined( __ITRON__ )

/* The uITRON thread-self function returns the thread ID via a reference
   parameter since uITRON IDs can be negative and there'd be no way to
   differentiate a thread ID from an error code.  Because of this we have
   to provide a wrapper that returns it as a return value */

ID threadSelf( void )
	{
	ID tskid;

	get_tid( &tskid );
	return( tskid );
	}

#endif /* __ITRON__ */

/****************************************************************************
*																			*
*								IBM Mainframe								*
*																			*
****************************************************************************/

/* VM/CMS, MVS, and AS/400 systems need to convert characters from ASCII <->
   EBCDIC before/after they're read/written to external formats, the
   following functions perform the necessary conversion using the latin-1
   code tables for systems that don't have etoa/atoe */

#ifdef EBCDIC_CHARS

#include <stdarg.h>

#ifndef USE_ETOA

/* ISO 8859-1 to IBM Latin-1 Code Page 01047 (EBCDIC) */

static const BYTE asciiToEbcdicTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F,	/* 00 - 07 */
	0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26,	/* 10 - 17 */
	0x18, 0x19, 0x3F, 0x27, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D,	/* 20 - 27 */
	0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,	/* 28 - 2F */
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,	/* 30 - 37 */
	0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,	/* 38 - 3F */
	0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,	/* 40 - 47 */
	0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,	/* 48 - 4F */
	0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,	/* 50 - 57 */
	0xE7, 0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,	/* 58 - 5F */
	0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,	/* 60 - 67 */
	0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,	/* 68 - 6F */
	0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,	/* 70 - 77 */
	0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,	/* 78 - 7F */
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x06, 0x17,	/* 80 - 87 */
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x09, 0x0A, 0x1B,	/* 88 - 8F */
	0x30, 0x31, 0x1A, 0x33, 0x34, 0x35, 0x36, 0x08,	/* 90 - 97 */
	0x38, 0x39, 0x3A, 0x3B, 0x04, 0x14, 0x3E, 0xFF,	/* 98 - 9F */
	0x41, 0xAA, 0x4A, 0xB1, 0x9F, 0xB2, 0x6A, 0xB5,	/* A0 - A7 */
	0xBB, 0xB4, 0x9A, 0x8A, 0xB0, 0xCA, 0xAF, 0xBC,	/* A8 - AF */
	0x90, 0x8F, 0xEA, 0xFA, 0xBE, 0xA0, 0xB6, 0xB3,	/* B0 - B7 */
	0x9D, 0xDA, 0x9B, 0x8B, 0xB7, 0xB8, 0xB9, 0xAB,	/* B8 - BF */
	0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9E, 0x68,	/* C0 - C7 */
	0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,	/* C8 - CF */
	0xAC, 0x69, 0xED, 0xEE, 0xEB, 0xEF, 0xEC, 0xBF,	/* D0 - D7 */
	0x80, 0xFD, 0xFE, 0xFB, 0xFC, 0xBA, 0xAE, 0x59,	/* D8 - DF */
	0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9C, 0x48,	/* E0 - E7 */
	0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,	/* E8 - EF */
	0x8C, 0x49, 0xCD, 0xCE, 0xCB, 0xCF, 0xCC, 0xE1,	/* F0 - F7 */
	0x70, 0xDD, 0xDE, 0xDB, 0xDC, 0x8D, 0x8E, 0xDF	/* F8 - FF */
	};

/* IBM Latin-1 Code Page 01047 (EBCDIC) to ISO 8859-1 */

static const BYTE ebcdicToAsciiTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F,	/* 00 - 07 */
	0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x9D, 0x0A, 0x08, 0x87,	/* 10 - 17 */
	0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1B,	/* 20 - 27 */
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,	/* 28 - 2F */
	0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04,	/* 30 - 37 */
	0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,	/* 38 - 3F */
	0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5,	/* 40 - 47 */
	0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,	/* 48 - 4F */
	0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF,	/* 50 - 57 */
	0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,	/* 58 - 5F */
	0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5,	/* 60 - 67 */
	0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,	/* 68 - 6F */
	0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF,	/* 70 - 77 */
	0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,	/* 78 - 7F */
	0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,	/* 80 - 87 */
	0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,	/* 88 - 8F */
	0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,	/* 90 - 97 */
	0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,	/* 98 - 9F */
	0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,	/* A0 - A7 */
	0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0x5B, 0xDE, 0xAE,	/* A8 - AF */
	0xAC, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC,	/* B0 - B7 */
	0xBD, 0xBE, 0xDD, 0xA8, 0xAF, 0x5D, 0xB4, 0xD7,	/* B8 - BF */
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,	/* C0 - C7 */
	0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,	/* C8 - CF */
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,	/* D0 - D7 */
	0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,	/* D8 - DF */
	0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,	/* E0 - E7 */
	0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,	/* E8 - EF */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,	/* F0 - F7 */
	0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F	/* F8 - FF */
	};

/* Convert a string to/from EBCDIC */

int asciiToEbcdic( char *dest, const char *src, const int length )
	{
	int i;

	assert( isReadPtr( src, length ) );
	assert( isWritePtr( dest, length ) );

	for( i = 0; i < length; i++ )
		dest[ i ] = asciiToEbcdicTbl[ ( unsigned int ) src[ i ] ];
	return( CRYPT_OK );
	}

int ebcdicToAscii( char *dest, const char *src, const int length )
	{
	int i;

	assert( isReadPtr( src, length ) );
	assert( isWritePtr( dest, length ) );

	for( i = 0; i < length; i++ )
		dest[ i ] = ebcdicToAsciiTbl[ ( unsigned int ) src[ i ] ];
	return( CRYPT_OK );
	}
#else

int asciiToEbcdic( char *dest, const char *src, const int length )
	{
	assert( isReadPtr( src, length ) );
	assert( isWritePtr( dest, length ) );

	memcpy( dest, src, length );
	return( __atoe_l( string, stringLen ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

int ebcdicToAscii( char *dest, const char *src, const int length )
	{
	assert( isReadPtr( src, length ) );
	assert( isWritePtr( dest, length ) );

	memcpy( dest, src, length );
	return( __etoa_l( string, stringLen ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}
#endif /* USE_ETOA */

/* Convert a string to EBCDIC via a temporary buffer, used when passing an
   ASCII string to a system function that requires EBCDIC */

char *bufferToEbcdic( char *buffer, const char *string )
	{
	strcpy( buffer, string );
	asciiToEbcdic( buffer, strlen( string ) );
	return( buffer );
	}

/* Table for ctype functions that explicitly use the ASCII character set */

#define A	ASCII_ALPHA
#define L	ASCII_LOWER
#define N	ASCII_NUMERIC
#define S	ASCII_SPACE
#define U	ASCII_UPPER
#define X	ASCII_HEX
#define AL	( A | L )
#define AU	( A | U )
#define ANX	( A | N | X )
#define AUX	( A | U | X )

const BYTE asciiCtypeTbl[ 256 ] = {
	/* 00	   01	   02	   03	   04	   05	   06	   07  */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 08	   09	   0A	   0B	   0C	   0D	   0E	   0F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 10	   11	   12	   13	   14	   15	   16	   17 */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 18	   19	   1A	   1B	   1C	   1D	   1E	   1F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/*			!		"		#		$		%		&		' */
		A,		A,		A,		A,		A,		A,		A,		A,
	/* 	(		)		*		+		,		-		.		/ */
		A,		A,		A,		A,		A,		A,		A,		A,
	/*	0		1		2		3		4		5		6		7 */
	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,
	/*	8		9		:		;		<		=		>		? */
	   ANX,	   ANX,		A,		A,		A,		A,		A,		A,
	/*	@		A		B		C		D		E		F		G */
		A,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AU,
	/*	H		I		J		K		L		M		N		O */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	P		Q		R		S		T		U		V		W */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	X		Y		Z		[		\		]		^		_ */
	   AU,	   AU,	   AU,		A,		A,		A,		A,		A,
	/*	`		a		b		c		d		e		f		g */
		A,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	h		i		j		k		l		m		n		o */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	p		q		r		s		t		u		v		w */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	x		y		z		{		|		}		~	   DL */
	   AL,	   AL,	   AL,		A,		A,		A,		A,		A,
	/* High-bit-set characters */
	0
	};

/* stricmp()/strnicmp() versions that explicitly use the ASCII character
   set.  In order for collation to be handled properly, we have to convert
   to EBCDIC and use the local stricmp()/strnicmp() */

int strCompare( const char *src, const char *dest, int length )
	{
	BYTE buffer1[ MAX_ATTRIBUTE_SIZE ], buffer2[ MAX_ATTRIBUTE_SIZE ];

	assert( isReadPtr( src, length ) );

	if( length > MAX_ATTRIBUTE_SIZE )
		return( 1 );	/* Invalid length */

	/* Virtually all strings are 7-bit ASCII, the following optimisation
	   speeds up checking, particularly in cases where we're walking down a
	   list of keywords looking for a match */
	if( *src < 0x80 && *dest < 0x80 && \
		toLower( *src ) != toLower( *dest ) )
		return( 1 );	/* Not equal */

	/* Convert the strings to EBCDIC and use a native compare */
	src = bufferToEbcdic( buffer1, src );
	dest = bufferToEbcdic( buffer2, dest );
	return( strnicmp( src, dest, length ) );
	}

int strCompareZ( const char *src, const char *dest )
	{
	const int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strCompare( src, dest, length ) );
	}

/* sprintf() that takes an ASCII format string */

int sPrintf( char *buffer, const char *format, ... )
	{
	BYTE formatBuffer[ MAX_ATTRIBUTE_SIZE ];
	va_list argPtr;
#ifndef NDEBUG
	int i;
#endif /* NDEBUG */
	int status;

#ifndef NDEBUG
	/* Make sure that we don't have any string args, which would require
	   their own conversion to EBCDIC */
	for( i = 0; i < strlen( format ) - 1; i++ )
		if( format[ i ] == '%' && format[ i + 1 ] == 's' )
			assert( NOTREACHED );
#endif /* NDEBUG */
	format = bufferToEbcdic( formatBuffer, format );
	va_start( argPtr, format );
	status = vsprintf( buffer, format, argPtr );
	if( status > 0 )
		ebcdicToAscii( buffer, status );
	va_end( argPtr );
	return( status );
	}

/* atio() that takes an ASCII string */

int aToI( const char *str )
	{
	BYTE buffer[ 16 ];

	/* The maximum length of a numeric string value that can be converted
	   to a 4-byte integer is considered as 10 characters (9,999,999,999) */
	strncpy( buffer, str, 10 );
	buffer[ 10 ] = '\0';
	asciiToEbcdic( buffer, strlen( buffer ) );
	return( atoi( buffer ) );
	}
#endif /* EBCDIC_CHARS */

/****************************************************************************
*																			*
*									PalmOS									*
*																			*
****************************************************************************/

#if defined( __PALMOS__ )

#include <CmnErrors.h>
#include <CmnLaunchCodes.h>

/* The cryptlib entry point, defined in cryptlib.sld */

uint32_t cryptlibMain( uint16_t cmd, void *cmdPBP, uint16_t launchFlags )
	{
	void preInit( void );
	void postShutdown( void );

	UNUSED( cmdPBP );
	UNUSED( launchFlags );

	switch( cmd )
		{
		case sysLaunchCmdInitialize:
			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case sysLaunchCmdFinalize:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;
		}

	return( errNone );
	}

#endif /* __PALMOS__ */

/****************************************************************************
*																			*
*									RTEMS									*
*																			*
****************************************************************************/

#if defined( __RTEMS__ )

/* The RTEMS thread-self function returns the task ID via a reference
   parameter, because of this we have to provide a wrapper that returns it
   as a return value.  We use RTEMS_SEARCH_ALL_NODES because there isn't
   any other way to specify the local node, this option always searches the
   local node first so it has the desired effect */

rtems_id threadSelf( void )
	{
	rtems_id taskID;

	rtems_task_ident( RTEMS_SELF, RTEMS_SEARCH_ALL_NODES, &taskID );
	return( taskID );
	}

#endif /* __RTEMS__ */

/****************************************************************************
*																			*
*									Tandem									*
*																			*
****************************************************************************/

/* The Tandem mktime() is broken and can't convert dates beyond 2023, if
   mktime() fails and the year is between then and the epoch try again with
   a time that it can convert */

#if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )

#undef mktime	/* Restore the standard mktime() */

time_t my_mktime( struct tm *timeptr )
	{
	time_t theTime;

	theTime = mktime( timeptr );
	if( theTime < 0 && timeptr->tm_year > 122 && timeptr->tm_year <= 138 )
		{
		timeptr->tm_year = 122;	/* Try again with a safe year of 2022 */
		theTime = mktime( timeptr );
		}
	return( theTime );
	}
#endif /* __TANDEM_NSK__ || __TANDEM_OSS__ */

/****************************************************************************
*																			*
*									Unix									*
*																			*
****************************************************************************/

#if defined( __UNIX__ ) && \
	  !( defined( __MVS__ ) || defined( __TANDEM_NSK__ ) || \
		 defined( __TANDEM_OSS__ ) )

#include <sys/time.h>

/* For performance evaluation purposes we provide the following function,
   which returns ticks of the 1us timer */

long getTickCount( long startTime )
	{
	struct timeval tv;
	long timeLSB, timeDifference;

	/* Only accurate to about 1us */
	gettimeofday( &tv, NULL );
	timeLSB = tv.tv_usec;

	/* If we're getting an initial time, return an absolute value */
	if( !startTime )
		return( timeLSB );

	/* We're getting a time difference */
	if( startTime < timeLSB )
		timeDifference = timeLSB - startTime;
	else
		/* gettimeofday() rolls over at 1M us */
		timeDifference = ( 1000000L - startTime ) + timeLSB;
	if( timeDifference <= 0 )
		{
		printf( "Error: Time difference = %X, startTime = %X, endTime = %X.\n",
				timeDifference, startTime, timeLSB );
		return( 1 );
		}
	return( timeDifference );
	}
#endif /* __UNIX__ */

/****************************************************************************
*																			*
*									Windows									*
*																			*
****************************************************************************/

#if defined( __WIN32__ )

/* A flag to record whether we're running under the Win95 or WinNT code
   base */

BOOLEAN isWin95;

/* For performance evaluation purposes we provide the following function,
   which returns ticks of the 3.579545 MHz hardware timer (see the long
   comment in rndwin32.c for more details on Win32 timing issues) */

long getTickCount( long startTime )
	{
	long timeLSB, timeDifference;

#if 1
	LARGE_INTEGER performanceCount;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeLSB = performanceCount.LowPart;
#else
	FILETIME dummyTime, kernelTime, userTime;
	int status;

	/* Only accurate to 10ms, returns constant values in VC++ debugger */
	GetThreadTimes( GetCurrentThread(), &dummyTime, &dummyTime,
					&kernelTime, &userTime );
	timeLSB = userTime.dwLowDateTime;
#endif /* 0 */

	/* If we're getting an initial time, return an absolute value */
	if( !startTime )
		return( timeLSB );

	/* We're getting a time difference */
	if( startTime < timeLSB )
		timeDifference = timeLSB - startTime;
	else
		/* Windows rolls over at INT_MAX */
		timeDifference = ( 0xFFFFFFFFUL - startTime ) + 1 + timeLSB;
	if( timeDifference <= 0 )
		{
		printf( "Error: Time difference = %X, startTime = %X, endTime = %X.\n",
				timeDifference, startTime, timeLSB );
		return( 1 );
		}
	return( timeDifference );
	}

/* Windows NT/2000/XP support ACL-based access control mechanisms for system
   objects, so when we create objects such as files and threads we give them
   an ACL that allows only the creator access.  The following functions
   return the security info needed when creating objects.  The interface for
   this has changed in every major OS release, although it never got any
   better, just differently ugly.  The following code uses the original NT
   3.1 interface, which works for all OS versions */

/* The size of the buffer for ACLs and the user token */

#define ACL_BUFFER_SIZE		1024
#define TOKEN_BUFFER_SIZE	256

/* A composite structure to contain the various ACL structures.  This is
   required because ACL handling is a complex, multistage operation that
   requires first creating an ACL and security descriptor to contain it,
   adding an access control entry (ACE) to the ACL, adding the ACL as the
   DACL of the security descriptor, and finally, wrapping the security
   descriptor up in a security attributes structure that can be passed to
   an object-creation function.

   The handling of the TOKEN_INFO is extraordinarily ugly because although
   the TOKEN_USER struct as defined is only 8 bytes long, Windoze allocates
   an extra 24 bytes after the end of the struct into which it stuffs data
   that the SID pointer in the TOKEN_USER struct points to.  This means that
   we can't statically allocate memory of the size of the TOKEN_USER struct
   but have to make it a pointer into a larger buffer that can contain the
   additional invisible data tacked onto the end */

typedef struct {
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR pSecurityDescriptor;
	PACL pAcl;
	PTOKEN_USER pTokenUser;
	BYTE aclBuffer[ ACL_BUFFER_SIZE ];
	BYTE tokenBuffer[ TOKEN_BUFFER_SIZE ];
	} SECURITY_INFO;

/* Initialise an ACL allowing only the creator access and return it to the
   caller as an opaque value */

void *initACLInfo( const int access )
	{
	SECURITY_INFO *securityInfo;
	HANDLE hToken = INVALID_HANDLE_VALUE;	/* See comment below */
	BOOLEAN tokenOK = FALSE;

	/* Win95/98/ME doesn't have any security, return null security info */
	if( isWin95 )
		return( NULL );

	/* Allocate and initialise the composite security info structure */
	if( ( securityInfo = \
				clAlloc( "initACLInfo", sizeof( SECURITY_INFO ) ) ) == NULL )
		return( NULL );
	memset( securityInfo, 0, sizeof( SECURITY_INFO ) );
	securityInfo->pAcl = ( PACL ) securityInfo->aclBuffer;
	securityInfo->pTokenUser = ( PTOKEN_USER ) securityInfo->tokenBuffer;

	/* Get the security token for this thread.  First we try for the thread
	   token (which it typically only has when impersonating), if we don't
	   get that we use the token associated with the process.  We also
	   initialise the hToken (above) even though it shouldn't be necessary
	   because Windows tries to read its contents, which indicates there
	   might be problems if it happens to start out with the wrong value */
	if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) || \
		OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
		DWORD cbTokenUser;

		tokenOK = GetTokenInformation( hToken, TokenUser,
									   securityInfo->pTokenUser,
									   TOKEN_BUFFER_SIZE, &cbTokenUser );
		CloseHandle( hToken );
		}
	if( !tokenOK )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set a security descriptor owned by the current user */
	if( !InitializeSecurityDescriptor( &securityInfo->pSecurityDescriptor,
									   SECURITY_DESCRIPTOR_REVISION ) || \
		!SetSecurityDescriptorOwner( &securityInfo->pSecurityDescriptor,
									 securityInfo->pTokenUser->User.Sid,
									 FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set up the discretionary access control list (DACL) with one access
	   control entry (ACE) for the current user */
	if( !InitializeAcl( securityInfo->pAcl, ACL_BUFFER_SIZE,
						ACL_REVISION ) || \
		!AddAccessAllowedAce( securityInfo->pAcl, ACL_REVISION, access,
							  securityInfo->pTokenUser->User.Sid ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Bind the DACL to the security descriptor */
	if( !SetSecurityDescriptorDacl( &securityInfo->pSecurityDescriptor, TRUE,
									securityInfo->pAcl, FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	assert( IsValidSecurityDescriptor( &securityInfo->pSecurityDescriptor ) );

	/* Finally, set up the security attributes structure */
	securityInfo->sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	securityInfo->sa.bInheritHandle = FALSE;
	securityInfo->sa.lpSecurityDescriptor = &securityInfo->pSecurityDescriptor;

	return( securityInfo );
	}

void freeACLInfo( void *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	if( securityInfo == NULL )
		return;
	clFree( "freeACLInfo", securityInfo );
	}

/* Extract the security info needed in Win32 API calls from the collection of
   security data that we set up earlier */

void *getACLInfo( void *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	return( ( securityInfo == NULL ) ? NULL : &securityInfo->sa );
	}

#if !( defined( NT_DRIVER ) || defined( STATIC_LIB ) )

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	void preInit( void );
	void postShutdown( void );
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	UNUSED( hinstDLL );
	UNUSED( lpvReserved );

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Figure out which version of Windows we're running under */
			if( dwPlatform == ( DWORD ) CRYPT_ERROR )
				{
				OSVERSIONINFO osvi = { sizeof( osvi ) };

				GetVersionEx( &osvi );
				dwPlatform = osvi.dwPlatformId;
				isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? \
						  TRUE : FALSE;

				/* Check for Win32s just in case someone ever tries to load
				   cryptlib under it */
				if( dwPlatform == VER_PLATFORM_WIN32s )
					return( FALSE );
				}

			/* Disable thread-attach notifications, which we don't do
			   anything with and therefore don't need */
			DisableThreadLibraryCalls( hinstDLL );

			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}
#endif /* !( NT_DRIVER || STATIC_LIB ) */

/* Idiot-proofing.  Yes, there really are people who'll try and register a
   straight DLL */

#define MB_OK				0x00000000L
#define MB_ICONQUESTION		0x00000020L

int WINAPI MessageBoxA( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,
						UINT uType );

#pragma comment( linker, "/export:DllRegisterServer=_DllRegisterServer@0,PRIVATE" )

STDAPI DllRegisterServer( void )
	{
	MessageBoxA( NULL, "Why are you trying to register the cryptlib DLL?\n"
				 "It's just a standard Windows DLL, there's nothing\nto be "
				 "registered.", "ESO Error",
				 MB_ICONQUESTION | MB_OK );
	return( E_NOINTERFACE );
	}
#endif /* __WIN32__ */

#if defined( __WIN16__ )

/* WinMain() and WEP() under Win16 are intended for DLL initialisation,
   however it isn't possible to reliably do anything terribly useful in these
   routines.  The reason for this is that the WinMain/WEP functions are
   called by the windows module loader, which has a very limited workspace
   and can cause peculiar behaviour for some functions (allocating/freeing
   memory and loading other modules from these routines is unreliable), the
   order in which WinMain() and WEP() will be called for a set of DLL's is
   unpredictable (sometimes WEP doesn't seem to be called at all), and they
   can't be tracked by a standard debugger.  This is why MS have
   xxxRegisterxxx() and xxxUnregisterxxx() functions in their DLL's.

   Under Win16 on a Win32 system this isn't a problem because the module
   loader has been rewritten to work properly, but it isn't possible to get
   reliable performance under pure Win16, so the DLL entry/exit routines here
   do almost nothing, with the real work being done in cryptInit()/
   cryptEnd() */

HWND hInst;

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{
	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	return( TRUE );
	}
#endif /* __WIN16__ */

/****************************************************************************
*																			*
*									Windows CE								*
*																			*
****************************************************************************/

#ifdef __WINCE__

/* Windows CE doesn't provide ANSI standard time functions (although it'd be
   relatively easy to do so, and they are in fact provided in MFC), so we
   have to provide our own */

static LARGE_INTEGER *getTimeOffset( void )
	{
	static LARGE_INTEGER timeOffset = { 0 };

	/* Get the difference between the ANSI/ISO C time epoch and the Windows
	   time epoch if we haven't already done so (we could also hardcode this
	   in as 116444736000000000LL) */
	if( timeOffset.QuadPart == 0 )
		{
		SYSTEMTIME ofsSystemTime;
		FILETIME ofsFileTime;

		memset( &ofsSystemTime, 0, sizeof( SYSTEMTIME ) );
		ofsSystemTime.wYear = 1970;
		ofsSystemTime.wMonth = 1;
		ofsSystemTime.wDay = 1;
		SystemTimeToFileTime( &ofsSystemTime, &ofsFileTime );
		timeOffset.HighPart = ofsFileTime.dwHighDateTime;
		timeOffset.LowPart = ofsFileTime.dwLowDateTime;
		}

	return( &timeOffset );
	}

static time_t fileTimeToTimeT( const FILETIME *fileTime )
	{
	const LARGE_INTEGER *timeOffset = getTimeOffset();
	LARGE_INTEGER largeInteger;

	/* Convert a Windows FILETIME to a time_t by dividing by
	   10,000,000 (to go from 100ns ticks to 1s ticks) */
	largeInteger.HighPart = fileTime->dwHighDateTime;
	largeInteger.LowPart = fileTime->dwLowDateTime;
	largeInteger.QuadPart = ( largeInteger.QuadPart - \
							  timeOffset->QuadPart ) / 10000000L;
	if( sizeof( time_t ) == 4 && \
		largeInteger.QuadPart > 0x80000000UL )
		/* time_t is 32 bits but the converted time is larger than a 32-bit
		   signed value, indicate that we couldn't convert it.  In theory
		   we could check for largeInteger.HighPart == 0 and perform a
		   second check to see if time_t is unsigned, but it's unlikely that
		   this change would be made to the VC++ runtime time_t since it'd
		   break too many existing apps */
		return( -1 );
	return( ( time_t ) largeInteger.QuadPart );
	}

static void timeTToFileTime( FILETIME *fileTime, const time_t timeT )
	{
	const LARGE_INTEGER *timeOffset = getTimeOffset();
	LARGE_INTEGER largeInteger = { timeT };

	/* Convert a time_t to a Windows FILETIME by multiplying by
	   10,000,000 (to go from 1s ticks to 100ns ticks) */
	largeInteger.QuadPart = ( largeInteger.QuadPart * 10000000L ) + \
							timeOffset->QuadPart;
	fileTime->dwHighDateTime = largeInteger.HighPart;
	fileTime->dwLowDateTime = largeInteger.LowPart;
	}

time_t time( time_t *timePtr )
	{
	FILETIME fileTime;
#ifdef __WINCE__
	SYSTEMTIME systemTime;
#endif /* __WINCE__ */

	assert( timePtr == NULL );

	/* Get the time via GetSystemTimeAsFileTime().  Windows CE doesn't have
	   the unified call so we have to assemble it from discrete calls */
#ifdef __WINCE__
	GetSystemTime( &systemTime );
	SystemTimeToFileTime( &systemTime, &fileTime );
#else
	GetSystemTimeAsFileTime( &fileTime );
#endif /* Win32 vs. WinCE */

	return( fileTimeToTimeT( &fileTime ) );
	}

time_t mktime( struct tm *tmStruct )
	{
	SYSTEMTIME systemTime;
	FILETIME fileTime;

	assert( isWritePtr( tmStruct, sizeof( struct tm ) ) );

	/* Use SystemTimeToFileTime() as a mktime() substitute.  The input time
	   seems to be treated as local time, so we have to convert it to GMT
	   before we return it */
	memset( &systemTime, 0, sizeof( SYSTEMTIME ) );
	systemTime.wYear = tmStruct->tm_year + 1900;
	systemTime.wMonth = tmStruct->tm_mon + 1;
	systemTime.wDay = tmStruct->tm_mday;
	systemTime.wHour = tmStruct->tm_hour;
	systemTime.wMinute = tmStruct->tm_min;
	systemTime.wSecond = tmStruct->tm_sec;
	SystemTimeToFileTime( &systemTime, &fileTime );
	LocalFileTimeToFileTime( &fileTime, &fileTime );

	return( fileTimeToTimeT( &fileTime ) );
	}

struct tm *gmtime( const time_t *timePtr )
	{
	static struct tm tmStruct;
	SYSTEMTIME systemTime;
	FILETIME fileTime;

	assert( isReadPtr( timePtr, sizeof( time_t ) ) );

	/* Use FileTimeToSystemTime() as a gmtime() substitute.  Note that this
	   function, like its original ANSI/ISO C counterpart, is not thread-
	   safe */
	timeTToFileTime( &fileTime, *timePtr );
	FileTimeToSystemTime( &fileTime, &systemTime );
	memset( &tmStruct, 0, sizeof( struct tm ) );
	tmStruct.tm_year = systemTime.wYear - 1900;
	tmStruct.tm_mon = systemTime.wMonth - 1;
	tmStruct.tm_mday = systemTime.wDay;
	tmStruct.tm_hour = systemTime.wHour;
	tmStruct.tm_min = systemTime.wMinute;
	tmStruct.tm_sec = systemTime.wSecond;

	return( &tmStruct );
	}

/* Windows CE systems need to convert characters from ASCII <-> Unicode
   before/after they're read/written to external formats, the following
   functions perform the necessary conversion.

   winnls.h was already included via the global include of windows.h, however
   it isn't needed for any other part of cryptlib so it was disabled via
   NONLS.  Since winnls.h is now locked out, we have to un-define the guards
   used earlier to get it included */

#undef _WINNLS_
#undef NONLS
#include <winnls.h>

int asciiToUnicode( wchar_t *dest, const char *src, const int length )
	{
	int status;

	assert( isReadPtr( src, length ) );

	status = MultiByteToWideChar( GetACP(), 0, src, length, dest, length );
	return( status <= 0 ? CRYPT_ERROR_BADDATA : status * sizeof( wchar_t ) );
	}

int unicodeToAscii( char *dest, const wchar_t *src, const int length )
	{
	int status;

	assert( isReadPtr( src, length ) );

	/* Convert the string, overriding the system default char '?', which
	   causes problems if the output is used as a filename.  This function
	   has stupid semantics in that instead of returning the number of bytes
	   written to the output, it returns the number of bytes specified as
	   available in the output buffer, zero-filling the rest.  Because
	   there's no way to tell how long the resulting string actually is, we
	   use wcstombs() instead */
#if 0
	status = WideCharToMultiByte( GetACP(), 0, src, length, dest,
								  length * sizeof( wchar_t ), "_", NULL );
	return( ( status <= 0 ) ? CRYPT_ERROR_BADDATA : wcslen( dest ) );
#else
	status = wcstombs( dest, src, length * sizeof( wchar_t ) );
	return( ( status <= 0 ) ? CRYPT_ERROR_BADDATA : status );
#endif
	}

BOOL WINAPI DllMain( HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved )
	{
	void preInit( void );
	void postShutdown( void );

	UNUSED( hinstDLL );
	UNUSED( lpvReserved );

	switch( dwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Disable thread-attach notifications, which we don't do
			   anything with and therefore don't need */
			DisableThreadLibraryCalls( hinstDLL );

			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}
#endif /* __WINCE__ */
