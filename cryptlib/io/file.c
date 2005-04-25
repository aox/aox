/****************************************************************************
*																			*
*							File Stream I/O Functions						*
*						Copyright Peter Gutmann 1993-2005					*
*																			*
****************************************************************************/

#if defined( __UNIX__ ) && defined( __linux__ )
  /* In order for the fileReadonly() check to work we need to be able to
	 check errno, however for this to work the headers that specify that
	 threading is being used must be the first headers included
	 (specifically, the include order has to be pthread.h, unistd.h,
	 everything else) or errno.h, which is pulled in by stdlib.h, gets
	 set up as an extern int rather than a function */
  #include "crypt.h"
#endif /* Older Linux broken include-file dependencies */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "stream.h"
  #include "file.h"
#elif defined( INC_CHILD )
  #include "stream.h"
  #include "file.h"
#else
  #include "io/stream.h"
  #include "io/file.h"
#endif /* Compiler-specific includes */

/* In order to get enhanced control over things like file security and 
   buffering we can't use stdio but have to rely on using OS-level file 
   routines, which is essential for working with things like ACL's for 
   sensitive files and forcing disk writes for files we want to erase.  
   Without the forced disk write the data in the cache doesn't get flushed 
   before the file delete request arrives, after which it's discarded rather 
   than being written, so the file never gets overwritten.  In addition some 
   embedded environments don't support stdio so we have to supply our own 
   alternatives.

   When implementing the following for new systems there are certain things
   that you need to ensure to guarantee error-free operation:

	- File permissions should be set as indicated by the file open flags.

	- File sharing controls (shared vs. exclusive access locks) should be
	  implemented.

	- If the file is locked for exclusive access, the open call should either
	  block until the lock is released (they're never held for more than a
	  fraction of a second) or return CRYPT_ERROR_TIMEOUT depending on how
	  the OS handles locks */

/****************************************************************************
*																			*
*							AMX File Stream Functions						*
*																			*
****************************************************************************/

#if defined( __AMX__ )

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const int modes[] = { 
		FJ_O_RDONLY, FJ_O_RDONLY, 
		FJ_O_WRONLY | FJ_O_CREAT | FJ_O_NOSHAREANY, 
		FJ_O_RDWR | FJ_O_NOSHAREWR
		};

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;
	openMode = modes[ mode & FILE_RW_MASK ];

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Try and open the file */
	stream->fd = fjopen( fileName, openMode, ( openMode & FJ_O_CREAT ) ? \
											 FJ_S_IREAD | FJ_S_IWRITE : 0 );
	if( stream->fd < 0 )
		{
		const int errNo = fjfserrno();

		return( ( errNo == FJ_EACCES || errNo == FJ_ESHARE ) ? \
					CRYPT_ERROR_PERMISSION : \
				( errNo == FJ_ENOENT ) ? \
					CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );
		}

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	fjclose( stream->fd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	if( ( bytesRead = fjread( stream->fd, buffer, length ) ) < 0 )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	int bytesWritten;

	if( ( bytesWritten = fjwrite( stream->fd, buffer, length ) ) < 0 || \
		bytesWritten != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	fjflush( stream->fd );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( fjlseek( stream->fd, position, FJ_SEEK_SET ) < 0 )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	struct fjxstat fileInfo;

	assert( fileName != NULL );

	if( fjstat( fileName, &fileInfo ) < 0 )
		return( TRUE );

	return( ( fileInfo->??? ) ? TRUE : FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ BUFSIZ * 2 ];
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );

		if( fjwrite( stream->fd, buffer, bytesToWrite ) < 0 )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}

	fjchsize( stream->fd, position );
	}

void fileClearToEOF( const STREAM *stream )
	{
	struct fjxstat fileInfo;
	int length, position;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	if( fjstat( fileName, &fileInfo ) < 0 )
		return;
	length = fileInfo.???;
	if( ( position = fjtell( stream->fd ) ) < 0 )
		return;
	length -= position;
	if( length <= 0 )
		return;	/* Nothing to do, exit */
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	struct fjxstat fileInfo;
	int status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	fjstat( fileName, &fileInfo );
	eraseFile( &stream, 0, fileInfo.??? );

	/* Reset the files attributes */
	fjfattr( stream.fd, FJ_DA_NORMAL );

	/* Delete the file */
	sFileClose( &stream );
	fjunlink( fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary.  We assume that
	   we're on the correct drive */
	strcpy( path, "\\cryptlib\\" );

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( option == BUILDPATH_CREATEPATH && fjisdir( path ) == 0 )
		{
		/* The directory doesn't exist, try and create it */
		if( fjmkdir( path ) < 0 )
			{
			*path = '\0';
			return;
			}
		}

	/* Add the filename to the path */
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*							uITRON File Stream Functions					*
*																			*
****************************************************************************/

/* See the comment in str_file.h for uITRON file handling */

#elif defined( __ITRON__ )

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Try and open the file */
	return( CRYPT_ERROR_OPEN );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	return( CRYPT_ERROR_READ );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	return( CRYPT_ERROR_WRITE );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	return( CRYPT_ERROR_WRITE );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	return( CRYPT_ERROR_WRITE );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	return( TRUE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	BYTE buffer[ BUFSIZ * 2 ];

	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( fwrite( buffer, 1, bytesToWrite, stream->filePtr ) == 0 )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}
	fflush( stream->filePtr );

	/* Truncate the file and if we're erasing the entire file, reset the 
	   timestamps.  This is only possible through a file handle on some 
	   systems, on others the caller has to do it via the filename */
	chsize( fileHandle, position );
	if( position <= 0 )
		{
		struct ftime fileTime;

		memset( &fileTime, 0, sizeof( struct ftime ) );
		setftime( fileHandle, &fileTime );
		}
	}

void fileClearToEOF( const STREAM *stream )
	{
	long position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	position = ftell( stream->filePtr );
	fseek( stream->filePtr, 0, SEEK_END );
	length = ftell( stream->filePtr ) - position;
	fseek( stream->filePtr, position, SEEK_SET );
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	int fileHandle, length, status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	fileHandle = fileno( stream.filePtr );
	fseek( stream.filePtr, 0, SEEK_END );
	length = ( int ) ftell( stream.filePtr );
	fseek( stream.filePtr, 0, SEEK_SET );
	eraseFile( stream, 0, length );

	/* Truncate the file to 0 bytes if we couldn't do it in eraseFile, reset 
	   the time stamps, and delete it */
	sFileClose( &stream );
	/* Under Win16 we can't really do anything without resorting to MSDOS int
	   21h calls, the best we can do is truncate the file using _lcreat() */
	hFile = _lcreat( fileName, 0 );
	if( hFile != HFILE_ERROR )
		_lclose( hFile );

	/* Finally, delete the file */
	remove( fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	if( option == BUILDPATH_RNDSEEDFILE )
		strcpy( path, "randseed.dat" );
	else
		{
		strcpy( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*							Macintosh File Stream Functions					*
*																			*
****************************************************************************/

#elif defined( __MAC__ )

/* Convert a C to a Pascal string */

static void CStringToPString( const char *cstring, StringPtr pstring )
	{
	short len = min( strlen( cstring ), 255 );

	memmove( pstring + 1, cstring, len );
	*pstring = len;
	}

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	Str255 pFileName;
	OSErr err;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

	CStringToPString( fileName, pFileName );
	err = FSMakeFSSpec( 0, 0, pFileName, &stream->fsspec );
	if( err == dirNFErr || err == nsvErr )
		/* Volume or parent directory not found */
		return( CRYPT_ERROR_NOTFOUND );
	if( err != noErr && err != fnfErr )
		/* fnfErr is OK since the fsspec is still valid */
		return( CRYPT_ERROR_OPEN );

	if( mode & FILE_WRITE )
		{
		/* Try and create the file, specifying its type and creator.  The
		   wierd string-looking constants are Mac compiler-specific and
		   evaluate to 32-bit unsigned type and creator IDs */
		err = FSpCreate( &stream->fsspec, '????', 'CLib', smSystemScript );
		if( err == wPrErr || err == vLckdErr || err == afpAccessDenied )
			return( CRYPT_ERROR_PERMISSION );
		if( err != noErr && err != dupFNErr && err != afpObjectTypeErr )
			return( CRYPT_ERROR_OPEN );
		}

	err = FSpOpenDF( &stream->fsspec, mode & FILE_RW_MASK, &stream->refNum );
	if( err == nsvErr || err == dirNFErr || err == fnfErr )
		return( CRYPT_ERROR_NOTFOUND );
	if( err == opWrErr || err == permErr || err == afpAccessDenied )
		return( CRYPT_ERROR_PERMISSION );
	if( err != noErr )
		return( CRYPT_ERROR_OPEN );

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	FSClose( stream->refNum );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
    long bytesRead = length;

	if( FSRead( stream->refNum, &bytesRead, buffer ) != noErr )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	long bytesWritten = length;

	if( FSWrite( stream->refNum, &bytesWritten, buffer ) != noErr || \
		( int ) bytesWritten != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	FileParam paramBlock;

	paramBlock.ioCompletion = NULL;
	paramBlock.ioFRefNum = stream->refNum;
	PBFlushFileSync( ( union ParamBlockRec * ) &paramBlock );
	return( CRYPT_OK );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( SetFPos( stream->refNum, fsFromStart, position ) != noErr )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	Str255 pFileName;
	FSSpec fsspec;
	OSErr err;
	short refnum;

	assert( fileName != NULL );

	CStringToPString( fileName, pFileName );

	err = FSMakeFSSpec( 0, 0, pFileName, &fsspec );
	if ( err == noErr )
		err = FSpOpenDF( &fsspec, fsRdWrPerm, &refnum );
	if ( err == noErr )
		FSClose( refnum );

	if ( err == opWrErr || err == permErr || err == afpAccessDenied )
		return( TRUE );

	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ BUFSIZ * 2 ];
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( FSWrite( stream->refNum, &bytesWritten, buffer ) != noErr )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}

	SetFPos( stream->refNum, fsFromStart, position );
	SetEOF( stream->refNum, position );
	}

void fileClearToEOF( const STREAM *stream )
	{
	long eof, position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	if( GetFPos( stream->refNum, &position ) != noErr || \
		GetEOF( stream->refNum, &eof ) != noErr )
		return;
	length = eof - position;
	if( length <= 0 )
		return;	/* Nothing to do, exit */
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	BYTE buffer[ BUFSIZ ];
	int length, status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	SetFPos( stream.refNum, fsFromStart, 0 );
	GetEOF( stream.refNum, &length );
	eraseFile( stream, position, length );

	/* Delete the file */
	sFileClose( &stream );
	FSpDelete( stream.fsspec );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	strcpy( path, ":" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*							Non-STDIO File Stream Functions					*
*																			*
****************************************************************************/

#elif defined( CONFIG_NO_STDIO )

#if defined( __VMCMS__ ) || defined( __IBM4758__ )

/* Some environments place severe restrictions on what can be done with file
   I/O, either having no filesystem at all or having one with characteristics
   that don't fit the stdio model.  For these systems we used our own in-
   memory buffers and make them look like memory streams until they're
   flushed, at which point they're written to backing store (flash RAM/
   EEPROM/DASD/whatever non-FS storage is being used) in one go.

   For streams with the sensitive bit set we don't expand the buffer size
   because the original was probably in protected memory, for non-sensitive
   streams we expand the size if necessary.  This means that we have to 
   choose a suitably large buffer for sensitive streams (private keys), but 
   one that isn't too big.  16K is about right, since typical private key 
   files with cert chains are 2K */

#define STREAM_BUFSIZE	16384

#endif /* __VMCMS__ || __IBM4758__ */

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
#ifdef __IBM4758__
	const BOOLEAN useBBRAM = ( mode & FILE_SENSITIVE ) ? TRUE : FALSE;
#endif /* __IBM4758__ */
	long length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_MEMORY;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

#if defined( __IBM4758__ )
	/* Make sure that the filename matches the 4758's data item naming 
	   conventions and remember the filename.  The best error code to return 
	   if there's a problem is a file open error, since this is buried so 
	   many levels down that a parameter error won't be meaningful to the 
	   caller */
	if( strlen( fileName ) > 8 )
		return( CRYPT_ERROR_OPEN );
	strcpy( stream->name, fileName );

	/* If we're doing a read, fetch the data into memory */
	if( mode & FILE_READ )
		{
		/* Find out how big the data item is and allocate a buffer for
		   it */
		status = sccGetPPDLen( ( char * ) fileName, &length );
		if( status != PPDGood )
			return( ( status == PPD_NOT_FOUND ) ? CRYPT_ERROR_NOTFOUND : \
					( status == PPD_NOT_AUTHORIZED ) ? CRYPT_ERROR_PERMISSION : \
					CRYPT_ERROR_OPEN );
		if( ( stream->buffer = clAlloc( "sFileOpen", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		stream->bufSize = stream->bufEnd = length;
		stream->isIOStream = TRUE;

		/* Fetch the data into the buffer so it can be read as a memory
		   stream */
		status = sccGetPPD( ( char * ) fileName, stream->buffer, length );
		return( ( status != PPDGood ) ? CRYPT_ERROR_READ : CRYPT_OK );
		}

	/* We're doing a write, make sure that there's enough room available.
	   This doesn't guarantee that there'll be enough when the data is 
	   committed, but it makes sense to at least check when the "file" is 
	   opened */
	status = sccQueryPPDSpace( &length, useBBRAM ? PPD_BBRAM : PPD_FLASH );
	if( status != PPDGood || length < STREAM_BUFSIZE )
		return( CRYPT_ERROR_OPEN );

	/* Allocate the initial I/O buffer for the data */
	if( ( stream->buffer = clAlloc( "sFileOpen", STREAM_BUFSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	stream->bufSize = STREAM_BUFSIZE;
	stream->isSensitive = useBBRAM;

	return( CRYPT_OK );
#elif defined( __VMCMS__ )
	/* If we're going to be doing a write either now or later, we can't open
	   the file until we have all of the data that we want to write to it 
	   available since the open arg has to include the file format 
	   information, so all we can do at this point is remember the name for 
	   later use */
	strcpy( stream->name, fileName );
	asciiToEbcdic( stream->name, strlen( stream->name ) );

	/* If we're doing a read, fetch the data into memory */
	if( mode & FILE_READ )
		{
		FILE *filePtr;
		fldata_t fileData;
		char fileBuffer[ MAX_PATH_LENGTH ];
		int count;

		/* Open the file and determine how large it is */
		filePtr = fopen( fileName, "rb" );
		if( filePtr == NULL )
			return( CRYPT_ERROR_OPEN );
		status = fldata( filePtr, fileBuffer, &fileData );
		if( status )
			{
			fclose( filePtr );
			return( CRYPT_ERROR_OPEN );
			}
		length = fileData.__maxreclen;

		/* Fetch the data into a buffer large enough to contain the entire
		   stream */
		if( ( stream->buffer = clAlloc( "sFileOpen", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		stream->bufSize = stream->bufEnd = length;
		status = fread( stream->buffer, length, 1, filePtr );
		fclose( filePtr );
		return( ( status != 1 ) ? CRYPT_ERROR_READ : CRYPT_OK );
		}

	/* Allocate the initial I/O buffer for the data */
	if( ( stream->buffer = clAlloc( "sFileOpen", STREAM_BUFSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	stream->bufSize = STREAM_BUFSIZE;

	return( CRYPT_OK );
#else
	#error Need to add mechanism to connect stream to backing store
	return( CRYPT_ERROR_OPEN );
#endif /* Nonstandard I/O enviroments */
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type != STREAM_TYPE_NULL );

#if defined( __IBM4758__ )
	/* Close the file and clear the stream structure */
	zeroise( stream->buffer, stream->bufSize );
	clFree( "sFileClose", stream->buffer );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
#elif defined( __VMCMS__ )
	/* Close the file and clear the stream structure */
	zeroise( stream->buffer, stream->bufSize );
	clFree( "sFileClose", stream->buffer );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
#else
	#error Need to add mechanism to disconnect stream from backing store
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
#endif /* Nonstandard I/O enviroments */
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* These environments move all data into an in-memory buffer when the 
	   file is opened, so there's never any need to read more data from the
	   stream */
	return( CRYPT_ERROR_READ );
#else
	#error Need to add mechanism to read data from backing store
	return( CRYPT_ERROR_READ );
#endif /* Nonstandard I/O enviroments */
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* Expand the write buffer on demand when it fills up.  If it's a small 
	   buffer allocated when we initially read a file and it doesn't look 
	   like we'll be overflowing a standard-size buffer, we first expand it 
	   up to STREAM_BUFSIZE before increasing it in STREAM_BUFSIZE steps.  
	   The following routine does a safe realloc() that wipes the original 
	   buffer */
	void *newBuffer;
	const int newSize = ( stream->bufSize < STREAM_BUFSIZE && \
						  stream->bufPos + length < STREAM_BUFSIZE - 1024 ) ? \
						STREAM_BUFSIZE : stream->bufSize + STREAM_BUFSIZE;

	/* Allocate the buffer and copy the new data across.  If the malloc
	   fails we return CRYPT_ERROR_OVERFLOW rather than CRYPT_ERROR_MEMORY
	   since the former is more appropriate for the emulated-I/O environment */
	if( ( newBuffer = clDynAlloc( "expandBuffer", \
								  stream->bufSize + STREAM_BUFSIZE ) ) == NULL )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( newBuffer, stream->buffer, stream->bufSize );
	zeroise( stream->buffer, stream->bufSize );
	clFree( "expandBuffer", stream->buffer );
	stream->buffer = newBuffer;
	stream->bufSize = newSize;

	return( CRYPT_OK );
#else
	#error Need to add mechanism to write data to backing store
	return( CRYPT_ERROR_WRITE );
#endif /* Nonstandard I/O enviroments */
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
#if defined( __IBM4758__ )
	/* Write the data to flash or BB memory as appropriate */
	if( sccSavePPD( stream->name, stream->buffer, stream->bufEnd,
			( stream->isSensitive ? PPD_BBRAM : PPD_FLASH ) | PPD_TRIPLE ) != PPDGood )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
#elif defined( __VMCMS__ )
	/* Under CMS, MVS, TSO, etc the only consistent way to handle writes is
	   to write a fixed-length single-record file containing all the data in
	   one record, so we can't really do anything until the data is flushed */
	FILE *filePtr;
	char formatBuffer[ 64 ];
	int count;

	sprintf( formatBuffer, "wb, recfm=F, lrecl=%d, noseek", stream->bufPos );
	filePtr = fopen( stream->name, formatBuffer );
	if( filePtr == NULL )
		return( CRYPT_ERROR_WRITE );
	count = fwrite( stream->buffer, stream->bufEnd, 1, filePtr );
	fclose( filePtr );
	return( ( count != 1 ) ? CRYPT_ERROR_WRITE : CRYPT_OK );
#else
	#error Need to add mechanism to commit data to backing store
	return( CRYPT_ERROR_WRITE );
#endif /* Nonstandard I/O enviroments */
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* These environments move all data into an in-memory buffer when the 
	   file is opened, so there's never any need to move around in the
	   stream */
	return( CRYPT_ERROR_READ );
#else
	#error Need to add mechanism to perform virtual seek on backing store
	return( CRYPT_ERROR_READ );
#endif /* Nonstandard I/O enviroments */
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* Since there's no filesystem, there's no concept of a read-only
	   file - all data items are always accessible */
	return( FALSE );
#else
	#error Need to add mechanism to determine readability of data in backing store
	return( FALSE );
#endif /* Nonstandard I/O enviroments */
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

void fileClearToEOF( const STREAM *stream )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* Data updates on these systems are atomic so there's no remaining data
	   left to clear */
	UNUSED( stream );
#else
  #error Need to add clear-to-EOF function for data in backing store
#endif /* Nonstandard I/O enviroments */
	}

void fileErase( const char *fileName )
	{
#if defined( __IBM4758__ )
	sccDeletePPD( ( char * ) fileName );
#elif defined( __VMCMS__ )
	FILE *filePtr;
	int length = CRYPT_ERROR, status;

	assert( fileName != NULL );

	/* Determine how large the file is */
	filePtr = fopen( fileName, "rb+" );
	if( filePtr != NULL )
		{
		fldata_t fileData;
		char fileBuffer[ MAX_PATH_LENGTH ];
		int status;

		status = fldata( filePtr, fileBuffer, &fileData );
		if( status == 0 )
			length = fileData.__maxreclen;
		}

	/* If we got a length, overwrite the data.  Since the file contains a
	   single record we can't perform the write-until-done overwrite used 
	   on other OS'es, however since we're only going to be deleting short
	   private key files using the default stream buffer is OK for this */
	if( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ STREAM_BUFSIZE ];

		length = max( length, STREAM_BUFSIZE );
		setMessageData( &msgData, buffer, length );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		fwrite( buffer, 1, length, filePtr );
		}
	if( filePtr != NULL )
		{
		fflush( filePtr );
		fclose( filePtr );
		}
	remove( fileName );
#else
  #error Need to add erase function for data in backing store
#endif /* Nonstandard I/O enviroments */
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
#if defined( __IBM4758__ )
	if( option == BUILDPATH_RNDSEEDFILE )
		/* Unlikely to really be necessary since we have a hardware RNG */
		strcpy( path, "RANDSEED" );
	else
		strcpy( path, fileName );
#elif defined( __VMCMS__ )
	if( option == BUILDPATH_RNDSEEDFILE )
		strcpy( path, "randseed dat" );
	else
		{
		strcpy( path, fileName );
		strcat( path, " p15" );
		}
#else
  #error Need to add function to build path to config data in backing store
#endif /* OS-specific file path creation */
	}

/****************************************************************************
*																			*
*							Palm OS File Stream Functions					*
*																			*
****************************************************************************/

#elif defined( __PALMOS__ )

#include <FeatureMgr.h>

/* In theory it's possible for a system not to have the VFS Manager 
   available, although this seems highly unlikely we check for it just
   in case using the Feature Manager */

static BOOLEAN checkVFSMgr( void )
	{
	uint32_t vfsMgrVersion;

	return( ( FtrGet( sysFileCVFSMgr, vfsFtrIDVersion, 
					  &vfsMgrVersion ) == errNone ) ? TRUE : FALSE );
	}

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const int modes[] = { 
		vfsModeRead, vfsModeRead, 
		vfsModeCreate | vfsModeExclusive | vfsModeWrite, 
		vfsModeReadWrite
		};
	uint32_t volIterator = vfsIteratorStart;
	uint16_t volRefNum, openMode;
	status_t err;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;
	openMode = modes[ mode & FILE_RW_MASK ];

	/* Make sure that VFS services are available and get the default volume 
	   to open the file on */
	if( !checkVFSMgr() )
		return( CRYPT_ERROR_OPEN );
	if( VFSVolumeEnumerate( &volRefNum, &volIterator ) != errNone )
		return( CRYPT_ERROR_OPEN );

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Try and open the file */
	err = VFSFileOpen( volRefNum, fileName, openMode, &stream->fileRef );
	if( err == vfsErrFilePermissionDenied || err == vfsErrIsADirectory || \
		err == vfsErrVolumeFull )
		return( CRYPT_ERROR_PERMISSION );
	if( err == vfsErrFileNotFound )
		return( CRYPT_ERROR_NOTFOUND );
	if( err != errNone )
		return( CRYPT_ERROR_OPEN );

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	VFSFileClose( stream->fileRef );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	uint32_t bytesRead;

	if( VFSFileRead( stream->fileRef, length, buffer, 
					 &bytesRead ) != errNone )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	uint32_t bytesWritten;

	if( VFSFileWrite( stream->fileRef, length, buffer, 
					  &bytesWritten ) != errNone || \
		bytesWritten != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	/* There doesn't seem to be any way to force data to be written do 
	   backing store, probably because the concept of backing store is
	   somewhat hazy in a system that's never really powered down.
	   Probably for removable media data is committed fairly quickly to
	   handle media removal while for fixed media it's committed as 
	   required since it can be retained in memory more or less 
	   indefinitely */
	return( CRYPT_OK );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( VFSFileSeek( stream->fileRef, vfsOriginBeginning, 
					 position ) != errNone )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	FileRef fileRef;
	uint32_t volIterator = vfsIteratorStart;
	uint16_t volRefNum;
	status_t err;

	assert( fileName != NULL );

	if( VFSVolumeEnumerate( &volRefNum, &volIterator ) != errNone )
		return( TRUE );
	err = VFSFileOpen( volRefNum, fileName, vfsModeRead, &fileRef );
	if( err == errNone )
		VFSFileClose( fileRef );

	return( ( err == vfsErrFilePermissionDenied ) ? TRUE : FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ BUFSIZ * 2 ];
		uint32_t bytesWritten;
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );

		if( VFSFileWrite( stream->fileRef, bytesToWrite, buffer, 
						  &bytesWritten ) != errNone )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}

	VFSFileResize( stream->fileRef, position );
	}

void fileClearToEOF( const STREAM *stream )
	{
	uint32_t length, position;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	if( VFSFileSize( stream->fileRef, &length ) != errNone || \
		VFSFileTell( stream->fileRef, &position ) != errNone );
		return;
	length -= position;
	if( length <= 0 )
		return;	/* Nothing to do, exit */
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	uint32_t volIterator = vfsIteratorStart, length;
	uint16_t volRefNum;
	int status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	if( VFSVolumeEnumerate( &volRefNum, &volIterator ) != errNone )
		return;
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	VFSFileSize( stream.fileRef, &length );
	eraseFile( &stream, 0, length );

	/* Reset the files attributes */
	VFSFileSetAttributes( stream.fileRef, 0 );
	VFSFileSetDate( stream.fileRef, vfsFileDateAccessed, 0 );
	VFSFileSetDate( stream.fileRef, vfsFileDateCreated, 0 );
	VFSFileSetDate( stream.fileRef, vfsFileDateModified, 0 );

	/* Delete the file */
	sFileClose( &stream );
	VFSFileDelete( volRefNum, fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Make sure that VFS services are available */
	if( !checkVFSMgr() )
		return;

	/* Build the path to the configuration file if necessary */
	strcpy( path, "/PALM/cryptlib/" );

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( option == BUILDPATH_CREATEPATH )
		{
		FileRef fileRef;
		uint32_t volIterator = vfsIteratorStart;
 		uint16_t volRefNum;

		if( VFSVolumeEnumerate( &volRefNum, &volIterator ) != errNone )
			{
			*path = '\0';
			return;
			}
		if( VFSFileOpen( volRefNum, path, vfsModeRead, &fileRef ) == errNone )
			VFSFileClose( fileRef );
		else
			/* The directory doesn't exist, try and create it */
			if( VFSDirCreate( volRefNum, path ) != errNone )
				{
				*path = '\0';
				return;
				}
		}

	/* Add the filename to the path */
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*					Unix/Unix-like Systems File Stream Functions			*
*																			*
****************************************************************************/

#elif defined( __BEOS__ ) || defined( __ECOS__ ) || defined( __RTEMS__ ) || \
	  defined( __SYMBIAN32__ ) || defined( __TANDEM_NSK__ ) || \
	  defined( __TANDEM_OSS__ ) || defined( __UNIX__ )

/* Tandem doesn't have ftruncate() even though there's a manpage for it
   (which claims it's prototyped in sys/types.h (!!)).  unistd.h has it
   protected by ( _XOPEN_SOURCE_EXTENDED == 1 && _TNS_R_TARGET ), which
   implies that we'd better emulate it if we want to make use of it.  For
   now we do nothing, this is just a placeholder if the Guardian native
   file layer isn't available */

#if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )

int ftruncate( int fd, off_t length )
	{
	return( 0 );
	}
#endif /* Tandem */

/* Open/close a file stream */

#ifdef DDNAME_IO 

/* DDNAME I/O can be used under MVS.  Low-level POSIX I/O APIs can't be 
   used at this level, only stream I/O functions can be used.  For 
   sFileOpen:

	- File permissions are controlled by RACF (or SAF compatable product)
	  and should not be set by the program.

	- No locking mechanism is implemented */

#define MODE_READ		"rb,byteseek"
#define MODE_WRITE		"wb,byteseek,recfm=*"
#define MODE_READWRITE	"rb+,byteseek,recfm=*"

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
#pragma convlit( suspend )
	static const char *modes[] = { MODE_READ, MODE_READ,
								   MODE_WRITE, MODE_READWRITE };
#pragma convlit( resume )
	const char *openMode;
	char fileNameBuffer[ MAX_PATH_LENGTH ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;
	openMode = modes[ mode & FILE_RW_MASK ];

	/* Try and open the file */
	fileName = bufferToEbcdic( fileNameBuffer, fileName );
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		/* The open failed, determine whether it was because the file doesn't
		   exist or because we can't use that access mode.  An errno value
		   of ENOENT results from a ddname not found, and 67 (no mnemonic
		   name defined by IBM for DYNALLOC return codes) is member not
		   found, and 49 is data set not found */
		return( ( errno == ENOENT || errno == 67 || errno == 49 ) ? \
				CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );

    return( CRYPT_OK );
	}
#else

#ifndef STDIN_FILENO		/* Usually defined in unistd.h */
  #define STDIN_FILENO		0
  #define STDOUT_FILENO		1
  #define STDERR_FILENO		2
#endif /* STDIN_FILENO */

static int openFile( STREAM *stream, const char *fileName, 
					 const int flags, const int mode )
	{
	int fd, count = 0;

	/* A malicious user could have exec()'d us after closing standard I/O
	   handles (which we inherit across the exec()), which means that any 
	   new files that we open will be allocated the same handles as the 
	   former standard I/O ones.  This could cause private data to be 
	   written to stdout or error messages emitted by the calling app to go 
	   into the opened file.  To avoid this, we retry the open if we get the 
	   same handle as a standard I/O one */
	do
		{
		fd = open( fileName, flags, mode );
		if( fd == -1 )
			{
			/* If we're creating the file, the only error condition is a
			   straight open error */
			if( flags & O_CREAT )
				return( CRYPT_ERROR_OPEN );

			/* Determine whether the open failed because the file doesn't 
			   exist or because we can't use that access mode */
			return( ( access( fileName, 0 ) == -1 ) ? \
					CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );
			}
		}
	while( count++ < 3 && \
		   ( fd == STDIN_FILENO || fd == STDOUT_FILENO || \
		     fd == STDERR_FILENO ) );

	stream->fd = fd;
	return( CRYPT_OK );
	}

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
#if defined( EBCDIC_CHARS )
  #pragma convlit( suspend )
#endif /* EBCDIC_CHARS */
	static const int modes[] = { O_RDONLY, O_RDONLY, O_WRONLY, O_RDWR };
#if defined( EBCDIC_CHARS )
  #pragma convlit( resume )
#endif /* EBCDIC_CHARS */
	int openMode = modes[ mode & FILE_RW_MASK ];
#ifdef EBCDIC_CHARS
	char fileNameBuffer[ MAX_PATH_LENGTH ];
#endif /* EBCDIC_CHARS */
#ifdef USE_FCNTL_LOCKING 
	struct flock flockInfo;
#endif /* USE_FCNTL_LOCKING */

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

#ifdef EBCDIC_CHARS
	fileName = bufferToEbcdic( fileNameBuffer, fileName );
#endif /* EBCDIC_CHARS */

	/* Defending against writing through links is somewhat difficult since 
	   there's no atomic way to do this.  What we do is lstat() the file, 
	   open it as appropriate, and if it's an existing file ftstat() it and 
	   compare various important fields to make sure that the file wasn't 
	   changed between the lstat() and the open().  If everything is OK, we 
	   then use the lstat() information to make sure that it isn't a symlink 
	   (or at least that it's a normal file) and that the link count is 1.  
	   These checks also catch other weird things like STREAMS stuff 
	   fattach()'d over files.  If these checks pass and the file already 
	   exists we truncate it to mimic the effect of an open with create */
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		{
		struct stat lstatInfo;
		int status;

		/* lstat() the file.  If it doesn't exist, create it with O_EXCL.  If
		   it does exist, open it for read/write and perform the fstat()
		   check */
		if( lstat( fileName, &lstatInfo ) == -1 )
			{
			/* If the lstat() failed for reasons other than the file not
			   existing, return a file open error */
			if( errno != ENOENT )
				return( CRYPT_ERROR_OPEN );

			/* The file doesn't exist, create it with O_EXCL to make sure 
			   that an attacker can't slip in a file between the lstat() and 
			   open() */
			status = openFile( stream, fileName, O_CREAT | O_EXCL | O_RDWR, 
							   0600 );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			struct stat fstatInfo;

			/* Open an existing file */
			status = openFile( stream, fileName, O_RDWR, 0 );
			if( cryptStatusError( status ) )
				return( status );

			/* fstat() the opened file and check that the file mode bits and
			   inode and device match */
			if( fstat( stream->fd, &fstatInfo ) == -1 || \
				lstatInfo.st_mode != fstatInfo.st_mode || \
				lstatInfo.st_ino != fstatInfo.st_ino || \
				lstatInfo.st_dev != fstatInfo.st_dev )
				{
				close( stream->fd );
				return( CRYPT_ERROR_OPEN );
				}

			/* If the above check was passed, we know that the lstat() and
			   fstat() were done to the same file.  Now check that there's
			   only one link, and that it's a normal file (this isn't
			   strictly necessary because the fstat() vs. lstat() st_mode
			   check would also find this).  This also catches tricks like 
			   an attacker closing stdin/stdout so that a newly-opened file 
			   ends up with those file handles, with the result that the app 
			   using cryptlib ends up corrupting cryptlib's files when it 
			   sends data to stdout.  In order to counter this we could 
			   simply repeatedly open /dev/null until we get a handle > 2, 
			   but the fstat() check will catch this in a manner that's also 
			   safe with systems that don't have a stdout (so the handle > 2 
			   check won't make much sense) */
			if( fstatInfo.st_nlink > 1 || !S_ISREG( lstatInfo.st_mode ) )
				{
				close( stream->fd );
				return( CRYPT_ERROR_OPEN );
				}

			/* Turn the file into an empty file */
			ftruncate( stream->fd, 0 );
			}
		}
	else
		{
		int status;

		/* Open an existing file for read access */
		status = openFile( stream, fileName, openMode, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set the file access permissions so that only the owner can access it */
	if( mode & FILE_PRIVATE )
		chmod( fileName, 0600 );

	/* Lock the file if possible to make sure that no-one else tries to do 
	   things to it.  If available we used the (BSD-style) flock(), if not we 
	   fall back to Posix fcntl() locking (both mechanisms are broken, but 
	   flock() is less broken).  fcntl() locking has two disadvantages over 
	   flock():

	   1. Locking is per-process rather than per-thread (specifically it's
		  based on processes and inodes rather than flock()'s file table
		  entries, for which any new handles created via dup()/fork()/open()
		  all refer to the same file table entry so there's a single location
		  at which to handle locking), so another thread in the same process
		  could still access the file.  Whether this is a good thing or not
		  is context-dependant: We want multiple threads to be able to read
		  from the file (if one keyset handle is shared among threads), but
		  not necessarily for multiple threads to be able to write.  We could
		  if necessary use mutexes for per-thread lock synchronisation, but
		  this gets incredibly ugly since we then have to duplicate parts of 
		  the the system file table with per-thread mutexes, mess around with 
		  an fstat() on each file access to determine if we're accessing an
		  already-open file, wrap all that up in more mutexes, etc etc, as
		  well as being something that's symtomatic of a user application bug
		  rather than normal behaviour that we can defend against.

	   2. Closing *any* descriptor for an fcntl()-locked file releases *all*
		  locks on the file (!!) (one manpage appropriately describes this
		  behaviour as "the completely stupid semantics of System V and IEEE
		  Std 1003.1-1988 (= POSIX.1)").  In other words if two threads or
		  processes open an fcntl()-locked file for shared read access then
		  the first close of the file releases all locks on it.  Since
		  fcntl() requires a file handle to work, the only way to determine
		  whether a file is locked requires opening it, but as soon as we
		  close it again (for example to abort the access if there's a lock
		  on it) all locks are released.

	   The downside of flock()-locking is that it doesn't usually work with
	   NFS unless special hacks have been applied.  fcntl() passes lock
	   requests to rpc.lockd to handle, but this is its own type of mess
	   since it's often unreliable, so it's really not much worse than
	   flock().  In addition locking support under filesystems like AFS is
	   often nonexistant, with the lock apparently succeeding but no lock
	   actually being applied.  Finally, locking is almost always advisory
	   only, but even mandatory locking can be bypassed by tricks such as
	   copying the original, unlinking it, and renaming the copy back to the
	   original (the unlinked - and still locked - original goes away once
	   the handle is closed) - this mechanism is standard practice for many
	   Unix utilities like text editors.  In addition mandatory locking is
	   wierd in that an open for write (or read, on a write-locked file) will
	   succeed, it's only a later attempt to read/write that will fail.

	   This mess is why dotfile-locking is still so popular, but that's
	   probably going a bit far for simple keyset accesses */
#ifndef USE_FCNTL_LOCKING
	if( flock( stream->fd, ( mode & FILE_EXCLUSIVE_ACCESS ) ? \
						   LOCK_EX | LOCK_NB : LOCK_SH | LOCK_NB ) == -1 && \
		errno == EWOULDBLOCK )
		{
		close( stream->fd );
		return( CRYPT_ERROR_PERMISSION );
		}
#else
	memset( &flockInfo, 0, sizeof( struct flock ) );
	flockInfo.l_type = ( mode & FILE_EXCLUSIVE_ACCESS ) ? \
					   F_WRLCK : F_RDLCK;
	flockInfo.l_whence = SEEK_SET;
	flockInfo.l_start = flockInfo.l_len = 0;
	if( fcntl( stream->fd, F_SETLK, flockInfo ) == -1 && \
		( errno == EACCES || errno == EDEADLK ) )
		{
		/* Now we're in a bind.  If we close the file and exit, the lock
		   we've just detected on the file is released (see the comment on
		   this utter braindamage above).  OTOH if we don't close the file
		   we'll leak the file handle, which is bad for long-running
		   processes.  Feedback from users indicates that leaking file
		   handles is less desirable than the possiblity of having the file
		   unlocked during an update (the former is a situation that occurs
		   far more frequently than the latter), so we close the handle and
		   hope that the update by the other process completes quickly */
		close( stream->fd );
		return( CRYPT_ERROR_PERMISSION );
		}
#endif /* flock() vs. fcntl() locking */

	return( CRYPT_OK );
	}
#endif /* MVS USS special-case handling */

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Unlock the file if necessary.  If we're using fcntl() locking there's
	   no need to unlock the file since all locks are automatically released
	   as soon as any handle to it is closed (see the long comment above for
	   more on this complete braindamage) */
#ifndef USE_FCNTL_LOCKING
	flock( stream->fd, LOCK_UN );
#endif /* !USE_FCNTL_LOCKING */
	close( stream->fd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	if( ( bytesRead = read( stream->fd, buffer, length ) ) == -1 )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	if( write( stream->fd, buffer, length ) != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	return( fsync( stream->fd ) == 0 ? CRYPT_OK : CRYPT_ERROR_WRITE );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
#if defined( DDNAME_IO )
	/* If we're using ddnames, we only seek if we're not already at the 
	   start of the file to prevent postioning to 0 in a new empty PDS 
	   member, which fails */
	if( ( stream->bufCount > 0 || stream->bufPos > 0 || position > 0 ) )
		/* Drop through */
#endif /* MVS USS special-case */
	if( lseek( stream->fd, position, SEEK_SET ) == ( off_t ) -1 )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
#ifdef EBCDIC_CHARS
	char fileNameBuffer[ MAX_PATH_LENGTH ];

	fileName = bufferToEbcdic( fileNameBuffer, fileName );
#endif /* EBCDIC_CHARS */
#if defined( DDNAME_IO )
	/* Requires a RACF check to determine this */
	return( FALSE );
#else
	if( access( fileName, W_OK ) == -1 && errno != ENOENT )
		return( TRUE );
#endif /* OS-specific file accessibility check */

	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	/* Wipe the file.  This is a fairly crude function that performs a
	   single pass of overwriting the data with random data, it's not
	   possible to do much better than this without getting terribly OS-
	   specific.

	   You'll NEVER get rid of me, Toddy */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ 1024 ];
		const int bytesToWrite = min( length, 1024 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( write( stream->fd, buffer, bytesToWrite ) <= bytesToWrite )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}
	fsync( stream->fd );
	ftruncate( stream->fd, position );
	}

void fileClearToEOF( const STREAM *stream )
	{
	struct stat fstatInfo;
	long position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	if( fstat( stream->fd, &fstatInfo ) == -1 )
		return;
	position = lseek( stream->fd, 0, SEEK_CUR );
	length = fstatInfo.st_size - position;
	if( length <= 0 )
		return;	/* Nothing to do, exit */
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	struct stat fstatInfo;
#ifndef __APPLE__
	struct utimbuf timeStamp;
#endif /* OS-specific variable declarations */
#ifdef EBCDIC_CHARS
	char fileNameBuffer[ MAX_PATH_LENGTH ];
#endif /* EBCDIC_CHARS */
	int status;

	assert( fileName != NULL );

#ifdef EBCDIC_CHARS
	fileName = bufferToEbcdic( fileNameBuffer, fileName );
#endif /* EBCDIC_CHARS */

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		unlink( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	if( fstat( stream.fd, &fstatInfo ) == 0 )
		eraseFile( &stream, 0, fstatInfo.st_size );

	/* Reset the time stamps and delete the file */
	sFileClose( &stream );
#ifdef __APPLE__
	utimes( fileName, NULL );
#else
	memset( &timeStamp, 0, sizeof( struct utimbuf ) );
	utime( fileName, &timeStamp );
#endif /* OS-specific size and date-mangling */
	unlink( fileName );
	}

/* Build the path to a file in the cryptlib directory */

#include <pwd.h>

#ifdef DDNAME_IO

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* MVS dataset name userid.CRYPTLIB.filename.  We can't use a PDS since
	   multiple members have to be opened in write mode simultaneously */
	if( option == BUILDPATH_RNDSEEDFILE )
		strcpy( path, "//RANDSEED" );
	else
		{
		strcpy( path, "//CRYPTLIB." );
		strcat( path, fileName );
		}
	}
#else

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	struct passwd *passwd;
	int length;
#ifdef EBCDIC_CHARS
	char fileNameBuffer[ MAX_PATH_LENGTH ];
#endif /* EBCDIC_CHARS */

	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
#ifdef EBCDIC_CHARS
	fileName = bufferToEbcdic( fileNameBuffer, fileName );
	#pragma convlit( suspend )
#endif /* EBCDIC_CHARS */
	/* Get the path to the user's home directory */
	if( ( passwd = getpwuid( getuid() ) ) == NULL )
		return;		/* Huh?  User not in passwd file */
	if( ( length = strlen( passwd->pw_dir ) ) > MAX_PATH_LENGTH - 64 )
		/* You're kidding, right? */
		return;
	memcpy( path, passwd->pw_dir, length );
	if( path[ length - 1 ] != '/' )
		path[ length++ ] = '/';
	strcpy( path + length, ".cryptlib" );

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( ( option == BUILDPATH_CREATEPATH ) && access( path, F_OK ) == -1 && \
		mkdir( path, 0700 ) == -1 )
		{
		*path = '\0';
		return;
		}

	/* Add the filename to the path */
	strcat( path, "/" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
#ifdef EBCDIC_CHARS
	#pragma convlit( resume )
	ebcdicToAscii( path, strlen( path ) );
#endif /* EBCDIC_CHARS */
	}
#endif /* DDNAME_IO */

/****************************************************************************
*																			*
*							VxWorks File Stream Functions					*
*																			*
****************************************************************************/

#elif defined( __VXWORKS__ )

/* Some file functions can only be performed via ioctl()'s.  These include:

	chmod() - FIOATTRIBSET, dosFsLib, best-effort use only.

	flush() - FIOFLUSH, dosFsLib, rt11FsLib, fallback to FIOSYNC for nfsDrv.

	fstat() - FIOFSTATGET, dosFsLib, nfsDrv, rt11FsLib.

	ftruncate() - FIOTRUNC, dosFsLib.

	tell() - FIOWHERE, dosFsLib, nfsDrv, rt11FsLib.
	
	utime() - FIOTIMESET, not documented to be supported, but probably 
			present for utime() support in dirLib, best-effort use only.  
			For dosFsLib the only way to set the time is to install a time 
			hook via dosFsDateTimeInstall() before accessing the file, have 
			it report the desired time when the file is accessed, and then 
			uninstall it again afterwards, which is too unsafe to use 
			(it'd affect all files on the filesystem.

   Of these ftruncate() is the only problem, being supported only in 
   dosFsLib */

/* When performing file accesses, we use the Unix-style errno to interpret
   errors.  Unlike some other threaded systems which use preprocessor
   tricks to turn errno into a function that returns a value on a per-thread
   basis, VxWorks stores the last error in the TCB, so that errno can read
   it directly from the TCB.

   The error status is a 32-bit value, of which the high 16 bits are the 
   module number and the low 16 bits are the module-specific error.  However,
   module 0 is reserved for Unix-compatible errors, allowing direct use of
   the standard errno.h values.  This is complicated by the fact that the
   error may also be a module-specific one, so we need a special function to
   sort out the actual error details */

static int getErrorCode( const int defaultErrorCode )
	{
	const int moduleNo = errno >> 16;
	const int errNo = errno & 0xFFFFL;

	/* If it's a Unix-compatible error code, we can use it directly */
	if( moduleNo == 0 )
		{
		switch( errNo )
			{
			case EPERM:
			case EACCES:
			case EROFS:
				return( CRYPT_ERROR_PERMISSION );
			case ENOENT:
				return( CRYPT_ERROR_NOTFOUND );
			case ENOMEM:
				return( CRYPT_ERROR_MEMORY );
			case EBUSY:
				return( CRYPT_ERROR_TIMEOUT );
			case EEXIST:
				return( CRYPT_ERROR_DUPLICATE );
			}
		}
	else
		{
		/* It's a module-specific error, check whether there's anything
		   that we can use */
		}

	return( defaultErrorCode );
	}

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Try and open the file.  We don't have to jump through the hoops that
	   are required for Unix because VxWorks doesn't support links (or the
	   functions that Unix provides to detec them) */
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		{
		/* We're creating the file, we have to use creat() rather than 
		   open(), which can only open an existing file (well, except for
		   NFS filesystems) */
		if( ( stream->fd = creat( fileName, 0600 ) ) == ERROR )
			return( getErrorCode( CRYPT_ERROR_OPEN ) );
		}
	else
		{
		const int mode = ( ( mode & FILE_RW_MASK ) == FILE_READ ) ? \
						 O_RDONLY : O_RDWR;

		/* Open an existing file */
		if( ( stream->fd = open( fileName, mode, 0600 ) ) == ERROR )
			/* The open failed, determine whether it was because the file 
			   doesn't exist or because we can't use that access mode */
			return( getErrorCode( CRYPT_ERROR_OPEN ) );
		}

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	close( stream->fd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	if( ( bytesRead = read( stream->fd, buffer, length ) ) == ERROR )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	if( write( stream->fd, buffer, length ) != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage.  We use FIOFLUSH rather
   then FIOSYNC, since the latter re-reads the written data into I/O buffers
   while all we're interested in is forcing a commit.  However, nfsDrv only
   supports FIOSYNC, so we try that as a fallback if FIOFLUSH fails */

int fileFlush( STREAM *stream )
	{
	return( ioctl( stream->fd, FIOFLUSH, 0 ) == ERROR && \
			ioctl( stream->fd, FIOSYNC, 0 ) == ERROR ? \
			CRYPT_ERROR_WRITE : CRYPT_OK );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( lseek( stream->fd, position, SEEK_SET ) == ERROR )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	int fd;

	/* The only way to tell whether a file is writeable is to try to open it
	   for writing, since there's no access() function */
	if( ( fd = open( fileName, O_RDWR, 0600 ) ) == ERROR )
		{
		/* We couldn't open it, check to see whether this is because it 
		   doesn't exist or because it's not writeable */
		return( getErrorCode( CRYPT_ERROR_OPEN ) == CRYPT_ERROR_PERMISSION ? \
				TRUE : FALSE );
		}
	close( fd );
	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	BYTE buffer[ BUFSIZ * 2 ];

	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( write( stream->fd, buffer, bytesToWrite ) <= bytesToWrite )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}
	ioctl( stream->fd, FIOFLUSH, 0 );

	/* Truncate the file and if we're erasing the entire file, reset the 
	   attributes and timestamps.  We ignore return codes since some 
	   filesystems don't support these ioctl()'s */
	ioctl( stream->fd, FIOTRUNC, position );
	if( position <= 0 )
		{
		ioctl( stream->fd, FIOATTRIBSET, 0 );
		ioctl( stream->fd, FIOTIMESET, 0 );
		}
	}

void fileClearToEOF( const STREAM *stream )
	{
	struct stat statStruct;
	long position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file.  We use the 
	   long-winded method of determining the overall length since it doesn't
	   require the presence of dirLib for fstat() */
	position = ioctl( stream->fd, FIOWHERE, 0 );
	if( ioctl( stream->fd, FIOFSTATGET, ( int ) &statStruct ) != ERROR )
		length = statStruct.st_size  - position;
	else
		{
		/* No stat support, do it via lseek() instead */
		lseek( stream->fd, 0, SEEK_END );
		length = ioctl( stream->fd, FIOWHERE, 0 ) - position;
		lseek( stream->fd, position, SEEK_SET );
		}
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	struct stat statStruct;
	int length, status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it.  We use the long-winded 
	   method of determining the overall length since it doesn't require the 
	   presence of dirLib for fstat() */
	if( ioctl( stream.fd, FIOFSTATGET, ( int ) &statStruct ) != ERROR )
		length = statStruct.st_size;
	else
		{
		/* No stat support, do it via lseek() instead */
		lseek( stream.fd, 0, SEEK_END );
		length = ioctl( stream.fd, FIOWHERE, 0 );
		lseek( stream.fd, 0, SEEK_SET );
		}
	eraseFile( &stream, 0, length );

	sFileClose( &stream );

	/* Finally, delete the file */
	remove( fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

#if 0	/* Default path is just cwd, which isn't too useful */
	ioDefPathGet( path );
#else
	strcat( path, "/" );
#endif /* 0 */
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*							Windows File Stream Functions					*
*																			*
****************************************************************************/

#elif defined( __WIN32__ ) || defined( __WINCE__ )

/* File flags to use when accessing a file and attributes to use when
   creating a file.  For access we tell the OS that we'll be reading the 
   file sequentially, for creation we prevent the OS from groping around 
   inside the file.  We could also be (inadvertently) opening the client 
   side of a named pipe, which would allow a server to impersonate us if 
   we're not careful.  To handle this we set the impersonation level to 
   SecurityAnonymous, which prevents the server from doing anything with our 
   capabilities.  Note that the pipe flag SECURITY_SQOS_PRESENT flag clashes
   with the file flag FILE_FLAG_OPEN_NO_RECALL (indicating that data 
   shouldn't be moved in from remote storage if it currently resides there), 
   this isn't likely to be a problem.  The SECURITY_ANONYMOUS define 
   evaluates to zero, which means that it won't clash with any file flags, 
   however if future flags below the no-recall flag (0x00100000) are defined 
   for CreateFile() care needs to be taken that they don't run down into the 
   area used by the pipe flags around 0x000x0000 */

#ifndef __WINCE__
  #ifndef FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
  #endif /* VC++ <= 6.0 */
  #define FILE_FLAGS			( FILE_FLAG_SEQUENTIAL_SCAN | \
								  SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS )
  #define FILE_ATTRIBUTES		FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
#else
  /* WinCE doesn't recognise the extended file flags */
  #define FILE_FLAGS			0
  #define FILE_ATTRIBUTES		0
#endif /* Win32 vs.WinCE */

/* Older versions of the Windows SDK don't include the defines for system 
   directories so we define them ourselves if necesary */

#ifndef CSIDL_PERSONAL
  #define CSIDL_PERSONAL		0x05	/* 'My Documents' */
#endif /* !CSIDL_PERSONAL */
#ifndef CSIDL_APPDATA
  #define CSIDL_APPDATA			0x1A	/* '<luser name>/Application Data' */
#endif /* !CSIDL_APPDATA */
#ifndef CSIDL_FLAG_CREATE
  #define CSIDL_FLAG_CREATE		0x8000	/* Force directory creation */
#endif /* !CSIDL_FLAG_CREATE */
#ifndef SHGFP_TYPE_CURRENT
  #define SHGFP_TYPE_CURRENT	0
#endif /* !SHGFP_TYPE_CURRENT */

/* Windows CE doesn't have security mechanisms, so we make it look like Win95
   for ACL handling purposes */

#ifdef __WINCE__
  #define isWin95				TRUE
  #define checkUserKnown( x )	TRUE
#endif /* __WINCE__ */

/* Check whether a user's SID is known to a server providing a network 
   share, so that we can set file ACLs based on it */

#ifndef __WINCE__ 

#define TOKEN_BUFFER_SIZE	256
#define UNI_BUFFER_SIZE		( 256 + _MAX_PATH )
#define PATH_BUFFER_SIZE	( _MAX_PATH + 16 )

static BOOLEAN checkUserKnown( const char *fileName )
	{
	HANDLE hToken;
	BYTE uniBuffer[ UNI_BUFFER_SIZE ], tokenBuffer[ TOKEN_BUFFER_SIZE ];
	char pathBuffer[ PATH_BUFFER_SIZE ], nameBuffer[ PATH_BUFFER_SIZE ];
	char domainBuffer[ PATH_BUFFER_SIZE ], *fileNamePtr;
    UNIVERSAL_NAME_INFO *nameInfo = ( UNIVERSAL_NAME_INFO * ) uniBuffer;
	TOKEN_USER *pTokenUser = ( TOKEN_USER * ) tokenBuffer;
	SID_NAME_USE eUse;
	BOOLEAN isMappedDrive = FALSE, tokenOK = FALSE, retVal;
	int uniBufSize = UNI_BUFFER_SIZE, nameBufSize = PATH_BUFFER_SIZE;
	int domainBufSize = PATH_BUFFER_SIZE, serverNameLength;

	assert( sizeof( UNIVERSAL_NAME_INFO ) + _MAX_PATH <= UNI_BUFFER_SIZE );

	/* Win95 doesn't have any ACL-based security, there's nothing to do */
	if( isWin95 )
		return( TRUE );

	/* Canonicalise the path name.  This turns relative paths into absolute 
	   ones and converts forward to backwards slashes.  The latter is
	   necessary because while the Windows filesystem functions will accept 
	   Unix-style forward slashes in paths, the WNetGetUniversalName() 
	   networking function doesn't */
	if( GetFullPathName( fileName, PATH_BUFFER_SIZE, pathBuffer, 
						 &fileNamePtr ) )
		fileName = pathBuffer;

	/* If the path is too short to contain a drive letter or UNC path, it 
	   must be local */
	if( strlen( fileName ) <= 2 )
		return( TRUE );

	/* If there's a drive letter present, check whether it's a local or
	   remote drive.  GetDriveType() is rather picky about what it'll accept 
	   so we have to extract just the drive letter from the path */
	if( fileName[ 1 ] == ':' )
		{
		char drive[ 8 ];

		memcpy( drive, fileName, 2 );
		drive[ 2 ] = '\0';
		if( GetDriveType( drive ) != DRIVE_REMOTE )
			/* It's a local drive, the user should be known */
			return( TRUE );
		isMappedDrive = TRUE;
		}
	else
		/* If it's not a UNC name, it's local (or something weird like a 
		   mapped web page to which we shouldn't be writing keys anyway) */
		if( memcmp( fileName, "\\\\", 2 ) )
			return( TRUE );

	/* If it's a mapped network drive, get the name in UNC form.  What to do
	   in case of failure is a bit tricky.  If we get here we know that it's 
	   a network share, but if there's some problem mapping it to a UNC (the 
	   usual reason for this will be that there's a problem with the network 
	   and the share is a cached remnant of a persistent connection), all we 
	   can do is fail safe and hope that the user is known */
	if( isMappedDrive )
		{
		typedef DWORD ( WINAPI *WNETGETUNIVERSALNAMEA )( LPCSTR lpLocalPath,
										DWORD dwInfoLevel, LPVOID lpBuffer,
										LPDWORD lpBufferSize );
		WNETGETUNIVERSALNAMEA pWNetGetUniversalNameA;
		HINSTANCE hMPR;
		BOOLEAN gotUNC = FALSE;

		/* Load the MPR library.  We can't (safely) use an opportunistic 
		   GetModuleHandle() before the LoadLibrary() for this because the 
		   code that originally loaded the DLL might do a FreeLibrary in 
		   another thread, causing the library to be removed from under us.
		   In any case LoadLibrary does this for us, merely incrementing the
		   reference count if the DLL is already loaded */
	 	hMPR = LoadLibrary( "Mpr.dll" );
		if( hMPR == NULL )
			/* Should never happen, we can't have a mapped network drive if
			   no network is available */
			return( TRUE );		/* Default fail-safe */

		/* Get the translated UNC name.  The UNIVERSAL_NAME_INFO struct is
		   one of those variable-length ones where the lpUniversalName 
		   member points to extra data stored off the end of the struct, so
		   we overlay it onto a much larger buffer */
		pWNetGetUniversalNameA = ( WNETGETUNIVERSALNAMEA ) \
								 GetProcAddress( hMPR, "WNetGetUniversalNameA" );
		if( pWNetGetUniversalNameA != NULL && \
			pWNetGetUniversalNameA( fileName, UNIVERSAL_NAME_INFO_LEVEL, 
									nameInfo, &uniBufSize ) == NO_ERROR )
			{
			fileName = nameInfo->lpUniversalName;
			gotUNC = TRUE;
			}
		FreeLibrary( hMPR );
		if( !gotUNC )
			return( TRUE );		/* Default fail-safe */
		}
	assert( !memcmp( fileName, "\\\\", 2 ) );

	/* We've got the network share in UNC form, extract the server name.  If
	   for some reason the name is still an absolute path, the following will 
	   convert it to "x:\", which is fine */
	for( serverNameLength = 2; \
		 fileName[ serverNameLength ] && fileName[ serverNameLength ] != '\\'; \
		 serverNameLength++ );
	memmove( pathBuffer, fileName, serverNameLength );
	memcpy( pathBuffer + serverNameLength, "\\", 2 );

	/* Check whether the current user's SID is known to the server */
	if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) || \
		OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
		DWORD cbTokenUser;

		tokenOK = GetTokenInformation( hToken, TokenUser, pTokenUser, 
									   TOKEN_BUFFER_SIZE, &cbTokenUser );
		CloseHandle( hToken );
		}
	if( !tokenOK )
		return( TRUE );			/* Default fail-safe */
	retVal = LookupAccountSid( pathBuffer, pTokenUser->User.Sid, 
							   nameBuffer, &nameBufSize, 
							   domainBuffer, &domainBufSize, &eUse );
	if( !retVal && GetLastError() == ERROR_NONE_MAPPED )
		/* The user with this SID isn't known to the server */
		return( FALSE );

	/* Either the user is known to the server or it's a fail-safe */
	return( TRUE );
	}
#endif /* __WINCE__ */

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
#ifndef __WINCE__
	HANDLE hFile;
	UINT uErrorMode;
	const char *fileNamePtr = fileName;
#else
	wchar_t fileNameBuffer[ _MAX_PATH + 16 ], *fileNamePtr = fileNameBuffer;
#endif /* __WINCE__ */
	void *aclInfo = NULL;
	int status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;

	/* Convert the filename to the native character set if necessary */
#ifdef __WINCE__
	status = asciiToUnicode( fileNameBuffer, fileName, 
							 strlen( fileName ) + 1 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_OPEN );
#endif /* __WINCE__ */

	/* Don't allow the use of escapes that disable path parsing, and make
	   sure that the path has a sensible length */
	if( !memcmp( fileNamePtr, "\\\\", 2 ) )
		{
		const int length = strlen( ( char * ) fileNamePtr );

		if( length >= 4 && memcmp( fileNamePtr, "\\\\?\\", 4 ) )
			return( CRYPT_ERROR_OPEN );
		}
	else
		if( !memcmp( fileNamePtr, L"\\\\", 4 ) )
			{
			const int length = wcslen( ( wchar_t * ) fileNamePtr );

			if( length >= 8 && memcmp( fileNamePtr, L"\\\\?\\", 8 ) )
				return( CRYPT_ERROR_OPEN );
			}

	/* If we're creating the file and we don't want others to get to it, set
	   up the security attributes to reflect this if the OS supports it.  
	   Unfortunately creating the file with ACLs doesn't always work when 
	   the file is located on a network share because what's:

		create file, ACL = user SID access

	   on a local drive can become:

		create file, ACL = <unknown SID> access

	   on the network share if the user is accessing it as a member of a 
	   group and their individual SID isn't known to the server.  As a 
	   result, they can't read the file that they've just created.  To get 
	   around this, we need to perform an incredibly convoluted check (via
	   checkUserKnown()) to see whether the path is a network path and if 
	   so, if the user is known to the server providing the network share */
	if( !isWin95 && ( mode & FILE_WRITE ) && ( mode & FILE_PRIVATE ) && \
		checkUserKnown( fileNamePtr ) && \
		( aclInfo = initACLInfo( FILE_GENERIC_READ | \
								 FILE_GENERIC_WRITE ) ) == NULL )
		return( CRYPT_ERROR_OPEN );

	/* Check that the file isn't a special file type, for example a device
	   pseudo-file that can crash the system under Win95/98/ME/whatever.
	   WinCE doesn't have these pseudo-files, so this function doesn't
	   exist there.  In theory we could check for the various 
	   FILE_ATTRIBUTE_xxxROM variations, but that'll be handled 
	   automatically by CreateFile()*/
#ifndef __WINCE__
	hFile = CreateFile( fileNamePtr, GENERIC_READ, FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_FLAGS, NULL );
	if( hFile != INVALID_HANDLE_VALUE )
		{
		const DWORD type = GetFileType( hFile );

		CloseHandle( hFile );
		if( type != FILE_TYPE_DISK )
			{
			freeACLInfo( aclInfo );
			return( CRYPT_ERROR_OPEN );
			}
		}
#endif /* __WINCE__ */

	/* Try and open the file */
#ifndef __WINCE__
	uErrorMode = SetErrorMode( SEM_FAILCRITICALERRORS );
#endif /* __WINCE__ */
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		{
		/* If we're creating the file, we need to remove any existing file
		   of the same name before we try and create a new one, otherwise
		   the OS will pick up the permissions for the existing file and
		   apply them to the new one.  This is safe because if an attacker
		   tries to slip in a wide-open file between the delete and the
		   create, we'll get a file-already-exists status returned that we
		   can trap and turn into an error */
		DeleteFile( fileNamePtr );
		stream->hFile = CreateFile( fileNamePtr, GENERIC_READ | GENERIC_WRITE, 0,
									getACLInfo( aclInfo ), CREATE_ALWAYS, 
									FILE_ATTRIBUTES | FILE_FLAGS, NULL );
		if( stream->hFile != INVALID_HANDLE_VALUE && \
			GetLastError() == ERROR_ALREADY_EXISTS )
			{
			/* There was already something there that wasn't hit by the
			   delete, we can't be sure that the file has the required 
			   semantics */
			CloseHandle( stream->hFile );
			DeleteFile( fileNamePtr );
			stream->hFile = INVALID_HANDLE_VALUE;
			}
		}
	else
		{
		const int openMode = ( ( mode & FILE_RW_MASK ) == FILE_READ ) ? \
							 GENERIC_READ : GENERIC_READ | GENERIC_WRITE;
		const int shareMode = ( mode & FILE_EXCLUSIVE_ACCESS ) ? \
							  0 : FILE_SHARE_READ;

		stream->hFile = CreateFile( fileNamePtr, openMode, shareMode, NULL,
									OPEN_EXISTING, FILE_FLAGS, NULL );
		}
#ifndef __WINCE__
	SetErrorMode( uErrorMode );
#endif /* __WINCE__ */
	if( stream->hFile == INVALID_HANDLE_VALUE )
		{
		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		switch( GetLastError() )
			{
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				status = CRYPT_ERROR_NOTFOUND;
				break;

			case ERROR_ACCESS_DENIED:
				status = CRYPT_ERROR_PERMISSION;
				break;

			case ERROR_BUSY:
				status = CRYPT_ERROR_TIMEOUT;
				break;

			default:
				status = CRYPT_ERROR_OPEN;
			}
		}

	/* Clean up */
	freeACLInfo( aclInfo );
	return( status );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	CloseHandle( stream->hFile );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
    DWORD bytesRead;

	if( !ReadFile( stream->hFile, buffer, length, &bytesRead, NULL ) )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	DWORD bytesWritten;

	if( !WriteFile( stream->hFile, buffer, length, &bytesWritten, NULL ) || \
		( int ) bytesWritten != length )
		return( CRYPT_ERROR_WRITE );

	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	return( FlushFileBuffers( stream->hFile ) ? CRYPT_OK : CRYPT_ERROR_WRITE );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( SetFilePointer( stream->hFile, position, NULL,
						FILE_BEGIN ) == 0xFFFFFFFF )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	HANDLE hFile;
#ifdef __WINCE__
	wchar_t fileNameBuffer[ _MAX_PATH + 16 ], *fileNamePtr = fileNameBuffer;
	int status;
#else
	const char *fileNamePtr = fileName;
#endif /* __WINCE__ */

	assert( fileName != NULL );

	/* Convert the filename to the native character set if necessary */
#ifdef __WINCE__
	status = asciiToUnicode( fileNameBuffer, fileName, 
							 strlen( fileName ) + 1 );
	if( cryptStatusError( status ) )
		return( TRUE );
#endif /* __WINCE__ */

	/* The only way to tell whether a file is writeable is to try to open it
	   for writing.  An access()-based check is pointless because it just
	   calls GetFileAttributes() and checks for the read-only bit being set.
	   Even if we wanted to check for this basic level of access, it 
	   wouldn't work because writes can still be blocked if it's a read-only 
	   file system or a network share */
	hFile = CreateFile( fileNamePtr, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		return( ( GetLastError() == ERROR_ACCESS_DENIED ) ? TRUE : FALSE );
	CloseHandle( hFile );

	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	/* Wipe the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ 1024 ];
		DWORD bytesWritten;
		int bytesToWrite = min( length, 1024 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		WriteFile( stream->hFile, buffer, bytesToWrite, &bytesWritten, NULL );
		length -= bytesToWrite;
		}

	/* Truncate the file and if we're erasing the entire file, reset the 
	   timestamps.  The delete just marks the file as deleted rather than 
	   actually deleting it, but there's not much information that can be 
	   recovered without a magnetic force microscope.  The call to 
	   FlushFileBuffers() ensures that the changed data gets committed 
	   before the delete call comes along.  If we didn't do this then the OS 
	   would drop all changes once DeleteFile() was called, leaving the 
	   original more or less intact on disk */
	SetFilePointer( stream->hFile, position, NULL, FILE_BEGIN );
	SetEndOfFile( stream->hFile );
	if( position <= 0 )
		SetFileTime( stream->hFile, 0, 0, 0 );
	FlushFileBuffers( stream->hFile );
	}

void fileClearToEOF( const STREAM *stream )
	{
	long position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	if( ( position = SetFilePointer( stream->hFile, 0, NULL,
									 FILE_CURRENT ) ) == 0xFFFFFFFF )
		return;
	length = GetFileSize( stream->hFile, NULL ) - position;
	if( length <= 0 )
		return;	/* Nothing to do, exit */
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
#ifdef __WINCE__
	wchar_t fileNameBuffer[ _MAX_PATH + 16 ], *fileNamePtr = fileNameBuffer;
#else
	const char *fileNamePtr = fileName;
#endif /* __WINCE__ */
	int status;

	assert( fileName != NULL );

	/* Convert the filename to the native character set if necessary */
#ifdef __WINCE__
	asciiToUnicode( fileNameBuffer, fileName, strlen( fileName ) + 1 );
#endif /* __WINCE__ */

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		DeleteFile( fileNamePtr );
		return;
		}
	eraseFile( &stream, 0, GetFileSize( stream.hFile, NULL ) );
	sFileClose( &stream );
	DeleteFile( fileNamePtr );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
#if defined( __WIN32__ )
	typedef HRESULT ( WINAPI *SHGETFOLDERPATH )( HWND hwndOwner,
										int nFolder, HANDLE hToken,
										DWORD dwFlags, LPTSTR lpszPath );
	SHGETFOLDERPATH pSHGetFolderPath;
	OSVERSIONINFO osvi = { sizeof( OSVERSIONINFO ) };
	BOOLEAN gotPath = FALSE;
	char *pathPtr = path;
#elif defined( __WINCE__ )
	wchar_t pathBuffer[ _MAX_PATH + 16 ], *pathPtr = pathBuffer;
	BOOLEAN gotPath = FALSE;
#elif defined( __WIN16__ )
	char *pathPtr = path;
#endif /* Win32 vs. WinCE */

	assert( ( ( option == BUILDPATH_CREATEPATH || \
				option == BUILDPATH_GETPATH ) && fileName != NULL ) || \
			( option == BUILDPATH_RNDSEEDFILE && fileName == NULL ) );

	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

#if defined( __WIN32__ )
	/* Build the path to the configuration file if necessary.  We can't 
	   (safely) use an opportunistic GetModuleHandle() before the 
	   LoadLibrary() for this because the code that originally loaded the 
	   DLL might do a FreeLibrary in another thread, causing the library to 
	   be removed from under us.  In any case LoadLibrary does this for us, 
	   merely incrementing the reference count if the DLL is already 
	   loaded */
	GetVersionEx( &osvi );
	if( osvi.dwMajorVersion <= 4 )
		{
		HINSTANCE hComCtl32, hSHFolder;

		/* Try and find the location of the closest thing that Windows has 
		   to a home directory.  This is a bit of a problem function in that 
		   both the function name and parameters have changed over time, and 
		   it's only included in pre-Win2K versions of the OS via a kludge 
		   DLL that takes the call and redirects it to the appropriate 
		   function anderswhere.  Under certain (very unusual) circumstances 
		   this kludge can fail if shell32.dll and comctl32.dll aren't 
		   mapped into the process' address space yet, so we have to check 
		   for the presence of these DLLs in memory as well as for the 
		   successful load of the kludge DLL */
	 	hComCtl32 = LoadLibrary( "ComCtl32.dll" );
		if( ( hSHFolder = LoadLibrary( "SHFolder.dll" ) ) != NULL )
			{
			pSHGetFolderPath = ( SHGETFOLDERPATH ) \
						   GetProcAddress( hSHFolder, "SHGetFolderPathA" );
			if( pSHGetFolderPath != NULL && \
				pSHGetFolderPath( NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
								  NULL, SHGFP_TYPE_CURRENT, path ) == S_OK )
				gotPath = TRUE;
			FreeLibrary( hSHFolder );
			}
		FreeLibrary( hComCtl32 );
		}
	else
		{
		HINSTANCE hShell32;

		/* Try and find the location of the closest thing that Windows has 
		   to a home directory */
		hShell32 = LoadLibrary( "Shell32.dll" );
		pSHGetFolderPath = ( SHGETFOLDERPATH ) \
						   GetProcAddress( hShell32, "SHGetFolderPathA" );
		if( pSHGetFolderPath != NULL && \
			pSHGetFolderPath( NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
							  NULL, SHGFP_TYPE_CURRENT, pathPtr ) == S_OK )
			gotPath = TRUE;
		FreeLibrary( hShell32 );
		}
	if( !gotPath )
		{
		/* Fall back to dumping it in the Windows directory.  This will 
		   probably fail on systems where the user doesn't have privs to 
		   write there, but if SHGetFolderPath() fails it's an indication 
		   that something's wrong anyway.
		   
		   If this too fails, we fall back to the root dir.  This has the
		   same problems as the Windows directory for non-admin users, but
		   we try it just in case the user manually copied the config there 
		   as a last resort */
		if( !GetWindowsDirectory( pathPtr, _MAX_PATH - 32 ) )
			*pathPtr = '\0';
		}
	else
		if( strlen( pathPtr ) < 3 )
			{
			/* Under WinNT and Win2K the LocalSystem account doesn't have
			   its own profile, so SHGetFolderPath() will report success but 
			   return a zero-length path if we're running as a service.  In
			   this case we use the nearest equivalent that LocalSystem has
			   to its own directories, which is the Windows directory.  This
			   is safe because LocalSystem always has permission to write
			   there */
			if( !GetWindowsDirectory( pathPtr, _MAX_PATH - 32 ) )
				*pathPtr = '\0';
			}
	strcat( pathPtr, "\\cryptlib" );
#elif defined( __WINCE__ )
	if( SHGetSpecialFolderPath( NULL, pathPtr, CSIDL_APPDATA, TRUE ) || \
		SHGetSpecialFolderPath( NULL, pathPtr, CSIDL_PERSONAL, TRUE ) )
		/* We have to check for the availability of two possible locations 
		   since some older PocketPC versions don't have CSIDL_APPDATA */
		gotPath = TRUE;
	if( !gotPath )
		/* This should never happen under WinCE since the get-path 
		   functionality is always available */
		wcscpy( pathPtr, L"\\Windows" );
	wcscat( pathPtr, L"\\cryptlib" );
#elif defined( __WIN16__ )
	GetWindowsDirectory( pathPtr, _MAX_PATH - 32 );
	strcat( pathPtr, "\\cryptlib" );
#endif /* Win32 vs. WinCE */

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( ( option == BUILDPATH_CREATEPATH ) && \
		GetFileAttributes( pathPtr ) == 0xFFFFFFFFUL )
		{
		void *aclInfo = NULL;
		BOOLEAN retVal = TRUE;

		if( !isWin95 && \
			( aclInfo = initACLInfo( FILE_ALL_ACCESS ) ) == NULL )
			retVal = FALSE;
		else
			retVal = CreateDirectory( pathPtr, getACLInfo( aclInfo ) );
		freeACLInfo( aclInfo );
		if( !retVal )
			{
			*path = '\0';
			return;
			}
		}
#if defined( __WINCE__ )
	unicodeToAscii( path, pathPtr, wcslen( pathPtr ) + 1 );
#endif /* __WINCE__ */

	/* Add the filename to the path */
	strcat( path, "\\" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*									Xilinx XMK								*
*																			*
****************************************************************************/

#elif defined( __XMK__ )

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const char *modes[] = { MODE_READ, MODE_READ,
								   MODE_CREATE, MODE_READWRITE };

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;
	openMode = modes[ mode & FILE_RW_MASK ];

	/* If we're trying to read from the file, check whether it exists */
	if( ( mode & FILE_READ ) && mfs_exists_file( fileName ) != 1 )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and open the file */
	if( ( stream->fd = mfs_file_open( fileName, openMode ) ) < 0 )
		return( CRYPT_ERROR_OPEN );

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	mfs_file_close( stream->fd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	if( ( bytesRead = mfs_file_read( stream->fd, buffer, length ) ) < 0 )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	if( mfs_file_write( stream->fd, buffer, length ) < 0 )
		return( CRYPT_ERROR_READ );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	/* Since the backing store is flash memory and writing simply copies it
	   to flash, there's no real way to flush data to disk */
	return( CRYPT_OK );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	/* MFS doesn't support any type of writing other than appending to the
	   end of the file, so if we try and seek in a non-readonly file we
	   return an error */
	if( !( stream->flags & STREAM_FLAG_READONLY ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_WRITE );
		}

	if( mfs_file_lseek( stream->fd, position, MFS_SEEK_SET ) < 0 )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
	/* All non-ROM filesystems are writeable under MFS, in theory a ROM-based
	   FS would be non-writeable but there's no way to tell whether the 
	   underlying system is ROM or RAM */
	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).  Since
   MFS doesn't support any type of file writes except appending data to an
   existing file, the best that we can do is to simply delete the file 
   without trying to overwrite it */

void fileClearToEOF( const STREAM *stream )
	{
	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	return;
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
	int status;

	assert( fileName != NULL );

	/* Delete the file */
	mfs_delete_file( fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
	strcpy( path, "/cryptlib/" );

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( option == BUILDPATH_CREATEPATH && mfs_exists_file( path ) != 2 )
		{
		/* The directory doesn't exist, try and create it */
		if( mfs_create_dir( path ) <= 0 )
			{
			*path = '\0';
			return;
			}
		}

	/* Add the filename to the path */
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
	}

/****************************************************************************
*																			*
*						Everything Else (Generic stdio)						*
*																			*
****************************************************************************/

#else

/* BC++ 3.1 is rather anal-retentive about not allowing extensions when in
   ANSI mode */

#if defined( __STDC__ ) && ( __BORLANDC__ == 0x410 )
  #define fileno( filePtr )		( ( filePtr )->fd )
#endif /* BC++ 3.1 in ANSI mode */

/* When checking whether a file is read-only we also have to check (via 
   errno) to make sure that the file actually exists since the access check 
   will return a false positive for a nonexistant file */

#if defined( __MSDOS16__ ) || defined( __OS2__ ) || defined( __WIN16__ )
  #include <errno.h>
#endif /* __MSDOS16__ || __OS2__ || __WIN16__ */

/* Some OS'es don't define W_OK for the access check */

#ifndef W_OK
  #define W_OK				2
#endif /* W_OK */

/* Symbolic defines for the stdio file access modes */

#define MODE_READ			"rb"
#define MODE_WRITE			"wb"
#define MODE_READWRITE		"rb+"

/* Open/close a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const char *modes[] = { MODE_READ, MODE_READ,
								   MODE_WRITE, MODE_READWRITE };
	const char *openMode;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_FILE;
	if( ( mode & FILE_RW_MASK ) == FILE_READ )
		stream->flags = STREAM_FLAG_READONLY;
	openMode = modes[ mode & FILE_RW_MASK ];

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

#if defined( __MSDOS16__ ) || defined( __WIN16__ ) || defined( __WINCE__ ) || \
	defined( __OS2__ ) || defined( __SYMBIAN32__ ) 
	/* Try and open the file */
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		/* The open failed, determine whether it was because the file doesn't
		   exist or because we can't use that access mode */
		return( ( access( fileName, 0 ) == -1 ) ? CRYPT_ERROR_NOTFOUND : \
												  CRYPT_ERROR_OPEN );
#elif defined( __TANDEMNSK__ )
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		return( ( errno == ENOENT ) ? \
				CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );
#else
  #error Need to add file accessibility call
#endif /* OS-specific file accessibility check */

	return( CRYPT_OK );
	}

int sFileClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Close the file and clear the stream structure */
	fclose( stream->filePtr );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Read/write a block of data from/to a file stream */

int fileRead( STREAM *stream, void *buffer, const int length )
	{
	int bytesRead;

	if( ( bytesRead = fread( buffer, 1, length, stream->filePtr ) ) < length && \
		( bytesRead < 0 || ferror( stream->filePtr ) ) )
		return( CRYPT_ERROR_READ );
	return( bytesRead );
	}

int fileWrite( STREAM *stream, const void *buffer, const int length )
	{
	if( fwrite( buffer, 1, length, stream->filePtr ) != length )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Commit data in a file stream to backing storage */

int fileFlush( STREAM *stream )
	{
	return( fflush( stream->filePtr ) == 0 ? CRYPT_OK : CRYPT_ERROR_WRITE );
	}

/* Change the read/write position in a file */

int fileSeek( STREAM *stream, const long position )
	{
	if( fseek( stream->filePtr, position, SEEK_SET ) )
		return( CRYPT_ERROR_WRITE );
	return( CRYPT_OK );
	}

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
#if defined( __MSDOS16__ ) || defined( __WIN16__ ) || defined( __OS2__ ) || \
	defined( __SYMBIAN32__ ) || defined( __BEOS__ )
	if( access( fileName, W_OK ) == -1 && errno != ENOENT )
		return( TRUE );
#elif defined( __TANDEMNSK__ )
	FILE *filePtr;

	if( ( filePtr = fopen( fileName, "rb+" ) ) == NULL )
		{
		if( errno == EACCES )
			return( TRUE );
		}
	else
		fclose( filePtr );
#else
  #error Need to add file accessibility call
#endif /* OS-specific file accessibility check */

	return( FALSE );
	}

/* File deletion functions: Wipe a file from the current position to EOF,
   and wipe and delete a file (although it's not terribly rigorous).
   Vestigia nulla retrorsum */

static void eraseFile( const STREAM *stream, long position, long length )
	{
	BYTE buffer[ BUFSIZ * 2 ];

	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		RESOURCE_DATA msgData;
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure that we fill the buffer with random data for 
		   each write, otherwise compressing filesystems will just compress 
		   it to nothing */
		setMessageData( &msgData, buffer, bytesToWrite );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( fwrite( buffer, 1, bytesToWrite, stream->filePtr ) == 0 )
			break;	/* An error occurred while writing, exit */
		length -= bytesToWrite;
		}
	fflush( stream->filePtr );

	/* Truncate the file and if we're erasing the entire file, reset the 
	   timestamps.  This is only possible through a file handle on some 
	   systems, on others the caller has to do it via the filename */
#if defined( __AMIGA__ )
	SetFileSize( fileHandle, OFFSET_BEGINNING, position );
#elif defined( __MSDOS16__ ) || defined( __MSDOS32__ )
	chsize( fileHandle, position );
#elif defined( __OS2__ )
	DosSetFileSize( fileHandle, position );
#elif defined( __WIN16__ )
	_chsize( fileHandle, position );
#endif /* OS-specific size mangling */
	if( position <= 0 )
		{
#if defined( __MSDOS16__ ) || defined( __MSDOS32__ )
		struct ftime fileTime;
#endif /* OS-specific variable declarations */

#if defined( __MSDOS16__ ) || defined( __MSDOS32__ )
		memset( &fileTime, 0, sizeof( struct ftime ) );
		setftime( fileHandle, &fileTime );
#endif /* OS-specific date mangling */
		}
	}

void fileClearToEOF( const STREAM *stream )
	{
	long position, length;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );

	/* Wipe everything past the current position in the file */
	position = ftell( stream->filePtr );
	fseek( stream->filePtr, 0, SEEK_END );
	length = ftell( stream->filePtr ) - position;
	fseek( stream->filePtr, position, SEEK_SET );
	eraseFile( stream, position, length );
	}

void fileErase( const char *fileName )
	{
	STREAM stream;
#if defined( __AMIGA__ )
	struct DateStamp dateStamp;
#elif defined( __OS2__ )
	FILESTATUS info;
#elif defined( __WIN16__ )
	HFILE hFile;
#endif /* OS-specific variable declarations */
	int fileHandle, length, status;

	assert( fileName != NULL );

	/* Try and open the file so that we can erase it.  If this fails, the 
	   best that we can do is a straight unlink */
	status = sFileOpen( &stream, fileName,
						FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
	if( cryptStatusError( status ) )
		{
		remove( fileName );
		return;
		}

	/* Determine the size of the file and erase it */
	fileHandle = fileno( stream.filePtr );
	fseek( stream.filePtr, 0, SEEK_END );
	length = ( int ) ftell( stream.filePtr );
	fseek( stream.filePtr, 0, SEEK_SET );
	eraseFile( stream, 0, length );

	/* Truncate the file to 0 bytes if we couldn't do it in eraseFile, reset 
	   the time stamps, and delete it */
	sFileClose( &stream );
#if defined( __AMIGA__ )
	memset( dateStamp, 0, sizeof( struct DateStamp ) );
	SetFileDate( fileName, &dateStamp );
#elif defined( __OS2__ )
	DosQueryPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ) );
	memset( &info.fdateLastWrite, 0, sizeof( info.fdateLastWrite ) );
	memset( &info.ftimeLastWrite, 0, sizeof( info.ftimeLastWrite ) );
	memset( &info.fdateLastAccess, 0, sizeof( info.fdateLastAccess ) );
	memset( &info.ftimeLastAccess, 0, sizeof( info.ftimeLastAccess ) );
	memset( &info.fdateCreation, 0, sizeof( info.fdateCreation ) );
	memset( &info.ftimeCreation, 0, sizeof( info.ftimeCreation ) );
	DosSetPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ), 0 );
#elif defined( __WIN16__ )
	/* Under Win16 we can't really do anything without resorting to MSDOS int
	   21h calls, the best we can do is truncate the file using _lcreat() */
	hFile = _lcreat( fileName, 0 );
	if( hFile != HFILE_ERROR )
		_lclose( hFile );
#endif /* OS-specific size and date-mangling */

	/* Finally, delete the file */
	remove( fileName );
	}

/* Build the path to a file in the cryptlib directory */

void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option )
	{
#if defined( __OS2__ )
	ULONG aulSysInfo[ 1 ] = { 0 };
#elif defined( __WIN16__ )
	BOOLEAN gotPath = FALSE;
#endif /* OS-specific info */

	/* Make sure that the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
#if defined( __MSDOS__ )
	strcpy( path, "c:/dos/" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
#elif defined( __WIN16__ )
	GetWindowsDirectory( path, _MAX_PATH - 32 );
	strcat( path, "\\cryptlib" );

	/* If we're being asked to create the cryptlib directory and it doesn't
	   already exist, create it now */
	if( ( option == BUILDPATH_CREATEPATH ) && \
		GetFileAttributes( path ) == 0xFFFFFFFFUL && \
		!CreateDirectory( path, NULL ) )
		{
		*path = '\0';
		return;
		}

	/* Add the filename to the path */
	strcat( path, "\\" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
#elif defined( __OS2__ )
	DosQuerySysInfo( QSV_BOOT_DRIVE, QSV_BOOT_DRIVE, ( PVOID ) aulSysInfo,
					 sizeof( ULONG ) );		/* Get boot drive info */
	if( *aulSysInfo == 0 )
		return;		/* No boot drive info */
	path[ 0 ] = *aulSysInfo + 'A' - 1;
	strcpy( path + 1, ":\\OS2\\" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
#elif defined( __TANDEMNSK__ )
	strcpy( path, "$system.system." );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed" );
	else
		strcat( path, fileName );
#elif defined( __SYMBIAN32__ )
	strcpy( path, "C:\\SYSTEM\\DATA\\" );
	if( option == BUILDPATH_RNDSEEDFILE )
		strcat( path, "randseed.dat" );
	else
		{
		strcat( path, fileName );
		strcat( path, ".p15" );
		}
#else
  #error Need to add function to build the config file path
#endif /* OS-specific file path creation */
	}
#endif /* OS-specific file stream handling */
