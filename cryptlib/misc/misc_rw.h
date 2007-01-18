/****************************************************************************
*																			*
*				Miscellaneous (Non-ASN.1) Routines Header File				*
*					  Copyright Peter Gutmann 1992-2004						*
*																			*
****************************************************************************/

#ifndef _MISCRW_DEFINED

#define _MISCRW_DEFINED

#include <time.h>
#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Constants and Macros						*
*																			*
****************************************************************************/

/* Sizes of encoded integer values */

#define UINT16_SIZE		2
#define UINT32_SIZE		4
#define UINT64_SIZE		8

/****************************************************************************
*																			*
*								Function Prototypes							*
*																			*
****************************************************************************/

/* Read 16-bit integer values.  Although in theory we could perform the read
   much more simply with ( sgetc( stream ) << 8 ) | sgetc( stream ), this
   will break with some compilers that reorder expressions */

int readUint16( STREAM *stream );
int writeUint16( STREAM *stream, const int value );

/* Read and write 32- and 64-bit integer values */

int readUint32( STREAM *stream );
int writeUint32( STREAM *stream, const long value );
int readUint64( STREAM *stream );
int writeUint64( STREAM *stream, const long value );

/* Read and write 32- and 64-bit time values */

int readUint32Time( STREAM *stream, time_t *timeVal );
int writeUint32Time( STREAM *stream, const time_t timeVal );
int readUint64Time( STREAM *stream, time_t *timeVal );
int writeUint64Time( STREAM *stream, const time_t timeVal );

/* Read and write strings preceded by 32-bit lengths */

#define sizeofString32( string, stringLength ) \
		( ( stringLength > 0 ) ? ( UINT32_SIZE + stringLength ) : \
								 ( UINT32_SIZE + strlen( string ) ) )

int readString32( STREAM *stream, void *string, int *stringLength,
				  const int maxLength );
int writeString32( STREAM *stream, const void *string,
				   const int stringLength );

/* Read a raw object preceded by a 32-bit length */

int readRawObject32( STREAM *stream, void *buffer, int *bufferLength,
					 const int maxLength );

/* Read a universal type and discard it (used to skip unknown or unwanted
   types) */

int readUniversal16( STREAM *stream );
int readUniversal32( STREAM *stream );

/* Read and write unsigned (large) integers preceded by 16- and 32-bit
   lengths, lengths in bits */

#define sizeofInteger16U( integerLength )	( UINT16_SIZE + integerLength )
#define sizeofInteger32( integer, integerLength ) \
		( UINT32_SIZE + ( ( ( ( BYTE * ) integer )[ 0 ] & 0x80 ) ? 1 : 0 ) + \
						integerLength )

int readInteger16U( STREAM *stream, void *integer, int *integerLength,
					const int minLength, const int maxLength );
int readInteger16Ubits( STREAM *stream, void *integer, int *integerLength,
						const int minLength, const int maxLength );
int readInteger32( STREAM *stream, void *integer, int *integerLength,
				   const int minLength, const int maxLength );
int readInteger32Ubits( STREAM *stream, void *integer, int *integerLength,
						const int minLength, const int maxLength );
int writeInteger16U( STREAM *stream, const void *integer,
					 const int integerLength );
int writeInteger16Ubits( STREAM *stream, const void *integer,
						 const int integerLength );
int writeInteger32( STREAM *stream, const void *integer,
					const int integerLength );
int writeInteger32Ubits( STREAM *stream, const void *integer,
						 const int integerLength );

/* Read and write bignum integers */

int readBignumInteger16U( STREAM *stream, void *bignum, const int minLength,
						  const int maxLength );
int writeBignumInteger16U( STREAM *stream, const void *bignum );
int readBignumInteger16Ubits( STREAM *stream, void *bignum, const int minBits,
							  const int maxBits );
int writeBignumInteger16Ubits( STREAM *stream, const void *bignum );
int sizeofBignumInteger32( const void *bignum );
int readBignumInteger32( STREAM *stream, void *bignum, const int minLength,
						 const int maxLength );
int writeBignumInteger32( STREAM *stream, const void *bignum );

/* PGP-specific read/write routines.  The difference between
   pgpReadPacketHeader() and pgpReadPacketHeaderI() is that the latter
   allows indefinite-length encoding for partial lengths.  Once we've
   read an indefinite length, we have to use pgpReadPartialLengh() to
   read subsequence partial-length values */

int pgpReadShortLength( STREAM *stream, const int ctb );
int pgpWriteLength( STREAM *stream, const long length );
int pgpReadPacketHeader( STREAM *stream, int *ctb, long *length, 
						 const int minLength );
int pgpReadPacketHeaderI( STREAM *stream, int *ctb, long *length, 
						  const int minLength );
int pgpReadPartialLength( STREAM *stream, long *length );
int pgpWritePacketHeader( STREAM *stream, const int packetType,
						  const long length );

#define pgpSizeofLength( length ) \
	( ( length < 0 ) ? length : ( length <= 191 ) ? 1 : ( length <= 8383 ) ? 2 : 4 )
#endif /* !_MISCRW_DEFINED */
