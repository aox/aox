/****************************************************************************
*																			*
*		Miscellaneous (Non-ASN.1) Routines Constants and Structures			*
*						Copyright Peter Gutmann 1992-2002					*
*																			*
****************************************************************************/

#ifndef _MISCRW_DEFINED

#define _MISCRW_DEFINED

#include <time.h>
#if defined( INC_ALL )
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "stream.h"
#else
  #include "misc/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							ASN.1 Constants and Macros						*
*																			*
****************************************************************************/

/* Sizes of encoded integer values */

#define UINT32_SIZE		4
#define UINT64_SIZE		8

/****************************************************************************
*																			*
*								Function Prototypes							*
*																			*
****************************************************************************/

/* Read and write 32- and 64-bit integer values */

int readUint32( STREAM *stream );
int writeUint32( STREAM *stream, const int value );
int readUint64( STREAM *stream );
int writeUint64( STREAM *stream, const int value );

/* Read and write 32- and 64-bit time values */

int readUint32Time( STREAM *stream, time_t *timeVal );
int writeUint32Time( STREAM *stream, const time_t timeVal );
int readUint64Time( STREAM *stream, time_t *timeVal );
int writeUint64Time( STREAM *stream, const time_t timeVal );

/* Read and write strings and (large) integers preceded by 32-bit lengths 
   (the difference between the two being that integers require handling of
   sign bits and zero-padding) */

#define sizeofString32( stringLength )	( UINT32_SIZE + stringLength )

int readString32( STREAM *stream, void *string, int *stringLength,
				  const int maxLength );
int writeString32( STREAM *stream, const void *string,
				   const int stringLength );
int readInteger32( STREAM *stream, void *integer, int *integerLength,
				   const int maxLength );
int writeInteger32( STREAM *stream, const void *integer,
					const int integerLength );

/* Read and write unsigned (large) integers preceded by 16- and 32-bit 
   lengths, lengths in bits */

int readInteger16Ubits( STREAM *stream, void *integer, int *integerLength,
						const int maxLength );
int readInteger32Ubits( STREAM *stream, void *integer, int *integerLength,
						const int maxLength );
int writeInteger16Ubits( STREAM *stream, const void *integer,
						 const int integerLength );
int writeInteger32Ubits( STREAM *stream, const void *integer,
						 const int integerLength );

/* Read and write bignum integers */

int sizeofBignumInteger32( const void *bignum );
int readBignumInteger32( STREAM *stream, void *bignum, const int minBytes, 
						 const int maxBytes );
int writeBignumInteger32( STREAM *stream, const void *bignum );

int readBignumInteger16Ubits( STREAM *stream, void *bignum, const int minBits, 
							  const int maxBits );
int writeBignumInteger16Ubits( STREAM *stream, const void *bignum );

/* PGP-specific read/write routines */

int pgpReadShortLength( STREAM *stream, const int ctb );
int pgpWriteLength( STREAM *stream, const int length );
int pgpReadPacketHeader( STREAM *stream, int *ctb, long *length );
int pgpWritePacketHeader( STREAM *stream, const int packetType,
						  const long length );

#define pgpSizeofLength( length ) \
	( ( length < 0 ) ? length : ( length <= 191 ) ? 1 : ( length <= 8383 ) ? 2 : 4 )
#endif /* !_MISCRW_DEFINED */
