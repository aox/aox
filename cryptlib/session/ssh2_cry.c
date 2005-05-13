/****************************************************************************
*																			*
*						  cryptlib SSHv2 Crypto Routines					*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH2

/****************************************************************************
*																			*
*							Key Load/Init Functions							*
*																			*
****************************************************************************/

/* Load the fixed SSHv2 DH key into a context.  The prime is the value
   2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }, from the Oakley spec
   (RFC 2412, other locations omit the q value).  Unfortunately the choice 
   of q leads to horribly inefficient operations since it's 860 bits larger 
   than it needs to be */

static const FAR_BSS BYTE dh1024SPKI[] = {
	0x30, 0x82, 0x01, 0x21,
		0x30, 0x82, 0x01, 0x17,
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01,
			0x30, 0x82, 0x01, 0x0A,
				0x02, 0x81, 0x81, 0x00,		/* p */
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
					0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
					0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
					0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
					0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
					0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
					0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
					0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
					0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
					0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
					0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
					0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
					0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
					0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0x02, 0x01,					/* g */
					0x02,
				0x02, 0x81, 0x80,			/* q */
					0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
					0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
					0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
					0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
					0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
					0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
					0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
					0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
					0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
					0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
					0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
					0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
					0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
					0x24, 0x94, 0x33, 0x28, 0xF6, 0x73, 0x29, 0xC0,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x03, 0x04, 0x00,
			0x02, 0x01, 					/* y */
				0x00
	};	

/* Additional DH values, from RFC 3526.  The 1536-bit value is widely used 
   in IKE, and has the prime value 
   2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }.  The 2048-bit
   value has the prime value 
   2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }, and the 3072-bit
   value has the prime value
   2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }.  All have a 
   generator of 2 */

static const FAR_BSS BYTE dh1536SSH[] = {
	0x00, 0x00, 0x00, 0xD8,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x00, 0xC1,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

static const FAR_BSS BYTE dh2048SSH[] = {
	0x00, 0x00, 0x01, 0x18,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x01, 0x01,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 
			0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
			0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 
			0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
			0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
			0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
			0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 
			0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
			0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

static const FAR_BSS BYTE dh3072SSH[] = {
	0x00, 0x00, 0x01, 0x98,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x01, 0x81,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 
			0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
			0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 
			0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
			0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
			0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
			0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 
			0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
			0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 
			0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 
			0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
			0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 
			0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 
			0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
			0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 
			0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 
			0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
			0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 
			0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 
			0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
			0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 
			0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 
			0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
			0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 
			0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

int initDHcontextSSH( CRYPT_CONTEXT *iCryptContext, int *keySize, 
					  const void *keyData, const int keyDataLength,
					  const int requestedKeySize )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	int length, status;

	assert( ( isReadPtr( keyData, keyDataLength ) && \
			  requestedKeySize == CRYPT_UNUSED ) || \
			( keyData == NULL && keyDataLength == 0 && \
			  requestedKeySize == CRYPT_USE_DEFAULT ) || \
			( keyData == NULL && keyDataLength == 0 && \
			  requestedKeySize >= bitsToBytes( MIN_PKCSIZE_BITS ) && \
			  requestedKeySize <= CRYPT_MAX_PKCSIZE ) );

	*iCryptContext = CRYPT_ERROR;
	*keySize = 0;

	/* Create the DH context */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context */
	setMessageData( &msgData, "SSH DH key", 10 );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusOK( status ) )
		{
		int keyType = CRYPT_IATTRIBUTE_KEY_SSH2;

		/* If we're being given externally-supplied DH key components, load 
		   them */
		if( keyData != NULL )
			{ setMessageData( &msgData, ( void * ) keyData, keyDataLength ); }
		else
			{
			/* Get the actual key size based on the requested key size.  The
			   spec requires that we use the smallest key size that's larger 
			   than the requested one, we allow for a small amount of slop 
			   to ensure that we don't scale up to some huge key size if the 
			   client's keysize calculation is off by a few bits */
			const int actualKeySize = \
					( requestedKeySize == CRYPT_USE_DEFAULT ) ? SSH2_DEFAULT_KEYSIZE : \
					( requestedKeySize < 128 + 8 ) ? bitsToBytes( 1024 ) : \
					( requestedKeySize < 192 + 8 ) ? bitsToBytes( 1536 ) : \
					( requestedKeySize < 256 + 8 ) ? bitsToBytes( 2048 ) : \
					( requestedKeySize < 384 + 8 ) ? bitsToBytes( 3072 ) : \
					0;

			/* If the request key size corresponds (at least approximately) 
			   to a built-in DH value, load the built-in key value, 
			   otherwise generate a new one.  In theory we should probably 
			   generate a new DH key each time:
			   
				status = krnlSendMessage( createInfo.cryptHandle,
										  IMESSAGE_SETATTRIBUTE, 
										  ( void * ) &requestedKeySize,
										  CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusOK( status ) )
					status = krnlSendMessage( createInfo.cryptHandle,
											  IMESSAGE_CTX_GENKEY, NULL, 
											  FALSE );
			   
			   however because the handshake is set up so that the client 
			   (rather than the server) chooses the key size, we can't 
			   actually perform the generation until we're in the middle of 
			   the handshake.  This means that the server will grind to a 
			   halt during each handshake as it generates a new key of 
			   whatever size takes the client's fancy (it also leads to a 
			   nice potential DoS attack on the server).  To avoid this 
			   problem, we use fixed keys of various common sizes */
			switch( actualKeySize )
				{
				case bitsToBytes( 1024 ):
					setMessageData( &msgData, ( void * ) dh1024SPKI, 
									sizeof( dh1024SPKI ) );
					keyType = CRYPT_IATTRIBUTE_KEY_SPKI;
					break;

				case bitsToBytes( 1536 ):
					setMessageData( &msgData, ( void * ) dh1536SSH, 
									sizeof( dh1536SSH ) );
					break;

				case bitsToBytes( 2048 ):
					setMessageData( &msgData, ( void * ) dh2048SSH, 
									sizeof( dh2048SSH ) );
					break;

				case bitsToBytes( 3072 ):
				default:		/* Hier ist der mast zu ende */
					setMessageData( &msgData, ( void * ) dh3072SSH, 
									sizeof( dh3072SSH ) );
					break;
				}
			}
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  keyType );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;
	*keySize = length;
	return( CRYPT_OK );
	}

/* Complete the hashing necessary to generate a cryptovariable and send it
   to a context */

static int loadCryptovariable( const CRYPT_CONTEXT iCryptContext,
							   const CRYPT_ATTRIBUTE_TYPE attribute,
							   const int attributeSize, HASHFUNCTION hashFunction,
							   const HASHINFO initialHashInfo, const BYTE *nonce,
							   const BYTE *data, const int dataLen )
	{
	RESOURCE_DATA msgData;
	HASHINFO hashInfo;
	BYTE buffer[ CRYPT_MAX_KEYSIZE ];
	int status;

	/* Complete the hashing */
	memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
	hashFunction( hashInfo, NULL, nonce, 1, HASH_CONTINUE );
	hashFunction( hashInfo, buffer, data, dataLen, HASH_END );
	if( attributeSize > 20 )
		{
		/* If we need more data than the hashing will provide in one go,
		   generate a second block as:

			hash( shared_secret || exchange_hash || data )

		   where the shared secret and exchange hash are present as the
		   precomputed data in the initial hash info and the data part is
		   the output of the hash step above */
		memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
		hashFunction( hashInfo, buffer + 20, buffer, 20, HASH_END );
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );

	/* Send the data to the context */
	setMessageData( &msgData, buffer, attributeSize );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, attribute );
	zeroise( buffer, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/* Initialise and destroy the security contexts */

int initSecurityContextsSSH( SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
		krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &sessionInfoPtr->cryptBlocksize,
						 CRYPT_CTXINFO_BLOCKSIZE );
		}
#ifdef USE_SSH1
	if( cryptStatusOK( status ) && sessionInfoPtr->version == 1 && \
		sessionInfoPtr->cryptAlgo == CRYPT_ALGO_IDEA )
		{
		const int cryptMode = CRYPT_MODE_CFB;

		/* SSHv1 uses stream ciphers in places, for which we have to set the
		   mode explicitly */
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE,
								  ( void * ) &cryptMode,
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
									  IMESSAGE_SETATTRIBUTE,
									  ( void * ) &cryptMode,
									  CRYPT_CTXINFO_MODE );
		}
	if( sessionInfoPtr->version == 2 )	/* Continue on to cSOK() check */
#endif /* USE_SSH1 */
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
			setMessageCreateObjectInfo( &createInfo,
										sessionInfoPtr->integrityAlgo );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
			krnlSendMessage( sessionInfoPtr->iAuthInContext,
							 IMESSAGE_GETATTRIBUTE,
							 &sessionInfoPtr->authBlocksize,
							 CRYPT_CTXINFO_BLOCKSIZE );
			}
		}
	if( cryptStatusError( status ) )
		/* One or more of the contexts couldn't be created, destroy all the
		   contexts that have been created so far */
		destroySecurityContextsSSH( sessionInfoPtr );
	return( status );
	}

void destroySecurityContextsSSH( SESSION_INFO *sessionInfoPtr )
	{
	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	}

/* Set up the security information required for the session */

int initSecurityInfo( SESSION_INFO *sessionInfoPtr,
					  SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO initialHashInfo;
	const BOOLEAN isClient = \
				( sessionInfoPtr->flags & SESSION_ISSERVER ) ? FALSE : TRUE;
	int keySize, ivSize, status;

	/* Create the security contexts required for the session */
	status = initSecurityContextsSSH( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
		/* Blowfish has a variable-length key so we have to explicitly
		   specify its length */
		keySize = SSH2_FIXED_KEY_SIZE;
	else
		krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &keySize,
						 CRYPT_CTXINFO_KEYSIZE );
	if( krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &ivSize,
						 CRYPT_CTXINFO_IVSIZE ) == CRYPT_ERROR_NOTAVAIL )
		/* It's a stream cipher */
		ivSize = 0;

	/* Get the hash algorithm information and pre-hash the shared secret and
	   exchange hash, which are re-used for all cryptovariables.  The 
	   overall hashing is:

		hash( MPI( shared_secret ) || exchange_hash || \
			  nonce || exchange_hash )

	   Note the apparently redundant double hashing of the exchange hash, 
	   this is required because the spec refers to it by two different names,
	   the exchange hash and the session ID, and then requires that both be
	   hashed (actually it's a bit more complex than that, with issues 
	   related to re-keying, but for now it acts as a re-hash of the same
	   data).

	   Before we can hash the shared secret we have to convert it into MPI
	   form, which we do by generating a pseudo-header and hashing that
	   separately.  The nonce is "A", "B", "C", ... */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	if( sessionInfoPtr->protocolFlags & SSH_PFLAG_NOHASHSECRET )
		{
		/* Some implementations erroneously omit the shared secret when
		   creating the keying material.  This is suboptimal but not fatal,
		   since the shared secret is also hashed into the exchange hash */
		hashFunction( initialHashInfo, NULL, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_START );
		}
	else
		{
		BYTE header[ 8 ], *headerPtr = header;
		const int mpiLength = \
					sizeofInteger32( handshakeInfo->secretValue,
									 handshakeInfo->secretValueLength ) - \
					LENGTH_SIZE;

		/* Hash the shared secret as an MPI.  We can't use hashAsMPI() for 
		   this because it works with contexts rather than the internal hash
		   functions used here */
		mputLong( headerPtr, mpiLength );
		if( handshakeInfo->secretValue[ 0 ] & 0x80 )
			/* MPIs are signed values */
			*headerPtr++ = 0;
		hashFunction( initialHashInfo, NULL, header, headerPtr - header,
					  HASH_START );
		hashFunction( initialHashInfo, NULL, handshakeInfo->secretValue,
					  handshakeInfo->secretValueLength, HASH_CONTINUE );
		hashFunction( initialHashInfo, NULL, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_CONTINUE );
		}

	/* Load the cryptovariables.  The order is:

		client_write_iv, server_write_iv
		client_write_key, server_write_key
		client_write_mac, server_write_mac

	   Although HMAC has a variable-length key and should therefore follow
	   the SSH2_FIXED_KEY_SIZE rule, the key size was in later RFC drafts
	   set to the HMAC block size.  Some implementations erroneously use
	   the fixed-size key, so we adjust the HMAC key size if we're talking
	   to one of these */
	if( !isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		{
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptOutContext : \
										sessionInfoPtr->iCryptInContext,
									 CRYPT_CTXINFO_IV, ivSize,
									 hashFunction, initialHashInfo, "A",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
		if( cryptStatusOK( status ) )
			status = loadCryptovariable( isClient ? \
											sessionInfoPtr->iCryptInContext : \
											sessionInfoPtr->iCryptOutContext,
										 CRYPT_CTXINFO_IV, ivSize,
										 hashFunction, initialHashInfo, "B",
										 handshakeInfo->sessionID,
										 handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptOutContext : \
										sessionInfoPtr->iCryptInContext,
									 CRYPT_CTXINFO_KEY, keySize,
									 hashFunction, initialHashInfo, "C",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
									 CRYPT_CTXINFO_KEY, keySize,
									 hashFunction, initialHashInfo, "D",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
									 CRYPT_CTXINFO_KEY,
									 ( sessionInfoPtr->protocolFlags & \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
										SSH2_FIXED_KEY_SIZE : \
										sessionInfoPtr->authBlocksize,
									 hashFunction, initialHashInfo, "E",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iAuthInContext : \
										sessionInfoPtr->iAuthOutContext,
									 CRYPT_CTXINFO_KEY,
									 ( sessionInfoPtr->protocolFlags & \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
										SSH2_FIXED_KEY_SIZE : \
										sessionInfoPtr->authBlocksize,
									 hashFunction, initialHashInfo, "F",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	return( status );
	}

/****************************************************************************
*																			*
*								Hash/MAC Data								*
*																			*
****************************************************************************/

/* Hash a value encoded as an SSH string and as an MPI */

int hashAsString( const CRYPT_CONTEXT iHashContext,
				  const BYTE *data, const int dataLength )
	{
	BYTE buffer[ 128 ], *bufPtr = buffer;
	int status;

	/* Prepend the string length to the data and hash it.  If it'll fit into
	   the buffer we copy it over to save a kernel call */
	mputLong( bufPtr, dataLength );
	if( dataLength <= 128 - LENGTH_SIZE )
		{
		memcpy( buffer + LENGTH_SIZE, data, dataLength );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
								  LENGTH_SIZE + dataLength );
		}
	else
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
						 LENGTH_SIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( void * ) data, dataLength );
		}
	zeroise( buffer, 128 );

	return( status );
	}

int hashAsMPI( const CRYPT_CONTEXT iHashContext, const BYTE *data, 
			   const int dataLength )
	{
	BYTE buffer[ 8 ], *bufPtr = buffer;
	const int length = ( data[ 0 ] & 0x80 ) ? dataLength + 1 : dataLength;
	int headerLength = LENGTH_SIZE;

	/* Prepend the MPI length to the data and hash it.  Since this is often
	   sensitive data, we don't take a local copy but hash it in two parts */
	mputLong( bufPtr, length );
	if( data[ 0 ] & 0x80 )
		{
		/* MPIs are signed values */
		*bufPtr++ = 0;
		headerLength++;
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, headerLength );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
							  ( void * ) data, dataLength ) );
	}

/* MAC the payload of a data packet.  Since we may not have the whole packet
   available at once, we can do this in one go or incrementally */

int macPayload( const CRYPT_CONTEXT iMacContext, const long seqNo, 
				const BYTE *data, const int dataLength, 
				const int packetDataLength, const MAC_TYPE macType,
				const int macLength, const BOOLEAN isRead )
	{
	int status;

	/* MAC the data and either compare the result to the stored MAC or 
	   append the MAC value to the data:

		HMAC( seqNo || length || payload )

	   During the handshake process we have the entire packet at hand 
	   (dataLength == packetDataLength) and can process it at once.  When 
	   we're processing payload data (dataLength a subset of 
	   packetDataLength) we have to process the header separately in order 
	   to determine how much more we have to read, so we have to MAC the 
	   packet in two parts */
	if( macType == MAC_START || macType == MAC_ALL )
		{
		BYTE buffer[ 16 ], *bufPtr = buffer;
		int length = ( macType == MAC_ALL ) ? dataLength : packetDataLength;

		assert( ( macType == MAC_ALL && packetDataLength == 0 ) || \
				( macType == MAC_START && packetDataLength >= dataLength ) );

		/* Since the payload had the length stripped during the speculative
		   read if we're MAC'ing read data, we have to reconstruct it and 
		   hash it separately before we hash the data.  If we're doing the 
		   hash in parts, the amount of data being hashed won't match the 
		   overall length so the caller needs to supply the overall packet 
		   length as well as the current data length */
		mputLong( bufPtr, seqNo );
		mputLong( bufPtr, length );
		krnlSendMessage( iMacContext, IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_CTXINFO_HASHVALUE );
		krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, buffer,
						 UINT32_SIZE + LENGTH_SIZE );
		}
	if( dataLength > 0 )
		status = krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, 
								  ( void * ) data, dataLength );
	if( macType == MAC_END || macType == MAC_ALL )
		{
		RESOURCE_DATA msgData;

		status = krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, "", 0 );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, ( BYTE * ) data + dataLength, macLength );
		if( isRead )
			/* It's a read, compare the MAC value to the stored MAC
			   value */
			status = krnlSendMessage( iMacContext, IMESSAGE_COMPARE, 
									  &msgData, MESSAGE_COMPARE_HASH );
		else
			/* It's a write, append the MAC value to the data */
			status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE_S, 
									  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Miscellaneous Functions							*
*																			*
****************************************************************************/

/* Complete the DH key agreement */

int completeKeyex( SESSION_INFO *sessionInfoPtr, 
				   SSH_HANDSHAKE_INFO *handshakeInfo, 
				   const BOOLEAN isServer )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	RESOURCE_DATA msgData;
	STREAM stream;
	int status;

	/* Read the other side's key agreement information.  Note that the size 
	   check has already been performed at a higher level when the overall 
	   key agreement value was read, this is a secondary check of the MPI
	   payload */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	if( isServer )
		sMemConnect( &stream, handshakeInfo->clientKeyexValue,
					 handshakeInfo->clientKeyexValueLength );
	else
		sMemConnect( &stream, handshakeInfo->serverKeyexValue,
					 handshakeInfo->serverKeyexValueLength );
	status = readInteger32( &stream, keyAgreeParams.publicValue, 
							&keyAgreeParams.publicValueLen, 
							bitsToBytes( MIN_PKCSIZE_BITS ),
							CRYPT_MAX_PKCSIZE );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) && \
		!isValidDHsize( keyAgreeParams.publicValueLen, 
						handshakeInfo->serverKeySize, 0 ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 1 MPI" );

	/* Perform phase 2 of the DH key agreement */
	status = krnlSendMessage( handshakeInfo->iServerCryptContext,
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusOK( status ) )
		{
		memcpy( handshakeInfo->secretValue, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->secretValueLength = keyAgreeParams.wrappedKeyLen;
		}
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using ephemeral DH, hash the requested keyex key length(s) 
	   and DH p and g values.  Since this has been deferred until long after 
	   the keyex negotiation took place, we have to recreate the original 
	   encoded values here */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		BYTE keyexBuffer[ 128 + ( CRYPT_MAX_PKCSIZE * 2 ) ];
		const int extraLength = LENGTH_SIZE + sizeofString32( "ssh-dh", 6 );

		krnlSendMessage( handshakeInfo->iExchangeHashcontext,
						 IMESSAGE_CTX_HASH, 
						 handshakeInfo->encodedReqKeySizes, 
						 handshakeInfo->encodedReqKeySizesLength );
		setMessageData( &msgData, keyexBuffer, 
						128 + ( CRYPT_MAX_PKCSIZE * 2 ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSH2 );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( handshakeInfo->iExchangeHashcontext, 
						 IMESSAGE_CTX_HASH, keyexBuffer + extraLength, 
						 msgData.length - extraLength );
		}

	/* Hash the client and server DH values and shared secret */
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH, 
					 handshakeInfo->clientKeyexValue,
					 handshakeInfo->clientKeyexValueLength );
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH,
					 handshakeInfo->serverKeyexValue,
					 handshakeInfo->serverKeyexValueLength );
	status = hashAsMPI( handshakeInfo->iExchangeHashcontext,
						handshakeInfo->secretValue,
						handshakeInfo->secretValueLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the hashing to obtain the exchange hash and then hash *that*
	   to get the hash that the server signs and sends to the client.  The
	   overall hashed data for the exchange hash is:

		string	V_C, client version string (CR and NL excluded)
		string	V_S, server version string (CR and NL excluded)
		string	I_C, client hello
		string	I_S, server hello
		string	K_S, the host key
	 [[	uint32	min, min.preferred keyex key size for ephemeral DH ]]
	  [	uint32	n, preferred keyex key size for ephemeral DH ]
	 [[	uint32	max, max.preferred keyex key size for ephemeral DH ]]
	  [	mpint	p, DH p for ephemeral DH ]
	  [	mpint	g, DH g for ephemeral DH ]
		mpint	e, client DH keyex value
		mpint	f, server DH keyex value
		mpint	K, the shared secret

	   The client and server version string ahd hellos and the host key were
	   hashed inline during the handshake.  The optional parameters are for 
	   negotiated DH values (see the conditional-hashing code above).  The 
	   double-optional parameters are for the revised version of the DH 
	   negotiation mechanism, the original only had n, the revised version 
	   allowed a { min, n, max } range */
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH,
					 "", 0 );
	setMessageData( &msgData, handshakeInfo->sessionID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->sessionIDlength = msgData.length;
	krnlSendMessage( handshakeInfo->iExchangeHashcontext,
					 IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->iExchangeHashcontext,
					 IMESSAGE_CTX_HASH, handshakeInfo->sessionID,
					 handshakeInfo->sessionIDlength );
	return( krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							 IMESSAGE_CTX_HASH, "", 0 ) );
	}
#endif /* USE_SSH2 */
