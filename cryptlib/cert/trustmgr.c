/****************************************************************************
*																			*
*					  Certificate Trust Management Routines					*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

/* The following code is actually part of the user rather than certificate
   routines, but it pertains to certificates so we include it here.  Trust
   info mutex handling is done in the user object, so there are no mutexes
   required here.

   The interpretation of what represents a "trusted cert" is somewhat complex
   and open-ended, it's not clear whether what's being trusted is the key
   in the cert, the cert, or the owner of the cert (corresponding to
   subjectKeyIdentifier, issuerAndSerialNumber/certHash, or subject DN).  The
   generally accepted form is to trust the subject, so we check for this in
   the cert.  The modification for trusting the key in the cert is fairly
   simple to make if required */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* The size of the table of trust information.  This must be a power of 2 */

#define TRUSTINFO_SIZE		256

/* The size of the hashed identifier info */

#define HASH_SIZE			20

/* Trusted certificate information */

typedef struct TI {
	/* Identification information, the checksum and hash of the cert
	   subjectName and subjectKeyIdentifier */
	int sCheck, kCheck;
	BYTE sHash[ HASH_SIZE ], kHash[ HASH_SIZE ];

	/* The trusted certificate.  When we read trusted certs from a config
	   file, the cert is stored in the encoded form to save creating a pile
	   of cert objects that will never be used, when it's needed the cert is
	   created on the fly from the encoded form.  When we get the trust info
	   directly from the user, the cert object already exists and the 
	   encoded form isn't used */
	void *certObject;
	int certObjectLength;
	CRYPT_CERTIFICATE iCryptCert;

	/* Pointer to the next entry */
	struct TI *next;				/* Next trustInfo record in the chain */
	} TRUST_INFO;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Hash data */

static void hashData( BYTE *hash, const void *data, const int dataLength )
	{
	static HASHFUNCTION hashFunction = NULL;

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	/* Hash the data */
	if( dataLength <= 0 )
		memset( hash, 0, HASH_SIZE );
	else
		hashFunction( NULL, hash, ( BYTE * ) data, dataLength, HASH_ALL );
	}

/****************************************************************************
*																			*
*							Retrieve Trusted Cert Info						*
*																			*
****************************************************************************/

/* Find the trust info entry for a given cert */

void *findTrustEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCert,
					  const BOOLEAN getIssuerEntry )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtr;
	const TRUST_INFO *trustInfoCursor;
	DYNBUF nameDB;
	BYTE sHash[ HASH_SIZE ];
	BOOLEAN nameHashed = FALSE;
	int sCheck, status;

	/* If we're trying to get a trusted issuer cert and we're already at a 
	   self-signed (CA root) cert, don't return it.  This check is necessary 
	   because self-signed certs have issuer name == subject name, so once 
	   we get to a self-signed cert's subject DN an attempt to fetch its 
	   issuer would just repeatedly fetch the same cert */
	if( getIssuerEntry )
		{
		int value;

		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusError( status ) || value )
			return( NULL );
		}

	/* Set up the information needed to find the trusted cert */
	status = dynCreate( &nameDB, iCryptCert, getIssuerEntry ? \
						CRYPT_IATTRIBUTE_ISSUER : CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusError( status ) )
		return( NULL );
	sCheck = checksumData( dynData( nameDB ), dynLength( nameDB ) );
	trustInfoCursor = trustInfoIndex[ sCheck & ( TRUSTINFO_SIZE - 1 ) ];

	/* Check to see whether something with the requested DN is present */
	while( trustInfoCursor != NULL )
		{
		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( trustInfoCursor->sCheck == sCheck )
			{
			if( !nameHashed )
				{
				hashData( sHash, dynData( nameDB ), dynLength( nameDB ) );
				nameHashed = TRUE;
				}
			if( !memcmp( trustInfoCursor->sHash, sHash, HASH_SIZE ) )
				{
				dynDestroy( &nameDB );
				return( ( TRUST_INFO * ) trustInfoCursor );
				}
			}
		trustInfoCursor = trustInfoCursor->next;
		}

	dynDestroy( &nameDB );
	return( NULL );
	}

/* Retrieve trusted certificates */

CRYPT_CERTIFICATE getTrustedCert( void *trustInfoPtr )
	{
	TRUST_INFO *trustInfo = trustInfoPtr;
	int status;

	/* If the cert hasn't already been instantiated yet, do so now */
	if( trustInfo->iCryptCert == CRYPT_ERROR )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Instantiate the cert */
		setMessageCreateObjectIndirectInfo( &createInfo, trustInfo->certObject,
											trustInfo->certObjectLength,
											CRYPT_CERTTYPE_CERTIFICATE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		assert( cryptStatusOK( status ) );
		if( cryptStatusError( status ) )
			return( status );

		/* The cert was successfully instantiated, free its encoded form */
		zeroise( trustInfo->certObject, trustInfo->certObjectLength );
		clFree( "getTrustedCert", trustInfo->certObject );
		trustInfo->certObject = NULL;
		trustInfo->certObjectLength = 0;
		trustInfo->iCryptCert = createInfo.cryptHandle;
		}

	/* Return the trusted cert */
	return( trustInfo->iCryptCert );
	}

int enumTrustedCerts( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCtl, 
					  const CRYPT_KEYSET iCryptKeyset )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtr;
	int i;

	assert( iCryptCtl == CRYPT_UNUSED || iCryptKeyset == CRYPT_UNUSED );

	/* If there's no destination for the trusted certs supplied, it's a 
	   presence check only */
	if( iCryptCtl == CRYPT_UNUSED && iCryptKeyset == CRYPT_UNUSED )
		{
		for( i = 0; i < TRUSTINFO_SIZE; i++ )
			if( trustInfoIndex[ i ] != NULL )
				return( CRYPT_OK );

		return( CRYPT_ERROR_NOTFOUND );
		}

	for( i = 0; i < TRUSTINFO_SIZE; i++ )
		{
		TRUST_INFO *trustInfoCursor;

		for( trustInfoCursor = trustInfoIndex[ i ]; trustInfoCursor != NULL; \
			 trustInfoCursor = trustInfoCursor->next )	
			{
			const CRYPT_CERTIFICATE iCryptCert = \
										getTrustedCert( trustInfoCursor );
			int status;

			if( cryptStatusError( iCryptCert ) )
				return( iCryptCert );
			if( iCryptCtl != CRYPT_UNUSED )
				{
				/* We're sending trusted certs to a cert trust list */
				status = krnlSendMessage( iCryptCtl, IMESSAGE_SETATTRIBUTE,
										  ( void * ) &iCryptCert,
										  CRYPT_IATTRIBUTE_CERTCOLLECTION );
				if( cryptStatusError( status ) )
					return( status );
				}
			else
				{
				MESSAGE_KEYMGMT_INFO setkeyInfo;

				/* We're sending trusted certs to a keyset */
				setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
									   NULL, 0, KEYMGMT_FLAG_NONE );
				setkeyInfo.cryptHandle = iCryptCert;
				status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_SETKEY, 
										  &setkeyInfo, 
										  KEYMGMT_ITEM_PUBLICKEY );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Add/Update Trusted Cert Info					*
*																			*
****************************************************************************/

/* Add and delete a trust entry */

static int addEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCert, 
					 const void *certObject, const int certObjectLength )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtr;
	TRUST_INFO *newElement;
	BOOLEAN recreateCert = FALSE;
	int trustInfoEntry;

	/* If we're adding a cert, check whether it has a context attached and
	   if it does, whether it's a public-key context.  If there's no context
	   attached (it's a data-only cert) or the attached context is a
	   private-key context (which we don't want to leave hanging around in
	   memory, or which could be in a removable crypto device), we don't try
	   and use the cert but instead add the cert data and re-instantiate a
	   new cert with attached public-key context if required */
	if( certObject == NULL )
		{
		CRYPT_CONTEXT iCryptContext;
		int status;

		status = krnlSendMessage( iCryptCert, IMESSAGE_GETDEPENDENT,
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			/* There's no context associated with this cert, we'll have to
			   recreate it later */
			recreateCert = TRUE;
		else
			{
			status = krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusOK( status ) )
				/* The context associated with the cert is a private-key
				   context, recreate it later as a public-key context */
				recreateCert = TRUE;
			}
		}

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( TRUST_INFO * ) \
				clAlloc( "addEntry", sizeof( TRUST_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( TRUST_INFO ) );
	if( certObject == NULL )
		{
		DYNBUF subjectDB, subjectKeyDB;
		BOOLEAN hasSKID = FALSE;
		int status;

		/* Generate the checksum and hash of the cert object's subject name and 
		   key ID */
		status = dynCreate( &subjectDB, iCryptCert, CRYPT_IATTRIBUTE_SUBJECT );
		if( cryptStatusError( status ) )
			return( status );
		status = dynCreate( &subjectKeyDB, iCryptCert, 
							CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
		if( cryptStatusOK( status ) )
			hasSKID = TRUE;
		newElement->sCheck = checksumData( dynData( subjectDB ), 
										   dynLength( subjectDB ) );
		hashData( newElement->sHash, dynData( subjectDB ), 
				  dynLength( subjectDB ) );
		if( hasSKID )
			{
			newElement->kCheck = checksumData( dynData( subjectKeyDB ), 
											   dynLength( subjectKeyDB ) );
			hashData( newElement->kHash, dynData( subjectKeyDB ), 
					  dynLength( subjectKeyDB ) );
			dynDestroy( &subjectKeyDB );
			}
		else
			{
			newElement->kCheck = 0;
			hashData( newElement->kHash, NULL, 0 );
			}
		dynDestroy( &subjectDB );
		}
	if( certObject != NULL || recreateCert )
		{
		DYNBUF certDB;
		int objectLength = certObjectLength, status;

		/* If we're using the data from an existing cert object, all we still
		   need is the encoded data */
		if( recreateCert )
			{
			/* Get the encoded cert */
			status = dynCreate( &certDB, iCryptCert, 
								CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			certObject = dynData( certDB );
			objectLength = dynLength( certDB );
			}
		else
			{
			STREAM stream;
			const BYTE *extensionPtr;
			const void *subjectDNptr, *subjectKeyIDptr;
			int subjectDNsize, subjectKeyIDsize;
			int extensionSize = 0, i;

			/* Parse the certificate to locate the start of the encoded
			   subject DN and cert extensions (if present) */
			sMemConnect( &stream, certObject, certObjectLength );
			readSequence( &stream, NULL );	/* Outer wrapper */
			readSequence( &stream, NULL );	/* Inner wrapper */
			if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
				readUniversal( &stream );	/* Version */
			readUniversal( &stream );		/* Serial number */
			readUniversal( &stream );		/* Sig.algo */
			readUniversal( &stream );		/* Issuer DN */
			readUniversal( &stream );		/* Validity */
			subjectDNptr = sMemBufPtr( &stream );
			readSequence( &stream, &subjectDNsize );
			subjectDNsize = sizeofObject( subjectDNsize );
			readUniversal( &stream );		/* Subject DN */
			status = readUniversal( &stream );/* Public key */
			if( cryptStatusOK( status ) && \
				peekTag( &stream ) == MAKE_CTAG( 3 ) )
				{
				status = readConstructed( &stream, &extensionSize, 3 );
				if( cryptStatusOK( status ) )
					{
					extensionPtr = sMemBufPtr( &stream );
					sSkip( &stream, extensionSize );
					}
				}
			if( cryptStatusOK( status ) )	/* Signature */
				status = readUniversal( &stream );
			sMemDisconnect( &stream );
			if( cryptStatusError( status ) )
				{
				clFree( "addEntry", newElement );
				assert( NOTREACHED );
				return( CRYPT_ERROR_BADDATA );
				}

			/* Now look for the subjectKeyID in the extensions.  It's easier
			   to do a pattern match than to try and parse the extensions */
			subjectKeyIDptr = NULL;
			subjectKeyIDsize = 0;
			for( i = 0; i < extensionSize - 64; i++ )
				{
				/* Look for the OID.  This potentially skips two bytes at a
				   time, but this is safe since the preceding bytes can never
				   contain either of these two values (they're 0x30, len) */
				if( extensionPtr[ i++ ] != BER_OBJECT_IDENTIFIER || \
					extensionPtr[ i++ ] != 3 )
					continue;
				if( memcmp( extensionPtr + i, "\x55\x1D\x0E", 3 ) )
					continue;
				i += 3;

				/* We've found the OID (with 1.1e-12 error probability), skip
				   the critical flag if necessary */
				if( extensionPtr[ i ] == BER_BOOLEAN )
					i += 3;

				/* Check for the OCTET STRING and a reasonable length */
				if( extensionPtr[ i++ ] != BER_OCTETSTRING || \
					extensionPtr[ i ] & 0x80 )
					continue;

				/* Extract the key ID */
				if( i + extensionPtr[ i ] <= extensionSize )
					{
					subjectKeyIDsize = extensionPtr[ i++ ];
					subjectKeyIDptr = extensionPtr + i;
					}
				}

			/* Generate the checksum and hash of the encoded cert's subject 
			   name and key ID */
			newElement->sCheck = checksumData( subjectDNptr, subjectDNsize );
			hashData( newElement->sHash, subjectDNptr, subjectDNsize );
			newElement->kCheck = checksumData( subjectKeyIDptr, subjectKeyIDsize );
			hashData( newElement->kHash, subjectKeyIDptr, subjectKeyIDsize );
			}

		/* Remember the trusted cert data for later use */
		if( ( newElement->certObject = clAlloc( "addEntry", 
												objectLength ) ) == NULL )
			{
			clFree( "addEntry", newElement );
			if( recreateCert )
				dynDestroy( &certDB );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( newElement->certObject, certObject, objectLength );
		newElement->certObjectLength = objectLength;
		newElement->iCryptCert = CRYPT_ERROR;

		/* Clean up */
		if( recreateCert )
			dynDestroy( &certDB );
		}
	else
		{
		/* The trusted key exists as a standard cert with a public-key 
		   context attached, remember it for later */
		krnlSendNotifier( iCryptCert, IMESSAGE_INCREFCOUNT );
		newElement->iCryptCert = iCryptCert;
		}

	/* Add it to the list */
	trustInfoEntry = newElement->sCheck & ( TRUSTINFO_SIZE - 1 );
	if( trustInfoIndex[ trustInfoEntry ] == NULL )
		trustInfoIndex[ trustInfoEntry ] = newElement;
	else
		{
		TRUST_INFO *trustInfoCursor;

		/* Add the new element to the end of the list */
		for( trustInfoCursor = trustInfoIndex[ trustInfoEntry ];
			 trustInfoCursor->next != NULL; 
			 trustInfoCursor = trustInfoCursor->next );
		trustInfoCursor->next = newElement;
		}

	return( CRYPT_OK );
	}

int addTrustEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCert, 
				   const void *certObject, const int certObjectLength, 
				   const BOOLEAN addSingleCert )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int status;

	assert( ( checkHandleRange( iCryptCert ) && certObject == NULL ) || \
			( iCryptCert == CRYPT_UNUSED && certObject != NULL ) );

	/* If we're adding encoded cert data, we can add it directly */
	if( certObject != NULL )
		return( addEntry( trustInfoPtr, CRYPT_UNUSED, certObject, 
						  certObjectLength ) );

	/* Add the cert/each cert in the trust list */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( !addSingleCert )
		/* It's a trust list, move to the start of the list */
		krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	do
		{
		/* Add the certificate info if it's not already present */
		if( findTrustEntry( trustInfoPtr, iCryptCert, FALSE ) == NULL )
			{
			seenNonDuplicate = TRUE;
			status = addEntry( trustInfoPtr, iCryptCert, NULL, 0 );
			}
		}
	while( cryptStatusOK( status ) && !addSingleCert && \
		   krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* There were no new certs to add present, return an inited error */
		status = CRYPT_ERROR_INITED;
	
	return( status );
	}

void deleteTrustEntry( void *trustInfoPtr, void *trustEntry )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtr;
	TRUST_INFO *entryToDelete = ( TRUST_INFO * ) trustEntry, *prevInfoPtr;
	const int trustInfoEntry = entryToDelete->sCheck & ( TRUSTINFO_SIZE - 1 );

	assert( trustInfoIndex[ trustInfoEntry ] != NULL );

	/* Unlink the trust info index */
	prevInfoPtr = trustInfoIndex[ trustInfoEntry ];
	if( prevInfoPtr == entryToDelete )
		/* Unlink from the start of the list */
		trustInfoIndex[ trustInfoEntry ] = entryToDelete->next;
	else
		{
		/* Unlink from the middle/end of the list */
		while( prevInfoPtr->next != entryToDelete )
			prevInfoPtr = prevInfoPtr->next;
		prevInfoPtr->next = entryToDelete->next;
		}

	/* Free the trust info entry */
	if( entryToDelete->iCryptCert != CRYPT_ERROR )
		krnlSendNotifier( entryToDelete->iCryptCert, IMESSAGE_DECREFCOUNT );
	if( entryToDelete->certObject != NULL )
		{
		zeroise( entryToDelete->certObject, entryToDelete->certObjectLength );
		clFree( "deleteTrustEntry", entryToDelete->certObject );
		}
	memset( entryToDelete, 0, sizeof( TRUST_INFO ) );
	clFree( "deleteTrustEntry", entryToDelete );
	}

/****************************************************************************
*																			*
*						Init/Shut down Trusted Cert Info					*
*																			*
****************************************************************************/

/* Initialise and shut down the trust information */

int initTrustInfo( void **trustInfoPtrPtr )
	{
	TRUST_INFO *trustInfoIndex;

	/* Initialise the trust information table */
	if( ( trustInfoIndex = \
			clAlloc( "initTrustInfo", TRUSTINFO_SIZE * \
									  sizeof( TRUST_INFO * ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( trustInfoIndex, 0, TRUSTINFO_SIZE * sizeof( TRUST_INFO * ) );
	*trustInfoPtrPtr = trustInfoIndex;
	return( CRYPT_OK );
	}

void endTrustInfo( void *trustInfoPtr )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtr;
	int i;

	if( trustInfoIndex == NULL )
		return;

	/* Destroy the chain of items at each table position */
	for( i = 0; i < TRUSTINFO_SIZE; i++ )
		{
		TRUST_INFO *trustInfoCursor = trustInfoIndex[ i ];

		/* Destroy any items in the list */
		while( trustInfoCursor != NULL )
			{
			TRUST_INFO *itemToFree = trustInfoCursor;

			trustInfoCursor = trustInfoCursor->next;
			deleteTrustEntry( trustInfoIndex, itemToFree );
			}
		}
	memset( trustInfoIndex, 0, TRUSTINFO_SIZE * sizeof( TRUST_INFO * ) );
	clFree( "endTrustInfo", trustInfoIndex );
	}
