/****************************************************************************
*																			*
*						cryptlib PKCS #15 Key Add Interface					*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* Define the following to use the post-PKCS #15 draft encapsulation for
   certificates.  Note that this will break backwards compatibility */

/* #define POST_DRAFT_ENCAPSULATION */

/* When writing attributes it's useful to have a fixed-size buffer rather
   than having to mess around with all sorts of variable-length structures,
   the following value defines the maximum size of the attribute data that
   we can write (that is, the I/O stream is opened with this size and
   generates a CRYPT_ERROR_OVERFLOW if we go beyond this).  The maximum-
   length buffer contents are two CRYPT_MAX_TEXTSIZE strings and a few odd
   bits and pieces so this is plenty */

#define KEYATTR_BUFFER_SIZE		256

/* The minimum number of keying iterations to use when deriving a key wrap
   key from a password.  Any recent system will handle a significant
   iteration count in no time but older systems may take awhile to handle
   this, however there's no easy way to determine CPU speed so we make the
   mimimal assumption that a 16-bit system isn't going to be too fast */

#if INT_MAX > 32767
  #define MIN_KEYING_ITERATIONS	2000
#else
  #define MIN_KEYING_ITERATIONS	800
#endif /* 16-bit systems */

/* When adding a public key and/or cert to a PKCS #15 collection, we have to 
   be able to cleanly handle the addition of arbitrary collections of 
   potentially overlapping objects.  Since a public key is a subset of the 
   data in a certificate, if we're adding a cert + public key pair the cert 
   data overrides the public key, which isn't added at all.  This leads to 
   some rather convoluted logic for deciding what needs updating and under 
   which conditions.  The actions taken are:

	key only:	if present
					return( CRYPT_ERROR_DUPLICATE )
				else
					add key;
	cert only:	if present
					return( CRYPT_ERROR_DUPLICATE );
				elif( matching key present )
					add, delete key data;
				elif( trusted cert )
					add as trusted cert;
				else
					error;
	key+cert:	if key present and cert present
					return( CRYPT_ERROR_DUPLICATE );
				delete key;
				if cert present -> don't add cert;

   The following values specify the action to be taken when adding a cert */

typedef enum {
	CERTADD_NONE,			/* No cert add action */
	CERTADD_UPDATE_EXISTING,/* Update existing key info with a cert */
	CERTADD_NORMAL,			/* Add a cert for which no key info present */
	CERTADD_STANDALONE_CERT,/* Add a standalone cert not assoc'd with a key */
	CERTADD_LAST			/* Last valid cert add action */
	} CERTADD_TYPE;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Determine the tag to use when encoding a given key type.  There isn't any
   tag for Elgamal but the keys are the same as X9.42 DH keys and cryptlib
   uses the OID rather than the tag to determine the key type, so the
   following sleight-of-hand works */

static int getKeyTypeTag( const CRYPT_CONTEXT cryptContext,
						  const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_ALGO_TYPE keyCryptAlgo = cryptAlgo;
	int status;

	assert( ( isHandleRangeValid( cryptContext ) && \
			  cryptAlgo == CRYPT_ALGO_NONE ) || \
			( cryptContext == CRYPT_UNUSED && \
			  ( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
				cryptAlgo <= CRYPT_ALGO_LAST_PKC ) ) );

	/* If the caller hasn't already supplied the algorithm details, get them
	   from the context */
	if( cryptAlgo == CRYPT_ALGO_NONE )
		{
		status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
								  &keyCryptAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		}
	switch( keyCryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( DEFAULT_TAG );

		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_ELGAMAL:
			return( 1 );

		case CRYPT_ALGO_DSA:
			return( 2 );

		case CRYPT_ALGO_KEA:
			return( 3 );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Calculate and if necessary allocate storage for public-key, private-key, 
   and cert data */

static int calculatePubkeyStorage( const PKCS15_INFO *pkcs15infoPtr,
								   void **newPubKeyDataPtr, 
								   int *newPubKeyDataSize, 
								   const int pubKeySize,
								   const int pubKeyAttributeSize,
								   const int extraDataSize )
	{
	void *newPubKeyData;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newPubKeyDataPtr, sizeof( void * ) ) );
	assert( isWritePtr( newPubKeyDataSize, sizeof( int ) ) ); 
	assert( pubKeySize > 0 ); 
	assert( pubKeyAttributeSize > 0 );
	assert( extraDataSize >= 0 );

	/* Calculate the new private-key data size */
	*newPubKeyDataSize = sizeofObject( \
							pubKeyAttributeSize + \
							sizeofObject( \
								sizeofObject( \
									sizeofObject( pubKeySize ) + \
									extraDataSize ) ) );

	/* If the new data will fit into the existing storage, we're done */
	if( *newPubKeyDataSize <= pkcs15infoPtr->pubKeyDataSize )
		return( CRYPT_OK );

	/* Allocate storage for the new data */
	newPubKeyData = clAlloc( "calculatePubkeyStorage", *newPubKeyDataSize );
	if( newPubKeyData == NULL )
		return( CRYPT_ERROR_MEMORY );
	*newPubKeyDataPtr = newPubKeyData;

	return( CRYPT_OK );
	}

static int calculatePrivkeyStorage( const PKCS15_INFO *pkcs15infoPtr,
									void **newPrivKeyDataPtr,
									int *newPrivKeyDataSize,
									const int privKeySize,
									const int privKeyAttributeSize,
									const int extraDataSize )
	{
	void *newPrivKeyData;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newPrivKeyDataPtr, sizeof( void * ) ) );
	assert( isWritePtr( newPrivKeyDataSize, sizeof( int ) ) ); 
	assert( privKeySize > 0 ); 
	assert( privKeyAttributeSize > 0 );
	assert( extraDataSize >= 0 );

	/* Calculate the new private-key data size */
	*newPrivKeyDataSize = sizeofObject( privKeyAttributeSize + \
										sizeofObject( \
											sizeofObject( privKeySize ) + \
											extraDataSize ) );

	/* If the new data will fit into the existing storage, we're done */
	if( *newPrivKeyDataSize <= pkcs15infoPtr->privKeyDataSize )
		return( CRYPT_OK );

	/* Allocate storage for the new data */
	newPrivKeyData = clAlloc( "calculatePrivkeyStorage", *newPrivKeyDataSize );
	if( newPrivKeyData == NULL )
		return( CRYPT_ERROR_MEMORY );
	*newPrivKeyDataPtr = newPrivKeyData;

	return( CRYPT_OK );
	}

static int calculateCertStorage( const PKCS15_INFO *pkcs15infoPtr,
								 void **newCertDataPtr, int *newCertDataSize,
								 const int certAttributeSize,
								 const int certSize )
	{
	void *newCertData;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newCertDataPtr, sizeof( void * ) ) );
	assert( isWritePtr( newCertDataSize, sizeof( int ) ) ); 
	assert( certAttributeSize > 0 );
	assert( certSize > 0 );

	/* Calculate the new cert data size */
	*newCertDataSize = sizeofObject( certAttributeSize + \
									 sizeofObject( \
										sizeofObject( certSize ) ) );

	/* If the new data will fit into the existing storage, we're done */
	if( *newCertDataSize <= pkcs15infoPtr->certDataSize )
		return( CRYPT_OK );

	/* Allocate storage for the new data */
	newCertData = clAlloc( "calculateCertStorage", *newCertDataSize );
	if( newCertData == NULL )
		return( CRYPT_ERROR_MEMORY );
	*newCertDataPtr = newCertData;

	return( CRYPT_OK );
	}

/* Delete the public-key entry for a personality, used when we're replacing
   the pubkey with a cert */

static void deletePubKey( PKCS15_INFO *pkcs15infoPtr )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );

	zeroise( pkcs15infoPtr->pubKeyData, pkcs15infoPtr->pubKeyDataSize );
	clFree( "deletePubKey", pkcs15infoPtr->pubKeyData );
	pkcs15infoPtr->pubKeyData = NULL;
	pkcs15infoPtr->pubKeyDataSize = 0;
	}

/* Replace existing public-key, private-key, or cert data with updated 
   information */

static void replacePubkeyData( PKCS15_INFO *pkcs15infoPtr, 
							   const void *newPubKeyData, 
							   const int newPubKeyDataSize,
							   const int newPubKeyOffset )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( newPubKeyData, newPubKeyDataSize ) );
	assert( newPubKeyOffset > 0 && newPubKeyOffset < newPubKeyDataSize );

	/* If we've allocated new storage for the data rather than directly 
	   replacing the existing entry, free the existing one and replace it
	   with the new one */
	if( newPubKeyData != pkcs15infoPtr->pubKeyData )
		{
		if( pkcs15infoPtr->pubKeyData != NULL )
			{
			zeroise( pkcs15infoPtr->pubKeyData, 
					 pkcs15infoPtr->pubKeyDataSize );
			clFree( "replacePubkeyData", pkcs15infoPtr->pubKeyData );
			}
		pkcs15infoPtr->pubKeyData = ( void * ) newPubKeyData;
		}

	/* Update the size information */
	pkcs15infoPtr->pubKeyDataSize = newPubKeyDataSize;
	pkcs15infoPtr->pubKeyOffset = newPubKeyOffset;
	}

static void replacePrivkeyData( PKCS15_INFO *pkcs15infoPtr, 
								 const void *newPrivKeyData, 
								 const int newPrivKeyDataSize,
								 const int newPrivKeyOffset )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( newPrivKeyData, newPrivKeyDataSize ) );
	assert( newPrivKeyOffset > 0 && newPrivKeyOffset < newPrivKeyDataSize );

	/* If we've allocated new storage for the data rather than directly 
	   replacing the existing entry, free the existing one and replace it
	   with the new one */
	if( newPrivKeyData != pkcs15infoPtr->privKeyData )
		{
		if( pkcs15infoPtr->privKeyData != NULL )
			{
			zeroise( pkcs15infoPtr->privKeyData, 
					 pkcs15infoPtr->privKeyDataSize );
			clFree( "replacePrivkeyData", pkcs15infoPtr->privKeyData );
			}
		pkcs15infoPtr->privKeyData = ( void * ) newPrivKeyData;
		}

	/* Update the size information */
	pkcs15infoPtr->privKeyDataSize = newPrivKeyDataSize;
	pkcs15infoPtr->privKeyOffset = newPrivKeyOffset;
	}

static void replaceCertData( PKCS15_INFO *pkcs15infoPtr, 
							 const void *newCertData, 
							 const int newCertDataSize,
							 const int newCertOffset )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( newCertData, newCertDataSize ) );
	assert( newCertOffset > 0 && newCertOffset < newCertDataSize );

	/* If we've allocated new storage for the data rather than directly 
	   replacing the existing entry, free the existing one and replace it
	   with the new one */
	if( newCertData != pkcs15infoPtr->certData )
		{
		if( pkcs15infoPtr->certData != NULL )
			{
			zeroise( pkcs15infoPtr->certData, pkcs15infoPtr->certDataSize );
			clFree( "replaceCertData", pkcs15infoPtr->certData );
			}
		pkcs15infoPtr->certData = ( void * ) newCertData;
		}

	/* Update the size information */
	pkcs15infoPtr->certDataSize = newCertDataSize;
	pkcs15infoPtr->certOffset = newCertOffset;
	}

/* Update the private-key attributes while leaving the private key itself
   untouched.  This is necessary after updating a cert associated with a 
   private key, which can affect the key's attributes */

static void updatePrivKeyAttributes( PKCS15_INFO *pkcs15infoPtr,
									 void *newPrivKeyData, 
									 const int newPrivKeyDataSize,
									 const void *privKeyAttributes,
									 const int privKeyAttributeSize,
									 const int privKeyInfoSize,
									 const int keyTypeTag )
	{
	STREAM stream;
	BYTE keyBuffer[ MAX_PRIVATE_KEYSIZE + 8 ];
	int newPrivKeyOffset, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newPrivKeyData, newPrivKeyDataSize ) );
	assert( isReadPtr( privKeyAttributes, privKeyAttributeSize ) );
	assert( privKeyInfoSize > 0 && privKeyInfoSize < MAX_PRIVATE_KEYSIZE );
	assert( keyTypeTag == DEFAULT_TAG || keyTypeTag >= 0 );

	/* Since we may be doing an in-place update of the private-key 
	   information, we copy the wrapped key data out to a temporary buffer 
	   while we make the changes */
	memcpy( keyBuffer, ( BYTE * ) pkcs15infoPtr->privKeyData +
								  pkcs15infoPtr->privKeyOffset,
			privKeyInfoSize );

	/* The corresponding key is already present, we need to update the key
	   attributes since adding the certificate may have changed them.  The
	   key data itself is unchanged, so we just memcpy() it across 
	   verbatim */
	sMemOpen( &stream, newPrivKeyData, newPrivKeyDataSize );
	writeConstructed( &stream, privKeyAttributeSize + \
							   sizeofObject( \
									sizeofObject( privKeyInfoSize ) ), 
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyInfoSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, privKeyInfoSize );
	newPrivKeyOffset = stell( &stream );
	status = swrite( &stream, keyBuffer, privKeyInfoSize );
	sMemDisconnect( &stream );
	zeroise( keyBuffer, MAX_PRIVATE_KEYSIZE );
	assert( cryptStatusOK( status ) );
	assert( checkObjectEncoding( newPrivKeyData, newPrivKeyDataSize ) > 0 );

	/* Replace the old data with the newly-written data */
	replacePrivkeyData( pkcs15infoPtr, newPrivKeyData, newPrivKeyDataSize, 
						newPrivKeyOffset );
	}

/****************************************************************************
*																			*
*								Add a Certificate							*
*																			*
****************************************************************************/

/* Add a certificate to a PKCS #15 collection, updating affected public and
   private key attributes as required */

static int addCert( PKCS15_INFO *pkcs15infoPtr,
					const CRYPT_CERTIFICATE iCryptCert,
					const void *privKeyAttributes,
					const int privKeyAttributeSize,
					const CERTADD_TYPE certAddType )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE certAttributes[ KEYATTR_BUFFER_SIZE + 8 ];
	void *newCertData = pkcs15infoPtr->certData;
	void *newPrivKeyData = pkcs15infoPtr->privKeyData;
	const int keyTypeTag = getKeyTypeTag( iCryptCert, CRYPT_ALGO_NONE );
	int newCertDataSize, newCertOffset, certInfoSize, certAttributeSize;
	int newPrivKeyDataSize, privKeyInfoSize;
	int subType = PKCS15_SUBTYPE_NORMAL, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptCert ) );
	assert( ( certAddType == CERTADD_UPDATE_EXISTING && \
			  isReadPtr( privKeyAttributes, privKeyAttributeSize ) ) || \
			( ( certAddType == CERTADD_NORMAL || \
				certAddType == CERTADD_STANDALONE_CERT ) && \
			  privKeyAttributes == NULL && privKeyAttributeSize == 0 ) );
	assert( certAddType > CERTADD_NONE && certAddType < CERTADD_LAST );

	if( cryptStatusError( keyTypeTag ) && ( keyTypeTag != DEFAULT_TAG ) )
		return( keyTypeTag );

	/* If we've been passed a standalone cert, it has to be implicitly
	   trusted in order to be added */
	if( certAddType == CERTADD_STANDALONE_CERT )
		{
		int value;

		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );

		/* Set the personality type to cert-only */
		subType = PKCS15_SUBTYPE_CERT;
		}

	/* Write the cert attributes */
	status = writeCertAttributes( certAttributes, KEYATTR_BUFFER_SIZE, 
								  &certAttributeSize, pkcs15infoPtr, 
								  iCryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Find out how big the PKCS #15 data will be and allocate room for it.
	   Since the cert will affect the key attributes, we need to rewrite the
	   key information once we've added the cert */
	if( certAddType == CERTADD_UPDATE_EXISTING )
		{
		/* Since we're re-using pre-encoded private key data, the extra info
		   is already present in encoded form, so we set the extraDataSize
		   parameter to zero */
		privKeyInfoSize = pkcs15infoPtr->privKeyDataSize - \
						  pkcs15infoPtr->privKeyOffset;
		status = calculatePrivkeyStorage( pkcs15infoPtr, &newPrivKeyData,
										  &newPrivKeyDataSize, 
										  privKeyInfoSize,
										  privKeyAttributeSize, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		certInfoSize = msgData.length;
		status = calculateCertStorage( pkcs15infoPtr, &newCertData,
									   &newCertDataSize, certAttributeSize,
									   certInfoSize );
		}
	if( cryptStatusError( status ) )
		{
		if( newPrivKeyData != pkcs15infoPtr->privKeyData )
			clFree( "addCert", newPrivKeyData );
		return( status );
		}

	/* Write the PKCS #15 cert data */
	sMemOpen( &stream, newCertData, newCertDataSize );
	writeSequence( &stream, certAttributeSize + \
							sizeofObject( sizeofObject( certInfoSize ) ) );
	swrite( &stream, certAttributes, certAttributeSize );
	writeConstructed( &stream, sizeofObject( certInfoSize ), 
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, certInfoSize );
	newCertOffset = stell( &stream );
	status = exportCertToStream( &stream, iCryptCert, 
								 CRYPT_CERTFORMAT_CERTIFICATE );
	sMemDisconnect( &stream );
	assert( cryptStatusOK( status ) );
	assert( checkObjectEncoding( newCertData, newCertDataSize ) > 0 );
	if( cryptStatusError( status ) )
		{
		/* Undo what we've done so far without changing the existing PKCS #15
		   data */
		if( newPrivKeyData != pkcs15infoPtr->privKeyData )
			clFree( "addCert", newPrivKeyData );
		if( newCertData != pkcs15infoPtr->certData && newCertData != NULL )
			clFree( "addCert", newCertData );
		return( status );
		}

#ifdef POST_DRAFT_ENCAPSULATION
	/* Certificates require an awkward [1] IMPLICIT tag, this is simple to 
	   handle handled when we're encoding the data ourselves (as we do for
	   public and private keys) but a serious pain if we're simply exporting
	   pre-encoded data like a certificate.  In order to handle this we 
	   modify the exported encoded data, which is easier than passing the 
	   tag requirement down through the kernel call to the certificate 
	   export code */
	( ( BYTE * ) newCertData )[ newCertOffset ] = MAKE_CTAG( CTAG_OV_DIRECT );
#endif /* POST_DRAFT_ENCAPSULATION */

	/* Replace the old cert (if there is one) with the new cert.  If it's a
	   cert associated with a private key, we also have to update the 
	   private-key attributes, which can be affected by cert info */
	pkcs15infoPtr->type = subType;
	replaceCertData( pkcs15infoPtr, newCertData, newCertDataSize, 
					 newCertOffset );
	if( certAddType == CERTADD_UPDATE_EXISTING )
		updatePrivKeyAttributes( pkcs15infoPtr, 
								 newPrivKeyData, newPrivKeyDataSize, 
								 privKeyAttributes, privKeyAttributeSize, 
								 privKeyInfoSize, keyTypeTag );

	/* The public-key data is redundant now that we've performed the update,
	   delete it */
	if( pkcs15infoPtr->pubKeyData != NULL )
		deletePubKey( pkcs15infoPtr );

	return( CRYPT_OK );
	}

/* Add a complete cert chain to a PKCS #15 collection */

int addCertChain( PKCS15_INFO *pkcs15info, const int noPkcs15objects,
				  const CRYPT_CERTIFICATE iCryptCert )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int iterationCount = 0, status;

	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isHandleRangeValid( iCryptCert ) );

	/* See if there are certs in the chain beyond the first one, which we've
	   already added.  Getting a data not found error is OK since it just
	   means that there are no more certs present */
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST,
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORNEXT,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );

	/* Walk up the chain checking each cert to see whether we need to add
	   it */
	do
		{
		PKCS15_INFO *pkcs15infoPtr;
		BYTE iAndSID[ CRYPT_MAX_HASHSIZE + 8 ];
		int index;

		/* Check whether this cert is present */
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
							iAndSID, KEYID_SIZE );
		if( cryptStatusError( status ) )
			continue;
		if( findEntry( pkcs15info, noPkcs15objects, CRYPT_IKEYID_ISSUERID, 
					   iAndSID, KEYID_SIZE, KEYMGMT_FLAG_NONE ) != NULL )
			continue;

		/* We've found a cert that isn't present yet, try and add it */
		pkcs15infoPtr = findFreeEntry( pkcs15info, noPkcs15objects, &index );
		if( pkcs15infoPtr == NULL )
			return( CRYPT_ERROR_OVERFLOW );
		status = addCert( pkcs15infoPtr, iCryptCert, NULL, 0, CERTADD_NORMAL );
		if( cryptStatusOK( status ) )
			pkcs15infoPtr->index = index;

		/* A cert being added may already be present, however we can't fail
		   immediately because there may be further certs in the chain that 
		   can be added, so we keep track of whether we've successfully 
		   added at least one cert and clear data duplicate errors */
		if( cryptStatusOK( status ) )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain without finding anything that we 
		   could add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;
	return( status );
	}

/****************************************************************************
*																			*
*								Add a Public Key							*
*																			*
****************************************************************************/

/* Add a public key to a PKCS #15 collection */

static int addPublicKey( PKCS15_INFO *pkcs15infoPtr,
						 const CRYPT_HANDLE iCryptContext,
						 const void *pubKeyAttributes,
						 const int pubKeyAttributeSize,
						 const CRYPT_ALGO_TYPE pkcCryptAlgo,
						 const int modulusSize )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	void *newPubKeyData = pkcs15infoPtr->pubKeyData;
	const int keyTypeTag = getKeyTypeTag( CRYPT_UNUSED, pkcCryptAlgo );
	int newPubKeyDataSize, newPubKeyOffset, pubKeySize;
	int extraDataSize = 0, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptContext ) );
	assert( isReadPtr( pubKeyAttributes, pubKeyAttributeSize ) );
	assert( pkcCryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			pkcCryptAlgo <= CRYPT_ALGO_LAST_PKC );
	assert( modulusSize >= bitsToBytes( MIN_PKCSIZE_BITS ) && \
			modulusSize <= CRYPT_MAX_PKCSIZE );

	if( cryptStatusError( keyTypeTag ) && ( keyTypeTag != DEFAULT_TAG ) )
		return( keyTypeTag );

	/* Find out how big the PKCS #15 data will be and allocate room for it */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		return( status );
	pubKeySize = msgData.length;
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		/* RSA keys have an extra element for PKCS #11 compatibility */
		extraDataSize = sizeofShortInteger( modulusSize );
	status = calculatePubkeyStorage( pkcs15infoPtr, &newPubKeyData, 
									 &newPubKeyDataSize, pubKeySize, 
									 pubKeyAttributeSize, extraDataSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the public key data */
	sMemOpen( &stream, newPubKeyData, newPubKeyDataSize );
	writeConstructed( &stream, pubKeyAttributeSize + \
							   sizeofObject( \
								sizeofObject( \
								  sizeofObject( pubKeySize ) + \
								  extraDataSize ) ),
					  keyTypeTag );
	swrite( &stream, pubKeyAttributes, pubKeyAttributeSize );
	writeConstructed( &stream, sizeofObject( \
								sizeofObject( pubKeySize ) + \
								extraDataSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, sizeofObject( pubKeySize ) + extraDataSize );
	writeConstructed( &stream, pubKeySize, CTAG_OV_DIRECT );
	newPubKeyOffset = stell( &stream );
	status = exportAttributeToStream( &stream, iCryptContext,
									  CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusOK( status ) && pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		/* When using the SPKI option for storing key components, the RSA
		   components require a [1] tag since the basic (non-SPKI) option is
		   also a SEQUENCE, so if it's an RSA key we modify the tag.  This is
		   easier than passing the tag requirement down through the kernel
		   call to the context.  In addition, RSA keys have an extra element
		   for PKCS #11 compatibility */
		( ( BYTE * ) newPubKeyData )[ newPubKeyOffset ] = MAKE_CTAG( 1 );
		status = writeShortInteger( &stream, modulusSize, DEFAULT_TAG );
		}
	assert( stell( &stream ) == newPubKeyDataSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		if( newPubKeyData != pkcs15infoPtr->pubKeyData )
			clFree( "addPublicKey", newPubKeyData );
		return( status );
		}
	assert( checkObjectEncoding( newPubKeyData, newPubKeyDataSize ) > 0 );

	/* Replace the old data with the newly-written data */
	replacePubkeyData( pkcs15infoPtr, newPubKeyData, newPubKeyDataSize,
					   newPubKeyOffset );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Add a Private Key							*
*																			*
****************************************************************************/

/* Create a strong encryption context to wrap a key */

static int createStrongEncryptionContext( CRYPT_CONTEXT *iCryptContext,
										  const CRYPT_USER iCryptOwner )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
			isHandleRangeValid( iCryptOwner ) );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* In the interests of luser-proofing we're rather paranoid and force
	   the use of non-weak algorithms and modes of operation.  In addition
	   since OIDs are only defined for a limited subset of algorithms, we
	   also default to a guaranteed available algorithm if no OID is defined
	   for the one requested */
	status = krnlSendMessage( iCryptOwner, IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_OPTION_ENCR_ALGO );
	if( cryptStatusError( status ) || isWeakCryptAlgo( cryptAlgo ) || \
		cryptStatusError( sizeofAlgoIDex( cryptAlgo, CRYPT_MODE_CBC, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;

	/* Create the context */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Generate a session key and write the wrapped key in the form
   SET OF {	[ 0 ] (EncryptedKey) } */

static int writeWrappedSessionKey( STREAM *stream,
								   CRYPT_CONTEXT iSessionKeyContext,
								   const CRYPT_USER iCryptOwner,
								   const char *password,
								   const int passwordLength )
	{
	CRYPT_CONTEXT iCryptContext;
	int iterations, exportedKeySize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( ( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
			isHandleRangeValid( iCryptOwner ) );
	assert( isReadPtr( password, passwordLength ) );

	/* In the interests of luser-proofing we force the use of a safe minimum 
	   number of iterations */
	status = krnlSendMessage( iCryptOwner, IMESSAGE_GETATTRIBUTE, &iterations,
							  CRYPT_OPTION_KEYING_ITERATIONS );
	if( cryptStatusError( status ) || \
		( iterations < MIN_KEYING_ITERATIONS ) )
		iterations = MIN_KEYING_ITERATIONS;

	/* Create an encryption context and derive the user password into it */
	status = createStrongEncryptionContext( &iCryptContext, iCryptOwner );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
							  &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Determine the size of the exported key and write the encrypted data
	   content field */
	status = iCryptExportKeyEx( NULL, &exportedKeySize, 0, CRYPT_FORMAT_CMS, 
								iSessionKeyContext, iCryptContext );
	if( cryptStatusOK( status ) )
		{
		writeSet( stream, exportedKeySize );
		status = iCryptExportKeyEx( sMemBufPtr( stream ), &exportedKeySize,
									sMemDataLeft( stream ), CRYPT_FORMAT_CMS,
									iSessionKeyContext, iCryptContext );
		if( cryptStatusOK( status ) )
			status = sSkip( stream, exportedKeySize );
		}

	/* Clean up */
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Write the private key wrapped using the session key */

static int writeWrappedPrivateKey( void *wrappedKey, 
								   const int wrappedKeyMaxLength,
								   int *wrappedKeyLength,
								   const CRYPT_HANDLE iPrivKeyContext,
								   const CRYPT_CONTEXT iSessionKeyContext,
								   const CRYPT_ALGO_TYPE pkcAlgo )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	STREAM encDataStream;
	int length, status;

	assert( isWritePtr( wrappedKey, wrappedKeyMaxLength ) );
	assert( isWritePtr( wrappedKeyLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iPrivKeyContext ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( pkcAlgo >= CRYPT_ALGO_FIRST_PKC && \
			pkcAlgo <= CRYPT_ALGO_LAST_PKC );

	/* Clear return values */
	memset( wrappedKey, 0, wrappedKeyMaxLength );
	*wrappedKeyLength = 0;

	/* Export the wrapped private key */
	setMechanismWrapInfo( &mechanismInfo, wrappedKey, wrappedKeyMaxLength, 
						  NULL, 0, iPrivKeyContext, iSessionKeyContext, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	length = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );
	*wrappedKeyLength = length;

	/* Try and check that the wrapped key data no longer contains 
	   identifiable structured data.  We can only do this for RSA keys since 
	   the amount of information present for DLP keys is too small to 
	   reliably check.  This check is performed in addition to checks 
	   already performed by the encryption code and the key wrap code */
	if( pkcAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_OK );

	/* For RSA keys the data would be:

		SEQUENCE {
			[3] INTEGER,
			...
			}

	   99.9% of all wrapped keys will fail the initial valid-SEQUENCE check, 
	   so we provide an early-out for it */
	sMemConnect( &encDataStream, wrappedKey, *wrappedKeyLength );
	status = readSequence( &encDataStream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &encDataStream );
		return( CRYPT_OK );
		}

	/* The data must contain at least p and q, or at most all key 
	   components */
	if( length < ( bitsToBytes( MIN_PKCSIZE_BITS ) * 2 ) || \
		length > MAX_PRIVATE_KEYSIZE )
		status = CRYPT_ERROR;
	else
		{
		/* The first key component is p, encoded as '[3] INTEGER' */
		status = readIntegerTag( &encDataStream, NULL, &length, 
								 CRYPT_MAX_PKCSIZE, 3 );
		if( cryptStatusOK( status ) && \
			( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
			  length > CRYPT_MAX_PKCSIZE ) )
			status = CRYPT_ERROR;
		}
	sMemDisconnect( &encDataStream );

	return( cryptStatusError( status ) ? CRYPT_OK : CRYPT_ERROR_FAILED );
	}

/* Add a private key to a PKCS #15 collection */

static int addPrivateKey( PKCS15_INFO *pkcs15infoPtr,
						  const CRYPT_HANDLE iCryptContext,
						  const CRYPT_HANDLE iCryptOwner,
						  const char *password, const int passwordLength,
						  const void *privKeyAttributes,
						  const int privKeyAttributeSize,
						  const CRYPT_ALGO_TYPE pkcCryptAlgo,
						  const int modulusSize )
	{
	CRYPT_CONTEXT iSessionKeyContext;
	MECHANISM_WRAP_INFO mechanismInfo;
	STREAM stream;
	BYTE envelopeHeaderBuffer[ 256 + 8 ];
	void *newPrivKeyData = pkcs15infoPtr->privKeyData;
	const int keyTypeTag = getKeyTypeTag( CRYPT_UNUSED, pkcCryptAlgo );
	int newPrivKeyDataSize, newPrivKeyOffset, privKeySize;
	int extraDataSize = 0, envelopeHeaderSize, envelopeContentSize, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptContext ) );
	assert( ( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
			isHandleRangeValid( iCryptOwner ) );
	assert( isReadPtr( password, passwordLength ) );
	assert( isReadPtr( privKeyAttributes, privKeyAttributeSize ) );
	assert( pkcCryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			pkcCryptAlgo <= CRYPT_ALGO_LAST_PKC );
	assert( modulusSize >= bitsToBytes( MIN_PKCSIZE_BITS ) && \
			modulusSize <= CRYPT_MAX_PKCSIZE );

	if( cryptStatusError( keyTypeTag ) && ( keyTypeTag != DEFAULT_TAG ) )
		return( keyTypeTag );

	/* Create a session key context and generate a key and IV into it.  The IV
	   would be generated automatically later on when we encrypt data for the
	   first time, but we do it explicitly here to catch any possible errors
	   at a point where recovery is easier */
	status = createStrongEncryptionContext( &iSessionKeyContext, iCryptOwner );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iSessionKeyContext, IMESSAGE_CTX_GENKEY, NULL, 
							  FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iSessionKeyContext, IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Calculate the eventual encrypted key size */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, iCryptContext,
						  iSessionKeyContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	privKeySize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusOK( status ) && privKeySize > 256 + MAX_PRIVATE_KEYSIZE )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_OVERFLOW;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Write the CMS envelope header for the wrapped private key except for 
	   the outermost wrapper, which we have to defer writing until later 
	   since we won't know the wrapped session key or inner CMS header size 
	   until we've written them.  Since we're using KEKRecipientInfo, we use 
	   a version of 2 rather than 0 */
	sMemOpen( &stream, envelopeHeaderBuffer, 256 );
	writeShortInteger( &stream, 2, DEFAULT_TAG );
	status = writeWrappedSessionKey( &stream, iSessionKeyContext,
									 iCryptOwner, password, passwordLength );
	if( cryptStatusOK( status ) )
		status = writeCMSencrHeader( &stream, OID_CMS_DATA, privKeySize,
									 iSessionKeyContext );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	envelopeHeaderSize = stell( &stream );
	envelopeContentSize = envelopeHeaderSize + privKeySize;
	sMemDisconnect( &stream );

	/* Since we haven't been able to write the outer CMS envelope wrapper 
	   yet, we need to adjust the overall size for the additional level of
	   encapsulation */
	privKeySize = ( int ) sizeofObject( privKeySize + envelopeHeaderSize );

	/* Calculate the private-key storage size */
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		/* RSA keys have an extra element for PKCS #11 compatibility */
		extraDataSize = sizeofShortInteger( modulusSize );
	status = calculatePrivkeyStorage( pkcs15infoPtr, &newPrivKeyData,
									  &newPrivKeyDataSize, privKeySize, 
									  privKeyAttributeSize, 
									  extraDataSize );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	sMemOpen( &stream, newPrivKeyData, newPrivKeyDataSize );

	/* Write the outer header and attributes */
	writeConstructed( &stream, privKeyAttributeSize + \
							   sizeofObject( sizeofObject( privKeySize ) + \
											 extraDataSize ),
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, sizeofObject( privKeySize + extraDataSize ), 
					  CTAG_OB_TYPEATTR );
	status = writeSequence( &stream, privKeySize + extraDataSize );
	newPrivKeyOffset = stell( &stream );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		if( newPrivKeyData != pkcs15infoPtr->privKeyData )
			clFree( "addPrivateKey", newPrivKeyData );
		return( status );
		}

	/* Write the previously-encoded CMS envelope header and key exchange
	   information, and follow it with the encrypted private key.  Since we
	   now know the size of the envelope header (which we couldn't write
	   earlier), we can add this now too */
	writeConstructed( &stream, envelopeContentSize, CTAG_OV_DIRECTPROTECTED );
	status = swrite( &stream, envelopeHeaderBuffer, envelopeHeaderSize );
	if( cryptStatusOK( status ) )
		status = writeWrappedPrivateKey( sMemBufPtr( &stream ), 
										 sMemDataLeft( &stream ), 
										 &privKeySize, iCryptContext, 
										 iSessionKeyContext, pkcCryptAlgo );
	if( cryptStatusOK( status ) )
		status = sSkip( &stream, privKeySize );
	if( cryptStatusOK( status ) && pkcCryptAlgo == CRYPT_ALGO_RSA )
		/* RSA keys have an extra element for PKCS #11 compability that we
		   need to kludge onto the end of the private-key data */
		status = writeShortInteger( &stream, modulusSize, DEFAULT_TAG );
	krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	assert( newPrivKeyDataSize == stell( &stream ) );
	sMemDisconnect( &stream );
	assert( checkObjectEncoding( newPrivKeyData, newPrivKeyDataSize ) > 0 );

	/* Replace the old data with the newly-written data */
	replacePrivkeyData( pkcs15infoPtr, newPrivKeyData, 
						newPrivKeyDataSize, newPrivKeyOffset );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							External Add-a-Key Interface					*
*																			*
****************************************************************************/

/* Add a key to a PKCS #15 collection */

int addKey( PKCS15_INFO *pkcs15infoPtr, const CRYPT_HANDLE iCryptHandle,
			const void *password, const int passwordLength,
			const CRYPT_USER iOwnerHandle, const BOOLEAN privkeyPresent, 
			const BOOLEAN certPresent, const BOOLEAN doAddCert, 
			const BOOLEAN pkcs15keyPresent )
	{
	CRYPT_ALGO_TYPE pkcCryptAlgo;
	BYTE pubKeyAttributes[ KEYATTR_BUFFER_SIZE + 8 ];
	BYTE privKeyAttributes[ KEYATTR_BUFFER_SIZE + 8 ];
	int pubKeyAttributeSize, privKeyAttributeSize;
	int modulusSize, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptHandle ) );
	assert( ( privkeyPresent && isReadPtr( password, passwordLength ) ) || \
			( !privkeyPresent && password == NULL && passwordLength == 0 ) );
	assert( ( iOwnerHandle == DEFAULTUSER_OBJECT_HANDLE ) || \
			isHandleRangeValid( iOwnerHandle ) );

	/* Get information from the context */
	krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE, &pkcCryptAlgo,
					 CRYPT_CTXINFO_ALGO );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE, 
							  &modulusSize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attribute information.  We have to rewrite the key
	   information when we add a non-standalone cert even if we don't change
	   the key because adding a cert can affect key attributes */
	if( ( certPresent && pkcs15keyPresent ) ||		/* Updating existing */
		( privkeyPresent && !pkcs15keyPresent ) )	/* Adding new */
		{
		status = writeKeyAttributes( privKeyAttributes, KEYATTR_BUFFER_SIZE,
									 &privKeyAttributeSize,
									 pubKeyAttributes, KEYATTR_BUFFER_SIZE,
									 &pubKeyAttributeSize, pkcs15infoPtr,
									 iCryptHandle );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the cert if necessary.  We do this one first because it's the
	   easiest to back out of */
	if( certPresent && doAddCert )
		{
		/* Select the leaf cert in case it's a cert chain */
		krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

		/* Write the cert information.  There may be further certs in the
		   chain but we don't try and do anything with these at this level,
		   the addition of supplemental certs is handled by the caller */
		if( pkcs15keyPresent )
			status = addCert( pkcs15infoPtr, iCryptHandle, privKeyAttributes,
							  privKeyAttributeSize, CERTADD_UPDATE_EXISTING );
		else
			status = addCert( pkcs15infoPtr, iCryptHandle, NULL, 0,
							  privkeyPresent ? CERTADD_NORMAL : \
											   CERTADD_STANDALONE_CERT );
		if( cryptStatusError( status ) )
			return( status );

		/* If there's no public/private-key context to add, exit */
		if( !privkeyPresent || pkcs15keyPresent )
			return( CRYPT_OK );
		}

	/* Add the public key info if the information hasn't already been added 
	   via a certificate */
	if( !certPresent )
		{
		status = addPublicKey( pkcs15infoPtr, iCryptHandle, pubKeyAttributes,
							   pubKeyAttributeSize, pkcCryptAlgo,
							   modulusSize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the private key info */
	return( addPrivateKey( pkcs15infoPtr, iCryptHandle, iOwnerHandle,
						   password, passwordLength, privKeyAttributes,
						   privKeyAttributeSize, pkcCryptAlgo,
						   modulusSize ) );
	}

/****************************************************************************
*																			*
*							Add Miscellaneous Items							*
*																			*
****************************************************************************/

/* Add configuration data to a PKCS #15 collection.  The different data
   types are:

	IATTRIBUTE_USERID: ID for objects in user keysets.  All items in the 
		keyset (which will be the user object's private key and their config 
		data) are given this value as their ID.
	
	IATTRIBUTE_CONFIGDATA: ASN.1-encoded cryptlib config options.

	IATTRIBUTE_USERINDEX: ASN.1-encoded table mapping userIDs and names to 
		a unique index value that's used to locate the file or storage 
		location for that user's config data.

	IATTRIBUTE_USERINFO: ASN.1-encoded user info containing their role, ID,
		name info, and any additional required information.

   The lookup process for a given user's info is to read the 
   IATTRIBUTE_USERINDEX from the user index file (typically index.p15) to
   find the user's index value, and then use that to read the 
   IATTRIBUTE_USERINFO from the user file (typically u<index>.p15).  The
   cryptlib-wide IATTRIBUTE_CONFIGDATA is stored in the cryptlib init.file, 
   typically cryptlib.p15.

   If we're being sent empty data (corresponding to an empty SEQUENCE, so 
   dataLength < 8), it means that the caller wants to clear this entry */

int addConfigData( PKCS15_INFO *pkcs15info, const int noPkcs15objects, 
				   const char *data, const int dataLength, const int flags )
	{
	PKCS15_INFO *pkcs15infoPtr = NULL;
	const BOOLEAN isDataClear = ( dataLength < 8 ) ? TRUE : FALSE;
	void *newData;
	int i;

	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isReadPtr( data, dataLength ) );
	assert( flags == CRYPT_IATTRIBUTE_CONFIGDATA || \
			flags == CRYPT_IATTRIBUTE_USERINDEX || \
			flags == CRYPT_IATTRIBUTE_USERID || \
			flags == CRYPT_IATTRIBUTE_USERINFO );

	/* If it's a user ID, set all object IDs to this value.  This is needed
	   for user keysets where there usually isn't any key ID present (there
	   is one for SO keysets that have public/private keys attached to them, 
	   but they're not identified by key ID so it's not much use).  In this 
	   case the caller has to explicitly set an ID, which is the user ID */
	if( flags == CRYPT_IATTRIBUTE_USERID )
		{
		const int length = min( dataLength, CRYPT_MAX_HASHSIZE );

		assert( dataLength == KEYID_SIZE );

		for( i = 0; i < noPkcs15objects; i++ )
			{
			memcpy( pkcs15info[ i ].iD, data, length );
  			pkcs15info[ i ].iDlength = length;
			}
		return( CRYPT_OK );
		}

	/* Find an entry that contains data identical to what we're adding now 
	   (which we'll replace with the new data) or, failing that, the first 
	   free entry */
	for( i = 0; i < noPkcs15objects; i++ )
		{
		if( pkcs15info[ i ].type == PKCS15_SUBTYPE_DATA && \
			pkcs15info[ i ].dataType == flags )
			{
			pkcs15infoPtr = &pkcs15info[ i ];
			break;
			}
		}
	if( pkcs15infoPtr == NULL )
		{
		/* If we're trying to delete an existing entry then not finding what
		   we want to delete is an error */
		if( isDataClear )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTFOUND );
			}

		/* We couldn't find an existing entry to update, add a new entry */
		pkcs15infoPtr = findFreeEntry( pkcs15info, noPkcs15objects, NULL );
		}
	if( pkcs15infoPtr == NULL )
		/* The appropriate error value to return here is a 
		   CRYPT_ERROR_OVERFLOW because we always try to add a new entry if
		   we can't find an existing one, so the final error status is 
		   always an overflow */
		return( CRYPT_ERROR_OVERFLOW );

	/* If we're clearing an existing entry, we're done */
	if( isDataClear )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		return( CRYPT_OK );
		}

	/* If we're adding new data and there's no existing storage available, 
	   allocate storage for it */
	if( pkcs15infoPtr->dataData == NULL || \
		dataLength > pkcs15infoPtr->dataDataSize )
		{
		newData = clAlloc( "addConfigData", dataLength );
		if( newData == NULL )
			return( CRYPT_ERROR_MEMORY );

		/* If there's existing data present, clear and free it */
		if( pkcs15infoPtr->dataData != NULL )
			{
			zeroise( pkcs15infoPtr->dataData, pkcs15infoPtr->dataDataSize );
			clFree( "addConfigData", pkcs15infoPtr->dataData );
			}
		}
	else
		/* There's existing data present and the new data will fit into its
		   storage, re-use the existing storage */
		newData = pkcs15infoPtr->dataData;

	/* Remember the pre-encoded config data */
	pkcs15infoPtr->dataData = newData;
	memcpy( pkcs15infoPtr->dataData, data, dataLength );
	pkcs15infoPtr->dataDataSize = dataLength;

	/* Set the type information for the data */
	pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
	pkcs15infoPtr->dataType = flags;

	return( CRYPT_OK );
	}

/* Add a secret key to a PKCS #15 collection */

int addSecretKey( PKCS15_INFO *pkcs15info, const int noPkcs15objects,
				  const CRYPT_CONTEXT iCryptContext )
	{
	PKCS15_INFO *pkcs15infoPtr = NULL;
	MESSAGE_DATA msgData;
	char label[ CRYPT_MAX_TEXTSIZE + 8 ];
	int status;

	assert( isWritePtr( pkcs15infoPtr, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isHandleRangeValid( iCryptContext ) );

	/* Check the object and make sure that the label of what we're adding
	   doesn't duplicate the label of an existing object */
	status = krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_CRYPT );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		return( status );
	if( findEntry( pkcs15info, noPkcs15objects, CRYPT_KEYID_NAME, 
				   msgData.data, msgData.length, 
				   KEYMGMT_FLAG_NONE ) != NULL )
		return( CRYPT_ERROR_DUPLICATE );

	/* Find out where we can add the new key data */
	pkcs15infoPtr = findFreeEntry( pkcs15info, noPkcs15objects, NULL );
	if( pkcs15infoPtr == NULL )
		return( CRYPT_ERROR_OVERFLOW );

	pkcs15infoPtr->type = PKCS15_SUBTYPE_SECRETKEY;

	/* This functionality is currently unused */
	assert( NOTREACHED );
	return( CRYPT_ERROR_INTERNAL );
	}
#endif /* USE_PKCS15 */
