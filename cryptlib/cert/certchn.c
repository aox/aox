/****************************************************************************
*																			*
*					  Certificate Chain Management Routines					*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

/* This module and certchk.c implement the following PKIX checks (* =
   unhandled, see the code comments.  Currently only policy mapping is
   unhandled, this is optional in PKIX and given the nature of the
   kitchenSink extension no-one really knows how to apply it anyway):

	General:

	(a) Verify the basic certificate information:
		(1) The certificate signature is valid.
		(2a) The certificate has not expired.
		(2b) If present, the private key usage period is satisfied.
		(3) The certificate has not been revoked.
		(4a) The subject and issuer name chains correctly.
		(4b) If present, the subjectAltName and issuerAltName chains
			 correctly.

	NameConstraints:

	(b) Verify that the subject name or critical subjectAltName is consistent
		with the constrained subtrees.

	(c) Verify that the subject name or critical subjectAltName is consistent
		with the excluded subtrees.

	Policy Constraints:

	(d) Verify that policy info.is consistent with the initial policy set:
		(1) If the explicit policy state variable is less than or equal to n,
			a policy identifier in the certificate must be in initial policy
			set.
*		(2) If the policy mapping variable is less than or equal to n, the
			policy identifier may not be mapped.

	(e) Verify that policy info.is consistent with the acceptable policy set:
		(1) If the policies extension is marked critical, the policies
			extension must lie within the acceptable policy set.
		(2) The acceptable policy set is assigned the resulting intersection
			as its new value.

	(g) Verify that the intersection of the acceptable policy set and the
		initial policy set is non-null (this is covered by chaining of e(1)).

	Other Constraints:

	(h) Recognize and process any other critical extension present in the
		certificate.

	(i) Verify that the certificate is a CA certificate.

	Update of state:

	(j) If permittedSubtrees is present in the certificate, set the
		constrained subtrees state variable to the intersection of its
		previous value and the value indicated in the extension field.

	(k) If excludedSubtrees is present in the certificate, set the excluded
		subtrees state variable to the union of its previous value and the
		value indicated in the extension field.

	(l) If a policy constraints extension is included in the certificate,
		modify the explicit policy and policy mapping state variables as
		follows:
		(1) If requireExplicitPolicy is present and has value r, the explicit
			policy state variable is set to the minimum of (a) its current
			value and (b) the sum of r and n (the current certificate in the
			sequence).
*		(2) If inhibitPolicyMapping is present and has value q, the policy
			mapping state variable is set to the minimum of (a) its current
			value and (b) the sum of q and n (the current certificate in the
			sequence) */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/* When matching by subjectKeyIdentifier, we don't use values less than 40
   bits because some CAs use monotonically increasing sequence numbers for 
   the sKID, which can clash with the same values when used by other CAs */

#define MIN_SKID_SIZE	5

/* A structure for storing pointers to parent and child (issuer and subject)
   names, key identifiers, and serial numbers (for finding a cert by 
   issuerAndSerialNumber), and one for storing pointers to chaining info */

typedef struct {
	const void *issuerDN, *subjectDN;
	int issuerDNsize, subjectDNsize;
	const void *subjectKeyIdentifier, *issuerKeyIdentifier;
	int subjectKeyIDsize, issuerKeyIDsize;
	const void *serialNumber;
	int serialNumberSize;
	} CERTCHAIN_INFO;

typedef struct {
	const void *DN, *keyIdentifier;
	int DNsize, keyIDsize;
	} CHAINING_INFO;

/* Prototypes for functions in cryptcrt.c */

int compareSerialNumber( const void *canonSerialNumber, 
						 const int canonSerialNumberLength,
						 const void *serialNumber, 
						 const int serialNumberLength );

/* Prototypes for functions in lib_sign.c */

int checkX509signature( const void *signedObject, const int signedObjectLength,
						void **object, int *objectLength, 
						const CRYPT_CONTEXT sigCheckContext,
						const int formatInfo );

/****************************************************************************
*																			*
*									Utility Routines						*
*																			*
****************************************************************************/

/* Copy subject or issuer chaining values from the chaining info */

static void getSubjectChainingInfo( CHAINING_INFO *chainingInfo,
									const CERTCHAIN_INFO *certChainInfo )
	{
	assert( isWritePtr( chainingInfo, CHAINING_INFO ) );
	assert( isReadPtr( certChainInfo, CERTCHAIN_INFO ) );

	chainingInfo->DN = certChainInfo->subjectDN;
	chainingInfo->DNsize = certChainInfo->subjectDNsize;
	chainingInfo->keyIdentifier = certChainInfo->subjectKeyIdentifier;
	chainingInfo->keyIDsize = certChainInfo->subjectKeyIDsize;
	}

static void getIssuerChainingInfo( CHAINING_INFO *chainingInfo,
								   const CERTCHAIN_INFO *certChainInfo )
	{
	assert( isWritePtr( chainingInfo, CHAINING_INFO ) );
	assert( isReadPtr( certChainInfo, CERTCHAIN_INFO ) );

	chainingInfo->DN = certChainInfo->issuerDN;
	chainingInfo->DNsize = certChainInfo->issuerDNsize;
	chainingInfo->keyIdentifier = certChainInfo->issuerKeyIdentifier;
	chainingInfo->keyIDsize = certChainInfo->issuerKeyIDsize;
	}

/* Determine whether a given cert is the subject or issuer for the requested 
   cert based on the chaining info.  We chain by issuer DN if possible, but
   if that fails we use the keyID.  This is somewhat dodgy since it can lead 
   to the situation where a certificate supposedly issued by Verisign Class 1 
   Public Primary Certification Authority is actually issued by Honest Joe's 
   Used Cars, but the standard requires this as a fallback.  There are 
   actually two different interpretations of chaining by keyID, the first
   (which we use here) says that the keyID is a non-DN identifier that can
   survive operations such as cross-certification and re-parenting, so that
   if a straight chain by DN fails then a chain by keyID is possible as a
   fallback option.  The second interpretation is that the keyID is a
   disambiguator if multiple paths in a chain-by-DN scenario are present in
   a spaghetti PKI.  Since the latter is rather unlikely to occur in a 
   standard PKCS #7/SSL cert chain (half the implementations around wouldn't
   be able to assemble the chain any more), we use the former 
   interpretation */

static BOOLEAN isSubject( const CHAINING_INFO *chainingInfo,
						  const CERTCHAIN_INFO *certChainInfo )
	{
	assert( isReadPtr( chainingInfo, CHAINING_INFO ) );
	assert( isReadPtr( certChainInfo, CERTCHAIN_INFO ) );

	/* In the simplest case we chain by name.  This works for almost all
	   certificates */
	if( chainingInfo->DNsize > 0 && \
		chainingInfo->DNsize == certChainInfo->subjectDNsize && \
		!memcmp( chainingInfo->DN, certChainInfo->subjectDN,
				 certChainInfo->subjectDNsize ) )
		return( TRUE );

	/* If that fails we chain by keyID */
	if( chainingInfo->keyIDsize > MIN_SKID_SIZE && \
		chainingInfo->keyIDsize == certChainInfo->subjectKeyIDsize && \
		!memcmp( chainingInfo->keyIdentifier, 
				 certChainInfo->subjectKeyIdentifier,
				 certChainInfo->subjectKeyIDsize ) )
		return( TRUE );

	return( FALSE );
	}

static BOOLEAN isIssuer( const CHAINING_INFO *chainingInfo,
						 const CERTCHAIN_INFO *certChainInfo )
	{
	assert( isReadPtr( chainingInfo, CHAINING_INFO ) );
	assert( isReadPtr( certChainInfo, CERTCHAIN_INFO ) );

	/* In the simplest case we chain by name.  This works for almost all
	   certificates */
	if( chainingInfo->DNsize > 0 && \
		chainingInfo->DNsize == certChainInfo->issuerDNsize && \
		!memcmp( chainingInfo->DN, certChainInfo->issuerDN,
				 certChainInfo->issuerDNsize ) )
		return( TRUE );

	/* If that fails we chain by keyID */
	if( chainingInfo->keyIDsize > MIN_SKID_SIZE && \
		chainingInfo->keyIDsize == certChainInfo->issuerKeyIDsize && \
		!memcmp( chainingInfo->keyIdentifier, 
				 certChainInfo->issuerKeyIdentifier,
				 certChainInfo->issuerKeyIDsize ) )
		return( TRUE );

	return( FALSE );
	}

/* Get the location and size of certificate attribute data required for
   chaining */

static void *getChainingAttribute( CERT_INFO *certInfoPtr,
								   const CRYPT_ATTRIBUTE_TYPE attributeType,
								   int *attributeLength )
	{
	ATTRIBUTE_LIST *attributePtr;

	assert( isWritePtr( certInfoPtr, CERT_INFO ) );

	/* Find the requested attribute and return a pointer to it */
	attributePtr = findAttributeField( certInfoPtr->attributes,
									   attributeType, CRYPT_ATTRIBUTE_NONE );
	if( attributePtr == NULL )
		{
		*attributeLength = 0;
		return( NULL );
		}
	*attributeLength = attributePtr->valueLength;
	return( attributePtr->value );
	}

/* Free a cert chain */

static void freeCertChain( CRYPT_CERTIFICATE *iCertChain,
						   const int certChainSize )
	{
	int i;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isWritePtrEx( iCertChain, CRYPT_CERTIFICATE, certChainSize ) );

	for( i = 0; i < certChainSize; i++ )
		{
		krnlSendNotifier( iCertChain[ i ], IMESSAGE_DESTROY );
		iCertChain[ i ] = CRYPT_ERROR;
		}
	}

/* Build up the parent/child pointers for a cert chain */

static int buildCertChainInfo( CERTCHAIN_INFO *certChainInfo,
							   const CRYPT_CERTIFICATE *iCertChain,
							   const int certChainSize )
	{
	int i;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isWritePtrEx( certChainInfo, CERTCHAIN_INFO, certChainSize ) );
	assert( isReadPtrEx( iCertChain, CRYPT_CERTIFICATE, certChainSize ) );

	/* Extract the subject and issuer DNs and key identifiers from each
	   certificate.  Maintaining an external pointer into the internal
	   structure is safe since the objects are reference-counted and won't be
	   destroyed until the encapsulating cert is destroyed */
	for( i = 0; i < certChainSize; i++ )
		{
		CERT_INFO *certChainPtr;
		int status;

		status = krnlGetObject( iCertChain[ i ], OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certChainPtr, 
								CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		certChainInfo[ i ].subjectDN = certChainPtr->subjectDNptr;
		certChainInfo[ i ].issuerDN = certChainPtr->issuerDNptr;
		certChainInfo[ i ].subjectDNsize = certChainPtr->subjectDNsize;
		certChainInfo[ i ].issuerDNsize = certChainPtr->issuerDNsize;
		certChainInfo[ i ].subjectKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
								  &certChainInfo[ i ].subjectKeyIDsize );
		certChainInfo[ i ].issuerKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
								  &certChainInfo[ i ].issuerKeyIDsize );
		certChainInfo[ i ].serialNumber = certChainPtr->serialNumber;
		certChainInfo[ i ].serialNumberSize = certChainPtr->serialNumberLength;
		krnlReleaseObject( certChainPtr->objectHandle );
		}

	return( CRYPT_OK );
	}

/* Find the leaf node in a (possibly unordered) cert chain by walking down
   the chain as far as possible.  The strategy we use is to pick an initial
   cert (which is usually the leaf cert anyway) and keep looking for certs 
   it (or its successors) have issued until we reach the end of the chain.
   Returns the position of the leaf node in the chain */

static int findLeafNode( const CERTCHAIN_INFO *certChainInfo,
						 const int certChainSize )
	{
	CHAINING_INFO chainingInfo;
	BOOLEAN certUsed[ MAX_CHAINLENGTH ];
	int lastCertPos, i;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isReadPtrEx( certChainInfo, CERTCHAIN_INFO, certChainSize ) );

	/* We start our search at the first cert, which is often the leaf cert
	   anyway */
	memset( certUsed, 0, MAX_CHAINLENGTH * sizeof( BOOLEAN ) );
	getSubjectChainingInfo( &chainingInfo, &certChainInfo[ 0 ] );
	certUsed[ 0 ] = TRUE;
	lastCertPos = 0;

	/* Walk down the chain from the currently selected cert checking for
	   certs issued by it, until we can't go any further */
	do
		{
		/* Try and find a cert issued by the current cert */
		for( i = 0; i < certChainSize; i++ )
			if( !certUsed[ i ] && \
				isIssuer( &chainingInfo, &certChainInfo[ i ] ) )
				{
				/* There's another cert below the current one in the chain, 
				   mark the current one as used and move on to the next
				   one */
				getSubjectChainingInfo( &chainingInfo, &certChainInfo[ i ] );
				certUsed[ i ] = TRUE;
				lastCertPos = i;
				break;
				}
		}
	while( i != certChainSize );

	return( lastCertPos );
	}

/* Find a leaf node as identified by issuerAndSerialNumber.  Returns the 
   position of the leaf node in the chain */

static int findIdentifiedLeafNode( const CERTCHAIN_INFO *certChainInfo,
								   const int certChainSize,
								   const CRYPT_KEYID_TYPE keyIDtype,
								   const void *keyID, const int keyIDlength )
	{
	STREAM stream;
	const BYTE *serialNumber;
	const void *issuerDNptr;
	int issuerDNsize, serialNumberSize;
	int length, i, status;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isReadPtrEx( certChainInfo, CERTCHAIN_INFO, certChainSize ) );
	assert( keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	assert( keyID != NULL );
	assert( keyIDlength > 16 );

	/* If it's a subjectKeyIdentifier, walk down the chain looking for a
	   match */
	if( keyIDtype == CRYPT_IKEYID_KEYID )
		{
		for( i = 0; i < certChainSize; i++ )
			if( certChainInfo[ i ].subjectKeyIDsize > MIN_SKID_SIZE && \
				certChainInfo[ i ].subjectKeyIDsize == keyIDlength && \
				!memcmp( certChainInfo[ i ].subjectKeyIdentifier, keyID,
						 keyIDlength ) )
			return( i );

		return( CRYPT_ERROR_NOTFOUND );
		}

	/* It's an issuerAndSerialNumber, extract the issuer DN and serial 
	   number */
	sMemConnect( &stream, keyID, keyIDlength );
	readSequence( &stream, NULL );
	issuerDNptr = sMemBufPtr( &stream );
	readSequence( &stream, &length );				/* Issuer DN */
	issuerDNsize = ( int ) sizeofObject( length );
	sSkip( &stream, length );
	readGenericHole( &stream, &serialNumberSize, BER_INTEGER );
	serialNumber = sMemBufPtr( &stream );			/* Serial number */
	status = sSkip( &stream, serialNumberSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* Walk down the chain looking for the one identified by the 
	   issuerAndSerialNumber */
	for( i = 0; i < certChainSize; i++ )
		if( certChainInfo[ i ].issuerDNsize > 0 && \
			certChainInfo[ i ].issuerDNsize == issuerDNsize && \
			!memcmp( certChainInfo[ i ].issuerDN, issuerDNptr,
					 issuerDNsize ) && \
			!compareSerialNumber( certChainInfo[ i ].serialNumber, 
								  certChainInfo[ i ].serialNumberSize,
								  serialNumber, serialNumberSize ) )
			return( i );

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Determine whether a cert is present in a cert collection based on its
   fingerprint */

static BOOLEAN certPresent( BYTE certChainHashes[][ CRYPT_MAX_HASHSIZE ],
							const int certChainLen, 
							const CRYPT_CERTIFICATE iCryptCert )
	{
	RESOURCE_DATA msgData;
	int i, status;

	/* Get the fingerprint of the (potential) next cert in the collection */
	setMessageData( &msgData, certChainHashes[ certChainLen ], 
					CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_FINGERPRINT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it isn't already present in the collection */
	for( i = 0; i < certChainLen; i++ )
		if( !memcmp( certChainHashes[ i ], 
					 certChainHashes[ certChainLen ], msgData.length ) )
			return( TRUE );
	return( FALSE );
	}

/* Sort the issuer certs in a cert chain, discarding any unnecessary certs.  
   If we're canonicalising an existing chain then the start point in the 
   chain is given by certChainStart and the -1th cert is the end user cert 
   and isn't part of the ordering process.  If we're building a new chain 
   from an arbitrary set of certs then the start point is given by the 
   chaining info for the leaf cert.  Returns the length of the ordered 
   chain */

static int sortCertChain( CRYPT_CERTIFICATE *iCertChain,
						  CERTCHAIN_INFO *certChainInfo,
						  const int certChainSize,
						  const CRYPT_CERTIFICATE certChainStart,
						  CHAINING_INFO *chainingInfo )
	{
	CRYPT_CERTIFICATE orderedChain[ MAX_CHAINLENGTH ];
	CHAINING_INFO localChainingInfo, *chainingInfoPtr = &localChainingInfo;
	int orderedChainIndex = 0, i;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isWritePtrEx( iCertChain, CRYPT_CERTIFICATE, certChainSize ) );
	assert( isWritePtrEx( certChainInfo, CERTCHAIN_INFO, certChainSize ) );
	assert( ( checkHandleRange( certChainStart ) && \
			  chainingInfo == NULL ) || \
			( certChainStart == CRYPT_UNUSED && \
			  isWritePtr( chainingInfo, CHAINING_INFO ) ) );

	/* If we're canonicalising an existing chain, there's a predefined chain
	   start that we copy over and prepare to look for the next cert up the
	   chain */
	if( certChainStart != CRYPT_UNUSED )
		{
		orderedChain[ orderedChainIndex++ ] = certChainStart;
		getIssuerChainingInfo( chainingInfoPtr, &certChainInfo[ 0 ] );
		memset( &certChainInfo[ 0 ], 0, sizeof( CERTCHAIN_INFO ) );
		}
	else
		/* We're building a new chain, the caller has supplied the chaining
		   info */
		chainingInfoPtr = chainingInfo;

	/* Build an ordered chain of certs from the leaf to the root */
	do
		{
		/* Find the cert with the current issuer as its subject */
		for( i = 0; i < certChainSize; i++ )
			if( isSubject( chainingInfoPtr, &certChainInfo[ i ] ) )
				{
				/* We've found the issuer, move the certs to the ordered
				   chain and prepare to find the issuer of this cert */
				orderedChain[ orderedChainIndex++ ] = iCertChain[ i ];
				getIssuerChainingInfo( chainingInfoPtr, &certChainInfo[ i ] );
				memset( &certChainInfo[ i ], 0, sizeof( CERTCHAIN_INFO ) );
				break;
				}
		}
	while( i != certChainSize );

	/* If there are any certs left, they're not needed for anything so we can
	   free the resources */
	for( i = 0; i < certChainSize; i++ )
		if( certChainInfo[ i ].subjectDN != NULL )
			krnlSendNotifier( iCertChain[ i ], IMESSAGE_DECREFCOUNT );

	/* Replace the existing chain with the ordered version */
	memset( iCertChain, 0, sizeof( CRYPT_CERTIFICATE ) * MAX_CHAINLENGTH );
	if( orderedChainIndex > 0 )
		memcpy( iCertChain, orderedChain,
				sizeof( CRYPT_CERTIFICATE ) * orderedChainIndex );

	return( orderedChainIndex );
	}

/* Copy a cert chain into a certificate object and canonicalise the chain by
   ordering the certs in a cert chain from the leaf cert up to the root.  
   This function is used when signing a cert with a cert chain, and takes as
   input ( oldCert, oldCert.chain[ ... ] ) and produces as output ( newCert, 
   chain[ oldCert, oldCert.chain[ ... ] ], i.e.the chain for the new cert
   contains the old cert and its attached cert chain */

int copyCertChain( CERT_INFO *certInfoPtr, const CRYPT_HANDLE certChain,
				   const BOOLEAN isCertCollection )
	{
	CRYPT_CERTIFICATE iChainCert;
	CERT_INFO *chainCertInfoPtr;
	CERTCHAIN_INFO certChainInfo[ MAX_CHAINLENGTH ];
	BYTE certChainHashes[ MAX_CHAINLENGTH + 1 ][ CRYPT_MAX_HASHSIZE ];
	int i, status;

	assert( isWritePtr( certInfoPtr, CERT_INFO ) );

	status = krnlSendMessage( certChain, IMESSAGE_GETDEPENDENT, &iChainCert, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're building a cert collection, all we need to ensure is non-
	   duplicate certs rather than a strict chain.  To handle duplicate-
	   checking, we build a list of the fingerprints for each cert in the
	   chain */
	if( isCertCollection )
		{
		for( i = 0; i < certInfoPtr->certChainEnd; i++ )
			{
			RESOURCE_DATA msgData;

			setMessageData( &msgData, certChainHashes[ i ], 
							CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( certInfoPtr->certChain[ i ], 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_CERTINFO_FINGERPRINT );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Extract the base certificate from the chain and copy it over */
	status = krnlGetObject( iChainCert, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &chainCertInfoPtr, 
							CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	if( !isCertCollection || \
		!certPresent( certChainHashes, certInfoPtr->certChainEnd,
					  iChainCert ) )
		{
		krnlSendNotifier( iChainCert, IMESSAGE_INCREFCOUNT );
		certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = iChainCert;
		}

	/* Copy the rest of the chain.  Because we're about to canonicalise it
	   (which reorders the certs and deletes unused ones) we copy individual
	   certs over rather than copying only the base cert and relying on the
	   chain held in that */
	for( i = 0; i < chainCertInfoPtr->certChainEnd; i++ )
		if( !isCertCollection || \
			!certPresent( certChainHashes, certInfoPtr->certChainEnd,
						  chainCertInfoPtr->certChain[ i ] ) )
			{
			certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = \
										chainCertInfoPtr->certChain[ i ];
			krnlSendNotifier( chainCertInfoPtr->certChain[ i ],
							  IMESSAGE_INCREFCOUNT );
			}
	krnlReleaseObject( chainCertInfoPtr->objectHandle );

	/* If we're building an unordered cert collection, mark the cert chain
	   object as a cert collection only and exit */
	if( isCertCollection )
		{
		certInfoPtr->flags |= CERT_FLAG_CERTCOLLECTION;
		return( CRYPT_OK );
		}

	/* If the chain being attached consists of a single cert (which occurs
	   when we're building a new chain by signing a cert with a CA cert), we 
	   don't have to bother doing anything else */
	if( chainCertInfoPtr->certChainEnd <= 0 )
		return( CRYPT_OK );

	/* Extract the chaining info from each certificate and use it to sort the
	   chain.  Since we know what the leaf cert is and since chaining info 
	   such as the encoded DN data in the certinfo structure may not have been
	   set up yet if it contains an unsigned cert, we feed in the leaf cert 
	   and omit the chaining info */
	status = buildCertChainInfo( certChainInfo, certInfoPtr->certChain,
								 certInfoPtr->certChainEnd );
	if( cryptStatusOK( status ) )
		status = sortCertChain( certInfoPtr->certChain, certChainInfo,
								certInfoPtr->certChainEnd, iChainCert, 
								NULL );
	if( cryptStatusError( status ) )
		return( status );
	certInfoPtr->certChainEnd = status;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Verify a Certificate Chain						*
*																			*
****************************************************************************/

/* Get the next certificate down the chain.  Returns OK_SPECIAL if there are
   no more certs present */

static int getNextCert( const CERT_INFO *certInfoPtr,
						CERT_INFO **certChainPtr, const int certChainIndex )
	{
	assert( isReadPtr( certInfoPtr, CERT_INFO ) );

	if( certChainIndex >= 0 )
		return( krnlGetObject( certInfoPtr->certChain[ certChainIndex ], 
							   OBJECT_TYPE_CERTIFICATE, 
							   ( void ** ) certChainPtr, 
							   CRYPT_ERROR_SIGNALLED ) );
	if( certChainIndex == -1 )
		{
		/* The -1th cert is the leaf itself */
		*certChainPtr = ( CERT_INFO * ) certInfoPtr;
		return( CRYPT_OK );
		}

	/* We've reached the end of the chain, return a special status value to
	   indicate this */
	*certChainPtr = NULL;
	return( OK_SPECIAL );
	}

/* Check constraints along a cert chain, checked if complianceLevel >=
   CRYPT_COMPLIANCELEVEL_PKIX_FULL.  There are three types of constraints 
   that can cover multiple certs: path constraints, name constraints, and 
   policy constraints.

   Path constraints are easiest to check, just make sure that the number of 
   certs from the issuer to the leaf is less than the constraint length.

   Name constraints are a bit more difficult, the abstract description
   requires building and maintaining a (potentially enormous) name constraint
   tree which is applied to each cert in turn as it is processed, however
   since name constraints are practically nonexistant and chains are short
   it's more efficient to walk down the cert chain when a constraint is
   encountered and check each cert in turn, which avoids having to maintain
   massive amounts of state information and is no less efficient than a
   single monolithic state comparison.

   Policy constraints are hardest of all because, with the complex mishmash
   of policies, policy constraints, qualifiers, and mappings it turns out
   that no-one actually knows how to apply them, and even if people could
   agree, with the de facto use of the policy extension as the kitchenSink
   extension it's uncertain how to apply the constraints to typical
   kitchenSink constructs.  The ambiguity of name constraints when applied 
   to altNames is bad enough, with a 50/50 split in PKIX about whether it 
   should be an AND or OR operation, and whether a DN constraint applies to 
   a subjectName or altName or both (the latter was fixed in the final 
   version of RFC 2459, although how many implementations follow exactly 
   this version rather than the dozen earlier drafts or any other profile is 
   unknown).  With policy constraints it's even worse and no-one seems to be 
   able to agree on what to do with them.  For this reason we should leave 
   this particular rathole for someone else to fall into, but to claim 
   buzzword-compliance to PKIX we need to implement this checking (although 
   we don't handle the weirder constraints on policies, which have never 
   been seen in the wild, yet).  Massa make big magic, gunga din */

static int checkConstraints( CERT_INFO *certInfoPtr,
							 const CERT_INFO *issuerCertInfoPtr,
							 int *subjectCertIndex )
	{
	const ATTRIBUTE_LIST *nameAttributeListPtr, *policyAttributeListPtr;
	const ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN hasExcludedSubtrees, hasPermittedSubtrees, hasPolicy;
	BOOLEAN requireExplicitPolicyPresent = FALSE;
	int requireExplicitPolicyLevel = CRYPT_ERROR;
	int certIndex = *subjectCertIndex, status = CRYPT_OK;

	assert( isWritePtr( certInfoPtr, CERT_INFO ) );
	assert( isReadPtr( issuerCertInfoPtr, CERT_INFO ) );

	/* If there's a path length constraint present, check that it's
	   satisfied: The number of certs from the issuer (at subjectCertIndex 
	   + 1) to the end entity (at -1) must be less than the length 
	   constraint, i.e. the subjectCertIndex must be greater than the 
	   length */
	attributeListPtr = findAttributeField( issuerCertInfoPtr->attributes,
										   CRYPT_CERTINFO_PATHLENCONSTRAINT, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && \
		!( issuerCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) && \
		attributeListPtr->intValue <= certIndex )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_PATHLENCONSTRAINT,
					  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're at the 0-th cert we don't have to perform any constraint
	   checking since the check for (leaf, [0]) is performed by checkCert().
	   If it's a self-signed cert, the constraints don't apply to itself (a 
	   Smith and Wesson beats four aces) */
	if( certIndex < 0 || ( issuerCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
		return( CRYPT_OK );

	/* If there aren't any name or policy constraint present, we're done */
	if( !checkAttributePresent( issuerCertInfoPtr->attributes, \
								CRYPT_CERTINFO_NAMECONSTRAINTS ) && \
		!checkAttributePresent( issuerCertInfoPtr->attributes, \
								CRYPT_CERTINFO_POLICYCONSTRAINTS ) )
		return( CRYPT_OK );
	
	/* Check that the name/policy constraints are satisfied for all certs 
	   below this one */
	nameAttributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
										  CRYPT_CERTINFO_NAMECONSTRAINTS, FALSE );
	policyAttributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
											CRYPT_CERTINFO_POLICYCONSTRAINTS, FALSE );
	hasExcludedSubtrees = findAttributeField( nameAttributeListPtr, \
											  CRYPT_CERTINFO_EXCLUDEDSUBTREES, 
											  CRYPT_ATTRIBUTE_NONE ) != NULL;
	hasPermittedSubtrees = findAttributeField( nameAttributeListPtr, \
											   CRYPT_CERTINFO_PERMITTEDSUBTREES, 
											   CRYPT_ATTRIBUTE_NONE ) != NULL;
	hasPolicy = findAttributeField( policyAttributeListPtr, \
									CRYPT_CERTINFO_CERTPOLICYID, 
								    CRYPT_ATTRIBUTE_NONE ) != NULL;

	/* Check whether there's a requireExplicitPolicy attribute.  The 
	   handling of this is very ambiguous since other parts of the path 
	   validation requirements stipulate that policies should be checked 
	   anyway (even if requireExplicitPolicy isn't set), and no-one knows 
	   what to do if multiple requireExplicitPolicy settings are present in 
	   a chain (for example due to reparenting).  This implementation 
	   handles it by returning an error if a second requireExplicitPolicy
	   attribute that contradicts the first one is encountered */
	attributeListPtr = findAttributeField( policyAttributeListPtr,
										   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		requireExplicitPolicyLevel = ( int ) attributeListPtr->intValue;
		requireExplicitPolicyPresent = TRUE;
		}

	/* Walk down the chain checking each cert against the issuer */
	do
		{
		CERT_INFO *subjectCertInfoPtr;

		/* Get the next cert in the chain */
		certIndex--;
		status = getNextCert( certInfoPtr, &subjectCertInfoPtr, certIndex );
		if( status == OK_SPECIAL )
			/* We've reached the end of the chain, exit */
			break;

		/* If there's a second policy constraint present further down the 
		   chain, make sure that it doesn't contradict the current one */
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && requireExplicitPolicyPresent && \
			attributeListPtr->intValue != requireExplicitPolicyLevel )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			status = CRYPT_ERROR_INVALID;
			break;
			}

		/* If there's a requireExplicitPolicy skip count, decrement it for 
		   each cert */
		if( requireExplicitPolicyLevel > CRYPT_ERROR )
			requireExplicitPolicyLevel--;

		/* Check that the current cert obeys the constraints set by the 
		   issuer */
		if( hasExcludedSubtrees && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
										nameAttributeListPtr, TRUE,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) );
			status = CRYPT_ERROR_INVALID;
		if( hasPermittedSubtrees && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
										nameAttributeListPtr, FALSE,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) );
			status = CRYPT_ERROR_INVALID;
		if( hasPolicy && requireExplicitPolicyLevel == CRYPT_ERROR && \
			cryptStatusError( checkPolicyConstraints( subjectCertInfoPtr,
										policyAttributeListPtr,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) );
			status = CRYPT_ERROR_INVALID;
		krnlReleaseObject( subjectCertInfoPtr->objectHandle );
		}
	while( cryptStatusOK( status ) );
	if( status == CRYPT_OK || status == OK_SPECIAL )
		return( CRYPT_OK );

	/* Remember which cert in the chain caused the problem */
	*subjectCertIndex = certIndex;
	return( status );
	}

/* Walk down a chain checking each certificate */

static int checkLeafCertTrust( CERT_INFO *certInfoPtr, 
							   CRYPT_CERTIFICATE *iIssuerCert )
	{
	SELECTION_STATE savedState;
	int status;

	/* Clear return value */
	*iIssuerCert = CRYPT_ERROR;

	/* Explicitly select the leaf cert by making it appear that the cert 
	   chain is empty.  This is required in order to ensure that we check 
	   the leaf rather than the currently-selected cert */
	saveSelectionState( savedState, certInfoPtr );
	certInfoPtr->certChainPos = CRYPT_ERROR;

	/* If the leaf cert is implicitly trusted, there's nothing to do */
	status = krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE,
							  &certInfoPtr->objectHandle, 
							  CRYPT_IATTRIBUTE_CERT_CHECKTRUST );
	if( cryptStatusOK( status ) )
		status = OK_SPECIAL;
	else
		{
		/* If the leaf cert's issuer is implicitly trusted, we only need to 
		   check the signature on the leaf cert */
		*iIssuerCert = certInfoPtr->objectHandle;
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_SETATTRIBUTE, iIssuerCert, 
								  CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
		}

	/* Restore the cert chain info */
	restoreSelectionState( savedState, certInfoPtr );

	return( status );
	}

int checkCertChain( CERT_INFO *certInfoPtr )
	{
	CRYPT_CERTIFICATE iIssuerCert;
	CERT_INFO *issuerCertInfoPtr = certInfoPtr, *subjectCertInfoPtr;
	BOOLEAN isTrusted = TRUE;
	int certIndex = certInfoPtr->certChainEnd - 1, complianceLevel, i, status;

	assert( isWritePtr( certInfoPtr, CERT_INFO ) );

	krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE,
					 &complianceLevel, CRYPT_OPTION_CERT_COMPLIANCELEVEL );

	/* Check whether the leaf cert is either implicitly trusted or signed by 
	   a trusted cert */
	status = checkLeafCertTrust( certInfoPtr, &iIssuerCert );
	if( status == OK_SPECIAL )
		/* The leaf is implicitly trusted, there's nothing more to do */
		return( CRYPT_OK );
	if( cryptStatusOK( status ) )
		/* The leaf is signed by a trusted cert, no need to check the cert 
		   chain */
		certIndex = CRYPT_ERROR;
	else
		{
		/* Walk up the chain from the leaf cert's issuer to the root checking
		   for an implicitly trusted cert */
		for( i = 0; i <= certIndex; i++ )
			{
			status = krnlGetObject( certInfoPtr->certChain[ i ], 
									OBJECT_TYPE_CERTIFICATE, 
									( void ** ) &issuerCertInfoPtr, 
									CRYPT_ERROR_SIGNALLED );
			if( cryptStatusError( status ) )
				break;
			iIssuerCert = issuerCertInfoPtr->objectHandle;
			status = krnlSendMessage( certInfoPtr->ownerHandle, 
									  IMESSAGE_SETATTRIBUTE, &iIssuerCert, 
									  CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
			if( cryptStatusOK( status ) )
				break;
			if( i != certIndex )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			}
		certIndex = i;	/* Remember how far we got */

		/* If we didn't end up at an implicitly trusted cert, check whether
		   we should implicitly trust a self-signed root */
		if( cryptStatusError( status ) )
			{
			/* We didn't end up at a trusted key, either there's a missing 
			   link in the chain (CRYPT_ERROR_STUART) and it was truncated 
			   before we got to a trusted cert, or it goes to a root cert 
			   but it isn't trusted */
			certInfoPtr->certChainPos = certInfoPtr->certChainEnd - 1;
			if( issuerCertInfoPtr->flags & CERT_FLAG_SELFSIGNED )
				{
				/* We got a root cert but it's not trusted */
				setErrorInfo( issuerCertInfoPtr, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				}
			else
				/* There's a missing link in the chain and it stops at this 
				   cert */
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );

			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Walk down the chain from the trusted cert checking each link in turn */
	subjectCertInfoPtr = ( CERT_INFO * ) issuerCertInfoPtr;
	do
		{
		CRYPT_CONTEXT iPubkeyContext = iIssuerCert;

		/* If the issuing cert for this one isn't implicitly trusted, check
		   the chaining from issuer to subject */
		if( !isTrusted )
			{
			iPubkeyContext = issuerCertInfoPtr->iPubkeyContext;
			status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr,
								TRUE, &subjectCertInfoPtr->errorLocus, 
								&subjectCertInfoPtr->errorType);
			if( cryptStatusOK( status ) )
				subjectCertInfoPtr->maxCheckLevel = complianceLevel;
			}
		isTrusted = FALSE;

		/* Check the signature on the subject cert unless it's a data-only
		   cert for which there isn't a context present.  This is OK since
		   the only time we can have a data-only chain is when we're reading
		   from an (implicitly trusted) private key store */
		if( cryptStatusOK( status ) && !cryptStatusError( iPubkeyContext ) )
			status = checkX509signature( subjectCertInfoPtr->certificate, 
										 subjectCertInfoPtr->certificateSize,
										 NULL, NULL, iPubkeyContext, 
										 CRYPT_UNUSED );

		/* Check any constraints that the issuer cert may place on the rest 
		   of the chain */
		if( cryptStatusOK( status ) && \
			complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL && \
			issuerCertInfoPtr != subjectCertInfoPtr )
			status = checkConstraints( certInfoPtr, issuerCertInfoPtr,
									   &certIndex );

		/* Move on to the next cert */
		if( issuerCertInfoPtr != subjectCertInfoPtr )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		issuerCertInfoPtr = subjectCertInfoPtr;
		certIndex--;
		}
	while( cryptStatusOK( status ) && \
		   ( status = getNextCert( certInfoPtr, &subjectCertInfoPtr,
								   certIndex ) ) == CRYPT_OK );
	if( status != OK_SPECIAL )
		{
		/* We stopped before we processed all the certs in the chain, if
		   the last cert that we processed wasn't the leaf, unlock it and
		   select the one that caused the problem */
		if( issuerCertInfoPtr != certInfoPtr )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		certInfoPtr->certChainPos = certIndex + 1;
		}
	else
		/* We successfully reached the end of the chain */
		status = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*						Read Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Read a collection of certs in a cert chain into a cert object */

static int buildCertChain( CRYPT_CERTIFICATE *iLeafCert, 
						   CRYPT_CERTIFICATE *iCertChain, int certChainEnd,
						   const CRYPT_KEYID_TYPE keyIDtype,
						   const void *keyID, const int keyIDlength )
	{
	CERTCHAIN_INFO certChainInfo[ MAX_CHAINLENGTH ];
	CERT_INFO *certChainPtr;
	CHAINING_INFO chainingInfo;
	int leafNodePos, selfSigned, status;

	assert( certChainEnd > 0 && certChainEnd < MAX_CHAINLENGTH );
	assert( isWritePtrEx( certChainInfo, CERTCHAIN_INFO, certChainEnd ) );
	assert( isReadPtrEx( iCertChain, CRYPT_CERTIFICATE, certChainEnd ) );

	/* We've now got a collection of certs in unknown order (although in most
	   cases the first cert is the leaf).  Extract the chaining info and
	   search the chain for the leaf node */
	status = buildCertChainInfo( certChainInfo, iCertChain, certChainEnd );
	if( cryptStatusError( status ) )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	if( keyID != NULL )
		leafNodePos = findIdentifiedLeafNode( certChainInfo, certChainEnd,
											  keyIDtype, keyID, keyIDlength );
	else
		leafNodePos = findLeafNode( certChainInfo, certChainEnd );
	if( cryptStatusError( leafNodePos ) )
		return( leafNodePos );

	/* Now that we have the leaf node, clear its entry in the chain to make
	   sure that it isn't used for further processing, order the remaining 
	   certs up to the root, and discard any unneeded certs */
	*iLeafCert = iCertChain[ leafNodePos ];
	getIssuerChainingInfo( &chainingInfo, &certChainInfo[ leafNodePos ] );
	memset( &certChainInfo[ leafNodePos ], 0, sizeof( CERTCHAIN_INFO ) );
	status = sortCertChain( iCertChain, certChainInfo, certChainEnd,
							CRYPT_UNUSED, &chainingInfo );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *iLeafCert, IMESSAGE_DECREFCOUNT );
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	certChainEnd = status;
	if( certChainEnd <= 0 )
		/* There's only one cert in the chain, either due to the chain 
		   containing only a single cert or due to all other certs being 
		   discarded, leave it as a standalone cert rather than turning it 
		   into a chain */
		return( CRYPT_OK );

	/* Finally, we've got the leaf cert and a chain up to the root.  Make the
	   leaf a cert-chain type and copy in the chain */
	status = krnlGetObject( *iLeafCert, OBJECT_TYPE_CERTIFICATE, 
							( void ** ) &certChainPtr, 
							CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( certChainPtr->certChain, iCertChain,
			certChainEnd * sizeof( CRYPT_CERTIFICATE ) );
	certChainPtr->certChainEnd = certChainEnd;
	certChainPtr->type = CRYPT_CERTTYPE_CERTCHAIN;

	/* If the root is self-signed, the entire chain counts as self-
	   signed */
	status = krnlSendMessage( certChainPtr->certChain[ certChainEnd - 1 ], 
							  IMESSAGE_GETATTRIBUTE, &selfSigned,
							  CRYPT_CERTINFO_SELFSIGNED );
	if( cryptStatusOK( status ) && selfSigned )
		certChainPtr->flags |= CERT_FLAG_SELFSIGNED;
	krnlReleaseObject( certChainPtr->objectHandle );

	return( CRYPT_OK );
	}

/* Read certificate chain/sequence information */

int readCertChain( STREAM *stream, CRYPT_CERTIFICATE *iCryptCert,
				   const CRYPT_USER cryptOwner,
				   const CRYPT_CERTTYPE_TYPE type,
				   const CRYPT_KEYID_TYPE keyIDtype,
				   const void *keyID, const int keyIDlength,
				   const BOOLEAN dataOnlyCert )
	{
	CRYPT_CERTIFICATE iCertChain[ MAX_CHAINLENGTH ];
	int certSequenceLength, endPos, certChainEnd = 0, status = CRYPT_OK;

	assert( type == CRYPT_CERTTYPE_CERTCHAIN || \
			type == CRYPT_ICERTTYPE_CMS_CERTSET || \
			type == CRYPT_ICERTTYPE_SSL_CERTCHAIN );
	assert( ( keyIDtype == CRYPT_KEYID_NONE && keyID == NULL && \
			  keyIDlength == 0 ) || \
			( ( keyIDtype == CRYPT_IKEYID_KEYID || \
				keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
			  keyID != NULL && keyIDlength > 16 ) );

	/* If it's a PKCS #7 chain, skip the contentType OID, read the content 
	   encapsulation and header if necessary, and burrow down into the PKCS 
	   #7 content */
	if( type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		long integer;
		int length, oidLength;

		/* Read the wrapper */
		readUniversal( stream );
		readConstructed( stream, NULL, 0 );
		readSequence( stream, NULL );

		/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
		   3 = S/MIME with attribute certificate(s)), and (should be empty) 
		   SET OF DigestAlgorithmIdentifier */
		readShortInteger( stream, &integer );
		status = readSet( stream, &length );
		if( cryptStatusOK( status ) && ( integer < 1 || integer > 3 ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusError( status ) )
			return( status );
		if( length > 0 )
			sSkip( stream, length );

		/* Read the ContentInfo header, contentType OID and the inner content 
		   encapsulation.  Sometimes we may (incorrectly) get passed actual 
		   signed data (rather than degenerate zero-length data signifying a 
		   pure cert chain), if there's data present we skip it */
		readSequenceI( stream, &length );
		status = readRawObject( stream, NULL, &oidLength, MAX_OID_SIZE, 
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );
		if( length == CRYPT_UNUSED )
			/* It's an indefinite-length ContentInfo, check for the EOC */
			status = checkEOC( stream );
		else
			/* If we've been fed signed data (i.e. the ContentInfo has the 
			   content field present), skip the content to get to the cert 
			   chain */
			if( length > sizeofObject( oidLength ) )
				status = readUniversal( stream );
		}
	if( type == CRYPT_CERTTYPE_CERTCHAIN || \
		type == CRYPT_ICERTTYPE_CMS_CERTSET )
		status = readConstructedI( stream, &certSequenceLength, 0 );
	else
		/* There's no outer wrapper to give us length information for an SSL 
		   cert chain, however the length will be equal to the total stream 
		   size */
		certSequenceLength = sMemBufSize( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a definite-length chain, determine where it ends */
	if( certSequenceLength != CRYPT_UNUSED )
		endPos = stell( stream ) + certSequenceLength;

	/* We've finally reached the certificate(s), read the collection of certs
	   into cert objects.  We allow for a bit of slop for software that gets 
	   the length encoding wrong by a few bytes */
	while( certSequenceLength == CRYPT_UNUSED || \
		   stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		CRYPT_CERTIFICATE iNewCert;

		/* Make sure that we don't overflow the chain */
		if( certChainEnd >= MAX_CHAINLENGTH - 1 )
			{
			freeCertChain( iCertChain, certChainEnd );
			return( CRYPT_ERROR_OVERFLOW );
			}

		/* If it's an SSL cert chain, there's a 24-bit length field between
		   certs */
		if( type == CRYPT_ICERTTYPE_SSL_CERTCHAIN )
			sSkip( stream, 3 );

		/* Read the next cert and add it to the chain.  When importing the
		   chain from an external (untrusted) source we create standard certs
		   so we can check the signatures on each link in the chain.  When
		   importing from a trusted source we create data-only certs, once
		   we've got all the certs and know which cert is the leaf, we can 
		   go back and decode the public key information for it */
		status = importCert( sMemBufPtr( stream ), sMemDataLeft( stream ),
							 &iNewCert, cryptOwner, CRYPT_KEYID_NONE,
							 NULL, 0, dataOnlyCert ? \
								CERTFORMAT_DATAONLY : \
								CRYPT_CERTTYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			{
			RESOURCE_DATA msgData;

			/* Add the newly-read cert to the chain and skip over its
			   encoded data.  Unfortunately due to the mixing of stream and 
			   non-stream functions we have to do this in a somewhat 
			   roundabout manner by getting the length of the data in the 
			   newly-created cert object and then skipping that far ahead in
			   the input stream */
			iCertChain[ certChainEnd++ ] = iNewCert;
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iNewCert, IMESSAGE_CRT_EXPORT, 
									  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusOK( status ) )
				status = sSkip( stream, msgData.length );
			}
		if( cryptStatusError( status ) )
			{
			if( certChainEnd > 0 )
				freeCertChain( iCertChain, certChainEnd );
			return( status );
			}

		/* If it's encoded using the indefinite form and we find the EOC
		   octets, exit */
		if( certSequenceLength == CRYPT_UNUSED )
			{
			status = checkEOC( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( status == TRUE )
				/* We've seen EOC octets, we're done */
				break;
			}
		}

	/* We must have read at least one cert in order to create a chain */
	if( certChainEnd <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Build the complete chain from the individual certs */
	return( buildCertChain( iCryptCert, iCertChain, certChainEnd, 
							keyIDtype, keyID, keyIDlength ) );
	}

/* Fetch a sequence of certs from an object to create a cert chain */

int assembleCertChain( CRYPT_CERTIFICATE *iCertificate,
					   const CRYPT_HANDLE iCertSource, 
					   const CRYPT_KEYID_TYPE keyIDtype,
					   const void *keyID, const int keyIDlength,
					   const int options )
	{
	CRYPT_CERTIFICATE iCertChain[ MAX_CHAINLENGTH ], lastCert;
	MESSAGE_KEYMGMT_INFO getnextcertInfo;
	const int chainOptions = options & KEYMGMT_FLAG_DATAONLY_CERT;
	int stateInfo = CRYPT_ERROR, certChainEnd = 1, status;

	/* Get the initial cert based on the key ID */
	setMessageKeymgmtInfo( &getnextcertInfo, keyIDtype, keyID, keyIDlength, 
						   &stateInfo, sizeof( int ), 
						   options & KEYMGMT_MASK_CERTOPTIONS );
	status = krnlSendMessage( iCertSource, IMESSAGE_KEY_GETFIRSTCERT,
							  &getnextcertInfo, KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	iCertChain[ 0 ] = lastCert = getnextcertInfo.cryptHandle;

	/* Fetch subsequent certs that make up the chain based on the state
	   information.  Since the basic options apply only to the leaf cert,
	   we only allow the data-only-cert flag at this point */
	setMessageKeymgmtInfo( &getnextcertInfo, CRYPT_KEYID_NONE, NULL, 0, 
						   &stateInfo, sizeof( int ), chainOptions );
	do
		{
		int selfSigned;

		/* If we've reached a self-signed cert, stop */
		krnlSendMessage( lastCert, IMESSAGE_GETATTRIBUTE, &selfSigned, 
						 CRYPT_CERTINFO_SELFSIGNED );
		if( selfSigned )
			break;

		/* Get the next cert in the chain from the source, import it, and 
		   add it to the collection */
		getnextcertInfo.cryptHandle = CRYPT_ERROR;	/* Reset result handle */
		status = krnlSendMessage( iCertSource, IMESSAGE_KEY_GETNEXTCERT,
								  &getnextcertInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			if( certChainEnd >= MAX_CHAINLENGTH - 1 )
				status = CRYPT_ERROR_OVERFLOW;
			else
				iCertChain[ certChainEnd++ ] = \
							lastCert = getnextcertInfo.cryptHandle;
			}
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = CRYPT_OK;
			break;	/* End of chain reached */
			}
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}

	/* Build the complete chain from the individual certs */
	return( buildCertChain( iCertificate, iCertChain, certChainEnd, 
							CRYPT_KEYID_NONE, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*						Write Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Determine the size of and write a certificate path from a base cert up to 
   the root.  If it's a cert collection, it's just a container for random
   certs but not a cert in its own right, so we skip the leaf cert */

static int sizeofCertPath( const CERT_INFO *certInfoPtr )
	{
	int length = 0, i;

	/* Evaluate the size of the current certificate and the issuer 
	   certificates in the chain */
	if( !( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION ) )
		length = certInfoPtr->certificateSize;
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		RESOURCE_DATA msgData;
		int status;

		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( certInfoPtr->certChain[ i ], 
								  IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_CERTFORMAT_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		length += msgData.length;
		}

	return( length );
	}

static int writeCertPath( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	int i, status = CRYPT_OK;

	/* Write the current certificate and the associated cert chain up to the
	   root */
	if( !( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION ) )
		status = swrite( stream, certInfoPtr->certificate, 
						 certInfoPtr->certificateSize );
	for( i = 0; cryptStatusOK( status ) && \
				i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainPtr;

		status = krnlGetObject( certInfoPtr->certChain[ i ], 
								OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certChainPtr, 
								CRYPT_ERROR_SIGNALLED );
		if( cryptStatusOK( status ) )
			{
			status = swrite( stream, certChainPtr->certificate,
							 certChainPtr->certificateSize );
			krnlReleaseObject( certChainPtr->objectHandle );
			}
		}

	return( status );
	}

/* Write certificate chain/sequence information:

	CertChain ::= SEQUENCE {
		contentType				OBJECT IDENTIFIER,	-- signedData
		content			  [ 0 ]	EXPLICIT SEQUENCE {
			version				INTEGER (1),
			digestAlgorithms	SET OF AlgorithmIdentifier,	-- SIZE(0)
			contentInfo			SEQUENCE {
				signedData		OBJECT IDENTIFIER	-- data
				}
			certificates  [ 0 ]	IMPLICIT SET OF {
									Certificate
				}
			}
		signerInfos				SET OF SignerInfo			-- SIZE(0)
		} */

int sizeofCertSet( const CERT_INFO *certInfoPtr )
	{
	return( ( int ) sizeofObject( sizeofCertPath( certInfoPtr ) ) );
	}

int writeCertSet( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	writeConstructed( stream, sizeofCertPath( certInfoPtr ), 0 );
	return( writeCertPath( stream, certInfoPtr ) );
	}

int writeCertSequence( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	writeSequence( stream, sizeofCertPath( certInfoPtr ) );
	return( writeCertPath( stream, certInfoPtr ) );
	}

int writeCertChain( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	int innerLength;

	/* Determine how big the encoded cert chain/sequence will be */
	innerLength = sizeofShortInteger( 1 ) + ( int ) sizeofObject( 0 ) + \
					  ( int ) sizeofObject( sizeofOID( OID_CMS_DATA ) ) + \
					  ( int ) sizeofObject( sizeofCertPath( certInfoPtr ) ) + \
					  ( int ) sizeofObject( 0 );

	/* Write the outer SEQUENCE wrapper and contentType and content wrapper */
	writeSequence( stream, 
				   sizeofOID( OID_CMS_SIGNEDDATA ) + \
					( int ) sizeofObject( sizeofObject( innerLength ) ) );
	swrite( stream, OID_CMS_SIGNEDDATA, sizeofOID( OID_CMS_SIGNEDDATA ) );
	writeConstructed( stream, sizeofObject( innerLength ), 0 );
	writeSequence( stream, innerLength );

	/* Write the inner content */
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeSet( stream, 0 );
	writeSequence( stream, sizeofOID( OID_CMS_DATA ) );
	swrite( stream, OID_CMS_DATA, sizeofOID( OID_CMS_DATA ) );
	writeCertSet( stream, certInfoPtr );
	return( writeSet( stream, 0 ) );
	}
