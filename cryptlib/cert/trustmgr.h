/****************************************************************************
*																			*
*						Certificate Trust Manger Interface 					*
*						Copyright Peter Gutmann 1998-2005					*
*																			*
****************************************************************************/

#ifndef _TRUSTMGR_DEFINED

#define _TRUSTMGR_DEFINED

/* Prototypes for certificate trust managemer functions */

int initTrustInfo( void **trustInfoPtrPtr );
void endTrustInfo( void *trustInfoPtr );
int addTrustEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCert,
				   const void *certObject, const int certObjectLength,
				   const BOOLEAN addSingleCert );
void deleteTrustEntry( void *trustInfoPtr, void *entryToDelete );
void *findTrustEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE cryptCert,
					  const BOOLEAN getIssuerEntry );
CRYPT_CERTIFICATE getTrustedCert( void *trustInfoPtr );
int enumTrustedCerts( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCtl,
					  const CRYPT_KEYSET iCryptKeyset );

/* If certificates aren't available, we have to no-op out the cert trust
   manager functions */

#ifndef USE_CERTIFICATES

#define initTrustInfo( trustInfoPtrPtr )	CRYPT_OK
#define endTrustInfo( trustInfoPtr )
#define addTrustEntry( trustInfoPtr, iCryptCert, certObject, \
					   certObjectLength, addSingleCert ) \
		CRYPT_ERROR_NOTAVAIL
#define deleteTrustEntry( trustInfoPtr, entryToDelete )
#define findTrustEntry( trustInfoPtr, cryptCert, getIssuerEntry ) \
		NULL
#define getTrustedCert( trustInfoPtr )		CRYPT_ERROR_NOTFOUND
#define enumTrustedCerts( trustInfoPtr, iCryptCtl, iCryptKeyset ) \
		CRYPT_ERROR_NOTFOUND

#endif /* USE_CERTIFICATES */

#endif /* _TRUSTMGR_DEFINED */
