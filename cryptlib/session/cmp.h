/****************************************************************************
*																			*
*							CMP Definitions Header File						*
*						Copyright Peter Gutmann 1999-2003					*
*																			*
****************************************************************************/

#ifndef _CMP_DEFINED

#define _CMP_DEFINED

/* CMP version and default port */

#define CMP_VERSION				2		/* CMP version */
#define CMP_PORT				829		/* TCP default port */

/* Various CMP constants */

#define CMP_NONCE_SIZE			16		/* Size of nonces */
#define CMP_PASSWORD_ITERATIONS	500		/* No.of PW hashing iterations */
#define CMP_MAX_PASSWORD_ITERATIONS	10000	/* Max allowable iterations */

/* The CMP spec never defines any keysize for the CMP/Entrust MAC, but
   everyone seems to use 160 bits for this */

#define CMP_HMAC_KEYSIZE		20

/* CMP protocol-specific flags that augment the general session flags.  If
   we're running a PnP PKI session, we leave the client connection active 
   to allow for further transactions.  In order to minimise the mount of junk
   in headers (see the comment at the start of cmp_wr.c), we record when
   various identifiers have been sent and don't send them again in subsequent
   messages */

#define CMP_PFLAG_NONE			0x00	/* No protocol-specific flags */
#define CMP_PFLAG_RETAINCONNECTION 0x01	/* Leave conn.open for further trans.*/
#define CMP_PFLAG_CLIBIDSENT	0x02	/* cryptlib ID sent */
#define CMP_PFLAG_USERIDSENT	0x04	/* User ID sent */
#define CMP_PFLAG_CERTIDSENT	0x08	/* Cert ID sent */
#define CMP_PFLAG_MACINFOSENT	0x10	/* MAC parameters sent */
#define CMP_PFLAG_PNPPKI		0x20	/* Session is PnP PKI-capable */

/* Since the CMP spec is so vague and open-ended that almost anything can
   be argued to be valid, it's useful to be able to grab a sample message
   from a server and pick it apart offline.  Uncommenting the following
   define will read this stored input from disk rather than communicating
   with the server */

/*#define SKIP_IO						// Don't communicate with server */

/* Context-specific tags for the PKIHeader record */

enum { CTAG_PH_MESSAGETIME, CTAG_PH_PROTECTIONALGO, CTAG_PH_SENDERKID,
	   CTAG_PH_RECIPKID, CTAG_PH_TRANSACTIONID, CTAG_PH_SENDERNONCE,
	   CTAG_PH_RECIPNONCE, CTAG_PH_FREETEXT, CTAG_PH_GENERALINFO };

/* Context-specific tags for the PKIBody wrapper */

enum { CTAG_PB_IR, CTAG_PB_IP, CTAG_PB_CR, CTAG_PB_CP, CTAG_PB_P10CR,
	   CTAG_PB_POPDECC, CTAG_PB_POPDECR, CTAG_PB_KUR, CTAG_PB_KUP,
	   CTAG_PB_KRR, CTAG_PB_KRP, CTAG_PB_RR, CTAG_PB_RP, CTAG_PB_CCR,
	   CTAG_PB_CCP, CTAG_PB_CKUANN, CTAG_PB_CANN, CTAG_PB_RANN,
	   CTAG_PB_CRLANN, CTAG_PB_PKICONF, CTAG_PB_NESTED, CTAG_PB_GENM,
	   CTAG_PB_GENP, CTAG_PB_ERROR, CTAG_PB_CERTCONF, CTAG_PB_LAST };

/* Context-specific tags for the PKIMessage */

enum { CTAG_PM_PROTECTION, CTAG_PM_EXTRACERTS };

/* Context-specific tags for the CertifiedKeyPair in the PKIMessage */

enum { CTAG_CK_CERT, CTAG_CK_ENCRYPTEDCERT, CTAG_CK_NEWENCRYPTEDCERT };

/* Context-specific tags for the EncryptedValue in the CertifiedKeyPair */

enum { CTAG_EV_DUMMY1, CTAG_EV_CEKALGO, CTAG_EV_ENCCEK, CTAG_EV_DUMMY2,
	   CTAG_EV_DUMMY3 };

/* PKIStatus values */

enum { PKISTATUS_OK, PKISTATUS_OK_WITHINFO, PKISTATUS_REJECTED,
	   PKISTATUS_WAITING, PKISTATUS_REVOCATIONIMMINENT,
	   PKISTATUS_REVOCATION, PKISTATUS_KEYUPDATE };

/* PKIFailureInfo values */

#define CMPFAILINFO_OK					0x00000000L
#define CMPFAILINFO_BADALG				0x00000001L
#define CMPFAILINFO_BADMESSAGECHECK		0x00000002L
#define CMPFAILINFO_BADREQUEST			0x00000004L
#define CMPFAILINFO_BADTIME				0x00000008L
#define CMPFAILINFO_BADCERTID			0x00000010L
#define CMPFAILINFO_BADDATAFORMAT		0x00000020L
#define CMPFAILINFO_WRONGAUTHORITY		0x00000040L
#define CMPFAILINFO_INCORRECTDATA		0x00000080L
#define CMPFAILINFO_MISSINGTIMESTAMP	0x00000100L
#define CMPFAILINFO_BADPOP				0x00000200L
#define CMPFAILINFO_CERTREVOKED			0x00000400L
#define CMPFAILINFO_CERTCONFIRMED		0x00000800L
#define CMPFAILINFO_WRONGINTEGRITY		0x00001000L
#define CMPFAILINFO_BADRECIPIENTNONCE	0x00002000L
#define CMPFAILINFO_TIMENOTAVAILABLE	0x00004000L
#define CMPFAILINFO_UNACCEPTEDPOLICY	0x00008000L
#define CMPFAILINFO_UNACCEPTEDEXTENSION	0x00010000L
#define CMPFAILINFO_ADDINFONOTAVAILABLE	0x00020000L
#define CMPFAILINFO_BADSENDERNONCE		0x00040000L
#define CMPFAILINFO_BADCERTTEMPLATE		0x00080000L
#define CMPFAILINFO_SIGNERNOTTRUSTED	0x00100000L
#define CMPFAILINFO_TRANSACTIONIDINUSE	0x00200000L
#define CMPFAILINFO_UNSUPPORTEDVERSION	0x00400000L
#define CMPFAILINFO_NOTAUTHORIZED		0x00800000L
#define CMPFAILINFO_SYSTEMUNAVAIL		0x01000000L
#define CMPFAILINFO_SYSTEMFAILURE		0x02000000L
#define CMPFAILINFO_DUPLICATECERTREQ	0x04000000L

/* The OID for the Entrust MAC */

#define OID_ENTRUST_MAC	MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0D" )

/* When we're writing the payload of a CMP message, we use a shared function
   for most payload types because they're all pretty similar.  The following
   values distinguish between the message classes that can be handled by a
   single write function */

typedef enum {
	CMPBODY_NORMAL, CMPBODY_CONFIRMATION, CMPBODY_ACK, CMPBODY_GENMSG,
	CMPBODY_ERROR, CMPBODY_LAST
	} CMPBODY_TYPE;

/* CMP uses so many unnecessary EXPLICIT tags that we define a macro to
   make it easier to evaluate the encoded sizes of objects tagged in this
   manner */

#define objSize( length )	( ( int ) sizeofObject( length ) )

/* CMP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* Session state information.  We record the operation being carried
	   out so that we can make decisions about message validity and contents
	   when reading/writing fields, whether the other side is a cryptlib 
	   implementation, which allows us to work around some of the 
	   braindamage in CMP since we know that the other side will do the right
	   thing and to include extra information required to avoid CMP
	   shortcomings, and whether the first message has been sent, after 
	   which we can send much shorter message headers without all of the 
	   cruft required by CMP */
	int operation;							/* ir/cr/kur/rr */
	BOOLEAN isCryptlib;						/* Whether peer is cryptlib */

	/* Identification/state variable information.  The userID is either the
	   CA-supplied user ID value (for MAC'ed messages) or the
	   subjectKeyIdentifier (for signed messages).  The sender and recipient
	   nonces change roles each at message turnaround (even though this is
	   totally unnecessary), so as we go through the various portions of the
	   protocol the different nonces slowly shift through the two values.
	   In order to accomodate nonstandard implementations, we allow for
	   nonces that are slightly larger than the required size.
	   
	   When using a persistent connection, the user info can change over
	   successive transactions.  If a new transaction arrives whose user ID
	   matches the previous one, we set the user/certInfo changed flag to 
	   tell the higher-level code to update the user info that it has 
	   stored */
	BYTE userID[ CRYPT_MAX_TEXTSIZE + 1 ];	/* User ID */
	BYTE transID[ CRYPT_MAX_HASHSIZE ];		/* Transaction nonce */
	BYTE certID[ CRYPT_MAX_HASHSIZE ];		/* Sender cert ID */
	BYTE senderNonce[ CRYPT_MAX_HASHSIZE ];	/* Sender nonce */
	BYTE recipNonce[ CRYPT_MAX_HASHSIZE ];	/* Recipient nonce */
	int userIDsize, transIDsize, certIDsize, senderNonceSize, recipNonceSize;
	BOOLEAN userIDchanged, certIDchanged;	/* Whether ID info same as prev.*/

	/* Usually the key we're getting a cert for is signature-capable, but 
	   sometimes we need to certify an encryption-only key.  In this case we
	   can't use the private key to authenticate the request, but either use
	   a password-derived MAC or a separate signing key, typically one that
	   we had certified before getting the encryption-only key certified.  To
	   keep things simple, we keep a reference to the whichever object is being
	   used for authentication */
	BOOLEAN cryptOnlyKey;					/* Whether key being cert'd is encr-only */
	CRYPT_CONTEXT authContext;

	/* When processing CMP data, we need to remember the last cryptlib error
	   status value we encountered and the last CMP extended failure value so
	   that we can send it to the remote client/server in an error response */
	int status;								/* Last error status */
	long pkiFailInfo;						/* Last extended failure status */

	/* The information needed to verify message integrity.  Typically we
	   use a MAC, however in some cases the data isn't MAC'd but signed by
	   the user or CA, in which case we use the user private key to sign or
	   CA certificate to verify instead of MAC'ing it.  If we're signing,
	   we clear the useMACsend flag, if we're verifying we clear the
	   useMACreceive flag (in theory the two should match, but there are
	   implementations that use MACs one way and sigs the other).  If we're
	   using a MAC then rather than recalculating the MAC keying info each
	   time (which can potentially get expensive with the iterated password
	   setup) we reuse it for each message by deleting the previous MAC
	   value */
	CRYPT_ALGO_TYPE hashAlgo;				/* Hash algo for signature */
	CRYPT_CONTEXT iMacContext;				/* MAC context */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];		/* MAC password salt  */
	int saltSize;
	int iterations;							/* MAC password iterations */
	BOOLEAN useMACsend, useMACreceive;		/* Use MAC to verify integrity */

	/* Sometimes the other side will changes the MAC parameters in their
	   response, which is annoying because it doesn't serve any purpose but
	   does mean that we can't reuse the MAC context.  When we get a response
	   we compare the parameters with our ones, if they don't match we create
	   an alternative MAC context with the returned parameters and use that
	   instead.  This process is repeated for each message received */
	CRYPT_CONTEXT iAltMacContext;			/* Alternative MAC context */
	BYTE altSalt[ CRYPT_MAX_HASHSIZE ];		/* Alternative MAC password salt */
	int altSaltSize;
	int altIterations;						/* Alt.MAC password iterations */
	BOOLEAN useAltMAC;						/* Use alternative MAC context */

	/* Other protocol information.  CMP uses an extremely clunky confirmation
	   mechanism in which a cert conf uses as hash algorithm the algorithm
	   that was used in a previous message by the CA to sign the
	   certificate, which means implementations will break each time a new
	   certificate format is added since the CMP transport-level code is now
	   dependent on the format of the data it carries.  In order to support
	   this content-coupling of protocol and data, we record the hash
	   algorithm when we receive the CA's reply so that it can be used 
	   later */
	CRYPT_ALGO_TYPE confHashAlgo;			/* Cert.conf.hash algo */

	/* Pointers to parsed data in the current message.  This is used by
	   lower-level decoding routines to return information needed by higher-
	   level ones.  The MAC info position records the position of the MAC
	   info (we can't set up the MAC info until we've read the sender key ID,
	   but the MAC info is sent first, so we have to go back and re-process
	   it once we've got the sender key ID).  The sender DN pointer records 
	   the DN of the key used to sign the message if we're not talking to a
	   cryptlib peer (the DN is ambiguous and can't properly identify the
	   sender, so we only use it if there's no alternative) */
	int macInfoPos;							/* Position of MAC info in stream */
	void *senderDNPtr;
	int senderDNlength;						/* Position of auth.key ID in stream */
	} CMP_PROTOCOL_INFO;

/* Prototypes for functions in cmp.c */

int reqToResp( const int reqType );
int initMacInfo( const CRYPT_CONTEXT iMacContext, const void *userPassword, 
				 const int userPasswordLength, const void *salt, 
				 const int saltLength, const int iterations );
int initServerAuthentMAC( SESSION_INFO *sessionInfoPtr, 
						  CMP_PROTOCOL_INFO *protocolInfo );
int initServerAuthentSign( SESSION_INFO *sessionInfoPtr, 
						   CMP_PROTOCOL_INFO *protocolInfo );
int hashMessageContents( const CRYPT_CONTEXT iHashContext,
						 const void *data, const int length );

/* Prototypes for functions in cmp_msg.c */

int readPkiMessage( SESSION_INFO *sessionInfoPtr,
					CMP_PROTOCOL_INFO *protocolInfo,
					int messageType );
int writePkiMessage( SESSION_INFO *sessionInfoPtr,
					 CMP_PROTOCOL_INFO *protocolInfo,
					 const CMPBODY_TYPE bodyType );

/* Prototypes for functions in pnppki.c */

int pnpPkiSession( SESSION_INFO *sessionInfoPtr );

#endif /* _CMP_DEFINED */
