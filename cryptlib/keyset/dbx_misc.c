/****************************************************************************
*																			*
*						  cryptlib DBMS Misc Interface						*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
  #include "asn1.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../keyset/dbms.h"
  #include "../misc/asn1.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
  #include "misc/asn1.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/* The table structure for the various DBMS tables is (# = indexed, 
   * = unique, + = cert store only):

	certificates:
		C, SP, L, O, OU, CN, email#, validTo, nameID#, issuerID#*, keyID#*, certID#*, certData
	CRLs:
		expiryDate+, nameID+, issuerID#*, certID#+, certData
	pkiUsers+:
		C, SP, L, O, OU, CN, nameID#*, keyID#*, certID, certData
	certRequests+:
		type, C, SP, L, O, OU, CN, email, certID, certData
	certLog+:
		action, date, certID#*, reqCertID, subjCertID, certData

   Note that in the CRL table the certID is the ID of the cert being
   revoked, not of the per-entry CRL data, and in the  PKIUsers table the
   keyID isn't for a public key but a nonce used to identify the PKI user
   and the nameID is used purely to ensure uniqueness of users.

   The cert store contains a table for logging cert management operations (e.g.
   when issued, when revoked, etc etc).  The operations are tied together by
   the certID of each object, associated with this in the log are optional
   certIDs of the request that caused the action to be taken and the subject
   that was affected by the request.  This allows a complete history of each
   item to be built via the log.  The certLog has a UNIQUE INDEX on the
   certID that detects attempts to add duplicates, although this
   unfortunately requires the addition of dummy nonce certIDs to handle
   certain types of actions that don't produce objects with certIDs.

   The handling for each type of CA management operation is:

	CERTACTION_REQUEST_CERT/CERTACTION_REQUEST_RENEWAL/
	CERTACTION_REQUEST_REVOCATION: Stores the incoming requests and generates
	a log entry.  Duplicate issue requests are detected by the certLog.certID
	uniqueness constraint.  Available: request with certID:

	  INSERT INTO certRequests VALUES ( <type>, <DN components>, <certID>, <request> );
	  INSERT INTO certLog VALUES
		(ACTION_REQUEST_CERT/RENEWAL/REVOCATION, $date, <certID>, NULL, NULL,
		  <request>);

	CERTACTION_ISSUE_CERT/CERTACTION_CERT_CREATION: Add the cert and remove
	the issue request.  Duplicate cert issuance is detected by the
	certLog.certID uniqueness constraint.  Available: request with
	req.certID, certificate with certID

	  INSERT INTO certificates VALUES (<DN components>, <IDs>, <cert>);
	  INSERT INTO certLog VALUES
		(ACTION_ISSUE_CERT/CERT_CREATION, $date, <certID>, <req.certID>, NULL,
		  <cert>);
	  DELETE FROM certRequests WHERE certID = <req.certID>;

	CERTACTION_ISSUE_CRL: Read each CRL entry with caCert.nameID and assemble
	the full CRL.  Requires an ongoing query:

	  SELECT FROM CRLs WHERE nameID = <caCert.nameID>

	CERTACTION_REVOKE_CERT: Add the CRL entry that causes the revocation,
	delete the cert and the request that caused the action.  Available:
	request with req.certID, certificate with cert.certID, CRL entry with
	certID

	  INSERT INTO CRLs VALUES (<IDs>, <crlData>);
	  INSERT INTO certLog VALUES
		(ACTION_REVOKE_CERT, $date, <nonce>, <req.certID>, <cert.certID>, <crlData>);
	  DELETE FROM certRequests WHERE certID = <req.certID>;
	  DELETE FROM certificates WHERE certID = <cert.certID>;

	CERTACTION_EXPIRE_CERT/CERTACTION_RESTART_CLEANUP: Delete each expired
	entry or clean up leftover cert requests after a restart.  The logging
	for these is a bit tricky, ideally we'd want to "INSERT INTO certLog
	VALUES (ACTION_CERT_EXPIRE, $date, SELECT certID FROM certificates WHERE
	validTo <= $date)" or the cleanup equivalent, however this isn't
	possible both because it's not possible to mix static values and a
	select result in an INSERT and because the certID is already present
	from when the cert/request was originally added.  We can fix the former
	by making the static values part of the select result, i.e."INSERT INTO
	certLog VALUES SELECT ACTION_CERT_EXPIRE, $date, certID FROM
	certificates WHERE validTo <= $date" but this still doesn't fix the
	problem with the duplicate IDs.  In fact there isn't really a certID
	present since it's an implicit action, but we can't make the certID
	column null since it's not possible to index nullable columns.  As a
	result the only way we can do it is to repetitively perform 'SELECT
	certID FROM certificates WHERE validTo <= $date' (or the equivalent
	cleanup select) and for each time it succeeds follow it with:

	  INSERT INTO certLog VALUES
		(ACTION_EXPIRE_CERT, $date, <nonce>, NULL, <certID>);
	  DELETE FROM certificates WHERE certID = <certID>

	or

	  INSERT INTO certLog VALUES
		(ACTION_RESTART_CLEANUP, $date, <nonce>, NULL, <certID>);
	  DELETE FROM certRequests WHERE certID = <certID>

	This has the unfortunate side-effect that the update isn't atomic, we
	could enforce this with "LOCK TABLE <name> IN EXCLUSIVE MODE", however
	the MS databases don't support this and either require the use of
	baroque mechanisms such as a "(TABLOCKX HOLDLOCK)" as a locking hint
	after the table name in the first statement after the transaction is
	begun or don't support this type of locking at all.  Because of this it
	isn't really possible to make the update atomic, in particular for the
	cleanup operation we rely on the caller to perform it at startup before
	anyone else accesses the cert store.  The fact that the update isn't
	quite atomic isn't really a major problem, at worst it'll result in
	either an expired cert being visible or a leftover request blocking a
	new request for a split second longer than they should.
	
	An additional feature that we could make use of for CA operations is the
	use of foreign keys to ensure referential integrity, usually via entries
	in the cert log.  For example we could require that all cert requests be
	authorised by adding an authCertID column to the certReq table and
	constraining it with:

		FOREIGN KEY (authCertID) REFERENCES certLog.reqCertID

	however (apart from the overhead of adding extra indexed columns just to
	ensure referential integrity) the syntax for this varies somewhat between
	vendors so that it'd require assorted rewriting by the back-end glue code
	to handle the different requirements for each database type.  In addition
	since the foreign key constraint is specified at table create time, we
	could experience strange failures on table creation requiring special-
	purpose workarounds where we remove the foreign-key constraint in the 
	hope that the table create then succeeds.

	An easier way to handle this is via manual references to entries in the 
	cert log.  Since this is append-only, a manual presence check can never
	return an incorrect result (an entry can't be removed between time of 
	check and time of use), so this provides the same result as using 
	referential integrity mechanisms.

	Another database feature that we could use is database triggers as a 
	backup for the access control settings.  For example (using one
	particular SQL dialect) we could say:

		CREATE TRIGGER checkLog ON certLog FOR UPDATE, DELETE AS
			BEGIN
				ROLLBACK
			END

	However as the "dialect" reference in the above comment implies, this
	process is *extremely* back-end specific (far more so than access 
	controls and the use of foreign keys), so we can't really do much here
	without ending up having to set different triggers for each back-end
	type and even back-end version */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Check that a key ID doesn't (appear to ) contain data that may cause
   problems with SQL */

static int checkKeyID( const char *keyID, const int keyIDlength )
	{
	int i;

	/* Make sure that the key doesn't contain anything that looks like an SQL
	   escape command.  A more rigorous check is done by formatSQL(), this
	   preliminary check only weeds out obviously problematic values */
	for( i = 0; i < keyIDlength; i++ )
		if( keyID[ i ] == '\'' )
			return( CRYPT_ERROR );
	return( keyIDlength );
	}

/* Set up key ID information for a query.  There are two variations of
   this, makeKeyID() encodes an existing keyID value and getKeyID() reads an
   attribute from an object and encodes it */

int makeKeyID( char *keyIDbuffer, const int keyIDbufSize,
			   const CRYPT_KEYID_TYPE keyIDtype, 
			   const void *keyID, const int keyIDlength )
	{
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
	int idLength = keyIDlength, status;

	assert( ( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_URI ) || \
			( keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERID || \
			  keyIDtype == CRYPT_IKEYID_CERTID ) );

	/* Name and email address are used as is */
	if( keyIDtype == CRYPT_KEYID_NAME || \
		keyIDtype == CRYPT_KEYID_URI )
		{
		idLength = min( idLength, ( CRYPT_MAX_TEXTSIZE * 2 ) - 1 );
		memcpy( keyIDbuffer, keyID, idLength );
		keyIDbuffer[ idLength ] = '\0';
		if( keyIDtype == CRYPT_KEYID_URI )
			{
			int i;

			/* Force the search URI to lowercase to make case-insensitive 
			   matching easier.  In most cases we could ask the back-end to 
			   do this, but this complicates indexing and there's no reason 
			   why we can't do it here */
			for( i = 0; i < idLength; i++ )
				keyIDbuffer[ i ] = toLower( keyIDbuffer[ i ] );
			}
		return( checkKeyID( keyIDbuffer, idLength ) );
		}

	/* A keyID is just a subjectKeyIdentifier, which is supposed to be an
	   SHA-1 hash anyway but which in practice can be almost anything so we
	   always hash it to a fixed-length value */
	if( keyIDtype == CRYPT_IKEYID_KEYID )
		{
		HASHFUNCTION hashFunction;

		/* Get the hash algorithm information and hash the keyID to get
		   the fixed-length keyID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
		hashFunction( NULL, hashBuffer, ( void * ) keyID, keyIDlength,
					  HASH_ALL );
		keyID = hashBuffer;
		idLength = DBXKEYID_SIZE;
		}

	assert( idLength >= DBXKEYID_SIZE );

	/* base64-encode the key ID so that we can use it with database queries.
	   Since we only store 128 bits of a (usually 160 bit) ID to save space
	   (particularly where it's used in indices) and speed lookups, this
	   encoding step has the side-effect of truncating the ID down to the
	   correct size */
	status = base64encode( keyIDbuffer, keyIDbufSize, keyID, DBXKEYID_SIZE,
						   CRYPT_CERTTYPE_NONE );
	keyIDbuffer[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
	assert( !cryptStatusError( status ) );
	return( checkKeyID( keyIDbuffer, MAX_ENCODED_DBXKEYID_SIZE ) );
	}

int getKeyID( char *keyIDbuffer, const CRYPT_HANDLE cryptHandle,
			  const CRYPT_ATTRIBUTE_TYPE keyIDtype )
	{
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
	int status;

	assert( ( keyIDtype == CRYPT_CERTINFO_FINGERPRINT_SHA || \
			  keyIDtype == CRYPT_IATTRIBUTE_AUTHCERTID ) || \
			( keyIDtype == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER || \
			  keyIDtype == CRYPT_IATTRIBUTE_ISSUER || \
			  keyIDtype == CRYPT_IATTRIBUTE_SUBJECT || \
			  keyIDtype == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			  keyIDtype == CRYPT_IATTRIBUTE_SPKI ) );

	/* Get the attribute from the cert and hash it, unless it's already a
	   hash */
	if( keyIDtype == CRYPT_CERTINFO_FINGERPRINT_SHA || \
		keyIDtype == CRYPT_IATTRIBUTE_AUTHCERTID )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, hashBuffer, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, keyIDtype );
		if( cryptStatusError( status ) )
			return( status );
		assert( msgData.length == KEYID_SIZE );
		}
	else
		{
		DYNBUF idDB;
		HASHFUNCTION hashFunction;
		int hashSize;

		/* Get the attribute data and hash it to get the ID */
		status = dynCreate( &idDB, cryptHandle, keyIDtype );
		if( cryptStatusError( status ) )
			return( status );
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( NULL, hashBuffer, dynData( idDB ), dynLength( idDB ),
					  HASH_ALL );
		assert( hashSize == KEYID_SIZE );
		dynDestroy( &idDB );
		}

	return( makeKeyID( keyIDbuffer, DBXKEYID_BUFFER_SIZE,
					   CRYPT_IKEYID_CERTID, hashBuffer, KEYID_SIZE ) );
	}

/* Get a keyID for a certificate */

int getCertKeyID( char *keyID, const CRYPT_CERTIFICATE iCryptCert )
	{
	int status;

	/* Certificate keyID handling isn't quite as simple as just reading an
	   attribute from the certificate since the subjectKeyIdentifier (if
	   present) may not be the same as the keyID if the cert has come from
	   a CA that does strange things with the sKID.  To resolve this we try
	   and build the key ID from the sKID, if this isn't present we use the
	   keyID (the sKID may have a nonstandard length since it's possible to
	   stuff anything in there, getKeyID() will hash it to the standard size
	   if the length is wrong) */
	status = getKeyID( keyID, iCryptCert,
					   CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( !cryptStatusError( status ) )
		return( status );

	/* There's no subjectKeyIdentifier, use the keyID.  Note that we can't
	   just read the CRYPT_IATTRIBUTE_KEYID attribute directly since this
	   may be a data-only cert (either a standalone cert or one from the
	   middle of a chain), so we have to generate it indirectly by hashing
	   the SubjectPublicKeyInfo, which is equivalent to the keyID and is
	   always present in a cert */
	return( getKeyID( keyID, iCryptCert, CRYPT_IATTRIBUTE_SPKI ) );
	}

/* Some internal actions set extended error codes as a result of their 
   operation that the user shouldn't really see.  For example performing a 
   cert cleanup will return a no-data-found error once the last cert is
   reached, which will be read by the user the next time they read the
   CRYPT_ATTRIBUTE_INT_ERRORCODE/CRYPT_ATTRIBUTE_INT_ERRORMESSAGE, even 
   though the error came from a previous internal operation.  To avoid
   this problem, we clean up the error status info when it's been set by
   an internal operation */

int resetErrorInfo( DBMS_INFO *dbmsInfo )
	{
	dbmsInfo->errorCode = 0;
	memset( dbmsInfo->errorMessage, 0, MAX_ERRMSG_SIZE );
	return( CRYPT_OK );
	}

/* Get names and IDs for various items */

char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype )
	{
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			return( "CN" );

		case CRYPT_KEYID_URI:
			return( "email" );

		case CRYPT_IKEYID_KEYID:
			return( "keyID" );

		case CRYPT_IKEYID_ISSUERID:
			return( "issuerID" );

		case CRYPT_IKEYID_CERTID:
			return( "certID" );
		}

	assert( NOTREACHED );
	return( "XXXX" );		/* Get rid of compiler warning */
	}

char *getTableName( const KEYMGMT_ITEM_TYPE itemType )
	{
	switch( itemType )
		{
		case KEYMGMT_ITEM_REQUEST:
			return( "certRequests" );

		case KEYMGMT_ITEM_PKIUSER:
			return( "pkiUsers" );

		case KEYMGMT_ITEM_PUBLICKEY:
			return( "certificates" );

		case KEYMGMT_ITEM_REVOCATIONINFO:
			return( "CRLs" );
		}

	assert( NOTREACHED );
	return( "XXXX" );		/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							Database Access Functions						*
*																			*
****************************************************************************/

/* Create a new key database */

static int createDatabase( DBMS_INFO *dbmsInfo, 
						   const BOOLEAN hasPermissions )
	{
	int updateProgress = 0, status;

	/* Create tables for certs, CRLs, cert requests, PKI users, and CA logs.
	   We use CHAR rather than VARCHAR for the ID fields since these always
	   have a fixed length and CHAR is faster than VARCHAR.  In addition we
	   make as many columns as possible NOT NULL since these fields should
	   always be present, and because this is faster for most databases.  The
	   BLOB type is nonstandard, this is rewritten by the database interface
	   layer to the type which is appropriate for the database */
	status = dbmsStaticUpdate(
			"CREATE TABLE certificates ("
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"email VARCHAR(64), "
				"validTo DATETIME NOT NULL, "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"keyID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
	if( cryptStatusError( status ) )
		return( status );
	if( isCertStore( dbmsInfo ) )
		/* The cert store contains in addition to the other CRL fields the
		   certificate expiry time which is used to remove the entry from
		   the CRL table once the certificate has expired anyway, the nameID
		   which is used to force clustering of entries for each CA, and the
		   ID of the cert being revoked, which isn't available if we're
		   creating it from a raw CRL */
		status = dbmsStaticUpdate(
			"CREATE TABLE CRLs ("
				"expiryDate DATETIME NOT NULL, "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL,"
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
	else
		status = dbmsStaticUpdate(
			"CREATE TABLE CRLs ("
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL,"
				"certData BLOB NOT NULL)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE pkiUsers ("
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"keyID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE certRequests ("
				"type SMALLINT NOT NULL, "
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"email VARCHAR(64), "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE certLog ("
				"action SMALLINT NOT NULL, "
				"actionTime DATETIME NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"reqCertID CHAR(" TEXT_DBXKEYID_SIZE "), "
				"subjCertID CHAR(" TEXT_DBXKEYID_SIZE "), "
				"certData BLOB)" );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo the previous table creations */
		dbmsStaticUpdate( "DROP TABLE certificates" );
		if( updateProgress > 0 )
			dbmsStaticUpdate( "DROP TABLE CRLs" );
		if( updateProgress > 1 )
			dbmsStaticUpdate( "DROP TABLE pkiUsers" );
		if( updateProgress > 2 )
			dbmsStaticUpdate( "DROP TABLE certRequests" );
		return( status );
		}

	/* Create an index for the email address, nameID, issuerID, keyID, and
	   certID in the certificates table, the issuerID and certID in the CRLs
	   table (the CRL nameID isn't indexed since we only use it for linear
	   scans), the nameID and keyID in the PKI users table (the former isn't 
	   used but is made a UNIQUE INDEX to ensure that the same entry can't 
	   be added more than once) and the certID in the cert log (this also 
	   isn't used but is made a UNIQUE INDEX to ensure that the same entry 
	   can't be added more than once).  We have to give these unique names 
	   since some databases don't allow two indexes to have the same name, 
	   even if they're in a different table.  Since most of the fields in 
	   the tables are supposed to be unique, we can specify this for the 
	   indexes we're creating, however we can't do it for the email address 
	   or the nameID in the certs table since there could be multiple certs 
	   present that differ only in key usage.  We don't index the other 
	   tables since indexes consume space and we don't expect to access any
	   of these much */
	status = dbmsStaticUpdate(
			"CREATE INDEX emailIdx ON certificates(email)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE INDEX nameIDIdx ON certificates(nameID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX issuerIDIdx ON certificates(issuerID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX keyIDIdx ON certificates(keyID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX certIDIdx ON certificates(certID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX crlIssuerIDIdx ON CRLs (issuerID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX crlCertIDIdx ON CRLs (certID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX userKeyIDIdx ON pkiUsers (keyID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX userNameIDIdx ON pkiUsers (nameID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX logCertIDIdx ON certLog (certID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		char dummyCertID[ DBXKEYID_BUFFER_SIZE ];

		/* Create a special dummy certID with an out-of-band value to mark
		   the first entry in the log */
		memset( dummyCertID, '-', MAX_ENCODED_DBXKEYID_SIZE );
		dummyCertID[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';

		/* Add the initial log entry recording the creation of the log */
		status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CREATE,
								dummyCertID, NULL, NULL, NULL, 0,
								DBMS_UPDATE_NORMAL );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo the creation of the various tables */
		dbmsStaticUpdate( "DROP TABLE certificates" );
		dbmsStaticUpdate( "DROP TABLE CRLs" );
		if( isCertStore( dbmsInfo ) )
			{
			dbmsStaticUpdate( "DROP TABLE pkiUsers" );
			dbmsStaticUpdate( "DROP TABLE certRequests" );
			dbmsStaticUpdate( "DROP TABLE certLog" );
			}
		return( CRYPT_ERROR_WRITE );
		}

	/* If the back-end doesn't support access permissions (generally only 
	   toy ones like Access and Paradox), or it's not a CA cert store, 
	   we're done */
	if( !hasPermissions || !isCertStore( dbmsInfo ) )
		return( CRYPT_OK );

	/* Set access controls for the cert store tables:

						Users				CAs
		certRequests:	-					INS,SEL,DEL
		certificates:	SEL					INS,SEL,DEL
		CRLs:			-					INS,SEL,DEL
		pkiUsers:		-					INS,SEL,DEL
		certLog:		-					INS,SEL
	
	   Once role-based access controls are enabled, we can allow only the CA 
	   user to update the certstore tables, and allow others only read 
	   access to the certs table.  In addition the revocation should be
	   phrased as REVOKE ALL, GRANT <permitted> rather than revoking specific
	   privileges, since each database vendor has their own nonstandard
	   additional privileges that a specific revoke won't cover.  
	   Unfortunately configuring this will be somewhat difficult since it
	   requires that cryptlib users create database user roles, which in turn
	   requires that they read the manual */
#if 1
	dbmsStaticUpdate( "REVOKE UPDATE ON certificates FROM PUBLIC" );
	dbmsStaticUpdate( "REVOKE UPDATE ON CRLs FROM PUBLIC" );
	dbmsStaticUpdate( "REVOKE UPDATE ON pkiUsers FROM PUBLIC" );
	dbmsStaticUpdate( "REVOKE UPDATE ON certRequests FROM PUBLIC" );
	dbmsStaticUpdate( "REVOKE DELETE,UPDATE ON certLog FROM PUBLIC" );
#else
	dbmsStaticUpdate( "REVOKE ALL ON certificates FROM PUBLIC" );
	dbmsStaticUpdate( "GRANT INSERT,SELECT,DELETE ON certificates TO ca" );
	dbmsStaticUpdate( "GRANT SELECT ON certificates TO PUBLIC" );
	dbmsStaticUpdate( "REVOKE ALL ON CRLs FROM PUBLIC" );
	dbmsStaticUpdate( "GRANT INSERT,SELECT,DELETE ON CRLs TO ca" );
	dbmsStaticUpdate( "REVOKE ALL ON pkiUsers FROM PUBLIC" );
	dbmsStaticUpdate( "GRANT INSERT,SELECT,DELETE ON pkiUsers TO ca" );
	dbmsStaticUpdate( "REVOKE ALL ON certRequests FROM PUBLIC" );
	dbmsStaticUpdate( "GRANT INSERT,SELECT,DELETE ON certRequests TO ca" );
	dbmsStaticUpdate( "REVOKE ALL ON certLog FROM PUBLIC" );
	dbmsStaticUpdate( "GRANT INSERT,SELECT ON certLog TO ca" );
#endif /* 1 */

	return( CRYPT_OK );
	}

/* Return status info for the keyset */

static BOOLEAN isBusyFunction( KEYSET_INFO *keysetInfo )
	{
	return( ( keysetInfo->keysetDBMS->flags & \
			  ( DBMS_FLAG_UPDATEACTIVE | DBMS_FLAG_QUERYACTIVE ) ) ? \
			  TRUE : FALSE );
	}

/* Open a connection to a database */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	int featureFlags, status;

	/* Perform a database back-end specific open */
	status = dbmsOpen( name, ( options == CRYPT_KEYOPT_READONLY ) ? \
							 options : CRYPT_KEYOPT_NONE, &featureFlags );
	if( cryptStatusError( status ) )
		{
		endDbxSession( keysetInfo );
		return( status );
		}

	/* If the back-end is read-only (which would be extremely unusual, 
	   usually related to misconfigured DBMS access permissions) and we're 
	   not opening it in read-only mode, signal an error */
	if( ( featureFlags & DBMS_HAS_NOWRITE ) && \
		options != CRYPT_KEYOPT_READONLY )
		{
		endDbxSession( keysetInfo );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* If we're being asked to create a new database, create it and exit */
	if( options == CRYPT_KEYOPT_CREATE )
		{
		status = createDatabase( dbmsInfo, 
								 ( featureFlags & DBMS_HAS_PRIVILEGES ) ? \
								   TRUE : FALSE );
		if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
			status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CONNECT,
									NULL, NULL, NULL, NULL, 0,
									DBMS_UPDATE_NORMAL );
		if( cryptStatusError( status ) )
			{
			dbmsClose();
			endDbxSession( keysetInfo );
			}
		return( status );
		}

	/* Check to see whether it's a cert store.  We do this by checking for
	   the presence of the cert store creation entry in the log, this is
	   always present with an action value of CRYPT_CERTACTION_CREATE */
	status = dbmsStaticQuery(
			"SELECT certData FROM certLog WHERE action = "
				TEXT_CERTACTION_CREATE,
							  DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
	if( cryptStatusOK( status ) )
		{
		/* It's a cert store, if we're opening it as a non-cert-store it has
		   to be in read-only mode.  We return an error rather than quietly
		   changing the access mode to read-only both to make it explicit to
		   the user at open time that they can't make changes and because we
		   need to have the read-only flag set when we open the database to
		   optimise the buffering and locking strategy, setting it at this
		   point is too late */
		if( !isCertStore( dbmsInfo ) )
			{
			if( options != CRYPT_KEYOPT_READONLY )
				{
				dbmsClose();
				endDbxSession( keysetInfo );
				status = CRYPT_ERROR_PERMISSION;
				}

			/* Remember that even though it's not functioning as a cert
			   store, we can still perform some extended queries on it based
			   on fields that are only present in cert stores */
			dbmsInfo->flags |= DBMS_FLAG_CERTSTORE_FIELDS;

			return( status );
			}

		/* If this isn't a read-only open then record a connection to the
		   store */
		if( options != CRYPT_KEYOPT_READONLY )
			{
			status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CONNECT,
									NULL, NULL, NULL, NULL, 0,
									DBMS_UPDATE_NORMAL );
			if( cryptStatusError( status ) )
				{
				dbmsClose();
				endDbxSession( keysetInfo );
				}
			}

		return( status );
		}

	/* It's not a cert store, if we're expecting to open it as one tell the
	   caller */
	if( isCertStore( dbmsInfo ) )
		{
		dbmsClose();
		endDbxSession( keysetInfo );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Since the failure of the query above will set the extended error
	   information, we have to explicitly clear it here to avoid making the
	   (invisible) query side-effects visible to the user */
	dbmsInfo->errorCode = 0;
	memset( dbmsInfo->errorMessage, 0, MAX_ERRMSG_SIZE );

	return( CRYPT_OK );
	}

/* Close the connection to a database */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;

	/* If it's a cert store opened in read/write mode, record a closed
	   connection to the store */
	if( isCertStore( dbmsInfo ) && \
		keysetInfo->options != CRYPT_KEYOPT_READONLY )
		updateCertLog( dbmsInfo, CRYPT_CERTACTION_DISCONNECT, NULL, NULL,
					   NULL, NULL, 0, DBMS_UPDATE_NORMAL );

	/* If we're in the middle of a query, cancel it.  We always use 
	   DBMS_CACHEDQUERY_NONE because this is the only query type that can
	   remain active outside the keyset object */
	if( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE )
		dbmsStaticQuery( NULL, DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CANCEL );

	dbmsClose();
	endDbxSession( keysetInfo );
	}

/****************************************************************************
*																			*
*							Database Access Routines						*
*																			*
****************************************************************************/

/* Set up the function pointers to the keyset methods */

int setAccessMethodDBMS( KEYSET_INFO *keysetInfo,
						 const CRYPT_KEYSET_TYPE type )
	{
	int status = CRYPT_ERROR;

	assert( DBMS_CACHEDQUERY_LAST == NO_CACHED_QUERIES );

	/* Set up the lower-level interface functions */
	status = initDbxSession( keysetInfo, type );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	initDBMSread( keysetInfo );
	initDBMSwrite( keysetInfo );
	if( type == CRYPT_KEYSET_ODBC_STORE || \
		type == CRYPT_KEYSET_DATABASE_STORE || \
		type == CRYPT_KEYSET_PLUGIN_STORE )
		initDBMSCA( keysetInfo );
	keysetInfo->isBusyFunction = isBusyFunction;

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
