/****************************************************************************
*																			*
*						cryptlib Configuration Settings  					*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#ifndef _CRYPTINI_DEFINED

#define _CRYPTINI_DEFINED

/* Note that VC 7.1 allows selective inheritance of defines set at the top
   level into source files within projects.  For some bizarre reason this
   defaults to 'none' so that setting USE_xxx values at the project level
   doesn't filter down to any of the source files */

/* General capabilities that affect further config options */

#if defined( __BEOS__ ) || defined( __ECOS__ ) || defined( __PALMOS__ ) || \
	defined( __RTEMS__ ) || defined( __SYMBIAN32__ ) || \
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	defined( __UNIX__ ) || defined( __WINDOWS__ )
  #define USE_TCP
#endif /* Systems with networking built into the base OS */

/* Whether to use the RPC API or not.  This provides total isolation of
   input and output data, at the expense of some additional overhead due
   to marshalling and unmarshalling */

/* #define USE_RPCAPI */

/* Whether to use FIPS 140 ACLs or not.  Enabling this setting disables
   all plaintext key loads.  Note that this will cause several of the
   self-tests, which assume that they can load keys directly, to fail */

/* #define USE_FIPS140 */

/* Whether to build the Java/JNI interface or not */

/* #define USE_JAVA */

/* Contexts.  The umbrella define USE_PATENTED_ALGORITHMS can be used to
   drop all patented algorithms (note that this removes IDEA as well, which is
   needed for PGP 2.x private keyring reads and message decryption),
   USE_OBSCURE_ALGORITHMS can be used to drop obscure, obsolete, or weak
   algorithms, and USE_SLIGHTLY_OBSCURE_ALGORITHMS can be used to drop
   further little-used algorithms */

#define USE_PATENTED_ALGORITHMS
#define USE_OBSCURE_ALGORITHMS
#define USE_SLIGHTLY_OBSCURE_ALGORITHMS
#if defined(ORYX_STRIPPED)
#undef USE_PATENTED_ALGORITHMS
#undef USE_OBSCURE_ALGORITHMS
#undef USE_SLIGHTLY_OBSCURE_ALGORITHMS
#endif
#ifdef USE_PATENTED_ALGORITHMS
  #define USE_IDEA
  #define USE_RC5
#endif /* Use of patented algorithms */
#ifdef USE_OBSCURE_ALGORITHMS
  #define USE_CAST
  #define USE_HMAC_MD5
  #define USE_HMAC_RIPEMD160
  #define USE_MD4
  #define USE_RC2
  #define USE_SKIPJACK
#endif /* Obscure/obsolete algorithms */
#ifdef USE_SLIGHTLY_OBSCURE_ALGORITHMS
  #define USE_ELGAMAL
  #define USE_MD2
  #define USE_RIPEMD160
#endif /* Slightly obscure algorithms */
#define USE_AES
#define USE_BLOWFISH
#define USE_RC4
#define USE_SHA2
#if defined( __UNIX__ ) && defined( _CRAY )
  /* The AES and SHA-2 reference code require a 32-bit data type, but Crays
	 only have 8-bit and 64-bit types */
  #undef USE_AES
  #undef USE_SHA2
#endif /* Crays */
#undef USE_SHA2

/* Devices */

#if defined( __WIN32__ )
  #define USE_PKCS11
  #define USE_FORTEZZA
  #define USE_CRYPTOAPI
#endif /* __WIN32__ */
#if defined( USE_PKCS11 ) || defined( USE_FORTEZZA ) || defined( USE_CRYPTOAPI )
  #define USE_DEVICES
#endif /* Device types */

/* Enveloping */

#define USE_CMS
#define USE_COMPRESSION
#define USE_PGP
#if defined(ORYX_STRIPPED)
#undef USE_CMS
#undef USE_PGP
#endif
#if defined( USE_PGP ) && !defined( USE_ELGAMAL )
  #define USE_ELGAMAL
#endif /* OpenPGP requires Elgamal */
#if defined( USE_CMS ) || defined( USE_PGP )
  #define USE_ENVELOPES
#endif /* Enveloping types */

/* Keysets */

#if defined( __WIN16__ ) || defined( __WIN32__ )
  #if !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 ) )
	#define USE_ODBC
  #endif /* Old Borland C++ */
  #if !defined( NT_DRIVER )
	#define USE_LDAP
  #endif /* !NT_DRIVER */
#endif /* Windows */
#if ( defined( USE_ODBC ) && ( defined( USE_MYSQL ) || defined( USE_ORACLE ) || defined( USE_POSTGRES ) ) ) || \
	( defined( USE_MYSQL ) && ( defined( USE_ORACLE ) || defined( USE_POSTGRES ) ) ) || \
	( defined( USE_ORACLE ) && defined( USE_POSTGRES ) )
  #error You can only define one of USE_MYSQL, USE_ODBC, USE_ORACLE, or USE_POSTGRES
#endif /* Conflicting USE_database defines */
#if defined( USE_TCP ) || defined( USE_ODBC ) || defined( USE_MYSQL ) || \
	defined( USE_ORACLE ) || defined( USE_POSTGRES )
  #define USE_DBMS
#endif /* RDBMS types */
#ifdef USE_TCP
  #define USE_HTTP
#endif /* TCP/IP networking */
/* By uncommenting the following PKCS #12 #define or enabling equivalent
   functionality in any other manner you acknowledge that you are disabling
   safety features in the code and take full responbility for any
   consequences arising from this action.  You also indemnify the cryptlib
   authors against all actions, claims, losses, costs, and expenses that
   may be suffered or incurred and that may have arisen directly or
   indirectly as a result of any use of cryptlib with this change made.  If
   you receive the code with the safety features already disabled, you must
   obtain an original, unmodified version.

   Actually since the code isn't currently implemented (see the comment in
   dbx_pk12.c) it's best not to uncomment it at all */
/* #define USE_PKCS12 */
#define USE_PGPKEYS
#define USE_PKCS15
#if defined( USE_DBMS ) || defined( USE_HTTP ) || defined( USE_LDAP ) || \
	defined( USE_PGPKEYS ) || defined( USE_PKCS12 ) || defined( USE_PKCS15 )
  #define USE_KEYSETS
#endif /* Keyset types */

/* Sessions.  SSHv1 is explicitly disabled (or at least not enabled), you
   should only enable this if there's a very good reason to use it.
   Enabling it here will also produce a double-check warning in ssh1.c that
   needs to be turned off to allow the code to build */

#ifdef USE_TCP
  #define USE_CERTSTORE
  #define USE_CMP
  #define USE_RTCS
  #define USE_OCSP
  #define USE_SCEP
  #define USE_SSH2
  #define USE_SSL
  #define USE_TSP
#endif /* USE_TCP */
#if defined( USE_CMP ) || defined( USE_RTCS ) || defined( USE_OCSP ) || \
	defined( USE_SCEP ) || defined( USE_SSH1 ) || defined( USE_SSH2 ) || \
	defined( USE_SSL ) || defined( USE_TSP )
  #define USE_SESSIONS
#endif /* Session types */

/* System resources.  Threads and widechars */

#if defined( __BEOS__ ) || defined( __ECOS__ ) || defined( __ITRON__ ) || \
	defined( __OS2__ ) || defined( __PALMOS__ ) || defined( __RTEMS__ ) || \
	defined( __VXWORKS__ ) || defined( __WIN32__ ) || defined( __WINCE__ )
  #define USE_THREADS
#endif /* Non-Unix systems with threads */
#if defined( __UNIX__ ) && \
	!( ( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
	   ( defined( sun ) && ( OSVERSION <= 4 ) ) || defined( __TANDEM ) )
  #define USE_THREADS
#endif /* Unix systems with threads */
#ifdef NO_THREADS
  /* Allow thread use to be overridden by the user if required */
  #undef USE_THREADS
#endif /* NO_THREADS */

#if defined( __BEOS__ ) || defined( __ECOS__ ) || defined( __MSDOS32__ ) || \
	defined( __OS2__ ) || defined( __RTEMS__ ) || \
	( ( defined( __WIN32__ ) || defined( __WINCE__ ) ) && \
	  !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 ) ) )
  #define USE_WIDECHARS
#endif /* Non-Unix systems with widechars */
#if defined( __UNIX__ ) && \
	!( ( defined( __APPLE__ ) && OSVERSION < 7 ) || \
	   defined( __bsdi__ ) || defined( __CYGWIN__ ) || \
	   defined( __OpenBSD__ ) || \
	   ( defined( __SCO_VERSION__ ) && OSVERSION < 5 ) || \
	   ( defined( sun ) && OSVERSION < 5 ) || \
	   defined( __SYMBIAN32__ ) )
  #define USE_WIDECHARS
#endif /* Unix systems with widechars */

/* Anti-defines.  Rather than making everything even more complex and
   conditional than it already is, it's easier to undefine the features that
   we don't want in one place rather than trying to conditionally enable
   them */

#if defined(ORYX_STRIPPED)	/* Devices */
  #undef USE_PKCS11
  #undef USE_FORTEZZA
  #undef USE_CRYPTOAPI
#endif /* 0 */
#if defined(ORYX_STRIPPED)	/* Heavyweight keysets */
  #undef USE_HTTP
  #undef USE_LDAP
  #undef USE_ODBC
  #undef USE_DBMS
#endif /* 0 */
#if defined(ORYX_STRIPPED)	/* Networking */
  #undef USE_CMP
  #undef USE_RTCS
  #undef USE_OCSP
  #undef USE_SCEP
  #undef USE_SSH1
  #undef USE_SSH2
  #undef USE_TSP
#endif /* 0 */
#endif /* _CRYPTINI_DEFINED */
