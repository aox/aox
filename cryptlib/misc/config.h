/****************************************************************************
*																			*
*						cryptlib Configuration Settings  					*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _CONFIG_DEFINED

#define _CONFIG_DEFINED

/* Note that VC 7.1 allows selective inheritance of defines set at the top
   level into source files within projects.  For some bizarre reason this
   defaults to 'none' so that setting USE_xxx values at the project level
   doesn't filter down to any of the source files unless it's manually
   enabled in the compiler config options */

/* General capabilities that affect further config options */

#if defined( __BEOS__ ) || defined( __CHORUS__ ) || defined( __ECOS__ ) || \
	defined( __PALMOS__ ) || defined( __RTEMS__ ) || defined( __SYMBIAN32__ ) || \
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	defined( __UNIX__ ) || defined( __WINDOWS__ )
  #define USE_TCP
#endif /* Systems with TCP/IP networking available */

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

/* Whether to provide descriptive text messages for errors or not.
   Disabling these can reduce code size, at the expense of making error
   diagnosis reliant solely on error codes */

#define USE_ERRMSGS

/****************************************************************************
*																			*
*									Contexts								*
*																			*
****************************************************************************/

/* The umbrella define USE_PATENTED_ALGORITHMS can be used to drop all
   patented algorithms (note that this removes IDEA, which is needed for PGP
   2.x private keyring reads and message decryption),
   USE_DEPRECATED_ALGORITHMS can be used to drop deprecated (obsolete or
   weak) algorithms, and USE_OBSCURE_ALGORITHMS can be used to drop little-
   used algorithms.  Technically both DES and MD5 are also deprecated, but
   they're still so widely used that it's not really possible to drop them */

#if !defined( __MSDOS__ ) && !defined( __WIN16__ )
  #define USE_PATENTED_ALGORITHMS
  #define USE_OBSCURE_ALGORITHMS
#endif /* __MSDOS__ || __WIN16__ */

/* Patented algorithms */

#ifdef USE_PATENTED_ALGORITHMS
  #define USE_IDEA
  #define USE_RC5
#endif /* Use of patented algorithms */

/* Obsolete and/or weak algorithms */

#ifdef USE_DEPRECATED_ALGORITHMS
  #define USE_MD2
  #define USE_MD4
  #define USE_RC2
  #define USE_RC4
  #define USE_SKIPJACK
#endif /* Obsolete and/or weak algorithms */

/* Obscure algorithms */

#ifdef USE_OBSCURE_ALGORITHMS
  #define USE_CAST
  #define USE_ELGAMAL
  #define USE_HMAC_MD5
  #define USE_HMAC_RIPEMD160
  #define USE_RIPEMD160
#endif /* Obscure algorithms */

/* Other algorithms.  Note that DES/3DES and SHA1 are always enabled, as
   they're used internally by cryptlib */

#define USE_AES
#define USE_BLOWFISH
#define USE_DH
#define USE_DSA
#define USE_MD5
#define USE_RSA
#define USE_SHA2
#if defined( __UNIX__ ) && defined( _CRAY )
  /* The AES and SHA-2 reference code require a 32-bit data type, but Crays
	 only have 8-bit and 64-bit types */
  #undef USE_AES
  #undef USE_SHA2
#endif /* Crays */
#if defined( __MSDOS__ )
  /* Remove some of the more memory-intensive or unlikely-to-be-used-under-DOS
	 algorithms */
  #undef USE_BLOWFISH
  #undef USE_DH
  #undef USE_MD5
  #undef USE_SHA2

  /* Remove further algorithms to save space */
  #undef USE_DSA
  #undef USE_RSA
#endif /* DOS */

/* General PKC context usage */

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL ) || \
	defined( USE_RSA )
  #define USE_PKC
#endif /* PKC types */

/****************************************************************************
*																			*
*									Certificates							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_CERTIFICATES

/* The cert-processing code is so deeply intertwingled (almost all of the
   code to manipulate cert attributes is shared, with only a few cert-type-
   specific routines) that it's not really possible to separate out specific
   sections, so all that we can provide is the ability to turn the entire
   lot on or off */

#define USE_CERTIFICATES

#if defined( USE_CERTIFICATES ) && !defined( USE_PKC )
  #error Use of certificates requires use of PKC algorithms to be enabled
#endif /* USE_CERTIFICATES && !USE_PKC */

#endif /* CONFIG_NO_CERTIFICATES */

/****************************************************************************
*																			*
*									Devices									*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_DEVICES

#if defined( __WIN32__ )
  #define USE_FORTEZZA
  #ifndef __BORLANDC__
	#define USE_CRYPTOAPI
	#define USE_PKCS11
  #endif /* __BORLANDC__ */
#endif /* __WIN32__ */

/* General device usage */

#if defined( USE_PKCS11 ) || defined( USE_FORTEZZA ) || defined( USE_CRYPTOAPI )
  #define USE_DEVICES
#endif /* Device types */

#endif /* CONFIG_NO_DEVICES */

/****************************************************************************
*																			*
*									Enveloping								*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_ENVELOPES

/* CMS envelopes */

#define USE_CMS
#if !defined( __MSDOS__ ) && !defined( __WIN16__ )
  #define USE_COMPRESSION
#endif /* __MSDOS__ || __WIN16__ */

/* PGP envelopes */

#define USE_PGP
#if defined( USE_PGP ) && !defined( USE_ELGAMAL )
  #define USE_ELGAMAL
#endif /* OpenPGP requires Elgamal */

/* General envelope usage */

#if defined( USE_CMS ) || defined( USE_PGP )
  #define USE_ENVELOPES
#endif /* Enveloping types */

#if defined( USE_ENVELOPE ) && !defined( USE_PKC )
  #error Use of envelopes requires use of PKC algorithms to be enabled
#endif /* USE_ENVELOPE && !USE_PKC */

#endif /* CONFIG_NO_ENVELOPES */

/****************************************************************************
*																			*
*									Keysets									*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_KEYSETS

/* Database keysets.  This setting can also be enabled under Unix by the 
   auto-config mechanism */

#if defined( __WIN32__ ) && !defined( NT_DRIVER )
  #if !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 ) )
	#define USE_ODBC
  #endif /* Old Borland C++ */
#endif /* Windows */
#if defined( USE_ODBC ) || defined( USE_DATABASE ) || \
						   defined( USE_DATABASE_PLUGIN )
  #define USE_DBMS
#endif /* RDBMS types */

/* Network keysets.  This setting can also be enabled under Unix by the
   auto-config mechanism */

#if defined( __WIN32__ ) && \
	!( defined( NT_DRIVER ) || defined( __BORLANDC__ ) )
  #define USE_LDAP
#endif /* Windows */
#ifdef USE_TCP
  #define USE_HTTP
#endif /* TCP/IP networking */

/* File keysets */

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
#if defined( USE_PGPKEYS ) || defined( USE_PKCS15 )
  #ifndef USE_PKC
	#error Use of PGP/PKCS #15 keysets requires use of PKC algorithms to be enabled
  #endif /* USE_PKC */
#endif /* USE_PGPKEYS || USE_PKCS15 */

/* General keyset usage */

#if defined( USE_DBMS ) || defined( USE_HTTP ) || defined( USE_LDAP ) || \
	defined( USE_PGPKEYS ) || defined( USE_PKCS12 ) || defined( USE_PKCS15 )
  #define USE_KEYSETS
#endif /* Keyset types */

#endif /* CONFIG_NO_KEYSETS */

/****************************************************************************
*																			*
*									Sessions								*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SESSIONS

/* SSHv1 is explicitly disabled (or at least not enabled), you should only
   enable this if there's a very good reason to use it.  Enabling it here
   will also produce a double-check warning in ssh1.c that needs to be
   turned off to allow the code to build */

#ifdef USE_TCP
  #define USE_CERTSTORE
  #define USE_CMP
  #define USE_RTCS
  #define USE_OCSP
  #define USE_SCEP
  #define USE_SSH
  #define USE_SSL
  #define USE_TSP
#endif /* USE_TCP */

/* General session usage */

#if defined( USE_CMP ) || defined( USE_RTCS ) || defined( USE_OCSP ) || \
	defined( USE_SCEP ) || defined( USE_SSH1 ) || defined( USE_SSH ) || \
	defined( USE_SSL ) || defined( USE_TSP )
  #define USE_SESSIONS
#endif /* Session types */

#if defined( USE_SESSIONS ) && !defined( USE_PKC )
  #error Use of secure sessions requires use of PKC algorithms to be enabled
#endif /* USE_SESSIONS && !USE_PKC */

#endif /* CONFIG_NO_SESSIONS */

/****************************************************************************
*																			*
*							OS Services and Resources						*
*																			*
****************************************************************************/

/* Threads */

#if defined( __BEOS__ ) || defined( __CHORUS__ ) || defined( __ECOS__ ) || \
	defined( __ITRON__ ) || defined( __OS2__ ) || defined( __PALMOS__ ) || \
	defined( __RTEMS__ ) || defined( __UCOSII__ ) || defined( __VXWORKS__ ) || \
	defined( __WIN32__ ) || defined( __WINCE__ )
  #define USE_THREADS
#endif /* Non-Unix systems with threads */

#ifdef __UNIX__
  #if !( ( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
		 ( defined( sun ) && ( OSVERSION <= 4 ) ) || defined( __TANDEM ) )
	#define USE_THREADS
  #endif
#endif /* Unix systems with threads */

#ifdef NO_THREADS
  /* Allow thread use to be overridden by the user if required */
  #undef USE_THREADS
#endif /* NO_THREADS */

/* Widechars */

#if defined( __BEOS__ ) || defined( __ECOS__ ) || defined( __MSDOS32__ ) || \
	defined( __OS2__ ) || defined( __RTEMS__ ) || \
	( ( defined( __WIN32__ ) || defined( __WINCE__ ) ) && \
	  !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 ) ) ) || \
	defined( __XMK__ )
  #define USE_WIDECHARS
#endif /* Non-Unix systems with widechars */

#ifdef __UNIX__
  #if !( ( defined( __APPLE__ ) && OSVERSION < 7 ) || \
		 defined( __bsdi__ ) || defined( __OpenBSD__ ) || \
		 ( defined( __SCO_VERSION__ ) && OSVERSION < 5 ) || \
		 ( defined( sun ) && OSVERSION < 5 ) || \
		 defined( __SYMBIAN32__ ) )
	#define USE_WIDECHARS
  #endif
#endif /* Unix systems with widechars */

/****************************************************************************
*																			*
*							Anti-defines for Testing						*
*																			*
****************************************************************************/

/* Rather than making everything even more complex and conditional than it
   already is, it's easier to undefine the features that we don't want in
   one place rather than trying to conditionally enable them */

#if 0	/* Devices */
  #undef USE_PKCS11
  #undef USE_FORTEZZA
  #undef USE_CRYPTOAPI
#endif /* 0 */
#if 0	/* Heavyweight keysets */
  #undef USE_HTTP
  #undef USE_LDAP
  #undef USE_ODBC
  #undef USE_DBMS
#endif /* 0 */
#if 0	/* Networking */
  #undef USE_CERTSTORE
  #undef USE_TCP
  #undef USE_CMP
  #undef USE_RTCS
  #undef USE_OCSP
  #undef USE_SCEP
  #undef USE_SSH1
  #undef USE_SSH
  #undef USE_SSL
  #undef USE_TSP
  #undef USE_SESSIONS
#endif /* 0 */

#endif /* _CONFIG_DEFINED */
