/****************************************************************************
*																			*
*						cryptlib Test Routines Header File					*
*						Copyright Peter Gutmann 1995-2003					*
*																			*
****************************************************************************/

/* Define the following to enable/disable various blocks of tests */

#if 1
#define TEST_SELFTEST		/* Perform internal self-test */
#define TEST_LOWLEVEL		/* Test low-level functions */
#define TEST_RANDOM			/* Test randomness functions */
#define TEST_CONFIG			/* Test configuration functions */
#define TEST_MIDLEVEL		/* Test high-level encr/sig.functions */
#endif /* 0 */
#if 1
#define TEST_CERT			/* Test certificate management functions */
#define TEST_KEYSET			/* Test keyset read functions */
#define TEST_CERTPROCESS	/* Test certificate handling/CA management */
#endif /* 0 */
#if 1
#define TEST_HIGHLEVEL		/* Test high-level encr/sig.functions */
#define TEST_ENVELOPE		/* Test enveloping functions */
#endif /* 0 */
#if 1
#define TEST_SESSION		/* Test session functions */
#define TEST_USER			/* Test user management functions */
#endif /* 0 */

/* The crypto device tests are disabled by default since relatively few users
   will have a crypto device set up so leaving them enabled by default would
   just produce a cascade of device-not-present warnings */

/* #define TEST_DEVICE */

/* Some of the device tests can be rather slow, the following defines disable
   these tests for speed reasons.  Note that the Fortezza test can be further
   cut down by not performing the CAW test (which erases any existing data on
   the card), this is turned off by default in testdev.c */

/* #define TEST_DEVICE_FORTEZZA */

/* When commenting out code for testing, the following macro displays a
   warning that the behaviour has been changed as well as the location of
   the change */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  #define KLUDGE_WARN( str )	\
			{ \
			char fileName[ 1000 ]; \
			strncpy( fileName, __FILE__, 1000 ); \
			fileName[ 999 ] = '\0'; \
			__atoe( fileName ); \
			printf( "Kludging " str ", file %s, line %d.\n", fileName, __LINE__ ); \
			}
#else
  #define KLUDGE_WARN( str )	\
			printf( "Kludging " str ", file " __FILE__ ", line %d.\n", __LINE__ );
#endif /* ASCII vs.EBCDIC strings */

/* Include univerally-needed headers */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Various useful types */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* Sentinel value used to denote non-data/non-values */

#define SENTINEL		-1000

/* There are a few OSes broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* If we're using a DOS compiler but not a 32-bit one, record this */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

/* It's useful to know if we're running under Windows to enable Windows-
   specific processing */

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define __WINDOWS__
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* In certain memory-starved environments we have to kludge things to help
   the compiler along.  The following define tells the compiler to move BSS
   data outside the default data segment */

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
  #define FAR_BSS			far
#else
  #define FAR_BSS
#endif /* Win16 */

/* Generic buffer size and dynamically-allocated file I/O buffer size.  The
   generic buffer has to be of a reasonable size so we can handle S/MIME
   signature chains, the file buffer should be less than the 16-bit INT_MAX
   for testing on 16-bit machines */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		4096
  #define FILEBUFFER_SIZE	20000
#else
  #define BUFFER_SIZE		8192
  #define FILEBUFFER_SIZE	40960
#endif /* __MSDOS__ && __TURBOC__ */

/* Try and detect OSes that have threading support, this is needed for some
   operations like async keygen and sleep calls.  Under OSF/1 pthread.h
   includes c_asm.h which contains a declaration

	long asm( const char *,...);

   that conflicts with the gcc asm keyword.  This asm stuff is only used
   when inline asm alternatives to the Posix threading functions are enabled,
   which isn't done by default so in theory we could also fix this by
   defining asm to something else before including pthread.h, but it's safer
   to just disable inclusion of c_asm.h by pre-defining the guard define,
   which should result in a more useful warning if for some reason inline
   threading functions with asm are enabled */

#if( ( defined( sun ) && ( OSVERSION > 4 ) ) || defined( __osf__ ) || \
	 defined( __alpha__ ) || defined( __Mach__ ) || defined( _AIX ) || \
	 defined( __linux__ ) )
  #define UNIX_THREADS

  /* We need to include pthread.h at this point because any number of other
     include files perform all sorts of peculiar and unnatural acts in order
     to make their functions (transparently) thread-safe, triggered by the
     detection of values defined in pthread.h.  Because of this we need to
     include it here as a rubber chicken before other files are pulled in
     even though it's not explicitly needed */
  #if defined( __osf__ ) || defined( __alpha__ )
	#define __C_ASM_H		/* See comment in cryptos.h */
  #endif /* Alpha */
  #include <pthread.h>
#endif /* Slowaris || OSF1/DEC Unix || Mach || AIX || Linux */
#if defined( WIN32 ) || defined( _WIN32 )
  #define WINDOWS_THREADS
  #include <process.h>
#endif /* Win32 */
#if defined( __IBMC__ ) && defined( __OS2__ )
  #define OS2_THREADS
#endif /* OS/2 */

/* Try and detect OSes that have widechar support */

#if defined( __WINDOWS__ ) || defined( __linux__ ) || \
	( defined( sun ) && ( OSVERSION > 4 ) ) || defined( __osf__ )
  #define HAS_WIDECHAR
#endif /* OSes with widechar support */

/* If we're running on an EBCDIC system, ensure we're compiled in EBCDIC mode
   to test the conversion of character strings */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* IBM big iron */

/* The key size to use for the PKC routines.  This is the minimum allowed by
   cryptlib, it speeds up the various tests but shouldn't be used in
   practice */

#define PKC_KEYSIZE			512

/* The names of the test key and certificate files.  For flat filesystems we
   give the test files names starting with 'z' so they're easier to find */

#if defined( __VMCMS__ )
  #define TEST_PRIVKEY_FILE			"zkeytest.p15"
  #define TEST_PRIVKEY_ALT_FILE		"zkeytest.p12"
  #define CA_PRIVKEY_FILE			"zkeyca.p15"
  #define ICA_PRIVKEY_FILE			"zkeyica.p15"
  #define SCEPCA_PRIVKEY_FILE		"zkeysca.p15"
  #define USER_PRIVKEY_FILE			"zkeyuser.p15"
  #define DUAL_PRIVKEY_FILE			"zkeydual.p15"
  #define RENEW_PRIVKEY_FILE		"zkeyren.p15"
  #define BIG_PRIVKEY_FILE			"zkeybig.p15"
  #define CMP_PRIVKEY_FILE_TEMPLATE	"zkeycmp.p15"
  #define PNP_PRIVKEY_FILE			"zkeypnp.p15"
  #define SERVER_PRIVKEY_FILE		"zkeysrv.p15"
  #define SSH_PRIVKEY_FILE			"zkeyssh.p15"
  #define TSA_PRIVKEY_FILE			"zkeytsa.p15"

  #define PGP_PUBKEY_FILE			"zpubring.pgp"
  #define PGP_PRIVKEY_FILE			"zsecring.pgp"
  #define OPENPGP_PUBKEY_FILE		"zpubring.gpg"
  #define OPENPGP_PRIVKEY_FILE		"zsecring.gpg"
  #define OPENPGP_PUBKEY_HASH_FILE	"zpubrinh.gpg"
  #define OPENPGP_PRIVKEY_HASH_FILE	"zsecrinh.gpg"
  #define NAIPGP_PUBKEY_FILE		"zpubring.pkr"
  #define NAIPGP_PRIVKEY_FILE		"zsecring.skr"
  #define PKCS12_FILE				"zkey.p12"

  #define CERT_FILE_TEMPLATE		"zcert%d.der"
  #define BASE64CERT_FILE_TEMPLATE	"zcert%d.asc"
  #define BROKEN_CERT_FILE			"zcertb.der"
  #define BROKEN_USER_CERT_FILE		"zcertbus.der"
  #define BROKEN_CA_CERT_FILE		"zcertbca.der"
  #define CERTREQ_FILE_TEMPLATE		"zcertreq%d.der"
  #define CRL_FILE_TEMPLATE			"zcrl%d.der"
  #define CERTCHAIN_FILE_TEMPLATE	"zcertchn%d.der"
  #define RTCS_OK_FILE				"zrtcsrok.der"
  #define OCSP_OK_FILE				"zocsprok.der"
  #define OCSP_REV_FILE				"zocsprrev.der"
  #define OCSP_CA_FILE				"zocspca.der"
  #define CRLCERT_FILE_TEMPLATE		"zcrlcrt%d.der"
  #define CHAINCERT_FILE_TEMPLATE	"zchncrt%d.der"
  #define RTCS_FILE_TEMPLATE		"zrtcsee%do.der"
  #define OCSP_CA_FILE_TEMPLATE		"zocspca%d.der"
  #define OCSP_EEOK_FILE_TEMPLATE	"zocspee%do.der"
  #define OCSP_EEREV_FILE_TEMPLATE	"zocspee%dr.der"
  #define CMP_CA_FILE_TEMPLATE		"zcmpca%d.der"
  #define SCEP_CA_FILE_TEMPLATE		"zscepca%d.der"

  #define SMIME_SIG_FILE_TEMPLATE	"zsmime%d.p7s"
  #define SMIME_ENVELOPED_FILE		"zsmime.p7m"
  #define PGP_ENC_FILE_TEMPLATE		"zenc%d.pgp"
  #define PGP_PKE_FILE_TEMPLATE		"zenc_pk%d.pgp"
  #define OPENPGP_PKE_FILE_TEMPLATE	"zenc_pk%d.gpg"
  #define PGP_SIG_FILE_TEMPLATE		"zsig%d.pgp"
  #define PGP_COPR_FILE_TEMPLATE	"zcopr%d.pgp"

  #define COMPRESS_FILE				"test.h"
#elif defined( __OS400__ )
  #define TEST_PRIVKEY_FILE			"testlib/zkeytest"
  #define TEST_PRIVKEY_ALT_FILE		"testlib/zkeytsta"
  #define CA_PRIVKEY_FILE			"testlib/zkeyca"
  #define ICA_PRIVKEY_FILE			"testlib/zkeyica"
  #define SCEPCA_PRIVKEY_FILE		"testlib/zkeysca"
  #define USER_PRIVKEY_FILE			"testlib/zkeyuser"
  #define DUAL_PRIVKEY_FILE			"testlib/zkeydual"
  #define RENEW_PRIVKEY_FILE		"testlib/zkeyren"
  #define BIG_PRIVKEY_FILE			"testlib/zkeybig"
  #define CMP_PRIVKEY_FILE_TEMPLATE	"testlib/zkeycmp"
  #define PNP_PRIVKEY_FILE			"testlib/zkeypnp"
  #define SERVER_PRIVKEY_FILE		"testlib/zkeysrv"
  #define SSH_PRIVKEY_FILE			"testlib/zkeyssh"
  #define TSA_PRIVKEY_FILE			"testlib/zkeytsa"

  #define PGP_PUBKEY_FILE			"testlib/zpubring"
  #define PGP_PRIVKEY_FILE			"testlib/zsecring"
  #define OPENPGP_PUBKEY_FILE		"testlib/zpubringg"
  #define OPENPGP_PRIVKEY_FILE		"testlib/zsecringg"
  #define OPENPGP_PUBKEY_HASH_FILE	"testlib/zpubrinhg"
  #define OPENPGP_PRIVKEY_HASH_FILE	"testlib/zsecrinhg"
  #define NAIPGP_PUBKEY_FILE		"testlib/zpubringp"
  #define NAIPGP_PRIVKEY_FILE		"testlib/zsecrings"
  #define PKCS12_FILE				"testlib/zkey"

  #define CERT_FILE_TEMPLATE		"testlib/zcert%d"
  #define BASE64CERT_FILE_TEMPLATE	"testlib/zcerta%d"
  #define BROKEN_CERT_FILE			"testlib/zcertb"
  #define BROKEN_USER_CERT_FILE		"testlib/zcertbus"
  #define BROKEN_CA_CERT_FILE		"testlib/zcertbca"
  #define CERTREQ_FILE_TEMPLATE		"testlib/zcertreq%d"
  #define CRL_FILE_TEMPLATE			"testlib/zcrl%d"
  #define CERTCHAIN_FILE_TEMPLATE	"testlib/zcertchn%d"
  #define RTCS_OK_FILE				"testlib/zrtcsrok"
  #define OCSP_OK_FILE				"testlib/zocsprok"
  #define OCSP_REV_FILE				"testlib/zocsprrev"
  #define OCSP_CA_FILE				"testlib/zocspca"
  #define CRLCERT_FILE_TEMPLATE		"testlib/zcrlcrt%d"
  #define CHAINCERT_FILE_TEMPLATE	"testlib/zchncrt%d"
  #define RTCS_FILE_TEMPLATE		"testlib/zrtcsee%do"
  #define OCSP_CA_FILE_TEMPLATE		"testlib/zocspca%d"
  #define OCSP_EEOK_FILE_TEMPLATE	"testlib/zocspee%do"
  #define OCSP_EEREV_FILE_TEMPLATE	"testlib/zocspee%dr"
  #define CMP_CA_FILE_TEMPLATE		"testlib/zcmpca%d"
  #define SCEP_CA_FILE_TEMPLATE		"testlib/zscepca%d"

  #define SMIME_SIG_FILE_TEMPLATE	"testlib/zsmime%d"
  #define SMIME_ENVELOPED_FILE		"testlib/zsmimem"
  #define PGP_ENC_FILE_TEMPLATE		"testlib/zenc%d"
  #define PGP_PKE_FILE_TEMPLATE		"testlib/zenc_pkp%d"
  #define OPENPGP_PKE_FILE_TEMPLATE	"testlib/enc_pkg%d"
  #define PGP_SIG_FILE_TEMPLATE		"testlib/zsig%d"
  #define PGP_COPR_FILE_TEMPLATE	"testlib/zcopr%d"

  #define COMPRESS_FILE				"testlib/test"
#elif defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define TEST_PRIVKEY_FILE			":test:key_test.p15"
  #define TEST_PRIVKEY_ALT_FILE		":test:key_test.p12"
  #define CA_PRIVKEY_FILE			":test:key_ca.p15"
  #define ICA_PRIVKEY_FILE			":test:key_ica.p15"
  #define SCEPCA_PRIVKEY_FILE		":test:key_sca.p15"
  #define USER_PRIVKEY_FILE			":test:key_user.p15"
  #define DUAL_PRIVKEY_FILE			":test:key_dual.p15"
  #define RENEW_PRIVKEY_FILE		":test:key_ren.p15"
  #define BIG_PRIVKEY_FILE			":test:key_big.p15"
  #define CMP_PRIVKEY_FILE_TEMPLATE	":test:key_cmp%d.p15"
  #define PNP_PRIVKEY_FILE			":test:key_pnp.p15"
  #define SERVER_PRIVKEY_FILE		":test:key_srv.p15"
  #define SSH_PRIVKEY_FILE			":test:key_ssh.p15"
  #define TSA_PRIVKEY_FILE			":test:key_tsa.p15"

  #define PGP_PUBKEY_FILE			":test:pubring.pgp"
  #define PGP_PRIVKEY_FILE			":test:secring.pgp"
  #define OPENPGP_PUBKEY_FILE		":test:pubring.gpg"
  #define OPENPGP_PRIVKEY_FILE		":test:secring.gpg"
  #define OPENPGP_PUBKEY_HASH_FILE	":test:pubrinh.gpg"
  #define OPENPGP_PRIVKEY_HASH_FILE	":test:secrinh.gpg"
  #define NAIPGP_PUBKEY_FILE		":test:pubring.pkr"
  #define NAIPGP_PRIVKEY_FILE		":test:secring.skr"
  #define PKCS12_FILE				":test:key.p12"

  #define CERT_FILE_TEMPLATE		":test:cert%d.der"
  #define BASE64CERT_FILE_TEMPLATE	":test:cert%d.asc"
  #define BROKEN_CERT_FILE			":test:certb.der"
  #define BROKEN_USER_CERT_FILE		":test:certbus.der"
  #define BROKEN_CA_CERT_FILE		":test:certbca.der"
  #define CERTREQ_FILE_TEMPLATE		":test:certreq%d.der"
  #define CRL_FILE_TEMPLATE			":test:crl%d.der"
  #define CERTCHAIN_FILE_TEMPLATE	":test:certchn%d.der"
  #define RTCS_OK_FILE				":test:rtcsrok.der"
  #define OCSP_OK_FILE				":test:ocsprok.der"
  #define OCSP_REV_FILE				":test:ocsprrev.der"
  #define OCSP_CA_FILE				":test:ocspca.der"
  #define CRLCERT_FILE_TEMPLATE		":test:crl_cert%d.der"
  #define CHAINCERT_FILE_TEMPLATE	":test:chn_cert%d.der"
  #define RTCS_FILE_TEMPLATE		":test:rtcs_ee%do.der"
  #define OCSP_CA_FILE_TEMPLATE		":test:ocsp_ca%d.der"
  #define OCSP_EEOK_FILE_TEMPLATE	":test:ocsp_ee%do.der"
  #define OCSP_EEREV_FILE_TEMPLATE	":test:ocsp_ee%dr.der"
  #define CMP_CA_FILE_TEMPLATE		":test:cmp_ca%d.der"
  #define SCEP_CA_FILE_TEMPLATE		":test:scep_ca%d.der"

  #define SMIME_SIG_FILE_TEMPLATE	":est:smime%d.p7s"
  #define SMIME_ENVELOPED_FILE		":test:smime.p7m"
  #define PGP_ENC_FILE_TEMPLATE		":test:enc%d.pgp"
  #define PGP_PKE_FILE_TEMPLATE		":test:enc_pk%d.pgp"
  #define OPENPGP_PKE_FILE_TEMPLATE	":test:enc_pk%d.gpg"
  #define PGP_SIG_FILE_TEMPLATE		":test:sig%d.pgp"
  #define PGP_COPR_FILE_TEMPLATE	":test:copr%d.pgp"

  #define COMPRESS_FILE				":test:test.h"
#elif defined( DDNAME_IO )
  #define TEST_PRIVKEY_FILE			"DD:CLBTEST"
  #define TEST_PRIVKEY_ALT_FILE		"DD:CLBTESTA"
  #define CA_PRIVKEY_FILE			"DD:CLBP15(KEYCA)"
  #define ICA_PRIVKEY_FILE			"DD:CLBP15(KEYICA)"
  #define SCEPCA_PRIVKEY_FILE		"DD:CLBP15(KEYSCA)"
  #define USER_PRIVKEY_FILE			"DD:CLBP15(KEYUSER)"
  #define DUAL_PRIVKEY_FILE			"DD:CLBP15(KEYDUAL)"
  #define RENEW_PRIVKEY_FILE		"DD:CLBP15(KEYREN)"
  #define BIG_PRIVKEY_FILE			"DD:CLBP15(KEYBIG)"
  #define CMP_PRIVKEY_FILE_TEMPLATE	"DD:CLBP15(KEYCMP%d)"
  #define PNP_PRIVKEY_FILE			"DD:CLBP15(KEYPNP)"
  #define SERVER_PRIVKEY_FILE		"DD:CLBP15(KEYSRV)"
  #define SSH_PRIVKEY_FILE			"DD:CLBP15(KEYSSH)"
  #define TSA_PRIVKEY_FILE			"DD:CLBP15(KEYTSA)"

  #define PGP_PUBKEY_FILE			"DD:CLBPGP(PUBRING)"
  #define PGP_PRIVKEY_FILE			"DD:CLBPGP(SECRING)"
  #define OPENPGP_PUBKEY_FILE		"DD:CLBGPG(PUBRING)"
  #define OPENPGP_PRIVKEY_FILE		"DD:CLBGPG(SECRING)"
  #define OPENPGP_PUBKEY_HASH_FILE	"DD:CLBGPG(PUBRINH)"
  #define OPENPGP_PRIVKEY_HASH_FILE	"DD:CLBGPG(SECRINH)"
  #define NAIPGP_PUBKEY_FILE		"DD:CLBPKR(PUBRING)"
  #define NAIPGP_PRIVKEY_FILE		"DD:CLBSKR(SECRING)"
  #define PKCS12_FILE				"DD:CLBP12(KEY)"

  #define CERT_FILE_TEMPLATE		"DD:CLBDER(CERT%d)"
  #define BASE64CERT_FILE_TEMPLATE	"DD:CLBDER(CERT%d)"
  #define BROKEN_CERT_FILE			"DD:CLBDER(CERTB)"
  #define BROKEN_USER_CERT_FILE		"DD:CLBDER(CERTBUS)"
  #define BROKEN_CA_CERT_FILE		"DD:CLBDER(CERTBCA)"
  #define CERTREQ_FILE_TEMPLATE		"DD:CLBDER(CERTREQ%d)"
  #define CRL_FILE_TEMPLATE			"DD:CLBDER(CRL%d)"
  #define CERTCHAIN_FILE_TEMPLATE	"DD:CLBDER(CERTCHN%d)"
  #define RTCS_OK_FILE				"DD:CLBDER(RTCSROK)"
  #define OCSP_OK_FILE				"DD:CLBDER(OCSPROK)"
  #define OCSP_REV_FILE				"DD:CLBDER(OCSPRREV)"
  #define OCSP_CA_FILE				"DD:CLBDER(OCSPCA)"
  #define CRLCERT_FILE_TEMPLATE		"DD:CLBDER(CRLCERT%d)"
  #define CHAINCERT_FILE_TEMPLATE	"DD:CLBDER(CHNCERT%d)"
  #define RTCS_FILE_TEMPLATE		"DD:CLBDER(RTCSEE%dO)"
  #define OCSP_CA_FILE_TEMPLATE		"DD:CLBDER(OCSPCA%d)"
  #define OCSP_EEOK_FILE_TEMPLATE	"DD:CLBDER(OCSPEE%dO)"
  #define OCSP_EEREV_FILE_TEMPLATE	"DD:CLBDER(OCSPEE%dR)"
  #define CMP_CA_FILE_TEMPLATE		"DD:CLBDER(CMPCA%d)"
  #define SCEP_CA_FILE_TEMPLATE		"DD:CLBDER(SCEPCA%d)"

  #define SMIME_SIG_FILE_TEMPLATE	"DD:CLBP7S(SMIME%d)"
  #define SMIME_ENVELOPED_FILE		"DD:CLBP7M(SMIME)"
  #define PGP_ENC_FILE_TEMPLATE		"DD:CLBPGP(ENC%d)"
  #define PGP_PKE_FILE_TEMPLATE		"DD:CLBPGP(ENCPK%d)"
  #define OPENPGP_PKE_FILE_TEMPLATE	"DD:CLBGPG(ENCPK%d)"
  #define PGP_SIG_FILE_TEMPLATE		"DD:CLBPGP(SIG%d)"
  #define PGP_COPR_FILE_TEMPLATE	"DD:CLBPGP(COPR%d)"

  #define COMPRESS_FILE				"DD:CLBCMP(TEST)"
#else
  #define TEST_PRIVKEY_FILE			"test/key_test.p15"
  #define TEST_PRIVKEY_ALT_FILE		"test/key_test.p12"
  #define CA_PRIVKEY_FILE			"test/key_ca.p15"
  #define ICA_PRIVKEY_FILE			"test/key_ica.p15"
  #define SCEPCA_PRIVKEY_FILE		"test/key_sca.p15"
  #define USER_PRIVKEY_FILE			"test/key_user.p15"
  #define DUAL_PRIVKEY_FILE			"test/key_dual.p15"
  #define RENEW_PRIVKEY_FILE		"test/key_ren.p15"
  #define BIG_PRIVKEY_FILE			"test/key_big.p15"
  #define CMP_PRIVKEY_FILE_TEMPLATE	"test/key_cmp%d.p15"
  #define PNP_PRIVKEY_FILE			"test/key_pnp.p15"
  #define SERVER_PRIVKEY_FILE		"test/key_srv.p15"
  #define SSH_PRIVKEY_FILE			"test/key_ssh.p15"
  #define TSA_PRIVKEY_FILE			"test/key_tsa.p15"

  #define PGP_PUBKEY_FILE			"test/pubring.pgp"
  #define PGP_PRIVKEY_FILE			"test/secring.pgp"
  #define OPENPGP_PUBKEY_FILE		"test/pubring.gpg"
  #define OPENPGP_PRIVKEY_FILE		"test/secring.gpg"
  #define OPENPGP_PUBKEY_HASH_FILE	"test/pubrinh.gpg"
  #define OPENPGP_PRIVKEY_HASH_FILE	"test/secrinh.gpg"
  #define NAIPGP_PUBKEY_FILE		"test/pubring.pkr"
  #define NAIPGP_PRIVKEY_FILE		"test/secring.skr"
  #define PKCS12_FILE				"test/key.p12"

  #define CERT_FILE_TEMPLATE		"test/cert%d.der"
  #define BASE64CERT_FILE_TEMPLATE	"test/cert%d.asc"
  #define BROKEN_CERT_FILE			"test/certb.der"
  #define BROKEN_USER_CERT_FILE		"test/certbus.der"
  #define BROKEN_CA_CERT_FILE		"test/certbca.der"
  #define CERTREQ_FILE_TEMPLATE		"test/certreq%d.der"
  #define CRL_FILE_TEMPLATE			"test/crl%d.der"
  #define CERTCHAIN_FILE_TEMPLATE	"test/certchn%d.der"
  #define RTCS_OK_FILE				"test/rtcsrok.der"
  #define OCSP_OK_FILE				"test/ocsprok.der"
  #define OCSP_REV_FILE				"test/ocsprrev.der"
  #define OCSP_CA_FILE				"test/ocspca.der"
  #define CRLCERT_FILE_TEMPLATE		"test/crl_cert%d.der"
  #define CHAINCERT_FILE_TEMPLATE	"test/chn_cert%d.der"
  #define RTCS_FILE_TEMPLATE		"test/rtcs_ee%do.der"
  #define OCSP_CA_FILE_TEMPLATE		"test/ocsp_ca%d.der"
  #define OCSP_EEOK_FILE_TEMPLATE	"test/ocsp_ee%do.der"
  #define OCSP_EEREV_FILE_TEMPLATE	"test/ocsp_ee%dr.der"
  #define CMP_CA_FILE_TEMPLATE		"test/cmp_ca%d.der"
  #define SCEP_CA_FILE_TEMPLATE		"test/scep_ca%d.der"

  #define SMIME_SIG_FILE_TEMPLATE	"test/smime%d.p7s"
  #define SMIME_ENVELOPED_FILE		"test/smime.p7m"
  #define PGP_ENC_FILE_TEMPLATE		"test/enc%d.pgp"
  #define PGP_PKE_FILE_TEMPLATE		"test/enc_pk%d.pgp"
  #define OPENPGP_PKE_FILE_TEMPLATE	"test/enc_pk%d.gpg"
  #define PGP_SIG_FILE_TEMPLATE		"test/sig%d.pgp"
  #define PGP_COPR_FILE_TEMPLATE	"test/copr%d.pgp"

  #define COMPRESS_FILE				"test/test.h"
#endif /* OS-specific naming */

/* Since the handling of filenames can get unwieldy when we have large
   numbers of similar files, we use a function to map a filename template
   and number into an actual filename rather the having to use huge
   numbers of defines */

#define filenameFromTemplate( buffer, fileTemplate, count ) \
		sprintf( buffer, fileTemplate, count )

/* When we're using common code to handle a variety of key file types for
   key read/encryption/signing tests, we need to distinguish between the
   different key files to use.  The following types are handled in the test
   code */

typedef enum { KEYFILE_X509, KEYFILE_PGP, KEYFILE_OPENPGP,
			   KEYFILE_OPENPGP_HASH, KEYFILE_NAIPGP } KEYFILE_TYPE;

/* The generic password for private keys */

#define TEST_PRIVKEY_PASSWORD	"test"

/* The database keyset type and name.  Under Windoze we use ODBC, for
   anything else we use the first database which is enabled by a preprocessor
   define, defaulting to an internal plugin (which doesn't have to be
   available, if it's not present we continue after printing a warning) */

#if defined( _MSC_VER )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_ODBC
  #define CERTSTORE_KEYSET_TYPE	CRYPT_KEYSET_ODBC_STORE
#elif defined( DBX_MYSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_DATABASE
  #define CERTSTORE_KEYSET_TYPE	CRYPT_KEYSET_DATABASE_STORE
#elif defined( DBX_PLUGIN )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_PLUGIN
  #define CERTSTORE_KEYSET_TYPE	CRYPT_KEYSET_PLUGIN_STORE
#else
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_DATABASE
  #define CERTSTORE_KEYSET_TYPE	CRYPT_KEYSET_DATABASE_STORE
#endif /* Various database backends */
#define DATABASE_KEYSET_NAME		"testkeys"
#define CERTSTORE_KEYSET_NAME		"testcertstore"
#define DATABASE_PLUGIN_KEYSET_NAME	"localhost:6500"

/* Some LDAP keyset names and names of probably-present certs and CRLs.
   These keysets (and their contents) come and go, so we have a variety of
   them and try them in turn until something works.  There's a list of more
   LDAP servers at http://www.dante.net/np/pdi.html, but none of these are
   known to contain certificates */

#define LDAP_KEYSET_NAME1		"ldap.diginotar.nl"
#define LDAP_CERT_NAME1			"cn=Root Certificaat Productie, "\
								"o=DigiNotar Root,c=NL"
#define LDAP_CRL_NAME1			"CN=CRL Productie,O=DigiNotar CRL,C=NL"
#define LDAP_KEYSET_NAME2		"ds.katalog.posten.se"
#define LDAP_CERT_NAME2			"cn=Posten CertPolicy_eIDKort_1 CA_nyckel_1, " \
								"o=Posten_Sverige_AB 556451-4148, c=SE"
#define LDAP_CRL_NAME2			"cn=Posten CertPolicy_eIDKort_1 CA_nyckel_1, " \
								"o=Posten_Sverige_AB 556451-4148, c=SE"

/* The HTTP keyset names (actually URLs for pages containing a cert and
   CRL) */

#define HTTP_KEYSET_CERT_NAME	"www.thawte.com/persfree.crt"
#define HTTP_KEYSET_CRL_NAME	"crl.verisign.com/Class1Individual.crl"
#define HTTP_KEYSET_HUGECRL_NAME "crl.verisign.com/RSASecureServer.crl"

/* Assorted default server names and authentication information, and the PKI
   SRV server (redirecting to mail.cryptoapps.com:8080).  There are so many
   TSP, OCSP, and CMP servers, and they never stay around for long, that we
   allow remapping in the functions where the secure session tests are
   performed */

#define SSH_USER_NAME			"test"
#define SSH_PASSWORD			"test"
#define SSL_USER_NAME			"test"
#define SSL_PASSWORD			"test"
#define PKI_SRV_NAME			"_pkiboot._tcp.cryptoapps.com"
#define TSP_DEFAULTSERVER_NAME	"http://www.edelweb.fr/cgi-bin/service-tsp"

/* Labels for the various public-key objects.  These are needed when the
   underlying implementation creates persistent objects (eg keys held in PKCS
   #11 tokens) that need to be identified */

#define RSA_PUBKEY_LABEL		"Test RSA public key"
#define RSA_PRIVKEY_LABEL		"Test RSA private key"
#define RSA_BIG_PRIVKEY_LABEL	"Test RSA big private key"
#define DSA_PUBKEY_LABEL		"Test DSA sigcheck key"
#define DSA_PRIVKEY_LABEL		"Test DSA signing key"
#define ELGAMAL_PUBKEY_LABEL	"Test Elgamal public key"
#define ELGAMAL_PRIVKEY_LABEL	"Test Elgamal private key"
#define DH_KEY1_LABEL			"Test DH key #1"
#define DH_KEY2_LABEL			"Test DH key #2"
#define CA_PRIVKEY_LABEL		RSA_PRIVKEY_LABEL
#define USER_PRIVKEY_LABEL		"Test user key"
#define USER_EMAIL				"dave@wetaburgers.com"
#define DUAL_SIGNKEY_LABEL		"Test signing key"
#define DUAL_ENCRYPTKEY_LABEL	"Test encryption key"
#define SSH_PRIVKEY_LABEL		"SSH host key"

/* A structure that allows us to specify a collection of extension
   components.  This is used when adding a collection of extensions to a
   cert */

typedef enum { IS_VOID, IS_NUMERIC, IS_STRING, IS_WCSTRING,
			   IS_TIME } COMPONENT_TYPE;

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE type;/* Extension component ID */
	const COMPONENT_TYPE componentType;	/* Component type */
	const int numericValue;			/* Value if numeric */
	const void *stringValue;		/* Value if string */
	const time_t timeValue;			/* Value if time */
	} CERT_DATA;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Prototypes for functions in certutil.c */

void printErrorAttributeInfo( const CRYPT_CERTIFICATE certificate );
int printCertInfo( const CRYPT_CERTIFICATE certificate );
int printCertChainInfo( const CRYPT_CERTIFICATE certChain );
void printExtError( const CRYPT_HANDLE cryptHandle,
					const char *functionName, const int functionStatus,
					const int lineNo );
int importCertFile( CRYPT_CERTIFICATE *cryptCert, const char *fileName );
int importCertFromTemplate( CRYPT_CERTIFICATE *cryptCert,
							const char *fileTemplate, const int number );
int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData );
int checkFileAccess( void );
int getPublicKey( CRYPT_CONTEXT *cryptContext, const char *keysetName,
				  const char *keyName );
int getPrivateKey( CRYPT_CONTEXT *cryptContext, const char *keysetName,
				   const char *keyName, const char *password );
void debugDump( const char *fileName, const void *data,
				const int dataLength );

/* Exit with an error message, in certutil.c.  attrErrorExit() prints the
   locus and type, extErrorExit() prints the extended error code and
   message */

BOOLEAN attrErrorExit( const CRYPT_HANDLE cryptHandle,
					   const char *functionName, const int errorCode,
					   const int lineNumber );
BOOLEAN extErrorExit( const CRYPT_HANDLE cryptHandle,
					  const char *functionName, const int errorCode,
					  const int lineNumber );

/* Prototypes for functions in testcert.c */

BOOLEAN certErrorExit( const CRYPT_HANDLE cryptHandle,
					   const char *functionName, const int errorCode,
					   const int lineNumber );

/* Prototypes for functions in testlib.c */

#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS ) || defined( OS2_THREADS )
  void delayThread( const int seconds );
#else
  #define delayThread( x )
#endif /* Systems with threading support */
CRYPT_ALGO_TYPE selectCipher( const CRYPT_ALGO_TYPE algorithm );

/* Prototypes for functions in testll.c */

BOOLEAN loadRSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *cryptContext,
						   CRYPT_CONTEXT *decryptContext,
						   const char *cryptContextLabel,
						   const char *decryptContextLabel );
BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadDSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *signContext,
						   CRYPT_CONTEXT *sigCheckContext,
						   const char *signContextLabel,
						   const char *sigCheckContextLabel );
BOOLEAN loadDSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext );
BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize );
void destroyContexts( const CRYPT_DEVICE cryptDevice,
					  CRYPT_CONTEXT cryptContext,
					  CRYPT_CONTEXT decryptContext );
int testLowlevel( const CRYPT_DEVICE cryptDevice,
				  const CRYPT_ALGO_TYPE cryptAlgo,
				  const BOOLEAN checkOnly );
int testCrypt( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext,
			   BYTE *buffer, const BOOLEAN isDevice,
			   const BOOLEAN noWarnFail );

/* Prototypes for functions in testkey.c */

const char *getKeyfileName( const KEYFILE_TYPE type,
							const BOOLEAN isPrivKey );
const char *getKeyfilePassword( const KEYFILE_TYPE type );
const char *getKeyfileUserID( const KEYFILE_TYPE type );

/* Prototypes for functions in testenv.c */

int testCMSEnvelopeSignEx( const CRYPT_CONTEXT signContext );
int testCMSEnvelopePKCCryptEx( const CRYPT_HANDLE encryptContext,
							   const CRYPT_HANDLE decryptKeyset,
							   const char *password );

/* Prototypes for functions in testsess.c */

int testSessionTSPServerEx( const CRYPT_CONTEXT privKeyContext );

/****************************************************************************
*																			*
*								Test Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in testhl.c */

int testLargeBufferEncrypt( void );
int testDeriveKey( void );
int testRandomRoutines( void );
int testConventionalExportImport( void );
int testMACExportImport( void );
int testKeyExportImport( void );
int testSignData( void );
int testKeyAgreement( void );
int testKeygen( void );
int testKeygenAsync( void );
int testKeyExportImportCMS( void );
int testSignDataCMS( void );

/* Prototypes for functions in testdev.c */

int testDevices( void );
int testUser( void );

/* Prototypes for functions in testkey.c */

int testGetPGPPublicKey( void );
int testGetPGPPrivateKey( void );
int testGetBorkenKey( void );
int testReadWriteFileKey( void );
int testWriteAltFileKey( void );
int testReadBigFileKey( void );
int testReadFilePublicKey( void );
int testAddTrustedCert( void );
int testAddGloballyTrustedCert( void );
int testDeleteFileKey( void );
int testChangeFileKeyPassword( void );
int testUpdateFileCert( void );
int testWriteFileCertChain( void );
int testWriteFileLongCertChain( void );
int testReadFileCert( void );
int testReadFileCertPrivkey( void );
int testReadFileCertChain( void );
int testSingleStepFileCert( void );
int testSingleStepAltFileCert( void );
int testDoubleCertFile( void );
int testRenewedCertFile( void );
int testWriteCert( void );
int testReadCert( void );
int testKeysetQuery( void );
int testWriteCertDbx( void );
int testWriteCertLDAP( void );
int testReadCertLDAP( void );
int testReadCertURL( void );
int testReadCertHTTP( void );

/* Prototypes for functions in testenv.c */

int testEnvelopeData( void );
int testEnvelopeDataLargeBuffer( void );
int testEnvelopeCompress( void );
int testEnvelopeCompressedDataImport( void );
int testEnvelopeSessionCrypt( void );
int testEnvelopeSessionCryptLargeBuffer( void );
int testEnvelopeCrypt( void );
int testEnvelopePasswordCrypt( void );
int testEnvelopePasswordCryptImport( void );
int testEnvelopePKCCrypt( void );
int testEnvelopePKCCryptImport( void );
int testEnvelopeSign( void );
int testEnvelopeSignOverflow( void );
int testEnvelopeSignedDataImport( void );
int testEnvelopeAuthenticate( void );
int testCMSEnvelopePKCCrypt( void );
int testCMSEnvelopePKCCryptDoubleCert( void );
int testCMSEnvelopeSign( void );
int testCMSEnvelopeDualSign( void );
int testCMSEnvelopeDetachedSig( void );
int testCMSEnvelopeSignedDataImport( void );

/* Prototypes for functions in testcert.c */

int testCert( void );
int testCACert( void );
int testXyzzyCert( void );
int testTextStringCert( void );
int testComplexCert( void );
int testCertExtension( void );
int testCustomDNCert( void );
int testSETCert( void );
int testAttributeCert( void );
int testCRL( void );
int testComplexCRL( void );
int testCertChain( void );
int testCertRequest( void );
int testComplexCertRequest( void );
int testCRMFRequest( void );
int testComplexCRMFRequest( void );
int testRevRequest( void );
int testCMSAttributes( void );
int testRTCSReqResp( void );
int testOCSPReqResp( void );
int testPKIUser( void );
int testCertImport( void );
int testCertReqImport( void );
int testCRLImport( void );
int testCertChainImport( void );
int testOCSPImport( void );
int testBase64CertImport( void );
int testCertComplianceLevel( void );
int testCertProcess( void );
int testCertManagement( void );

/* Prototypes for functions in testsess.c (the last one is actually in with
   the enveloping code because the only way to fully exercise the TS
   functionality is by using it to timestamp an S/MIME signature) */

int testSessionUrlParse( void );
int testSessionSSHv1( void );
int testSessionSSHv2( void );
int testSessionSSHClientCert( void );
int testSessionSSH_SFTP( void );
int testSessionSSHv1Server( void );
int testSessionSSHv2Server( void );
int testSessionSSH_SFTPServer( void );
int testSessionSSL( void );
int testSessionSSLLocalSocket( void );
int testSessionSSLClientCert( void );
int testSessionSSLSharedKey( void );
int testSessionSSLServer( void );
int testSessionSSLServerCached( void );
int testSessionSSLServerClientCert( void );
int testSessionTLS( void );
int testSessionTLSServer( void );
int testSessionTLSServerSharedKey( void );
int testSessionTLS11( void );
int testSessionTLS11Server( void );
int testSessionRTCS( void );
int testSessionRTCSServer( void );
int testSessionOCSP( void );
int testSessionOCSPServer( void );
int testSessionTSP( void );
int testSessionTSPServer( void );
int testSessionSCEP( void );
int testSessionSCEPServer( void );
int testSessionCMP( void );
int testSessionCMPServer( void );
int testSessionPNPPKI( void );
int testSessionEnvTSP( void );

/* Functions to test local client/server sessions.  These require threading
   support since they run the client and server in different threads */

#ifdef WINDOWS_THREADS
  int testSessionSSHv1ClientServer( void );
  int testSessionSSHv2ClientServer( void );
  int testSessionSSHClientServerFingerprint( void );
  int testSessionSSHClientServerSFTP( void );
  int testSessionSSHClientServerPortForward( void );
  int testSessionSSLClientServer( void );
  int testSessionSSLClientCertClientServer( void );
  int testSessionTLSClientServer( void );
  int testSessionTLSSharedKeyClientServer( void );
  int testSessionTLSBulkTransferClientServer( void );
  int testSessionTLS11ClientServer( void );
  int testSessionRTCSClientServer( void );
  int testSessionOCSPClientServer( void );
  int testSessionTSPClientServer( void );
  int testSessionTSPClientServerPersistent( void );
  int testSessionSCEPClientServer( void );
  int testSessionCMPClientServer( void );
  int testSessionCMPPKIBootClientServer( void );
  int testSessionPNPPKIClientServer( void );
#else
  #define testSessionSSHv1ClientServer()			TRUE
  #define testSessionSSHv2ClientServer()			TRUE
  #define testSessionSSHClientServerFingerprint()	TRUE
  #define testSessionSSHClientServerSFTP()			TRUE
  #define testSessionSSHClientServerPortForward()	TRUE
  #define testSessionSSLClientServer()				TRUE
  #define testSessionSSLClientCertClientServer()	TRUE
  #define testSessionTLSClientServer()				TRUE
  #define testSessionTLSSharedKeyClientServer()		TRUE
  #define testSessionTLSBulkTransferClientServer()	TRUE
  #define testSessionTLS11ClientServer()			TRUE
  #define testSessionRTCSClientServer()				TRUE
  #define testSessionOCSPClientServer()				TRUE
  #define testSessionTSPClientServer()				TRUE
  #define testSessionTSPClientServerPersistent()	TRUE
  #define testSessionSCEPClientServer()				TRUE
  #define testSessionCMPClientServer()				TRUE
  #define testSessionCMPPKIBootClientServer()		TRUE
  #define testSessionPNPPKIClientServer()			TRUE
#endif /* WINDOWS_THREADS */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* IBM big iron */
