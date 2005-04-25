/****************************************************************************
*																			*
*						cryptlib Test Data Filenames						*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

/* The names of the test key and certificate files.  For flat filesystems we
   give the test files names starting with 'z' so they're easier to find */

/****************************************************************************
*																			*
*									AS/400									*
*																			*
****************************************************************************/

#if defined( __OS400__ )

#define TEST_PRIVKEY_FILE			"testlib/zkeytest"
#define TEST_PRIVKEY_ALT_FILE		"testlib/zkeytsta"
#define CA_PRIVKEY_FILE				"testlib/zkeyca"
#define ICA_PRIVKEY_FILE			"testlib/zkeyica"
#define SCEPCA_PRIVKEY_FILE			"testlib/zkeysca"
#define USER_PRIVKEY_FILE			"testlib/zkeyuser"
#define DUAL_PRIVKEY_FILE			"testlib/zkeydual"
#define RENEW_PRIVKEY_FILE			"testlib/zkeyren"
#define BIG_PRIVKEY_FILE			"testlib/zkeybig"
#define CMP_PRIVKEY_FILE_TEMPLATE	"testlib/zkeycmp"
#define PNP_PRIVKEY_FILE			"testlib/zkeypnp"
#define PNPCA_PRIVKEY_FILE			"testlib/zkeypnpc"
#define SERVER_PRIVKEY_FILE			"testlib/zkeysrv"
#define SSH_PRIVKEY_FILE			"testlib/zkeyssh"
#define TSA_PRIVKEY_FILE			"testlib/zkeytsa"

#define PGP_PUBKEY_FILE				"testlib/zpubring"
#define PGP_PRIVKEY_FILE			"testlib/zsecring"
#define OPENPGP_PUBKEY_FILE			"testlib/zpubringg"
#define OPENPGP_PRIVKEY_FILE		"testlib/zsecringg"
#define OPENPGP_PUBKEY_HASH_FILE	"testlib/zpubrinhg"
#define OPENPGP_PRIVKEY_HASH_FILE	"testlib/zsecrinhg"
#define OPENPGP_PUBKEY_AES_FILE		"testlib/zpubrinap"
#define OPENPGP_PRIVKEY_AES_FILE	"testlib/zsecrinas"
#define NAIPGP_PUBKEY_FILE			"testlib/zpubringp"
#define NAIPGP_PRIVKEY_FILE			"testlib/zsecrings"
#define PKCS12_FILE					"testlib/zkey"

#define CERT_FILE_TEMPLATE			"testlib/zcert%d"
#define BASE64CERT_FILE_TEMPLATE	"testlib/zcerta%d"
#define BROKEN_CERT_FILE			"testlib/zcertb"
#define BROKEN_USER_CERT_FILE		"testlib/zcertbus"
#define BROKEN_CA_CERT_FILE			"testlib/zcertbca"
#define CERTREQ_FILE_TEMPLATE		"testlib/zcertreq%d"
#define CRL_FILE_TEMPLATE			"testlib/zcrl%d"
#define CERTCHAIN_FILE_TEMPLATE		"testlib/zcertchn%d"
#define BASE64CERTCHAIN_FILE_TEMPLATE "testlib/zcertcha%d"
#define PATHTEST_FILE_TEMPLATE		"testlib/zntest%d"
#define SSHKEY_FILE_TEMPLATE		"testlib/zsshkey%d"
#define PGPKEY_FILE_TEMPLATE		"testlib/zpgpkey%d"
#define RTCS_OK_FILE				"testlib/zrtcsrok"
#define OCSP_OK_FILE				"testlib/zocsprok"
#define OCSP_REV_FILE				"testlib/zocsprrev"
#define OCSP_CA_FILE				"testlib/zocspca"
#define CRLCERT_FILE_TEMPLATE		"testlib/zcrlcrt%d"
#define CHAINCERT_FILE_TEMPLATE		"testlib/zchncrt%d"
#define RTCS_FILE_TEMPLATE			"testlib/zrtcsee%do"
#define OCSP_CA_FILE_TEMPLATE		"testlib/zocspca%d"
#define OCSP_EEOK_FILE_TEMPLATE		"testlib/zocspee%do"
#define OCSP_EEREV_FILE_TEMPLATE	"testlib/zocspee%dr"
#define CMP_CA_FILE_TEMPLATE		"testlib/zcmpca%d"
#define SCEP_CA_FILE_TEMPLATE		"testlib/zscepca%d"

#define SMIME_SIG_FILE_TEMPLATE		"testlib/zsmime%d"
#define SMIME_ENVELOPED_FILE		"testlib/zsmimem"
#define PGP_ENC_FILE_TEMPLATE		"testlib/zenc%d"
#define PGP_PKE_FILE_TEMPLATE		"testlib/zenc_pkp%d"
#define OPENPGP_PKE_FILE_TEMPLATE	"testlib/enc_pkg%d"
#define PGP_SIG_FILE_TEMPLATE		"testlib/zsig%d"
#define PGP_COPR_FILE_TEMPLATE		"testlib/zcopr%d"

#define COMPRESS_FILE				"test/filename"

/****************************************************************************
*																			*
*							Macintosh pre-OS X								*
*																			*
****************************************************************************/

#elif defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )

#define TEST_PRIVKEY_FILE			":testdata:key_test.p15"
#define TEST_PRIVKEY_ALT_FILE		":testdata:key_test.p12"
#define CA_PRIVKEY_FILE				":testdata:key_ca.p15"
#define ICA_PRIVKEY_FILE			":testdata:key_ica.p15"
#define SCEPCA_PRIVKEY_FILE			":testdata:key_sca.p15"
#define USER_PRIVKEY_FILE			":testdata:key_user.p15"
#define DUAL_PRIVKEY_FILE			":testdata:key_dual.p15"
#define RENEW_PRIVKEY_FILE			":testdata:key_ren.p15"
#define BIG_PRIVKEY_FILE			":testdata:key_big.p15"
#define CMP_PRIVKEY_FILE_TEMPLATE	":testdata:key_cmp%d.p15"
#define PNP_PRIVKEY_FILE			":testdata:key_pnp.p15"
#define PNPCA_PRIVKEY_FILE			":testdata:key_pnpca.p15"
#define SERVER_PRIVKEY_FILE			":testdata:key_srv.p15"
#define SSH_PRIVKEY_FILE			":testdata:key_ssh.p15"
#define TSA_PRIVKEY_FILE			":testdata:key_tsa.p15"

#define PGP_PUBKEY_FILE				":testdata:pubring.pgp"
#define PGP_PRIVKEY_FILE			":testdata:secring.pgp"
#define OPENPGP_PUBKEY_FILE			":testdata:pubring.gpg"
#define OPENPGP_PRIVKEY_FILE		":testdata:secring.gpg"
#define OPENPGP_PUBKEY_HASH_FILE	":testdata:pubrinh.gpg"
#define OPENPGP_PRIVKEY_HASH_FILE	":testdata:secrinh.gpg"
#define OPENPGP_PUBKEY_AES_FILE		":testdata:pubrina.pkr"
#define OPENPGP_PRIVKEY_AES_FILE	":testdata:secrina.skr"
#define NAIPGP_PUBKEY_FILE			":testdata:pubring.pkr"
#define NAIPGP_PRIVKEY_FILE			":testdata:secring.skr"
#define PKCS12_FILE					":testdata:key.p12"

#define CERT_FILE_TEMPLATE			":testdata:cert%d.der"
#define BASE64CERT_FILE_TEMPLATE	":testdata:cert%d.asc"
#define BROKEN_CERT_FILE			":testdata:certb.der"
#define BROKEN_USER_CERT_FILE		":testdata:certbus.der"
#define BROKEN_CA_CERT_FILE			":testdata:certbca.der"
#define CERTREQ_FILE_TEMPLATE		":testdata:certreq%d.der"
#define CRL_FILE_TEMPLATE			":testdata:crl%d.crl"
#define CERTCHAIN_FILE_TEMPLATE		":testdata:certchn%d.der"
#define BASE64CERTCHAIN_FILE_TEMPLATE ":testdata:certchn%d.asc"
#define PATHTEST_FILE_TEMPLATE		":testdata:ntest%d.p7s"
#define SSHKEY_FILE_TEMPLATE		":testdata:sshkey%d.asc"
#define PGPKEY_FILE_TEMPLATE		":testdata:pgpkey%d.asc"
#define RTCS_OK_FILE				":testdata:rtcsrok.der"
#define OCSP_OK_FILE				":testdata:ocsprok.der"
#define OCSP_REV_FILE				":testdata:ocsprrev.der"
#define OCSP_CA_FILE				":testdata:ocspca.der"
#define CRLCERT_FILE_TEMPLATE		":testdata:crl_cert%d.der"
#define CHAINCERT_FILE_TEMPLATE		":testdata:chn_cert%d.der"
#define RTCS_FILE_TEMPLATE			":testdata:rtcs_ee%do.der"
#define OCSP_CA_FILE_TEMPLATE		":testdata:ocsp_ca%d.der"
#define OCSP_EEOK_FILE_TEMPLATE		":testdata:ocsp_ee%do.der"
#define OCSP_EEREV_FILE_TEMPLATE	":testdata:ocsp_ee%dr.der"
#define CMP_CA_FILE_TEMPLATE		":testdata:cmp_ca%d.der"
#define SCEP_CA_FILE_TEMPLATE		":testdata:scep_ca%d.der"

#define SMIME_SIG_FILE_TEMPLATE		":testdata:smime%d.p7s"
#define SMIME_ENVELOPED_FILE		":testdata:smime.p7m"
#define PGP_ENC_FILE_TEMPLATE		":testdata:enc%d.pgp"
#define PGP_PKE_FILE_TEMPLATE		":testdata:enc_pk%d.pgp"
#define OPENPGP_PKE_FILE_TEMPLATE	":testdata:enc_pk%d.gpg"
#define PGP_SIG_FILE_TEMPLATE		":testdata:sig%d.pgp"
#define PGP_COPR_FILE_TEMPLATE		":testdata:copr%d.pgp"

#define COMPRESS_FILE				":test:filename.h"

/****************************************************************************
*																			*
*							MVS with DDNAME I/O								*
*																			*
****************************************************************************/

#elif defined( DDNAME_IO )

#define TEST_PRIVKEY_FILE			"DD:CLBTEST"
#define TEST_PRIVKEY_ALT_FILE		"DD:CLBTESTA"
#define CA_PRIVKEY_FILE				"DD:CLBP15(KEYCA)"
#define ICA_PRIVKEY_FILE			"DD:CLBP15(KEYICA)"
#define SCEPCA_PRIVKEY_FILE			"DD:CLBP15(KEYSCA)"
#define USER_PRIVKEY_FILE			"DD:CLBP15(KEYUSER)"
#define DUAL_PRIVKEY_FILE			"DD:CLBP15(KEYDUAL)"
#define RENEW_PRIVKEY_FILE			"DD:CLBP15(KEYREN)"
#define BIG_PRIVKEY_FILE			"DD:CLBP15(KEYBIG)"
#define CMP_PRIVKEY_FILE_TEMPLATE	"DD:CLBP15(KEYCMP%d)"
#define PNP_PRIVKEY_FILE			"DD:CLBP15(KEYPNP)"
#define PNPCA_PRIVKEY_FILE			"DD:CLBP15(KEYPNPC)"
#define SERVER_PRIVKEY_FILE			"DD:CLBP15(KEYSRV)"
#define SSH_PRIVKEY_FILE			"DD:CLBP15(KEYSSH)"
#define TSA_PRIVKEY_FILE			"DD:CLBP15(KEYTSA)"

#define PGP_PUBKEY_FILE				"DD:CLBPGP(PUBRING)"
#define PGP_PRIVKEY_FILE			"DD:CLBPGP(SECRING)"
#define OPENPGP_PUBKEY_FILE			"DD:CLBGPG(PUBRING)"
#define OPENPGP_PRIVKEY_FILE		"DD:CLBGPG(SECRING)"
#define OPENPGP_PUBKEY_HASH_FILE	"DD:CLBGPG(PUBRINH)"
#define OPENPGP_PRIVKEY_HASH_FILE	"DD:CLBGPG(SECRINH)"
#define OPENPGP_PUBKEY_AES_FILE		"DD:CLBPKR(PUBRINA)"
#define OPENPGP_PRIVKEY_AES_FILE	"DD:CLBSKR(SECRINA)"
#define NAIPGP_PUBKEY_FILE			"DD:CLBPKR(PUBRING)"
#define NAIPGP_PRIVKEY_FILE			"DD:CLBSKR(SECRING)"
#define PKCS12_FILE					"DD:CLBP12(KEY)"

#define CERT_FILE_TEMPLATE			"DD:CLBDER(CERT%d)"
#define BASE64CERT_FILE_TEMPLATE	"DD:CLBDER(CERT%d)"
#define BROKEN_CERT_FILE			"DD:CLBDER(CERTB)"
#define BROKEN_USER_CERT_FILE		"DD:CLBDER(CERTBUS)"
#define BROKEN_CA_CERT_FILE			"DD:CLBDER(CERTBCA)"
#define CERTREQ_FILE_TEMPLATE		"DD:CLBDER(CERTREQ%d)"
#define CRL_FILE_TEMPLATE			"DD:CLBDER(CRL%d)"
#define CERTCHAIN_FILE_TEMPLATE		"DD:CLBDER(CERTCHN%d)"
#define BASE64CERTCHAIN_FILE_TEMPLATE "DD:CLBDER(CERT%d)"
#define PATHTEST_FILE_TEMPLATE		"DD:CLBDER(NTEST%d)"
#define SSHKEY_FILE_TEMPLATE		"DD:CLBDER(SSHKEY%d)"
#define PGPKEY_FILE_TEMPLATE		"DD:CLBDER(PGPKEY%d)"
#define RTCS_OK_FILE				"DD:CLBDER(RTCSROK)"
#define OCSP_OK_FILE				"DD:CLBDER(OCSPROK)"
#define OCSP_REV_FILE				"DD:CLBDER(OCSPRREV)"
#define OCSP_CA_FILE				"DD:CLBDER(OCSPCA)"
#define CRLCERT_FILE_TEMPLATE		"DD:CLBDER(CRLCERT%d)"
#define CHAINCERT_FILE_TEMPLATE		"DD:CLBDER(CHNCERT%d)"
#define RTCS_FILE_TEMPLATE			"DD:CLBDER(RTCSEE%dO)"
#define OCSP_CA_FILE_TEMPLATE		"DD:CLBDER(OCSPCA%d)"
#define OCSP_EEOK_FILE_TEMPLATE		"DD:CLBDER(OCSPEE%dO)"
#define OCSP_EEREV_FILE_TEMPLATE	"DD:CLBDER(OCSPEE%dR)"
#define CMP_CA_FILE_TEMPLATE		"DD:CLBDER(CMPCA%d)"
#define SCEP_CA_FILE_TEMPLATE		"DD:CLBDER(SCEPCA%d)"

#define SMIME_SIG_FILE_TEMPLATE		"DD:CLBP7S(SMIME%d)"
#define SMIME_ENVELOPED_FILE		"DD:CLBP7M(SMIME)"
#define PGP_ENC_FILE_TEMPLATE		"DD:CLBPGP(ENC%d)"
#define PGP_PKE_FILE_TEMPLATE		"DD:CLBPGP(ENCPK%d)"
#define OPENPGP_PKE_FILE_TEMPLATE	"DD:CLBGPG(ENCPK%d)"
#define PGP_SIG_FILE_TEMPLATE		"DD:CLBPGP(SIG%d)"
#define PGP_COPR_FILE_TEMPLATE		"DD:CLBPGP(COPR%d)"

#define COMPRESS_FILE				"DD:CLBCMP(FILENAME)"

/****************************************************************************
*																			*
*									VM/CMS									*
*																			*
****************************************************************************/

#elif defined( __VMCMS__ )

#define TEST_PRIVKEY_FILE			"zkeytest.p15"
#define TEST_PRIVKEY_ALT_FILE		"zkeytest.p12"
#define CA_PRIVKEY_FILE				"zkeyca.p15"
#define ICA_PRIVKEY_FILE			"zkeyica.p15"
#define SCEPCA_PRIVKEY_FILE			"zkeysca.p15"
#define USER_PRIVKEY_FILE			"zkeyuser.p15"
#define DUAL_PRIVKEY_FILE			"zkeydual.p15"
#define RENEW_PRIVKEY_FILE			"zkeyren.p15"
#define BIG_PRIVKEY_FILE			"zkeybig.p15"
#define CMP_PRIVKEY_FILE_TEMPLATE	"zkeycmp.p15"
#define PNP_PRIVKEY_FILE			"zkeypnp.p15"
#define PNPCA_PRIVKEY_FILE			"zkeypnpc.p15"
#define SERVER_PRIVKEY_FILE			"zkeysrv.p15"
#define SSH_PRIVKEY_FILE			"zkeyssh.p15"
#define TSA_PRIVKEY_FILE			"zkeytsa.p15"

#define PGP_PUBKEY_FILE				"zpubring.pgp"
#define PGP_PRIVKEY_FILE			"zsecring.pgp"
#define OPENPGP_PUBKEY_FILE			"zpubring.gpg"
#define OPENPGP_PRIVKEY_FILE		"zsecring.gpg"
#define OPENPGP_PUBKEY_HASH_FILE	"zpubrinh.gpg"
#define OPENPGP_PRIVKEY_HASH_FILE	"zsecrinh.gpg"
#define OPENPGP_PUBKEY_AES_FILE		"zpubrina.pkr"
#define OPENPGP_PRIVKEY_AES_FILE	"zsecrina.skr"
#define NAIPGP_PUBKEY_FILE			"zpubring.pkr"
#define NAIPGP_PRIVKEY_FILE			"zsecring.skr"
#define PKCS12_FILE					"zkey.p12"

#define CERT_FILE_TEMPLATE			"zcert%d.der"
#define BASE64CERT_FILE_TEMPLATE	"zcert%d.asc"
#define BROKEN_CERT_FILE			"zcertb.der"
#define BROKEN_USER_CERT_FILE		"zcertbus.der"
#define BROKEN_CA_CERT_FILE			"zcertbca.der"
#define CERTREQ_FILE_TEMPLATE		"zcertreq%d.der"
#define CRL_FILE_TEMPLATE			"zcrl%d.crl"
#define CERTCHAIN_FILE_TEMPLATE		"zcertchn%d.der"
#define BASE64CERTCHAIN_FILE_TEMPLATE "zcertchn%d.asc"
#define PATHTEST_FILE_TEMPLATE		"zntest%d.p7s"
#define SSHKEY_FILE_TEMPLATE		"zsshkey%d.asc"
#define PGPKEY_FILE_TEMPLATE		"zpgpkey%d.asc"
#define RTCS_OK_FILE				"zrtcsrok.der"
#define OCSP_OK_FILE				"zocsprok.der"
#define OCSP_REV_FILE				"zocsprrev.der"
#define OCSP_CA_FILE				"zocspca.der"
#define CRLCERT_FILE_TEMPLATE		"zcrlcrt%d.der"
#define CHAINCERT_FILE_TEMPLATE		"zchncrt%d.der"
#define RTCS_FILE_TEMPLATE			"zrtcsee%do.der"
#define OCSP_CA_FILE_TEMPLATE		"zocspca%d.der"
#define OCSP_EEOK_FILE_TEMPLATE		"zocspee%do.der"
#define OCSP_EEREV_FILE_TEMPLATE	"zocspee%dr.der"
#define CMP_CA_FILE_TEMPLATE		"zcmpca%d.der"
#define SCEP_CA_FILE_TEMPLATE		"zscepca%d.der"

#define SMIME_SIG_FILE_TEMPLATE		"zsmime%d.p7s"
#define SMIME_ENVELOPED_FILE		"zsmime.p7m"
#define PGP_ENC_FILE_TEMPLATE		"zenc%d.pgp"
#define PGP_PKE_FILE_TEMPLATE		"zenc_pk%d.pgp"
#define OPENPGP_PKE_FILE_TEMPLATE	"zenc_pk%d.gpg"
#define PGP_SIG_FILE_TEMPLATE		"zsig%d.pgp"
#define PGP_COPR_FILE_TEMPLATE		"zcopr%d.pgp"

#define COMPRESS_FILE				"filename.h"

/****************************************************************************
*																			*
*									Windows CE								*
*																			*
****************************************************************************/

#elif defined( _WIN32_WCE )

#define TEST_PRIVKEY_FILE			L"\\Storage Card\\key_test.p15"
#define TEST_PRIVKEY_ALT_FILE		L"\\Storage Card\\key_test.p12"
#define CA_PRIVKEY_FILE				L"\\Storage Card\\key_ca.p15"
#define ICA_PRIVKEY_FILE			L"\\Storage Card\\key_ica.p15"
#define SCEPCA_PRIVKEY_FILE			L"\\Storage Card\\key_sca.p15"
#define USER_PRIVKEY_FILE			L"\\Storage Card\\key_user.p15"
#define DUAL_PRIVKEY_FILE			L"\\Storage Card\\key_dual.p15"
#define RENEW_PRIVKEY_FILE			L"\\Storage Card\\key_ren.p15"
#define BIG_PRIVKEY_FILE			L"\\Storage Card\\key_big.p15"
#define CMP_PRIVKEY_FILE_TEMPLATE	L"\\Storage Card\\key_cmp%d.p15"
#define PNP_PRIVKEY_FILE			L"\\Storage Card\\key_pnp.p15"
#define PNPCA_PRIVKEY_FILE			L"\\Storage Card\\key_pnpca.p15"
#define SERVER_PRIVKEY_FILE			L"\\Storage Card\\key_srv.p15"
#define SSH_PRIVKEY_FILE			L"\\Storage Card\\key_ssh.p15"
#define TSA_PRIVKEY_FILE			L"\\Storage Card\\key_tsa.p15"

#define PGP_PUBKEY_FILE				L"\\Storage Card\\pubring.pgp"
#define PGP_PRIVKEY_FILE			L"\\Storage Card\\secring.pgp"
#define OPENPGP_PUBKEY_FILE			L"\\Storage Card\\pubring.gpg"
#define OPENPGP_PRIVKEY_FILE		L"\\Storage Card\\secring.gpg"
#define OPENPGP_PUBKEY_HASH_FILE	L"\\Storage Card\\pubrinh.gpg"
#define OPENPGP_PRIVKEY_HASH_FILE	L"\\Storage Card\\secrinh.gpg"
#define OPENPGP_PUBKEY_AES_FILE		L"\\Storage Card\\pubrina.pkr"
#define OPENPGP_PRIVKEY_AES_FILE	L"\\Storage Card\\secrina.skr"
#define NAIPGP_PUBKEY_FILE			L"\\Storage Card\\pubring.pkr"
#define NAIPGP_PRIVKEY_FILE			L"\\Storage Card\\secring.skr"
#define PKCS12_FILE					L"\\Storage Card\\key.p12"

#define CERT_FILE_TEMPLATE			L"\\Storage Card\\cert%d.der"
#define BASE64CERT_FILE_TEMPLATE	L"\\Storage Card\\cert%d.asc"
#define BROKEN_CERT_FILE			L"\\Storage Card\\certb.der"
#define BROKEN_USER_CERT_FILE		L"\\Storage Card\\certbus.der"
#define BROKEN_CA_CERT_FILE			L"\\Storage Card\\certbca.der"
#define CERTREQ_FILE_TEMPLATE		L"\\Storage Card\\certreq%d.der"
#define CRL_FILE_TEMPLATE			L"\\Storage Card\\crl%d.crl"
#define CERTCHAIN_FILE_TEMPLATE		L"\\Storage Card\\certchn%d.der"
#define BASE64CERTCHAIN_FILE_TEMPLATE L"\\Storage Card\\certchn%d.asc"
#define PATHTEST_FILE_TEMPLATE		L"\\Storage Card\\ntest%d.p7s"
#define SSHKEY_FILE_TEMPLATE		L"\\Storage Card\\sshkey%d.asc"
#define PGPKEY_FILE_TEMPLATE		L"\\Storage Card\\pgpkey%d.asc"
#define RTCS_OK_FILE				L"\\Storage Card\\rtcsrok.der"
#define OCSP_OK_FILE				L"\\Storage Card\\ocsprok.der"
#define OCSP_REV_FILE				L"\\Storage Card\\ocsprrev.der"
#define OCSP_CA_FILE				L"\\Storage Card\\ocspca.der"
#define CRLCERT_FILE_TEMPLATE		L"\\Storage Card\\crl_cert%d.der"
#define CHAINCERT_FILE_TEMPLATE		L"\\Storage Card\\chn_cert%d.der"
#define RTCS_FILE_TEMPLATE			L"\\Storage Card\\rtcs_ee%do.der"
#define OCSP_CA_FILE_TEMPLATE		L"\\Storage Card\\ocsp_ca%d.der"
#define OCSP_EEOK_FILE_TEMPLATE		L"\\Storage Card\\ocsp_ee%do.der"
#define OCSP_EEREV_FILE_TEMPLATE	L"\\Storage Card\\ocsp_ee%dr.der"
#define CMP_CA_FILE_TEMPLATE		L"\\Storage Card\\cmp_ca%d.der"
#define SCEP_CA_FILE_TEMPLATE		L"\\Storage Card\\scep_ca%d.der"

#define SMIME_SIG_FILE_TEMPLATE		L"\\Storage Card\\smime%d.p7s"
#define SMIME_ENVELOPED_FILE		L"\\Storage Card\\smime.p7m"
#define PGP_ENC_FILE_TEMPLATE		L"\\Storage Card\\enc%d.pgp"
#define PGP_PKE_FILE_TEMPLATE		L"\\Storage Card\\enc_pk%d.pgp"
#define OPENPGP_PKE_FILE_TEMPLATE	L"\\Storage Card\\enc_pk%d.gpg"
#define PGP_SIG_FILE_TEMPLATE		L"\\Storage Card\\sig%d.pgp"
#define PGP_COPR_FILE_TEMPLATE		L"\\Storage Card\\copr%d.pgp"

#define COMPRESS_FILE				L"\\Storage Card\\filename.h"

/****************************************************************************
*																			*
*								Generic Filesystem							*
*																			*
****************************************************************************/

#else

#define TEST_PRIVKEY_FILE			TEXT( "testdata/key_test.p15" )
#define TEST_PRIVKEY_ALT_FILE		TEXT( "testdata/key_test.p12" )
#define CA_PRIVKEY_FILE				TEXT( "testdata/key_ca.p15" )
#define ICA_PRIVKEY_FILE			TEXT( "testdata/key_ica.p15" )
#define SCEPCA_PRIVKEY_FILE			TEXT( "testdata/key_sca.p15" )
#define USER_PRIVKEY_FILE			TEXT( "testdata/key_user.p15" )
#define DUAL_PRIVKEY_FILE			TEXT( "testdata/key_dual.p15" )
#define RENEW_PRIVKEY_FILE			TEXT( "testdata/key_ren.p15" )
#define BIG_PRIVKEY_FILE			TEXT( "testdata/key_big.p15" )
#define CMP_PRIVKEY_FILE_TEMPLATE	TEXT( "testdata/key_cmp%d.p15" )
#define PNP_PRIVKEY_FILE			TEXT( "testdata/key_pnp.p15" )
#define PNPCA_PRIVKEY_FILE			TEXT( "testdata/key_pnpca.p15" )
#define SERVER_PRIVKEY_FILE			TEXT( "testdata/key_srv.p15" )
#define SSH_PRIVKEY_FILE			TEXT( "testdata/key_ssh.p15" )
#define TSA_PRIVKEY_FILE			TEXT( "testdata/key_tsa.p15" )

#define PGP_PUBKEY_FILE				TEXT( "testdata/pubring.pgp" )
#define PGP_PRIVKEY_FILE			TEXT( "testdata/secring.pgp" )
#define OPENPGP_PUBKEY_FILE			TEXT( "testdata/pubring.gpg" )
#define OPENPGP_PRIVKEY_FILE		TEXT( "testdata/secring.gpg" )
#define OPENPGP_PUBKEY_HASH_FILE	TEXT( "testdata/pubrinh.gpg" )
#define OPENPGP_PRIVKEY_HASH_FILE	TEXT( "testdata/secrinh.gpg" )
#define OPENPGP_PUBKEY_AES_FILE		TEXT( "testdata/pubrina.pkr" )
#define OPENPGP_PRIVKEY_AES_FILE	TEXT( "testdata/secrina.skr" )
#define NAIPGP_PUBKEY_FILE			TEXT( "testdata/pubring.pkr" )
#define NAIPGP_PRIVKEY_FILE			TEXT( "testdata/secring.skr" )
#define PKCS12_FILE					TEXT( "testdata/key.p12" )

#define CERT_FILE_TEMPLATE			TEXT( "testdata/cert%d.der" )
#define BASE64CERT_FILE_TEMPLATE	TEXT( "testdata/cert%d.asc" )
#define BROKEN_CERT_FILE			TEXT( "testdata/certb.der" )
#define BROKEN_USER_CERT_FILE		TEXT( "testdata/certbus.der" )
#define BROKEN_CA_CERT_FILE			TEXT( "testdata/certbca.der" )
#define CERTREQ_FILE_TEMPLATE		TEXT( "testdata/certreq%d.der" )
#define CRL_FILE_TEMPLATE			TEXT( "testdata/crl%d.crl" )
#define CERTCHAIN_FILE_TEMPLATE		TEXT( "testdata/certchn%d.der" )
#define BASE64CERTCHAIN_FILE_TEMPLATE TEXT( "testdata/certchn%d.asc" )
#define PATHTEST_FILE_TEMPLATE		TEXT( "testdata/ntest%d.p7s" )
#define SSHKEY_FILE_TEMPLATE		TEXT( "testdata/sshkey%d.asc" )
#define PGPKEY_FILE_TEMPLATE		TEXT( "testdata/pgpkey%d.asc" )
#define RTCS_OK_FILE				TEXT( "testdata/rtcsrok.der" )
#define OCSP_OK_FILE				TEXT( "testdata/ocsprok.der" )
#define OCSP_REV_FILE				TEXT( "testdata/ocsprrev.der" )
#define OCSP_CA_FILE				TEXT( "testdata/ocspca.der" )
#define CRLCERT_FILE_TEMPLATE		TEXT( "testdata/crl_cert%d.der" )
#define CHAINCERT_FILE_TEMPLATE		TEXT( "testdata/chn_cert%d.der" )
#define RTCS_FILE_TEMPLATE			TEXT( "testdata/rtcs_ee%do.der" )
#define OCSP_CA_FILE_TEMPLATE		TEXT( "testdata/ocsp_ca%d.der" )
#define OCSP_EEOK_FILE_TEMPLATE		TEXT( "testdata/ocsp_ee%do.der" )
#define OCSP_EEREV_FILE_TEMPLATE	TEXT( "testdata/ocsp_ee%dr.der" )
#define CMP_CA_FILE_TEMPLATE		TEXT( "testdata/cmp_ca%d.der" )
#define SCEP_CA_FILE_TEMPLATE		TEXT( "testdata/scep_ca%d.der" )

#define SMIME_SIG_FILE_TEMPLATE		TEXT( "testdata/smime%d.p7s" )
#define SMIME_ENVELOPED_FILE		TEXT( "testdata/smime.p7m" )
#define PGP_ENC_FILE_TEMPLATE		TEXT( "testdata/enc%d.pgp" )
#define PGP_PKE_FILE_TEMPLATE		TEXT( "testdata/enc_pk%d.pgp" )
#define OPENPGP_PKE_FILE_TEMPLATE	TEXT( "testdata/enc_pk%d.gpg" )
#define PGP_SIG_FILE_TEMPLATE		TEXT( "testdata/sig%d.pgp" )
#define PGP_COPR_FILE_TEMPLATE		TEXT( "testdata/copr%d.pgp" )

#define COMPRESS_FILE				TEXT( "test/filename.h" )

#endif /* OS-specific naming */
