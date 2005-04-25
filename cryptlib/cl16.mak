# Microsoft Visual C++ generated build script - Do not modify

PROJ = CL16
DEBUG = 0
PROGTYPE = 1
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = P:\WINDOWS\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = CRYPT.C     
FIRSTCPP =             
RC = rc
CFLAGS_D_WDLL = /nologo /G2 /W3 /Gf /Zi /ALw /Od /D "_DEBUG" /D "INC_CHILD" /D "WIN16" /I "..\." /GD /Fd"CL16.PDB"
CFLAGS_R_WDLL = /nologo /G3 /W3 /Gf /ALw /O2 /D "NDEBUG" /D "INC_CHILD" /D "WIN16" /GD 
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /SEG:192 /ALIGN:16 /ONERROR:NOEXE /CO
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /SEG:256 /ALIGN:16 /ONERROR:NOEXE
LIBS_D_WDLL = oldnames libw ldllcew toolhelp.lib
LIBS_R_WDLL = oldnames libw ldllcew toolhelp.lib
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = CRYPT.DEF
OBJS_EXT = ..\CRYPT\SAFER_C.OBJ ..\BN\X86W32.OBJ 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WDLL)
LFLAGS = $(LFLAGS_D_WDLL)
LIBS = $(LIBS_D_WDLL)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WDLL)
LFLAGS = $(LFLAGS_R_WDLL)
LIBS = $(LIBS_R_WDLL)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = CRYPT.SBR \
		LIB_3DES.SBR \
		LIB_DES.SBR \
		LIB_IDEA.SBR \
		LIB_MD4.SBR \
		LIB_MD5.SBR \
		LIB_RC4.SBR \
		LIB_RC5.SBR \
		LIB_SAFR.SBR \
		LIB_SHA.SBR \
		LIB_RSA.SBR \
		LIB_RC2.SBR \
		ASN1.SBR \
		STREAM.SBR \
		LIB_RAND.SBR \
		LIB_DH.SBR \
		ASN1KEYS.SBR \
		MD4.SBR \
		CRYPTCAP.SBR \
		CRYPTAPI.SBR \
		CRYPTDBX.SBR \
		ASN1OBJS.SBR \
		MD2.SBR \
		RIPEMD.SBR \
		LIB_MD2.SBR \
		LIB_RIPE.SBR \
		X509_KEY.SBR \
		PGP_KEY.SBR \
		LIB_DSA.SBR \
		ADLER32.SBR \
		DEFLATE.SBR \
		INFBLOCK.SBR \
		INFCODES.SBR \
		INFFAST.SBR \
		INFLATE.SBR \
		INFTREES.SBR \
		INFUTIL.SBR \
		TREES.SBR \
		ZUTIL.SBR \
		DES_ENC.SBR \
		ECB_ENC.SBR \
		ECB3_ENC.SBR \
		SET_KEY.SBR \
		CRYPTENV.SBR \
		RC2.SBR \
		RC5.SBR \
		SAFER.SBR \
		IDEA.SBR \
		BF_ECB.SBR \
		BF_ENC.SBR \
		BF_SKEY.SBR \
		LIB_CAST.SBR \
		LIB_DBMS.SBR \
		RIPECORE.SBR \
		DEENVEL.SBR \
		ENVELOPE.SBR \
		LIB_HMD5.SBR \
		LIB_HSHA.SBR \
		PGP_MISC.SBR \
		RESOURCE.SBR \
		PGP_DEEN.SBR \
		CRYPTCFG.SBR \
		LIB_ELG.SBR \
		LIB_HRMD.SBR \
		RNDWIN16.SBR \
		DBXODBC.SBR \
		ASN1OID.SBR \
		SCGEMPLU.SBR \
		SCTOWITO.SBR \
		CRYPTKEY.SBR \
		DBXFILE.SBR \
		SCMISC.SBR \
		CERT.SBR \
		MD5_DGST.SBR \
		SHA_DGST.SBR \
		SHA1DGST.SBR \
		RC4_ENC.SBR \
		RC4_SKEY.SBR \
		C_ECB.SBR \
		C_ENC.SBR \
		C_SKEY.SBR \
		CERTEXT.SBR \
		LIB_KEYX.SBR \
		LIB_SIGN.SBR \
		CERTEXRW.SBR \
		CERTEDEF.SBR \
		CERTCHK.SBR \
		CERTCOMP.SBR \
		CERTSTR.SBR \
		LIB_BF.SBR \
		BN_ADD.SBR \
		BN_BLIND.SBR \
		BN_DIV.SBR \
		BN_EXP.SBR \
		BN_GCD.SBR \
		BN_LIB.SBR \
		BN_MOD.SBR \
		BN_MONT.SBR \
		BN_MUL.SBR \
		BN_RECP.SBR \
		BN_SHIFT.SBR \
		BN_SQR.SBR \
		BN_SUB.SBR \
		BN_WORD.SBR \
		LIB_SKIP.SBR \
		CERTCHN.SBR \
		SKIPJACK.SBR \
		LIB_MDC2.SBR \
		MDC2DGST.SBR \
		LIB_KG.SBR \
		CERTIO.SBR \
		OCTETSTR.SBR \
		CRYPTKRN.SBR \
		CMS.SBR \
		CRYPTCRT.SBR \
		CRYPTDEV.SBR \
		DEV_CEI.SBR \
		DEV_FORT.SBR \
		CERTSIG.SBR \
		CRYPTLIB.SBR \
		CERTRUST.SBR \
		CERTECHK.SBR


SAFER_C_DEP = 

X86W32_DEP = 

CRYPT_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


LIB_3DES_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\des/des.h


LIB_DES_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\des/des.h \
	p:\crypt/testdes.h


LIB_IDEA_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/idea.h


LIB_MD4_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/md4.h


LIB_MD5_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/md5.h


LIB_RC4_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/rc4.h


LIB_RC5_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/rc5.h


LIB_SAFR_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/safer.h


LIB_SHA_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/sha.h


CRYPT_RCDEP = 

LIB_RSA_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


LIB_RC2_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/rc2.h


ASN1_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	keymgmt/asn1.h


STREAM_DEP = p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	sys/file.h \
	sys/mode.h


LIB_RAND_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\bn/bn.h \
	p:\hash/sha.h \
	p:\misc/random.h


LIB_DH_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


ASN1KEYS_DEP = p:\cryptctx.h \
	p:\crypt.h \
	p:\bn/bn.h \
	p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h


MD4_DEP = p:\hash\md4.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	hash/md4.h


CRYPTCAP_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


CRYPTAPI_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\hash/md2.h \
	p:\hash/md4.h \
	p:\hash/md5.h \
	p:\hash/ripemd.h \
	p:\hash/sha.h


CRYPTDBX_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1keys.h \
	p:\keymgmt/asn1objs.h \
	p:\misc/dbms.h \
	p:\misc/\lber.h \
	d:\msvc\include\winsock.h \
	p:\misc/\ldap.h \
	sys/socket.h \
	sys/select.h \
	p:\misc/lber.h \
	p:\misc/ldap.h \
	p:\misc/\scard.h \
	p:\misc/scard.h \
	sys/param.h


ASN1OBJS_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h


MD2_DEP = p:\hash\md2.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	hash/md2.h


RIPEMD_DEP = p:\hash\clink.h \
	p:\hash\ripemd.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	hash/clink.h \
	hash/ripemd.h


LIB_MD2_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/md2.h


LIB_RIPE_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/ripemd.h


X509_KEY_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h


PGP_KEY_DEP = p:\keymgmt\asn1keys.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\envelope/pgp.h \
	p:\keymgmt/stream.h \
	envelope/pgp.h \
	keymgmt/asn1keys.h


LIB_DSA_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


ADLER32_DEP = p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h


DEFLATE_DEP = p:\zlib\deflate.h \
	p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	zlib/zutil.h \
	zlib/deflate.h


INFBLOCK_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\infblock.h \
	p:\zlib\inftrees.h \
	p:\zlib\infcodes.h \
	p:\zlib\infutil.h \
	zlib/zutil.h \
	zlib/infblock.h \
	zlib/inftrees.h \
	zlib/infcodes.h \
	zlib/infutil.h


INFCODES_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\inftrees.h \
	p:\zlib\infblock.h \
	p:\zlib\infcodes.h \
	p:\zlib\infutil.h \
	p:\zlib\inffast.h \
	zlib/zutil.h \
	zlib/inftrees.h \
	zlib/infblock.h \
	zlib/infcodes.h \
	zlib/infutil.h \
	zlib/inffast.h


INFFAST_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\inftrees.h \
	p:\zlib\infblock.h \
	p:\zlib\infcodes.h \
	p:\zlib\infutil.h \
	p:\zlib\inffast.h \
	zlib/zutil.h \
	zlib/inftrees.h \
	zlib/infblock.h \
	zlib/infcodes.h \
	zlib/infutil.h \
	zlib/inffast.h


INFLATE_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\infblock.h \
	zlib/zutil.h \
	zlib/infblock.h


INFTREES_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\inftrees.h \
	zlib/zutil.h \
	zlib/inftrees.h \
	p:\zlib\inffixed.h \
	zlib/inffixed.h


INFUTIL_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	p:\zlib\infblock.h \
	p:\zlib\inftrees.h \
	p:\zlib\infcodes.h \
	p:\zlib\infutil.h \
	zlib/zutil.h \
	zlib/infblock.h \
	zlib/inftrees.h \
	zlib/infcodes.h \
	zlib/infutil.h


TREES_DEP = p:\zlib\deflate.h \
	p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	zlib/zutil.h \
	zlib/deflate.h \
	p:\zlib\trees.h \
	zlib/trees.h


ZUTIL_DEP = p:\zlib\zutil.h \
	p:\zlib\zlib.h \
	p:\zlib\zconf.h \
	zlib/zconf.h \
	zlib/zlib.h \
	zlib/zutil.h


DES_ENC_DEP = p:\des\des_locl.h \
	p:\des\des.h \
	des/des.h \
	des/des_locl.h


ECB_ENC_DEP = p:\des\des_locl.h \
	p:\des\des.h \
	des/des.h \
	p:\des\spr.h \
	des/des_locl.h \
	des/spr.h


ECB3_ENC_DEP = p:\des\des_locl.h \
	p:\des\des.h \
	des/des.h \
	des/des_locl.h


SET_KEY_DEP = p:\des\des_locl.h \
	p:\des\des.h \
	des/des.h \
	p:\des\podd.h \
	p:\des\sk.h \
	des/des_locl.h \
	des/podd.h \
	des/sk.h


CRYPTENV_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt/asn1oid.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/stream.h \
	p:\envelope/envelope.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h


RC2_DEP = p:\crypt\rc2.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	crypt/rc2.h


RC5_DEP = p:\crypt\rc5.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	crypt/rc5.h


SAFER_DEP = p:\crypt\safer.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	crypt/safer.h


IDEA_DEP = p:\crypt\idea.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	crypt/idea.h


BF_ECB_DEP = p:\crypt\blowfish.h \
	p:\crypt\bf_locl.h \
	crypt/blowfish.h \
	crypt/bf_locl.h


BF_ENC_DEP = p:\crypt\blowfish.h \
	p:\crypt\bf_locl.h \
	crypt/blowfish.h \
	crypt/bf_locl.h


BF_SKEY_DEP = p:\crypt\blowfish.h \
	p:\crypt\bf_locl.h \
	p:\crypt\bf_pi.h \
	crypt/blowfish.h \
	crypt/bf_locl.h \
	crypt/bf_pi.h


LIB_CAST_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/cast.h


LIB_DBMS_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\misc/dbms.h \
	p:\misc/\lber.h \
	d:\msvc\include\winsock.h \
	p:\misc/\ldap.h \
	sys/socket.h \
	sys/select.h \
	p:\misc/lber.h \
	p:\misc/ldap.h \
	p:\keymgmt/stream.h \
	p:\misc/\scard.h \
	p:\misc/scard.h \
	sys/param.h \
	p:\keymgmt/asn1keys.h \
	p:\keymgmt/\stream.h


RIPECORE_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h


DEENVEL_DEP = p:\envelope\envelope.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h \
	zlib/zlib.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/asn1oid.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	envelope/envelope.h


ENVELOPE_DEP = p:\envelope\envelope.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h \
	zlib/zlib.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/asn1oid.h \
	p:\envelope/envelope.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	envelope/envelope.h


LIB_HMD5_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/md5.h


LIB_HSHA_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/sha.h


PGP_MISC_DEP = p:\envelope\pgp.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	envelope/pgp.h


RESOURCE_DEP = p:\envelope\envelope.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h \
	zlib/zlib.h \
	p:\envelope/envelope.h \
	envelope/envelope.h


PGP_DEEN_DEP = p:\envelope\envelope.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h \
	zlib/zlib.h \
	p:\envelope\pgp.h \
	p:\envelope/envelope.h \
	p:\envelope/pgp.h \
	p:\keymgmt\stream.h \
	envelope/envelope.h \
	envelope/pgp.h


CRYPTCFG_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt/stream.h


LIB_ELG_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


LIB_HRMD_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/ripemd.h


RNDWIN16_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\misc\random.h


DBXODBC_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\misc\dbms.h \
	p:\misc\lber.h \
	d:\msvc\include\winsock.h \
	p:\misc\ldap.h \
	sys/socket.h \
	sys/select.h \
	misc/lber.h \
	misc/ldap.h \
	p:\keymgmt/stream.h \
	keymgmt/stream.h \
	p:\misc\scard.h \
	p:\misc/scard.h \
	misc/scard.h \
	sys/param.h


ASN1OID_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h


SCGEMPLU_DEP = p:\misc\scard.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	misc/scard.h


SCTOWITO_DEP = p:\misc\scard.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	misc/scard.h


CRYPTKEY_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/stream.h \
	p:\hash/sha.h


DBXFILE_DEP = p:\misc\dbms.h \
	p:\misc\lber.h \
	d:\msvc\include\winsock.h \
	p:\misc\ldap.h \
	sys/socket.h \
	sys/select.h \
	misc/lber.h \
	misc/ldap.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\misc\scard.h \
	p:\misc/scard.h \
	misc/scard.h \
	sys/param.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/asn1oid.h \
	p:\keymgmt/asn1keys.h \
	misc/dbms.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/asn1keys.h \
	p:\envelope/pgp.h \
	p:\keymgmt\stream.h \
	envelope/pgp.h


SCMISC_DEP = p:\misc\scard.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	keymgmt/asn1.h \
	misc/scard.h


CERT_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h


MD5_DGST_DEP = p:\hash\md5_locl.h \
	p:\hash\md5.h \
	hash/md5.h \
	hash/md5_locl.h


SHA_DGST_DEP = p:\hash\sha.h \
	p:\hash\sha_locl.h \
	hash/sha.h \
	hash/sha_locl.h


SHA1DGST_DEP = p:\hash\sha.h \
	p:\hash\sha_locl.h \
	hash/sha.h \
	hash/sha_locl.h


RC4_ENC_DEP = p:\crypt\rc4.h \
	p:\crypt\rc4_locl.h \
	crypt/rc4.h \
	crypt/rc4_locl.h


RC4_SKEY_DEP = p:\crypt\rc4.h \
	p:\crypt\rc4_locl.h \
	crypt/rc4.h \
	crypt/rc4_locl.h


C_ECB_DEP = p:\crypt\cast.h \
	p:\crypt\cast_lcl.h \
	crypt/cast.h \
	crypt/cast_lcl.h


C_ENC_DEP = p:\crypt\cast.h \
	p:\crypt\cast_lcl.h \
	crypt/cast.h \
	crypt/cast_lcl.h


C_SKEY_DEP = p:\crypt\cast.h \
	p:\crypt\cast_lcl.h \
	p:\crypt\cast_s.h \
	crypt/cast.h \
	crypt/cast_lcl.h \
	crypt/cast_s.h


CERTEXT_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\cert.h \
	p:\keymgmt\certattr.h \
	keymgmt/asn1.h \
	keymgmt/cert.h \
	keymgmt/certattr.h


LIB_KEYX_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/asn1oid.h


LIB_SIGN_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/asn1oid.h


CERTEXRW_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	p:\keymgmt\certattr.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h \
	keymgmt/certattr.h


CERTEDEF_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	p:\keymgmt\certattr.h \
	keymgmt/asn1.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h \
	keymgmt/certattr.h


CERTCHK_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/cert.h


CERTCOMP_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/cert.h


CERTSTR_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/cert.h


LIB_BF_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\crypt/blowfish.h


BN_ADD_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_BLIND_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_DIV_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_EXP_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_GCD_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_LIB_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_MOD_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_MONT_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_MUL_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_RECP_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_SHIFT_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_SQR_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_SUB_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


BN_WORD_DEP = p:\bn\bn_lcl.h \
	p:\bn\bn.h \
	bn/bn.h \
	bn/bn_lcl.h


LIB_SKIP_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h


CERTCHN_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h


SKIPJACK_DEP = 

LIB_MDC2_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\hash/mdc2.h \
	p:\des/des.h


MDC2DGST_DEP = p:\hash\mdc2.h \
	p:\des/des.h \
	des/des.h \
	hash/mdc2.h


LIB_KG_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\bn/bn_prime.h


CERTIO_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h


OCTETSTR_DEP = p:\envelope\envelope.h \
	p:\keymgmt/stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	keymgmt/stream.h \
	p:\zlib/zlib.h \
	p:\zlib/\zconf.h \
	p:\zlib/zconf.h \
	zlib/zlib.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/ber.h \
	keymgmt/asn1.h \
	envelope/envelope.h


CRYPTKRN_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	sys/mman.h


CMS_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1objs.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h


CRYPTCRT_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	p:\keymgmt/asn1objs.h \
	p:\keymgmt/cert.h


CRYPTDEV_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\misc/device.h \
	p:\misc/\scard.h \
	p:\misc/scard.h


DEV_CEI_DEP = p:\misc\device.h \
	p:\misc\scard.h \
	p:\misc/scard.h \
	misc/scard.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	misc/device.h


DEV_FORT_DEP = p:\misc\device.h \
	p:\misc\scard.h \
	p:\misc/scard.h \
	misc/scard.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\cryptctx.h \
	p:\bn/bn.h \
	p:\keymgmt/asn1.h \
	p:\keymgmt/\stream.h \
	p:\keymgmt/\ber.h \
	p:\keymgmt/stream.h \
	p:\keymgmt/ber.h \
	keymgmt/asn1.h \
	misc/device.h


CERTSIG_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/cert.h


CRYPTLIB_DEP = p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h


CERTRUST_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1keys.h \
	p:\keymgmt\cert.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/cert.h


CERTECHK_DEP = p:\keymgmt\asn1.h \
	p:\keymgmt\stream.h \
	p:\crypt.h \
	p:\capi.h \
	p:\cryptos.h \
	p:\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	p:\keymgmt\asn1oid.h \
	p:\keymgmt\cert.h \
	p:\keymgmt\certattr.h \
	keymgmt/asn1.h \
	keymgmt/asn1oid.h \
	keymgmt/cert.h \
	keymgmt/certattr.h


all:	$(PROJ).DLL

CRYPT.OBJ:	..\CRYPT.C $(CRYPT_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ..\CRYPT.C

LIB_3DES.OBJ:	..\LIB_3DES.C $(LIB_3DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_3DES.C

LIB_DES.OBJ:	..\LIB_DES.C $(LIB_DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DES.C

LIB_IDEA.OBJ:	..\LIB_IDEA.C $(LIB_IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_IDEA.C

LIB_MD4.OBJ:	..\LIB_MD4.C $(LIB_MD4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD4.C

LIB_MD5.OBJ:	..\LIB_MD5.C $(LIB_MD5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD5.C

LIB_RC4.OBJ:	..\LIB_RC4.C $(LIB_RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC4.C

LIB_RC5.OBJ:	..\LIB_RC5.C $(LIB_RC5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC5.C

LIB_SAFR.OBJ:	..\LIB_SAFR.C $(LIB_SAFR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SAFR.C

LIB_SHA.OBJ:	..\LIB_SHA.C $(LIB_SHA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SHA.C

CRYPT.RES:	CRYPT.RC $(CRYPT_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r CRYPT.RC

LIB_RSA.OBJ:	..\LIB_RSA.C $(LIB_RSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RSA.C

LIB_RC2.OBJ:	..\LIB_RC2.C $(LIB_RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC2.C

ASN1.OBJ:	..\KEYMGMT\ASN1.C $(ASN1_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1.C

STREAM.OBJ:	..\KEYMGMT\STREAM.C $(STREAM_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\STREAM.C

LIB_RAND.OBJ:	..\LIB_RAND.C $(LIB_RAND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RAND.C

LIB_DH.OBJ:	..\LIB_DH.C $(LIB_DH_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DH.C

ASN1KEYS.OBJ:	..\KEYMGMT\ASN1KEYS.C $(ASN1KEYS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1KEYS.C

MD4.OBJ:	..\HASH\MD4.C $(MD4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD4.C

CRYPTCAP.OBJ:	..\CRYPTCAP.C $(CRYPTCAP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTCAP.C

CRYPTAPI.OBJ:	..\CRYPTAPI.C $(CRYPTAPI_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTAPI.C

CRYPTDBX.OBJ:	..\CRYPTDBX.C $(CRYPTDBX_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTDBX.C

ASN1OBJS.OBJ:	..\KEYMGMT\ASN1OBJS.C $(ASN1OBJS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1OBJS.C

MD2.OBJ:	..\HASH\MD2.C $(MD2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD2.C

RIPEMD.OBJ:	..\HASH\RIPEMD.C $(RIPEMD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\RIPEMD.C

LIB_MD2.OBJ:	..\LIB_MD2.C $(LIB_MD2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD2.C

LIB_RIPE.OBJ:	..\LIB_RIPE.C $(LIB_RIPE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RIPE.C

X509_KEY.OBJ:	..\KEYMGMT\X509_KEY.C $(X509_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\X509_KEY.C

PGP_KEY.OBJ:	..\KEYMGMT\PGP_KEY.C $(PGP_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\PGP_KEY.C

LIB_DSA.OBJ:	..\LIB_DSA.C $(LIB_DSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DSA.C

ADLER32.OBJ:	..\ZLIB\ADLER32.C $(ADLER32_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\ADLER32.C

DEFLATE.OBJ:	..\ZLIB\DEFLATE.C $(DEFLATE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\DEFLATE.C

INFBLOCK.OBJ:	..\ZLIB\INFBLOCK.C $(INFBLOCK_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFBLOCK.C

INFCODES.OBJ:	..\ZLIB\INFCODES.C $(INFCODES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFCODES.C

INFFAST.OBJ:	..\ZLIB\INFFAST.C $(INFFAST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFFAST.C

INFLATE.OBJ:	..\ZLIB\INFLATE.C $(INFLATE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFLATE.C

INFTREES.OBJ:	..\ZLIB\INFTREES.C $(INFTREES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFTREES.C

INFUTIL.OBJ:	..\ZLIB\INFUTIL.C $(INFUTIL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\INFUTIL.C

TREES.OBJ:	..\ZLIB\TREES.C $(TREES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\TREES.C

ZUTIL.OBJ:	..\ZLIB\ZUTIL.C $(ZUTIL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ZLIB\ZUTIL.C

DES_ENC.OBJ:	..\DES\DES_ENC.C $(DES_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\DES\DES_ENC.C

ECB_ENC.OBJ:	..\DES\ECB_ENC.C $(ECB_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\DES\ECB_ENC.C

ECB3_ENC.OBJ:	..\DES\ECB3_ENC.C $(ECB3_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\DES\ECB3_ENC.C

SET_KEY.OBJ:	..\DES\SET_KEY.C $(SET_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\DES\SET_KEY.C

CRYPTENV.OBJ:	..\CRYPTENV.C $(CRYPTENV_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTENV.C

RC2.OBJ:	..\CRYPT\RC2.C $(RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\RC2.C

RC5.OBJ:	..\CRYPT\RC5.C $(RC5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\RC5.C

SAFER.OBJ:	..\CRYPT\SAFER.C $(SAFER_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\SAFER.C

IDEA.OBJ:	..\CRYPT\IDEA.C $(IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\IDEA.C

BF_ECB.OBJ:	..\CRYPT\BF_ECB.C $(BF_ECB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\BF_ECB.C

BF_ENC.OBJ:	..\CRYPT\BF_ENC.C $(BF_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\BF_ENC.C

BF_SKEY.OBJ:	..\CRYPT\BF_SKEY.C $(BF_SKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\BF_SKEY.C

LIB_CAST.OBJ:	..\LIB_CAST.C $(LIB_CAST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_CAST.C

LIB_DBMS.OBJ:	..\LIB_DBMS.C $(LIB_DBMS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DBMS.C

RIPECORE.OBJ:	..\HASH\RIPECORE.C $(RIPECORE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\RIPECORE.C

DEENVEL.OBJ:	..\ENVELOPE\DEENVEL.C $(DEENVEL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\DEENVEL.C

ENVELOPE.OBJ:	..\ENVELOPE\ENVELOPE.C $(ENVELOPE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\ENVELOPE.C

LIB_HMD5.OBJ:	..\LIB_HMD5.C $(LIB_HMD5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_HMD5.C

LIB_HSHA.OBJ:	..\LIB_HSHA.C $(LIB_HSHA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_HSHA.C

PGP_MISC.OBJ:	..\ENVELOPE\PGP_MISC.C $(PGP_MISC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\PGP_MISC.C

RESOURCE.OBJ:	..\ENVELOPE\RESOURCE.C $(RESOURCE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\RESOURCE.C

PGP_DEEN.OBJ:	..\ENVELOPE\PGP_DEEN.C $(PGP_DEEN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\PGP_DEEN.C

CRYPTCFG.OBJ:	..\CRYPTCFG.C $(CRYPTCFG_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTCFG.C

LIB_ELG.OBJ:	..\LIB_ELG.C $(LIB_ELG_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_ELG.C

LIB_HRMD.OBJ:	..\LIB_HRMD.C $(LIB_HRMD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_HRMD.C

RNDWIN16.OBJ:	..\MISC\RNDWIN16.C $(RNDWIN16_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\RNDWIN16.C

DBXODBC.OBJ:	..\MISC\DBXODBC.C $(DBXODBC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\DBXODBC.C

ASN1OID.OBJ:	..\KEYMGMT\ASN1OID.C $(ASN1OID_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1OID.C

SCGEMPLU.OBJ:	..\MISC\SCGEMPLU.C $(SCGEMPLU_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\SCGEMPLU.C

SCTOWITO.OBJ:	..\MISC\SCTOWITO.C $(SCTOWITO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\SCTOWITO.C

CRYPTKEY.OBJ:	..\CRYPTKEY.C $(CRYPTKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTKEY.C

DBXFILE.OBJ:	..\MISC\DBXFILE.C $(DBXFILE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\DBXFILE.C

SCMISC.OBJ:	..\MISC\SCMISC.C $(SCMISC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\SCMISC.C

CERT.OBJ:	..\KEYMGMT\CERT.C $(CERT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERT.C

MD5_DGST.OBJ:	..\HASH\MD5_DGST.C $(MD5_DGST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD5_DGST.C

SHA_DGST.OBJ:	..\HASH\SHA_DGST.C $(SHA_DGST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\SHA_DGST.C

SHA1DGST.OBJ:	..\HASH\SHA1DGST.C $(SHA1DGST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\SHA1DGST.C

RC4_ENC.OBJ:	..\CRYPT\RC4_ENC.C $(RC4_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\RC4_ENC.C

RC4_SKEY.OBJ:	..\CRYPT\RC4_SKEY.C $(RC4_SKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\RC4_SKEY.C

C_ECB.OBJ:	..\CRYPT\C_ECB.C $(C_ECB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\C_ECB.C

C_ENC.OBJ:	..\CRYPT\C_ENC.C $(C_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\C_ENC.C

C_SKEY.OBJ:	..\CRYPT\C_SKEY.C $(C_SKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\C_SKEY.C

CERTEXT.OBJ:	..\KEYMGMT\CERTEXT.C $(CERTEXT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTEXT.C

LIB_KEYX.OBJ:	..\LIB_KEYX.C $(LIB_KEYX_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_KEYX.C

LIB_SIGN.OBJ:	..\LIB_SIGN.C $(LIB_SIGN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SIGN.C

CERTEXRW.OBJ:	..\KEYMGMT\CERTEXRW.C $(CERTEXRW_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTEXRW.C

CERTEDEF.OBJ:	..\KEYMGMT\CERTEDEF.C $(CERTEDEF_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTEDEF.C

CERTCHK.OBJ:	..\KEYMGMT\CERTCHK.C $(CERTCHK_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTCHK.C

CERTCOMP.OBJ:	..\KEYMGMT\CERTCOMP.C $(CERTCOMP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTCOMP.C

CERTSTR.OBJ:	..\KEYMGMT\CERTSTR.C $(CERTSTR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTSTR.C

LIB_BF.OBJ:	..\LIB_BF.C $(LIB_BF_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_BF.C

BN_ADD.OBJ:	..\BN\BN_ADD.C $(BN_ADD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_ADD.C

BN_BLIND.OBJ:	..\BN\BN_BLIND.C $(BN_BLIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_BLIND.C

BN_DIV.OBJ:	..\BN\BN_DIV.C $(BN_DIV_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_DIV.C

BN_EXP.OBJ:	..\BN\BN_EXP.C $(BN_EXP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_EXP.C

BN_GCD.OBJ:	..\BN\BN_GCD.C $(BN_GCD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_GCD.C

BN_LIB.OBJ:	..\BN\BN_LIB.C $(BN_LIB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_LIB.C

BN_MOD.OBJ:	..\BN\BN_MOD.C $(BN_MOD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_MOD.C

BN_MONT.OBJ:	..\BN\BN_MONT.C $(BN_MONT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_MONT.C

BN_MUL.OBJ:	..\BN\BN_MUL.C $(BN_MUL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_MUL.C

BN_RECP.OBJ:	..\BN\BN_RECP.C $(BN_RECP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_RECP.C

BN_SHIFT.OBJ:	..\BN\BN_SHIFT.C $(BN_SHIFT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_SHIFT.C

BN_SQR.OBJ:	..\BN\BN_SQR.C $(BN_SQR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_SQR.C

BN_SUB.OBJ:	..\BN\BN_SUB.C $(BN_SUB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_SUB.C

BN_WORD.OBJ:	..\BN\BN_WORD.C $(BN_WORD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BN\BN_WORD.C

LIB_SKIP.OBJ:	..\LIB_SKIP.C $(LIB_SKIP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SKIP.C

CERTCHN.OBJ:	..\KEYMGMT\CERTCHN.C $(CERTCHN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTCHN.C

SKIPJACK.OBJ:	..\CRYPT\SKIPJACK.C $(SKIPJACK_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPT\SKIPJACK.C

LIB_MDC2.OBJ:	..\LIB_MDC2.C $(LIB_MDC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MDC2.C

MDC2DGST.OBJ:	..\HASH\MDC2DGST.C $(MDC2DGST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MDC2DGST.C

LIB_KG.OBJ:	..\LIB_KG.C $(LIB_KG_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_KG.C

CERTIO.OBJ:	..\KEYMGMT\CERTIO.C $(CERTIO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTIO.C

OCTETSTR.OBJ:	..\ENVELOPE\OCTETSTR.C $(OCTETSTR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\ENVELOPE\OCTETSTR.C

CRYPTKRN.OBJ:	..\CRYPTKRN.C $(CRYPTKRN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTKRN.C

CMS.OBJ:	..\KEYMGMT\CMS.C $(CMS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CMS.C

CRYPTCRT.OBJ:	..\CRYPTCRT.C $(CRYPTCRT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTCRT.C

CRYPTDEV.OBJ:	..\CRYPTDEV.C $(CRYPTDEV_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTDEV.C

DEV_CEI.OBJ:	..\MISC\DEV_CEI.C $(DEV_CEI_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\DEV_CEI.C

DEV_FORT.OBJ:	..\MISC\DEV_FORT.C $(DEV_FORT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MISC\DEV_FORT.C

CERTSIG.OBJ:	..\KEYMGMT\CERTSIG.C $(CERTSIG_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTSIG.C

CRYPTLIB.OBJ:	..\CRYPTLIB.C $(CRYPTLIB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTLIB.C

CERTRUST.OBJ:	..\KEYMGMT\CERTRUST.C $(CERTRUST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTRUST.C

CERTECHK.OBJ:	..\KEYMGMT\CERTECHK.C $(CERTECHK_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\CERTECHK.C


$(PROJ).DLL::	CRYPT.RES

$(PROJ).DLL::	CRYPT.OBJ LIB_3DES.OBJ LIB_DES.OBJ LIB_IDEA.OBJ LIB_MD4.OBJ LIB_MD5.OBJ \
	LIB_RC4.OBJ LIB_RC5.OBJ LIB_SAFR.OBJ LIB_SHA.OBJ LIB_RSA.OBJ LIB_RC2.OBJ ASN1.OBJ \
	STREAM.OBJ LIB_RAND.OBJ LIB_DH.OBJ ASN1KEYS.OBJ MD4.OBJ CRYPTCAP.OBJ CRYPTAPI.OBJ \
	CRYPTDBX.OBJ ASN1OBJS.OBJ MD2.OBJ RIPEMD.OBJ LIB_MD2.OBJ LIB_RIPE.OBJ X509_KEY.OBJ \
	PGP_KEY.OBJ LIB_DSA.OBJ ADLER32.OBJ DEFLATE.OBJ INFBLOCK.OBJ INFCODES.OBJ INFFAST.OBJ \
	INFLATE.OBJ INFTREES.OBJ INFUTIL.OBJ TREES.OBJ ZUTIL.OBJ DES_ENC.OBJ ECB_ENC.OBJ \
	ECB3_ENC.OBJ SET_KEY.OBJ CRYPTENV.OBJ RC2.OBJ RC5.OBJ SAFER.OBJ IDEA.OBJ BF_ECB.OBJ \
	BF_ENC.OBJ BF_SKEY.OBJ LIB_CAST.OBJ LIB_DBMS.OBJ RIPECORE.OBJ DEENVEL.OBJ ENVELOPE.OBJ \
	LIB_HMD5.OBJ LIB_HSHA.OBJ PGP_MISC.OBJ RESOURCE.OBJ PGP_DEEN.OBJ CRYPTCFG.OBJ LIB_ELG.OBJ \
	LIB_HRMD.OBJ RNDWIN16.OBJ DBXODBC.OBJ ASN1OID.OBJ SCGEMPLU.OBJ SCTOWITO.OBJ CRYPTKEY.OBJ \
	DBXFILE.OBJ SCMISC.OBJ CERT.OBJ MD5_DGST.OBJ SHA_DGST.OBJ SHA1DGST.OBJ RC4_ENC.OBJ \
	RC4_SKEY.OBJ C_ECB.OBJ C_ENC.OBJ C_SKEY.OBJ CERTEXT.OBJ LIB_KEYX.OBJ LIB_SIGN.OBJ \
	CERTEXRW.OBJ CERTEDEF.OBJ CERTCHK.OBJ CERTCOMP.OBJ CERTSTR.OBJ LIB_BF.OBJ BN_ADD.OBJ \
	BN_BLIND.OBJ BN_DIV.OBJ BN_EXP.OBJ BN_GCD.OBJ BN_LIB.OBJ BN_MOD.OBJ BN_MONT.OBJ BN_MUL.OBJ \
	BN_RECP.OBJ BN_SHIFT.OBJ BN_SQR.OBJ BN_SUB.OBJ BN_WORD.OBJ LIB_SKIP.OBJ CERTCHN.OBJ \
	SKIPJACK.OBJ LIB_MDC2.OBJ MDC2DGST.OBJ LIB_KG.OBJ CERTIO.OBJ OCTETSTR.OBJ CRYPTKRN.OBJ \
	CMS.OBJ CRYPTCRT.OBJ CRYPTDEV.OBJ DEV_CEI.OBJ DEV_FORT.OBJ CERTSIG.OBJ CRYPTLIB.OBJ \
	CERTRUST.OBJ CERTECHK.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
CRYPT.OBJ +
LIB_3DES.OBJ +
LIB_DES.OBJ +
LIB_IDEA.OBJ +
LIB_MD4.OBJ +
LIB_MD5.OBJ +
LIB_RC4.OBJ +
LIB_RC5.OBJ +
LIB_SAFR.OBJ +
LIB_SHA.OBJ +
LIB_RSA.OBJ +
LIB_RC2.OBJ +
ASN1.OBJ +
STREAM.OBJ +
LIB_RAND.OBJ +
LIB_DH.OBJ +
ASN1KEYS.OBJ +
MD4.OBJ +
CRYPTCAP.OBJ +
CRYPTAPI.OBJ +
CRYPTDBX.OBJ +
ASN1OBJS.OBJ +
MD2.OBJ +
RIPEMD.OBJ +
LIB_MD2.OBJ +
LIB_RIPE.OBJ +
X509_KEY.OBJ +
PGP_KEY.OBJ +
LIB_DSA.OBJ +
ADLER32.OBJ +
DEFLATE.OBJ +
INFBLOCK.OBJ +
INFCODES.OBJ +
INFFAST.OBJ +
INFLATE.OBJ +
INFTREES.OBJ +
INFUTIL.OBJ +
TREES.OBJ +
ZUTIL.OBJ +
DES_ENC.OBJ +
ECB_ENC.OBJ +
ECB3_ENC.OBJ +
SET_KEY.OBJ +
CRYPTENV.OBJ +
RC2.OBJ +
RC5.OBJ +
SAFER.OBJ +
IDEA.OBJ +
BF_ECB.OBJ +
BF_ENC.OBJ +
BF_SKEY.OBJ +
LIB_CAST.OBJ +
LIB_DBMS.OBJ +
RIPECORE.OBJ +
DEENVEL.OBJ +
ENVELOPE.OBJ +
LIB_HMD5.OBJ +
LIB_HSHA.OBJ +
PGP_MISC.OBJ +
RESOURCE.OBJ +
PGP_DEEN.OBJ +
CRYPTCFG.OBJ +
LIB_ELG.OBJ +
LIB_HRMD.OBJ +
RNDWIN16.OBJ +
DBXODBC.OBJ +
ASN1OID.OBJ +
SCGEMPLU.OBJ +
SCTOWITO.OBJ +
CRYPTKEY.OBJ +
DBXFILE.OBJ +
SCMISC.OBJ +
CERT.OBJ +
MD5_DGST.OBJ +
SHA_DGST.OBJ +
SHA1DGST.OBJ +
RC4_ENC.OBJ +
RC4_SKEY.OBJ +
C_ECB.OBJ +
C_ENC.OBJ +
C_SKEY.OBJ +
CERTEXT.OBJ +
LIB_KEYX.OBJ +
LIB_SIGN.OBJ +
CERTEXRW.OBJ +
CERTEDEF.OBJ +
CERTCHK.OBJ +
CERTCOMP.OBJ +
CERTSTR.OBJ +
LIB_BF.OBJ +
BN_ADD.OBJ +
BN_BLIND.OBJ +
BN_DIV.OBJ +
BN_EXP.OBJ +
BN_GCD.OBJ +
BN_LIB.OBJ +
BN_MOD.OBJ +
BN_MONT.OBJ +
BN_MUL.OBJ +
BN_RECP.OBJ +
BN_SHIFT.OBJ +
BN_SQR.OBJ +
BN_SUB.OBJ +
BN_WORD.OBJ +
LIB_SKIP.OBJ +
CERTCHN.OBJ +
SKIPJACK.OBJ +
LIB_MDC2.OBJ +
MDC2DGST.OBJ +
LIB_KG.OBJ +
CERTIO.OBJ +
OCTETSTR.OBJ +
CRYPTKRN.OBJ +
CMS.OBJ +
CRYPTCRT.OBJ +
CRYPTDEV.OBJ +
DEV_CEI.OBJ +
DEV_FORT.OBJ +
CERTSIG.OBJ +
CRYPTLIB.OBJ +
CERTRUST.OBJ +
CERTECHK.OBJ +
$(OBJS_EXT)
$(PROJ).DLL
$(MAPFILE)
d:\msvc\lib\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) CRYPT.RES $@
	@copy $(PROJ).CRF MSVC.BND
	implib /nowep $(PROJ).LIB $(PROJ).DLL

$(PROJ).DLL::	CRYPT.RES
	if not exist MSVC.BND 	$(RC) $(RESFLAGS) CRYPT.RES $@

run: $(PROJ).DLL
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
