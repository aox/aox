#include "mac.h"


static const int macromantable[256] = {
#include "mac-roman.inc"
};


/*! \class MacRomanCodec mac.h

    The MacRomanCodec class maps between MacRoman and Unicode.

    MacRoman is the character set most commonly used on the Macintosh.
    It's used a little now and then on the net, and many other converters
    support it. So we do too.

    Since other Macintosh encodings aren't, we don't. Apple seems to
    encourage MUAs to generate other encodings for internet use,
    apparently with success. Good.

At ftp.unicode.org, there are Apple-supplied tables called ARABIC.TXT,
CENTEURO.TXT, CORPCHAR.TXT, CROATIAN.TXT, CYRILLIC.TXT, DEVANAGA.TXT,
DINGBATS.TXT, FARSI.TXT, GREEK.TXT, GUJARATI.TXT, GURMUKHI.TXT,
HEBREW.TXT, ICELAND.TXT, KEYBOARD.TXT, LATIN2.TXT, ROMANIAN.TXT,
SYMBOL.TXT, THAI.TXT, TURKISH.TXT and UKRAINE.TXT. They correspond to
some subset of the Apple encodings MacArabic, MacArmenian, MacBengali,
MacBurmese, MacCentralEurRoman, MacChineseSimp, MacChineseTrad,
MacCroatian, MacCyrillic, MacDevanagari, MacDingbats, MacEthiopic,
MacExtArabic, MacFarsi, MacGeorgian, MacGreek, MacGujarati,
MacGurmukhi, MacHebrew, MacIcelandic, MacJapanese, MacKannada,
MacKhmer, MacKorean, MacLaotian, MacMalayalam, MacMongolian, MacOriya,
MacRomanian, MacSinhalese, MacSymbol, MacTamil, MacTelugu, MacThai,
MacTibetan, MacTurkish, MacUkrainian and MacVietnamese. None of those
names are defined in the IANA tables, and except MacRoman they don't
seem to crop up in mail. For ease of testing, we've decided to drop
support for them until there is a demonstrable need.
*/


/*!  Constructs an codec for the Macintosh "roman" character
     set/encoding, based on data provided by the Unicode Consortium.
*/

MacRomanCodec::MacRomanCodec()
    : TableCodec( macromantable, "macintosh" )
{
}

// this is the only standard name... we should also support the name
// macroman. how?

//codec macintosh MacRomanCodec
