#!/bin/sh

# fetches umpteen original conversion files from ftp.unicode.org, such
# that our *.inc files can be updates from these. the unicode tables
# may change, so it's a good idea to run this once per year. --arnt

wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-1.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-2.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-3.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-4.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-5.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-6.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-7.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-8.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-9.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-10.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-11.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-13.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-14.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-15.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-16.TXT

wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP737.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP775.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP852.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP855.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP857.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP860.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP861.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP862.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP863.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP864.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP865.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP866.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP869.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP874.TXT

wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1250.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1251.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1253.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1254.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1255.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1256.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1257.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1258.TXT

# we drop support for these until there is a demonstrable need. kept
# here since most of hte URLs never were in the depot.
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/ARABIC.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/CENTEURO.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/CORPCHAR.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/CROATIAN.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/CYRILLIC.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/DEVANAGA.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/DINGBATS.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/FARSI.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/GREEK.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/GUJARATI.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/GURMUKHI.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/HEBREW.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/ICELAND.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/KEYBOARD.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/README.TXT
wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/ROMAN.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/ROMANIAN.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/SYMBOL.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/THAI.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/TURKISH.TXT
#wget ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/APPLE/UKRAINE.TXT

# also, fetches the iana table, which changes often

wget http://www.iana.org/assignments/character-sets
