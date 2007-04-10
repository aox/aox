#!/bin/sh

# the files from which this script was run are kept (at the time of
# writing) in //oryx/external/codecmaps/.

p4 edit *.inc

# DOS code pages

for a in CP???.TXT ; do tr '[a-f]' '[A-F]' < $a | tr -s ' ' | awk '/^0x[0123456789ABCDEF]/{ print $1, $2 }' | sort | sed -e 's/#UNDEF.*$/0xFFFD/' | cut -c6- | paste '-d ' - - - - - - - - | sed -e 's/ /, /g' -e 's/$/,/' -e 's/^/    /' -e '$ s/,$//' > `basename $a .TXT | tr 'A-Z' 'a-z'`.inc ; done

# windows code pages, except 874, which is above

for a in CP12??.TXT ; do ( awk '/^0x[0123456789ABCDEF]/{ print $1, $2 }' < $a ) | sort | sed -e 's/#UNDEF.*$/0xFFFD/' | cut -c6- | paste '-d ' - - - - - - - - | sed -e 's/ /, /g' -e 's/$/,/' -e 's/^/    /' -e '$ s/,$//' > `basename $a .TXT | tr 'A-Z' 'a-z'`.inc ; done

# 8859-*

for A in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do for B in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do echo 0xFFFD 0x${A}${B} ; done ; done > /tmp/digits

for a in 8859-*.TXT ; do ( awk '/^0x[0123456789ABCDEF]/{ print $2, $1 }' < $a ; cat /tmp/digits ) | sort +1 | uniq -s7 | awk '{print $2, $1}' | cut -c6- | paste '-d ' - - - - - - - - | sed -e 's/ /, /g' -e 's/$/,/' -e 's/^/    /' -e '$ s/,$//' > `basename $a .TXT`.inc ; done

# mac codecs

for a in ROMAN.TXT ; do ( awk '/^0x[0123456789ABCDEF]/{ print $1, $2 }' < $a ; for hi in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do for lo in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do echo 0x$hi$lo 0xFFFD ; done ; done ) | sort | uniq -w4 | sed -e 's/#UNDEF.*$/0xFFFD/' | cut -c6- | paste '-d ' - - - - - - - - | sed -e 's/ /, /g' -e 's/$/,/' -e 's/^/    /' -e '$ s/,$//' > mac-`basename $a .TXT | tr 'A-Z' 'a-z'`.inc ; done

# hp

( awk '/^0x[0123456789ABCDEF]/{ print $1, $2 }' < hproman8.txt ; for hi in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do for lo in 0 1 2 3 4 5 6 7 8 9 A B C D E F ; do echo 0x$hi$lo 0xFFFD ; done ; done ) | sort | uniq -w4 | sed -e 's/#UNDEF.*$/0xFFFD/' | cut -c6- | paste '-d ' - - - - - - - - | sed -e 's/ /, /g' -e 's/$/,/' -e 's/^/    /' -e '$ s/,$//' > hproman8.inc 


p4 revert -a ...
