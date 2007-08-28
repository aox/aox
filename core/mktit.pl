#!/usr/bin/perl

open( I, "< /usr/share/perl/5.8.8/unicore/UnicodeData.txt" ) || die;
while ( <I> ) {
    #0069;LATIN SMALL LETTER I;Ll;0;L;;;;;N;;;0049;;0049
    ($cp,$desc,$cl,$j,$j,$j,$j,$j,$j,$j,$j,$j,$equiv) = split( /;/, $_ );
    if ( $cl =~ /^L/ && $equiv ne "" ) {
        $titlecase[hex $cp] = hex $equiv;
        $titlecase[hex $equiv] = hex $equiv;
    }
    $desc[hex $cp] = $desc;
}

open( O, "> unicode-titlecase.inc" ) || die;
$i = 0;
print O "static uint numTitlecaseCodepoints = ", $#titlecase + 1, ";\n",
        "static uint titlecaseCodepoints[", $#titlecase + 1, "] = {\n";
while ( $i <= $#titlecase ) {
    if ( !defined( $titlecase[$i] ) ) {
        print O "    ", 0, ",\n";
    }
    elsif ( $i == $titlecase[$i] ) {
        printf( O "    0x%05x, // %05x == %s\n",
                $titlecase[$i], $i, $desc[$titlecase[$i]] );
    } else {
        printf( O "    0x%05x, // %05x -> %s\n",
                $titlecase[$i], $i, $desc[$titlecase[$i]] );
    }
    $i++;
}
print O "};\n";
