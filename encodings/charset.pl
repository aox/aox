#!/usr/bin/perl -w

open( I, "< character-sets" ) || die;

while( <I> ) {
    if ( /^Name: ([^\s]+)/ ) {
	$name = $1;
	$mimecanon{$name} = $1;
	$alias{$name}{$name} = 1;
    } elsif ( /^Alias: ([^\s]+)/ ) {
	$alias{$name}{$1} = 1;
    }
    if ( /([^\s]+)\s*.preferred MIME name/ ) {
	$mimecanon{$name} = $1;
    }
}

foreach ( sort keys %alias ) {
    if ( defined( $mimecanon{$_} ) ) {
	$m = $mimecanon{$_};
	$a{lc $m} = $m;
	foreach $k ( sort keys %{$alias{$_}} ) {
	    $a{lc $k} = $m;
	}
    }
}

open( G, "grep '^//codec .* .*' *.cpp |" );
while( <G> ) {
    if ( /codec (.*) (.*)/ ) {
	$n = $1;
	$c = $2;
	if ( lc $a{lc $n} ne lc $n ) {
	    $a{lc $n} = $n;
	    print "charset $n unknown\n";
	}
	$c{lc $n} = $c;
        $x{$n} = 1;
    }
}


open( O, "> codec-aliases.inc" );
foreach ( sort keys %a ) {
    print O "{\"$_\", \"$a{$_}\"},\n" unless ( $_ eq "none" || !$x{$a{$_}} );
}
close O;


open( O, "> codec-map.inc" );
foreach ( sort keys %c ) {
    print O "if ( name == \"$a{$_}\" ) codec = new $c{$_};\nelse ";
}
print O ";\n";
close O;
