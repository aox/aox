// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "html.h"

#include "utf.h"
#include "ustring.h"
#include "entities.h"

#include <ctype.h>


/*! \class HTML html.h
    This class is responsible for extracting indexable text from HTML.
    Its interface is subject to change once there are other classes to
    do the same thing for other formats.
*/


/*! Returns indexable text extracted from \a h. */

UString HTML::asText( const UString &h )
{
    UString r;
    UString t, s, qs, a;
    char last = 0;
    char quote = 0;
    char c;
    uint mark = 0;

    int tag = 0;        /* 1 inside <...> */
    int tagname = 0;    /* 1 inside tag, before whitespace */
    int sgml = 0;       /* 1 inside <[!?]...> */
    int quoted = 0;     /* 1 inside <foo bar="..."> */

    uint i = 0;
    while ( i < h.length() ) {
        /* Each case below sets i to the position of the last character
           it processed. */
        switch ( h[i] ) {
        case '<':
            if ( quoted )
                goto next;
            if ( h[i+1] == '!' || h[i+1] == '?' ) {
                sgml = 1;
                i++;
            }
            tag = 1;
            tagname = 1;
            t.truncate();
            break;

        case '>':
            if ( quoted )
                goto next;
            if ( tag ) {
                //t = t.lower();
                if ( t == "p" ) {
                    s.append( '\n' );
                    s.append( '\n' );
                }
                else if ( t == "br" ) {
                    s.append( '\n' );
                }
                else if ( t == "body" ) {
                    r.truncate();
                }
                sgml = tag = 0;
            }
            break;

        case '-':
            if ( !sgml )
                goto unspecial;
            if ( quoted && quote != '-' )
                goto next;
            if ( last == '-' ) {
                quote = '-';
                quoted = !quoted;
            }
            break;

        case '"':
        case '\'':
            if ( !tag )
                goto unspecial;
            if ( quoted && quote == h[i] ) {
                quoted = 0;
            } else if ( !quoted && last == '=' ) {
                quoted = 1;
                quote = h[i];
                qs.truncate();
            }
            break;

        case ' ':
        case '\t':
        case '\r':
        case '\n':
            /* Whitespace shouldn't appear in last, and we compress it
               to one space. */
            if ( !tag && s.isEmpty() )
                s.append( ' ' );
            tagname = false;
            a.truncate();
            i++;
            continue;
            break;

        case '&':
            /* May be a character reference. */
            if ( ( c = h[i+1] ) == '#' ) {
                char d = h[i+2] | 0x20;

                if ( isdigit( d ) ) {
                    /* Decimal numeric reference: &#[0-9]+;? */
                    i += 2;
                    mark = i++;
                    while ( isdigit( h[i] ) )
                        i++;
                    r.append( s );
                    r.append( h.mid( mark, i-mark ).number( 0 ) );
                    s.truncate();

                    /* The terminating semicolon is required only
                       where the next character would otherwise be
                       interpreted as a part of the reference. */
                    if ( h[i] != ';' )
                        i--;
                }
                else if ( d == 'x' ) {
                    /* Hexadecimal numeric reference: &#[xX][0-9A-Za-z]+;? */
                    i += 2;
                    mark = ++i;
                    while ( isxdigit( h[i] ) )
                        i++;
                    if ( i != mark ) {
                        r.append( s );
                        r.append( h.mid( mark, i-mark ).number( 0, 16 ) );
                        s.truncate();
                    }
                    if ( h[i] != ';' )
                        i--;
                }
                else {
                    /* Not a reference. */
                    i++;
                    r.append( s );
                    r.append( '&' );
                    r.append( '#' );
                    s.truncate();
                }
            } else if ( isalpha( c ) ) {
                /* Entity reference: &[a-zA-Z0-9]+;? */
                i++;
                mark = i++;
                while ( isalnum( h[i] ) )
                    i++;
                UString ent( h.mid( mark, i-mark ) );
                if ( h[i] != ';' )
                    i--;

                int n = 0;
                while ( n < ents ) {
                    uint l = 0;
                    bool match = true;
                    while ( l < ent.length() ) {
                        if ( ent[l] != entities[n].name[l] ) {
                            match = false;
                            break;
                        }
                        l++;
                    }

                    if ( match && entities[n].name[l] == '\0' ) {
                        r.append( s );
                        r.append( entities[n].chr );
                        s.truncate();
                        break;
                    }

                    n++;
                }
            }
            else {
                /* Not a reference. */
                r.append( s );
                r.append( '&' );
                s.truncate();
            }
            break;

    unspecial:
        default:
            if ( !tag ) {
                r.append( s );
                r.append( h[i] );
                s.truncate();
            } else if ( tagname ) {
                t.append( h[i] );
            } else if ( !quoted && h[i] == '=' ) {
                a.truncate();
            } else {
                a.append( h[i] );
            }
            break;
        }

    next:
        last = h[i];
        i++;
    }

    return r;
}
