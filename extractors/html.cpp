// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "html.h"

#include "entities.h"


/*! \class HTML html.h
    This class is responsible for extracting indexable text from HTML.
    Its interface is subject to change once there are other classes to
    do the same thing for other formats.
*/


/*! Returns indexable text extracted from \a s. */

String HTML::asText( String h )
{
    String r;
    String t, s, qs, a;
    char last, quote;

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
            t = "";
            break;

        case '>':
            if ( quoted )
                goto next;
            if ( tag ) {
                t = t.lower();
                if ( t == "p" )
                    s = "\n\n";
                else if ( t == "br" )
                    s = "\n";
                else if ( t == "body" )
                    r = "";
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
                qs = "";
            }
            break;

        case ' ':
        case '\t':
        case '\r':
        case '\n':
            /* Whitespace shouldn't appear in last, and we compress it
               to one space. */
            if ( !tag && s.isEmpty() )
                s = " ";
            tagname = false;
            a = "";
            i++;
            continue;
            break;

#if 0
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
                    r = r + s + QChar( h.mid( mark, i-mark ).toUInt() );
                    s = "";

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
                        r = r + s +
                            QChar( h.mid( mark, i-mark ).toUInt( 0, 16 ) );
                        s = "";
                    }
                    if ( h[i] != ';' )
                        i--;
                }
                else {
                    /* Not a reference. */
                    i++;
                    r = r + s + "&#";
                    s = "";
                }
            } else if ( isalpha( c ) ) {
                /* Entity reference: &[a-zA-Z0-9]+;? */
                int m, l = 0, u = ents - 1;
                struct entity *p = 0;
                String ent;

                i++;
                mark = i++;
                while ( isalnum( h[i] ) )
                    i++;
                ent = h.mid( mark, i-mark );
                if ( h[i] != ';' )
                    i--;

                if ( !sorted ) {
                    qsort( entities, ents, sizeof( entities[0] ), _cmp_ent );
                    sorted = 1;
                }

                /* Binary search for the named entity. */
                do {
                    int n;

                    m = (l + u)/2;
                    n = strcmp( entities[m].name, ent );

                    if ( n < 0 )
                        l = m + 1;
                    else if ( n > 0 )
                        u = m - 1;
                    else {
                        p = &entities[m];
                        break;
                    }
                } while ( l <= u );

                if ( p ) {
                    r = r + s + QChar( p->chr );
                    s = "";
                }
            }
            else {
                /* Not a reference. */
                r = r + s + '&';
                s = "";
            }
            break;
#endif

    unspecial:
        default:
            if ( !tag ) {
                r.append( s );
                r.append( h[i] );
                s = "";
            } else if ( tagname ) {
                t.append( h[i] );
            } else if ( !quoted && h[i] == '=' ) {
                a = "";
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
