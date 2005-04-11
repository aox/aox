// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "address.h"

#include "dict.h"


class AddressData
{
public:
    uint id;
    String name;
    String localpart;
    String domain;
};


/*! \class Address address.h
    The Address class represents one e-mail address.

    All aspects of e-mail addresses are emulated, mostly except
    address groups. Address groups can exist, but only as empty groups
    ("internet-drafts:;"). (An empty address group is an address with a
    name() but without a localpart() or a domain().)

    Domains are kept as naked strings, and there is as yet no attempt
    to make this fit nicely in the database.
*/


/*  The following should all result in the same set of addresses:

    Set 1:
    To: ams@oryx.com (Abhijit Menon-Sen)
    To: Abhijit Menon-Sen <ams@oryx.com>
    To: "Abhijit Menon-Sen" <ams@oryx.com>
    To: "'Abhijit Menon-Sen'" <ams@oryx.com>
    To: =?us-ascii?q?Abhijit?= =?us-ascii?q?=20Menon=2DSen?= <ams@oryx.com>
    To: Abhijit Menon-Sen <ams@Oryx.COM>
    To: Abhijit Menon-Sen <ams@oryx.com (stuff)>
    To: Abhijit Menon-Sen <ams@oryx.com> (stuff)

    Set 2:
    To: ams@oryx.com
    To: <ams@oryx.com>
    To: "ams@oryx.com" <ams@oryx.com>
    To: "'ams@oryx.com'" <ams@oryx.com>
    To: "'ams@oryx.com'" <ams@ORYX.COM>
    To: computer-wallahs:ams@oryx.com;

    That is, duplicates are eliminated, domains are treated properly,
    groups are opened, antioutlookery is unfucked, etc. However, the
    next three to fields are not the same as any of the above:

    To: ams@oryx.com, other-recipients:;
    To: AMS@oryx.com
    To: Ambitious Manager wearing Suits <ams@oryx.com>

    At the time of writing, the implementation differs somewhat from
    the ideal described in this comment.
*/


/*!  Constructs an empty Address. */

Address::Address()
    : d( new AddressData )
{
    d->id = 0;
}


/*!  Constructs an address whose display-name is \a n, whose localpart
    is \a l and whose domain is \a o.
*/

Address::Address( const String &n, const String &l, const String &o )
    : d( new AddressData )
{
    d->id = 0;
    d->name = n;
    d->localpart = l;
    d->domain = o;
}


/*!  Constructs a copy of \a other. */

Address::Address( const Address & other )
    : d( 0 )
{
    *this = other;
}


/*! Destroys the object and frees any allocated resources. */

Address::~Address()
{
    delete d;
}


Address & Address::operator=( const Address & other )
{
    d = other.d;
    return *this;
}


/*! Returns the numeric ID of this address object in the database, or 0
    if it is not known.
*/

uint Address::id() const
{
    return d->id;
}


/*! Sets the numeric ID of this address object to \a id. This is only
    meant to be used by the AddressQuery class when it retrieves the
    ID from the database.
*/

void Address::setId( uint id )
{
    d->id = id;
}


/*! Returns the name stored in this Address. The name is the RFC2822
    display-part, or in case of memberless groups, the display-name of
    the group.

    A memberless group is stored as an Address whose localpart() and
    domain() are both empty.
*/

String Address::name() const
{
    return d->name;
}


/*! Returns the localpart stored in this Address. In case of a
    memberless group, localpart() returns an empty string.
*/

String Address::localpart() const
{
    return d->localpart;
}


/*! Returns the domain stored in this Address. In case of a memberless
    group, domain() returns an empty string.
*/

String Address::domain() const
{
    return d->domain;
}


static String qhack( const String & s )
{
    bool atom = true;
    uint i = 0;
    while ( atom && i < s.length() ) {
        // source: 2822 section 3.2.4
        if ( ( s[i] >= 'a' && s[i] <= 'z' ) ||
             ( s[i] >= 'A' && s[i] <= 'Z' ) ||
             ( s[i] >= '0' && s[i] <= '9' ) ||
             s[i] == '!' || s[i] == '#' || s[i] == '$' || s[i] == '%' ||
             s[i] == '&' || s[i] == '\''|| s[i] == '*' || s[i] == '+' ||
             s[i] == '-' || s[i] == '/' || s[i] == '=' || s[i] == '?' ||
             s[i] == '^' || s[i] == '_' || s[i] == '`' || s[i] == '{' ||
             s[i] == '|' || s[i] == '}' || s[i] == '~' ||
             // extra
             s[i] == ' ' ) {
            // still an atom
        }
        else {
            atom = false;
        }
        i++;
    }

    if ( atom )
        // it was all atoms, return it as-is
        return s;

    String r( "\"" );
    i = 0;
    while ( i < s.length() ) {
        if ( s[i] == '"' || s[i] == '\\' )
            r.append( '\\' );
        r.append( s[i] );
        i++;
    }
    r.append( '"' );
    return r;
}


/*! Returns an RFC 2822 representation of this address.  This should
    do RFC 2047 encoding, but currently does not. We fix that when we
    add unicode strings.
*/

String Address::toString() const
{
    String r;
    if ( !valid() ) {
        // it's not valid at all
    }
    else if ( d->name.isEmpty() ) {
        // it's a naked address
        r = d->localpart + "@" + d->domain;
    }
    else if ( d->localpart.isEmpty() ) {
        // it's a memberless group
        r = d->name + ":;";
    }
    else {
        // it's a fully-fledged name.
        r = qhack( d->name ) + " <" + d->localpart + "@" + d->domain + ">";
        // qhack is rather incomplete. solve it properly later.
    }
    return r;
}


/*! Returns true if this Address is a meaningful object, or false if
    its content is meaningless.
*/

bool Address::valid() const
{
    if ( d->name.isEmpty() && d->localpart.isEmpty() )
        return false;
    if ( !d->localpart.isEmpty() && d->domain.isEmpty() )
        return false; // just for sanity
    return true;
}


/*! Sets this Address to have name \a n, overwriting whatever was
    there before.
*/

void Address::setName( const String & n )
{
    d->name = n;
}


class AddressParserData
{
public:
    AddressParserData() {}

    String s;
    String e;
    List<Address> a;
    String lastComment;
};


/*! \class AddressParser address.h
    The AddressParser class helps parse email addresses and lists.

    In the interests of simplicity, AddressParser parses everything as
    if it were a list of addresses - either of the mailbox-list or
    address-list productions in RFC2822. The user of this class must
    check that the supplied addresses fit the (often more specific)
    requirements.

    AddressParser supports most of RFC822 and 2822, but mostly omits
    address groups. An empty address group is translated into a single
    Address, a nonempty group is translated into the equivalent number
    of addresses.

    AddressParser does not attempt to canonicalize the addresses
    parsed or get rid of duplicates (To: ams@oryx.com, ams@ory.com),
    it only parses.

    The first error seen is stored and can be accessed using error().
*/




/*
address         =       mailbox / group
mailbox         =       name-addr / addr-spec
name-addr       =       [display-name] angle-addr
angle-addr      =       [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
group           =       display-name ":" [mailbox-list / CFWS] ";"
                        [CFWS]
display-name    =       phrase
mailbox-list    =       (mailbox *("," mailbox)) / obs-mbox-list
address-list    =       (address *("," address)) / obs-addr-list
addr-spec       =       local-part "@" domain
local-part      =       dot-atom / quoted-string / obs-local-part
domain          =       dot-atom / domain-literal / obs-domain
domain-literal  =       [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
dcontent        =       dtext / quoted-pair
dtext           =       NO-WS-CTL /     ; Non white space controls
                        %d33-90 /       ; The rest of the US-ASCII
                        %d94-126        ;  characters not including "[",
                                        ;  "]", or "\"
obs-angle-addr  =       [CFWS] "<" [obs-route] addr-spec ">" [CFWS]
obs-route       =       [CFWS] obs-domain-list ":" [CFWS]
obs-domain-list =       "@" domain *(*(CFWS / "," ) [CFWS] "@" domain)
obs-local-part  =       word *("." word)
obs-domain      =       atom *("." atom)
obs-mbox-list   =       1*([mailbox] [CFWS] "," [CFWS]) [mailbox]
obs-addr-list   =       1*([address] [CFWS] "," [CFWS]) [address]

*/



/*! Constructs an Address Parser parsing \a s. After construction,
    addresses() and error() may be accessed immediately.
*/

AddressParser::AddressParser( String s )
    : d( new AddressParserData )
{
    d->s = s;
    int i = s.length()-1;
    int j = i+1;
    while ( i >= 0 && i < j ) {
        j = i;
        address( i );
        if ( i < j && i >= 0 && s[i] == ',' )
            i--;
    }
    Address::uniquify( &d->a );
    if ( i >= 0 ) {
        // there's stuff left over that we can't parse
    }
}


/*! Destroys the object. */

AddressParser::~AddressParser()
{
    delete d;
}



/*! Returns the first error detected (and not compensated) this parser. */

String AddressParser::error() const
{
    return d->e;
}


/*! Returns a pointer to the addresses parsed. The pointer remains
    valid until this object is deleted.
*/

List<Address> * AddressParser::addresses() const
{
    return &d->a;
}


/*! This private helper adds the address with \a name, \a localpart
    and \a domain to the list, unless it's there already.

    \a name is adjusted heuristically.
*/

void AddressParser::add( String name,
                         const String & localpart,
                         const String & domain )
{
    // if the localpart is too long, reject the add()
    if ( localpart.length() > 128 ) {
        if ( d->e.isEmpty() )
            d->e = "Localpart too long (" +
                   fn( localpart.length() ) +
                   " characters, RFC2821's maximum is 64): " +
                   localpart + "@" + domain;
        return;
    }
    // anti-outlook hackery, step 1: remove extra surrounding quotes
    uint i = 0;
    while ( i < name.length()-1 &&
            name[i] == name[name.length()-1-i] &&
            ( name[i] == '\'' || name[i] == '"' ) )
        i++;
    if ( i > 0 )
        name = name.mid( i, name.length() - 2*i ).simplified();
    // step 2: if the name is the same as the address, kill it.
    if ( ( name.lower() == localpart.lower()+"@"+domain.lower() ) ||
         ( name.lower() == localpart.lower() ) )
        name = "";

    Address * a = new Address( name, localpart, domain );
    d->a.prepend( a );
}


/*! This static function parses the references field \a r. This is in
    AddressParser because References and Message-ID both use the
    address productions in RFC 822/1034.

*/

AddressParser * AddressParser::references( const String & r )
{
    AddressParser * ap = new AddressParser( "" );
    ap->d->s = r;
    bool ok = true;
    int i = r.length() - 1;
    ap->comment( i );
    while ( ok && i > 0 && r[i] == '>' ) {
        i--;
        String dom = ap->domain( i );
        if ( r[i] == '<' ) {
            // Some people send illegal message-ids, the most common
            // being "<no.id>". We cater to it for the time being. In
            // References we handle it by ignoring it.
            i--;
        }
        else {
            if ( r[i] != '@' )
                ok = false;
            i--;
            String lp = ap->localpart( i );
            if ( r[i] != '<' )
                ok = false;
            i--;
            ap->comment( i );
            if ( dom.isEmpty() || lp.isEmpty() )
                ok = false;
            if ( ok )
                ap->add( 0, lp, dom );
        }
    }
    if ( !ok || i >= 0 )
        ap->error( "Syntax error", i );
    return ap;
}


/*! This private function parses an address ending at position \a i
    and adds it to the list.
*/

void AddressParser::address( int & i )
{
    // we're presumably looking at an address
    d->lastComment = "";
    comment( i );
    String & s = d->s;
    if ( i < 0 ) {
        // nothing there. error of some sort.
    }
    else if ( s[i] == '>' ) {
        // name-addr
        i--;
        String dom = domain( i );
        String lp;
        String name;
        if ( s[i] == '@' ) {
            i--;
            lp = localpart( i );
        }
        if ( i >= 0 && s[i] == ':' ) {
            i--;
            String rdom;
            do {
                rdom = domain( i );
                if ( i < 0 || s[i] != '@' )
                    error( "no @ preceding route-addr", i );
                else
                    i--;
            } while ( i >= 0 && s[i] != '<' && !rdom.isEmpty() );
        }
        if ( s[i] == '<' ) {
            i--;
            name = phrase( i );
        }
        if ( !dom.isEmpty() && !lp.isEmpty() ) {
            add( name, lp, dom );
        }
        else {
            if ( dom.isEmpty() )
                error( "Empty domain", i );
            if ( lp.isEmpty() )
                error( "Empty localpart ", i );
        }
    }
    else if ( s[i] == ';' ) {
        // group
        bool empty = true;
        int j = i;
        i--;
        while ( i != j && i > 0 && s[i] != ':' ) {
            j = i;
            address( i );
            empty = false;
            if ( i == j ) {
                error( "No progress while parsing addresses in group", i );
                return;
            }
        }
        if ( s[i] == ':' ) {
            i--;
            String name = phrase( i );
            if ( empty )
                add( name, 0, 0 );
        }
    }
    else {
        // addr-spec
        String name = d->lastComment;
        String dom = domain( i );
        String lp;
        if ( s[i] == '@' ) {
            i--;
            lp = localpart( i );
        }
        if ( dom.isEmpty() )
            error( "Empty domain", i );
        else if ( lp.isEmpty() )
            error( "Empty localpart ", i );
        else
            add( name, lp, dom );
    }
    comment( i );
}



/*! This private function skips past space at position \a i, or past
    nothing. Nothing is perfectly okay.
*/

void AddressParser::space( int & i )
{
    while ( i >= 0 && ( d->s[i] == 32 || d->s[i] == 9 ||
                        d->s[i] == 13 || d->s[i] == 10 ) )
        i--;
}


/*! This private function skips past a sequence of spaces and comments
    at \a i, or past nothing. Nothing is perfectly okay.
*/

void AddressParser::comment( int & i )
{
    space( i );
    while ( i >= 0 && d->s[i] == ')' ) {
        int j = i;
        // ctext    = NO-WS-CTL /     ; Non white space controls
        //
        //            %d33-39 /       ; The rest of the US-ASCII
        //            %d42-91 /       ;  characters not including "(",
        //            %d93-126        ;  ")", or "\"
        //
        // ccontent = ctext / quoted-pair / comment
        //
        // comment  = "(" *([FWS] ccontent) [FWS] ")"
        --i;
        ccontent( i );
        if ( d->s[i] != '(' )
            error( "Unbalanced comment: ", i );
        else
            d->lastComment = unqp( d->s.mid( i+1, j-i-1 ) );
        --i;
        space( i );
    }
}


/*! This very private helper helps comment() handle nested
    comments. It advances \a i to the start of a comment (where it
    points to '(').
*/

void AddressParser::ccontent( int & i )
{
    while ( true ) {
        if ( i > 0 && d->s[i-1] == '\\' )
            i--;
        else if ( d->s[i] == ')' )
            comment( i );
        else if ( d->s[i] == '(' )
            return;

        if ( i == 0 )
            return;
        i--;
    }
}


/*! This static helper removes quoted-pair from \a s and turns all
    sequences of spaces into a single space. It returns the result.
*/

String AddressParser::unqp( const String & s )
{
    bool sp = false;
    String r;
    uint j = 0;
    while ( j < s.length() ) {
        if ( s[j] == ' ' || s[j] == 9 ||
             s[j] == 10 || s[j] == 13 ) {
            sp = true;
            while( s[j] == ' ' || s[j] == 9 ||
                   s[j] == 10 || s[j] == 13 )
                j++;
        }
        else {
            if ( sp )
                r.append( " " );
            sp = false;
            if ( s[j] == '\\' ) {
                j++;
                r.append( s[j] );
                j++;
            }
            else {
                r.append( s[j] );
                j++;
            }
        }
    }
    return r;
}


/*! This private function picks up a domain ending at \a i and returns
    it as a string. The validity of the domain is not checked (and
    should not be - it may come from an old mail message) only its
    syntactical validity.
*/

String AddressParser::domain( int & i )
{
    comment( i );

    //domain         = dot-atom / domain-literal / obs-domain
    //domain-literal = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
    //dcontent       = dtext / quoted-pair
    //dtext          = NO-WS-CTL /     ; Non white space controls
    //                 %d33-90 /       ; The rest of the US-ASCII
    //                 %d94-126        ;  characters not including "[",
    //                                 ;  "]", or "\"

    String dom;
    if ( i < 0 )
        return dom;

    if ( d->s[i] == ']' ) {
        i--;
        int j = i;
        while ( i >= 0 && d->s[i] != '[' )
            i--;
        if ( i > 0 ) {
            i--;
            // copy the string we fetched, turn FWS into a single
            // space and unquote quoted-pair. we parse forwards here
            // because of quoted-pair.
            dom = unqp( d->s.mid( i+1, j-i+1 ) );
        }
        else {
            error( "literal domain missing [", i );
        }
    }
    else {
        // atoms, separated by '.' and (obsoletely) spaces. the spaces
        // are stripped.
        dom = atom( i );
        comment( i );
        while( i >= 0 && d->s[i] == '.' ) {
            i--;
            dom = atom( i ) + "." + dom;
        }
        if ( dom.isEmpty() )
            error( "zero-length domain", i );
    }

    return dom;
}


/*! This private function parses and returns the atom ending at \a i. */

String AddressParser::atom( int & i )
{
    comment( i );
    int j = i;
    String & s = d->s;
    while ( i >= 0 &&
            ( s[i] >= 'a' && s[i] <= 'z' ) ||
            ( s[i] >= 'A' && s[i] <= 'Z' ) ||
            ( s[i] >= '0' && s[i] <= '9' ) ||
            s[i] == '!' || s[i] == '#' ||
            s[i] == '$' || s[i] == '%' ||
            s[i] == '&' || s[i] == '\'' ||
            s[i] == '*' || s[i] == '+' ||
            s[i] == '-' || s[i] == '/' ||
            s[i] == '=' || s[i] == '?' ||
            s[i] == '^' || s[i] == '_' ||
            s[i] == '`' || s[i] == '{' ||
            s[i] == '|' || s[i] == '}' ||
            s[i] == '~' )
        i--;
    String r = s.mid( i+1, j-i );
    comment( i );
    return r;
}


/*! This private function parses an RFC 2822 phrase (a sequence of
    words, more or less) ending at \a i, and returns the phrase as a
    string.

    No RFC 2047 decoding is done by this function; that has to be
    handled by upper layers to conform to the RFC.
*/

String AddressParser::phrase( int & i )
{
    String r;
    comment( i );
    bool done = false;
    while ( !done ) {
        String tmp;
        if ( i > 0 && d->s[i] == '"' ) {
            // quoted stuff
            i--;
            int j = i;
            do {
                j = i;
                if ( i >= 0 && d->s[i] != '"' && d->s[i] != '\\' ) {
                    tmp = d->s.mid( i, 1 ) + tmp;
                    i--;
                }
                else if ( i > 0 && d->s[i-1] == '\\' ) {
                    tmp = d->s.mid( i, 1 ) + tmp;
                    i = i - 2;
                }
            } while ( i < j );
            if ( i < 0 || d->s[i] != '"' )
                error( "quoted phrase must begin with '\"'", i );
            else
                i--;
        }
        else if ( d->s[i] == '.' ) {
            // obs-phrase allows a single dot as alternative to word.
            // we allow atom "." as an alternative, too, to handle
            // initials.
            i--;
            tmp = atom( i ) + ".";
        }
        else {
            // single word
            tmp = atom( i );
            if ( tmp.isEmpty() )
                done = true;
        }
        if ( r.isEmpty() )
            r = tmp;
        else if ( tmp.endsWith( " " ) )
            r = tmp + r;
        else if ( !tmp.isEmpty() )
            r = tmp + " " + r;
    }
    return r;
}


/*! This private function parses the localpart ending at \a i, and
    returns it as a string.
*/

String AddressParser::localpart( int & i )
{
    // code copied from domain and calling phrase. separate this out
    // for easier testing.
    String lp;
    if ( d->s[i] == '"' ) {
        lp = phrase( i ); // ick.
    }
    else {
        // atoms, separated by '.' and (obsoletely) spaces. the spaces
        // are stripped.
        lp = atom( i );
        comment( i );
        while( i >= 0 && d->s[i] == '.' ) {
            i--;
            lp = atom( i ) + "." + lp;
        }
    }
    return lp;
}


/*! This private function records the error \a s, which is considered
    to occur at position \a i.

    The name error() is overloaded, nastily. But I don't feel like
    fixing that right now.
*/

void AddressParser::error( const char * s, int i )
{
    if ( d->e.isEmpty() )
        d->e = String( s ) + " at position " + fn( i > 0 ? i : 0 ) +
               " (text ...'" + d->s.mid( i, 20 ).simplified() + "'...)";
}


static String key( Address * a )
{
    return a->name() + " " + a->localpart() + "@" + a->domain().lower();
}


/*! Removes any addresses from \a l that exist twice in the list. */

void Address::uniquify( List<Address> * l )
{
    if ( !l || l->isEmpty() )
        return;

    Dict<Address> unique;
    
    List<Address>::Iterator it( l->first() );
    while ( it ) {
        Address *a = it;
        ++it;
        String k = key( a );
        if ( !unique.contains( k ) ) {
            unique.insert( k, a );
            if ( !a->name().isEmpty() ) {
                k = " " + a->localpart() + "@" + a->domain().lower();
                unique.insert( k, a );
            }
        }
    }
    it = l->first();
    while ( it ) {
        List<Address>::Iterator a = it;
        ++it;
        if ( unique.find( key( a ) ) != a )
            l->take( a );
    }
}
