// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "address.h"

#include "field.h"
#include "estringlist.h"
#include "ustringlist.h"
#include "endpoint.h"
#include "ustring.h"
#include "parser.h"
#include "cache.h"
#include "dict.h"
#include "ace.h"
#include "utf.h"


class AddressData
    : public Garbage
{
public:
    AddressData(): id( 0 ), type( Address::Invalid ) {}

    uint id;
    UString name;
    UString localpart;
    UString domain;
    Address::Type type;
    EString error;
};


/*! \class Address address.h
    The Address class represents one e-mail address.

    All aspects of e-mail addresses are emulated, mostly except
    address groups.

    Address groups can exist, but only as empty groups
    ("internet-drafts:;"). (An empty address group is an address with
    a name() but without a localpart() or a domain().)

    The un-address <> can be parsed and represented; both its name(),
    localpart() and domain() are empty. Local-only addresses
    (e.g. "root") are accepted, because so much legacy software
    generated it, and some even generates it still.

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


/*!  Constructs an empty invalid Address. */

Address::Address()
    : d( new AddressData )
{
}


/*!  Constructs an address whose display-name is \a n, whose localpart
    is \a l and whose domain is \a o.
*/

Address::Address( const UString &n, const EString &l, const EString &o )
    : d( 0 )
{
    AsciiCodec a;
    init( n, a.toUnicode( l ), a.toUnicode( o ) );
}


/*! Constructs an address whose display-name is \a n, whose localpart
 *  is \a l and whose domain is \a o.

*/

Address::Address( const UString & n, const UString & l, const UString & o )
    : d( 0 )
{
    init( n, l, o );
}


class AddressCache
    : public Cache
{
public:
    AddressCache(): Cache( 8 ) {}
    void clear() { step1.clear(); }
    UDict< UDict< UDict<AddressData> > > step1;
};

static AddressCache * cache = 0;


/*! This private function contains the shared part of the
    constructors, initialising the object with the display-name \a n,
    localpart \a l, and domain \a o and an appropriate type(). Uses a
    cache to try to share the id() with other instances of the same
    address.
*/

void Address::init( const UString &n, const UString &l, const UString &o )
{
    if ( !::cache )
        ::cache = new AddressCache;

    UString dl( ACE::decode( o.titlecased() ) );
    UDict< UDict<AddressData> > * step2 = ::cache->step1.find( dl );
    if ( !step2 ) {
        step2 = new UDict< UDict<AddressData> >;
        ::cache->step1.insert( dl, step2 );
    }
    UDict<AddressData> * step3 = step2->find( l );
    if ( !step3 ) {
        step3 = new UDict<AddressData>;
        step2->insert( l, step3 );
    }
    d = step3->find( n );
    if ( !d ) {
        d = new AddressData;
        d->name = n;
        d->localpart = l;
        d->domain = o;
        if ( !d->domain.isEmpty() )
            d->type = Normal;
        else if ( !d->localpart.isEmpty() )
            d->type = Local;
        else if ( !d->name.isEmpty() )
            d->type = EmptyGroup;
        else if ( d->name.isEmpty() &&
                  d->localpart.isEmpty() &&
                  d->domain.isEmpty() )
            d->type = Bounce;
        step3->insert( n, d );
    }
}


/*!  Constructs a copy of \a other. */

Address::Address( const Address & other )
    : Garbage(), d( 0 )
{
    *this = other;
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


/*! Returns the name stored in this Address. The name is the RFC 2822
    display-part, or in case of memberless groups, the display-name of
    the group.

    A memberless group is stored as an Address whose localpart() and
    domain() are both empty.
*/

EString Address::name( bool avoidUtf8 ) const
{
    bool atom = true;
    bool ascii = true;

    uint i = 0;
    while ( i < d->name.length() ) {
        int c = d->name[i];

        // source: 2822 section 3.2.4
        if ( ( c >= 'a' && c <= 'z' ) ||
             ( c >= 'A' && c <= 'Z' ) ||
             ( c >= '0' && c <= '9' ) ||
             c == '!' || c == '#' || c == '$' || c == '%' ||
             c == '&' || c == '\''|| c == '*' || c == '+' ||
             c == '-' || c == '/' || c == '=' || c == '?' ||
             c == '^' || c == '_' || c == '`' || c == '{' ||
             c == '|' || c == '}' || c == '~' ||
             // extra
             c == ' ' )
        {
            // still an atom
        }
        else if ( c >= 128 ) {
            ascii = false;
            if ( avoidUtf8 )
                atom = false;

        }
        else {
            atom = false;
        }

        i++;
    }

    if ( atom || i == 0 )
        return d->name.utf8();

    if ( ascii || !avoidUtf8 )
        return d->name.utf8().quoted( '"', '\\' );

    return HeaderField::encodePhrase( d->name );
}


/*! Returns the canonical name belonging to this address.
*/

UString Address::uname() const
{
    return d->name;
}


/*! Returns the localpart stored in this Address. In case of a
    memberless group, localpart() returns an empty string.
*/

UString Address::localpart() const
{
    return d->localpart;
}


/*! Returns the domain stored in this Address. In case of a memberless
    group, domain() returns an empty string.
*/

UString Address::domain() const
{
    return d->domain;
}


/*! Returns the localpart and domain as a EString. Returns toString()
    if the type() isn't Normal or Local.
*/

EString Address::lpdomain() const
{
    EString r;
    if ( type() == Normal ||
         type() == Local ) {
        if ( localpartIsSensible() )
            r = d->localpart.utf8();
        else
            r = d->localpart.utf8().quoted();
    }
    if ( type() == Normal ) {
        r.append( "@" );
        r.append( d->domain.utf8() );
    }
    if ( r.isEmpty() )
        r = toString( false );
    return r;
}


/*! Returns an RFC 2822 representation of this address. If \a
    avoidUtf8 is present and true (the default is false), toString()
    returns an address which avoids UTF-8 at all costs, even if that
    loses information.
*/

EString Address::toString( bool avoidUtf8 ) const
{
    EString r;
    switch( type() ) {
    case Invalid:
        r = "";
        break;
    case Bounce:
        r = "<>";
        break;
    case EmptyGroup:
        r = name(true) + ":;";
        break;
    case Local:
        if ( avoidUtf8 && needsUnicode() )
            r = "this-address@needs-unicode.invalid";
        else if ( localpartIsSensible() )
            r = d->localpart.utf8();
        else
            r = d->localpart.utf8().quoted();
        break;
    case Normal:
        if ( avoidUtf8 && needsUnicode() ) {
            r = "this-address@needs-unicode.invalid";
        }
        else {
            EString postfix;
            if ( !d->name.isEmpty() ) {
                r.append( name( avoidUtf8 ) );
                r.append( " <" );
                postfix = ">";
            }
            if ( localpartIsSensible() )
                r.append( d->localpart.utf8() );
            else
                r.append( d->localpart.utf8().quoted() );
            r.append( "@" );
            r.append( d->domain.utf8() );
            r.append( postfix );
        }
        break;
    }
    return r;
}


/*! \fn bool Address::valid() const

    Returns true if this Address is a meaningful object, or false if
    its content is meaningless.
*/


static struct {
    int length;
    const char * name;
} tld[] = {
#include "tld.inc"
    { 0, "" }
};


class AddressParserData
    : public Garbage
{
public:
    AddressParserData() {}

    EString s;
    EString firstError;
    EString recentError;
    List<Address> a;
    EString lastComment;
};


/*! \class AddressParser address.h
    The AddressParser class helps parse email addresses and lists.

    In the interests of simplicity, AddressParser parses everything as
    if it were a list of addresses - either of the mailbox-list or
    address-list productions in RFC 2822. The user of this class must
    check that the supplied addresses fit the (often more specific)
    requirements.

    AddressParser supports most of RFC 822 and 2822, but mostly omits
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

AddressParser::AddressParser( EString s )
    : d( new AddressParserData )
{
    d->s = s;
    int i = s.length()-1;
    int j = i+1;
    bool colon = s.contains( ':' );
    while ( i >= 0 && i < j ) {
        j = i;
        address( i );
        while ( i < j && i >= 0 &&
                ( s[i] == ',' ||
                  ( !colon && s[i] == ';' ) ) ) {
            i--;
            space( i );
        }
    }
    Address::uniquify( &d->a );
    if ( i < 0 && d->firstError.isEmpty() )
        return;

    // Plan B: Look for '@' signs and scan for addresses around
    // them. Use what's there.
    d->a.clear();
    int leftBorder = 0;
    int atsign = s.find( '@');
    while ( atsign >= 0 ) {
        int nextAtsign = s.find( '@', atsign + 1 );
        int rightBorder;
        if ( nextAtsign < 0 )
            rightBorder = s.length();
        else
            rightBorder = findBorder( atsign + 1, nextAtsign - 1 );
        if ( leftBorder > 0 &&
             ( d->s[leftBorder] == '.' || d->s[leftBorder] == '>' ) )
            leftBorder++;
        int end = atsign + 1;
        while ( end <= rightBorder && s[end] == ' ' )
            end++;
        while ( end <= rightBorder &&
                ( ( s[end] >= 'a' && s[end] <= 'z' ) ||
                  ( s[end] >= 'A' && s[end] <= 'Z' ) ||
                  ( s[end] >= '0' && s[end] <= '9' ) ||
                  s[end] == '.' ||
                  s[end] == '-' ) )
            end++;
        int start = atsign;
        while ( start >= leftBorder && s[start-1] == ' ' )
            start--;
        while ( start >= leftBorder &&
                ( ( s[start-1] >= 'a' && s[start-1] <= 'z' ) ||
                  ( s[start-1] >= 'A' && s[start-1] <= 'Z' ) ||
                  ( s[start-1] >= '0' && s[start-1] <= '9' ) ||
                  s[start-1] == '.' ||
                  s[start-1] == '-' ) )
            start--;
        EString lp = s.mid( start, atsign - start ).simplified();
        EString dom = s.mid( atsign+1, end - atsign - 1 ).simplified();
        if ( !lp.isEmpty() && !dom.isEmpty() ) {
            AsciiCodec a;
            d->a.append( new Address( UString(),
                                      a.toUnicode( lp ),
                                      a.toUnicode( dom ) ) );
        }
        atsign = nextAtsign;
        leftBorder = rightBorder;
    }
    if ( !d->a.isEmpty() ) {
        d->firstError.truncate();
        d->recentError.truncate();
        Address::uniquify( &d->a );
        return;
    }

    // Plan C: Is it an attempt at group syntax by someone who should
    // rather be filling shelves at a supermarket?
    if ( s.contains( ":;" ) && !s.contains( "@" ) ) {
        EString n = s.mid( 0, s.find( ":;" ) ).simplified();
        UString name;
        uint j = 0;
        bool bad = false;
        while ( j < n.length() ) {
            if ( ( n[j] >= 'a' && n[j] <= 'z' ) ||
                 ( n[j] >= 'A' && n[j] <= 'Z' ) ||
                 ( n[j] >= '0' && n[j] <= '9' ) )
                name.append( n[j] );
            else if ( n[j] == ' ' || n[j] == '_' || n[j] == '-' )
                name.append( '-' );
            else
                bad = true;
            j++;
        }
        if ( !bad ) {
            d->firstError.truncate();
            d->recentError.truncate();
            AsciiCodec ac;
            Address * a = new Address( ac.toUnicode( n ),
                                       UString(), UString() );
            d->a.clear();
            d->a.append( a );
        }
    }
}


/*! Finds the point between \a left and \a right which is most likely
    to be the border between two addresses. Mucho heuristics. Never
    used for correct addresses, only when we're grasping at straws.

    Both \a left and \a right are considered to be possible borders,
    but a border between the extremes is preferred if possible.
*/

int AddressParser::findBorder( int left, int right )
{
    // if there's only one chance, that _is_ the border.
    if ( right <= left )
        return left;

    // comma?
    int b = d->s.find( ',', left );
    if ( b >= left && b <= right )
        return b;

    // semicolon? perhaps we should also guard against a dot?
    b = d->s.find( ';', left );
    if ( b >= left && b <= right )
        return b;

    // less-than or greater-than? To: <asdf@asdf.asdf><asdf@asdf.asdf>
    b = d->s.find( '<', left );
    if ( b >= left && b <= right )
        return b;
    b = d->s.find( '>', left );
    if ( b >= left && b <= right )
        return b;

    // whitespace?
    b = left;
    while ( b <= right &&
            d->s[b] != ' ' && d->s[b] != '\t' &&
            d->s[b] != '\r' && d->s[b] != '\n' )
        b++;
    if ( b >= left && b <= right )
        return b;

    // try to scan for end of the presumed right-hand-side domain
    b = left;
    int dot = b;
    while ( b <= right ) {
        bool any = false;
        while ( b <= right &&
                ( ( d->s[b] >= 'a' && d->s[b] <= 'z' ) ||
                  ( d->s[b] >= 'A' && d->s[b] <= 'Z' ) ||
                  ( d->s[b] >= '0' && d->s[b] <= '9' ) ||
                  d->s[b] == '-' ) ) {
            any = true;
            b++;
        }
        // did we see a domain component at all?
        if ( !any ) {
            if ( b > left && d->s[b-1] == '.' )
                return b-1; // no, but we just saw a dot, make that the border
            return b; // no, and no dot, so put the border here
        }
        if ( b <= right ) {
            // if we don't see a dot here, the domain cannot go on
            if ( d->s[b] != '.' )
                return b;
            dot = b;
            b++;
            // see if the next domain component is a top-level domain
            uint i = 0;
            while ( tld[i].length ) {
                if ( b + tld[i].length <= right ) {
                    char c = d->s[b + tld[i].length];
                    if ( !( c >= 'a' && c <= 'z' ) &&
                         !( c >= 'A' && c <= 'Z' ) &&
                         !( c >= '0' && c <= '9' ) ) {
                        if ( d->s.mid( b, tld[i].length ).lower() ==
                             tld[i].name )
                            return b + tld[i].length;
                    }
                }
                i++;
            }
        }
    }
    // the entire area is legal in a domain, but we have to draw the
    // line somewhere, so if we've seen one or more dots in the
    // middle, we use the rightmost dot.
    if ( dot > left && dot < right )
        return dot;

    // the entire area is a single word. what can we do?
    if ( right + 1 >= (int)d->s.length() )
        return right;
    return left;
}



/*! Returns the first error detected (and not compensated) this parser. */

EString AddressParser::error() const
{
    return d->firstError;
}


/*! Returns a pointer to the addresses parsed. The pointer remains
    valid until this object is deleted.
*/

List<Address> * AddressParser::addresses() const
{
    return &d->a;
}


/*! Asserts that addresses() should return a list of a single regular
    fully-qualified address. error() will return an error message if
    that isn't the case.
*/

void AddressParser::assertSingleAddress()
{
    uint normal = 0;
    List<Address>::Iterator i( d->a );
    while ( i ) {
        if ( i->type() == Address::Normal ) {
            normal++;
            if ( normal > 1 )
                i->setError( "This is address no. " + fn( normal ) +
                             " of 1 allowed" );
        }
        else {
            i->setError( "Expected normal email address "
                         "(whatever@example.com), got " +
                         i->toString( false ) );
        }
        ++i;
    }

    i = d->a.first();
    while ( i ) {
        if ( !i->error().isEmpty() )
            error( i->error().cstr(), 0 );
        ++i;
    }

    if ( d->a.isEmpty() )
        error( "No address supplied", 0 );
}


/*! This private helper adds the address with \a name, \a localpart
    and \a domain to the list, unless it's there already.

    \a name is adjusted heuristically.
*/

void AddressParser::add( UString name,
                         const UString & localpart,
                         const UString & domain )
{
    // if the localpart is too long, reject the add()
    if ( localpart.length() > 256 ) {
        d->recentError = "Localpart too long (" +
                         fn( localpart.length() ) +
                         " characters, RFC 2821's maximum is 64): " +
                         localpart.utf8() + "@" + domain.utf8();
        if ( d->firstError.isEmpty() )
            d->firstError = d->recentError;
        return;
    }
    // anti-outlook hackery, step 1: remove extra surrounding quotes
    uint i = 0;
    while ( i < name.length()-1 &&
            ( name[i] == name[name.length()-1-i] &&
              ( name[i] == '\'' || name[i] == '"' ) ) )
        i++;
    if ( i > 0 )
        name = name.mid( i, name.length() - 2*i );

    // for names, we treat all whitespace equally. "a b" == " a   b "
    name = name.simplified();

    // sometimes a@b (c) is munged as (c) <a@b>, let's unmunge that.
    if ( name.length() > 1 && name[0] == '(' && name[name.length()-1] == ')' )
        name = name.mid( 1, name.length() - 2 ).simplified();

    // anti-outlook, step 2: if the name is the same as the address,
    // just kill it.
    UString an = name.titlecased();
    if ( an == localpart.titlecased() ||
         ( an.length() == localpart.length()+1+domain.length() &&
           an == localpart.titlecased()+"@"+domain.titlecased() ) )
        name.truncate();

    Address * a = new Address( name, localpart, domain );
    a->setError( d->recentError );
    d->a.prepend( a );
}


/*! This version of add() uses only \a localpart and \a domain. */

void AddressParser::add( const UString & localpart,
                         const UString & domain )
{
    UString n;
    add( n, localpart, domain );
}


/*! This static function parses the references field \a r. This is in
    AddressParser because References and Message-ID both use the
    address productions in RFC 822/1034.

    This function does it best to skip ahead to the next message-id if
    there is a syntax error in one. It silently ignores the
    errors. This is because it's so common to have a bad message-id in
    the references field of an otherwise impeccable message.
*/

AddressParser * AddressParser::references( const EString & r )
{
    AddressParser * ap = new AddressParser( "" );
    ap->d->s = r;
    int i = r.length() - 1;
    ap->comment( i );
    while ( i > 0 ) {
        int l = i;
        bool ok = true;
        UString dom;
        UString lp;
        if ( r[i] != '>' ) {
            ok = false;
        }
        else {
            i--;
            dom = ap->domain( i );
            if ( r[i] == '@' )
                i--;
            else
                ok = false;
            lp = ap->localpart( i );
            if ( r[i] == '<' )
                i--;
            else
                ok = false;
            ap->comment( i );
            if ( ap->d->s[i] == ',' ) {
                i--;
                ap->comment( i );
            }
        }
        if ( ok && !dom.isEmpty() && !lp.isEmpty() ) {
            ap->add( lp, dom );
        }
        else {
            i = l;
            i--;
            while ( i >= 0 && r[i] != ' ' )
                i--;
            ap->comment( i );
        }
    }
    ap->d->firstError = "";
    return ap;
}


/*! This private function parses an address ending at position \a i
    and adds it to the list.
*/

void AddressParser::address( int & i )
{
    // we're presumably looking at an address
    d->lastComment = "";
    d->recentError.truncate();
    comment( i );
    EString & s = d->s;
    while ( i > 0 && s[i] == ',' ) {
        i--;
        comment( i );
    }
    while ( i >= 0 && s[i] == '>' && s[i-1] == '>' ) {
        i--;
    }
    if ( i < 0 ) {
        // nothing there. error of some sort.
    }
    else if ( i > 0 && s[i-1] == '<' && s[i] == '>' ) {
        // the address is <>. whether that's legal is another matter.
        add( UString(), UString() );
        i = i - 2;
        if ( i >= 0 && s[i] == '<' )
            i--;
        (void)phrase( i );
    }
    else if ( i > 2 && s[i] == '>' && s[i-1] == ';' && s[i-2] == ':' ) {
        // it's a microsoft-broken '<Unknown-Recipient:;>'
        i = i - 3;
        UString name = phrase( i );
        add( name, UString(), UString() );
        if ( s[i] == '<' )
            i--;
    }
    else if ( i > 2 && s[i] == '>' && s[i-1] == ';' &&
              s.mid( 0, i ).contains( ":@" ) < i ) {
        // it may be a sendmail-broken '<Unknown-Recipient:@x.y;>'
        uint x = i;
        i = i - 2;
        (void)domain( i );
        if ( i > 1 && s[i] == '@' && s[i-1] == ':' ) {
            i = i - 2;
            UString name = phrase( i );
            add( name, UString(), UString() );
            if ( i >= 0 && s[i] == '<' )
                i--;
        }
        else {
            i = x;
        }
    }
    else if ( s[i] == '>' ) {
        // name-addr
        i--;
        UString dom = domain( i );
        UString lp;
        UString name;
        if ( s[i] == '<' ) {
            lp = dom;
            dom.truncate();
        }
        else {
            if ( s[i] == '@' ) {
                i--;
                while ( i > 0 && s[i] == '@' )
                    i--;

                int aftercomment = i;
                comment( i );
                if ( i >= 1 && s[i] == ';' ) {
                    int j = i-1;
                    while ( j > 0 && d->s[j] == ' ' )
                        j--;
                    if ( d->s[j] == ':' ) {
                        // <unlisted-recipients:; (no To-header on input)@do.ma.in>
                        j --;
                        UString n = phrase( j );
                        if ( !n.isEmpty() ) {
                            lp.truncate();
                            dom.truncate();
                            name = n;
                            i = j;
                        }
                    }
                }
                else if ( aftercomment > i && i < 0 ) {
                    // To: <(Recipient list suppressed)@localhost>
                    EString n = d->lastComment.simplified();
                    lp.truncate();
                    dom.truncate();
                    name.truncate();
                    uint j = 0;
                    while ( j < n.length() ) {
                        if ( ( n[j] >= 'a' && n[j] <= 'z' ) ||
                             ( n[j] >= 'A' && n[j] <= 'Z' ) ||
                             ( n[j] >= '0' && n[j] <= '9' ) )
                            name.append( n[j] );
                        else if ( n[j] == ' ' || n[j] == '_' || n[j] == '-' )
                            name.append( '-' );
                        else
                            error( "localpart contains parentheses", i );
                        j++;
                    }
                }
                else {
                    lp = localpart( i );
                    if ( s[i] != '<' ) {
                        int j = i;
                        while ( j >= 0 &&
                                ( ( s[j] >= 'a' && s[j] <= 'z' ) ||
                                  ( s[j] >= 'A' && s[j] <= 'Z' ) ||
                                  s[j] == ' ' ) )
                            j--;
                        if ( j >= 0 && s[j] == '<' ) {
                            Utf8Codec c;
                            UString tmp = c.toUnicode( s.mid( j + 1, i - j ) );
                            if ( s[i+1] == ' ' )
                                tmp.append( ' ' );
                            tmp.append( lp );
                            lp = tmp;
                            i = j;
                        }
                    }
                }
            }
            route( i );
        }
        if ( i >= 0 && s[i] == '<' ) {
            i--;
            while ( i >= 0 && s[i] == '<' )
                i--;
            UString n = phrase( i );
            while ( i >= 0 && ( s[i] == '@' || s[i] == '<' ) ) {
                // we're looking at an unencoded 8-bit name, or at
                // 'lp@domain<lp@domain>', or at 'x<y<z@domain>'. we
                // react to that by ignoring the display-name.
                i--;
                (void)phrase( i );
                n.truncate();
            }
            if ( !n.isEmpty() )
                name = n;
        }
        // if the display-name contains unknown-8bit or the
        // undisplayable marker control characters, we drop the
        // display-name.
        uint i = 0;
        while ( i < name.length() &&
                ( name[i] < 0xED80 || name[i] > 0xEDFF ) &&
                name[i] >= ' ' &&
                name[i] != 0xFFFD )
            i++;
        if ( i < name.length() )
            name.truncate();
        add( name, lp, dom );
    }
    else if ( i > 1 && s[i] == '=' && s[i-1] == '?' && s[i-2] == '>' ) {
        // we're looking at "=?charset?q?safdsafsdfs<a@b>?=". how ugly.
        i = i - 3;
        UString dom = domain( i );
        if ( s[i] == '@' ) {
            i--;
            while ( i > 0 && s[i] == '@' )
                i--;
            UString lp = localpart( i );
            if ( s[i] == '<' ) {
                i--;
                (void)atom( i ); // discard the "supplied" display-name
                add( lp, dom );
            }
            else {
                error( "Expected '<' while in "
                       "=?...?...<localpart@domain>?=", i );
                return;
            }
        }
        else {
            error( "Expected '@' while in "
                   "=?...?...<localpart@domain>?=", i );
            return;
        }
    }
    else if ( s[i] == ';' && s.mid( 0, i ).contains( ':' ) ) {
        // group
        bool empty = true;
        i--;
        comment( i );
        while ( i > 0 && s[i] != ':' ) {
            int j = i;
            address( i );
            empty = false;
            if ( i == j ) {
                error( "Parsing stopped while in group parser", i );
                return;
            }
            if ( s[i] == ',' ) {
                i--;
            }
            else if ( s[i] != ':' ) {
                error( "Expected : or ',' while parsing group", i );
                return;
            }

        }
        if ( s[i] == ':' ) {
            i--;
            UString name = phrase( i );
            if ( empty )
                add( name, UString(), UString() );
        }
    }
    else if ( s[i] == '"' && s.mid( 0, i ).contains( "%\"" ) ) {
        // quite likely we're looking at x%"y@z", as once used on vms
        int x = i;
        x--;
        UString dom = domain( x );
        if ( x > 0 && s[x] == '@' ) {
            x--;
            UString lp = localpart( x );
            if ( x > 2 && s[x] == '"' && s[x-1] == '%' ) {
                x = x - 2;
                (void)domain( x );
                add( lp, dom );
                i = x;
            }
        }
    }
    else if ( s[i] == '"' && s.mid( 0, i ).contains( "::" ) ) {
        // we may be looking at A::B "display-name"
        uint b = i-1;
        while ( b > 0 && s[b] != '"' )
            b--;
        AsciiCodec a;
        UString name;
        if ( s[b] == '"' ) {
            name = a.toUnicode( s.mid( b+1, i-b-1 ) );
            i = b - 1;
            if ( !a.wellformed() )
                name.truncate();
            name.truncate(); // do it anyway: we don't want name <localpart>.
        }
        UString lp = atom( i );
        if ( i > 2 && s[i] == ':' && s[i-1] == ':' ) {
            i = i - 2;
            lp = atom( i ) + "::" + lp;
            add( name, lp, UString() );
        }
        else {
            error( "Expected NODE::USER while parsing VMS address", i );
        }
    }
    else if ( i > 10 && s[i] >= '0' && s[i] <= '9' && s[i-2] == '.' &&
              s.contains( '"' ) && s.contains( "-19" ) ) {
        // we may be looking at A::B "display-name" date
        int x = i;
        while ( x > 0 && s[x] != '"' )
            x--;
        EString date = s.mid( x+1, i-x-1 ).lower().simplified();
        uint dp = 0;
        char c = date[0];
        while ( dp < date.length() &&
                ( ( c >= 'a' && c <= 'z' ) ||
                  ( c >= '0' && c <= '9' ) ||
                  c == ' ' || c == '-' ||
                  c == ':' || c == '.' ) )
            c = date[++dp];
        if ( dp == date.length() && date.contains( "-19" ) )
            // at least it resembles the kind of date field we skip
            i = x;
    }
    else if ( s.isQuoted() && s.contains( '@' ) ) {
        AddressParser wrapped( s.unquoted() );
        if ( wrapped.error().isEmpty() ) {
            // changes the address order...
            d->a.append( wrapped.addresses() );
            i = -1;
        }
        else {
            error( "Unexpected quote character", i );
        }
    }
    else {
        // addr-spec
        AsciiCodec a;
        UString name = a.toUnicode( d->lastComment );
        if ( !a.wellformed() || d->lastComment.contains( "=?" ) )
            name.truncate();
        UString dom = domain( i );
        UString lp;
        if ( s[i] == '@' ) {
            i--;
            while ( i > 0 && s[i] == '@' )
                i--;
            int aftercomment = i;
            comment( i );
            if ( i >= 1 && s[i] == ';' ) {
                int j = i-1;
                while ( j > 0 && d->s[j] == ' ' )
                    j--;
                if ( d->s[j] == ':' ) {
                    // unlisted-recipients:; (no To-header on input)@do.ma.in
                    j --;
                    UString n = phrase( j );
                    if ( !n.isEmpty() ) {
                        lp.truncate();
                        dom.truncate();
                        name = n;
                        i = j;
                    }
                }
            }
            else if ( aftercomment > i && i < 0 ) {
                // To: (Recipient list suppressed)@localhost
                EString n = d->lastComment.simplified();
                lp.truncate();
                dom.truncate();
                name.truncate();
                uint j = 0;
                while ( j < n.length() ) {
                    if ( ( n[j] >= 'a' && n[j] <= 'z' ) ||
                         ( n[j] >= 'A' && n[j] <= 'Z' ) ||
                         ( n[j] >= '0' && n[j] <= '9' ) )
                        name.append( n[j] );
                    else if ( n[j] == ' ' || n[j] == '_' || n[j] == '-' )
                        name.append( '-' );
                    else
                        error( "localpart contains parentheses", i );
                    j++;
                }
            }
            else {
                lp = localpart( i );
            }
        }
        else {
            lp = dom;
            dom.truncate();
        }
        route( i );
        comment( i );
        if ( !lp.isEmpty() || !dom.isEmpty() || !name.isEmpty() )
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
    while ( i > 0 && d->s[i] == ')' ) {
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
        if ( d->s[i] != '(' ) {
            error( "Unbalanced comment: ", i );
        }
        else {
            EmailParser p( d->s.mid( i, j+1-i ) );
            d->lastComment = p.comment();
        }
        if ( i )
            space( --i );
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

EString AddressParser::unqp( const EString & s )
{
    bool sp = false;
    EString r;
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

UString AddressParser::domain( int & i )
{
    comment( i );

    //domain         = dot-atom / domain-literal / obs-domain
    //domain-literal = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
    //dcontent       = dtext / quoted-pair
    //dtext          = NO-WS-CTL /     ; Non white space controls
    //                 %d33-90 /       ; The rest of the US-ASCII
    //                 %d94-126        ;  characters not including "[",
    //                                 ;  "]", or "\"

    UString dom;
    if ( i < 0 )
        return dom;

    Utf8Codec c;

    if ( d->s[i] >= '0' && d->s[i] <= '9' ) {
        // scan for an unquoted IPv4 address and turn that into an
        // address literal if found.
        int j = i;
        while ( ( d->s[i] >= '0' && d->s[i] <= '9' ) || d->s[i] == '.' )
            i--;
        Endpoint test( d->s.mid( i+1, j-i ), 1 );
        if ( test.valid() )
            return c.toUnicode( "[" + test.address() + "]" );
        i = j;
    }

    if ( d->s[i] == ']' ) {
        i--;
        int j = i;
        while ( i >= 0 && d->s[i] != '[' )
            i--;
        if ( i > 0 ) {
            i--;
            // copy the string we fetched, turn FWS into a single
            // space and unquote quoted-pair. we parse forward here
            // because of quoted-pair.
            dom = c.toUnicode( unqp( d->s.mid( i+1, j-i+1 ) ) );
        }
        else {
            error( "literal domain missing [", i );
        }
    }
    else {
        // atoms, separated by '.' and (obsoletely) spaces. the spaces
        // are stripped.
        UStringList atoms;

        atoms.append( atom( i ) );
        comment( i );
        while( i >= 0 && d->s[i] == '.' ) {
            i--;
            UString a = atom( i );
            if ( !a.isEmpty() )
                atoms.prepend( new UString( a ) );
        }
        dom = atoms.join( "." );
        if ( dom.isEmpty() )
            error( "zero-length domain", i );
    }

    return dom;
}


/*! This private function parses and returns the atom ending at \a i. */

UString AddressParser::atom( int & i )
{
    comment( i );
    int j = i;
    EString & s = d->s;
    while ( i >= 0 &&
            ( ( s[i] >= 'a' && s[i] <= 'z' ) ||
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
              s[i] == '~' ||
              s[i] >= 128 ) )
        i--;
    Utf8Codec c;
    UString r = c.toUnicode( s.mid( i+1, j-i ) );
    comment( i );
    return r;
}


/*! This private function parses an RFC 2822 phrase (a sequence of
    words, more or less) ending at \a i, and returns the phrase as a
    string.
*/

UString AddressParser::phrase( int & i )
{
    UString r;
    comment( i );
    bool done = false;
    bool drop = false;
    bool enc = false;
    while ( !done && i >= 0 ) {
        UString word;
        Utf8Codec ac;
        bool encw = false;
        if ( i > 0 && d->s[i] == '"' ) {
            // quoted phrase
            int j = i;
            i--;
            bool progressing = true;
            while ( progressing ) {
                if ( i > 0 && d->s[i-1] == '\\' )
                    i -= 2;
                else if ( i >= 0 && d->s[i] != '"' )
                    i--;
                else
                    progressing = false;
            }
            if ( i < 0 || d->s[i] != '"' )
                error( "quoted phrase must begin with '\"'", i );
            EString w = d->s.mid( i, j + 1 - i ).unquoted();
            int l = 0;
            while ( l >= 0 && !drop ) {
                int b = w.find( "=?", l );
                if ( b >= 0 ) {
                    int e = w.find( "?", b+2 ); // after charset
                    if ( e > b )
                        e = w.find( "?", e+1 ); // after codec
                    if ( e > b )
                        e = w.find( "?=", e+1 ); // at the end
                    if ( e > b ) {
                        UString tmp = EmailParser::de2047( w.mid( b, e+2-b ) );
                        word.append( ac.toUnicode( w.mid( l, b-l ) ) );
                        word.append( tmp );
                        if ( tmp.isEmpty() )
                            drop = true;
                        l = e + 2;
                    }
                    else {
                        drop = true;
                    }
                }
                else {
                    word.append( ac.toUnicode( w.mid( l ) ) );
                    l = -1;
                }
            }
            i--;
        }
        else if ( d->s[i] == '.' ) {
            // obs-phrase allows a single dot as alternative to word.
            // we allow atom "." as an alternative, too, to handle
            // initials.
            i--;
            word = atom( i );
            word.append( '.' );
        }
        else {
            // single word
            UString a = atom( i );
            // outlook or something close to it seems to occasionally
            // put backslashes into otherwise unquoted names. work
            // around that:
            uint l = a.length();
            while ( l > 0 && i >= 0 && d->s[i] == '\\' ) {
                i--;
                UString w = atom( i );
                l = w.length();
                a = w + a;
            }
            if ( a.isEmpty() )
                done = true;
            if ( a.startsWith( "=?" ) ) {
                EmailParser p( a.utf8() );
                UString tmp = p.phrase().simplified();
                if ( tmp.startsWith( "=?" ) ||
                     tmp.contains( " =?" ) )
                    drop = true;
                if ( p.atEnd() ) {
                    word = tmp;
                    encw = true;
                }
                else {
                    word = a;
                }
            }
            else {
                word = a;
            }
        }
        if ( r.isEmpty() ) {
            r = word;
        }
        else if ( word[word.length()-1] == ' ' ) {
            word.append( r );
            r = word;
        }
        else if ( !word.isEmpty() ) {
            if ( !enc || !encw ||
                 ( word.length() + r.length() < 50 && r[0] <= 'Z' ) )
                word.append( ' ' );
            word.append( r );
            r = word;
        }
        comment( i );
        enc = encw;
        if ( !ac.valid() )
            drop = true;
    }
    if ( drop )
        r.truncate();
    return r.simplified();
}


/*! This private function parses the localpart ending at \a i, and
    returns it as a string.
*/

UString AddressParser::localpart( int & i )
{
    AsciiCodec a;
    UString r;
    EString s;
    bool more = true;
    if ( i < 0 )
        more = false;
    bool atomOnly = true;
    while ( more ) {
        UString w;
        if ( d->s[i] == '"' ) {
            atomOnly = false;
            w = phrase( i );
        }
        else {
            w = atom( i );
        }
        UString t = w;
        t.append( a.toUnicode( s ) );
        t.append( r );
        r = t;
        if ( i >= 0 && d->s[i] == '.' ) {
            s = d->s.mid( i, 1 );
            i--;
        }
        else if ( w.startsWith( "%" ) ) {
            s.truncate();
        }
        else {
            more = false;
        }
    }
    if ( atomOnly && r.isEmpty() )
        error( "Empty localpart", i );
    return r;
}


/*! This private function records the error \a s, which is considered
    to occur at position \a i.

    The name error() is overloaded, nastily. But I don't feel like
    fixing that right now.
*/

void AddressParser::error( const char * s, int i )
{
    if ( i < 0 )
        i = 0;
    d->recentError
        = EString( s ) + " at position " + fn( i ) +
        " (nearby text: '" +
        d->s.mid( i > 8 ? i-8 : 0, 20 ).simplified() + ")";
    if ( d->firstError.isEmpty() )
        d->firstError = d->recentError;
}


static EString key( Address * a )
{
    EString t;

    t.append( a->uname().utf8() );
    t.append( " " );
    t.append( a->localpart().titlecased().utf8() );
    t.append( "@" );
    t.append( a->domain().titlecased().utf8() );

    return t;
}


/*! Removes any addresses from \a l that exist twice in the list. */

void Address::uniquify( List<Address> * l )
{
    if ( !l || l->isEmpty() )
        return;

    Dict<Address> unique;

    List<Address>::Iterator it( l );
    while ( it ) {
        Address *a = it;
        ++it;
        EString k = key( a );
        if ( !unique.contains( k ) ) {
            unique.insert( k, a );
            if ( !a->uname().isEmpty() ) {
                k = " ";
                k.append( a->localpart().titlecased().utf8() );
                k.append( "@" );
                k.append( a->domain().titlecased().utf8() );
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


/*! Returns the type of Address, which is inferred at construction
    time.

    If type() is Normal, name(), localpart() and domain() are
    valid. If type() is EmptyGroup, name() alone is. If type() is
    Bounce or Invalid, none of the three are.
*/

Address::Type Address::type() const
{
    return d->type;
}


/*! Returns true if this is a sensible-looking localpart, and false if
    it needs quoting. We should never permit one of our users to need
    quoting, but we must permit foreign addresses that do.
*/

bool Address::localpartIsSensible() const
{
    if ( d->localpart.isEmpty() )
        return false;
    uint i = 0;
    while ( i < d->localpart.length() ) {
        char c = d->localpart[i];
        if ( c == '.' ) {
            if ( d->localpart[i+1] == '.' )
                return false;
        }
        else if ( ! ( ( c >= 'a' && c <= 'z' ) ||
                      ( c >= 'A' && c <= 'Z' ) ||
                      ( c >= '0' && c <= '9' ) ||
                      c == '!' || c == '#' ||
                      c == '$' || c == '%' ||
                      c == '&' || c == '\'' ||
                      c == '*' || c == '+' ||
                      c == '-' || c == '/' ||
                      c == '=' || c == '?' ||
                      c == '^' || c == '_' ||
                      c == '`' || c == '{' ||
                      c == '|' || c == '}' ||
                      c == '~' || c >= 161 ) )
        {
            return false;
        }
        i++;
    }
    return true;
}


/*! If \a i points to an obs-route, this function silently skips the
    route.
*/

void AddressParser::route( int & i )
{
    if ( i < 0 || d->s[i] != ':' || !error().isEmpty() )
        return;

    i--;
    UString rdom = domain( i );
    if ( rdom == "mailto" )
        return;
    while ( i >= 0 && !rdom.isEmpty() &&
            ( d->s[i] == ',' || d->s[i] == '@' ) ) {
        if ( i >= 0 && d->s[i] == '@' )
            i--;
        while ( i >= 0 && d->s[i] == ',' )
            i--;
        rdom = domain( i );
    }
    d->firstError = "";
    d->recentError = "";
}


/*! Records \a message as an error message relating to the parsing of
    this Address. The initial value is empty.
*/

void Address::setError( const EString & message )
{
    d->error = message;
}


/*! Returns whatever setError() set, or an empty string. */

EString Address::error() const
{
    return d->error;
}


/*! Returns true if this message needs unicode address support, and
    false if it can be transmitted over plain old SMTP.

    Note that the display-name can require unicode even if the address
    does not.
*/

bool Address::needsUnicode() const
{
    if ( d->localpart.isAscii() && d->domain.isAscii() )
        return false;
    return true;
}
