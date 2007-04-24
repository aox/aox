// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "address.h"

#include "field.h"
#include "stringlist.h"
#include "endpoint.h"
#include "ustring.h"
#include "parser.h"
#include "dict.h"
#include "utf.h"


class AddressData
    : public Garbage
{
public:
    AddressData(): id( 0 ), type( Address::Invalid ) {}

    uint id;
    UString name;
    String localpart;
    String domain;
    Address::Type type;
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

Address::Address( const UString &n, const String &l, const String &o )
    : d( new AddressData )
{
    init( n, l, o );
}


/*! Constructs an address whose display-name is \a n (which must be
    in ASCII), whose localpart is \a l and whose domain is \a o.
*/

Address::Address( const String &n, const String &l, const String &o )
    : d( new AddressData )
{
    AsciiCodec a;
    UString un( a.toUnicode( n ) );
    if ( !a.valid() )
        un.truncate();
    init( un, l, o );
}


/*! This private function contains the shared part of the constructors,
    initialising the object with the display-name \a n, localpart \a l,
    and domain \a o and an appropriate type().
*/

void Address::init( const UString &n, const String &l, const String &o )
{
    d->name = n;
    d->localpart = l;
    d->domain = o;
    if ( !d->localpart.isEmpty() && !d->domain.isEmpty() )
        d->type = Normal;
    else if ( !d->localpart.isEmpty() )
        d->type = Local;
    else if ( !d->name.isEmpty() )
        d->type = EmptyGroup;
    else if ( d->name.isEmpty() &&
              d->localpart.isEmpty() &&
              d->domain.isEmpty() )
        d->type = Bounce;
}


/*!  Constructs a copy of \a other. */

Address::Address( const Address & other )
    : Garbage(), d( 0 )
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


/*! Returns the name stored in this Address. The name is the RFC 2822
    display-part, or in case of memberless groups, the display-name of
    the group.

    A memberless group is stored as an Address whose localpart() and
    domain() are both empty.
*/

String Address::name() const
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
        else {
            atom = false;
        }

        if ( c == '\0' || c > 127 )
            ascii = false;

        i++;
    }

    if ( atom || i == 0 )
        return d->name.ascii();

    if ( ascii )
        return d->name.ascii().quoted( '"', '\\' );

    return HeaderField::encodePhrase( d->name.utf8() );
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


/*! Returns an RFC 2822 representation of this address.
*/

String Address::toString() const
{
    String r;
    switch( type() ) {
    case Invalid:
        r = "";
        break;
    case Bounce:
        r = "<>";
        break;
    case EmptyGroup:
        r = name() + ":;";
        break;
    case Local:
        if ( localpartIsSensible() )
            r = d->localpart;
        else
            r = d->localpart.quoted();
        break;
    case Normal:
        if ( d->name.isEmpty() ) {
            if ( localpartIsSensible() )
                r.append( d->localpart );
            else
                r.append( d->localpart.quoted() );
            r.append( "@" );
            r.append( d->domain );
        }
        else {
            r.append( name() );
            r.append( " <" );
            if ( localpartIsSensible() )
                r.append( d->localpart );
            else
                r.append( d->localpart.quoted() );
            r.append( "@" );
            r.append( d->domain );
            r.append( ">" );
        }
    }
    return r;
}


/*! \fn bool Address::valid() const

    Returns true if this Address is a meaningful object, or false if
    its content is meaningless.
*/


/*! Sets this Address to have name \a n, overwriting whatever was
    there before.
*/

void Address::setName( const UString & n )
{
    d->name = n;
}


class AddressParserData
    : public Garbage
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

AddressParser::AddressParser( String s )
    : d( new AddressParserData )
{
    d->s = s;
    int i = s.length()-1;
    int j = i+1;
    while ( i >= 0 && i < j ) {
        j = i;
        address( i );
        if ( i < j && i >= 0 && s[i] == ',' ) {
            i--;
            if ( i >= 0 && s[i] == ';' )
                i--;
        }
    }
    Address::uniquify( &d->a );
    if ( i >= 0 )
        // there's stuff left over that we can't parse
        error( "Unable to parse complete address list", i );
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

void AddressParser::add( UString name,
                         const String & localpart,
                         const String & domain )
{
    // if the localpart is too long, reject the add()
    if ( localpart.length() > 128 ) {
        if ( d->e.isEmpty() )
            d->e = "Localpart too long (" +
                   fn( localpart.length() ) +
                   " characters, RFC 2821's maximum is 64): " +
                   localpart + "@" + domain;
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
    String an = name.ascii().lower();
    if ( an == localpart.lower() ||
         ( an.length() == localpart.length()+1+domain.length() &&
           an == localpart.lower()+"@"+domain.lower() ) )
        name.truncate();

    Address * a = new Address( name, localpart, domain );
    d->a.prepend( a );
}


/*! This version of add() uses only \a localpart and \a domain. */

void AddressParser::add( const String & localpart,
                         const String & domain )
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

AddressParser * AddressParser::references( const String & r )
{
    AddressParser * ap = new AddressParser( "" );
    ap->d->s = r;
    int i = r.length() - 1;
    ap->comment( i );
    while ( i > 0 ) {
        int l = i;
        bool ok = true;
        String dom;
        String lp;
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
    ap->d->e = "";
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
    while ( i > 0 && s[i] == ',' ) {
        i--;
        comment( i );
    }
    if ( i < 0 ) {
        // nothing there. error of some sort.
    }
    else if ( i > 0 && s[i-1] == '<' && s[i] == '>' ) {
        // the address is <>. whether that's legal is another matter.
        add( "", "" );
        i = i - 2;
    }
    else if ( i > 2 && s[i] == '>' && s[i-1] == ';' && s[i-2] == ':' ) {
        // it's a microsoft-broken '<Unknown-Recipient:;>'
        i = i - 3;
        UString name = phrase( i );
        add( name, 0, 0 );
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
            add( name, 0, 0 );
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
        String dom = domain( i );
        String lp;
        UString name;
        if ( s[i] == '<' ) {
            lp = dom;
            dom = "";
        }
        else {
            if ( s[i] == '@' ) {
                i--;
                lp = localpart( i );
                if ( lp.isEmpty() && i >= 0 && s[i] > 127 )
                    error( "localpart contains 8-bit character", i );
            }
            route( i );
        }
        if ( i >= 0 && s[i] == '<' ) {
            i--;
            name = phrase( i );
            while ( i >= 0 && ( s[i] > 127 || s[i] == '@' || s[i] == '<' ) ) {
                // we're looking at an unencoded 8-bit name, or at
                // 'lp@domain<lp@domain>', or at 'x<y<z@domain>'. we
                // react to that by ignoring the display-name.
                i--;
                (void)phrase( i );
                name.truncate();
            }
            // if the display-name contains unknown-8bit, the
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
        }
        if ( lp.isEmpty() )
            error( "Empty localpart ", i );
        else
            add( name, lp, dom );
    }
    else if ( i > 1 && s[i] == '=' && s[i-1] == '?' && s[i-2] == '>' ) {
        // we're looking at "=?charset?q?safdsafsdfs<a@b>?=". how ugly.
        i = i - 3;
        String dom = domain( i );
        if ( s[i] == '@' ) {
            i--;
            String lp = localpart( i );
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
    else if ( s[i] == ';' ) {
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
                add( name, 0, 0 );
        }
    }
    else if ( s[i] == '"' && s.mid( 0, i ).contains( "%\"" ) ) {
        // quite likely we're looking at x%"y@z", as once used on vms
        int x = i;
        x--;
        String dom = domain( x );
        if ( x > 0 && s[x] == '@' ) {
            x--;
            String lp = localpart( x );
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
        String lp = atom( i );
        if ( i > 2 && s[i] == ':' && s[i-1] == ':' ) {
            i = i - 2;
            lp = atom( i ) + "::" + lp;
            add( name, lp, "" );
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
        String date = s.mid( x+1, i-x-1 ).lower().simplified();
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
    else {
        // addr-spec
        AsciiCodec a;
        UString name = a.toUnicode( d->lastComment );
        if ( !a.wellformed() || d->lastComment.contains( "=?" ) )
            name.truncate();
        String dom = domain( i );
        String lp;
        if ( s[i] == '@' ) {
            i--;
            lp = localpart( i );
        }
        else {
            lp = dom;
            dom = "";
        }
        route( i );
        comment( i );
        if ( lp.isEmpty() && i >= 1 && s[i] == ';' && s[i-1] == ':' ) {
            // To: unlisted-recipients:; (no To-header on input)@zmailer.site
            int j = i;
            i -= 2;
            UString n = phrase( i );
            if ( n.isEmpty() ) {
                i = j;
            }
            else {
                lp = "";
                dom = "";
                name = n;
            }
        }
        if ( lp.isEmpty() && i >= 0 && s[i] > 127 )
            error( "localpart contains 8-bit character", i );
        else if ( lp.isEmpty() && !dom.isEmpty() )
            error( "Empty localpart", i );
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
        if ( d->s[i] != '(' ) {
            error( "Unbalanced comment: ", i );
        }
        else {
            Parser822 p( d->s.mid( i, j+1-i ) );
            d->lastComment = p.comment();
        }
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

    if ( d->s[i] >= '0' && d->s[i] <= '9' ) {
        // scan for an unquoted IPv4 address and turn that into an
        // address literal if found.
        int j = i;
        while ( ( d->s[i] >= '0' && d->s[i] <= '9' ) || d->s[i] == '.' )
            i--;
        Endpoint test( d->s.mid( i+1, j-i ), 1 );
        if ( test.valid() )
            return "[" + test.address() + "]";
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
        StringList atoms;

        atoms.append( atom( i ) );
        comment( i );
        while( i >= 0 && d->s[i] == '.' ) {
            i--;
            atoms.prepend( new String( atom( i ) ) );
        }
        dom = atoms.join( "." );
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
        AsciiCodec ac;
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
            word = ac.toUnicode(  d->s.mid( i, j + 1 - i ).unquoted() );
            i--;
        }
        else if ( d->s[i] == '.' ) {
            // obs-phrase allows a single dot as alternative to word.
            // we allow atom "." as an alternative, too, to handle
            // initials.
            i--;
            word = ac.toUnicode( atom( i ) );
            word.append( '.' );
        }
        else {
            // single word
            String a = atom( i );
            // outlook or something close to it seems to occasionally
            // put backslashes into otherwise unquoted names. work
            // around that:
            uint l = a.length();
            while ( l > 0 && i >= 0 && d->s[i] == '\\' ) {
                i--;
                String w = atom( i );
                l = w.length();
                a = w + a;
            }
            if ( a.isEmpty() )
                done = true;
            if ( a.startsWith( "=?" ) ) {
                Parser822 p( a );
                String tmp = p.phrase().simplified();
                if ( tmp.startsWith( "=?" ) ||
                     tmp.contains( " =?" ) )
                    drop = true;
                if ( !tmp.isEmpty() ) {
                    // XXX fixme: Parser822::phrase() blah.
                    Utf8Codec u;
                    word = u.toUnicode( tmp ); // phrase() did fromUnicode()
                    encw = true;
                }
                else {
                    word = ac.toUnicode( a );
                }
            }
            else {
                word = ac.toUnicode( a );
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
    return r;
}


/*! This private function parses the localpart ending at \a i, and
    returns it as a string.
*/

String AddressParser::localpart( int & i )
{
    if ( i < 0 )
        return "";
    String r;
    String s;
    bool more = true;
    while ( more ) {
        String w;
        if ( d->s[i] == '"' ) {
            UString u = phrase( i );
            if ( u.isAscii() )
                w = u.ascii();
            else
                error( "Only ASCII allowed in localparts", i );
        }
        else {
            w = atom( i );
        }
        String t = w;
        t.append( s );
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
    return r;
}


/*! This private function records the error \a s, which is considered
    to occur at position \a i.

    The name error() is overloaded, nastily. But I don't feel like
    fixing that right now.
*/

void AddressParser::error( const char * s, int i )
{
    if ( !d->e.isEmpty() )
        return;
    if ( i < 0 )
        i = 0;
    d->e = String( s ) + " at position " + fn( i ) +
           " (nearby text: '" +
           d->s.mid( i > 8 ? i-8 : 0, 20 ).simplified() + ")";
}


static String key( Address * a )
{
    String t;

    t.append( a->uname().utf8() );
    t.append( " " );
    t.append( a->localpart() );
    t.append( "@" );
    t.append( a->domain().lower() );

    return t;
}


/*! Removes any addresses from \a l that exist twice in the list. */

void Address::uniquify( List<Address> * l )
{
    if ( !l || l->isEmpty() )
        return;

    Dict<Address> unique( l->count() );

    List<Address>::Iterator it( l );
    while ( it ) {
        Address *a = it;
        ++it;
        String k = key( a );
        if ( !unique.contains( k ) ) {
            unique.insert( k, a );
            if ( !a->uname().isEmpty() ) {
                k = " ";
                k.append( a->localpart() );
                k.append( "@" );
                k.append( a->domain().lower() );
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
                      c == '~' ) )
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
    String rdom = domain( i );
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
    d->e = "";
}
