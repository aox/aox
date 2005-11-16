// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "selector.h"

#include "utf.h"
#include "flag.h"
#include "date.h"
#include "session.h"
#include "mailbox.h"
#include "annotation.h"
#include "field.h"
#include "user.h"


static uint lmatch( const String &, uint, const String &, uint );

class SearchQuery: public Query {
public:
    SearchQuery( EventHandler * e ): Query( e ) {}
    String string() const { return s; }
    String s;
};


class SelectorData
    : public Garbage
{
public:
    SelectorData()
        : f( Selector::NoField ), a( Selector::None ), mboxId( 0 ),
          placeholder( 0 ), query( 0 ), parent( 0 ),
          children( new List< Selector > ),
          session( 0 )
    {}

    Selector::Field f;
    Selector::Action a;

    String error;

    String s8;
    String s8b;
    UString s16;
    MessageSet s;
    uint n;

    uint mboxId;
    int placeholder;
    SearchQuery * query;

    Selector * parent;
    List< Selector > * children;
    Session * session;
    User * user;
};


/*! \class Selector selector.h
    This class represents d->a set of conditions to select messages from a
    mailbox.

XXX:

    The Selector class represents a single condition in a
    search, which is either a leaf condition or an AND/OR operator.

    The class can simplify() and regularize itself, such that all
    equivalent search inputs give the same result, and and it can
    express itself in a form amenable to testing. Rather simple.
*/


/*! Creates a new root selector. */

Selector::Selector()
    : d( new SelectorData )
{
    d->a = And;
}


/*! ... */

Selector::Selector( Field f, Action a, uint n )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->n = n;
}


/*! ... */

Selector::Selector( Field f, Action a, const String &s )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
}


/*! ... */

Selector::Selector( Field f, Action a, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s16 = u;
}


/*! ... */

Selector::Selector( Field f, Action a, const String &s, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s16 = u;
}


/*! ... */

Selector::Selector( Field f, Action a, const String &s,
                    const String &t, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s8b = t;
    d->s16 = u;
}


/*! ... */

Selector::Selector( const MessageSet &s )
    : d( new SelectorData )
{
    d->f = Uid;
    d->a = Contains;
    d->s = s;
}


/*! ... */

Selector::Selector( Action a )
    : d( new SelectorData )
{
    d->f = NoField;
    d->a = a;
}


/*! Returns the ultimate parent of this Selector. */

const Selector * Selector::root() const
{
    const Selector * p = this;

    while ( p->parent() )
        p = p->parent();

    return p;
}


/*! Returns the parent of this Selector, or 0 if it is the root. */

const Selector * Selector::parent() const
{
    return d->parent;
}


/*! Adds the Selector \a s to the list of this Selector's children. */

void Selector::add( Selector * s )
{
    s->d->parent = this;
    d->children->append( s );
}


/*! Returns the next integer from a monotonically increasing sequence on
    each call. The first value is 1. (This is used to construct the $n
    placeholder names in queries.)
*/

uint Selector::placeHolder()
{
    root()->d->placeholder++;
    return root()->d->placeholder;
}


/*! Records \a s as an error during the construction of this Selector
    tree. Only the first error in a tree is recorded, and it is recorded
    at the root of the tree (rather than the node where it occurred).
*/

void Selector::setError( const String &s )
{
    if ( root()->d->error.isEmpty() )
        root()->d->error = s;
}


/*! This helper transforms this search conditions and all its children
    into a simpler form, if possible. There are three goals to this:

    1. Provide a regular search expression, so that we can eventually
    detect and prepare statements for often-repeated searches.

    2. Ditto, so that we can test that equivalent input gives
    identical output.

    3. Avoid search expressions which would be horribly inefficient or
    just plain impossible for the RDBMS.
*/

void Selector::simplify()
{
    // not (not x) -> x
    if ( d->a == Not && d->children->first()->d->a == Not ) {
        Selector * again = d->children->first()->d->children->first();

        d->f = again->d->f;
        d->a = again->d->a;
        d->s8 = again->d->s8;
        d->s8b = again->d->s8b;
        d->s16 = again->d->s16;
        d->s = again->d->s;
        d->n = again->d->n;
        d->children = again->d->children;
    }

    if ( d->a == Larger && d->n == 0 ) {
        // > 0 matches everything
        d->a = All;
    }
    else if ( d->a == Contains ) {
        // x contains y may match everything
        switch ( d->f ) {
        case InternalDate:
        case Sent:
            d->a = None;
            break;
        case Header:
        case Body:
            if ( d->s16.isEmpty() )
                d->a = All;
            break;
        case Rfc822Size:
            break;
        case Flags:
            if ( !Flag::find( d->s8 ) )
                d->a = None;
            break;
        case Uid:
            // if s contains all messages or is empty...
            if ( d->s.isEmpty() )
                d->a = None;
            // the All Messages case is harder.
            break;
        case Annotation:
            // can't simplify this
            break;
        case NoField:
            // contains is orthogonal to nofield, so this we cannot
            // simplify
            break;
        }
        // contains empty string too
    }
    else if ( d->a == Contains && d->f == Uid ) {
        if ( d->s.isEmpty() )
            d->a = None; // contains d->a set of nonexistent messages
        else if ( d->s.where() == "uid>=1" )
            d->a = All; // contains any messages at all
    }
    else if ( d->a == And ) {
        // zero-element and becomes all, "none and x" becomes none
        List< Selector >::Iterator i( d->children );
        while ( i && d->a == And ) {
            List< Selector >::Iterator p( i );
            ++i;
            p->simplify();
            if ( p->d->a == All )
                d->children->take( p );
            else if ( p->d->a == None )
                d->a = None;
        }
        if ( d->a == And && d->children->isEmpty() )
            d->a = All;

    }
    else if ( d->a == Or ) {
        // zero-element or becomes all, "all or x" becomes all
        List< Selector >::Iterator i( d->children );
        while ( i && d->a == Or ) {
            List< Selector >::Iterator p( i );
            ++i;
            p->simplify();
            if ( p->d->a == None )
                d->children->take( p );
            else if ( p->d->a == All )
                d->a = All;
        }
        if ( d->a == And && d->children->isEmpty() )
            d->a = All;

    }
    if ( d->a == All || d->a == None )
        d->f = NoField;

    if ( d->a != And && d->a != Or )
        return;

    // an empty and/or means everything matches
    if ( d->children->isEmpty() ) {
        d->a = All;
        return;
    }

    // or (a or (b c)) -> or (a b c). ditto and.
    if ( d->children ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            List< Selector >::Iterator p( i );
            ++i;
            if ( p->d->a == d->a ) {
                List<Selector>::Iterator c( p->d->children );
                while ( c ) {
                    d->children->prepend( c );
                    ++c;
                }
                d->children->take( p );
            }
        }
    }

    // d->a single-element and/or can be removed and its argument substituted
    if ( d->children->count() == 1 ) {
        List< Selector >::Iterator p( d->children );
        d->f = p->d->f;
        d->a = p->d->a;
        d->s8 = p->d->s8;
        d->s8b = p->d->s8b;
        d->s16 = p->d->s16;
        d->s = p->d->s;
        d->children = p->d->children;
        return;
    }

    // at this point, for proper uniqueness, we ought to sort the
    // children, killing any duplicates in the process. then we'll
    // have d->a single query for each job. but that can wait. this will
    // do for testing.
}


/*! Returns a query representing this Selector or 0 if anything goes
    wrong, in which case error() contains a description of the problem.
*/

Query * Selector::query( User * user, Session * session,
                         EventHandler * owner )
{
    d->query = new SearchQuery( owner );
    d->user = user;
    d->session = session;
    d->placeholder = 0;
    d->mboxId = placeHolder();
    d->query->bind( d->mboxId, session->mailbox()->id() );
    d->query->s = "select distinct messages.uid from messages";
    d->query->s.append( " where messages.mailbox=$" + fn( d->mboxId ) +
                        " and (" + where() + ") order by"
                        " messages.uid" );
    return d->query;
}




/*! Gives an SQL string representing this condition.

    The string may include $n placeholders; where() and its helpers
    will bind them as required.
*/

String Selector::where()
{
    switch( d->f ) {
    case InternalDate:
        return whereInternalDate();
        break;
    case Sent:
        return whereSent();
        break;
    case Header:
        if ( d->s8.isEmpty() )
            return whereHeader();
        else
            return whereHeaderField();
        break;
    case Body:
        return whereBody();
        break;
    case Rfc822Size:
        return whereRfc822Size();
        break;
    case Flags:
        return whereFlags();
        break;
    case Uid:
        return whereUid();
        break;
    case Annotation:
        return whereAnnotation();
        break;
    case NoField:
        return whereNoField();
        break;
    }
    setError( "Internal error for " + debugString() );
    return "";
}

/*! This implements the INTERNALDATE part of where().
*/

String Selector::whereInternalDate()
{
    uint day = d->s8.mid( 0, 2 ).number( 0 );
    String month = d->s8.mid( 3, 3 );
    uint year = d->s8.mid( 7 ).number( 0 );
    // XXX: local time zone is ignored here
    Date d1;
    d1.setDate( year, month, day, 0, 0, 0, 0 );
    Date d2;
    d2.setDate( year, month, day, 23, 59, 59, 0 );
    uint n1 = placeHolder();
    root()->d->query->bind( n1, d1.unixTime() );
    uint n2 = placeHolder();
    root()->d->query->bind( n2, d2.unixTime() );

    if ( d->a == OnDate ) {
        return "messages.idate>=$" + fn( n1 ) +
            " and messages.idate<=$" + fn( n2 );
    }
    else if ( d->a == SinceDate ) {
        return "messages.idate>=$" + fn( n1 );
    }
    else if ( d->a == BeforeDate ) {
        return "messages.idate<=$" + fn( n2 );
    }
    setError( "Cannot search for: " + debugString() );
    return "";
}

/*! This implements the SENTON/SENTBEFORE/SENTSINCE part of where().
*/

String Selector::whereSent()
{
    setError( "Searching on the Date field unimplemented, sorry" );
    return "";
}


static String matchAny( int n )
{
    return "'%'||$" + fn( n ) + "||'%'";
}


static String q( const UString & orig )
{
    Utf8Codec c;
    String r( c.fromUnicode( orig ) );
    // escape % somehow?
    return r;
}


/*! This implements searches on d->a single header field.
*/

String Selector::whereHeaderField()
{
    d->s8 = d->s8.headerCased();

    uint f = 1;
    while ( f <= HeaderField::LastAddressField &&
            HeaderField::fieldName( (HeaderField::Type)f ) != d->s8 )
        f++;
    if ( f <= HeaderField::LastAddressField )
        return whereAddressField( d->s8 );

    uint fnum = placeHolder();
    root()->d->query->bind( fnum, d->s8 );
    uint like = placeHolder();
    root()->d->query->bind( like, q( d->s16 ) );

    return
        "messages.uid in "
        "(select uid from header_fields where mailbox=$" + mboxId() +
        " and field=(select id from field_names where name=$" + fn( fnum ) +
        ") and value ilike " + matchAny( like ) + ")";
}


/*! This implements searches on the single address field \a field, or
    on all address fields if \a field is empty. \a d as usual.
*/

String Selector::whereAddressField( const String & field )
{
    String r( "messages.uid in (" );
    r.append( "select uid from address_fields af join addresses a "
              "on (af.address=a.id)" );

    uint fnum = 0;
    if ( !field.isEmpty() ) {
        fnum = placeHolder();
        root()->d->query->bind( fnum, d->s8 );
        r.append( " join field_names fn on (af.field=fn.id)" );
    }

    r.append( " where af.mailbox=$" + mboxId() );
    if ( fnum != 0 )
        r.append( " and fn.name=$" + fn( fnum ) );

    String raw( q( d->s16 ) );
    int at = raw.find( '@' );

    if ( at < 0 ) {
        uint name = placeHolder();
        root()->d->query->bind( name, raw );
        r.append( " and "
                  "(a.name ilike " + matchAny( name ) + " or"
                  " a.localpart ilike " + matchAny( name ) + " or"
                  " a.domain ilike " + matchAny( name ) + ")" );
    }
    else {
        String lc, dc;
        if ( at > 0 ) {
            uint lp = placeHolder();
            if ( raw.startsWith( "<" ) ) {
                root()->d->query->bind( lp, raw.mid( 1, at-1 ) );
                lc = "a.localpart ilike $" + fn( lp );
            }
            else {
                root()->d->query->bind( lp, raw.mid( 0, at ) );
                lc = "a.localpart ilike '%'||$" + fn( lp ) + " ";
            }
        }
        if ( at < (int)raw.length() - 1 ) {
            uint dom = placeHolder();
            if ( raw.endsWith( ">" ) ) {
                root()->d->query->bind( dom, raw.mid( at+1, raw.length()-at-2 ) );
                dc = "a.domain ilike $" + fn( dom );
            }
            else {
                root()->d->query->bind( dom, raw.mid( at+1 ) );
                dc = "a.domain ilike $" + fn( dom ) + "||'%'";
            }
        }
        if ( lc.isEmpty() && dc.isEmpty() ) {
            // imap SEARCH FROM "@" matches messages with a nonempty
            // from field. the sort of thing only a test suite would
            // do.
        }
        if ( !lc.isEmpty() ) {
            r.append( " and " );
            r.append( lc );
        }
        if ( !dc.isEmpty() ) {
            r.append( " and " );
            r.append( dc );
        }
    }
    r.append( ")" );
    return r;
}

/*! This implements searches on all header fields.
*/

String Selector::whereHeader()
{
    uint str = placeHolder();
    root()->d->query->bind( str, q( d->s16 ) );
    return
        "messages.uid in "
        "(select uid from header_fields hf"
        " where hf.mailbox=$" + mboxId() + " and"
        " hf.value ilike " + matchAny( str ) + ") "
        "or " + whereAddressField();
}


/*! This implements searches on (text) bodyparts. We cannot and will
    not do "full-text" search on the contents of e.g. jpeg
    pictures. (For some formats we search on the text part, because
    the injector sets bodyparts.text based on bodyparts.data.)
*/

String Selector::whereBody()
{
    String s;

    uint bt = placeHolder();
    root()->d->query->bind( bt, q( d->s16 ) );

    s = "messages.uid in "
        "(select pn.uid from part_numbers pn, bodyparts b"
        " where pn.mailbox=$" + mboxId() + " and"
        " pn.bodypart=b.id and ";

    String db = Database::type();
    if ( db.lower().endsWith( "tsearch2" ) )
        s.append( "b.ftidx @@ to_tsquery('default', $" + fn( bt ) + ")" );
    else
        s.append( "b.text ilike " + matchAny( bt ) );

    s.append( ")" );
    return s;
}


/*! This implements searches on the rfc822size of messages.
*/

String Selector::whereRfc822Size()
{
    uint s = placeHolder();
    root()->d->query->bind( s, d->n );
    if ( d->a == Smaller )
        return "messages.rfc822size<$" + fn( s );
    else if ( d->a == Larger )
        return "messages.rfc822size>$" + fn( s );
    setError( "Internal error: " + debugString() );
    return "";
}


/*! This implements searches on whether a message has/does not have
    flags.
*/

String Selector::whereFlags()
{
    if ( d->a == Contains && d->f == Flags && d->s8.lower() == "\\recent" ) {
        // the database cannot look at the recent flag, so we turn
        // this query into a test for the relevant UIDs.
        return root()->d->session->recent().where( "messages" );
    }

    // the database can look in the ordinary way. we make it easy, if we can.
    Flag * f = Flag::find( d->s8 );
    uint name = placeHolder();
    if ( f ) {
        root()->d->query->bind( name, f->id() );
        return "messages.uid in ("
            "select uid from flags where flags.mailbox=$" + mboxId() +
            " and flags.flag=$" + fn( name ) + ")";
    }
    root()->d->query->bind( name, d->s8 ); // do we need to smash case on flags?
    return
        "messages.uid in "
        "(select uid from flags where mailbox=$" + mboxId() +
        " and flag=(select id from flag_names where name=$" +
        fn( name ) + "))";
}


/*! This implements searches on whether a message has the right UID.
*/

String Selector::whereUid()
{
    return d->s.where( "messages" );
}


/*! This implements searches on whether a message has/does not have
    the right annotation.
*/

String Selector::whereAnnotation()
{
    ::AnnotationName * a = ::AnnotationName::find( d->s8 );
    String annotations;
    String sep = "";
    if ( a ) {
        annotations = "name=" + fn( a->id() );
    }
    else {
        uint n = 0;
        uint u = 0;
        while ( u <= ::AnnotationName::largestId() ) {
            a = ::AnnotationName::find( u );
            u++;
            if ( a && lmatch( d->s8, 0, a->name(), 0 ) == 2 ) {
                n++;
                annotations.append( sep );
                annotations.append( "name=" );
                annotations.append( fn( a->id() ) );
                if ( sep.isEmpty() )
                    sep = " or ";
            }
        }
        if ( n > 3 && d->s8.find( '%' ) < 0 ) {
            // if there are many, we're better off using set logic.
            uint pattern = placeHolder();
            annotations = "name in ("
                          "select id from annotation_names where name like $" +
                          fn( pattern ) +
                          ")";
            String sql = 0;
            uint i = 0;
            while ( i < d->s8.length() ) {
                if ( d->s8[i] == '*' )
                    sql.append( '%' );
                else
                    sql.append( d->s8[i] );
                i++;
            }
            root()->d->query->bind( pattern, sql );
        }
        else if ( n > 1 ) {
            annotations = "(" + annotations + ")";
        }
    }

    String user;
    String attribute;
    if ( d->s8b.endsWith( ".priv" ) ) {
        attribute = d->s8b.mid( 0, d->s8b.length()-5 ).lower();
        uint userId = placeHolder();
        user = "owner=$" + fn( userId );
        root()->d->query->bind( userId, root()->d->user->id() );
    }
    else if ( d->s8b.endsWith( ".shared" ) ) {
        attribute = d->s8b.mid( 0, d->s8b.length()-7 ).lower();
        user = "owner is null";
    }
    else {
        attribute = d->s8b.lower();
        uint userId = placeHolder();
        user = "(owner is null or owner=$" + fn( userId ) + ")";
        root()->d->query->bind( userId, root()->d->user->id() );
    }

    String field = "value";
    if ( attribute == "content-type" )
        field = "type";
    else if ( attribute == "content-language" )
        field = "language";
    else if ( attribute == "display-name" )
        field = "displayname";
    else if ( attribute == "size" )
        field = "length(value)";

    String like = " is not null";
    if ( !d->s16.isEmpty() ) {
        uint i = placeHolder();
        root()->d->query->bind( i, q( d->s16 ) );
        like = " ilike " + matchAny( i );
    }

    return "messages.uid in (select uid from annotations "
        "where mailbox=$" + mboxId() + " and " + user + " and " +
        annotations + " and " + field + like + ")";
}


/*! This implements any search that's not bound to a specific field,
    generally booleans and "all".
*/

String Selector::whereNoField()
{
    if ( d->a == And || d->a == Or ) {
        if ( d->children->isEmpty() ) {
            if ( d->a == And )
                return "true";
            return "false";
        }
        List<Selector>::Iterator i( d->children );
        String r = "(" + i->where();
        ++i;
        String sep;
        if ( d->a == And )
            sep = ") and (";
        else
            sep = ") or (";
        while ( i ) {
            r.append( sep );
            r.append( i->where() );
            ++i;
        }
        r.append( ")" );
        return r;
    }
    else if ( d->a == Not ) {
        return "not (" + d->children->first()->where() + ")";
    }
    else if ( d->a == All ) {
        return "true";
    }
    else if ( d->a == None ) {
        return "false";
    }
    setError( "Internal error: " + debugString() );
    return "";
}


/*! Give an ASCII representatation of this object, suitable for debug
    output or for equality testing.
*/

String Selector::debugString() const
{
    String r;

    String o, w;

    switch ( d->a ) {
    case OnDate:
        o = "on";
        break;
    case SinceDate:
        o = "since";
        break;
    case BeforeDate:
        o = "before";
        break;
    case Contains:
        o = "contains";
        break;
    case Larger:
        o = "larger";
        break;
    case Smaller:
        o = "smaller";
        break;
    case And:
    case Or:
        break;
    case Not:
        return "not " + d->children->first()->debugString();
    case All:
        return "all";
        break;
    case None:
        return "none";
        break;
    };

    if ( o.isEmpty() ) {
        r = "(";
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            r += i->debugString();
            ++i;
            if ( i ) {
                if ( d->a == And )
                    r += " and ";
                else
                    r += " or ";
            }
        }
        r += ")";
        return r;
    }

    switch( d->f ) {
    case InternalDate:
        w = "delivery";
        break;
    case Sent:
        w = "sent";
        break;
    case Header:
        if ( d->s8.isEmpty() )
            w = "header";
        else
            w = "header field " + d->s8;
        break;
    case Body:
        w = "body";
        break;
    case Rfc822Size:
        w = "rfc822 size";
        break;
    case Flags:
        w = "set of flags";
        break;
    case NoField:
        w = "none";
        break;
    case Uid:
        return d->s.where();
        break;
    case Annotation:
        w = "annotation " + d->s8b + " of ";
    };

    r = w + " " + o + " ";
    if ( d->s16.isEmpty() )
        r.append( d->s8 );
    else
        r.append( d->s16.ascii() );

    return r;

}


/*! Matches \a m against this condition, provided the match is
    reasonably simple and quick, and returns either Yes, No, or (if
    the match is difficult, expensive or depends on data that isn't
    available) Punt.
*/

Selector::MatchResult Selector::match( Message * m, uint uid )
{
    if ( d->a == And || d->a == Or ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            MatchResult sub = i->match( m, uid );
            if ( sub == Punt )
                return Punt;
            if ( d->a == And && sub == No )
                return No;
            if ( d->a == Or && sub == Yes )
                return Yes;
            ++i;
        }
        if ( d->a == And )
            return Yes;
        else
            return No;
    }
    else if ( d->a == Contains && d->f == Uid ) {
        if ( d->s.contains( uid ) )
            return Yes;
        return No;
    }
    else if ( d->a == Contains && d->f == Flags ) {
        if ( d->s8 == "\\recent" ) {
            // XXX: Will segfault. We promise.
            Session * s = root()->d->session;
            if ( s->isRecent( uid ) )
                return Yes;
            return No;
        }
        return Punt;
    }
    else if ( d->a == Not ) {
        MatchResult sub = d->children->first()->match( m, uid );
        if ( sub == Punt )
            return Punt;
        else if ( sub == Yes )
            return No;
        else
            return Yes;
    }
    else if ( d->a == All ) {
        return Yes;
    }

    return Punt;
}


/*! Returns true if this condition needs an updated Session to be
    correctly evaluated, and false if not.
*/

bool Selector::needSession() const
{
    if ( d->a == Contains && d->f == Flags && d->s8 == "\\recent" )
        return true;

    if ( d->a == And || d->a == Or ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            if ( i->needSession() )
                return true;
            ++i;
        }
    }
    return false;
}


static uint lmatch( const String & pattern, uint p,
                    const String & name, uint n )
{
    uint r = 0;
    while ( p <= pattern.length() ) {
        if ( pattern[p] == '*' || pattern[p] == '%' ) {
            bool star = false;
            while ( pattern[p] == '*' || pattern[p] == '%' ) {
                if ( pattern[p] == '*' )
                    star = true;
                p++;
            }
            uint i = n;
            if ( star )
                i = name.length();
            else
                while ( i < name.length() && name[i] != '/' )
                    i++;
            while ( i >= n ) {
                uint s = lmatch( pattern, p, name, i );
                if ( s == 2 )
                    return 2;
                if ( s == 1 )
                    r = 1;
                i--;
            }
        }
        else if ( p == pattern.length() && n == name.length() ) {
            // ran out of pattern and name at the same time. success.
            return 2;
        }
        else if ( pattern[p] == name[n] ) {
            // nothing. proceed.
            p++;
        }
        else if ( pattern[p] == '/' && n == name.length() ) {
            // we ran out of name and the pattern wants a child.
            return 1;
        }
        else {
            // plain old mismatch.
            return r;
        }
        n++;
    }
    return r;
}


/*! Returns a string representing the number (without $) of the
    placeholder that's bound to the mbox id.
*/

String Selector::mboxId()
{
    return fn( root()->d->mboxId );
}


/*! Returns the string representation of this Selector. */

String Selector::string()
{
    return "Not yet implemented";
}
