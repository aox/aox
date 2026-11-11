// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "emailget.h"

#include "map.h"
#include "utf.h"
#include "date.h"
#include "json.h"
#include "user.h"
#include "flag.h"
#include "query.h"
#include "field.h"
#include "header.h"
#include "message.h"
#include "mailbox.h"
#include "address.h"
#include "fetcher.h"
#include "selector.h"
#include "bodypart.h"
#include "mimefields.h"
#include "addressfield.h"
#include "estringlist.h"
#include "messagecache.h"


class EmailGetData
    : public Garbage
{
public:
    EmailGetData()
        : find( 0 ), keywords( 0 ), state( 0 ), fetcher( 0 ),
          messages( new List<Message> ),
          mailboxes( new Map<EStringList> ),
          flags( new Map<EStringList> ),
          bodyBytes( 0 ), wantText( false ), wantHtml( false ),
          wantAll( false ), wantBody( false )
    {}

    Query * find;
    Query * keywords;
    Query * state;
    Fetcher * fetcher;
    List<Message> * messages;
    Map<EStringList> * mailboxes;
    Map<EStringList> * flags;
    IntegerSet ids;
    IntegerSet found;
    EStringList properties;
    uint bodyBytes;
    bool wantText;
    bool wantHtml;
    bool wantAll;
    bool wantBody;
};


/*! \class EmailGet emailget.h

    The EmailGet class implements Email/get of RFC8621 4.2. Nothing
    here marks anything as read.
*/


static const char * defaultProperties[] = {
    "id", "threadId", "mailboxIds", "keywords", "size", "receivedAt",
    "messageId", "inReplyTo", "references", "sender", "from", "to", "cc",
    "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview",
    "bodyValues", "textBody", "htmlBody", 0
};


/*! The properties this implements. A client that asks for one of the
    others - blobId, attachments, bodyStructure, headers and the
    header:* forms - is told so, rather than handed an object with the
    property quietly missing: a client cannot tell "we have no answer"
    from "the answer is nothing" if we say nothing.
*/

static const char * knownProperties[] = {
    "id", "threadId", "mailboxIds", "keywords", "size", "receivedAt",
    "messageId", "inReplyTo", "references", "sender", "from", "to", "cc",
    "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview",
    "bodyValues", "textBody", "htmlBody", 0
};


/*! Constructs an Email/get for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

EmailGet::EmailGet( EventHandler * owner, User * user, Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new EmailGetData )
{
}



/*! Sorts the parts of a message into the body parts a client would
    display if it prefers plain text (\a text), the ones it would
    display if it prefers HTML (\a html), and the rest (\a
    attachments).

    This is RFC8621 4.1.4 in miniature. The two body lists differ only
    where a multipart/alternative offers both kinds.
*/

static void classifyPart( Bodypart *, List<Bodypart> *, List<Bodypart> *,
                          List<Bodypart> * );


/*! Sorts the children of \a parent, whose content type is \a ct, into
    \a text, \a html and \a attachments.
*/

static void classifyChildren( Multipart * parent, ContentType * ct,
                              List<Bodypart> * text, List<Bodypart> * html,
                              List<Bodypart> * attachments )
{
    List<Bodypart> * children = parent->children();
    if ( !children )
        return;

    bool alternative = ( ct && ct->type() == "multipart" &&
                         ct->subtype() == "alternative" );

    if ( !alternative ) {
        List<Bodypart>::Iterator i( children );
        while ( i ) {
            classifyPart( i, text, html, attachments );
            ++i;
        }
        return;
    }

    // The children are the same content in several forms, so each list
    // takes the form it prefers: RFC2046 5.1.4 orders alternatives
    // from plainest to richest, so the plain-text reader wants the
    // first form it can use and the HTML reader the last.
    Bodypart * plainest = 0;
    Bodypart * richest = 0;
    List<Bodypart>::Iterator i( children );
    while ( i ) {
        Bodypart * child = i;
        ++i;
        List<Bodypart> t;
        List<Bodypart> h;
        classifyPart( child, &t, &h, attachments );
        List<Bodypart>::Iterator c( t );
        while ( c ) {
            ContentType * cct = c->contentType();
            bool markup = ( cct && cct->subtype() == "html" );
            if ( !plainest && !markup )
                plainest = c;
            if ( markup || !richest )
                richest = c;
            ++c;
        }
    }
    if ( plainest )
        text->append( plainest );
    else if ( richest )
        text->append( richest );
    if ( richest )
        html->append( richest );
    else if ( plainest )
        html->append( plainest );
}


/*! Sorts \a b, and anything inside it, into \a text, \a html and \a
    attachments.
*/

static void classifyPart( Bodypart * b, List<Bodypart> * text,
                          List<Bodypart> * html,
                          List<Bodypart> * attachments )
{
    ContentType * ct = b->contentType();
    EString type( "text" );
    EString subtype( "plain" );
    if ( ct ) {
        type = ct->type();
        subtype = ct->subtype();
    }

    if ( type == "multipart" ) {
        classifyChildren( b, ct, text, html, attachments );
    }
    else if ( type == "message" ) {
        // an attached message is an attachment, not body text, however
        // much text it contains
        attachments->append( b );
    }
    else if ( type == "text" ) {
        text->append( b );
        html->append( b );
    }
    else {
        attachments->append( b );
    }
}


/*! Returns the text of \a html with the markup taken out, for use as a
    preview.

    This is not a renderer and does not try to be one: it drops tags,
    throws away what style and script elements contain, resolves the
    handful of entities that occur in practice, and leaves the rest.
    For a fragment of a few hundred characters that is enough, and a
    client that wants the real thing asks for the part itself.
*/

static UString textFromHtml( const UString & html )
{
    UString r;
    uint i = 0;
    while ( i < html.length() ) {
        if ( html[i] == '<' ) {
            // skip the tag, and the contents of style and script
            uint start = i;
            while ( i < html.length() && html[i] != '>' )
                i++;
            EString tag = html.mid( start + 1, i - start - 1 ).utf8().lower();
            if ( i < html.length() )
                i++;
            if ( tag.startsWith( "style" ) || tag.startsWith( "script" ) ) {
                EString end( tag.startsWith( "style" )
                             ? "</style" : "</script" );
                bool done = false;
                while ( !done && i < html.length() ) {
                    if ( html[i] == '<' &&
                         html.mid( i, end.length() ).utf8().lower() ==
                         end ) {
                        while ( i < html.length() && html[i] != '>' )
                            i++;
                        done = true;
                    }
                    if ( i < html.length() )
                        i++;
                }
            }
            else if ( !r.isEmpty() && r[r.length()-1] != ' ' ) {
                // A tag that breaks the line or the block separates
                // words; one that marks a word up does not, so <b>x</b>!
                // is "x!" and not "x !".
                EString name( tag );
                if ( name.startsWith( "/" ) )
                    name = name.mid( 1 );
                int space = name.find( ' ' );
                if ( space > 0 )
                    name.truncate( space );
                if ( name == "p" || name == "br" || name == "div" ||
                     name == "tr" || name == "td" || name == "th" ||
                     name == "li" || name == "ul" || name == "ol" ||
                     name == "table" || name == "blockquote" ||
                     name == "hr" || name == "pre" ||
                     ( name.length() == 2 && name[0] == 'h' &&
                       name[1] >= '1' && name[1] <= '6' ) )
                    r.append( ' ' );
            }
        }
        else if ( html[i] == '&' ) {
            uint start = ++i;
            while ( i < html.length() && html[i] != ';' && html[i] != '&' &&
                    html[i] != '<' && i < start + 12 )
                i++;
            EString e = html.mid( start, i - start ).utf8().lower();
            if ( i < html.length() && html[i] == ';' )
                i++;
            if ( e == "amp" )
                r.append( '&' );
            else if ( e == "lt" )
                r.append( '<' );
            else if ( e == "gt" )
                r.append( '>' );
            else if ( e == "quot" )
                r.append( '"' );
            else if ( e == "apos" )
                r.append( '\'' );
            else if ( e == "nbsp" )
                r.append( ' ' );
            else if ( e.startsWith( "#x" ) )
                r.append( e.mid( 2 ).number( 0, 16 ) );
            else if ( e.startsWith( "#" ) )
                r.append( e.mid( 1 ).number( 0 ) );
            // and anything else is dropped, since guessing is worse
        }
        else {
            r.append( html[i] );
            i++;
        }
    }
    return r.simplified();
}


/*! Returns the JMAP form of the addresses in field \a field of \a m,
    or a null value if the message has no such field.
*/

Json * EmailGet::addresses( Message * m, uint field )
{
    List<Address> * l = m->header()->addresses( (HeaderField::Type)field );
    if ( !l || l->isEmpty() )
        return new Json( Json::Null );
    Json * r = Json::list();
    List<Address>::Iterator i( l );
    while ( i ) {
        Json * a = Json::object();
        if ( i->uname().isEmpty() )
            a->insert( "name", new Json( Json::Null ) );
        else
            a->insert( "name", Json::string( i->uname() ) );
        if ( i->localpart().isEmpty() )
            a->insert( "email", new Json( Json::Null ) );
        else
            a->insert( "email",
                       Json::string( i->localpart() + "@" + i->domain() ) );
        r->append( a );
        ++i;
    }
    return r;
}


static EString messageIdList( Header * h, HeaderField::Type t )
{
    HeaderField * f = h->field( t, 0 );
    if ( !f )
        return "";
    return f->rfc822( false );
}


/*! Returns the JMAP Email object for \a m. */

Json * EmailGet::email( Message * m )
{
    Json * r = Json::object();
    Header * h = m->header();
    EStringList::Iterator p( d->properties );
    while ( p ) {
        EString property = *p;
        ++p;

        if ( property == "id" ) {
            r->insert( "id", Json::string( "m" + fn( m->databaseId() ) ) );
        }
        else if ( property == "threadId" ) {
            r->insert( "threadId", Json::string( "t" + fn( m->threadId() ) ) );
        }
        else if ( property == "mailboxIds" ) {
            Json * ids = Json::object();
            EStringList * l = d->mailboxes->find( m->databaseId() );
            EStringList::Iterator i( l );
            while ( i ) {
                ids->insert( *i, Json::boolean( true ) );
                ++i;
            }
            r->insert( "mailboxIds", ids );
        }
        else if ( property == "keywords" ) {
            Json * k = Json::object();
            EStringList * l = d->flags->find( m->databaseId() );
            EStringList::Iterator i( l );
            while ( i ) {
                k->insert( *i, Json::boolean( true ) );
                ++i;
            }
            r->insert( "keywords", k );
        }
        else if ( property == "size" ) {
            r->insert( "size", Json::number( m->rfc822Size() ) );
        }
        else if ( property == "receivedAt" ) {
            Date date;
            date.setUnixTime( m->internalDate() );
            r->insert( "receivedAt", Json::string( date.isoDateTime() ) );
        }
        else if ( property == "sentAt" ) {
            ::Date * date = h->date();
            if ( date ) {
                // A JMAP UTCDate is in UTC, where the Date field keeps
                // the sender's offset, so this goes via unix time.
                Date utc;
                utc.setUnixTime( date->unixTime() );
                r->insert( "sentAt", Json::string( utc.isoDateTime() ) );
            }
            else {
                r->insert( "sentAt", new Json( Json::Null ) );
            }
        }
        else if ( property == "subject" ) {
            if ( h->field( HeaderField::Subject, 0 ) )
                r->insert( "subject",
                           Json::string( h->subject() ) );
            else
                r->insert( "subject", new Json( Json::Null ) );
        }
        else if ( property == "messageId" || property == "inReplyTo" ||
                  property == "references" ) {
            HeaderField::Type t = HeaderField::MessageId;
            if ( property == "inReplyTo" )
                t = HeaderField::InReplyTo;
            else if ( property == "references" )
                t = HeaderField::References;
            EString v = messageIdList( h, t );
            if ( v.isEmpty() ) {
                r->insert( property, new Json( Json::Null ) );
            }
            else {
                // JMAP carries these as lists of ids without the
                // angle brackets RFC5322 wraps them in.
                Json * l = Json::list();
                int i = 0;
                while ( i >= 0 ) {
                    int open = v.find( '<', i );
                    int close = v.find( '>', open + 1 );
                    if ( open < 0 || close < 0 ) {
                        i = -1;
                    }
                    else {
                        l->append( Json::string(
                            v.mid( open + 1, close - open - 1 ) ) );
                        i = close + 1;
                    }
                }
                r->insert( property, l );
            }
        }
        else if ( property == "from" || property == "to" ||
                  property == "cc" || property == "bcc" ||
                  property == "replyTo" || property == "sender" ) {
            HeaderField::Type t = HeaderField::From;
            if ( property == "to" )
                t = HeaderField::To;
            else if ( property == "cc" )
                t = HeaderField::Cc;
            else if ( property == "bcc" )
                t = HeaderField::Bcc;
            else if ( property == "replyTo" )
                t = HeaderField::ReplyTo;
            else if ( property == "sender" )
                t = HeaderField::Sender;
            r->insert( property, addresses( m, t ) );
        }
        else if ( property == "hasAttachment" ) {
            List<Bodypart> text;
            List<Bodypart> html;
            List<Bodypart> attachments;
            classifyChildren( m, m->header()->contentType(),
                              &text, &html, &attachments );
            r->insert( "hasAttachment",
                       Json::boolean( !attachments.isEmpty() ) );
        }
        else if ( property == "preview" || property == "textBody" ||
                  property == "htmlBody" || property == "bodyValues" ) {
            List<Bodypart> text;
            List<Bodypart> html;
            List<Bodypart> attachments;
            classifyChildren( m, m->header()->contentType(),
                              &text, &html, &attachments );

            if ( property == "textBody" || property == "htmlBody" ) {
                List<Bodypart> * l = ( property == "textBody" )
                                     ? &text : &html;
                Json * parts = Json::list();
                List<Bodypart>::Iterator b( l );
                while ( b ) {
                    Json * part = Json::object();
                    part->insert( "partId",
                                  Json::string( m->partNumber( b ) ) );
                    // null, honestly: there is nothing to download it
                    // from until this server serves blobs
                    part->insert( "blobId", new Json( Json::Null ) );
                    part->insert( "size", Json::number( b->numBytes() ) );
                    ContentType * ct = b->contentType();
                    EString type( "text/plain" );
                    if ( ct )
                        type = ct->type() + "/" + ct->subtype();
                    part->insert( "type", Json::string( type ) );
                    part->insert( "charset",
                                  Json::string( EString( "utf-8" ) ) );
                    parts->append( part );
                    ++b;
                }
                r->insert( property, parts );
            }
            else if ( property == "bodyValues" ) {
                // Which parts the client gets depends on what it asked
                // for: the text body, the HTML body, or everything.
                List<Bodypart> wanted;
                List<Bodypart>::Iterator b( text );
                while ( b ) {
                    if ( d->wantText )
                        wanted.append( b );
                    ++b;
                }
                List<Bodypart>::Iterator h( html );
                while ( h ) {
                    if ( ( d->wantHtml || d->wantAll ) &&
                         !wanted.find( (Bodypart*)h ) )
                        wanted.append( h );
                    ++h;
                }
                if ( d->wantAll ) {
                    List<Bodypart>::Iterator a( attachments );
                    while ( a ) {
                        ContentType * ct = a->contentType();
                        if ( ct && ct->type() == "text" &&
                             !wanted.find( (Bodypart*)a ) )
                            wanted.append( a );
                        ++a;
                    }
                }

                Json * v = Json::object();
                List<Bodypart>::Iterator w( wanted );
                while ( w ) {
                    UString t = w->text();
                    bool truncated = false;
                    if ( d->bodyBytes ) {
                        // maxBodyValueBytes counts octets of UTF-8,
                        // and RFC8621 4.1.4 forbids splitting a
                        // character, so this counts as it goes.
                        Utf8Codec u;
                        uint bytes = 0;
                        uint i = 0;
                        while ( i < t.length() && !truncated ) {
                            UString one;
                            one.append( t[i] );
                            bytes += u.fromUnicode( one ).length();
                            if ( bytes > d->bodyBytes )
                                truncated = true;
                            else
                                i++;
                        }
                        if ( truncated )
                            t.truncate( i );
                    }
                    Json * value = Json::object();
                    value->insert( "value", Json::string( t ) );
                    value->insert( "isEncodingProblem",
                                   Json::boolean( false ) );
                    value->insert( "isTruncated",
                                   Json::boolean( truncated ) );
                    v->insert( m->partNumber( w ), value );
                    ++w;
                }
                r->insert( "bodyValues", v );
            }
            else {
                // The preview is plain text, so an HTML part has to
                // have its markup taken out, as RFC8621 4.1.4 wants a
                // fragment a human can read.
                UString t;
                List<Bodypart>::Iterator b( text );
                if ( b ) {
                    ContentType * ct = b->contentType();
                    if ( ct && ct->type() == "text" &&
                         ct->subtype() == "html" )
                        t = textFromHtml( b->text() );
                    else
                        t = b->text().simplified();
                }
                if ( t.length() > 256 )
                    t.truncate( 256 );
                r->insert( "preview", Json::string( t ) );
            }
        }
    }
    return r;
}


void EmailGet::execute()
{
    if ( !d->find ) {
        if ( !checkAccount() )
            return;

        Json * ids = arguments()->member( "ids" );
        if ( !ids || !ids->valid( Json::Array ) ) {
            // ids:null means every message in the account, which is
            // not a question we answer.
            fail( "requestTooLarge" );
            return;
        }
        if ( ids->array()->count() > 64 ) {
            fail( "requestTooLarge" );
            return;
        }
        List<Json>::Iterator i( ids->array() );
        while ( i ) {
            if ( i->valid( Json::String ) ) {
                EString id = i->ascii();
                if ( id.startsWith( "m" ) ) {
                    bool ok = false;
                    uint n = id.mid( 1 ).number( &ok );
                    if ( ok && n )
                        d->ids.add( n );
                }
            }
            ++i;
        }

        Json * properties = arguments()->member( "properties" );
        if ( properties && properties->valid( Json::Array ) ) {
            List<Json>::Iterator p( properties->array() );
            while ( p ) {
                if ( !p->valid( Json::String ) ) {
                    fail( "invalidArguments" );
                    return;
                }
                EString name = p->ascii();
                uint k = 0;
                while ( knownProperties[k] && name != knownProperties[k] )
                    k++;
                if ( !knownProperties[k] ) {
                    fail( "invalidArguments" );
                    return;
                }
                d->properties.append( name );
                ++p;
            }
            // id is always returned, as RFC8620 5.1 says
            if ( !d->properties.contains( "id" ) )
                d->properties.append( "id" );
        }
        else {
            uint n = 0;
            while ( defaultProperties[n] ) {
                d->properties.append( defaultProperties[n] );
                n++;
            }
        }
        // RFC8621 4.2.2: the three fetch arguments say which parts the
        // client wants the text of, and default to false. Asking for
        // bodyValues without any of them is asking for an empty map,
        // which is what a client that only wants the structure does.
        Json * f = arguments()->member( "fetchTextBodyValues" );
        if ( f && f->valid( Json::Boolean ) )
            d->wantText = f->boolean();
        f = arguments()->member( "fetchHTMLBodyValues" );
        if ( f && f->valid( Json::Boolean ) )
            d->wantHtml = f->boolean();
        f = arguments()->member( "fetchAllBodyValues" );
        if ( f && f->valid( Json::Boolean ) )
            d->wantAll = f->boolean();
        if ( d->wantAll )
            d->wantText = true;
        Json * mb = arguments()->member( "maxBodyValueBytes" );
        if ( mb && mb->valid( Json::Number ) && mb->number() > 0 )
            d->bodyBytes = (uint)mb->number();
        d->wantBody = d->wantText || d->wantHtml || d->wantAll ||
                      d->properties.contains( "preview" ) ||
                      d->properties.contains( "textBody" ) ||
                      d->properties.contains( "htmlBody" ) ||
                      d->properties.contains( "bodyValues" ) ||
                      d->properties.contains( "hasAttachment" );

        if ( d->ids.isEmpty() ) {
            Json * r = Json::object();
            r->insert( "accountId", Json::string( fn( user()->id() ) ) );
            r->insert( "state", Json::string( EString( "m0" ) ) );
            r->insert( "list", Json::list() );
            r->insert( "notFound", Json::list() );
            respond( "Email/get", r );
            return;
        }

        // Selector decides what this user may see, the same way a
        // search does, so a message in someone else's mailbox is
        // notFound rather than readable.
        Selector * s = new Selector( Selector::Or );
        uint n = 1;
        while ( n <= d->ids.count() ) {
            s->add( new Selector( Selector::DatabaseId, Selector::Equals,
                                  d->ids.value( n ) ) );
            n++;
        }
        s->simplify();
        EStringList wanted;
        wanted.append( "message" );
        wanted.append( "mailbox" );
        d->find = s->query( user(), 0, 0, this, false, &wanted, false );
        d->find->execute();

        d->keywords = new Query(
            "select f.message, fn.name from flags f "
            "join flag_names fn on (f.flag=fn.id) "
            "where f.message=any($1) and coalesce(f.owner,0) in (0,$2)",
            this );
        d->keywords->bind( 1, d->ids );
        d->keywords->bind( 2, user()->id() );
        d->keywords->execute();

        d->state = new Query( "select last_value from nextmodseq", this );
        d->state->execute();
    }

    if ( !d->find->done() || !d->keywords->done() || !d->state->done() )
        return;

    if ( d->find->failed() || d->keywords->failed() ) {
        fail( "serverFail" );
        return;
    }

    if ( !d->fetcher ) {
        Row * r;
        while ( (r=d->find->nextRow()) != 0 ) {
            uint message = r->getInt( "message" );
            uint mailbox = r->getInt( "mailbox" );
            EStringList * l = d->mailboxes->find( message );
            if ( !l ) {
                l = new EStringList;
                d->mailboxes->insert( message, l );
                d->found.add( message );
            }
            EString id( "f" + fn( mailbox ) );
            if ( !l->contains( id ) )
                l->append( id );
        }
        while ( (r=d->keywords->nextRow()) != 0 ) {
            uint message = r->getInt( "message" );
            EStringList * l = d->flags->find( message );
            if ( !l ) {
                l = new EStringList;
                d->flags->insert( message, l );
            }
            // IMAP spells them \Seen, JMAP $seen
            EString name = r->getEString( "name" );
            if ( name.startsWith( "\\" ) )
                name = "$" + name.mid( 1 ).lower();
            if ( !l->contains( name ) )
                l->append( name );
        }

        uint n = 1;
        while ( n <= d->found.count() ) {
            uint id = d->found.value( n );
            Message * m = new Message;
            m->setDatabaseId( id );
            d->messages->append( m );
            n++;
        }

        if ( d->messages->isEmpty() ) {
            d->fetcher = new Fetcher( d->messages, this, 0 );
        }
        else {
            d->fetcher = new Fetcher( d->messages, this, 0 );
            d->fetcher->fetch( Fetcher::Addresses );
            d->fetcher->fetch( Fetcher::OtherHeader );
            d->fetcher->fetch( Fetcher::Trivia );
            if ( d->wantBody ) {
                d->fetcher->fetch( Fetcher::Body );
                d->fetcher->fetch( Fetcher::PartNumbers );
            }
            d->fetcher->execute();
        }
    }

    if ( !d->fetcher->done() )
        return;

    Json * list = Json::list();
    List<Message>::Iterator m( d->messages );
    while ( m ) {
        list->append( email( m ) );
        ++m;
    }

    Json * notFound = Json::list();
    uint n = 1;
    while ( n <= d->ids.count() ) {
        uint id = d->ids.value( n );
        if ( !d->found.contains( id ) )
            notFound->append( Json::string( "m" + fn( id ) ) );
        n++;
    }

    int64 state = 1;
    Row * r = d->state->nextRow();
    if ( r )
        state = r->getBigint( "last_value" );

    Json * response = Json::object();
    response->insert( "accountId", Json::string( fn( user()->id() ) ) );
    response->insert( "state", Json::string( "m" + fn( state ) ) );
    response->insert( "list", list );
    response->insert( "notFound", notFound );
    respond( "Email/get", response );
}
