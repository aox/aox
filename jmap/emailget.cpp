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
          bodyBytes( 0 ), wantText( false ), wantBody( false )
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
    bool wantBody;
};


/*! \class EmailGet emailget.h

    The EmailGet class implements Email/get of RFC8621 4.2, which is
    where an agent reads what a message says.

    Nothing here marks anything as read.
*/


static const char * defaultProperties[] = {
    "id", "threadId", "mailboxIds", "keywords", "size", "receivedAt",
    "messageId", "inReplyTo", "references", "sender", "from", "to", "cc",
    "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview",
    "bodyValues", "textBody", 0
};


/*! Constructs an Email/get for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

EmailGet::EmailGet( EventHandler * owner, User * user, Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new EmailGetData )
{
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
            bool attachment = false;
            List<Bodypart>::Iterator i( m->allBodyparts() );
            while ( i && !attachment ) {
                ContentType * ct = i->contentType();
                if ( ct && ct->type() != "text" && ct->type() != "multipart" )
                    attachment = true;
                ++i;
            }
            r->insert( "hasAttachment", Json::boolean( attachment ) );
        }
        else if ( property == "preview" || property == "textBody" ||
                  property == "bodyValues" ) {
            // The text parts, in order. A single-part message has one,
            // numbered 1 by Message::partNumber().
            List<Bodypart> text;
            List<Bodypart>::Iterator i( m->allBodyparts() );
            while ( i ) {
                ContentType * ct = i->contentType();
                if ( !ct ||
                     ( ct->type() == "text" && ct->subtype() == "plain" ) )
                    text.append( i );
                ++i;
            }

            if ( property == "textBody" ) {
                Json * l = Json::list();
                List<Bodypart>::Iterator b( text );
                while ( b ) {
                    Json * part = Json::object();
                    part->insert( "partId",
                                  Json::string( m->partNumber( b ) ) );
                    part->insert( "type",
                                  Json::string( EString( "text/plain" ) ) );
                    part->insert( "size", Json::number( b->numBytes() ) );
                    l->append( part );
                    ++b;
                }
                r->insert( "textBody", l );
            }
            else if ( property == "bodyValues" ) {
                Json * v = Json::object();
                if ( d->wantText ) {
                    List<Bodypart>::Iterator b( text );
                    while ( b ) {
                        UString t = b->text();
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
                        v->insert( m->partNumber( b ), value );
                        ++b;
                    }
                }
                r->insert( "bodyValues", v );
            }
            else {
                // The preview is the start of the first text part, with
                // whitespace collapsed, as RFC8621 4.1.4 suggests.
                UString t;
                List<Bodypart>::Iterator b( text );
                if ( b )
                    t = b->text().simplified();
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
                d->properties.append( p->ascii() );
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
        d->wantText = d->properties.contains( "bodyValues" );
        Json * f = arguments()->member( "fetchTextBodyValues" );
        if ( f && f->valid( Json::Boolean ) && !f->boolean() )
            d->wantText = false;
        Json * mb = arguments()->member( "maxBodyValueBytes" );
        if ( mb && mb->valid( Json::Number ) && mb->number() > 0 )
            d->bodyBytes = (uint)mb->number();
        d->wantBody = d->wantText ||
                      d->properties.contains( "preview" ) ||
                      d->properties.contains( "textBody" ) ||
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
