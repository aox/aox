// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "emailquery.h"

#include "json.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "selector.h"
#include "estringlist.h"


class EmailQueryData
    : public Garbage
{
public:
    EmailQueryData()
        : q( 0 ), count( 0 ), state( 0 ),
          position( 0 ), limit( 256 ), total( false )
    {}

    Query * q;
    Query * count;
    Query * state;
    uint position;
    uint limit;
    bool total;
};


/*! \class EmailQuery emailquery.h

    The EmailQuery class implements Email/query of RFC8621 4.4: it
    turns a JMAP filter into a Selector.

    Filter conditions this does not implement are refused with
    unsupportedFilter rather than ignored.
*/


/*! Constructs an Email/query for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

EmailQuery::EmailQuery( EventHandler * owner, User * user, Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new EmailQueryData )
{
}


/*! Returns a Selector for the JMAP FilterCondition or FilterOperator
    \a filter, or a null pointer, in which case \a error names the
    JMAP error to return.
*/

Selector * EmailQuery::condition( Json * filter, EString & error )
{
    if ( !filter || filter->valid( Json::Null ) )
        return new Selector( Selector::All );

    if ( !filter->valid( Json::Object ) ) {
        error = "invalidArguments";
        return 0;
    }

    Json * op = filter->member( "operator" );
    if ( op ) {
        if ( !op->valid( Json::String ) ) {
            error = "invalidArguments";
            return 0;
        }
        Json * conditions = filter->member( "conditions" );
        if ( !conditions || !conditions->valid( Json::Array ) ) {
            error = "invalidArguments";
            return 0;
        }
        EString o = op->ascii();
        Selector * s = 0;
        if ( o == "AND" )
            s = new Selector( Selector::And );
        else if ( o == "OR" )
            s = new Selector( Selector::Or );
        else if ( o == "NOT" )
            s = new Selector( Selector::Not );
        else {
            error = "unsupportedFilter";
            return 0;
        }
        List<Json>::Iterator i( conditions->array() );
        while ( i ) {
            Selector * c = condition( i, error );
            if ( !c )
                return 0;
            s->add( c );
            ++i;
        }
        return s;
    }

    Selector * s = new Selector( Selector::And );
    EStringList::Iterator m( filter->members() );
    while ( m ) {
        EString name = *m;
        Json * v = filter->member( name );
        ++m;

        if ( name == "inMailbox" ) {
            if ( !v->valid( Json::String ) ) {
                error = "invalidArguments";
                return 0;
            }
            Mailbox * mb = 0;
            EString id = v->ascii();
            if ( id.startsWith( "f" ) )
                mb = Mailbox::find( id.mid( 1 ).number( 0 ) );
            if ( !mb || mb->deleted() ) {
                // RFC8621 4.4.1: an unknown mailbox id is an invalid
                // argument, not an empty result
                error = "invalidArguments";
                return 0;
            }
            s->add( new Selector( mb, false ) );
        }
        else if ( name == "from" || name == "to" ||
                  name == "cc" || name == "bcc" ||
                  name == "subject" ) {
            if ( !v->valid( Json::String ) ) {
                error = "invalidArguments";
                return 0;
            }
            s->add( new Selector( Selector::Header, Selector::Contains,
                                  name, v->string() ) );
        }
        else if ( name == "body" ) {
            if ( !v->valid( Json::String ) ) {
                error = "invalidArguments";
                return 0;
            }
            s->add( new Selector( Selector::Body, Selector::Contains,
                                  v->string() ) );
        }
        else if ( name == "text" ) {
            if ( !v->valid( Json::String ) ) {
                error = "invalidArguments";
                return 0;
            }
            // header and body, as IMAP's TEXT does. The field name is
            // null for any-field searches.
            Selector * o = new Selector( Selector::Or );
            o->add( new Selector( Selector::Body, Selector::Contains,
                                  v->string() ) );
            o->add( new Selector( Selector::Header, Selector::Contains,
                                  0, v->string() ) );
            s->add( o );
        }
        else if ( name == "header" ) {
            if ( !v->valid( Json::Array ) || v->array()->isEmpty() ||
                 v->array()->count() > 2 ) {
                error = "invalidArguments";
                return 0;
            }
            List<Json>::Iterator h( v->array() );
            EString field = h->ascii();
            ++h;
            if ( h )
                s->add( new Selector( Selector::Header, Selector::Contains,
                                      field, h->string() ) );
            else
                s->add( new Selector( Selector::Header, Selector::Contains,
                                      field, UString() ) );
        }
        else if ( name == "minSize" || name == "maxSize" ) {
            if ( !v->valid( Json::Number ) ) {
                error = "invalidArguments";
                return 0;
            }
            // JMAP's minSize is inclusive and maxSize exclusive;
            // Larger and Smaller are both exclusive.
            if ( name == "minSize" )
                s->add( new Selector( Selector::Rfc822Size, Selector::Larger,
                                      (uint)v->number() - 1 ) );
            else
                s->add( new Selector( Selector::Rfc822Size, Selector::Smaller,
                                      (uint)v->number() ) );
        }
        else if ( name == "hasKeyword" || name == "notKeyword" ) {
            if ( !v->valid( Json::String ) ) {
                error = "invalidArguments";
                return 0;
            }
            // JMAP spells the system keywords $seen, IMAP \Seen.
            EString keyword = v->ascii();
            if ( keyword.startsWith( "$" ) )
                keyword = "\\" + keyword.mid( 1 );
            Selector * k = new Selector( Selector::Flags, Selector::Contains,
                                         keyword );
            if ( name == "hasKeyword" ) {
                s->add( k );
            }
            else {
                Selector * n = new Selector( Selector::Not );
                n->add( k );
                s->add( n );
            }
        }
        else {
            // before, after, inMailboxOtherThan, hasAttachment and the
            // three thread-keyword conditions are not implemented. The
            // date ones need a Selector that compares timestamps
            // rather than whole days.
            error = "unsupportedFilter";
            return 0;
        }
    }
    return s;
}


/*! Returns the SQL order by clause for the JMAP sort \a sort, or an
    empty string, in which case \a error names the JMAP error.
*/

EString EmailQuery::order( Json * sort, EString & error )
{
    EStringList keys;
    EStringList clauses;
    if ( sort && sort->valid( Json::Array ) ) {
        List<Json>::Iterator i( sort->array() );
        while ( i ) {
            Json * c = i;
            ++i;
            if ( !c->valid( Json::Object ) ) {
                error = "invalidArguments";
                return "";
            }
            Json * p = c->member( "property" );
            if ( !p || !p->valid( Json::String ) ) {
                error = "invalidArguments";
                return "";
            }
            EString property = p->ascii();
            EString key;
            if ( property == "receivedAt" )
                key = "arrival";
            else if ( property == "sentAt" )
                key = "date";
            else if ( property == "size" )
                key = "size";
            else if ( property == "subject" )
                key = "subject";
            else if ( property == "from" )
                key = "from";
            else if ( property == "to" )
                key = "to";
            else {
                error = "unsupportedSort";
                return "";
            }
            bool ascending = true;
            Json * a = c->member( "isAscending" );
            if ( a ) {
                if ( !a->valid( Json::Boolean ) ) {
                    error = "invalidArguments";
                    return "";
                }
                ascending = a->boolean();
            }
            EString alias( "k" + fn( keys.count() ) );
            keys.append( Selector::sortExpression( key ) + " as " + alias );
            clauses.append( alias + ( ascending ? "" : " desc" ) );
        }
    }
    if ( keys.isEmpty() ) {
        // The default is newest first, which is what a client asking
        // for mail without saying more usually wants.
        keys.append( Selector::sortExpression( "arrival" ) + " as k0" );
        clauses.append( "k0 desc" );
    }
    clauses.append( "id" );
    return ", " + keys.join( ", " ) + " from (%s) s "
        "join messages m on (m.id=s.message) "
        "order by " + clauses.join( ", " );
}


void EmailQuery::execute()
{
    if ( !d->q ) {
        if ( !checkAccount() )
            return;

        Json * p = arguments()->member( "position" );
        if ( p && p->valid( Json::Number ) && p->number() > 0 )
            d->position = (uint)p->number();
        Json * l = arguments()->member( "limit" );
        if ( l && l->valid( Json::Number ) && l->number() >= 0 )
            d->limit = (uint)l->number();
        if ( d->limit > 256 )
            d->limit = 256;
        Json * t = arguments()->member( "calculateTotal" );
        if ( t && t->valid( Json::Boolean ) )
            d->total = t->boolean();
        if ( arguments()->member( "anchor" ) ) {
            // anchor and anchorOffset are not implemented; a client
            // that needs them can use position.
            fail( "invalidArguments" );
            return;
        }

        EString error;
        Selector * s = condition( arguments()->member( "filter" ), error );
        if ( !s ) {
            fail( error );
            return;
        }
        s->simplify();

        EStringList wanted;
        wanted.append( "message" );
        d->q = s->query( user(), 0, 0, this, false, &wanted, false );

        EString inner( d->q->string() );
        EString tail = order( arguments()->member( "sort" ), error );
        if ( tail.isEmpty() ) {
            fail( error );
            return;
        }
        int at = tail.find( "%s" );
        EString outer = "select distinct s.message as id" +
                        tail.mid( 0, at ) + inner + tail.mid( at + 2 );
        // With calculateTotal we have to count the matches anyway, so
        // we read them all and slice in C++. Without it, the database
        // does the slicing and sends only what the client asked for.
        if ( !d->total ) {
            // bound, not formatted in: no part of a request belongs in
            // the text of a query, however harmless a uint looks
            uint l = s->placeHolder();
            uint o = s->placeHolder();
            d->q->bind( l, d->limit );
            d->q->bind( o, d->position );
            outer.append( " limit $" + fn( l ) + " offset $" + fn( o ) );
        }
        d->q->setString( outer );
        d->q->execute();

        d->state = new Query( "select last_value from nextmodseq", this );
        d->state->execute();
    }

    if ( !d->q->done() || !d->state->done() )
        return;

    if ( d->q->failed() || d->state->failed() ) {
        fail( "serverFail" );
        return;
    }

    Json * ids = Json::list();
    uint seen = 0;
    uint used = 0;
    Row * r;
    while ( (r=d->q->nextRow()) != 0 ) {
        if ( !d->total ) {
            ids->append( Json::string( "m" + fn( r->getInt( "id" ) ) ) );
        }
        else {
            if ( seen >= d->position && used < d->limit ) {
                ids->append( Json::string( "m" + fn( r->getInt( "id" ) ) ) );
                used++;
            }
            seen++;
        }
    }

    int64 state = 1;
    r = d->state->nextRow();
    if ( r )
        state = r->getBigint( "last_value" );

    Json * response = Json::object();
    response->insert( "accountId", Json::string( fn( user()->id() ) ) );
    response->insert( "queryState", Json::string( "m" + fn( state ) ) );
    response->insert( "canCalculateChanges", Json::boolean( false ) );
    response->insert( "position", Json::number( d->position ) );
    response->insert( "ids", ids );
    if ( d->total )
        response->insert( "total", Json::number( seen ) );
    respond( "Email/query", response );
}
