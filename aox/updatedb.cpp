// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "updatedb.h"

#include "md5.h"
#include "utf.h"
#include "dict.h"
#include "query.h"
#include "cache.h"
#include "ustring.h"
#include "address.h"
#include "transaction.h"
#include "addresscache.h"

#include <stdio.h>
#include <stdlib.h>


class LwAddressCache;
class HeaderFieldRow;


static PreparedStatement * fetchValues;
static PreparedStatement * fetchAddresses;
static PreparedStatement * updateAddressField;
static PreparedStatement * insertAddressField;
static PreparedStatement * deleteHeaderFields;


struct Id
    : public Garbage
{
    Id( uint n, String s )
        : id( n ), name( s )
    {}

    uint id;
    String name;
};


struct AddressMap
    : public Garbage
{
    AddressMap() : bad( 0 ), good( 0 ) {}

    Address * bad;
    Address * good;
};


class HeaderFieldRow
    : public Garbage
{
public:
    HeaderFieldRow()
        : mailbox( 0 ), uid( 0 ), position( 0 ), field( 0 )
    {}

    uint mailbox;
    uint uid;
    String part;
    uint position;
    uint field;
    String value;
};


class LwAddressCache
    : public EventHandler
{
public:
    Query * q;
    Dict<uint> * names;
    EventHandler * owner;

    LwAddressCache( EventHandler * ev )
        : q( 0 ), names( new Dict<uint>( 16384 ) ), owner( ev )
    {}

    void execute()
    {
        while ( q->hasResults() ) {
            Row * r = q->nextRow();

            uint * id = (uint *)Allocator::alloc( sizeof(uint), 0 );
            *id = r->getInt( "id" );
            Address * a =
                new Address( r->getUString( "name" ),
                             r->getString( "localpart" ),
                             r->getString( "domain" ) );

            names->insert( a->toString(), id );
        }

        if ( q->done() ) {
            printf( "  Loaded %d addresses into cache.\n", q->rows() );
            owner->execute();
        }
    }

    uint lookup( const Address * a )
    {
        uint * id = names->find( a->toString() );
        if ( id )
            return *id;
        return 0;
    }
};


class UpdateDatabaseData
    : public Garbage
{
public:
    UpdateDatabaseData()
        : query( 0 ), q( 0 ), conversions( 0 ), t( 0 ), address( 0 ),
          state( 0 ), ids( 0 ), addressCache( 0 ),
          parsers( 0 ), unknownAddresses( 0 ), headerFieldRows( 0 ),
          cacheLookup( 0 ), uniq( new Dict<void>( 1000 ) ),
          addressMap( new List<AddressMap> ), row( 0 )
    {}

    Query * query;
    Query * q;
    uint conversions;
    Transaction * t;
    Address * address;
    String s;
    int state;
    List< Id > * ids;
    LwAddressCache * addressCache;
    Dict<AddressParser> * parsers;
    List<Address> * unknownAddresses;
    List<HeaderFieldRow> * headerFieldRows;
    CacheLookup * cacheLookup;
    Dict<void> * uniq;
    List<AddressMap> * addressMap;
    Row * row;
    String hash;
};


/*! \class UpdateDatabase updatedb.h
    This class handles the "aox update database" command.
*/

UpdateDatabase::UpdateDatabase( StringList * args )
    : AoxCommand( args )
{
    d = 0;
}


bool UpdateDatabase::convertField( uint mailbox, uint uid,
                                   const String & part,
                                   uint position, uint field,
                                   const String & value )
{
    Query * q;
    AddressParser * p;
    p = d->parsers->find( value );
    if ( !p ) {
        p = new AddressParser( value );
        d->parsers->insert( value, p );
    }

    bool unknown = false;
    List<Address>::Iterator it( p->addresses() );
    while ( it ) {
        Address * a = it;
        uint address = d->addressCache->lookup( a );
        if ( address == 0 ) {
            if ( !d->uniq->contains( a->toString() ) ) {
                d->unknownAddresses->append( a );
                d->uniq->insert( a->toString(), (void *)1 );
            }
            unknown = true;
        }
        a->setId( address );
        ++it;
    }

    if ( unknown )
        return false;

    uint number = 0;
    it = p->addresses();
    while ( it ) {
        Address * a = it;

        if ( part.isEmpty() )
            q = new Query( *updateAddressField, this );
        else
            q = new Query( *insertAddressField, this );

        q->bind( 1, mailbox );
        q->bind( 2, uid );
        q->bind( 3, part );
        q->bind( 4, position );
        q->bind( 5, field );
        q->bind( 6, a->id() );
        q->bind( 7, number );

        d->t->enqueue( q );

        number++;
        ++it;
    }

    d->conversions++;
    return true;
}


void UpdateDatabase::execute()
{
    if ( !d ) {
        d = new UpdateDatabaseData;
        end();

        fetchValues =
            new PreparedStatement(
                "select uid,part,position,field,value from header_fields "
                "where mailbox=$1 and ((part<>'' and field<=12) or "
                "(mailbox,uid,part,position,field) in "
                "(select mailbox,uid,part,position,field from address_fields"
                " where mailbox=$1 group by mailbox,uid,part,position,field"
                " having count(*)<>count(number)))"
            );
        Allocator::addEternal( fetchValues, "fetchValues" );

        fetchAddresses =
            new PreparedStatement(
                "select id,name,localpart,domain from address_fields af "
                "join addresses a on (af.address=a.id) where mailbox=$1 "
                "and uid in (select uid from address_fields where "
                "mailbox=$1 group by uid having count(*)<>count(number))"
            );
        Allocator::addEternal( fetchAddresses, "fetchAddresses" );

        updateAddressField =
            new PreparedStatement(
                "update address_fields set number=$7 where mailbox=$1 and "
                "uid=$2 and part=$3 and position=$4 and field=$5 and "
                "address=$6"
            );
        Allocator::addEternal( updateAddressField, "updateAddressField" );

        insertAddressField =
            new PreparedStatement(
                "insert into address_fields "
                "(mailbox,uid,part,position,field,address,number) values "
                "($1,$2,$3,$4,$5,$6,$7)"
            );
        Allocator::addEternal( insertAddressField, "insertAddressField" );

        deleteHeaderFields =
            new PreparedStatement(
                "delete from header_fields where mailbox=$1 and field<=12 "
                "and uid not in (select uid from address_fields where "
                "mailbox=$1 group by uid having count(*)<>count(number))"
            );
        Allocator::addEternal( deleteHeaderFields, "deleteHeaderFields" );

        database( true );
        AddressCache::setup();
        d->state = 0;
    }

    while ( d->state != 675 ) {
        if ( d->state == 0 ) {
            printf( "- Checking for unconverted address fields in "
                    "header_fields.\n" );
            d->state = 1;
            d->query =
                new Query( "select id,name from mailboxes where id in "
                           "(select distinct mailbox from address_fields"
                           " where number is null) order by name", this );
            d->query->execute();
        }

        if ( d->state == 1 ) {
            if ( !d->query->done() )
                return;

            d->ids = new List<Id>;

            Row * r;
            while ( ( r = d->query->nextRow() ) != 0 ) {
                Id * id = new Id( r->getInt( "id" ),
                                  r->getString( "name" ) );
                d->ids->append( id );
            }

            uint n = d->ids->count();
            if ( n == 0 ) {
                d->state = 666;
            }
            else {
                printf( "  %d mailboxes to process:\n", n );
                d->state = 2;
            }
        }

        if ( d->state <= 7 && d->state >= 2 ) {
            List<Id>::Iterator it( d->ids );
            while ( it ) {
                Id * m = it;

                if ( d->state == 2 ) {
                    printf( "- Processing %s\n", m->name.cstr() );
                    d->state = 3;
                    d->t = new Transaction( this );
                    d->parsers = new Dict<AddressParser>( 1000 );
                    d->unknownAddresses = new List<Address>;
                    d->headerFieldRows = new List<HeaderFieldRow>;
                    d->addressCache = new LwAddressCache( this );
                    d->query = new Query( *fetchAddresses, d->addressCache );
                    d->addressCache->q = d->query;
                    d->query->bind( 1, m->id );
                    d->query->execute();
                }

                if ( d->state == 3 ) {
                    if ( !d->query->done() )
                        return;

                    d->state = 4;
                    d->query = new Query( *fetchValues, this );
                    d->query->bind( 1, m->id );
                    d->query->execute();
                }

                if ( d->state == 4 ) {
                    uint updates = 0;

                    while ( d->query->hasResults() ) {
                        Row * r = d->query->nextRow();

                        uint mailbox( m->id );
                        uint uid( r->getInt( "uid" ) );
                        String part( r->getString( "part" ) );
                        uint position = r->getInt( "position" );
                        uint field( r->getInt( "field" ) );
                        String value( r->getString( "value" ) );

                        bool p = convertField( mailbox, uid, part, position,
                                               field, value );
                        if ( p ) {
                            updates++;
                        }
                        else {
                            HeaderFieldRow * hf = new HeaderFieldRow;
                            hf->mailbox = mailbox;
                            hf->uid = uid;
                            hf->part = part;
                            hf->position = position;
                            hf->field = field;
                            hf->value = value;
                            d->headerFieldRows->append( hf );
                        }
                    }

                    if ( updates )
                        d->t->execute();

                    if ( !d->query->done() )
                        return;

                    if ( d->unknownAddresses->isEmpty() ) {
                        d->state = 6;
                    }
                    else {
                        d->state = 5;
                        if ( d->conversions )
                            printf( "  Converted %d address fields.\n",
                                    d->conversions );
                        d->conversions = 0;
                        if ( !d->unknownAddresses->isEmpty() )
                            printf( "  Looking up %d more addresses.\n",
                                    d->unknownAddresses->count() );
                        d->cacheLookup =
                            AddressCache::lookup( d->t, d->unknownAddresses,
                                                  this );
                    }
                }

                if ( d->state == 5 ) {
                    if ( !d->cacheLookup->done() )
                        return;

                    List<Address>::Iterator ad( d->unknownAddresses );
                    while ( ad ) {
                        Address * a = ad;
                        uint * n = (uint *)Allocator::alloc( sizeof(uint), 0 );
                        *n = a->id();
                        d->addressCache->names->insert( a->toString(), n );
                        ++ad;
                    }

                    List<HeaderFieldRow>::Iterator it( d->headerFieldRows );
                    while ( it ) {
                        bool p;
                        HeaderFieldRow * hf = it;
                        p = convertField( hf->mailbox, hf->uid, hf->part,
                                          hf->position, hf->field, hf->value );
                        if ( p )
                            d->headerFieldRows->take( it );
                        else
                            ++it;
                    }

                    if ( d->conversions )
                        printf( "  Converted %d address fields on the "
                                "second attempt.\n", d->conversions );
                    d->conversions = 0;
                    d->state = 6;
                }

                if ( d->state == 6 ) {
                    d->state = 7;
                    d->query = new Query( *deleteHeaderFields, this );
                    d->query->bind( 1, m->id );
                    d->t->enqueue( d->query );
                    d->t->commit();
                }

                if ( d->state == 7 ) {
                    if ( !d->t->done() )
                        return;

                    if ( d->t->failed() ) {
                        fprintf( stderr, "Database error: %s\n",
                                 d->t->error().cstr() );
                        exit( -1 );
                    }

                    d->state = 2;
                    d->ids->take( it );
                }
            }

            if ( it )
                return;

            d->state = 666;
        }

        if ( d->state == 666 ) {
            d->state = 667;
            printf( "- Checking for misparsed addresses.\n" );
            d->t = new Transaction( this );
            d->query =
                new Query( "select distinct id,name,localpart,domain "
                           "from address_fields af join addresses a "
                           "on (af.address=a.id) where number is null ",
                           this );
            d->t->enqueue( d->query );
            d->t->execute();
        }

        if ( d->state == 667 ) {
            if ( !d->query->done() )
                return;

            List<Address> * addresses = new List<Address>;
            while ( d->query->hasResults() ) {
                Row * r = d->query->nextRow();

                AddressMap * m = new AddressMap;
                m->bad = new Address( r->getUString( "name" ),
                                      r->getString( "localpart" ),
                                      r->getString( "domain" ) );
                m->bad->setId( r->getInt( "id" ) );

                AddressParser ap( m->bad->toString() );
                if ( ap.addresses() )
                    m->good = ap.addresses()->first();

                if ( m->good ) {
                    d->addressMap->append( m );
                    addresses->append( m->good );
                }
            }

            printf( "  Reparsing %d addresses.\n", addresses->count() );

            d->state = 668;
            d->cacheLookup = AddressCache::lookup( d->t, addresses, this );
        }

        if ( d->state == 668 ) {
            if ( !d->cacheLookup->done() )
                return;

            String s( "update address_fields set address=CASE address " );
            String w( "" );

            d->conversions = 0;
            List<AddressMap>::Iterator it( d->addressMap );
            while ( it ) {
                if ( it->good->id() != 0 &&
                     it->good->id() != it->bad->id() )
                {
                    s.append( "WHEN " );
                    s.append( fn( it->bad->id() ) );
                    s.append( " THEN " );
                    s.append( fn( it->good->id() ) );
                    s.append( " " );
                    d->conversions++;
                    if ( w.isEmpty() )
                        w.append( "WHERE " );
                    else
                        w.append( "or " );
                    w.append( "address=" );
                    w.append( fn( it->bad->id() ) );
                    w.append( " " );
                }
                ++it;
            }

            s.append( "END " );
            s.append( w );

            d->state = 669;

            if ( d->conversions != 0 ) {
                printf( "  Updating %d reparsed addresses.\n",
                        d->conversions );
                d->query = new Query( s, this );
                d->t->enqueue( d->query );
            }

            d->t->commit();
        }

        if ( d->state == 669 ) {
            if ( !d->t->done() )
                return;

            if ( d->t->failed() ) {
                fprintf( stderr, "Database error: %s\n",
                         d->t->error().cstr() );
                exit( -1 );
            }
            else {
                if ( d->conversions != 0 ) {
                    printf( "- Rerunning update database.\n" );
                    d->addressMap->clear();
                    d->state = 0;
                }
                else {
                    d->state = 670;
                }
            }
        }

        if ( d->state == 670 ) {
            printf( "- Checking for NUL bytes in bodyparts\n" );
            d->query =
                new Query( "select id,textsend(text) as text "
                           "from bodyparts where "
                           "position('\\\\000' in textsend(text)) > 0",
                           this );
            d->state = 671;
            d->query->execute();
        }

        if ( d->state == 671 ) {
            while ( d->query->hasResults() ) {
                d->row = d->query->nextRow();
                UString s( d->row->getUString( "text" ) );

                PgUtf8Codec u;
                String data( u.fromUnicode( s ) );
                d->hash = MD5::hash( data ).hex();

                d->state = 672;
                d->q = new Query( "update bodyparts set text=$1,hash=$2 "
                                  "where id=$3", this );
                d->q->bind( 1, s );
                d->q->bind( 2, d->hash );
                d->q->bind( 3, d->row->getInt( "id" ) );
                d->q->allowFailure();
                d->q->execute();
                return;
            }

            if ( !d->query->done() )
                return;

            printf( "- Finished processing %d bodyparts.\n",
                    d->query->rows() );

            d->state = 675;
        }

        if ( d->state == 672 ) {
            if ( !d->q->done() )
                return;

            if ( d->q->failed() ) {
                if ( d->q->error().contains( "unique constraint" ) ) {
                    d->state = 673;
                    d->t = new Transaction( this );
                    d->q = new Query( "select id from bodyparts where "
                                      "hash=$1", this );
                    d->q->bind( 1, d->hash );
                    d->t->enqueue( d->q );
                    d->t->execute();
                }
                else {
                    error( "Error: " + d->q->error() );
                }
            }
            else {
                d->state = 671;
            }
        }

        if ( d->state == 673 ) {
            if ( !d->q->done() )
                return;

            Row * r = d->q->nextRow();
            if ( !r || d->q->failed() ) {
                String s( "Error: Couldn't fetch colliding bodypart id" );
                if ( d->q->failed() ) {
                    s.append( ": " );
                    s.append( d->q->error() );
                }
                error( s );
            }

            printf( "  Resolving hash collision between bodyparts %d "
                    "and %d (%s).\n",
                    r->getInt( "id" ), d->row->getInt( "id" ),
                    d->hash.cstr() );

            d->state = 674;
            d->q = new Query( "update part_numbers set bodypart=$1 "
                              "where bodypart=$2", this );
            d->q->bind( 1, r->getInt( "id" ) );
            d->q->bind( 2, d->row->getInt( "id" ) );
            d->t->enqueue( d->q );
            d->q = new Query( "delete from bodyparts where id=$1", this );
            d->q->bind( 1, d->row->getInt( "id" ) );
            d->t->enqueue( d->q );
            d->t->commit();
        }

        if ( d->state == 674 ) {
            if ( !d->t->done() )
                return;

            if ( d->t->failed() )
                error( "Error: " + d->t->error() );

            d->state = 671;
        }
    }

    printf( "Done.\n" );
    finish();
}
