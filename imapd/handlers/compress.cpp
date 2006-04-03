// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "compress.h"

#include "buffer.h"
#include "filter.h"
#include "scope.h"
#include "imap.h"
#include "sys.h"
#include "log.h"

#include <zlib.h>


static const uint bufsiz = 8192;
static char buffer[bufsiz];


class DeflateFilter: public Filter
{
public:
    DeflateFilter();
    ~DeflateFilter();

    int read( char *, uint, Buffer * );
    int write( char *, uint, Buffer * );
    z_stream s;
};


DeflateFilter::DeflateFilter()
    : Filter()
{
    s.zalloc = 0;
    s.zfree = 0;
    s.opaque = 0;
    ::deflateInit( &s, 9 );
}


DeflateFilter::~DeflateFilter()
{
    ::deflateEnd( &s );
}


int DeflateFilter::read( char *, uint, Buffer * )
{
    throw FD;
}


int DeflateFilter::write( char * data, uint len, Buffer * next )
{
    uint done = 0;
    int r = Z_OK;
    while ( done < len && r == Z_OK ) {
        s.avail_in = len - done;
        s.next_in = (Bytef*)(data + done);
        s.next_out = (Bytef*)buffer;
        s.avail_out = bufsiz;
        r = ::deflate( &s, Z_SYNC_FLUSH );
        uint wrote = (len-done)-s.avail_in;
        done += wrote;
        next->append( buffer, bufsiz - s.avail_out );
    }
    return done;
}


class InflateFilter: public Filter
{
public:
    InflateFilter();
    ~InflateFilter();

    virtual int read( char *, uint, Buffer * );
    virtual int write( char *, uint, Buffer * );
    z_stream s;
};


InflateFilter::InflateFilter()
    : Filter()
{
    s.zalloc = 0;
    s.zfree = 0;
    s.opaque = 0;
    ::inflateInit( &s );
}


InflateFilter::~InflateFilter()
{
    ::inflateEnd( &s );
}


int InflateFilter::read( char * data, uint len, Buffer * next )
{
    uint done = 0;
    int r = Z_OK;
    while ( done < len && next->size() > 0 && r == Z_OK ) {
        s.avail_in = next->size();
        String b = next->string( s.avail_in );
        s.next_in = (Bytef*)b.data();
        s.next_out = (Bytef*)(data + done);
        s.avail_out = len-done;
        uint availin = s.avail_in;
        uint availout = s.avail_out;

        // note that if inflate allocates memory, it'll use its own
        // system, not ours.
        r = ::inflate( &s, Z_SYNC_FLUSH );
        done = done + ( availout - s.avail_out );
        next->remove( availin - s.avail_in );
    }

    return done;
}


int InflateFilter::write( char *, uint, Buffer * )
{
    throw FD;
}


/*! \class Compress compress.h
  This Compress class implements the (gone?) COMPRESS=DEFLATE extension.

  This is/was an IMAP extension draft. It seems to have been
  superseded/replaced by a TLS extension. The code here may be usable
  to implement the TLS extension, who knows.
*/

/*!  Constructs a handler for the deflate compression. */

Compress::Compress()
    : Command()
{
}


/*! Parses the single argument to compress: "deflate". */

void Compress::parse()
{
    space();
    a = astring();
    end();
}


/*! Starts deflating, assuming all goes well. */

void Compress::execute()
{
    if ( a.lower() != "deflate" ) {
        error( Bad, "Only DEFLATE is supported" );
        return;
    }

    Buffer * r = imap()->readBuffer();
    Buffer * w = imap()->writeBuffer();
    emitResponses();

    r->addFilter( new InflateFilter );
    w->addFilter( new DeflateFilter );

    setState( Finished );
}
