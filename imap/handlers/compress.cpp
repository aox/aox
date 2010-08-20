// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "compress.h"

#include "buffer.h"
#include "imap.h"


/*! \class Compress compress.h
  This Compress class implements the COMPRESS=DEFLATE extension.

  Wow. After only four years as a draft, and dying twice, the draft
  came out as RFC 4978 and is implemented by five programs at the time
  of publication.

  Our implementation is a little primitive. Interoperates with the
  latest, but doesn't contain the good ideas that were added late.
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

    r->setCompression( Buffer::Decompressing );
    w->setCompression( Buffer::Compressing );

    setState( Finished );
}
