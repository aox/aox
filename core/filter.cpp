// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "filter.h"


/*! \class Filter filter.h
  The Filter class filters a the I/O of a Buffer.

  A Buffer may call the file read/write functions, or it may call a
  Filter's read() or write() (both of which are virtual functions). A
  filter may be installed on a Buffer using Buffer::addFilter().
*/

/*! Constructs an empty Filter. */

Filter::Filter()
{
}


/*! Destroys the object and frees any allocated resources. */

Filter::~Filter()
{
}



/*! \fn int Filter::read( char * address, uint len, Buffer * buffer )

    This virtual function reads up to \a len bytes into memory
    starting at \a address. It may use \a buffer as a data source,
    filtering the data as appropriate for each subclass of Filter.
*/


/*! \fn int Filter::write( char * address, uint len, Buffer * buffer )

    This virtual function writes \a len bytes starting at \a
    address. It may use \a buffer as a sink after filtering the data.
*/


/*! \fn void Filter::flush( Buffer * buffer )
   
   This virtual function is responsible for flushing any queues the
   filter may have, such that all output is sent to \a buffer. The
   default implementation does nothing.
*/
