#include "imap.h"

#include "test.h"
#include "buffer.h"


class IMAPData {
public:
    // nothing for now
};


/*! \class IMAP

  \brief The IMAP class implements the IMAP server seen by clients.

  Most of IMAP functionality is in the command handlers, but this
  class contains the top-level responsibility and functionality. This
  class reads commands from its network connection, does basic
  parsing and creates command handlers as necessary.
*/


/*! Creates a basic IMAP connection */

IMAP::IMAP(int s)
    : Connection(s), d(0)
{
    setReadBuffer( new Buffer );
    setWriteBuffer( new Buffer );
    writeBuffer()->append("* PREAUTH\r\n");
}


/*! Destroys the object and closes its network connection. */

IMAP::~IMAP()
{
    delete d;
}


/*! Handles incoming data and timeouts. */

bool IMAP::react(Event e)
{
    switch (e) {
    case Connection::Read: {
        parse();
        break;
    }
    case Connection::Timeout:
        break;
    }
    return true;
}


void IMAP::parse()
{
    readBuffer()->remove(readBuffer()->size());
    writeBuffer()->append("* BAD parsefeil\r\n");
}


static class IMAPTest : public Test {
public:
    IMAPTest() : Test( 500 ) {}
    void test() {
    }
} imapTest;
