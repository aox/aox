#include "imap.h"

#include "test.h"
#include "buffer.h"

class IMAPData {
public:
    Buffer readBuf, writeBuf;
};

IMAP::IMAP(int s)
    : Connection(s)
{
    d = new IMAPData;
    d->writeBuf.append("* PREAUTH\r\n");
}

IMAP::~IMAP()
{
    delete d;
}

bool IMAP::wants(Event e) const
{
    switch (e) {
    case Connection::Read:
        return true;
        break;
    case Connection::Write:
        if (d->writeBuf.size() != 0)
            return true;
        break;
    case Connection::Except:
        break;
    case Connection::Timeout:
        if (timeout() != 0)
            return true;
        break;
    }
    return false;
}

bool IMAP::react(Event e)
{
    switch (e) {
    case Connection::Read: {
        uint sz = d->readBuf.size(); /* XXX */
        d->readBuf.read(fd());
        if (sz == d->readBuf.size())
            /* close */
            return false;
        parse();
        break;
    }
    case Connection::Write:
        d->writeBuf.write(fd());
        break;
    case Connection::Timeout:
        break;
    case Connection::Except:
        break;
    }
    return true;
}

void IMAP::parse()
{
    d->readBuf.remove(d->readBuf.size());
    d->writeBuf.append("* BAD parsefeil\r\n");
}

static class IMAPTest : public Test {
public:
    IMAPTest() : Test( 500 ) {}
    void test() {
    }
} imapTest;
