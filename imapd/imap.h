#ifndef __IMAP_H__
#define __IMAP_H__

#include "connection.h"

class IMAPData;
class IMAP : public Connection {
public:
    IMAP(int s);
    ~IMAP();

    bool react(Event e);

    void parse();

private:
    IMAPData *d;
};

#endif
