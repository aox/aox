#ifndef __IMAP_H__
#define __IMAP_H__

#include "connection.h"

class IMAPData;
class IMAP : public Connection {
public:
    IMAP(int s);
    ~IMAP();

    int react(Event e);

    int parse();
    void addCommand();

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

private:
    IMAPData *d;
};

#endif
