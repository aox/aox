#ifndef __IMAP_H__
#define __IMAP_H__

#include "connection.h"

class Command;


class IMAPData;
class IMAP : public Connection {
public:
    IMAP(int s);
    ~IMAP();

    int react(Event e);

    int parse();
    void addCommand();
    void runCommands();

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

    void setIdle( bool );
    bool idle() const;

    void reserve( Command * );

private:
    IMAPData *d;
};

#endif
