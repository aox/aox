#ifndef TLS_H
#define TLS_H

#include "global.h"

class String;
class EventHandler;


class TlsServer
{
public:
    TlsServer( EventHandler * );

    bool done() const;
    bool ok() const;

    int userSideSocket() const;
    int serverSideSocket() const;

private:
    void parent( int );
    void intermediate();
    void child();
    void bad();

private:
    class TlsServerData * d;
};


#endif
