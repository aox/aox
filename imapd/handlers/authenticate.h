#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "imapcommand.h"
#include "string.h"


class Authenticate
    : public ImapCommand
{
public:
    Authenticate()
        : m( 0 ), r( 0 )
    {}

    void parse();
    void execute();
    void read();

private:
    class SaslMechanism *m;
    String *r;
    String t;
};


#endif
