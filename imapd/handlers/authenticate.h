#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "command.h"
#include "string.h"


class Authenticate
    : public Command
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
