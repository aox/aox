#ifndef SUBSCRIBE_H
#define SUBSCRIBE_H

#include "command.h"


class Subscribe
    : public Command
{
public:
    enum Mode { Add, Remove };

    Subscribe( Mode m = Add )
        : mode( m ), q( 0 )
    {}

    void parse();
    void execute();

private:
    String m;
    Mode mode;
    class Query *q;
};


class Unsubscribe
    : public Subscribe
{
public:
    Unsubscribe()
        : Subscribe( Subscribe::Remove )
    {}
};


#endif
