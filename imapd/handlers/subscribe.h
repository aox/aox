#ifndef SUBSCRIBE_H
#define SUBSCRIBE_H

#include "imapcommand.h"


class Subscribe
    : public ImapCommand
{
public:
    enum Mode { Add, Remove };

    Subscribe( Mode m = Add )
        : mode( m ), selected( false ), q( 0 )
    {}

    void parse();
    void execute();

private:
    String m;
    Mode mode;
    bool selected;
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
