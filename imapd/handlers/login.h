#ifndef LOGIN_H
#define LOGIN_H

#include "imapcommand.h"
#include "string.h"
#include "sasl/plain.h"


class Login
    : public ImapCommand
{
public:
    Login()
        : m( 0 )
    {}

    void parse();
    void execute();

private:
    String n, p;
    Plain *m;
};


#endif
