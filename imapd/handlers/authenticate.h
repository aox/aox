#ifndef __AUTHENTICATE_H__
#define __AUTHENTICATE_H__

#include "command.h"
#include "string.h"


class Authenticate: public Command {
public:
    Authenticate();
    void parse();
    void execute();
    void read();

private:
    String t, r;
    class Authenticator *a;
};

#endif
