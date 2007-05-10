// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCOPE_H
#define SCOPE_H

class Log;

#include "global.h"


class Scope
    : public Garbage
{
public:
    Scope();
    Scope( Log * );
    ~Scope();

    static Scope *current();

    Log *log() const;
    void setLog( Log * );

private:
    class ScopeData * d;
};


#endif
