#ifndef OCADMIN_H
#define OCADMIN_H

#include "connection.h"


class OCAdmin
    : public Connection
{
public:
    OCAdmin( int );
    ~OCAdmin();

    void parse();
    void react( Event );

private:
    class OCAData *d;
};


#endif
