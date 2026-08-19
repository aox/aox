#ifndef CLIENT_H
#define CLIENT_H

#include "connection.h"

#include "list.h"
#include "script.h"


class TestClient
    : public Connection
{
public:
    TestClient( class TestRunner *, const EString &, int = -1 );

    void react( Event );

    static void setServerAddress( const EString & );
    static EString serverAddress();

    EString name() const;

    void read();
    void write();

private:
    class TestClientData * d;
};


#endif
