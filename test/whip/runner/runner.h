#ifndef RUNNER_H
#define RUNNER_H

#include "global.h"

#include "list.h"
#include "script.h"
#include "connection.h"


class TestRunner
    : public Garbage
{
public:
    TestRunner( List<TestScript> *, bool verbose );

    void react( Connection::Event, class TestClient * );

    static void add( TestScript * );
    static bool running();
    static void run( bool );

    void finish();
    void close( bool );

    void compare();

    void error( EString );
    void log( EString );

    void send();

    void accept( TestClient * );

private:
    class TestRunnerData * d;
};


#endif
