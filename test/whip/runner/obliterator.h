// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OBLITERATOR_H
#define OBLITERATOR_H

#include "event.h"
#include "connection.h"

class TestRunner;


class Obliterator
    : public EventHandler
{
public:
    Obliterator( TestRunner *, const EString & loginName );

    void execute();

    bool done() const;
    EString error() const;

private:
    EString ln;
    class Query * ao;
    class Transaction * t;
    class TestRunner * r;
    Connection * w;
};


class ObliteratorBouncer
    : public EventHandler
{
public:
    ObliteratorBouncer( TestRunner * );

    void execute();

private:
    TestRunner * r;
};


#endif
