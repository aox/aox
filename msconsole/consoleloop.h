// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONSOLELOOP_H
#define CONSOLELOOP_H

#include "eventloop.h"
#include <qobject.h>


class ConsoleLoop
    : public EventLoop
{
public:
    ConsoleLoop();

    void stop();
    void shutdown();
    void addConnection( Connection * );
    void removeConnection( Connection * );

private:
    class ConsoleLoopData * d;
};


class EventNotifier
    : public QObject
{
    Q_OBJECT
public:
    EventNotifier( Connection * );
    ~EventNotifier();

    Connection * connection() const;

public slots:
    void acceptRead();
    void acceptWrite();
    void dispatch();

private:
    class QSocketNotifier * rn;
    class QSocketNotifier * wn;
    Connection * c;
    bool r;
    bool w;
};


#endif
