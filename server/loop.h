#ifndef LOOP_H
#define LOOP_H

class Connection;


class Loop {
public:
    static void setup();
    static void start();
    static void shutdown();
    static void addConnection( Connection * );
    static void removeConnection( Connection * );
    static void closeAllExcept( Connection *, Connection * );
    static void flushAll();
};


#endif
