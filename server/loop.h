#ifndef LOOP_H
#define LOOP_H


class Connection;


class Loop {
public:
    static void start();
    static void shutdown();
    static void addConnection( Connection * );
    static void removeConnection( Connection * );

private:
    static void dispatch( Connection *, bool, bool, int );
};


#endif
