// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EVENT_H
#define EVENT_H

class Arena;


class EventHandler {
public:
    EventHandler();

    Arena *arena() const;
    void setArena( Arena * );

    virtual void notify();
    virtual void execute() = 0;

private:
    Arena *a;
};


#endif
