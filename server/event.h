#ifndef EVENT_H
#define EVENT_H

class Arena;


class EventHandler {
public:
    EventHandler();

    virtual void notify();
    virtual void execute() = 0;

    Arena * arena() const;
    void setArena( Arena * );

private:
    class DCData *d;
};


#endif
