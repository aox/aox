// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCOPE_H
#define SCOPE_H

class Arena;
class Log;


class Scope {
public:
    Scope();
    Scope( Arena * );
    Scope( Arena *, Log * );
    ~Scope();

    static Scope *current();

    Arena *arena() const;
    void setArena( Arena * );

    Log *log() const;
    void setLog( Log * );

private:
    Scope *parent;
    Arena *currentArena;
    Log   *currentLog;
};


#endif
