#ifndef SCOPE_H
#define SCOPE_H

class Arena;
class Log;

class Scope {
public:
    Scope();
    Scope( Arena *a );
    ~Scope();

    static Scope *current();

    Arena *arena() const;
    void setArena( Arena *a );

    Log *log() const;
    void setLog( Log *l );

private:
    Scope *parent;
    Arena *currentArena;
    Log   *currentLog;
};

#endif
