#ifndef TABLE_H
#define TABLE_H

#include "list.h"
#include "map.h"


class TableBase
{
public:
    TableBase();
    ~TableBase();

    void note( uint );
    void clear();
    String failures();

private:
    class TableBaseData * d;
};


template<class T>
class Table: public TableBase
{
public:
    Table() {}

    T * find( uint i ) {
        T * t = m.find( i );
        if ( t == 0 )
            note( i );
        return t;
    }
    bool contains( uint i ) {
        return m.find( i ) != 0;
    }

private:
    Map<T> m;
};


#endif
