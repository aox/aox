#include "search.h"

/*! \class Search
  
  search          = "SEARCH" [SP "CHARSET" SP astring] 1*(SP search-key)
search-key      = "ALL" / "ANSWERED" / "DELETED" / "FLAGGED" / "NEW" / "OLD" /
                  "RECENT" / "SEEN" / "UNANSWERED" / "UNDELETED" / "UNFLAGGED" /
                  "UNSEEN" / "DRAFT" / "UNDRAFT" /
                  "ON" SP date / "BEFORE" SP date / "SINCE" SP date /
                  "SENTBEFORE" SP date / "SENTON" SP date / "SENTSINCE" SP date /
                  "FROM" SP astring / "TO" SP astring / "CC" SP astring / "BCC" SP astring /
                  "SUBJECT" SP astring / "BODY" SP astring / "TEXT" SP astring /
                  "KEYWORD" SP flag-keyword / "UNKEYWORD" SP flag-keyword /
                  "HEADER" SP header-fld-name SP astring /
                  "OR" SP search-key SP search-key / "NOT" SP search-key /
                  "LARGER" SP number / "SMALLER" SP number /
                  "UID" SP set / set /
                  "(" search-key *(SP search-key) ")"

*/


void Search::parse()
{
    // nothing.
}



/*! One might surmise that this function is a true noop, but it's
    not. The side effects need to be handled somehow.
*/

void Search::execute()
{
    // executing a noop is very simple.
    setState( Finished );
}
