//
// Utility routines I can't live without
//

#include <list>
#include <string>
#include <map>
#include <iostream>

//
// Split string into parts
//
std::list<std::string> split(const std::string& s, const std::string& separator);

//
// Quick-n-dirty parse command line options into a key/value map.
// Isn't fussy about leading dashes, so --foo=bar and -foo=bar and foo=bar
// are all treated the same.
// Repeated options end up under the same key, separated by commas.
//
bool parse_command_line(int argc, char** argv, const std::list<std::string>& expected, std::map<std::string, std::string>& result);

//
// Generic usage message to stderr
//
void usage(const std::list<std::string>& expected);
