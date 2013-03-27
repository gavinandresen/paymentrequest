#include "util.h"

#include <set>

using namespace std;

list<string> split(const string& s, const string& separator)
{
    list<string> result;
    if (s.empty()) return result;

    size_t start = 0;
    for (size_t pos = s.find(separator); pos != string::npos; pos = s.find(separator, start)) {
        result.push_back(s.substr(start, pos-start));
        start = pos+1;
    }
    result.push_back(s.substr(start));
    return result;
}

bool parse_command_line(int argc, char** argv, const list<string>& expectedList, map<string, string>& result)
{
    set<string> expected(expectedList.begin(), expectedList.end());

    for (int i = 1; i < argc; i++) {
        string kv(argv[i]);
        string value;
        size_t eqpos = kv.find("=");
        if (eqpos != string::npos) value = kv.substr(eqpos+1);
        size_t nondash = kv.find_first_not_of("-");
        string key = kv.substr(nondash, eqpos);

        if (expected.count(key) == 0) {
            cerr << "Invalid argument: " << key << "\n";
            return false;
        }

        if (result.count(key) > 0) result[key] = result[key]+","+value;
        else result.insert(make_pair(key,value));
    }
    return true;
}

void usage(const list<string>& expected)
{
    cerr << "Allowed arguments: (--arg=value or just arg=value)\n";
    for (list<string>::const_iterator it = expected.begin(); it != expected.end(); it++) {
        cerr << " " << *it << "\n";
    }
}
