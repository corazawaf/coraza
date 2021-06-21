This package is based on https://github.com/glenn-brown/golang-pkg-pcre 

There are so many forks with useful modifications but I had to pick some of them and embed it inside the project.

* https://github.com/gijsbers/go-pcre
* https://github.com/rubrikinc/go-pcre

There are some big TODOs, see https://linux.die.net/man/3/pcreapi

```
The match_limit field provides a means of preventing PCRE from using up a vast amount of resources when running patterns that are not going to match, but which have a very large number of possibilities in their search trees. The classic example is the use of nested unlimited repeats.

Internally, PCRE uses a function called match() which it calls repeatedly (sometimes recursively). The limit set by match_limit is imposed on the number of times this function is called during a match, which has the effect of limiting the amount of backtracking that can take place. For patterns that are not anchored, the count restarts from zero for each position in the subject string.

The default value for the limit can be set when PCRE is built; the default default is 10 million, which handles all but the most extreme cases. You can override the default by suppling pcre_exec() with a pcre_extra block in which match_limit is set, and PCRE_EXTRA_MATCH_LIMIT is set in the flags field. If the limit is exceeded, pcre_exec() returns PCRE_ERROR_MATCHLIMIT.

The match_limit_recursion field is similar to match_limit, but instead of limiting the total number of times that match() is called, it limits the depth of recursion. The recursion depth is a smaller number than the total number of calls, because not all calls to match() are recursive. This limit is of use only if it is set smaller than match_limit.
```