# postfix-log-parser
Parses Postfix log files to find the disposition of emails, and dumps them to a JSON file for import into another system.

#ToDo
Currently, it re-reads the whole file every time, and I should use timestamps and a half-interval search algorithm to find the last-processed time stamp. I am relying on log rotate to make it not-too-terribly-big), but after we switch to the half-interval algo, we'll need to hash and store the first line of the log file to detect log rotate changes, which means we'd start searching from line one after rotation.

*Nice to haves*: 
1. Command line prompt for the destination path for the JSON file.
2. Command line prompt for the source file (currently using Debian package installation path, but not everyone uses that).
