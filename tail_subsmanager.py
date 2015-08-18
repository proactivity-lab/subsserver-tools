#!/usr/bin/env python2

"""Tool for monitoring subscription manager state from logfiles"""

__author__ = "Raido Pahtma"
__license__ = "MIT"

import sys
import os
import time
import re

INTERVAL = 0.1

class AddressStatus(object):

    def __init__(self, addr=0):
        self.addr = addr

    def parse(self, statusline):
        # 2015-08-03T07:27:10.20Z 'I|binf:  22|TOS_NODE_ID EEA2 GUID 01A2EE0E 1500001D'
        m = re.search("TOS_NODE_ID ([0-9A-F]*) GUID ([ 0-9A-F]*).*", statusline)
        if m is not None:
            self.addr = int(m.group(1), 16)
            return True

    def __str__(self):
        return "%04X" % (self.addr)


class ManagerStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.cid = self.slot = self.priority = self.max_timeout = self.start = self.maintenance = self.contact = None

    def parse(self, statusline):
        # 2015-07-31T14:21:46.93Z 'D|smng: 594|[01] --'
        m = re.search("\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        # 2015-07-31T14:21:46.93Z 'D|smng: 589|[00] F802 cid 4 s0 p0 637/638/637'
        m = re.search("\[([0-9]*)\] ([0-9A-F]*) cid ([0-9]+) s([0-9]+) p([0-9]+) t([0-9]+) ([0-9]+)/([0-9]+)/([0-9]+).*", statusline)
        if m is not None:
            # ('00', 'F802', '4', '0', '0', '637', '638', '637')
            self.index = int(m.group(1))
            self.addr = int(m.group(2), 16)
            self.cid = int(m.group(3))
            self.slot = int(m.group(4))
            self.priority = int(m.group(5))
            self.max_timeout = int(m.group(6))
            self.start = int(m.group(7))
            self.maintenance = int(m.group(8))
            self.contact = int(m.group(9))
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[#%s#]_addr|_cid_|ss|pp|_timeout__|_start____|_maint____|_contact__|" % ("")
        elif self.addr is None:
            return "[%02u]     |     |  |  |          |          |          |          |" % (self.index)
        else:
            return "[%02u] %04X|%5u|%2u|%2u|%10u|%10u|%10u|%10u|" % (self.index, self.addr, self.cid, self.slot, self.priority, self.max_timeout, self.start, self.maintenance, self.contact)


class MiddlewareStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.state = self.cid = self.priority = self.last_broadcast = self.max_timeout = self.providers = None

    def parse(self, statusline):
        m = re.search("\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        #"[%02u] s%u i%u p%u b%"PRIu32" c%u"
        m = re.search("\[([0-9]*)\] s([0-9]*) i([0-9]+) p([0-9]+) b([0-9]+) t([0-9]+) c([0-9]+).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.state = int(m.group(2))
            self.cid = int(m.group(3))
            self.priority = int(m.group(4))
            self.last_broadcast = int(m.group(5))
            self.max_timeout = int(m.group(6))
            self.providers = int(m.group(7))
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[#%s#]_st|_cid_|pp|_broadcast|_timeout__|pc|" % ("")
        elif self.state is None:
            return "[%02u]   |     |  |          |          |  |" % (self.index)
        else:
            return "[%02u]%3u|%5u|%2u|%10u|%10u|%2u|" % (self.index, self.state, self.cid, self.priority, self.last_broadcast, self.max_timeout, self.providers)


class SchedulerStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.lid = self.state = None

    def parse(self, statusline):
        m = re.search("\[([0-9]*)\]\(--\).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        #debug3("[%02u](%2u) s%u "PRIu32"/%"PRIu32"/%"PRIu32"/%"PRIu32"/%"PRIu32,
        m = re.search("\[([0-9]*)\]\(([0-9]+)\) s([0-9]+).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.lid = int(m.group(2))
            self.state = int(m.group(3))
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[#%s#]lid|_st|" % ("")
        elif self.lid is None:
            return "[%02u][  ]   |" % (self.index)
        else:
            return "[%02u][%02u]%3u|" % (self.index, self.lid, self.state)


def tailfile(file):
    while True:
        where = file.tell()
        line = file.readline()
        if line:
            line = line.lstrip().rstrip()
            m = re.search("(.*) '[DIWE]\|(.*):[ 0-9]*\|(.*)", line)
            if m is not None:
                timestamp, module, logline = m.groups()

                if module.startswith("smng"):
                    s = ManagerStatus()
                elif module.startswith("mddl"):
                    s = MiddlewareStatus()
                elif module.startswith("amdl"):
                    s = SchedulerStatus()
                elif module.startswith("binf"):
                    s = AddressStatus()
                else:
                    continue

                if s.parse(logline):
                    yield s
        else:
            time.sleep(INTERVAL)
            file.seek(where)


if __name__ == "__main__":

    from argparse import ArgumentParser
    parser = ArgumentParser(description="Statusparser")
    parser.add_argument("filename")
    parser.add_argument("--old", action="store_true")
    args = parser.parse_args()

    try:
        if args.old:
            filesize = 0
        else:
            filesize = os.stat(args.filename)[6]

        file = open(args.filename, "r")
        file.seek(filesize)

        addr = AddressStatus()
        managermap = {0: ManagerStatus(0)}
        middlewaremap = {0: MiddlewareStatus(0)}
        schedulermap = {0: SchedulerStatus(0)}
        for status in tailfile(file):
            if isinstance(status, ManagerStatus):
                managermap[status.index] = status
            elif isinstance(status, MiddlewareStatus):
                middlewaremap[status.index] = status
            elif isinstance(status, SchedulerStatus):
                schedulermap[status.index] = status
            elif isinstance(status, AddressStatus):
                addr = status

            print "\033c" # clear screen
            print addr
            print

            print ManagerStatus()
            for i in xrange(0, max(managermap.iterkeys())+1):
                if i not in managermap:
                    managermap[i] = ManagerStatus(i)
                print managermap[i]

            print
            print MiddlewareStatus()
            for i in xrange(0, max(middlewaremap.iterkeys())+1):
                if i not in middlewaremap:
                    middlewaremap[i] = MiddlewareStatus(i)
                print middlewaremap[i]

            print
            print SchedulerStatus()
            for i in xrange(0, max(schedulermap.iterkeys())+1):
                if i not in schedulermap:
                    schedulermap[i] = SchedulerStatus(i)
                print schedulermap[i]

    except KeyboardInterrupt:
        print "interrupted"
        file.close()
        sys.stdout.flush()
