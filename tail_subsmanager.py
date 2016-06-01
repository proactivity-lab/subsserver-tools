#!/usr/bin/env python2
"""tail_subsmanager.py: Tool for monitoring subscription manager state from logfiles"""
import calendar
import sys
import os
import time
import re
import datetime

__author__ = "Raido Pahtma"
__license__ = "MIT"

INTERVAL = 0.1


class AddressStatus(object):

    def __init__(self, addr=0):
        self.addr = addr
        self.boot = None

    def parse(self, statusline, timestamp):
        # 2015-08-03T07:27:10.20Z 'I|binf:  22|TOS_NODE_ID EEA2 GUID 01A2EE0E 1500001D'
        m = re.search("TOS_NODE_ID ([0-9A-F]*) GUID ([ 0-9A-F]*).*", statusline)
        if m is not None:
            self.addr = int(m.group(1), 16)
            try:
                self.boot = calendar.timegm(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f").timetuple())
            except ValueError:
                self.boot = None
            return True

    def __str__(self):
        if self.boot is None:
            uptime = None
        else:
            uptime = int(time.time() - self.boot)
        return "%04X (uptime %s)" % (self.addr, uptime)


class OutputStatus(object):

    def __init__(self, output=None):
        self.output = output

    def parse(self, statusline, timestamp):
        # 2016-05-31 08:07:07.933: I | dclc: 117 | output[100]
        m = re.search("output\[\s*(-?[0-9]+)\].*", statusline)
        if m is not None:
            self.output = int(m.group(1), 10)
            return True

    def __str__(self):
        if self.output is None:
            return "---"
        return "%3d" % (self.output)


class InputStatus(object):

    def __init__(self, input=None):
        self.input = input

    def parse(self, statusline, timestamp):
        # 2016-05-31 08:07:07.933: I | dclc: 117 | output[100]
        m = re.search("input\[\s*(-?[0-9]+)\].*", statusline)
        if m is not None:
            self.input = int(m.group(1), 10)
            return True

    def __str__(self):
        if self.input is None:
            return "---"
        return "%3d" % (self.input)


class ManagerStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.priority = self.len = self.status = self.stored = self.max_timeout = self.start = None

    def parse(self, statusline, timestamp):
        # 2015-07-31T14:21:46.93Z 'D|sbslog: 594|[01] --'
        m = re.search("s\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        # 2016-04-07 13:00:57.468 : D|  sbslog:  23|s[00] p0 l33 (1|0) 14/3600
        m = re.search("s\[([0-9]*)\] p([0-9]+) l([0-9]+) \(([0-9]+)\|([0-9]+)\) ([0-9]+)/([0-9]+).*", statusline)
        if m is not None:
            # ('00', 'F802', '4', '0', '0', '637', '638', '637')
            self.index = int(m.group(1))
            self.priority = int(m.group(2))
            self.len = int(m.group(3))
            self.status = int(m.group(4))
            self.stored = int(m.group(5))
            self.start = int(m.group(6))
            self.max_timeout = int(m.group(7))

            if self.max_timeout == 0xFFFFFFFF:
                self.max_timeout = "never"

            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[ l]len|pp|s|f|_start____|_timeout__|"
        elif self.len is None:
            return "[%02u]   |  | | |          |          |" % (self.index)
        else:
            return "[%02u]%3u|%2u|%u|%u|%10u|%10s|" % (self.index, self.len, self.priority, self.status, self.stored, self.start, self.max_timeout)


class StreamStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.lid = 0xFF
        self.addr = self.cid = self.slot = self.status = self.stored = self.contact = self.maintenance = None

    def parse(self, statusline, timestamp):
        # 2015-07-31T14:21:46.93Z 'D|sbslog: 594|[01] --'
        m = re.search("t\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        # 2016-04-07 14:55:47.107 : D|  sbslog:  35|t[00|00] BDE8:834e(0)(1|0) 14/14
        m = re.search("t\[([0-9]+)\|([0-9]+)\] ([0-9A-F]+):([0-9a-f]+)\(([0-9]+)\)\(([0-9]+)\|([0-9]+)\) ([0-9]+)/([0-9]+).*", statusline)
        if m is not None:
            print "match", m.groups()
            # ('00', 'F802', '4', '0', '0', '637', '638', '637')
            self.index = int(m.group(1))
            self.lid = int(m.group(2))
            self.addr = int(m.group(3), 16)
            self.cid = int(m.group(4), 16)
            self.slot = int(m.group(5))
            self.status = int(m.group(6))
            self.stored = int(m.group(7))
            self.contact = int(m.group(8))
            self.maintenance = int(m.group(9))
            return True
        else:
            print "bad", statusline

        return False

    def __str__(self):
        if self.index is None:
            return "[ s| l]|addr|__cid___|ss|s|f|_contact__|_maint____|"
        elif self.addr is None:
            return "[%02u|%s%s]|    |        |  | | |          |          |" % (self.index, " ", " ")
        else:
            return "[%02u|%02u]|%04X|%8x|%2u|%u|%u|%10u|%10u|" % (self.index, self.lid, self.addr, self.cid, self.slot, self.status, self.stored, self.contact, self.maintenance)


class MiddlewareStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.state = self.cid = self.priority = self.last_broadcast = self.max_timeout = self.providers = None

    def parse(self, statusline, timestamp):
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

            if self.max_timeout == 0xFFFFFFFF:
                self.max_timeout = "never"

            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[mw]_st|__cid___|pp|_broadcast|_timeout__|pc|_last_data|"
        elif self.state is None:
            return "[%02u]   |        |  |          |          |  |          |" % (self.index)
        else:
            return "[%02u]%3u|%8x|%2u|%10u|%10s|%2u|---TODO---|" % (self.index, self.state, self.cid, self.priority, self.last_broadcast, self.max_timeout, self.providers)


class SchedulerStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.lid = self.state = None

    def parse(self, statusline, timestamp):
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
            return "[ a| l|_st|"
        elif self.lid is None:
            return "[%02u|  ]   |" % (self.index)
        else:
            return "[%02u|%02u]%3u|" % (self.index, self.lid, self.state)


def tail_file(file_path, seek=0):
    logfile = open(file_path, "r")
    logfile.seek(seek)
    actual_path = None
    if os.path.islink(file_path):
        actual_path = os.readlink(file_path)

    while True:
        if actual_path is not None:
            new_path = os.readlink(file_path)
            if new_path != actual_path:
                actual_path = new_path
                logfile.close()
                logfile = open(file_path)
                print "opened {}".format(actual_path)

        where = logfile.tell()
        line = logfile.readline()
        if line:
            line = line.lstrip().rstrip()
            m = re.search("(.*):\s*[DIWE]\|(.*):[ 0-9]*\|(.*)", line)
            if m is not None:
                timestamp, module, logline = m.groups()
                module = module.strip()
                timestamp = timestamp.strip()

                if module.startswith("sbslog"):
                    if logline.startswith("s"):
                        s = ManagerStatus()
                    elif logline.startswith("t"):
                        s = StreamStatus()
                    else:
                        continue
                elif module.startswith("mddl"):
                    s = MiddlewareStatus()
                elif module.startswith("amdl"):
                    s = SchedulerStatus()
                elif module.startswith("binf"):
                    s = AddressStatus()
                else:
                    if logline.find("output") >= 0:
                        s = OutputStatus()
                    elif logline.find("input") >= 0:
                        s = InputStatus()
                    else:
                        # print "useless", line
                        continue

                if s.parse(logline, timestamp):
                    yield s
            # else:
            #    print "bad", line
        else:
            time.sleep(INTERVAL)
            logfile.seek(where)


def main():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Statusparser")
    parser.add_argument("filename")
    parser.add_argument("--old", action="store_true")
    args = parser.parse_args()

    logfile = None
    try:
        if args.old:
            file_size = 0
        else:
            file_size = os.stat(args.filename)[6]

        addr = AddressStatus()
        managermap = {0: ManagerStatus(0)}
        streammap = {0: StreamStatus(0)}
        middlewaremap = {0: MiddlewareStatus(0)}
        schedulermap = {0: SchedulerStatus(0)}
        output = OutputStatus()
        input = InputStatus()
        for status in tail_file(args.filename, seek=file_size):
            if isinstance(status, ManagerStatus):
                managermap[status.index] = status
            if isinstance(status, StreamStatus):
                streammap[status.index] = status
            elif isinstance(status, MiddlewareStatus):
                middlewaremap[status.index] = status
            elif isinstance(status, SchedulerStatus):
                schedulermap[status.index] = status
            elif isinstance(status, AddressStatus):
                addr = status
                managermap = {0: ManagerStatus(0)}
                streammap = {0: StreamStatus(0)}
                # not reset because boot will print all slots
                # middlewaremap = {0: MiddlewareStatus(0)}
                # schedulermap = {0: SchedulerStatus(0)}
                output = OutputStatus()
                input = InputStatus()
            elif isinstance(status, OutputStatus):
                output = status
            elif isinstance(status, InputStatus):
                input = status

            print "\033c"  # clear screen
            print addr
            print

            print ManagerStatus()
            for i in xrange(0, max(managermap.iterkeys())+1):
                if i not in managermap:
                    managermap[i] = ManagerStatus(i)
                print managermap[i]

            print
            print StreamStatus()
            for i in xrange(0, max(streammap.iterkeys())+1):
                if i not in streammap:
                    streammap[i] = StreamStatus(i)
                print streammap[i]

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

            print
            print "Output {}".format(output)
            print "Input  {}".format(input)

    except KeyboardInterrupt:
        print "interrupted"
        if logfile is not None:
            logfile.close()
        sys.stdout.flush()


if __name__ == "__main__":
    main()