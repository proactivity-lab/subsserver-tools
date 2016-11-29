#!/usr/bin/env python2
"""tail_subsmanager.py: Tool for monitoring subscription manager state from logfiles"""
import calendar
import sys
import os
import time
import re
import datetime
from stat import ST_SIZE

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
                try:
                    self.boot = calendar.timegm(datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())
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
        self.priority = self.len = self.status = self.stored = self.max_timeout = self.start = self.streams = None

    def parse(self, statusline, timestamp):
        # 2015-07-31T14:21:46.93Z 'D|sbslog: 594|[01] --'
        m = re.search("s\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        # 2016-04-07 13:00:57.468 : D|  sbslog:  23|s[00] p0 l33 (1|0) 14/3600
        m = re.search("s\[([0-9]*)\] p([0-9]+) l([0-9]+) \(([0-9]+)\|([0-9]+)\) ([0-9]+)/([0-9]+) \(([0-9]+)\).*", statusline)
        if m is not None:
            # ('00', 'F802', '4', '0', '0', '637', '638', '637')
            self.index = int(m.group(1))
            self.priority = int(m.group(2))
            self.len = int(m.group(3))
            self.status = int(m.group(4))
            self.stored = int(m.group(5))
            self.start = int(m.group(6))
            self.max_timeout = int(m.group(7))
            self.streams = int(m.group(8))

            if self.max_timeout == 0xFFFFFFFF:
                self.max_timeout = "never"

            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[ l]len|pp|s|f|_start____|_timeout__|strms|"
        elif self.len is None:
            return "[%02u]   |  | | |          |          |     |" % (self.index)
        else:
            return "[%02u]%3u|%2u|%u|%u|%10u|%10s|%5u|" % (self.index, self.len, self.priority, self.status, self.stored, self.start, self.max_timeout, self.streams)


class StreamStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.lid = 0xFF
        self.mote = self.cid = self.slot = self.status = self.stored = self.start = None
        self.contact = self.maintenance = self.data_out = self.tstart = self.tend = None

    def parse(self, statusline, timestamp):
        # 2015-07-31T14:21:46.93Z 'D|sbslog: 594|[01] --'
        m = re.search("t\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        # 2016-04-07 14:55:47.107 : D|  sbslog:  35|t[00|00] m02:834e(0)(1|0) 14/14
        m = re.search("t\[([0-9]+)\|([0-9]+)\] m([-0-9]+):([0-9a-f]+)\(([0-9]+)\)\(([0-9]+)\|([0-9]+)\) ([0-9]+)/([0-9]+)/([0-9]+)/([0-9]+) ([0-9]+)~([0-9]+).*", statusline)
        if m is not None:
            print "match", m.groups()
            # ('00', 'F802', '4', '0', '0', '637', '638', '637')
            self.index = int(m.group(1))
            self.lid = int(m.group(2))
            self.mote = int(m.group(3), 10)
            self.cid = int(m.group(4), 16)
            self.slot = int(m.group(5))
            self.status = int(m.group(6))
            self.stored = int(m.group(7))
            self.start = int(m.group(8))
            self.contact = int(m.group(9))
            self.maintenance = int(m.group(10))
            self.data_out = int(m.group(11))
            self.tstart = int(m.group(12))
            self.tend = int(m.group(13))
            return True
        else:
            print "bad", statusline

        return False

    def __str__(self):
        if self.index is None:
            return "[ s| l]|mote|__cid___|ss|s|f|__start___|_contact__|__mntnnc__|_data_out_|_yxk_start|_yxk_end__|"
        elif self.mote is None:
            return "[%02u|%s%s]|    |        |  | | |          |          |          |          |          |          |" % (self.index, " ", " ")
        else:
            return "[%02u|%02u]|%4d|%8x|%2u|%u|%u|%10u|%10u|%10u|%10u|%10u|%10u|" % (self.index, self.lid, self.mote, self.cid, self.slot, self.status, self.stored,
                                                                                     self.start, self.contact, self.maintenance, self.data_out,
                                                                                     self.tstart, self.tend)


class MiddlewareStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.state = self.cid = self.priority = self.start = self.last_broadcast = self.max_timeout = self.providers = self.latest_data = None

    def parse(self, statusline, timestamp):
        m = re.search("\[([0-9]*)\] --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        #"[%02u] s%u i%u p%u b%"PRIu32" c%u"
        m = re.search("\[([0-9]*)\] s([0-9]*) i([0-9a-f]+) p([0-9]+) c([0-9]+) ([0-9]+)/([0-9]+)/([0-9]+)/([0-9]+).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.state = int(m.group(2))
            self.cid = int(m.group(3), 16)
            self.priority = int(m.group(4))
            self.providers = int(m.group(5))
            self.start = int(m.group(6))
            self.last_broadcast = int(m.group(7))
            self.max_timeout = int(m.group(8))
            self.latest_data = int(m.group(9))

            if self.max_timeout == 0xFFFFFFFF:
                self.max_timeout = "never"

            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[mw]_st|__cid___|pp|pc|__start___|_broadcast|timeout_pr|___data___|"
        elif self.state is None:
            return "[%02u]   |        |  |  |          |          |          |          |" % (self.index)
        else:
            return "[%02u]%3u|%8x|%2u|%2u|%10u|%10u|%10s|%10u|" % (self.index, self.state, self.cid, self.priority,
                                                                   self.providers, self.start, self.last_broadcast,
                                                                   self.max_timeout, self.latest_data)


class MiddlewareProviderStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.mote = self.expected = self.stream = self.start = self.contact = self.outgoing = self.timeout = None
        self.live = False

    def parse(self, statusline, timestamp):
        m = re.search("\[([0-9]*)\] m([0-9]+) --.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.mote = int(m.group(2))
            self.expected = self.stream = self.contact = self.outgoing = self.timeout = None
            self.live = False
            return True

        # "[%02u] m%02d e%u s%02x %PRIu32/%PRIu32/%PRIu32"
        m = re.search("\[([0-9]*)\] m([0-9]+) e([01]+) s([0-9a-f]+) ([0-9]+)/([0-9]+)/([0-9]+)/([0-9]+).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.mote = int(m.group(2))
            self.expected = int(m.group(3))
            self.stream = int(m.group(4), 16)
            self.start = int(m.group(5))
            self.contact = int(m.group(6))
            self.outgoing = int(m.group(7))
            self.timeout = int(m.group(8))
            self.live = True
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "   |mote|e|st|__start___|_contact__|_outgoing_|timeout_tm|"
        elif not self.live:
            return "   |    | |  |          |          |          |          |"
        else:
            return "   |%4u|%u|%2x|%10u|%10u|%10s|%10u|" % (self.mote, self.expected, self.stream, self.start, self.contact, self.outgoing, self.timeout)


class SchedulerStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.sensm = self.lid = self.state = self.active = None

    def parse(self, statusline, timestamp):
        m = re.search("\[([0-9]*)\]<-->.*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            return True

        #debug3("[%02u](%2u) s%u "PRIu32"/%"PRIu32"/%"PRIu32"/%"PRIu32"/%"PRIu32,
        m = re.search("\[([0-9]*)\]<([0-9]+)>\(([0-9]+)\) s([0-9]+) a([01]).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.sensm = int(m.group(2))
            self.lid = int(m.group(3))
            self.state = int(m.group(4))
            self.active = int(m.group(5))
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[ a|sm]lid|_st|"
        elif self.lid is None:
            return "[%02u|  ]   |   |" % (self.index)
        else:
            return "[%02u|%02u] %2u|%2u%s|" % (self.index, self.sensm, self.lid, self.state, "*" if self.active else " ")


class RegistryStatus(object):

    def __init__(self, index=None):
        self.index = index
        self.addr = self.guid = self.count = self.contact = None

    def parse(self, statusline, timestamp):
        # "m%02d %04X c%u t%PRIu32"
        m = re.search("m([0-9]+) ([0-9A-F]+) c([0-9]+) t([0-9]+) ([0-9a-f]+) ([0-9a-f]+).*", statusline)
        if m is not None:
            self.index = int(m.group(1))
            self.addr = int(m.group(2), 16)
            self.count = int(m.group(3))
            self.contact = int(m.group(4))
            self.guid = (m.group(5) + m.group(6)).upper()
            return True

        return False

    def __str__(self):
        if self.index is None:
            return "[id]______guid______|addr|_contact__|cnt|"
        elif self.addr is None:
            return "[%02d]                |    |          |   |" % (self.index)
        else:
            return "[%02d]%s|%04X|%10u|%3u|" % (self.index, self.guid, self.addr, self.contact, self.count)


def tail_file(file_path, seek=0, sim_filter=None):
    logfile = open(file_path, "r")
    logfile.seek(seek)
    actual_path = None
    if os.path.islink(file_path):
        actual_path = os.readlink(file_path)

    if sim_filter is not None:
        sim_filter = "%04X" % int(sim_filter, 16)

    where = logfile.tell()
    while True:
        if actual_path is not None:
            new_path = os.readlink(file_path)
            if new_path != actual_path:
                actual_path = new_path
                logfile.close()
                logfile = open(file_path)
                print "opened {}".format(actual_path)

        if os.stat(file_path)[ST_SIZE] < where:
            logfile.close()
            logfile = open(file_path)

        where = logfile.tell()
        line = logfile.readline()
        if line:
            line = line.lstrip().rstrip()

            if sim_filter is not None:  # Handle super long simulator log line
                # 0:28:50.537109425 DEBUG (4): 2016-10-26 12:46:39 00:28:50.537109425 #0004
                m = re.search(".* DEBUG \([0-9]*\): ([0-9]*-[0-9]*-[0-9]* [0-9]*:[0-9]*:[0-9]*) [0-9:\.]* #([0-9A-F]+)\s*[DIWE]\|\s*(.*):[ 0-9]*\|(.*)", line)
                if m is None:
                    continue

                # Filter based on address
                timestamp, address, module, logline = m.groups()
                if address != sim_filter:
                    continue
            else:
                m = re.search("(.*)[:']\s*[DIWE]\|(.*):[ 0-9]*\|(.*)", line)
                if m is None:
                    continue
                timestamp, module, logline = m.groups()

            module = module.strip()
            timestamp = timestamp.strip()
            logline.rstrip("'")

            if module.startswith("sbslog"):
                if logline.startswith("s"):
                    parsers = (ManagerStatus(),)
                elif logline.startswith("t"):
                    parsers = (StreamStatus(),)
                else:
                    continue
            elif module.startswith("mddl"):
                parsers = (MiddlewareStatus(), MiddlewareProviderStatus())
            elif module.startswith("amdl"):
                parsers = (SchedulerStatus(),)
            elif module.startswith("binf"):
                parsers = (AddressStatus(),)
            elif module.startswith("mreg"):
                parsers = (RegistryStatus(),)
            else:
                if logline.find("output") >= 0:
                    parsers = (OutputStatus(),)
                elif logline.find("input") >= 0:
                    parsers = (InputStatus(),)
                else:
                    # print "useless", line
                    continue

            for ls in parsers:
                if ls.parse(logline, timestamp):
                    yield ls

        else:
            time.sleep(INTERVAL)
            logfile.seek(where)


def main():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Statusparser")
    parser.add_argument("filename")
    parser.add_argument("--old", action="store_true")
    parser.add_argument("--sim-filter", default=None, help="Use simulation log, specify node address to filter, hex!")
    args = parser.parse_args()

    logfile = None
    try:
        while True:
            try:
                if args.old:
                    file_size = 0
                else:
                    file_size = os.stat(args.filename)[6]

                addr = AddressStatus()
                managermap = {0: ManagerStatus(0)}
                streammap = {0: StreamStatus(0)}
                middlewaremap = {0: MiddlewareStatus(0)}
                middlewareproviders = {}
                schedulermap = {0: SchedulerStatus(0)}
                registrystatus = {0: RegistryStatus(0)}
                outputstatus = OutputStatus()
                inputstatus = InputStatus()
                for status in tail_file(args.filename, seek=file_size, sim_filter=args.sim_filter):
                    if isinstance(status, ManagerStatus):
                        managermap[status.index] = status
                    if isinstance(status, StreamStatus):
                        streammap[status.index] = status
                    elif isinstance(status, MiddlewareStatus):
                        middlewaremap[status.index] = status
                    elif isinstance(status, MiddlewareProviderStatus):
                        if status.index not in middlewareproviders:
                            middlewareproviders[status.index] = {}
                        if status.live:
                            middlewareproviders[status.index][status.mote] = status
                        else:
                            middlewareproviders[status.index].pop(status.mote, None)
                    elif isinstance(status, SchedulerStatus):
                        schedulermap[status.index] = status
                    elif isinstance(status, RegistryStatus):
                        registrystatus[status.index] = status
                    elif isinstance(status, AddressStatus):
                        addr = status
                        managermap = {0: ManagerStatus(0)}
                        streammap = {0: StreamStatus(0)}
                        middlewaremap = {0: MiddlewareStatus(0)}
                        middlewareproviders = {}
                        schedulermap = {0: SchedulerStatus(0)}
                        registrystatus = {0: RegistryStatus(0)}
                        outputstatus = OutputStatus()
                        inputstatus = InputStatus()
                    elif isinstance(status, OutputStatus):
                        outputstatus = status
                    elif isinstance(status, InputStatus):
                        inputstatus = status

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
                    previous_had_providers = False
                    for i in xrange(0, max(middlewaremap.iterkeys())+1):
                        if i in middlewaremap:
                            if previous_had_providers:
                                print
                                print MiddlewareStatus()
                            print middlewaremap[i]
                            if i in middlewareproviders:
                                if len(middlewareproviders[i]) > 0:
                                    print MiddlewareProviderStatus()
                                    for k in sorted(middlewareproviders[i].keys()):
                                        print middlewareproviders[i][k]
                                    previous_had_providers = True
                                    continue
                                else:
                                    del middlewareproviders[i]

                        previous_had_providers = False

                    print
                    print SchedulerStatus()
                    for i in xrange(0, max(schedulermap.iterkeys())+1):
                        if i not in schedulermap:
                            schedulermap[i] = SchedulerStatus(i)
                        print schedulermap[i]

                    print
                    print RegistryStatus()
                    for i in xrange(0, max(registrystatus.iterkeys())+1):
                        if i not in registrystatus:
                            registrystatus[i] = RegistryStatus(i)
                        print registrystatus[i]

                    print
                    print "Output {}".format(outputstatus)
                    print "Input  {}".format(inputstatus)
            except (OSError, IOError) as e:
                print "\033c"  # clear screen
                print "Error:", str(e)
                time.sleep(1)

    except KeyboardInterrupt:
        print "interrupted"
        if logfile is not None:
            logfile.close()
        sys.stdout.flush()


if __name__ == "__main__":
    main()