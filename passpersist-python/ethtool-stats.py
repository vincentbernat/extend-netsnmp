import re
import os
import glob
import subprocess

import snmp_passpersist as snmp

def update():
    for interface in os.listdir("/sys/class/net"):
        # Get index
        index = open("/sys/class/net/%s/ifindex" % interface)
        index = int(index.read())

        # Call ethtool
        try:
            ethtool = subprocess.check_output(["ethtool", "-S", interface],
                                              stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            continue

        ethtool = ethtool.decode("ascii")
        for line in ethtool.split("\n"):
            mo = re.match("\s+(\w+): (\d+)", line)
            if not mo: continue
            name = mo.group(1)
            value = int(mo.group(2))
            oid = "%d.%s" % (index,
                             ".".join([str(ord(a)) for a in name]))
            pp.add_cnt_64bit(oid, value)

pp = snmp.PassPersist('.1.3.6.1.4.1.39178.100.1.1.1.2')
pp.start(update, 10)
