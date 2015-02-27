#!/usr/bin/python

import pip
installed_packages = pip.get_installed_distributions()
installed_packages_list = sorted(["%s==%s" % (i.key, i.version)
print 'The following packages are currently installed:'
     for i in installed_packages])
print installed_packages_list