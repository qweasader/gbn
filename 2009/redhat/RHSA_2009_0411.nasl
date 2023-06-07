# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0411 ()
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63762");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0115");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0411");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0411.

The device-mapper multipath packages provide tools to manage multipath
devices by issuing instructions to the device-mapper multipath kernel
module, and by managing the creation and removal of partitions for
device-mapper devices.

It was discovered that the multipathd daemon set incorrect permissions on
the socket used to communicate with command line clients. An unprivileged,
local user could use this flaw to send commands to multipathd, resulting in
access disruptions to storage devices accessible via multiple paths and,
possibly, file system corruption on these devices. (CVE-2009-0115)

Users of device-mapper-multipath are advised to upgrade to these updated
packages, which contain a backported patch to resolve this issue. The
multipathd service must be restarted for the changes to take effect.

Important: the version of the multipathd daemon in Red Hat Enterprise Linux
5 has a known issue which may cause a machine to become unresponsive when
the multipathd service is stopped. This issue is tracked in the Bugzilla
bug #494582. A link is provided in the References section of this erratum.
Until this issue is resolved, we recommend restarting the multipathd
service by issuing the following commands in sequence:

# killall -KILL multipathd

# service multipathd restart");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0411.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"device-mapper-multipath", rpm:"device-mapper-multipath~0.4.5~31.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"device-mapper-multipath-debuginfo", rpm:"device-mapper-multipath-debuginfo~0.4.5~31.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"device-mapper-multipath", rpm:"device-mapper-multipath~0.4.7~23.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"device-mapper-multipath-debuginfo", rpm:"device-mapper-multipath-debuginfo~0.4.7~23.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kpartx", rpm:"kpartx~0.4.7~23.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
