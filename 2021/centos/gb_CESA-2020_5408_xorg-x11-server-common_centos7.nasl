# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883328");
  script_version("2021-08-17T06:00:55+0000");
  script_cve_id("CVE-2020-14347", "CVE-2020-14360", "CVE-2020-25712");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 18:29:00 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-02-28 04:00:35 +0000 (Sun, 28 Feb 2021)");
  script_name("CentOS: Security Advisory for xorg-x11-server-common (CESA-2020:5408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2020:5408");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-February/048276.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-common'
  package(s) announced via the CESA-2020:5408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"X.Org is an open-source implementation of the X Window System. It provides
the basic low-level functionality that full-fledged graphical user
interfaces are designed upon.

Security Fix(es):

  * xorg-x11-server: Out-of-bounds access in XkbSetMap function
(CVE-2020-14360)

  * xorg-x11-server: XkbSetDeviceInfo heap-based buffer overflow privilege
escalation vulnerability (CVE-2020-25712)

  * xorg-x11-server: Leak of uninitialized heap memory from the X server to
clients in AllocatePixmap of dix/pixmap.c (CVE-2020-14347)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'xorg-x11-server-common' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-devel", rpm:"xorg-x11-server-devel~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland", rpm:"xorg-x11-server-Xwayland~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.20.4~15.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);