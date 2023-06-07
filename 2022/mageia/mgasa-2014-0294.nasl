# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0294");
  script_cve_id("CVE-2014-3532", "CVE-2014-3533");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0294.html");
  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/dbus/2014-July/016235.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135226.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13653");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the MGASA-2014-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dbus packages fix security vulnerabilities:

A flaw was reported in D-Bus's file descriptor passing feature. A local
attacker could use this flaw to cause a service or application to disconnect
from the bus, typically resulting in that service or application exiting
(CVE-2014-3532).

A flaw was reported in D-Bus's file descriptor passing feature. A local
attacker could use this flaw to cause an invalid file descriptor to be
forwarded to a service or application, causing it to disconnect from the bus,
typically resulting in that service or application exiting (CVE-2014-3533).");

  script_tag(name:"affected", value:"'dbus' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-doc", rpm:"dbus-doc~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus-devel", rpm:"lib64dbus-devel~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus1_3", rpm:"lib64dbus1_3~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-devel", rpm:"libdbus-devel~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus1_3", rpm:"libdbus1_3~1.6.8~4.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-doc", rpm:"dbus-doc~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus-devel", rpm:"lib64dbus-devel~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus1_3", rpm:"lib64dbus1_3~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-devel", rpm:"libdbus-devel~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus1_3", rpm:"libdbus1_3~1.6.18~1.3.mga4", rls:"MAGEIA4"))) {
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
