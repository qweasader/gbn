# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850160");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"SUSE-SA", value:"2011-010");
  script_cve_id("CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4451", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4474", "CVE-2010-4475", "CVE-2010-4476");
  script_name("SUSE: Security Advisory for java-1_6_0-sun (SUSE-SA:2011:010)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_6_0-sun'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.2|openSUSE11\.3)");

  script_tag(name:"impact", value:"remote code execution");

  script_tag(name:"affected", value:"java-1_6_0-sun on openSUSE 11.2, openSUSE 11.3");

  script_tag(name:"insight", value:"Sun Java 1.6 was updated to Update 24 fixing various bugs and security
  issues.

  The update is rated critical by Sun.

  The following CVEs were addressed:
  CVE-2010-4462
  CVE-2010-4467
  CVE-2010-4422
  CVE-2010-4470
  CVE-2010-4447
  CVE-2010-4450
  CVE-2010-4474");

  script_xref(name:"URL", value:"http://blogs.oracle.com/security/2011/02/security_alert_for_cve-2010-44.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alert-cve-2010-4476-305811.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.2") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u24~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.3") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u24~0.2.1", rls:"openSUSE11.3"))) {
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
