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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0325");
  script_cve_id("CVE-2019-13313");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 20:49:00 +0000 (Tue, 28 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2021-0325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0325");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0325.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25112");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:3387");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHBA-2020:4758");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libosinfo' package(s) announced via the MGASA-2021-0325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libosinfo packages fix security vulnerability:

A flaw was found in libosinfo, version 1.5.0, where the script for
automated guest installations, 'osinfo-install-script', accepts user
and admin passwords via command line arguments. This could allow guest
passwords to leak to other system users via a process listing
(CVE-2019-13313).

The libosinfo package has been updated to version 1.8.0, fixing this
issue and other bugs.");

  script_tag(name:"affected", value:"'libosinfo' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64osinfo-gir1.0", rpm:"lib64osinfo-gir1.0~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osinfo1.0-devel", rpm:"lib64osinfo1.0-devel~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osinfo1.0_0", rpm:"lib64osinfo1.0_0~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosinfo", rpm:"libosinfo~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosinfo-gir1.0", rpm:"libosinfo-gir1.0~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosinfo-vala", rpm:"libosinfo-vala~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosinfo1.0-devel", rpm:"libosinfo1.0-devel~1.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosinfo1.0_0", rpm:"libosinfo1.0_0~1.8.0~1.mga7", rls:"MAGEIA7"))) {
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
