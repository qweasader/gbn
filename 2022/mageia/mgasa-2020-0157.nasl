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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0157");
  script_cve_id("CVE-2017-13735", "CVE-2017-14608", "CVE-2018-19655");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0157)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0157");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0157.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26406");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21757");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcraw' package(s) announced via the MGASA-2020-0157 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

There is a floating point exception in the kodak_radc_load_raw function
in dcraw_common.cpp in LibRaw 0.18.2. It will lead to a remote denial
of service attack. (CVE-2017-13735)

In LibRaw through 0.18.4, an out of bounds read flaw related to
kodak_65000_load_raw has been reported in dcraw/dcraw.c and internal/
dcraw_common.cpp. An attacker could possibly exploit this flaw to
disclose potentially sensitive memory or cause an application crash.
(CVE-2017-14608)

A stack-based buffer overflow in the find_green() function of dcraw
through 9.28, as used in ufraw-batch and many other products, may allow
a remote attacker to cause a control-flow hijack, denial-of-service, or
unspecified other impact via a maliciously crafted raw photo file.
(CVE-2018-19655)");

  script_tag(name:"affected", value:"'dcraw' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcraw", rpm:"dcraw~9.28.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-gimp2.0", rpm:"dcraw-gimp2.0~9.28.0~2.1.mga7", rls:"MAGEIA7"))) {
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
