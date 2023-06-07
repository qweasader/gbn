# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122914");
  script_cve_id("CVE-2016-0636");
  script_tag(name:"creation_date", value:"2016-03-31 05:06:16 +0000 (Thu, 31 Mar 2016)");
  script_version("2021-09-20T11:01:47+0000");
  script_tag(name:"last_modification", value:"2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Oracle: Security Advisory (ELSA-2016-0513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0513");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0513.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the ELSA-2016-0513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:1.8.0.77-0.b03]
- Remove what remains of the SunEC sources in the remove-intree-libraries script.
- Resolves: rhbz#1320664

[1:1.8.0.77-0.b03]
- Update to u77b03.
- Drop 8146566 which is applied upstream.
- Replace s390 Java options patch with general version from IcedTea.
- Apply s390 patches unconditionally to avoid arch-specific patch failures.
- Remove fragment of s390 size_t patch that unnecessarily removes a cast, breaking ppc64le.
- Remove aarch64-specific suffix as update/build version are now the same as for other archs.
- Only use z format specifier on s390, not s390x.
- Adjust tarball generation script to allow ecc_impl.h to be included.
- Correct spelling mistakes in tarball generation script.
- Synchronise minor changes from Fedora.
- Use a simple backport for PR2462/8074839.
- Don't backport the crc check for pack.gz. It's not tested well upstream.
- Resolves: rhbz#1320664");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility-debug", rpm:"java-1.8.0-openjdk-accessibility-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-debug", rpm:"java-1.8.0-openjdk-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debug", rpm:"java-1.8.0-openjdk-demo-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debug", rpm:"java-1.8.0-openjdk-devel-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debug", rpm:"java-1.8.0-openjdk-headless-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-debug", rpm:"java-1.8.0-openjdk-javadoc-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-debug", rpm:"java-1.8.0-openjdk-src-debug~1.8.0.77~0.b03.el7_2", rls:"OracleLinux7"))) {
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
