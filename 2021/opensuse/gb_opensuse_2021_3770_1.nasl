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
  script_oid("1.3.6.1.4.1.25623.1.0.854320");
  script_version("2021-11-29T14:44:44+0000");
  script_cve_id("CVE-2021-35550", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35567", "CVE-2021-35578", "CVE-2021-35586", "CVE-2021-35588", "CVE-2021-35603");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-29 14:44:44 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-25 19:10:00 +0000 (Mon, 25 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-11-25 02:03:03 +0000 (Thu, 25 Nov 2021)");
  script_name("openSUSE: Security Advisory for java-1_8_0-openjdk (openSUSE-SU-2021:3770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3770-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XBTSKQFBRMEJYNB4FQDRGX4SHHFX2QSS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the openSUSE-SU-2021:3770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

     Update to version OpenJDK 8u312 (October 2021 CPU):

  - CVE-2021-35550: Fixed weak ciphers preferred over stronger ones for TLS
       (bsc#1191901).

  - CVE-2021-35556: Fixed excessive memory allocation in RTFParser
       (bsc#1191910).

  - CVE-2021-35559: Fixed excessive memory allocation in RTFReader
       (bsc#1191911).

  - CVE-2021-35561: Fixed excessive memory allocation in HashMap and HashSet
       (bsc#1191912).

  - CVE-2021-35564: Fixed certificates with end dates too far in the future
       can corrupt keystore (bsc#1191913).

  - CVE-2021-35565: Fixed loop in HttpsServer triggered during TLS session
       close (bsc#1191909).

  - CVE-2021-35567: Fixed incorrect principal selection when using Kerberos
       Constrained Delegation (bsc#1191903).

  - CVE-2021-35578: Fixed unexpected exception raised during TLS handshake
       (bsc#1191904).

  - CVE-2021-35586: Fixed excessive memory allocation in BMPImageReader
       (bsc#1191914).

  - CVE-2021-35588: Fixed incomplete validation of inner class references in
       ClassFileParser (bsc#1191905)

  - CVE-2021-35603: Fixed non-constant comparison during TLS handshakes
       (bsc#1191906).");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.312~3.58.2", rls:"openSUSELeap15.3"))) {
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