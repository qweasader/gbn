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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0655.1");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0655-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190655-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2_org' package(s) announced via the SUSE-SU-2019:0655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh2_org fixes the following issues:

Security issues fixed:
CVE-2019-3861: Fixed Out-of-bounds reads with specially crafted SSH
 packets (bsc#1128490).

CVE-2019-3862: Fixed Out-of-bounds memory comparison with specially
 crafted message channel request packet (bsc#1128492).

CVE-2019-3860: Fixed Out-of-bounds reads with specially crafted SFTP
 packets (bsc#1128481).

CVE-2019-3863: Fixed an Integer overflow in user authenticate keyboard
 interactive which could allow out-of-bounds writes with specially
 crafted keyboard responses (bsc#1128493).

CVE-2019-3856: Fixed a potential Integer overflow in keyboard
 interactive handling which could allow out-of-bounds write with
 specially crafted payload (bsc#1128472).

CVE-2019-3859: Fixed Out-of-bounds reads with specially crafted payloads
 due to unchecked use of _libssh2_packet_require and
 _libssh2_packet_requirev (bsc#1128480).

CVE-2019-3855: Fixed a potential Integer overflow in transport read
 which could allow out-of-bounds write with specially crafted payload
 (bsc#1128471).

CVE-2019-3858: Fixed a potential zero-byte allocation which could lead
 to an out-of-bounds read with a specially crafted SFTP packet
 (bsc#1128476).

CVE-2019-3857: Fixed a potential Integer overflow which could lead to
 zero-byte allocation and out-of-bounds with specially crafted message
 channel request SSH packet (bsc#1128474).

Other issue addressed:
Libbssh2 will stop using keys unsupported types in the known_hosts file
 (bsc#1091236).");

  script_tag(name:"affected", value:"'libssh2_org' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.4.3~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.4.3~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo-32bit", rpm:"libssh2-1-debuginfo-32bit~1.4.3~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.4.3~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~20.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.4.3~20.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.4.3~20.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo-32bit", rpm:"libssh2-1-debuginfo-32bit~1.4.3~20.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.4.3~20.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~20.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.4.3~20.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.4.3~20.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo-32bit", rpm:"libssh2-1-debuginfo-32bit~1.4.3~20.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.4.3~20.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~20.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.4.3~20.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.4.3~20.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo-32bit", rpm:"libssh2-1-debuginfo-32bit~1.4.3~20.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.4.3~20.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~20.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.4.3~20.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.4.3~20.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo-32bit", rpm:"libssh2-1-debuginfo-32bit~1.4.3~20.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.4.3~20.3.1", rls:"SLES12.0SP4"))) {
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
