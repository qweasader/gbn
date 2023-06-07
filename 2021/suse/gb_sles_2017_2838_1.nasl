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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2838.1");
  script_cve_id("CVE-2016-6329", "CVE-2017-12166", "CVE-2017-7478", "CVE-2017-7479");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-05-16T04:20:37+0000");
  script_tag(name:"last_modification", value:"2022-05-16 04:20:37 +0000 (Mon, 16 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-12 20:10:00 +0000 (Thu, 12 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2838-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2838-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172838-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the SUSE-SU-2017:2838-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvpn fixes the following security issues:
- CVE-2017-12166: OpenVPN was vulnerable to a buffer overflow
 vulnerability when key-method 1 is used, possibly resulting in code
 execution. (bsc#1060877).
- CVE-2016-6329: Now show which ciphers should no longer be used in
 openvpn --show-ciphers to avoid the SWEET32 attack (bsc#995374)
- CVE-2017-7478: OpenVPN was vulnerable to unauthenticated Denial of
 Service of server via received large control packet. (bsc#1038709)
- CVE-2017-7479: OpenVPN was vulnerable to reachable assertion when
 packet-ID counter rolls over resulting into Denial of Service of server
 by authenticated attacker. (bsc#1038711)
- Some other hardening fixes have also been applied (bsc#1038713)");

  script_tag(name:"affected", value:"'openvpn' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.0.9~143.47.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.0.9~143.47.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.0.9~143.47.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.0.9~143.47.3.1", rls:"SLES11.0SP4"))) {
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
