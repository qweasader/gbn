# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851572");
  script_version("2021-09-15T12:01:38+0000");
  script_tag(name:"last_modification", value:"2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-06-26 18:54:41 +0200 (Mon, 26 Jun 2017)");
  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for openvpn (openSUSE-SU-2017:1680-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvpn fixes the following issues:

  - Some parts of the certificate-parsing code did not always clear all
  allocated memory. This would have allowed clients to leak a few bytes of
  memory for each connection attempt, thereby facilitating a (quite
  inefficient) DoS attack on the server. [bsc#1044947, CVE-2017-7521]

  - The ASN1 parsing code contained a bug that could have resulted in some
  buffers being free()d twice, and this issue could have potentially been
  triggered remotely by a VPN peer. [bsc#1044947, CVE-2017-7521]

  - If clients used a HTTP proxy with NTLM authentication, a
  man-in-the-middle attacker between client and proxy could cause the
  client to crash or disclose at most 96 bytes of stack memory. The
  disclosed stack memory was likely to contain the proxy password. If the
  proxy password had not been reused, this was unlikely to compromise the
  security of the OpenVPN tunnel itself. Clients who did not use the

  - -http-proxy option with ntlm2 authentication were not affected.
  [bsc#1044947, CVE-2017-7520]

  - It was possible to trigger an assertion by sending a malformed IPv6
  packet. That issue could have been abused to remotely shutdown an
  openvpn server or client, if IPv6 and --mssfix were enabled and if the
  IPv6 networks used inside the VPN were known. [bsc#1044947,
  CVE-2017-7508]


  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"openvpn on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1680-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin-debuginfo", rpm:"openvpn-auth-pam-plugin-debuginfo~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-debuginfo", rpm:"openvpn-debuginfo~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-debugsource", rpm:"openvpn-debugsource~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-devel", rpm:"openvpn-devel~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-down-root-plugin", rpm:"openvpn-down-root-plugin~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-down-root-plugin-debuginfo", rpm:"openvpn-down-root-plugin-debuginfo~2.3.8~8.10.1", rls:"openSUSELeap42.2"))) {
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
