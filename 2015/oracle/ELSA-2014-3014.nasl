# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123437");
  script_cve_id("CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0101", "CVE-2014-2523");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-04T14:03:28+0000");
  script_tag(name:"last_modification", value:"2022-04-04 14:03:28 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-3014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3014");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-26.2.2.el6uek, kernel-uek' package(s) announced via the ELSA-2014-3014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-26.2.2.el6uek]
- netfilter: nf_conntrack_dccp: fix skb_header_pointer API usages (Daniel Borkmann) [Orabug: 18421673] {CVE-2014-2523}
- cifs: ensure that uncached writes handle unmapped areas correctly (Jeff Layton) [Orabug: 18461067] {CVE-2014-0069} {CVE-2014-0069}
- net: sctp: fix sctp_sf_do_5_1D_ce to verify if we/peer is AUTH capable (Daniel Borkmann) [Orabug: 18461065] {CVE-2014-0101}
- vhost-net: insufficient handling of error conditions in get_rx_bufs() (Guangyu Sun) [Orabug: 18461050] {CVE-2014-0055}");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-26.2.2.el6uek, kernel-uek' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-26.2.2.el6uek", rpm:"dtrace-modules-3.8.13-26.2.2.el6uek~0.4.2~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~3.8.13~26.2.2.el6uek", rls:"OracleLinux6"))) {
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
