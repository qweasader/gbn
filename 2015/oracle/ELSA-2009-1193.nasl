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
  script_oid("1.3.6.1.4.1.25623.1.0.122460");
  script_cve_id("CVE-2007-5966", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:48 +0000 (Thu, 08 Oct 2015)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 19:19:16 +0000 (Thu, 15 Feb 2024)");

  script_name("Oracle: Security Advisory (ELSA-2009-1193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1193");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1193.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-128.4.1.0.1.el5, oracleasm-2.6.18-128.4.1.0.1.el5' package(s) announced via the ELSA-2009-1193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-128.4.1.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888]
- [NET] Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [XEN] use hypercall to fixmap pte updates (Mukesh Rathor) [orabug 8433329]
- [XEN] Extend physical mask to 40bit for machine above 64G [orabug 8312526]

[2.6.18-128.4.1.el5]
- [fs] ecryptfs: check tag 11 packet literal data buffer size (Eric Sandeen ) [512862 512863] {CVE-2009-2406}
- [fs] ecryptfs: check tag 3 packet encrypted key size (Eric Sandeen ) [512886 512887] {CVE-2009-2407}
- [misc] personality handling: fix PER_CLEAR_ON_SETID (Vitaly Mayatskikh ) [511173 508842] {CVE-2009-1895}
- [xen] HV: remove high latency spin_lock (Chris Lalancette ) [512311 459410]

[2.6.18-128.3.1.el5]
- [pci] quirk: disable MSI on VIA VT3364 chipsets (Dean Nelson ) [507529 501374]
- [char] tty: prevent an O_NDELAY writer from blocking (Mauro Carvalho Chehab ) [510239 506806]
- [misc] hrtimer: fix a soft lockup (Amerigo Wang ) [418061 418071] {CVE-2007-5966}
- [misc] hrtimer: check relative timeouts for overflow (AMEET M. PARANJAPE ) [510018 492230]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-128.4.1.0.1.el5, oracleasm-2.6.18-128.4.1.0.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.4.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.4.1.0.1.el5", rpm:"ocfs2-2.6.18-128.4.1.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.4.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-128.4.1.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.4.1.0.1.el5debug", rpm:"ocfs2-2.6.18-128.4.1.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.4.1.0.1.el5xen", rpm:"ocfs2-2.6.18-128.4.1.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.4.1.0.1.el5", rpm:"oracleasm-2.6.18-128.4.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.4.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-128.4.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.4.1.0.1.el5debug", rpm:"oracleasm-2.6.18-128.4.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.4.1.0.1.el5xen", rpm:"oracleasm-2.6.18-128.4.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
