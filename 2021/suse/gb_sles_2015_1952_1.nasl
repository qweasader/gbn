# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1952.1");
  script_cve_id("CVE-2014-0222", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1952-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151952-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:1952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to fix eight security issues.
These security issues were fixed:
- CVE-2015-4037: The slirp_smb function in net/slirp.c created temporary
 files with predictable names, which allowed local users to cause a
 denial of service (instantiation failure) by creating /tmp/qemu-smb.*-*
 files before the program (bsc#932267).
- CVE-2014-0222: Integer overflow in the qcow_open function allowed remote
 attackers to cause a denial of service (crash) via a large L2 table in a
 QCOW version 1 image (bsc#877642).
- CVE-2015-7835: Uncontrolled creation of large page mappings by PV guests
 (bsc#950367).
- CVE-2015-5239: Integer overflow in vnc_client_read() and
 protocol_client_msg() (bsc#944463).
- CVE-2015-6815: With e1000 NIC emulation support it was possible to enter
 an infinite loop (bsc#944697).
- CVE-2015-7969: Leak of main per-domain vcpu pointer array leading to
 denial of service (bsc#950703).
- CVE-2015-7969: Leak of per-domain profiling- related vcpu pointer array
 leading to denial of service (bsc#950705).
- CVE-2015-7971: Some pmu and profiling hypercalls log without rate
 limiting (bsc#950706).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.6_08_3.0.101_0.7.37~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.6_08_3.0.101_0.7.37~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.6_08_3.0.101_0.7.37~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.6_08~20.1", rls:"SLES11.0SP2"))) {
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
