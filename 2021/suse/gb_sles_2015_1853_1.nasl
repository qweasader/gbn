# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1853.1");
  script_cve_id("CVE-2014-0222", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 21:34:36 +0000 (Tue, 28 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1853-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1853-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151853-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:1853-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to fix nine security issues.
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
- CVE-2015-7311: libxl in Xen did not properly handle the readonly flag on
 disks when using the qemu-xen device model, which allowed local guest
 users to write to a read-only disk image (bsc#947165).
- CVE-2015-5239: Integer overflow in vnc_client_read() and
 protocol_client_msg() (bsc#944463).
- CVE-2015-6815: With e1000 NIC emulation support it was possible to enter
 an infinite loop (bsc#944697).
- CVE-2015-7969: Leak of main per-domain vcpu pointer array leading to
 denial of service (bsc#950703).
- CVE-2015-7969: Leak of per-domain profiling- related vcpu pointer array
 leading to denial of service (bsc#950705).
- CVE-2015-7971: Some pmu and profiling hypercalls log without rate
 limiting (bsc#950706).
These non-security issues were fixed:
- bsc#907514: Bus fatal error: SLES 12 sudden reboot has been observed
- bsc#910258: SLES12 Xen host crashes with FATAL NMI after shutdown of
 guest with VT-d NIC
- bsc#918984: Bus fatal error: SLES11-SP4 sudden reboot has been observed
- bsc#923967: Partner-L3: Bus fatal error: SLES11-SP3 sudden reboot has
 been observed
- bsc#941074: Device 51728 could not be connected. Hotplug scripts not
 working");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_14_3.0.101_0.47.67~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_14_3.0.101_0.47.67~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_14~18.2", rls:"SLES11.0SP3"))) {
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
