# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2339.1");
  script_cve_id("CVE-2017-10664", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 17:38:27 +0000 (Tue, 29 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2339-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172339-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:2339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:
- CVE-2017-12855: Premature clearing of GTF_writing / GTF_reading lead to
 potentially leaking sensitive information (XSA-230, bsc#1052686).
- CVE-2017-12135: Unbounded recursion in grant table code allowed a
 malicious guest to crash the host or potentially escalate
 privileges/leak information (XSA-226, bsc#1051787).
- CVE-2017-12137: Incorrectly-aligned updates to pagetables allowed for
 privilege escalation (XSA-227, bsc#1051788).
- CVE-2017-11334: The address_space_write_continue function in exec.c
 allowed local guest OS privileged users to cause a denial of service
 (out-of-bounds access and guest instance crash) by leveraging use of
 qemu_map_ram_ptr to access guest ram block area (bsc#1048920).
- CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local
 guest OS users to cause a denial of service (out-of-bounds read) via a
 crafted DHCP
 options string (bsc#1049578).
- CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which allowed remote
 attackers to cause a denial of service (daemon crash) by disconnecting
 during a server-to-client reply attempt (bsc#1046637).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_21_3.0.101_0.47.105~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_21_3.0.101_0.47.105~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_21~45.5.1", rls:"SLES11.0SP3"))) {
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
