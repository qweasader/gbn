# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1156.1");
  script_cve_id("CVE-2015-3209", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4164");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1156-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151156-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:1156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xen was updated to fix six security issues:
CVE-2015-4103: Potential unintended writes to host MSI message data field via qemu. (XSA-128, bsc#931625)
CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests. (XSA-129, bsc#931626)
CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error messages. (XSA-130, bsc#931627)
CVE-2015-4106: Unmediated PCI register access in qemu. (XSA-131, bsc#931628)
CVE-2015-3209: heap overflow in qemu pcnet controller allowing guest to host escape. (XSA-135, bsc#932770)
CVE-2015-4164: DoS through iret hypercall handler. (XSA-136, bsc#932996)
Security Issues:
CVE-2015-4103 CVE-2015-4104 CVE-2015-4105 CVE-2015-4106 CVE-2015-4164 CVE-2015-3209");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1"))) {
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
