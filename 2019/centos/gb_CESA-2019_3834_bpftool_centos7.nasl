# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883133");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-11135");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2019-11-15 03:00:43 +0000 (Fri, 15 Nov 2019)");
  script_name("CentOS Update for bpftool CESA-2019:3834 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:3834");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-November/023516.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2019:3834 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * hw: Machine Check Error on Page Size Change (IFU) (CVE-2018-12207)

  * hw: TSX Transaction Asynchronous Abort (TAA) (CVE-2019-11135)

  * hw: Intel GPU Denial Of Service while accessing MMIO in lower power state
(CVE-2019-0154)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

1646768 - CVE-2018-12207 hw: Machine Check Error on Page Size Change (IPU)
1724393 - CVE-2019-0154 hw: Intel GPU Denial Of Service while accessing MMIO in lower power state
1753062 - CVE-2019-11135 hw: TSX Transaction Asynchronous Abort (TAA)

6. Package List:

Red Hat Enterprise Linux Client (v. 7):

Source:
kernel-3.10.0-1062.4.2.el7.src.rpm

noarch:
kernel-abi-whitelists-3.10.0-1062.4.2.el7.noarch.rpm
kernel-doc-3.10.0-1062.4.2.el7.noarch.rpm

x86_64:
bpftool-3.10.0-1062.4.2.el7.x86_64.rpm
bpftool-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debug-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debug-devel-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-devel-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-headers-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-tools-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-tools-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-tools-libs-3.10.0-1062.4.2.el7.x86_64.rpm
perf-3.10.0-1062.4.2.el7.x86_64.rpm
perf-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
python-perf-3.10.0-1062.4.2.el7.x86_64.rpm
python-perf-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm

Red Hat Enterprise Linux Client Optional (v. 7):

x86_64:
bpftool-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-tools-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
kernel-tools-libs-devel-3.10.0-1062.4.2.el7.x86_64.rpm
perf-debuginfo-3.10.0-1062.4.2.el7.x86_64.rpm
python-perf-debuginfo-3.10.0-1062 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'bpftool' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1062.4.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
