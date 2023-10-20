# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2447.1");
  script_cve_id("CVE-2017-1000112", "CVE-2017-8890", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:32:00 +0000 (Fri, 24 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2447-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172447-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel Live Patch 18 for SLE 12 SP1' package(s) announced via the SUSE-SU-2017:2447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_51 fixes several issues.
The following security bugs were fixed:
- CVE-2017-1000112: Prevent a race condition in net-packet code that could
 have been exploited by unprivileged users to gain root access
 (bsc#1052368).
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c
 in the Linux kernel was too late in checking whether an overwrite of an
 skb data structure may occur, which allowed local users to cause a
 denial of service (system crash) via crafted system calls (bsc#1038564,
 bsc#1042892).
- CVE-2017-8890: The inet_csk_clone_lock function in
 net/ipv4/inet_connection_sock.c in the Linux kernel allowed attackers to
 cause a denial of service (double free) or possibly have unspecified
 other impact by leveraging use of the accept system call (bsc#1038564).");

  script_tag(name:"affected", value:"'Linux Kernel Live Patch 18 for SLE 12 SP1' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_51-default", rpm:"kgraft-patch-3_12_74-60_64_51-default~2~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_51-xen", rpm:"kgraft-patch-3_12_74-60_64_51-xen~2~2.1", rls:"SLES12.0SP1"))) {
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
