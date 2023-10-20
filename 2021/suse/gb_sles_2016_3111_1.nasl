# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3111.1");
  script_cve_id("CVE-2016-7117", "CVE-2016-8655", "CVE-2016-9555");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3111-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3111-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163111-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel Live Patch 9 for SLE 12' package(s) announced via the SUSE-SU-2016:3111-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.51-52_31 fixes several issues.
The following security bugs were fixed:
- CVE-2016-8655: A race condition in the af_packet packet_set_ring
 function could be used by local attackers to crash the kernel or gain
 privileges (bsc#1012759).
- CVE-2016-9555: The sctp_sf_ootb function in net/sctp/sm_statefuns.c in
 the Linux kernel lacks chunk-length checking for the first chunk, which
 allowed remote attackers to cause a denial of service (out-of-bounds
 slab access) or possibly have unspecified other impact via crafted SCTP
 data (bsc#1012183).
- CVE-2016-7117: Use-after-free vulnerability in the __sys_recvmmsg
 function in net/socket.c in the Linux kernel allowed remote attackers to
 execute arbitrary code via vectors involving a recvmmsg system call that
 is mishandled during error processing (bsc#1003253).");

  script_tag(name:"affected", value:"'Linux Kernel Live Patch 9 for SLE 12' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_51-52_31-default", rpm:"kgraft-patch-3_12_51-52_31-default~7~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_51-52_31-xen", rpm:"kgraft-patch-3_12_51-52_31-xen~7~2.1", rls:"SLES12.0"))) {
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
