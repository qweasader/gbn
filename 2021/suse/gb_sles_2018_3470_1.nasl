# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3470.1");
  script_cve_id("CVE-2018-14633", "CVE-2018-5390");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3470-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183470-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 25 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2018:3470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_95 fixes several issues.

The following security issues were fixed:
CVE-2018-14633: A security flaw was found in the
 chap_server_compute_md5() function in the ISCSI target code in a way an
 authentication request from an ISCSI initiator is processed. An
 unauthenticated remote attacker can cause a stack buffer overflow and
 smash up to 17 bytes of the stack. The attack requires the iSCSI target
 to be enabled on the victim host. Depending on how the target's code was
 built (i.e. depending on a compiler, compile flags and hardware
 architecture) an attack may lead to a system crash and thus to a
 denial-of-service or possibly to a non-authorized access to data
 exported by an iSCSI target. Due to the nature of the flaw, privilege
 escalation cannot be fully ruled out, although we believe it is highly
 unlikely. (bsc#1107832).

CVE-2018-5390: The Linux kernel could be forced to make very expensive
 calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every
 incoming packet which can lead to a denial of service (bsc#1102682).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 25 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_95-default", rpm:"kgraft-patch-4_4_121-92_95-default~2~2.1", rls:"SLES12.0SP2"))) {
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
