# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2355.1");
  script_cve_id("CVE-2017-11600", "CVE-2018-10853", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-19 18:51:20 +0000 (Mon, 19 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2355-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2355-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182355-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 20 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2018:2355-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_57 fixes several issues.
The following security issues were fixed:
- CVE-2018-3646: Local attackers in virtualized guest systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data, even from other virtual
 machines or the host system (bsc#1099306).
- CVE-2017-11600: net/xfrm/xfrm_policy.c did not ensure that the dir value
 of xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which allowed local
 users to cause a denial of service (out-of-bounds access) or possibly
 have unspecified other impact via an XFRM_MSG_MIGRATE xfrm Netlink
 message (bsc#1096564)
- CVE-2018-10853: A flaw was found in kvm. In which certain instructions
 such as sgdt/sidt call segmented_write_std didn't propagate access
 correctly. As such, during userspace induced exception, the guest can
 incorrectly assume that the exception happened in the kernel and panic.
 (bsc#1097108).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 20 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_57-default", rpm:"kgraft-patch-3_12_74-60_64_57-default~11~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_57-xen", rpm:"kgraft-patch-3_12_74-60_64_57-xen~11~2.1", rls:"SLES12.0SP1"))) {
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
