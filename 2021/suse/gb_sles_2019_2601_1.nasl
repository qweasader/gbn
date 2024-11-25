# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2601.1");
  script_cve_id("CVE-2018-5390", "CVE-2019-14835");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-18 19:06:21 +0000 (Wed, 18 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2601-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2601-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192601-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 32 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2019:2601-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_120 fixes several issues.

The following security issues were fixed:
CVE-2019-14835: A buffer overflow flaw was found in the way vhost
 functionality, that translates virtqueue buffers to IOVs, logged the
 buffer descriptors during migration. A privileged guest user able to
 pass descriptors with invalid length to the host when migration is
 underway, could use this flaw to increase their privileges on the host
 (bsc#1151021).

CVE-2018-5390: Fixed a denial of service ('SegmentSmack') in
 tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every incoming
 packet (bsc#1102682).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 32 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_120-default", rpm:"kgraft-patch-4_4_121-92_120-default~2~2.1", rls:"SLES12.0SP2"))) {
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
