# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0328.1");
  script_cve_id("CVE-2018-25020", "CVE-2019-0136", "CVE-2020-3702", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-05 03:21:38 +0000 (Sat, 05 Feb 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 16:34:33 +0000 (Mon, 13 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0328-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220328-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2022:0328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_147 fixes several issues.

The following security issues were fixed:

CVE-2018-25020: Fixed an issue in the BPF subsystem in the Linux kernel
 mishandled situations with a long jump over an instruction sequence
 where inner instructions require substantial expansions into multiple
 BPF instructions, leading to an overflow. (bsc#1193575)

CVE-2020-3702: Fixed a bug which could be triggered with specifically
 timed and handcrafted traffic and cause internal errors in a WLAN device
 that lead to improper layer 2 Wi-Fi encryption with a consequent
 possibility of information disclosure. (bsc#1191193)

CVE-2019-0136: Fixed an insufficient access control which allow an
 unauthenticated user to execute a denial of service. (bsc#1193157)

CVE-2021-42739: The firewire subsystem had a buffer overflow related to
 drivers/media/firewire/firedtv-avc.c and
 drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled
 bounds checking (bsc#1184673).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default", rpm:"kgraft-patch-4_4_180-94_147-default~7~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_147-default-debuginfo~7~2.2", rls:"SLES12.0SP3"))) {
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
