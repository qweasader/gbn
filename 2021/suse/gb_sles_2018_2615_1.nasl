# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2615.1");
  script_cve_id("CVE-2018-11806", "CVE-2018-12617", "CVE-2018-3639");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:15:00 +0000 (Thu, 10 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2615-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182615-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2018:2615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes the following security issues:
CVE-2018-12617: qmp_guest_file_read had an integer overflow that could
 have been exploited by sending a crafted QMP command (including
 guest-file-read with a large count value) to the agent via the listening
 socket causing DoS (bsc#1098735)

CVE-2018-11806: Prevent heap-based buffer overflow via incoming
 fragmented datagrams (bsc#1096223)

With this release the mitigations for Spectre v4 are moved the patches from upstream (CVE-2018-3639, bsc#1092885).");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~53.23.2", rls:"SLES11.0SP3"))) {
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
