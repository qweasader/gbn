# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3091.1");
  script_cve_id("CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3091-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193091-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2019:3091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel to version fixes the following issues:
Updated to 20191115 official security release (bsc#1157004 and
 bsc#1155988)

Includes security fixes for:
 - CVE-2019-11135: Added feature allowing to disable TSX RTM (bsc#1139073)
 - CVE-2019-11139: A CPU microcode only fix for Voltage modulation issues
 (bsc#1141035)");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20191115~3.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20191115~3.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20191115~3.3.1", rls:"SLES12.0SP5"))) {
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
