# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1627.1");
  script_cve_id("CVE-2017-1000367", "CVE-2017-1000368");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-08 18:19:45 +0000 (Thu, 08 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1627-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1627-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171627-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2017:1627-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sudo fixes the following issues:
- CVE-2017-1000368: A follow-up fix to CVE-2017-1000367, the Linux process
 name could also contain a newline, which could be used to trick sudo to
 read/write to an arbitrary open terminal. (bsc#1042146)
Also the following non security bug was fixed:
- Link the 'system_group' plugin with sudo_util library to resolve the
 missing sudo_dso_findsym symbol (bsc#1034560)");

  script_tag(name:"affected", value:"'sudo' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE OpenStack Cloud 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.10p3~2.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.10p3~2.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debugsource", rpm:"sudo-debugsource~1.8.10p3~2.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.10p3~2.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.10p3~2.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debugsource", rpm:"sudo-debugsource~1.8.10p3~2.16.1", rls:"SLES12.0SP1"))) {
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
