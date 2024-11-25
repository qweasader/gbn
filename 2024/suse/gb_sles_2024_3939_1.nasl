# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3939.1");
  script_cve_id("CVE-2024-47220");
  script_tag(name:"creation_date", value:"2024-11-08 04:31:30 +0000 (Fri, 08 Nov 2024)");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3939-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243939-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.1' package(s) announced via the SUSE-SU-2024:3939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.1 fixes the following issues:

CVE-2024-47220: Fixed HTTP request smuggling in WEBrick (bsc#1230930)");

  script_tag(name:"affected", value:"'ruby2.1' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1-debuginfo", rpm:"libruby2_1-2_1-debuginfo~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debuginfo", rpm:"ruby2.1-debuginfo~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debugsource", rpm:"ruby2.1-debugsource~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib-debuginfo", rpm:"ruby2.1-stdlib-debuginfo~2.1.9~19.9.1", rls:"SLES12.0SP5"))) {
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
