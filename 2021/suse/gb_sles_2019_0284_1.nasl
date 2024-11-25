# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0284.1");
  script_cve_id("CVE-2015-3239");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0284-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190284-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libunwind' package(s) announced via the SUSE-SU-2019:0284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libunwind fixes the following issues:

Security issues fixed:
CVE-2015-3239: Fixed a off-by-one in the dwarf_to_unw_regnum function
 (bsc#936786)

Non-security issues fixed:
Fixed a dependency issue with libzmq5 (bsc#1122012)

Fixed build on armv7 (bsc#976955)");

  script_tag(name:"affected", value:"'libunwind' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libunwind", rpm:"libunwind~1.1~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debuginfo", rpm:"libunwind-debuginfo~1.1~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debugsource", rpm:"libunwind-debugsource~1.1~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-devel", rpm:"libunwind-devel~1.1~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libunwind", rpm:"libunwind~1.1~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debuginfo", rpm:"libunwind-debuginfo~1.1~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debugsource", rpm:"libunwind-debugsource~1.1~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-devel", rpm:"libunwind-devel~1.1~11.3.1", rls:"SLES12.0SP4"))) {
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
