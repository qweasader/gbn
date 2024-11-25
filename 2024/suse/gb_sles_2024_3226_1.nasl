# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3226.1");
  script_tag(name:"creation_date", value:"2024-09-13 04:27:55 +0000 (Fri, 13 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3226-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3226-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243226-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'colord' package(s) announced via the SUSE-SU-2024:3226-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for colord fixes the following issues:

Fixed a potential local privilege escalation by removing the script in the specfile which changes the ownership of /var/lib/colord. (bsc#1208056)");

  script_tag(name:"affected", value:"'colord' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"colord-debuginfo", rpm:"colord-debuginfo~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"colord-debugsource", rpm:"colord-debugsource~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolord2", rpm:"libcolord2~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolord2-32bit", rpm:"libcolord2-32bit~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolord2-debuginfo", rpm:"libcolord2-debuginfo~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolord2-debuginfo-32bit", rpm:"libcolord2-debuginfo-32bit~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolorhug2", rpm:"libcolorhug2~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolorhug2-debuginfo", rpm:"libcolorhug2-debuginfo~1.3.3~13.6.1", rls:"SLES12.0SP5"))) {
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
