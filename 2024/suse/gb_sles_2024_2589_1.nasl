# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2589.1");
  script_cve_id("CVE-2024-36472");
  script_tag(name:"creation_date", value:"2024-07-23 04:24:22 +0000 (Tue, 23 Jul 2024)");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242589-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-shell' package(s) announced via the SUSE-SU-2024:2589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnome-shell fixes the following issues:

CVE-2024-36472: Fixed portal helper automatically launched without user confirmation (bsc#1225567)");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-browser-plugin", rpm:"gnome-shell-browser-plugin~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-browser-plugin-debuginfo", rpm:"gnome-shell-browser-plugin-debuginfo~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debuginfo", rpm:"gnome-shell-debuginfo~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debugsource", rpm:"gnome-shell-debugsource~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-lang", rpm:"gnome-shell-lang~3.20.4~77.28.1", rls:"SLES12.0SP5"))) {
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
