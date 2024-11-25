# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2898.1");
  script_cve_id("CVE-2024-6655");
  script_tag(name:"creation_date", value:"2024-08-14 04:25:53 +0000 (Wed, 14 Aug 2024)");
  script_version("2024-08-14T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-08-14 05:05:52 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2898-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242898-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk3' package(s) announced via the SUSE-SU-2024:2898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gtk3 fixes the following issues:

CVE-2024-6655: Fixed library injection from current working directory (bsc#1228120).");

  script_tag(name:"affected", value:"'gtk3' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gettext-its-gtk3", rpm:"gettext-its-gtk3~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-data", rpm:"gtk3-data~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-debugsource", rpm:"gtk3-debugsource~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel", rpm:"gtk3-devel~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-debuginfo", rpm:"gtk3-devel-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-doc", rpm:"gtk3-devel-doc~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-lang", rpm:"gtk3-lang~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-schema", rpm:"gtk3-schema~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools", rpm:"gtk3-tools~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-debuginfo", rpm:"gtk3-tools-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0", rpm:"libgtk-3-0~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-debuginfo", rpm:"libgtk-3-0-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gtk-3_0", rpm:"typelib-1_0-Gtk-3_0~3.24.20~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gettext-its-gtk3", rpm:"gettext-its-gtk3~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-data", rpm:"gtk3-data~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-debugsource", rpm:"gtk3-debugsource~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel", rpm:"gtk3-devel~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-debuginfo", rpm:"gtk3-devel-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-doc", rpm:"gtk3-devel-doc~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-lang", rpm:"gtk3-lang~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-schema", rpm:"gtk3-schema~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools", rpm:"gtk3-tools~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-debuginfo", rpm:"gtk3-tools-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0", rpm:"libgtk-3-0~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-debuginfo", rpm:"libgtk-3-0-debuginfo~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gtk-3_0", rpm:"typelib-1_0-Gtk-3_0~3.24.20~150200.3.9.1", rls:"SLES15.0SP3"))) {
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
