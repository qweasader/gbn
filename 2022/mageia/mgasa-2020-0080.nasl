# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0080");
  script_cve_id("CVE-2020-0569", "CVE-2020-0570");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 17:54:02 +0000 (Tue, 22 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0080");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0080.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25418");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26153");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/01/30/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase5' package(s) announced via the MGASA-2020-0080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qtbase5 packages fix security vulnerabilities:

QPluginLoader in Qt versions 5.0.0 through 5.13.2 would search for certain
plugins first on the current working directory of the application, which
allows an attacker that can place files in the file system and influence
the working directory of Qt-based applications to load and execute
malicious code (CVE-2020-0569).

QLibrary in Qt versions 5.12.0 through 5.14.0, on certain x86 machines,
would search for certain libraries and plugins relative to current working
directory of the application, which allows an attacker that can place files
in the file system and influence the working directory of Qt-based
applications to load and execute malicious code (CVE-2020-0570).

Also, a file conflict that caused issues when upgrading from Mageia 6 has
been fixed (mga#25418)");

  script_tag(name:"affected", value:"'qtbase5' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-mysql", rpm:"lib64qt5-database-plugin-mysql~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-odbc", rpm:"lib64qt5-database-plugin-odbc~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-pgsql", rpm:"lib64qt5-database-plugin-pgsql~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-sqlite", rpm:"lib64qt5-database-plugin-sqlite~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-tds", rpm:"lib64qt5-database-plugin-tds~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5accessibilitysupport-static-devel", rpm:"lib64qt5accessibilitysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5base5-devel", rpm:"lib64qt5base5-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5bootstrap-static-devel", rpm:"lib64qt5bootstrap-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent-devel", rpm:"lib64qt5concurrent-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent5", rpm:"lib64qt5concurrent5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core-devel", rpm:"lib64qt5core-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core5", rpm:"lib64qt5core5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus-devel", rpm:"lib64qt5dbus-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus5", rpm:"lib64qt5dbus5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5devicediscoverysupport-static-devel", rpm:"lib64qt5devicediscoverysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5edid-devel", rpm:"lib64qt5edid-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration-devel", rpm:"lib64qt5eglfsdeviceintegration-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration5", rpm:"lib64qt5eglfsdeviceintegration5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport-devel", rpm:"lib64qt5eglfskmssupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport5", rpm:"lib64qt5eglfskmssupport5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglsupport-static-devel", rpm:"lib64qt5eglsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eventdispatchersupport-static-devel", rpm:"lib64qt5eventdispatchersupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fbsupport-static-devel", rpm:"lib64qt5fbsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fontdatabasesupport-static-devel", rpm:"lib64qt5fontdatabasesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5glxsupport-static-devel", rpm:"lib64qt5glxsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui-devel", rpm:"lib64qt5gui-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui5", rpm:"lib64qt5gui5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5inputsupport-static-devel", rpm:"lib64qt5inputsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5kmssupport-static-devel", rpm:"lib64qt5kmssupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5linuxaccessibilitysupport-static-devel", rpm:"lib64qt5linuxaccessibilitysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network-devel", rpm:"lib64qt5network-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network5", rpm:"lib64qt5network5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl-devel", rpm:"lib64qt5opengl-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl5", rpm:"lib64qt5opengl5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformcompositorsupport-static-devel", rpm:"lib64qt5platformcompositorsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformsupport-devel", rpm:"lib64qt5platformsupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport-devel", rpm:"lib64qt5printsupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport5", rpm:"lib64qt5printsupport5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5servicesupport-static-devel", rpm:"lib64qt5servicesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql-devel", rpm:"lib64qt5sql-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql5", rpm:"lib64qt5sql5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test-devel", rpm:"lib64qt5test-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test5", rpm:"lib64qt5test5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5themesupport-static-devel", rpm:"lib64qt5themesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets-devel", rpm:"lib64qt5widgets-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets5", rpm:"lib64qt5widgets5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa-devel", rpm:"lib64qt5xcbqpa-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa5", rpm:"lib64qt5xcbqpa5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml-devel", rpm:"lib64qt5xml-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml5", rpm:"lib64qt5xml5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-mysql", rpm:"libqt5-database-plugin-mysql~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-odbc", rpm:"libqt5-database-plugin-odbc~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-pgsql", rpm:"libqt5-database-plugin-pgsql~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-sqlite", rpm:"libqt5-database-plugin-sqlite~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-tds", rpm:"libqt5-database-plugin-tds~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5accessibilitysupport-static-devel", rpm:"libqt5accessibilitysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5base5-devel", rpm:"libqt5base5-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5bootstrap-static-devel", rpm:"libqt5bootstrap-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent-devel", rpm:"libqt5concurrent-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent5", rpm:"libqt5concurrent5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core-devel", rpm:"libqt5core-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core5", rpm:"libqt5core5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus-devel", rpm:"libqt5dbus-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus5", rpm:"libqt5dbus5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5devicediscoverysupport-static-devel", rpm:"libqt5devicediscoverysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5edid-devel", rpm:"libqt5edid-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration-devel", rpm:"libqt5eglfsdeviceintegration-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration5", rpm:"libqt5eglfsdeviceintegration5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport-devel", rpm:"libqt5eglfskmssupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport5", rpm:"libqt5eglfskmssupport5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglsupport-static-devel", rpm:"libqt5eglsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eventdispatchersupport-static-devel", rpm:"libqt5eventdispatchersupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fbsupport-static-devel", rpm:"libqt5fbsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fontdatabasesupport-static-devel", rpm:"libqt5fontdatabasesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5glxsupport-static-devel", rpm:"libqt5glxsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui-devel", rpm:"libqt5gui-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui5", rpm:"libqt5gui5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5inputsupport-static-devel", rpm:"libqt5inputsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5kmssupport-static-devel", rpm:"libqt5kmssupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5linuxaccessibilitysupport-static-devel", rpm:"libqt5linuxaccessibilitysupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network-devel", rpm:"libqt5network-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network5", rpm:"libqt5network5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl-devel", rpm:"libqt5opengl-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl5", rpm:"libqt5opengl5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformcompositorsupport-static-devel", rpm:"libqt5platformcompositorsupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformsupport-devel", rpm:"libqt5platformsupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport-devel", rpm:"libqt5printsupport-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport5", rpm:"libqt5printsupport5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5servicesupport-static-devel", rpm:"libqt5servicesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql-devel", rpm:"libqt5sql-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql5", rpm:"libqt5sql5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test-devel", rpm:"libqt5test-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test5", rpm:"libqt5test5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5themesupport-static-devel", rpm:"libqt5themesupport-static-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets-devel", rpm:"libqt5widgets-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets5", rpm:"libqt5widgets5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa-devel", rpm:"libqt5xcbqpa-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa5", rpm:"libqt5xcbqpa5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml-devel", rpm:"libqt5xml-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml5", rpm:"libqt5xml5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5", rpm:"qtbase5~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common", rpm:"qtbase5-common~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common-devel", rpm:"qtbase5-common-devel~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-doc", rpm:"qtbase5-doc~5.12.6~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-examples", rpm:"qtbase5-examples~5.12.6~2.mga7", rls:"MAGEIA7"))) {
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
