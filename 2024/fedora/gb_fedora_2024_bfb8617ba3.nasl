# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886924");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:22 +0000 (Fri, 07 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-bfb8617ba3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bfb8617ba3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-bfb8617ba3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282868");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282870");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fcitx5-qt, python-pyqt6, qadwaitadecorations, qgnomeplatform, qt6, qt6-qt3d, qt6-qt5compat, qt6-qtbase, qt6-qtcharts, qt6-qtcoap, qt6-qtconnectivity, qt6-qtdatavis3d, qt6-qtdeclarative, qt6-qtgraphs, qt6-qtgrpc, qt6-qthttpserver, qt6-qtimageformats, qt6-qtlanguageserver, qt6-qtlocation, qt6-qtlottie, qt6-qtmqtt, qt6-qtmultimedia, qt6-qtnetworkauth, qt6-qtopcua, qt6-qtpositioning, qt6-qtquick3d, qt6-qtquick3dphysics, qt6-qtquicktimeline, qt6-qtremoteobjects, qt6-qtscxml, qt6-qtsensors, qt6-qtserialbus, qt6-qtserialport, qt6-qtshadertools, qt6-qtspeech, qt6-qtsvg, qt6-qttools, qt6-qttranslations, qt6-qtvirtualkeyboard, qt6-qtwayland, qt6-qtwebchannel, qt6-qtwebengine, qt6-qtwebsockets, qt6-qtwebview, zeal' package(s) announced via the FEDORA-2024-bfb8617ba3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qt 6.7.1 bugfix update.");

  script_tag(name:"affected", value:"'fcitx5-qt, python-pyqt6, qadwaitadecorations, qgnomeplatform, qt6, qt6-qt3d, qt6-qt5compat, qt6-qtbase, qt6-qtcharts, qt6-qtcoap, qt6-qtconnectivity, qt6-qtdatavis3d, qt6-qtdeclarative, qt6-qtgraphs, qt6-qtgrpc, qt6-qthttpserver, qt6-qtimageformats, qt6-qtlanguageserver, qt6-qtlocation, qt6-qtlottie, qt6-qtmqtt, qt6-qtmultimedia, qt6-qtnetworkauth, qt6-qtopcua, qt6-qtpositioning, qt6-qtquick3d, qt6-qtquick3dphysics, qt6-qtquicktimeline, qt6-qtremoteobjects, qt6-qtscxml, qt6-qtsensors, qt6-qtserialbus, qt6-qtserialport, qt6-qtshadertools, qt6-qtspeech, qt6-qtsvg, qt6-qttools, qt6-qttranslations, qt6-qtvirtualkeyboard, qt6-qtwayland, qt6-qtwebchannel, qt6-qtwebengine, qt6-qtwebsockets, qt6-qtwebview, zeal' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt", rpm:"fcitx5-qt~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debuginfo", rpm:"fcitx5-qt-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debugsource", rpm:"fcitx5-qt-debugsource~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-devel", rpm:"fcitx5-qt-devel~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets", rpm:"fcitx5-qt-libfcitx5qt5widgets~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt5widgets-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets", rpm:"fcitx5-qt-libfcitx5qt6widgets~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt6widgets-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus", rpm:"fcitx5-qt-libfcitx5qtdbus~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus-debuginfo", rpm:"fcitx5-qt-libfcitx5qtdbus-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui", rpm:"fcitx5-qt-qt5gui~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui-debuginfo", rpm:"fcitx5-qt-qt5gui-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui", rpm:"fcitx5-qt-qt6gui~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui-debuginfo", rpm:"fcitx5-qt-qt6gui-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5", rpm:"fcitx5-qt5~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5-debuginfo", rpm:"fcitx5-qt5-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6", rpm:"fcitx5-qt6~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6-debuginfo", rpm:"fcitx5-qt6-debuginfo~5.1.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyqt6", rpm:"python-pyqt6~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyqt6-debuginfo", rpm:"python-pyqt6-debuginfo~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyqt6-debugsource", rpm:"python-pyqt6-debugsource~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyqt6-doc", rpm:"python-pyqt6-doc~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyqt6-rpm-macros", rpm:"python-pyqt6-rpm-macros~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyqt6", rpm:"python3-pyqt6~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyqt6-base", rpm:"python3-pyqt6-base~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyqt6-base-debuginfo", rpm:"python3-pyqt6-base-debuginfo~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyqt6-debuginfo", rpm:"python3-pyqt6-debuginfo~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyqt6-devel", rpm:"python3-pyqt6-devel~6.7.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations", rpm:"qadwaitadecorations~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-debuginfo", rpm:"qadwaitadecorations-debuginfo~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-debugsource", rpm:"qadwaitadecorations-debugsource~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt5", rpm:"qadwaitadecorations-qt5~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt5-debuginfo", rpm:"qadwaitadecorations-qt5-debuginfo~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt6", rpm:"qadwaitadecorations-qt6~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt6-debuginfo", rpm:"qadwaitadecorations-qt6-debuginfo~0.1.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform", rpm:"qgnomeplatform~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-common", rpm:"qgnomeplatform-common~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-debuginfo", rpm:"qgnomeplatform-debuginfo~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-debugsource", rpm:"qgnomeplatform-debugsource~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt5", rpm:"qgnomeplatform-qt5~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt5-debuginfo", rpm:"qgnomeplatform-qt5-debuginfo~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt6", rpm:"qgnomeplatform-qt6~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt6-debuginfo", rpm:"qgnomeplatform-qt6-debuginfo~0.9.2~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6", rpm:"qt6~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-assistant", rpm:"qt6-assistant~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-assistant-debuginfo", rpm:"qt6-assistant-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-designer", rpm:"qt6-designer~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-designer-debuginfo", rpm:"qt6-designer-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-doctools", rpm:"qt6-doctools~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-doctools-debuginfo", rpm:"qt6-doctools-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-linguist", rpm:"qt6-linguist~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-linguist-debuginfo", rpm:"qt6-linguist-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qdbusviewer", rpm:"qt6-qdbusviewer~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qdbusviewer-debuginfo", rpm:"qt6-qdbusviewer-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d", rpm:"qt6-qt3d~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d-debuginfo", rpm:"qt6-qt3d-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d-debugsource", rpm:"qt6-qt3d-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d-devel", rpm:"qt6-qt3d-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d-examples", rpm:"qt6-qt3d-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt3d-examples-debuginfo", rpm:"qt6-qt3d-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat", rpm:"qt6-qt5compat~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat-debuginfo", rpm:"qt6-qt5compat-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat-debugsource", rpm:"qt6-qt5compat-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat-devel", rpm:"qt6-qt5compat-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat-examples", rpm:"qt6-qt5compat-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qt5compat-examples-debuginfo", rpm:"qt6-qt5compat-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase", rpm:"qt6-qtbase~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-common", rpm:"qt6-qtbase-common~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-debuginfo", rpm:"qt6-qtbase-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-debugsource", rpm:"qt6-qtbase-debugsource~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-devel", rpm:"qt6-qtbase-devel~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-devel-debuginfo", rpm:"qt6-qtbase-devel-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-examples", rpm:"qt6-qtbase-examples~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-examples-debuginfo", rpm:"qt6-qtbase-examples-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-gui", rpm:"qt6-qtbase-gui~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-gui-debuginfo", rpm:"qt6-qtbase-gui-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-ibase", rpm:"qt6-qtbase-ibase~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-ibase-debuginfo", rpm:"qt6-qtbase-ibase-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-mysql", rpm:"qt6-qtbase-mysql~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-mysql-debuginfo", rpm:"qt6-qtbase-mysql-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-odbc", rpm:"qt6-qtbase-odbc~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-odbc-debuginfo", rpm:"qt6-qtbase-odbc-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-postgresql", rpm:"qt6-qtbase-postgresql~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-postgresql-debuginfo", rpm:"qt6-qtbase-postgresql-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-private-devel", rpm:"qt6-qtbase-private-devel~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-static", rpm:"qt6-qtbase-static~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts", rpm:"qt6-qtcharts~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts-debuginfo", rpm:"qt6-qtcharts-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts-debugsource", rpm:"qt6-qtcharts-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts-devel", rpm:"qt6-qtcharts-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts-examples", rpm:"qt6-qtcharts-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcharts-examples-debuginfo", rpm:"qt6-qtcharts-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap", rpm:"qt6-qtcoap~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap-debuginfo", rpm:"qt6-qtcoap-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap-debugsource", rpm:"qt6-qtcoap-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap-devel", rpm:"qt6-qtcoap-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap-examples", rpm:"qt6-qtcoap-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtcoap-examples-debuginfo", rpm:"qt6-qtcoap-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity", rpm:"qt6-qtconnectivity~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity-debuginfo", rpm:"qt6-qtconnectivity-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity-debugsource", rpm:"qt6-qtconnectivity-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity-devel", rpm:"qt6-qtconnectivity-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity-examples", rpm:"qt6-qtconnectivity-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtconnectivity-examples-debuginfo", rpm:"qt6-qtconnectivity-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d", rpm:"qt6-qtdatavis3d~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d-debuginfo", rpm:"qt6-qtdatavis3d-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d-debugsource", rpm:"qt6-qtdatavis3d-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d-devel", rpm:"qt6-qtdatavis3d-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d-examples", rpm:"qt6-qtdatavis3d-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdatavis3d-examples-debuginfo", rpm:"qt6-qtdatavis3d-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative", rpm:"qt6-qtdeclarative~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-debuginfo", rpm:"qt6-qtdeclarative-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-debugsource", rpm:"qt6-qtdeclarative-debugsource~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-devel", rpm:"qt6-qtdeclarative-devel~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-devel-debuginfo", rpm:"qt6-qtdeclarative-devel-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-examples", rpm:"qt6-qtdeclarative-examples~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-examples-debuginfo", rpm:"qt6-qtdeclarative-examples-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-static", rpm:"qt6-qtdeclarative-static~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs", rpm:"qt6-qtgraphs~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs-debuginfo", rpm:"qt6-qtgraphs-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs-debugsource", rpm:"qt6-qtgraphs-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs-devel", rpm:"qt6-qtgraphs-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs-examples", rpm:"qt6-qtgraphs-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgraphs-examples-debuginfo", rpm:"qt6-qtgraphs-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc", rpm:"qt6-qtgrpc~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-debuginfo", rpm:"qt6-qtgrpc-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-debugsource", rpm:"qt6-qtgrpc-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-devel", rpm:"qt6-qtgrpc-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-devel-debuginfo", rpm:"qt6-qtgrpc-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-examples", rpm:"qt6-qtgrpc-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtgrpc-examples-debuginfo", rpm:"qt6-qtgrpc-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver", rpm:"qt6-qthttpserver~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver-debuginfo", rpm:"qt6-qthttpserver-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver-debugsource", rpm:"qt6-qthttpserver-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver-devel", rpm:"qt6-qthttpserver-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver-examples", rpm:"qt6-qthttpserver-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qthttpserver-examples-debuginfo", rpm:"qt6-qthttpserver-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtimageformats", rpm:"qt6-qtimageformats~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtimageformats-debuginfo", rpm:"qt6-qtimageformats-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtimageformats-debugsource", rpm:"qt6-qtimageformats-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlanguageserver", rpm:"qt6-qtlanguageserver~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlanguageserver-debuginfo", rpm:"qt6-qtlanguageserver-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlanguageserver-debugsource", rpm:"qt6-qtlanguageserver-debugsource~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlanguageserver-devel", rpm:"qt6-qtlanguageserver-devel~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation", rpm:"qt6-qtlocation~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation-debuginfo", rpm:"qt6-qtlocation-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation-debugsource", rpm:"qt6-qtlocation-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation-devel", rpm:"qt6-qtlocation-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation-examples", rpm:"qt6-qtlocation-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlocation-examples-debuginfo", rpm:"qt6-qtlocation-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlottie", rpm:"qt6-qtlottie~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlottie-debuginfo", rpm:"qt6-qtlottie-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlottie-debugsource", rpm:"qt6-qtlottie-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtlottie-devel", rpm:"qt6-qtlottie-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt", rpm:"qt6-qtmqtt~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt-debuginfo", rpm:"qt6-qtmqtt-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt-debugsource", rpm:"qt6-qtmqtt-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt-devel", rpm:"qt6-qtmqtt-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt-examples", rpm:"qt6-qtmqtt-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmqtt-examples-debuginfo", rpm:"qt6-qtmqtt-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia", rpm:"qt6-qtmultimedia~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia-debuginfo", rpm:"qt6-qtmultimedia-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia-debugsource", rpm:"qt6-qtmultimedia-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia-devel", rpm:"qt6-qtmultimedia-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia-examples", rpm:"qt6-qtmultimedia-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtmultimedia-examples-debuginfo", rpm:"qt6-qtmultimedia-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth", rpm:"qt6-qtnetworkauth~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth-debuginfo", rpm:"qt6-qtnetworkauth-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth-debugsource", rpm:"qt6-qtnetworkauth-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth-devel", rpm:"qt6-qtnetworkauth-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth-examples", rpm:"qt6-qtnetworkauth-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtnetworkauth-examples-debuginfo", rpm:"qt6-qtnetworkauth-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua", rpm:"qt6-qtopcua~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua-debuginfo", rpm:"qt6-qtopcua-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua-debugsource", rpm:"qt6-qtopcua-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua-devel", rpm:"qt6-qtopcua-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua-examples", rpm:"qt6-qtopcua-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtopcua-examples-debuginfo", rpm:"qt6-qtopcua-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf", rpm:"qt6-qtpdf~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-debuginfo", rpm:"qt6-qtpdf-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-devel", rpm:"qt6-qtpdf-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-examples", rpm:"qt6-qtpdf-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-examples-debuginfo", rpm:"qt6-qtpdf-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning", rpm:"qt6-qtpositioning~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning-debuginfo", rpm:"qt6-qtpositioning-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning-debugsource", rpm:"qt6-qtpositioning-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning-devel", rpm:"qt6-qtpositioning-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning-examples", rpm:"qt6-qtpositioning-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpositioning-examples-debuginfo", rpm:"qt6-qtpositioning-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d", rpm:"qt6-qtquick3d~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-debuginfo", rpm:"qt6-qtquick3d-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-debugsource", rpm:"qt6-qtquick3d-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-devel", rpm:"qt6-qtquick3d-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-devel-debuginfo", rpm:"qt6-qtquick3d-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-examples", rpm:"qt6-qtquick3d-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3d-examples-debuginfo", rpm:"qt6-qtquick3d-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics", rpm:"qt6-qtquick3dphysics~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-debuginfo", rpm:"qt6-qtquick3dphysics-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-debugsource", rpm:"qt6-qtquick3dphysics-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-devel", rpm:"qt6-qtquick3dphysics-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-devel-debuginfo", rpm:"qt6-qtquick3dphysics-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-examples", rpm:"qt6-qtquick3dphysics-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquick3dphysics-examples-debuginfo", rpm:"qt6-qtquick3dphysics-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquicktimeline", rpm:"qt6-qtquicktimeline~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquicktimeline-debuginfo", rpm:"qt6-qtquicktimeline-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquicktimeline-debugsource", rpm:"qt6-qtquicktimeline-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtquicktimeline-devel", rpm:"qt6-qtquicktimeline-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects", rpm:"qt6-qtremoteobjects~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects-debuginfo", rpm:"qt6-qtremoteobjects-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects-debugsource", rpm:"qt6-qtremoteobjects-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects-devel", rpm:"qt6-qtremoteobjects-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects-examples", rpm:"qt6-qtremoteobjects-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtremoteobjects-examples-debuginfo", rpm:"qt6-qtremoteobjects-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml", rpm:"qt6-qtscxml~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml-debuginfo", rpm:"qt6-qtscxml-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml-debugsource", rpm:"qt6-qtscxml-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml-devel", rpm:"qt6-qtscxml-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml-examples", rpm:"qt6-qtscxml-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtscxml-examples-debuginfo", rpm:"qt6-qtscxml-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors", rpm:"qt6-qtsensors~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors-debuginfo", rpm:"qt6-qtsensors-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors-debugsource", rpm:"qt6-qtsensors-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors-devel", rpm:"qt6-qtsensors-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors-examples", rpm:"qt6-qtsensors-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsensors-examples-debuginfo", rpm:"qt6-qtsensors-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus", rpm:"qt6-qtserialbus~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus-debuginfo", rpm:"qt6-qtserialbus-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus-debugsource", rpm:"qt6-qtserialbus-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus-devel", rpm:"qt6-qtserialbus-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus-examples", rpm:"qt6-qtserialbus-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialbus-examples-debuginfo", rpm:"qt6-qtserialbus-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport", rpm:"qt6-qtserialport~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport-debuginfo", rpm:"qt6-qtserialport-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport-debugsource", rpm:"qt6-qtserialport-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport-devel", rpm:"qt6-qtserialport-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport-examples", rpm:"qt6-qtserialport-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtserialport-examples-debuginfo", rpm:"qt6-qtserialport-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtshadertools", rpm:"qt6-qtshadertools~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtshadertools-debuginfo", rpm:"qt6-qtshadertools-debuginfo~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtshadertools-debugsource", rpm:"qt6-qtshadertools-debugsource~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtshadertools-devel", rpm:"qt6-qtshadertools-devel~6.7.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech", rpm:"qt6-qtspeech~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-debuginfo", rpm:"qt6-qtspeech-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-debugsource", rpm:"qt6-qtspeech-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-devel", rpm:"qt6-qtspeech-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-examples", rpm:"qt6-qtspeech-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-examples-debuginfo", rpm:"qt6-qtspeech-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-flite", rpm:"qt6-qtspeech-flite~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-flite-debuginfo", rpm:"qt6-qtspeech-flite-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-speechd", rpm:"qt6-qtspeech-speechd~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtspeech-speechd-debuginfo", rpm:"qt6-qtspeech-speechd-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsvg", rpm:"qt6-qtsvg~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsvg-debuginfo", rpm:"qt6-qtsvg-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsvg-debugsource", rpm:"qt6-qtsvg-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsvg-devel", rpm:"qt6-qtsvg-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtsvg-examples", rpm:"qt6-qtsvg-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools", rpm:"qt6-qttools~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-common", rpm:"qt6-qttools-common~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-debuginfo", rpm:"qt6-qttools-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-debugsource", rpm:"qt6-qttools-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-devel", rpm:"qt6-qttools-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-devel-debuginfo", rpm:"qt6-qttools-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-examples", rpm:"qt6-qttools-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-examples-debuginfo", rpm:"qt6-qttools-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-designer", rpm:"qt6-qttools-libs-designer~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-designer-debuginfo", rpm:"qt6-qttools-libs-designer-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-designercomponents", rpm:"qt6-qttools-libs-designercomponents~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-designercomponents-debuginfo", rpm:"qt6-qttools-libs-designercomponents-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-help", rpm:"qt6-qttools-libs-help~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-libs-help-debuginfo", rpm:"qt6-qttools-libs-help-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttools-static", rpm:"qt6-qttools-static~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qttranslations", rpm:"qt6-qttranslations~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard", rpm:"qt6-qtvirtualkeyboard~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard-debuginfo", rpm:"qt6-qtvirtualkeyboard-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard-debugsource", rpm:"qt6-qtvirtualkeyboard-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard-devel", rpm:"qt6-qtvirtualkeyboard-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard-examples", rpm:"qt6-qtvirtualkeyboard-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtvirtualkeyboard-examples-debuginfo", rpm:"qt6-qtvirtualkeyboard-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland", rpm:"qt6-qtwayland~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-debuginfo", rpm:"qt6-qtwayland-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-debugsource", rpm:"qt6-qtwayland-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-devel", rpm:"qt6-qtwayland-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-devel-debuginfo", rpm:"qt6-qtwayland-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-examples", rpm:"qt6-qtwayland-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwayland-examples-debuginfo", rpm:"qt6-qtwayland-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel", rpm:"qt6-qtwebchannel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel-debuginfo", rpm:"qt6-qtwebchannel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel-debugsource", rpm:"qt6-qtwebchannel-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel-devel", rpm:"qt6-qtwebchannel-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel-examples", rpm:"qt6-qtwebchannel-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebchannel-examples-debuginfo", rpm:"qt6-qtwebchannel-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine", rpm:"qt6-qtwebengine~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-debuginfo", rpm:"qt6-qtwebengine-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-debugsource", rpm:"qt6-qtwebengine-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devel", rpm:"qt6-qtwebengine-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devel-debuginfo", rpm:"qt6-qtwebengine-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devtools", rpm:"qt6-qtwebengine-devtools~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-examples", rpm:"qt6-qtwebengine-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-examples-debuginfo", rpm:"qt6-qtwebengine-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets", rpm:"qt6-qtwebsockets~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-debuginfo", rpm:"qt6-qtwebsockets-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-debugsource", rpm:"qt6-qtwebsockets-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-devel", rpm:"qt6-qtwebsockets-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-devel-debuginfo", rpm:"qt6-qtwebsockets-devel-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-examples", rpm:"qt6-qtwebsockets-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebsockets-examples-debuginfo", rpm:"qt6-qtwebsockets-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview", rpm:"qt6-qtwebview~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview-debuginfo", rpm:"qt6-qtwebview-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview-debugsource", rpm:"qt6-qtwebview-debugsource~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview-devel", rpm:"qt6-qtwebview-devel~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview-examples", rpm:"qt6-qtwebview-examples~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebview-examples-debuginfo", rpm:"qt6-qtwebview-examples-debuginfo~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-rpm-macros", rpm:"qt6-rpm-macros~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-srpm-macros", rpm:"qt6-srpm-macros~6.7.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeal", rpm:"zeal~0.7.0~10.fc40", rls:"FC40"))) {
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
