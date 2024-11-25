# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856338");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2024-6655");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-31 04:00:33 +0000 (Wed, 31 Jul 2024)");
  script_name("openSUSE: Security Advisory for gtk3 (SUSE-SU-2024:2633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2633-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IZVA4MIHLZSWBEVJ62WWXN55I72PB2DI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk3'
  package(s) announced via the SUSE-SU-2024:2633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gtk3 fixes the following issues:

  * CVE-2024-6655: Fixed library injection from current working directory
      (bsc#1228120)");

  script_tag(name:"affected", value:"'gtk3' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gtk3-lang", rpm:"gtk3-lang~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-doc", rpm:"gtk3-devel-doc~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-branding-upstream", rpm:"gtk3-branding-upstream~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-schema", rpm:"gtk3-schema~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-its-gtk3", rpm:"gettext-its-gtk3~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-data", rpm:"gtk3-data~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-Gtk-3.0", rpm:"typelib-1.0-Gtk-3.0~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai", rpm:"gtk3-immodule-thai~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim-debuginfo", rpm:"gtk3-immodule-xim-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-debuginfo", rpm:"gtk3-tools-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic-debuginfo", rpm:"gtk3-immodule-amharic-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic", rpm:"gtk3-immodule-amharic~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese-debuginfo", rpm:"gtk3-immodule-vietnamese-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0", rpm:"libgtk-3-0~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai-debuginfo", rpm:"gtk3-immodule-thai-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut-debuginfo", rpm:"gtk3-immodule-inuktitut-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese", rpm:"gtk3-immodule-vietnamese~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-debuginfo", rpm:"gtk3-devel-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-broadway", rpm:"gtk3-immodule-broadway~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim", rpm:"gtk3-immodule-xim~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-debugsource", rpm:"gtk3-debugsource~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools", rpm:"gtk3-tools~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress-debuginfo", rpm:"gtk3-immodule-multipress-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel", rpm:"gtk3-devel~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-broadway-debuginfo", rpm:"gtk3-immodule-broadway-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress", rpm:"gtk3-immodule-multipress~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna", rpm:"gtk3-immodule-tigrigna~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut", rpm:"gtk3-immodule-inuktitut~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna-debuginfo", rpm:"gtk3-immodule-tigrigna-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-debuginfo", rpm:"libgtk-3-0-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese-32bit-debuginfo", rpm:"gtk3-immodule-vietnamese-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai-32bit", rpm:"gtk3-immodule-thai-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress-32bit", rpm:"gtk3-immodule-multipress-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-32bit", rpm:"gtk3-devel-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress-32bit-debuginfo", rpm:"gtk3-immodule-multipress-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-32bit-debuginfo", rpm:"libgtk-3-0-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-32bit-debuginfo", rpm:"gtk3-devel-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic-32bit-debuginfo", rpm:"gtk3-immodule-amharic-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim-32bit", rpm:"gtk3-immodule-xim-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim-32bit-debuginfo", rpm:"gtk3-immodule-xim-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-32bit-debuginfo", rpm:"gtk3-tools-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-32bit", rpm:"libgtk-3-0-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-32bit", rpm:"gtk3-tools-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic-32bit", rpm:"gtk3-immodule-amharic-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna-32bit", rpm:"gtk3-immodule-tigrigna-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai-32bit-debuginfo", rpm:"gtk3-immodule-thai-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut-32bit", rpm:"gtk3-immodule-inuktitut-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna-32bit-debuginfo", rpm:"gtk3-immodule-tigrigna-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese-32bit", rpm:"gtk3-immodule-vietnamese-32bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut-32bit-debuginfo", rpm:"gtk3-immodule-inuktitut-32bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai-64bit", rpm:"gtk3-immodule-thai-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese-64bit", rpm:"gtk3-immodule-vietnamese-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic-64bit", rpm:"gtk3-immodule-amharic-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-64bit", rpm:"gtk3-devel-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-64bit-debuginfo", rpm:"gtk3-tools-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-thai-64bit-debuginfo", rpm:"gtk3-immodule-thai-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut-64bit", rpm:"gtk3-immodule-inuktitut-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress-64bit-debuginfo", rpm:"gtk3-immodule-multipress-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna-64bit-debuginfo", rpm:"gtk3-immodule-tigrigna-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-multipress-64bit", rpm:"gtk3-immodule-multipress-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-64bit", rpm:"libgtk-3-0-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-inuktitut-64bit-debuginfo", rpm:"gtk3-immodule-inuktitut-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-tools-64bit", rpm:"gtk3-tools-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-3-0-64bit-debuginfo", rpm:"libgtk-3-0-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-vietnamese-64bit-debuginfo", rpm:"gtk3-immodule-vietnamese-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim-64bit", rpm:"gtk3-immodule-xim-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-xim-64bit-debuginfo", rpm:"gtk3-immodule-xim-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-amharic-64bit-debuginfo", rpm:"gtk3-immodule-amharic-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-immodule-tigrigna-64bit", rpm:"gtk3-immodule-tigrigna-64bit~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk3-devel-64bit-debuginfo", rpm:"gtk3-devel-64bit-debuginfo~3.24.38+111~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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
