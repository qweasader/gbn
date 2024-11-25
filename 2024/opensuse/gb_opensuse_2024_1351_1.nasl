# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856088");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-46045");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 04:06:57 +0000 (Sat, 10 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-23 01:00:20 +0000 (Tue, 23 Apr 2024)");
  script_name("openSUSE: Security Advisory for graphviz (SUSE-SU-2024:1351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UDSXMXWCIIUJIXJL4MVW5CLRX25ISWKW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz'
  package(s) announced via the SUSE-SU-2024:1351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for graphviz fixes the following issues:

  * CVE-2023-46045: Fixed out-of-bounds read via a crafted config6a file
      (bsc#1219491)

  ##");

  script_tag(name:"affected", value:"'graphviz' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"python3-gv", rpm:"python3-gv~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd-debuginfo", rpm:"graphviz-gd-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php-debuginfo", rpm:"graphviz-php-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua-debuginfo", rpm:"graphviz-lua-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp-debuginfo", rpm:"graphviz-webp-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile-debuginfo", rpm:"graphviz-guile-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp", rpm:"graphviz-webp~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java-debuginfo", rpm:"graphviz-java-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit", rpm:"graphviz-gvedit~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11", rpm:"graphviz-x11~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna", rpm:"graphviz-smyrna~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit-debuginfo", rpm:"graphviz-gvedit-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv-debuginfo", rpm:"python3-gv-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11-debuginfo", rpm:"graphviz-x11-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna-debuginfo", rpm:"graphviz-smyrna-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby-debuginfo", rpm:"graphviz-ruby-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv", rpm:"python3-gv~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd-debuginfo", rpm:"graphviz-gd-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php-debuginfo", rpm:"graphviz-php-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua-debuginfo", rpm:"graphviz-lua-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp-debuginfo", rpm:"graphviz-webp-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile-debuginfo", rpm:"graphviz-guile-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp", rpm:"graphviz-webp~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java-debuginfo", rpm:"graphviz-java-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit", rpm:"graphviz-gvedit~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11", rpm:"graphviz-x11~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna", rpm:"graphviz-smyrna~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit-debuginfo", rpm:"graphviz-gvedit-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv-debuginfo", rpm:"python3-gv-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11-debuginfo", rpm:"graphviz-x11-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna-debuginfo", rpm:"graphviz-smyrna-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby-debuginfo", rpm:"graphviz-ruby-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python3-gv", rpm:"python3-gv~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd-debuginfo", rpm:"graphviz-gd-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php-debuginfo", rpm:"graphviz-php-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua-debuginfo", rpm:"graphviz-lua-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp-debuginfo", rpm:"graphviz-webp-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile-debuginfo", rpm:"graphviz-guile-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp", rpm:"graphviz-webp~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java-debuginfo", rpm:"graphviz-java-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit", rpm:"graphviz-gvedit~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11", rpm:"graphviz-x11~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna", rpm:"graphviz-smyrna~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit-debuginfo", rpm:"graphviz-gvedit-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv-debuginfo", rpm:"python3-gv-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11-debuginfo", rpm:"graphviz-x11-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna-debuginfo", rpm:"graphviz-smyrna-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby-debuginfo", rpm:"graphviz-ruby-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv", rpm:"python3-gv~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd-debuginfo", rpm:"graphviz-gd-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php-debuginfo", rpm:"graphviz-php-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua-debuginfo", rpm:"graphviz-lua-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp-debuginfo", rpm:"graphviz-webp-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile-debuginfo", rpm:"graphviz-guile-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-webp", rpm:"graphviz-webp~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java-debuginfo", rpm:"graphviz-java-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit", rpm:"graphviz-gvedit~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11", rpm:"graphviz-x11~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna", rpm:"graphviz-smyrna~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit-debuginfo", rpm:"graphviz-gvedit-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gv-debuginfo", rpm:"python3-gv-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-x11-debuginfo", rpm:"graphviz-x11-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna-debuginfo", rpm:"graphviz-smyrna-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby-debuginfo", rpm:"graphviz-ruby-debuginfo~2.48.0~150400.3.3.1", rls:"openSUSELeap15.5"))) {
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