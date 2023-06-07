# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853398");
  script_version("2021-08-12T12:00:56+0000");
  script_cve_id("CVE-2018-10196");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 11:15:00 +0000 (Thu, 13 May 2021)");
  script_tag(name:"creation_date", value:"2020-09-02 11:51:20 +0530 (Wed, 02 Sep 2020)");
  script_name("openSUSE: Security Advisory for graphviz (openSUSE-SU-2020:1303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1303-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz'
  package(s) announced via the openSUSE-SU-2020:1303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for graphviz fixes the following issues:

  - CVE-2018-10196: Fixed a null dereference in rebuild_vlis (bsc#1093447).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1303=1");

  script_tag(name:"affected", value:"'graphviz' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gd-debuginfo", rpm:"graphviz-gd-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-guile-debuginfo", rpm:"graphviz-guile-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit", rpm:"graphviz-gvedit~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gvedit-debuginfo", rpm:"graphviz-gvedit-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-java-debuginfo", rpm:"graphviz-java-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-lua-debuginfo", rpm:"graphviz-lua-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-php-debuginfo", rpm:"graphviz-php-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-python", rpm:"graphviz-python~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-python-debuginfo", rpm:"graphviz-python-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-ruby-debuginfo", rpm:"graphviz-ruby-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna", rpm:"graphviz-smyrna~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-smyrna-debuginfo", rpm:"graphviz-smyrna-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.40.1~lp152.7.7.1", rls:"openSUSELeap15.2"))) {
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