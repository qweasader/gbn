# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851737");
  script_version("2021-06-29T02:00:29+0000");
  script_tag(name:"last_modification", value:"2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-27 05:24:59 +0200 (Fri, 27 Apr 2018)");
  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714",
                "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-1071", "CVE-2018-1083",
                "CVE-2018-7549");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-11 19:27:00 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for zsh (openSUSE-SU-2018:1093-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zsh fixes the following issues:

  - CVE-2014-10070: environment variable injection could lead to local
  privilege escalation (bnc#1082885)

  - CVE-2014-10071: buffer overflow in exec.c could lead to denial of
  service. (bnc#1082977)

  - CVE-2014-10072: buffer overflow In utils.c when scanning very long
  directory paths for symbolic links. (bnc#1082975)

  - CVE-2016-10714: In zsh before 5.3, an off-by-one error resulted in
  undersized buffers that were intended to support PATH_MAX characters.
  (bnc#1083250)

  - CVE-2017-18205: In builtin.c when sh compatibility mode is used, a NULL
  pointer dereference could lead to denial of service (bnc#1082998)

  - CVE-2018-1071: exec.c:hashcmd() function vulnerability could lead to
  denial of service. (bnc#1084656)

  - CVE-2018-1083: Autocomplete vulnerability could lead to privilege
  escalation. (bnc#1087026)

  - CVE-2018-7549: In params.c in zsh through 5.4.2, there is a crash during
  a copy of an empty hash table, as demonstrated by typeset -p.
  (bnc#1082991)

  - CVE-2017-18206: buffer overrun in xsymlinks could lead to denial of
  service (bnc#1083002)

  - Autocomplete and REPORTTIME broken (bsc#896914)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-399=1");

  script_tag(name:"affected", value:"zsh on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1093-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-04/msg00073.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.0.5~9.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-debuginfo", rpm:"zsh-debuginfo~5.0.5~9.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-debugsource", rpm:"zsh-debugsource~5.0.5~9.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-htmldoc", rpm:"zsh-htmldoc~5.0.5~9.3.1", rls:"openSUSELeap42.3"))) {
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
