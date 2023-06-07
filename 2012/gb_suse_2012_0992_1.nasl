# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850311");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:16 +0530 (Thu, 13 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0992-1");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2012:0992-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");

  script_tag(name:"affected", value:"opera on openSUSE 12.1, openSUSE 11.4");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"Opera was updated to version 12.1, fixing various bugs and
  security issues.

  Fixes and Stability Enhancements since Opera 12.00 General
  and User Interface

  Several general fixes and stability improvements
  Website thumbnail memory usage improvements Address bar
  inline auto-completion no longer prefers shortest domain
  Corrected an error that could occur after removing the
  plugin wrapper Resolved an issue where favicons were
  squeezed too much when many tabs were open

  Display and Scripting

  Resolved an error with XHR transfers where content-type
  was incorrectly determined Improved handling of object
  literals with numeric duplicate properties Changed behavior
  of nested/chained comma expressions: now expressing and
  compiling them as a list rather than a tree Aligned
  behavior of the #caller property on function code objects
  in ECMAScript 5 strict mode with the specification Fixed an
  issue where input type=month would return an incorrect
  value in its valueAsDate property Resolved an issue with
  JSON.stringify() that could occur on cached number
  conversion Fixed a problem with redefining special
  properties using Object.defineProperty()

  Network and Site-Specific

  Fixed an issue where loading would stop at 'Document
  100%' but the page would still be loading tuenti.com:
  Corrected behavior when long content was displayed
  Fixed an issue with secure transaction errors Fixed an issue
  with Google Maps Labs that occurred when compiling top-level loops inside strict evals
  Corrected a problem that could occur with DISQUS Fixed a
  crash occurring on Lenovo's 'Shop now' page Corrected
  issues when calling window.console.log via a variable at
  watch4you Resolved an issue with Yahoo! chat

  Mail, News, Chat

  Resolved an issue where under certain conditions the
  mail panel would continuously scroll up Fixed a crash
  occurring when loading mail databases on startup

  Security

  Re-fixed an issue where certain URL constructs could
  allow arbitrary code execution, as reported by Andrey
  Stroganov. See our advisory Fixed an issue where certain
  characters in HTML could incorrectly be ignored, which
  could facilitate XSS attacks. See our advisory Fixed
  another issue where small windows could be used to trick
  users into executing downloads as reported by Jordi Chancel.

  Description truncated, please see the referenced URL(s) for more information.");

  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1201/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~12.01~25.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-gtk", rpm:"opera-gtk~12.01~25.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-kde4", rpm:"opera-kde4~12.01~25.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~12.01~19.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-gtk", rpm:"opera-gtk~12.01~19.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-kde4", rpm:"opera-kde4~12.01~19.1", rls:"openSUSE12.1"))) {
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
