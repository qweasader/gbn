# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131233");
  script_cve_id("CVE-2013-7447");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:39 +0000 (Thu, 18 Feb 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:00:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0070");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0070.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17739");
  script_xref(name:"URL", value:"https://github.com/mate-desktop/eom/issues/93");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/gtk+2.0/+bug/1540811");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=799275");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=703220");
  script_xref(name:"URL", value:"https://git.gnome.org/browse/gtk+/commit?id=894b1ae76a32720f4bb3d39cf460402e3ce331d6");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/10/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17731");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eom' package(s) announced via the MGASA-2016-0070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated eom packages fix security vulnerability:

Due to a logic error, an attempt to allocate a large block of memory
fails in gdk_cairo_set_source_pixbuf, leading to a crash of eom (CVE-2013-7447).");

  script_tag(name:"affected", value:"'eom' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"eom", rpm:"eom~1.8.1~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eom-devel", rpm:"eom-devel~1.8.1~2.1.mga5", rls:"MAGEIA5"))) {
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
