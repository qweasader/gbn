# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5723.1");
  script_cve_id("CVE-2022-1674", "CVE-2022-1725", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2175", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2304");
  script_tag(name:"creation_date", value:"2022-11-15 04:13:45 +0000 (Tue, 15 Nov 2022)");
  script_version("2022-11-15T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-11-15 10:10:43 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 01:54:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5723-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5723-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-5723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim could be made to crash when searching specially
crafted patterns. An attacker could possibly use this to crash Vim and
cause denial of service. (CVE-2022-1674)

It was discovered that there existed a NULL pointer dereference in Vim. An
attacker could possibly use this to crash Vim and cause denial of service.
(CVE-2022-1725)

It was discovered that there existed a buffer over-read in Vim when
searching specially crafted patterns. An attacker could possibly use this
to crash Vim and cause denial of service. (CVE-2022-2124)

It was discovered that there existed a heap buffer overflow in Vim when
auto-indenting lisp. An attacker could possibly use this to crash Vim and
cause denial of service. (CVE-2022-2125)

It was discovered that there existed an out of bounds read in Vim when
performing spelling suggestions. An attacker could possibly use this to
crash Vim and cause denial of service. (CVE-2022-2126)

It was discovered that Vim accessed invalid memory when executing specially
crafted command line expressions. An attacker could possibly use this to
crash Vim, access or modify memory, or execute arbitrary commands.
(CVE-2022-2175)

It was discovered that there existed an out-of-bounds read in Vim when
auto-indenting lisp. An attacker could possibly use this to crash Vim,
access or modify memory, or execute arbitrary commands. (CVE-2022-2183)


It was discovered that Vim accessed invalid memory when terminal size
changed. An attacker could possibly use this to crash Vim, access or modify
memory, or execute arbitrary commands. (CVE-2022-2206)

It was discovered that there existed a stack buffer overflow in Vim's
spelldump. An attacker could possibly use this to crash Vim and cause
denial of service. (CVE-2022-2304)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena-py2", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gnome-py2", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk-py2", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3-py2", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox-py2", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.1689-3ubuntu1.5+esm13", rls:"UBUNTU16.04 LTS"))) {
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
