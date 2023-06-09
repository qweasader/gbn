# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.55796");
  script_cve_id("CVE-2005-2969");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-882)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-882");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-882");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-882");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl095' package(s) announced via the DSA-882 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yutaka Oiwa discovered a vulnerability in the Open Secure Socket Layer (OpenSSL) library that can allow an attacker to perform active protocol-version rollback attacks that could lead to the use of the weaker SSL 2.0 protocol even though both ends support SSL 3.0 or TLS 1.0.

The following matrix explains which version in which distribution has this problem corrected.



oldstable (woody)

stable (sarge)

unstable (sid)

openssl

0.9.6c-2.woody.8

0.9.7e-3sarge1

0.9.8-3

openssl094

0.9.4-6.woody.4

n/a

n/a

openssl095

0.9.5a-6.woody.6

n/a

n/a

openssl096

n/a

0.9.6m-1sarge1

n/a

openssl097

n/a

n/a

0.9.7g-5

We recommend that you upgrade your libssl packages.");

  script_tag(name:"affected", value:"'openssl095' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl095a", ver:"0.9.5a-6.woody.6", rls:"DEB3.0"))) {
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
