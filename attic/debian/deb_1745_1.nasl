# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.63677");
  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1745-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1745-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1745");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lcms' package(s) announced via the DSA-1745-1 advisory. [This VT has been merged into the VT 'deb_1745.nasl' (OID: 1.3.6.1.4.1.25623.1.0.63677).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in lcms, a color management library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0581

Chris Evans discovered that lcms is affected by a memory leak, which could result in a denial of service via specially crafted image files.

CVE-2009-0723

Chris Evans discovered that lcms is prone to several integer overflows via specially crafted image files, which could lead to the execution of arbitrary code.

CVE-2009-0733

Chris Evans discovered the lack of upper-bounds check on sizes leading to a buffer overflow, which could be used to execute arbitrary code.

For the stable distribution (lenny), these problems have been fixed in version 1.17.dfsg-1+lenny1.

For the oldstable distribution (etch), these problems have been fixed in version 1.15-1.1+etch2.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your lcms packages.");

  script_tag(name:"affected", value:"'lcms' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);