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
  script_oid("1.3.6.1.4.1.25623.1.0.64423");
  script_cve_id("CVE-2009-1890", "CVE-2009-1891");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1834-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1834");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2 apache2-mpm-itk' package(s) announced via the DSA-1834-1 advisory. [This VT has been merged into the VT 'deb_1834.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64423).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2009-1890

A denial of service flaw was found in the Apache mod_proxy module when it was used as a reverse proxy. A remote attacker could use this flaw to force a proxy process to consume large amounts of CPU time. This issue did not affect Debian 4.0 'etch'.

CVE-2009-1891

A denial of service flaw was found in the Apache mod_deflate module. This module continued to compress large files until compression was complete, even if the network connection that requested the content was closed before compression completed. This would cause mod_deflate to consume large amounts of CPU if mod_deflate was enabled for a large file. A similar flaw related to HEAD requests for compressed content was also fixed.

The oldstable distribution (etch), these problems have been fixed in version 2.2.3-4+etch9.

For the stable distribution (lenny), these problems have been fixed in version 2.2.9-10+lenny4.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed in version 2.2.11-7.

This advisory also provides updated apache2-mpm-itk packages which have been recompiled against the new apache2 packages.

Updated packages for the s390 and mipsel architectures are not included yet. They will be released as soon as they become available.");

  script_tag(name:"affected", value:"'apache2 apache2-mpm-itk' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);