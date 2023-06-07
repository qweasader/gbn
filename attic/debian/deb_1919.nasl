# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.67847");
  script_cve_id("CVE-2008-4810", "CVE-2009-1669");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1919)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1919");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1919");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'smarty' package(s) announced via the DSA-1919 advisory.

  This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-1919-1)' (OID: 1.3.6.1.4.1.25623.1.0.66103).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Smarty, a PHP templating engine. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4810

The _expand_quoted_text function allows for certain restrictions in templates, like function calling and PHP execution, to be bypassed.

CVE-2009-1669

The smarty_function_math function allows context-dependent attackers to execute arbitrary commands via shell metacharacters in the equation attribute of the math function.

For the old stable distribution (etch), these problems have been fixed in version 2.6.14-1etch2.

For the stable distribution (lenny), these problems have been fixed in version 2.6.20-1.2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your smarty package.");

  script_tag(name:"affected", value:"'smarty' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
