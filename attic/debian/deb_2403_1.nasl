# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2403-1 (php5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70721");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-0830");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 06:39:47 -0500 (Sun, 12 Feb 2012)");
  script_name("Debian Security Advisory DSA 2403-1 (php5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202403-1");
  script_tag(name:"insight", value:"Stefan Esser discovered that the implementation of the max_input_vars
configuration variable in a recent PHP security update was flawed such
that it allows remote attackers to crash PHP or potentially execute
code.

For the oldstable distribution (lenny), no fix is available at this time.

For the stable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze7.

The testing distribution (wheezy) and unstable distribution (sid)
will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your php5 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to php5 announced via advisory DSA 2403-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-2403)' (OID: 1.3.6.1.4.1.25623.1.0.70725).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);