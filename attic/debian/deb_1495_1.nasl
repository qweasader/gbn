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
  script_oid("1.3.6.1.4.1.25623.1.0.60370");
  script_cve_id("CVE-2007-5198", "CVE-2007-5623");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1495-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1495-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1495");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nagios-plugins' package(s) announced via the DSA-1495-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1495)' (OID: 1.3.6.1.4.1.25623.1.0.60431).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in two of the plugins for the Nagios network monitoring and management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5198

A buffer overflow has been discovered in the parser for HTTP Location headers (present in the check_http module).

CVE-2007-5623

A buffer overflow has been discovered in the check_snmp module.

For the old stable distribution (sarge), these problems have been fixed in version 1.4-6sarge1.

For the stable distribution (etch), these problems have been fixed in version 1.4.5-1etch1.

We recommend that you upgrade your nagios-plugins package.");

  script_tag(name:"affected", value:"'nagios-plugins' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);