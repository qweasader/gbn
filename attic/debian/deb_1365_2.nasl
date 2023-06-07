# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1365-2
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
  script_oid("1.3.6.1.4.1.25623.1.0.58591");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-4460");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1365-2 (id3lib3.8.3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201365-2");
  script_tag(name:"insight", value:"Nikolaus Schulz discovered that a programming error in id3lib, an ID3 Tag
Library, may lead to denial of service through symlink attacks.

This update to DSA 1365-2 provides fixes packages for the stable
distribution (etch).");

  script_tag(name:"solution", value:"We recommend that you upgrade your id3lib3.8.3 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to id3lib3.8.3 announced via advisory DSA 1365-2.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1365)' (OID: 1.3.6.1.4.1.25623.1.0.58638).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);