# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 957-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.56210");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-4601");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 957-1 (imagemagick)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 6.0.6.2-2.5.

For the unstable distribution (sid) this problem has been fixed in
version 6.2.4.5-0.6.

  We recommend that you upgrade your imagemagick packages.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20957-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16093");
  script_tag(name:"summary", value:"The remote host is missing an update to imagemagick announced via advisory DSA 957-1.  Florian Weimer discovered that delegate code in ImageMagick is vulnerable to shell command injection using specially crafted file names.  This allows attackers to encode commands inside of graphic commands.  With some user interaction, this is exploitable through Gnus and Thunderbird.  For the old stable distribution (woody) this problem has been fixed in version 5.4.4.5-1woody7.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-957)' (OID: 1.3.6.1.4.1.25623.1.0.56217).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);