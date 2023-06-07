# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1493-1 (sdl-image1.2)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.60368");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
  script_cve_id("CVE-2007-6697", "CVE-2008-0554", "CVE-2008-0544");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1493-1 (sdl-image1.2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201493-1");
  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in the image
loading library for the Simple DirectMedia Layer 1.2. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6697

Gynvael Coldwind discovered a buffer overflow in GIF image parsing,
which could result in denial of service and potentially the
execution of arbitrary code.

CVE-2008-0544

It was discovered that a buffer overflow in IFF ILBM image parsing
could result in denial of service and potentially the execution of
arbitrary code.

For the stable distribution (etch), these problems have been fixed in
version 1.2.5-2etch1.

For the old stable distribution (sarge), these problems have been fixed
in version 1.2.4-1etch1. Due to a copy & paste error etch1 was appended
to the version number instead of sarge1. Since the update is otherwise
technically correct, the update was not rebuild to the buildd network.");

  script_tag(name:"solution", value:"We recommend that you upgrade your sdl-image1.2 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to sdl-image1.2 announced via advisory DSA 1493-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1493)' (OID: 1.3.6.1.4.1.25623.1.0.60574).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);