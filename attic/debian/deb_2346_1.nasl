# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2346-1 (proftpd-dfsg)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70559");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2011-4130", "CVE-2011-0411");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-02-11 02:29:49 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2346-1 (proftpd-dfsg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202346-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in ProFTPD, an FTP server:

ProFTPD incorrectly uses data from an unencrypted input buffer
after encryption has been enabled with STARTTLS, an issue
similar to CVE-2011-0411.

CVE-2011-4130
ProFTPD uses a response pool after freeing it under
exceptional conditions, possibly leading to remote code
execution.  (The version in lenny is not affected by this
problem.)

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny8.

For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze4.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1.3.4~rc3-2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your proftpd-dfsg packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd-dfsg announced via advisory DSA 2346-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-2346)' (OID: 1.3.6.1.4.1.25623.1.0.70560).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);