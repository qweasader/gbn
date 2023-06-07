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
  script_oid("1.3.6.1.4.1.25623.1.0.90025");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 22:29:05 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-0166");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Ubuntu: Security Advisories for openssl (USN-612-1 - USN-612-11)");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-2");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-3");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-4");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-5");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-6");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-7");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-8");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-9");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-10");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-11");

  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities
  described in USN-612-1, USN-612-2, USN-612-3, USN-612-4: OpenSSL vulnerability.

  This VT has been deprecated by dedicated LSCs covering each USN separately.");

  script_tag(name:"insight", value:"Luciano Bello discovered that the random number generator in
  Debian's openssl package is predictable. This is caused by an incorrect Debian-specific change to
  the openssl package (CVE-2008-0166). As a result, cryptographic key material may be guessable.

  This is a Debian-specific vulnerability which does not affect other operating systems which are
  not based on Debian.  However, other systems can be indirectly affected if weak keys are imported
  into them.

  It is strongly recommended that all cryptographic key material which has been generated by OpenSSL
  versions starting with 0.9.8c-1 on Debian systems is recreated from scratch. Furthermore, all DSA
  keys ever used on affected Debian systems for signing or authentication purposes should be
  considered compromised. The Digital Signature Algorithm relies on a secret random value used
  during signature generation.

  The first vulnerable version, 0.9.8c-1, was uploaded to the unstable distribution on 2006-09-17,
  and has since propagated to the testing and current stable (etch) distributions.  The old stable
  distribution (sarge) is not affected.

  Affected keys include SSH keys, OpenVPN keys, DNSSEC keys, and key material for use in X.509
  certificates and session keys used in SSL/TLS connections. Keys generated with GnuPG or GNUTLS are
  not affected, though.");

  script_tag(name:"solution", value:"The problem can be corrected by upgrading your system to the
  actual packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  # nb: LSCs covering each USN separately are available.
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);