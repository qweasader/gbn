# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1225-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.57688");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-4310", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5748");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1225-1 (mozilla-firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge13.

For the unstable distribution (sid) these problems have been fixed in
the current iceweasel package 2.0+dfsg-1.

  We recommend that you upgrade your mozilla-firefox package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201225-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19678");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20957");
  script_tag(name:"summary", value:"The remote host is missing an update to mozilla-firefox announced via advisory DSA 1225-1.  Several security related problems have been discovered in Mozilla and derived products such as Mozilla Firefox.  The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:  CVE-2006-4310  Tomas Kempinsky discovered that malformed FTP server responses could lead to denial of service.  CVE-2006-5462  Ulrich Kuhn discovered that the correction for a cryptographic flaw in the handling of PKCS-1 certificates was incomplete, which allows the forgery of certificates.  CVE-2006-5463  shutdown discovered that modification of JavaScript objects during execution could lead to the execution of arbitrary JavaScript bytecode.  CVE-2006-5464  Jesse Ruderman and Martijn Wargers discovered several crashes in the layout engine, which might also allow execution of arbitrary code.  CVE-2006-5748  Igor Bukanov and Jesse Ruderman discovered several crashes in the JavaScript engine, which might allow execution of arbitrary code.  This update also addresses several crashes, which could be triggered by malicious websites and fixes a regression introduced in the previous Mozilla update.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1225)' (OID: 1.3.6.1.4.1.25623.1.0.57689).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);