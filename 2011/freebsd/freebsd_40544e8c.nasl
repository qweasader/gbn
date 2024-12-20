# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69996");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-2529", "CVE-2011-2535", "CVE-2011-2536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: asterisk14");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  asterisk14
   asterisk16
   asterisk18

CVE-2011-2529
chan_sip.c in the SIP channel driver in Asterisk Open Source 1.6.x
before 1.6.2.18.1 and 1.8.x before 1.8.4.3 does not properly handle
'\0' characters in SIP packets, which allows remote attackers to cause
a denial of service (memory corruption) or possibly have unspecified
other impact via a crafted packet.

CVE-2011-2535
chan_iax2.c in the IAX2 channel driver in Asterisk Open Source 1.4.x
before 1.4.41.1, 1.6.2.x before 1.6.2.18.1, and 1.8.x before 1.8.4.3,
and Asterisk Business Edition C.3 before C.3.7.3, accesses a memory
address contained in an option control frame, which allows remote
attackers to cause a denial of service (daemon crash) or possibly have
unspecified other impact via a crafted frame.

CVE-2011-2536
chan_sip.c in the SIP channel driver in Asterisk Open Source 1.4.x
before 1.4.41.2, 1.6.2.x before 1.6.2.18.2, and 1.8.x before 1.8.4.4,
and Asterisk Business Edition C.3.x before C.3.7.3, disregards the
alwaysauthreject option and generates different responses for invalid
SIP requests depending on whether the user account exists, which
allows remote attackers to enumerate account names via a series of
requests.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-008.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-009.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-010.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-011.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/40544e8c-9f7b-11e0-9bec-6c626dd55a41.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"asterisk14");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>0 && revcomp(a:bver, b:"1.4.41.2")<0) {
  txt += 'Package asterisk14 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"asterisk16");
if(!isnull(bver) && revcomp(a:bver, b:"1.6")>0 && revcomp(a:bver, b:"1.6.2.18.2")<0) {
  txt += 'Package asterisk16 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8")>0 && revcomp(a:bver, b:"1.8.4.4")<0) {
  txt += 'Package asterisk18 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}