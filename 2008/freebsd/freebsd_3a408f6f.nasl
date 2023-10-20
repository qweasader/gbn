# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52428");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0421");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: linux-png");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   linux-png
   png

CVE-2004-0421
The Portable Network Graphics library (libpng) 1.0.15 and earlier
allows attackers to cause a denial of service (crash) via a malformed
PNG image file that triggers an error that causes an out-of-bounds
read when creating the error message.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=120508");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10244");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-181.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11505");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3a408f6f-9c52-11d8-9366-0020ed76ef5a.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"linux-png");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.14_3")<=0) {
  txt += 'Package linux-png version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>=0 && revcomp(a:bver, b:"1.2.2")<=0) {
  txt += 'Package linux-png version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"png");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.5_4")<0) {
  txt += 'Package png version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}