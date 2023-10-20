# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52440");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0623");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: gnats");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gnats");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5CP0N0UAAA.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8006");
  script_xref(name:"URL", value:"http://secunia.com/advisories/9096");
  script_xref(name:"URL", value:"http://x82.inetcop.org/h0me/adv1sor1es/INCSA.2003-0x82-018-GNATS-bt.txt");
  script_xref(name:"URL", value:"http://www.gnu.org/software/gnats/gnats.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/326337");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4d837296-cc28-11d8-a54c-02e0185c0b53.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"gnats");
if(!isnull(bver) && revcomp(a:bver, b:"3.113.1_9")<=0) {
  txt += 'Package gnats version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}