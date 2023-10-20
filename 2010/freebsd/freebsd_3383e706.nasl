# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67355");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-1157");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: tomcat

CVE-2010-1157
Apache Tomcat 5.5.0 through 5.5.29 and 6.0.0 through 6.0.26 might
allow remote attackers to discover the server's hostname or IP address
by sending a request for a resource that requires (1) BASIC or (2)
DIGEST authentication, and then reading the realm field in the
WWW-Authenticate header in the reply.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/Apr/200");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3383e706-4fc3-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"5.5.0")>0 && revcomp(a:bver, b:"5.5.28")<=0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.24")<=0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}