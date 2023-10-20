# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71377");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1823", "CVE-2012-2311", "CVE-2012-2329");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  php5
   php53
   php52

CVE-2012-1823
sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when
configured as a CGI script (aka php-cgi), does not properly handle
query strings that lack an = (equals sign) character, which allows
remote attackers to execute arbitrary code by placing command-line
options in the query string, related to lack of skipping a certain
php_getopt for the 'd' case.
CVE-2012-2311
sapi/cgi/cgi_main.c in PHP before 5.3.13 and 5.4.x before 5.4.3, when
configured as a CGI script (aka php-cgi), does not properly handle
query strings that contain a %3D sequence but no = (equals sign)
character, which allows remote attackers to execute arbitrary code by
placing command-line options in the query string, related to lack of
skipping a certain php_getopt for the 'd' case.  NOTE: this
vulnerability exists because of an incomplete fix for CVE-2012-1823.
CVE-2012-2329
Buffer overflow in the apache_request_headers function in
sapi/cgi/cgi_main.c in PHP 5.4.x before 5.4.3 allows remote attackers
to cause a denial of service (application crash) via a long string in
the header of an HTTP request.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.4")>0 && revcomp(a:bver, b:"5.4.3")<0) {
  txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.3.13")<0) {
  txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"php53");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.13")<0) {
  txt += "Package php53 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"php52");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.17_9")<0) {
  txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}