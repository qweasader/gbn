# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52253");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1284");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: mpg123, mpg123-nas, mpg123-esound");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mpg123, mpg123-nas, mpg123-esound

CVE-2004-1284
Buffer overflow in the find_next_file function in playlist.c for
mpg123 0.59r allows remote attackers to execute arbitrary code via a
crafted MP3 playlist.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/mpg123.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11958");
  script_xref(name:"URL", value:"http://secunia.com/advisories/13511/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/18626");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110321888413132");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/877e918e-5362-11d9-96d4-00065be4b5b6.html");

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

bver = portver(pkg:"mpg123");
if(!isnull(bver) && revcomp(a:bver, b:"0.59r_15")<=0) {
  txt += 'Package mpg123 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mpg123-nas");
if(!isnull(bver) && revcomp(a:bver, b:"0.59r_15")<=0) {
  txt += 'Package mpg123-nas version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mpg123-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.59r_15")<=0) {
  txt += 'Package mpg123-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}