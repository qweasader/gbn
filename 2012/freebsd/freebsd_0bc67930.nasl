# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71519");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2012-3817");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: bind99");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  bind99

  bind98

  bind97

  bind96

CVE-2012-3817
ISC BIND 9.4.x, 9.5.x, 9.6.x, and 9.7.x before 9.7.6-P2, 9.8.x before
9.8.3-P2, 9.9.x before 9.9.1-P2, and 9.6-ESV before 9.6-ESV-R7-P2,
when DNSSEC validation is enabled, does not properly initialize the
failing-query cache, which allows remote attackers to cause a denial
of service (assertion failure and daemon exit) by sending many
queries.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-00729");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0bc67930-d5c3-11e1-bef6-0024e81297ae.html");

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

bver = portver(pkg:"bind99");
if(!isnull(bver) && revcomp(a:bver, b:"9.9.1.2")<0) {
  txt += "Package bind99 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"bind98");
if(!isnull(bver) && revcomp(a:bver, b:"9.8.3.2")<0) {
  txt += "Package bind98 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"bind97");
if(!isnull(bver) && revcomp(a:bver, b:"9.7.6.2")<0) {
  txt += "Package bind97 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"bind96");
if(!isnull(bver) && revcomp(a:bver, b:"9.6.3.1.ESV.R7.2")<0) {
  txt += "Package bind96 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}