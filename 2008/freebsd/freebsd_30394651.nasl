# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60881");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1530");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: gnupg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gnupg

CVE-2008-1530
GnuPG (gpg) 1.4.8 and 2.0.8 allows remote attackers to cause a denial
of service (crash) and possibly execute arbitrary code via crafted
duplicate keys that are imported from keyservers, which triggers
'memory corruption around deduplication of user IDs.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28487");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29568");
  script_xref(name:"URL", value:"https://bugs.g10code.com/gnupg/issue894");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/30394651-13e1-11dd-bab7-0016179b2dd5.html");

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

bver = portver(pkg:"gnupg");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.0")>=0 && revcomp(a:bver, b:"1.4.9")<0) {
  txt += 'Package gnupg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0")>=0 && revcomp(a:bver, b:"2.0.9")<0) {
  txt += 'Package gnupg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}