# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61955");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
  script_cve_id("CVE-2008-4314");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_name("FreeBSD Ports: samba, samba3, ja-samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  samba
   samba3
   ja-samba
   samba32-devel

CVE-2008-4314
smbd in Samba 3.0.29 through 3.2.4 might allow remote attackers to
read arbitrary memory and cause a denial of service via crafted (1)
trans, (2) trans2, and (3) nttrans requests, related to a 'cut&paste
error' that causes an improper bounds check to be performed.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2008-4314.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32813/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/1583640d-be20-11dd-a578-0030843d3802.html");

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

bver = portver(pkg:"samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
  txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"samba3");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
  txt += 'Package samba3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
  txt += 'Package ja-samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"samba32-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.4_1")<0) {
  txt += 'Package samba32-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}