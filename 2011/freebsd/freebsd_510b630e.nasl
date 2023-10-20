# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70263");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-2748", "CVE-2011-2749");
  script_name("FreeBSD Ports: isc-dhcp31-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  isc-dhcp31-server
   isc-dhcp41-server
   isc-dhcp42-server

CVE-2011-2748
The server in ISC DHCP 3.x and 4.x before 4.2.2, 3.1-ESV before
3.1-ESV-R3, and 4.1-ESV before 4.1-ESV-R3 allows remote attackers to
cause a denial of service (daemon exit) via a crafted DHCP packet.

CVE-2011-2749
The server in ISC DHCP 3.x and 4.x before 4.2.2, 3.1-ESV before
3.1-ESV-R3, and 4.1-ESV before 4.1-ESV-R3 allows remote attackers to
cause a denial of service (daemon exit) via a crafted BOOTP packet.");

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

bver = portver(pkg:"isc-dhcp31-server");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.ESV_1,1")<0) {
  txt += 'Package isc-dhcp31-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp41-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.e_2,2")<0) {
  txt += 'Package isc-dhcp41-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp42-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.2")<0) {
  txt += 'Package isc-dhcp42-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}