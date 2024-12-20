# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69366");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1002", "CVE-2010-2244");
  script_name("avahi -- denial of service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  avahi, avahi-app, avahi-autoipd, avahi-gtk, avahi-libdns,
  avahi-qt3, avahi-qt4, avahi-sharp

CVE-2011-1002
avahi-core/socket.c in avahi-daemon in Avahi before 0.6.29 allows
remote attackers to cause a denial of service (infinite loop) via an
empty (1) IPv4 or (2) IPv6 UDP packet to port 5353.  NOTE: this
vulnerability exists because of an incorrect fix for CVE-2010-2244.

CVE-2010-2244
The AvahiDnsPacket function in avahi-core/socket.c in avahi-daemon in
Avahi 0.6.16 and 0.6.25 allows remote attackers to cause a denial of
service (assertion failure and daemon exit) via a DNS packet with an
invalid checksum followed by a DNS packet with a valid checksum, a
different vulnerability than CVE-2008-5081.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43361/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=667187");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8b986a05-4dbe-11e0-8b9a-02e0184b8d35.html");

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

bver = portver(pkg:"avahi");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-app");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-app version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-autoipd");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-autoipd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-libdns");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-libdns version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-qt3");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-qt3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-qt4");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-qt4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"avahi-sharp");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
  txt += 'Package avahi-sharp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}