# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0041", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-0068");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wireshark
   wireshark-lite
   tshark
   tshark-lite");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-01.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-02.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-03.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6663");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6666");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6667");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6668");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6669");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6670");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6634");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6391");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3ebb2dc8-4609-11e1-9f47-00e0815b8da8.html");

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

bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.11")<0) {
  txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.6.0")>=0 && revcomp(a:bver, b:"1.6.5")<0) {
  txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.11")<0) {
  txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.6.0")>=0 && revcomp(a:bver, b:"1.6.5")<0) {
  txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.11")<0) {
  txt += 'Package tshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.6.0")>=0 && revcomp(a:bver, b:"1.6.5")<0) {
  txt += 'Package tshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.11")<0) {
  txt += 'Package tshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.6.0")>=0 && revcomp(a:bver, b:"1.6.5")<0) {
  txt += 'Package tshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}