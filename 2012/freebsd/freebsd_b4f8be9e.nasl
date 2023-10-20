# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71172");
  script_cve_id("CVE-2012-0845");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
  script_name("FreeBSD Ports: python32");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  python32
   python31
   python27
   python26
   python25
   python24
   pypy");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugs.python.org/issue14001");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=789790");
  script_xref(name:"URL", value:"https://bugs.pypy.org/issue1047");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b4f8be9e-56b2-11e1-9fb7-003067b2972c.html");

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

bver = portver(pkg:"python32");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.2_2")<=0) {
  txt += "Package python32 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"python31");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.4_2")<=0) {
  txt += "Package python31 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"python27");
if(!isnull(bver) && revcomp(a:bver, b:"2.7.2_3")<=0) {
  txt += "Package python27 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"python26");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.7_2")<=0) {
  txt += "Package python26 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"python25");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.6_2")<=0) {
  txt += "Package python25 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"python24");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5_8")<=0) {
  txt += "Package python24 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"pypy");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")<=0) {
  txt += "Package pypy version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}