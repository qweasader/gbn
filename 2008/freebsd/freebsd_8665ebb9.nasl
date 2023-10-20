# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55275");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2871");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox, linux-firefox, mozilla, linux-mozilla, linux-mozilla-devel, netscape7,
  de-linux-mozillafirebird, el-linux-mozillafirebird, ja-linux-mozillafirebird-gtk1,
  ja-mozillafirebird-gtk2, linux-mozillafirebird, ru-linux-mozillafirebird,
  zhCN-linux-mozillafirebird, zhTW-linux-mozillafirebird, de-linux-netscape,
  de-netscape7, fr-linux-netscape, fr-netscape7, ja-linux-netscape, ja-netscape7,
  linux-netscape, linux-phoenix, mozilla+ipv6, mozilla-embedded, mozilla-firebird,
  mozilla-gtk1, mozilla-gtk2, mozilla-gtk, mozilla-thunderbird, phoenix, pt_BR-netscape7");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=full-disclosure&m=112624614008387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14784");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/idn.html");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=307259");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8665ebb9-2237-11da-978e-0001020eed82.html");

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

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.6_5,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.11_1,2")<0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,2")>=0 && revcomp(a:bver, b:"1.8.b1_5,2")<0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package de-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"el-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package el-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-linux-mozillafirebird-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ja-linux-mozillafirebird-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-mozillafirebird-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ja-mozillafirebird-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ru-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zhCN-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package zhCN-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zhTW-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package zhTW-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package de-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package de-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fr-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package fr-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fr-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package fr-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ja-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ja-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-phoenix");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux-phoenix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-embedded");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-embedded version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-firebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-firebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mozilla-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"phoenix");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package phoenix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pt_BR-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package pt_BR-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}