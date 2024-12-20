# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70754");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-4838", "CVE-2011-4815", "CVE-2011-5036", "CVE-2011-5037");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: jruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  jruby
   ruby
   ruby+nopthreads
   ruby+nopthreads+oniguruma
   ruby+oniguruma
   rubygem-rack
   v8
   redis
   node

CVE-2011-4838
JRuby before 1.6.5.1 computes hash values without restricting the
ability to trigger hash collisions predictably, which allows
context-dependent attackers to cause a denial of service (CPU
consumption) via crafted input to an application that maintains a hash
table.

CVE-2011-4815
Ruby (aka CRuby) before 1.8.7-p357 computes hash values without
restricting the ability to trigger hash collisions predictably, which
allows context-dependent attackers to cause a denial of service (CPU
consumption) via crafted input to an application that maintains a hash
table.

CVE-2011-5036
Rack before 1.1.3, 1.2.x before 1.2.5, and 1.3.x before 1.3.6 computes
hash values for form parameters without restricting the ability to
trigger hash collisions predictably, which allows remote attackers to
cause a denial of service (CPU consumption) by sending many crafted
parameters.

CVE-2011-5037
Google V8 computes hash values for form parameters without restricting
the ability to trigger hash collisions predictably, which allows
remote attackers to cause a denial of service (CPU consumption) by
sending many crafted parameters, as demonstrated by attacks against
Node.js.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/91be81e7-3fea-11e1-afc7-2c4138874f7d.html");

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

bver = portver(pkg:"jruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.5.1")<0) {
  txt += 'Package jruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
  txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+nopthreads");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
  txt += 'Package ruby+nopthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+nopthreads+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
  txt += 'Package ruby+nopthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
  txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"rubygem-rack");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.6,3")<0) {
  txt += 'Package rubygem-rack version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"v8");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.5")<0) {
  txt += 'Package v8 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"redis");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.6")<=0) {
  txt += 'Package redis version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"node");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.7")<0) {
  txt += 'Package node version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}