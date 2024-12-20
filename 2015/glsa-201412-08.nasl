# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121294");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:04 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201412-08");
  script_tag(name:"insight", value:"Vulnerabilities have been discovered in the packages listed below. Please review the CVE identifiers in the references for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201412-08");
  script_cve_id("CVE-2006-3005", "CVE-2007-2741", "CVE-2008-0553", "CVE-2008-1382", "CVE-2008-5907", "CVE-2008-6218", "CVE-2008-6661", "CVE-2009-0040", "CVE-2009-0360", "CVE-2009-0361", "CVE-2009-0946", "CVE-2009-2042", "CVE-2009-2624", "CVE-2009-3736", "CVE-2009-4029", "CVE-2009-4411", "CVE-2009-4896", "CVE-2010-0001", "CVE-2010-0436", "CVE-2010-0732", "CVE-2010-0829", "CVE-2010-1000", "CVE-2010-1205", "CVE-2010-1511", "CVE-2010-2056", "CVE-2010-2060", "CVE-2010-2192", "CVE-2010-2251", "CVE-2010-2529", "CVE-2010-2809", "CVE-2010-2945");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:50:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201412-08");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-util/insight", unaffected: make_list("ge 6.7.1-r1"), vulnerable: make_list("lt 6.7.1-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-perl/perl-tk", unaffected: make_list("ge 804.028-r2"), vulnerable: make_list("lt 804.028-r2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-util/sourcenav", unaffected: make_list("ge 5.1.4"), vulnerable: make_list("lt 5.1.4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-lang/tk", unaffected: make_list("ge 8.4.18-r1"), vulnerable: make_list("lt 8.4.18-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-block/partimage", unaffected: make_list("ge 0.6.8"), vulnerable: make_list("lt 0.6.8"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-antivirus/bitdefender-console", unaffected: make_list(), vulnerable: make_list("lt 7.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-mail/mlmmj", unaffected: make_list("ge 1.2.17.1"), vulnerable: make_list("lt 1.2.17.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-apps/acl", unaffected: make_list("ge 2.2.49"), vulnerable: make_list("lt 2.2.49"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"x11-apps/xinit", unaffected: make_list("ge 1.2.0-r4"), vulnerable: make_list("lt 1.2.0-r4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-arch/gzip", unaffected: make_list("ge 1.4"), vulnerable: make_list("lt 1.4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-arch/ncompress", unaffected: make_list("ge 4.2.4.3"), vulnerable: make_list("lt 4.2.4.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-libs/liblzw", unaffected: make_list("ge 0.2"), vulnerable: make_list("lt 0.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-gfx/splashutils", unaffected: make_list("ge 1.5.4.3-r3"), vulnerable: make_list("lt 1.5.4.3-r3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-devel/m4", unaffected: make_list("ge 1.4.14-r1"), vulnerable: make_list("lt 1.4.14-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"kde-base/kdm", unaffected: make_list("ge 4.3.5-r1"), vulnerable: make_list("lt 4.3.5-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"x11-libs/gtk+", unaffected: make_list("ge 2.18.7"), vulnerable: make_list("lt 2.18.7"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"kde-base/kget", unaffected: make_list("ge 4.3.5-r1"), vulnerable: make_list("lt 4.3.5-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-text/dvipng", unaffected: make_list("ge 1.13"), vulnerable: make_list("lt 1.13"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-misc/beanstalkd", unaffected: make_list("ge 1.4.6"), vulnerable: make_list("lt 1.4.6"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-apps/pmount", unaffected: make_list("ge 0.9.23"), vulnerable: make_list("lt 0.9.23"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-auth/pam_krb5", unaffected: make_list("ge 4.3"), vulnerable: make_list("lt 4.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-text/gv", unaffected: make_list("ge 3.7.1"), vulnerable: make_list("lt 3.7.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-ftp/lftp", unaffected: make_list("ge 4.0.6"), vulnerable: make_list("lt 4.0.6"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/uzbl", unaffected: make_list("ge 2010.08.05"), vulnerable: make_list("lt 2010.08.05"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"x11-misc/slim", unaffected: make_list("ge 1.3.2"), vulnerable: make_list("lt 1.3.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-misc/iputils", unaffected: make_list("ge 20100418"), vulnerable: make_list("lt 20100418"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-tv/dvbstreamer", unaffected: make_list("ge 1.1-r1"), vulnerable: make_list("lt 1.1-r1"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
