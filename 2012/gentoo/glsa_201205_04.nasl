###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71390");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106", "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3109", "CVE-2011-3111", "CVE-2011-3115");
  script_version("2022-01-20T08:23:36+0000");
  script_tag(name:"last_modification", value:"2022-01-20 08:23:36 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2012-05-31 11:54:21 -0400 (Thu, 31 May 2012)");
  script_name("Gentoo Security Advisory GLSA 201205-04 (chromium v8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Chromium and V8,
    some of which may allow execution of arbitrary code.");
  script_tag(name:"solution", value:"All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-19.0.1084.52'


All V8 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.9.24.28'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201205-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=417321");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/05/stable-channel-update_23.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201205-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 19.0.1084.52"), vulnerable: make_list("lt 19.0.1084.52"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-lang/v8", unaffected: make_list("ge 3.9.24.28"), vulnerable: make_list("lt 3.9.24.28"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
