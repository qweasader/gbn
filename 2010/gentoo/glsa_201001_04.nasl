###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2010 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.66737");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-01-20 20:07:43 +0100 (Wed, 20 Jan 2010)");
  script_cve_id("CVE-2009-3692", "CVE-2009-3940");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 201001-04 (virtualbox-bin virtualbox-ose virtualbox-guest-additions virtualbox-ose-additions)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in VirtualBox were found, the worst of which
    allowing for privilege escalation.");
  script_tag(name:"solution", value:"All users of the binary version of VirtualBox should upgrade to the
    latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-bin-3.0.12'

All users of the Open Source version of VirtualBox should upgrade to
    the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-ose-3.0.12'

All users of the binary VirtualBox Guest Additions should upgrade to
    the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-guest-additions-3.0.12'

All users of the Open Source VirtualBox Guest Additions should upgrade
    to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-ose-additions-3.0.12'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201001-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=288836");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=294678");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201001-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-emulation/virtualbox-bin", unaffected: make_list("ge 3.0.12"), vulnerable: make_list("lt 3.0.12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/virtualbox-ose", unaffected: make_list("ge 3.0.12"), vulnerable: make_list("lt 3.0.12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/virtualbox-guest-additions", unaffected: make_list("ge 3.0.12"), vulnerable: make_list("lt 3.0.12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/virtualbox-ose-additions", unaffected: make_list("ge 3.0.12"), vulnerable: make_list("lt 3.0.12"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}