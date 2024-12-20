# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66104");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:21:52 +0000 (Wed, 14 Feb 2024)");
  script_name("SUSE: Security Advisory for MozillaFirefox (SUSE-SA:2009:048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"The Mozilla Firefox was updated to current stable versions on all
affected Linux products.

openSUSE 10.3, 11.0 and 11.1: Firefox was updated to the current stable
branch version 3.0.14. These updates were already released on
September 21st.

The SUSE Linux Enterprise 11 products were upgraded to Mozilla Firefox
3.5.3, released on September 30th.

The SUSE Linux Enterprise 10 Service Pack 2 and 3 were upgraded to
Mozilla Firefox 3.5.3, released on October 20th.

For details on the issues addresses with these updates, please
visit the referenced security advisories.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:048");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:048.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.14~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.0.14~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.14~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-64bit", rpm:"mozilla-xulrunner190-64bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-64bit", rpm:"mozilla-xulrunner190-gnomevfs-64bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-64bit", rpm:"mozilla-xulrunner190-translations-64bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-64bit", rpm:"mozilla-xulrunner190-64bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-64bit", rpm:"mozilla-xulrunner190-gnomevfs-64bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-64bit", rpm:"mozilla-xulrunner190-translations-64bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.14~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.14~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.14~0.1", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
