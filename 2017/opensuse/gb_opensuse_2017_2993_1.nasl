# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851644");
  script_version("2022-05-23T14:26:21+0000");
  script_tag(name:"last_modification", value:"2022-05-23 14:26:21 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2017-11-11 07:31:22 +0100 (Sat, 11 Nov 2017)");
  script_cve_id("CVE-2017-15088");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 15:28:00 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for krb5 (openSUSE-SU-2017:2993-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following securitz issue

  - CVE-2017-15088: A buffer overflow in get_matching_data() was fixed that
  could under specific circumstances be used to execute code (bsc#1065274)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");

  script_tag(name:"affected", value:"krb5 on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:2993-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client-debuginfo", rpm:"krb5-client-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-doc", rpm:"krb5-doc~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini", rpm:"krb5-mini~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-debuginfo", rpm:"krb5-mini-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-debugsource", rpm:"krb5-mini-debugsource~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-devel", rpm:"krb5-mini-devel~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap-debuginfo", rpm:"krb5-plugin-kdb-ldap-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp-debuginfo", rpm:"krb5-plugin-preauth-otp-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit-debuginfo", rpm:"krb5-plugin-preauth-pkinit-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.12.5~6.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client-debuginfo", rpm:"krb5-client-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-doc", rpm:"krb5-doc~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini", rpm:"krb5-mini~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-debuginfo", rpm:"krb5-mini-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-debugsource", rpm:"krb5-mini-debugsource~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-mini-devel", rpm:"krb5-mini-devel~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap-debuginfo", rpm:"krb5-plugin-kdb-ldap-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp-debuginfo", rpm:"krb5-plugin-preauth-otp-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit-debuginfo", rpm:"krb5-plugin-preauth-pkinit-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.12.5~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
