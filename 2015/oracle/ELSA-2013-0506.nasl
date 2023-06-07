# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123695");
  script_cve_id("CVE-2012-1182");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:27:53+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:27:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0506)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0506");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0506.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba4' package(s) announced via the ELSA-2013-0506 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.0.0-55.rc4]
- Fix dependencies of samba4-test package.
- related: #896142

[4.0.0-54.rc4]
- Fix summary and description of dc subpackages.
- resolves: #896142
- Remove conflicting libsmbclient.7 manpage.
- resolves: #896240

[4.0.0-53.rc4]
- Fix provides filter rules to remove conflicting libraries from samba4-libs.
- resolves: #895718

[4.0.0-52.rc4]
- Fix typo in winbind-krb-locator post uninstall script.
- related: #864889

[4.0.0-51.rc4]
- Make sure we use the same directory as samba package for the winbind pipe.
- resolves: #886157

[4.0.0-50.rc4]
- Fix typo in winbind-krb-locator post uninstall script.
- related: #864889

[4.0.0-49.rc4]
- Fix Netlogon AES encryption.
- resolves: #885089

[4.0.0-48.rc4]
- Fix IPA trust AD lookup of users.
- resolves: #878564

[4.0.0-47.rc4]
- Add require for krb5-libs >= 1.10 to samba4-libs.
- resolves: #877533

[4.0.0-46.rc4]
- Rename /etc/sysconfig/samba4 to name to mach init scripts.
- resolves: #877085

[4.0.0-45.rc4]
- Don't require samba4-common and samba4-test in samba4-devel package.
- related: #871748

[4.0.0-44.rc4]
- Make libnetapi and internal library to fix dependencies.
- resolves: #873491

[4.0.0-43.rc4]
- Move libnetapi and internal printing migration lib to libs package.
- related: #766333

[4.0.0-42.rc4]
- Fix perl, pam and logrotate dependencies.
- related: #766333

[4.0.0-41.rc4]
- Fix library dependencies found by rpmdiff.
- Update winbind offline logon patch.
- related: #766333

[4.0.0-40.rc4]
- Move libgpo to samba-common
- resolves: #871748

[4.0.0-39.rc4]
- Rebase to version 4.0.0rc4.
- related: #766333

[4.0.0-38.rc3]
- Add missing export KRB5CCNAME in init scripts.
- resolves: #868419

[4.0.0-37.rc3]
- Move /var/log/samba to samba-common package for winbind which
 requires it.
- resolves: #868248

[4.0.0-36.rc3]
- The standard auth modules need to be built into smbd to function.
- resolves: #867854

[4.0.0-35.rc3]
- Move pam_winbind.conf to the package of the module.
- resolves: #867317

[4.0.0-34.rc3]
- Built auth_builtin as static module.
- related: #766333

[4.0.0-33.rc3]
- Add back the AES patches which didn't make it in rc3.
- related: #766333

[4.0.0-32.rc3]
- Rebase to version 4.0.0rc3.
- related: #766333

[4.0.0-31.rc2]
- Use alternatives to configure winbind_krb5_locator.so
- resolves: #864889

[4.0.0-30.rc2]
- Fix multilib package installation.
- resolves: #862047
- Filter out libsmbclient and libwbclient provides.
- resolves: #861892
- Rebase to version 4.0.0rc2.
- related: #766333

[4.0.0-29.rc1]
- Fix Requires and Conflicts.
- related: #766333

[4.0.0-28.rc1]
- Move pam_winbind and wbinfo manpages to the right subpackage.
- related: #766333

[4.0.0-27.rc1]
- Fix permission for init scripts.
- Define a common KRB5CCNAME for smbd and winbind.
- Set piddir back to /var/run in RHEL6.
- related: #766333

[4.0.0-26.rc1]
- Add '-fno-strict-aliasing' to CFLAGS again.
- related: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'samba4' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"samba4", rpm:"samba4~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-client", rpm:"samba4-client~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-common", rpm:"samba4-common~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-dc", rpm:"samba4-dc~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-dc-libs", rpm:"samba4-dc-libs~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-devel", rpm:"samba4-devel~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-libs", rpm:"samba4-libs~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-pidl", rpm:"samba4-pidl~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-python", rpm:"samba4-python~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-swat", rpm:"samba4-swat~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-test", rpm:"samba4-test~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind", rpm:"samba4-winbind~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind-clients", rpm:"samba4-winbind-clients~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind-krb5-locator", rpm:"samba4-winbind-krb5-locator~4.0.0~55.el6.rc4", rls:"OracleLinux6"))) {
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
