# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851950");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-10-25 06:01:37 +0200 (Thu, 25 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for pam_pkcs11 (openSUSE-SU-2018:3369-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam_pkcs11'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pam_pkcs11 provides the following fixes:

  Security issues fixed (bsc#1105012):

  - Fixed a logic bug in pampkcs11.c, leading to an authentication replay
  vulnerability

  - Fixed a stack-based buffer overflow in opensshmapper.c

  - Make sure memory is properly cleaned before invoking free()

  Other changes:

  - Add a systemd service file. (bsc#1049219)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1244=1");

  script_tag(name:"affected", value:"pam_pkcs11 on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:3369-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00054.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"pam_pkcs11", rpm:"pam_pkcs11~0.6.8~13.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_pkcs11-debuginfo", rpm:"pam_pkcs11-debuginfo~0.6.8~13.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_pkcs11-debugsource", rpm:"pam_pkcs11-debugsource~0.6.8~13.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_pkcs11-32bit", rpm:"pam_pkcs11-32bit~0.6.8~13.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_pkcs11-debuginfo-32bit", rpm:"pam_pkcs11-debuginfo-32bit~0.6.8~13.3.1", rls:"openSUSELeap42.3"))) {
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
