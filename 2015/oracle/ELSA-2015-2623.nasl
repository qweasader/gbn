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
  script_oid("1.3.6.1.4.1.25623.1.0.122805");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"creation_date", value:"2015-12-16 09:36:46 +0000 (Wed, 16 Dec 2015)");
  script_version("2022-04-05T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-04-05 03:03:58 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2623)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2623");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2623.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the ELSA-2015-2623 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.02-0.33.0.1]
- Fix comparison in patch for 18504756
- Remove symlink to grub environment file during uninstall on EFI platforms
 [bug 19231481]
- update Oracle Linux certificates (Alexey Petrenko)
- Put 'with' in menuentry instead of 'using' [bug 18504756]
- Use different titles for UEK and RHCK kernels [bug 18504756]

[2.02-0.33]
- Don't remove 01_users, it's the wrong thing to do.
 Related:rhbz1290089

[2.02-0.32]
- Rebuild for .z so the release number is different.
 Related: rhbz#1290089

[2.02-0.31]
- More work on handling of GRUB2_PASSWORD
 Resolves: rhbz#1290089

[2.02-0.30]
- Fix security issue when reading username and password
 Resolves: CVE-2015-8370
- Do a better job of handling GRUB_PASSWORD
 Resolves: rhbz#1290089");

  script_tag(name:"affected", value:"'grub2' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.33.0.1.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.33.0.1.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-modules", rpm:"grub2-efi-modules~2.02~0.33.0.1.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.33.0.1.el7_2", rls:"OracleLinux7"))) {
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
