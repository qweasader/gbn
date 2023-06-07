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
  script_oid("1.3.6.1.4.1.25623.1.0.123258");
  script_cve_id("CVE-2014-3675", "CVE-2014-3676", "CVE-2014-3677");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:23 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:49:18 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1801)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1801");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1801.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim, shim-signed' package(s) announced via the ELSA-2014-1801 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"shim
[0.7-8.0.1]
- update Oracle Linux certificates (Alexey Petrenko)
- replace securebootca.cer (Alexey Petrenko)

[0.7-8]
- out-of-bounds memory read flaw in DHCPv6 packet processing
 Resolves: CVE-2014-3675
- heap-based buffer overflow flaw in IPv6 address parsing
 Resolves: CVE-2014-3676
- memory corruption flaw when processing Machine Owner Keys (MOKs)
 Resolves: CVE-2014-3677

[0.7-7]
- Use the right key for ARM Aarch64.

[0.7-6]
- Preliminary build for ARM Aarch64.

shim-signed
[0.7-8.0.1]
- Oracle Linux certificates (Alexey Petrenko)

[0.7-8]
- out-of-bounds memory read flaw in DHCPv6 packet processing
 Resolves: CVE-2014-3675
- heap-based buffer overflow flaw in IPv6 address parsing
 Resolves: CVE-2014-3676
- memory corruption flaw when processing Machine Owner Keys (MOKs)
 Resolves: CVE-2014-3677

[0.7-5.2]
- Get the right signatures on shim-redhat.efi
 Related: rhbz#1064449

[0.7-5.1]
- Update for signed shim for RHEL 7
 Resolves: rhbz#1064449");

  script_tag(name:"affected", value:"'shim, shim-signed' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"mokutil", rpm:"mokutil~0.7~8.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~0.7~8.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-signed", rpm:"shim-signed~0.7~8.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-unsigned", rpm:"shim-unsigned~0.7~8.0.1.el7_0", rls:"OracleLinux7"))) {
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
