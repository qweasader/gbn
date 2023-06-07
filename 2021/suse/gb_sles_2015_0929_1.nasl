# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0929.1");
  script_cve_id("CVE-2014-0222", "CVE-2014-0223", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0929-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150929-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'KVM' package(s) announced via the SUSE-SU-2015:0929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KVM was updated to fix the following security issues:
CVE-2015-3456: Buffer overflow in the floppy drive emulation, which could be used to carry out denial of service attacks or potential code execution against the host. This vulnerability is also known as VENOM.
CVE-2014-0222: Integer overflow in the qcow_open function in block/qcow.c in QEMU allowed remote attackers to cause a denial of service (crash) via a large L2 table in a QCOW version 1 image.
CVE-2014-0223: Integer overflow in the qcow_open function in block/qcow.c in QEMU allowed local users to cause a denial of service (crash) and possibly execute arbitrary code via a large image size, which triggers a buffer overflow or out-of-bounds read.
Security Issues:
CVE-2015-3456 CVE-2014-0222 CVE-2014-0223");

  script_tag(name:"affected", value:"'KVM' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~0.12.5~1.26.1", rls:"SLES11.0SP1"))) {
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
