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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1642.1");
  script_cve_id("CVE-2013-4291", "CVE-2013-4296", "CVE-2013-4311", "CVE-2013-5651");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1642-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1642-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131642-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2013:1642-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libvirt has been updated to the 1.0.5.6 stable release that fixes bugs and security issues:

 * CVE-2013-4296: Fix crash in remoteDispatchDomainMemoryStats
 * CVE-2013-5651: virBitmapParse out-of-bounds read access Libvirt on SLES 11 SP3 is not affected:
 * CVE-2013-4311: Add support for using 3-arg pkcheck syntax for process ()
 * CVE-2013-4291: security: provide supplemental groups even when parsing label ()

Changes in this version:

 * virsh: fix change-media bug on disk block type
 * Include process start time when doing polkit checks
 * qemuDomainChangeGraphics: Check listen address change by listen type
 * python: return dictionary without value in case of no blockjob
 * virbitmap: Refactor virBitmapParse to avoid access beyond bounds of array

Also the following bug has been fixed:

 * Fix retrieval of SRIOV VF info, which prevented using some SRIOV virtual functions in guest domains with ''
(bnc#837329)

Security Issue references:

 * CVE-2013-4296
>
 * CVE-2013-5651
>");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-32bit", rpm:"libvirt-client-32bit~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~1.0.5.6~0.7.1", rls:"SLES11.0SP3"))) {
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
