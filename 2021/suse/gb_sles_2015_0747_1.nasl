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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0747.1");
  script_cve_id("CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2756");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0747-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0747-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150747-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:0747-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Virtualization service XEN was updated to fix various bugs and security issues.
The following security issues have been fixed:
CVE-2015-2756: XSA-126: Unmediated PCI command register access in qemu could have lead to denial of service attacks against the host, if PCI cards are passed through to guests.
XSA-125: Long latency MMIO mapping operations were not preemptible.
CVE-2015-2151: XSA-123: Instructions with register operands ignored eventual segment overrides encoded for them. Due to an insufficiently conditional assignment such a bogus segment override could have,
however, corrupted a pointer used subsequently to store the result of the instruction.
CVE-2015-2045: XSA-122: The code handling certain sub-operations of the HYPERVISOR_xen_version hypercall failed to fully initialize all fields of structures subsequently copied back to guest memory. Due to this hypervisor stack contents were copied into the destination of the operation, thus becoming visible to the guest.
CVE-2015-2044: XSA-121: Emulation routines in the hypervisor dealing with certain system devices checked whether the access size by the guest is a supported one. When the access size is unsupported these routines failed to set the data to be returned to the guest for read accesses,
so that hypervisor stack contents were copied into the destination of the operation, thus becoming visible to the guest.
Also fixed:
Fully virtualized guest install from network source failed with 'cannot find guest domain' in XEN. (bsc#919341)
Security Issues:
CVE-2015-2044 CVE-2015-2045 CVE-2015-2151 CVE-2015-2756");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_04_3.0.101_0.47.52~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_04_3.0.101_0.47.52~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_04~0.9.1", rls:"SLES11.0SP3"))) {
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
