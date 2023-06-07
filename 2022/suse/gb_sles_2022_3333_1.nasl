# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3333.1");
  script_cve_id("CVE-2022-1798", "CVE-2022-1996", "CVE-2022-29162");
  script_tag(name:"creation_date", value:"2022-09-23 04:48:10 +0000 (Fri, 23 Sep 2022)");
  script_version("2022-09-23T10:10:45+0000");
  script_tag(name:"last_modification", value:"2022-09-23 10:10:45 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223333-1/");
  script_xref(name:"URL", value:"https://github.com/kubevirt/kubevirt/releases/tag/v0.54.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubevirt, virt-api-container, virt-controller-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container' package(s) announced via the SUSE-SU-2022:3333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubevirt, virt-api-container, virt-controller-container,
virt-handler-container, virt-launcher-container,
virt-libguestfs-tools-container, virt-operator-container fixes the following issues:

The kubevirt stack was updated to version 0.54.0

Release notes [link moved to references]

Security fixes:

CVE-2022-1798: Fix arbitrary file read on the host from KubeVirt VMs
 (bsc#1202516)

Security fixes in vendored dependencies:

CVE-2022-1996: Fixed go-restful CORS bypass bsc#1200528)

CVE-2022-29162: Fixed runc incorrect handling of inheritable
 capabilities in default configuration (bsc#1199460)

Fix containerdisk unmount logic

Support topology spread constraints

Update libvirt-go to fix memory leak

Pack nft rules and nsswitch.conf for virt-handler

Only create 1MiB-aligned disk images (bsc#1199603)

Avoid to return nil failure message

Use semantic equality comparison

Drop kubevirt-psp-caasp.yaml

Allow to configure utility containers for update test

Symlink nsswitch.conf and nft rules to proper locations

Drop unused package libvirt-client

Install vim-small instead of vim

Remove unneeded libvirt-daemon-driver-storage-core

Install missing packages ethtool and gawk. Fixes bsc#1199392");

  script_tag(name:"affected", value:"'kubevirt, virt-api-container, virt-controller-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container' package(s) on SUSE Linux Enterprise Module for Containers 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-manifests", rpm:"kubevirt-manifests~0.54.0~150400.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl", rpm:"kubevirt-virtctl~0.54.0~150400.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl-debuginfo", rpm:"kubevirt-virtctl-debuginfo~0.54.0~150400.3.3.2", rls:"SLES15.0SP4"))) {
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
