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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0440.1");
  script_cve_id("CVE-2019-0804");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0440-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0440-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200440-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-azure-agent' package(s) announced via the SUSE-SU-2020:0440-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-azure-agent fixes the following issues:

python-azure-agent was updated to version 2.2.45 (jsc#ECO-80)
Add support for Gen2 VM resource disks

Use alternate systemd detection

Fix /proc/net/route requirement that causes errors on FreeBSD

Add cloud-init auto-detect to prevent multiple provisioning mechanisms
 from relying on configuration for coordination

Disable cgroups when daemon is setup incorrectly

Remove upgrade extension loop for the same goal state

Add container id for extension telemetry events

Be more exact when detecting IMDS service health

Changing add_event to start sending missing fields

From 2.2.44 update:
Remove outdated extension ZIP packages

Improved error handling when starting extensions using systemd

Reduce provisioning time of some custom images

Improve the handling of extension download errors

New API for extension authors to handle errors during extension update

Fix handling of errors in calls to openssl

Improve logic to determine current distro

Reduce verbosity of several logging statements

From 2.2.42 update:
Poll for artifact blob, addresses goal state procesing issue

From 2.2.41 update:
Rewriting the mechanism to start the extension using systemd-run for
 systems using systemd for managing

Refactoring of resource monitoring framework using cgroup for both
 systemd and non-systemd approaches [#1530, #1534]

Telemetry pipeline for resource monitoring data

From 2.2.40 update:
Fixed tracking of memory/cpu usage

Do not prevent extensions from running if setting up cgroups fails

Enable systemd-aware deprovisioning on all versions >= 18.04

Add systemd support for Debian Jessie, Stretch, and Buster

Support for Linux Openwrt

From 2.2.38 update:

Security issue fixed:
CVE-2019-0804: An issue with swapfile handling in the agent creates a
 data leak situation that exposes system memory data. (bsc#1127838)

Add fixes for handling swap file and other nit fixes

From 2.2.37 update:
Improves re-try logic to handle errors while downloading extensions");

  script_tag(name:"affected", value:"'python-azure-agent' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python-azure-agent", rpm:"python-azure-agent~2.2.45~3.3.1", rls:"SLES15.0SP1"))) {
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
