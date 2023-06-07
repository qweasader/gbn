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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3711.1");
  script_cve_id("CVE-2022-41973", "CVE-2022-41974");
  script_tag(name:"creation_date", value:"2022-10-25 04:56:25 +0000 (Tue, 25 Oct 2022)");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 19:47:00 +0000 (Mon, 31 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3711-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3711-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223711-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'multipath-tools' package(s) announced via the SUSE-SU-2022:3711-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for multipath-tools fixes the following issues:

CVE-2022-41973: Fixed a symlink attack in multipathd. (bsc#1202739)

CVE-2022-41974: Fixed an authorization bypass issue in multipathd.
 (bsc#1202739)

Avoid linking to libreadline to avoid licensing issue (bsc#1202616)

libmultipath: fix find_multipaths_timeout for unknown hardware
 (bsc#1201483)

multipath-tools: fix 'multipath -ll' for Native NVME Multipath devices
 (bsc#1201483)

multipathd: don't switch to DAEMON_IDLE during startup (bsc#1199346,
 bsc#1197570)

multipathd: avoid delays during uevent processing (bsc#1199347)

multipathd: Don't keep starting TUR threads, if they always hang.
 (bsc#1199345)

Fix busy loop with delayed_reconfigure (bsc#1199342)

multipath.conf: add support for 'protocol' subsection in 'overrides'
 section to set certain config options by protocol.

Removed the previously deprecated options getuid_callout, config_dir,
 multipath_dir, pg_timeout

Add disclaimer about vendor support

Change built-in defaults for NVMe: group by prio, and immediate failback

Fixes for minor issues reported by coverity

Fix for memory leak with uid_attrs

Updates for built in hardware db

Logging improvements

multipathd: use remove_map_callback for delayed reconfigure

Fix handling of path addition in read-only arrays on NVMe

Updates of built-in hardware database

libmultipath: only warn once about unsupported dev_loss_tmo");

  script_tag(name:"affected", value:"'multipath-tools' package(s) on SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kpartx", rpm:"kpartx~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kpartx-debuginfo", rpm:"kpartx-debuginfo~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmmp-devel", rpm:"libdmmp-devel~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmmp0_2_0", rpm:"libdmmp0_2_0~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmmp0_2_0-debuginfo", rpm:"libdmmp0_2_0-debuginfo~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpath0", rpm:"libmpath0~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpath0-debuginfo", rpm:"libmpath0-debuginfo~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools", rpm:"multipath-tools~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools-debuginfo", rpm:"multipath-tools-debuginfo~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools-debugsource", rpm:"multipath-tools-debugsource~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools-devel", rpm:"multipath-tools-devel~0.9.0+62+suse.3e048d4~150400.4.7.1", rls:"SLES15.0SP4"))) {
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
