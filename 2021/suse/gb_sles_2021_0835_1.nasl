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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0835.1");
  script_cve_id("CVE-2020-0429", "CVE-2020-1749", "CVE-2020-25645", "CVE-2020-27786", "CVE-2020-28374");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-12 15:15:00 +0000 (Wed, 12 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0835-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210835-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 39 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2021:0835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_149 fixes several issues.

The following security issues were fixed:

CVE-2020-27786: Fixed a potential user after free which could have led
 to memory corruption or privilege escalation (bsc#1179616).

CVE-2020-28374: Fixed insufficient identifier checking in the LIO SCSI
 target code which could have been used by remote attackers to read or
 write files via directory traversal in an XCOPY request (bsc#1178684).

CVE-2020-25645: Fixed an issue where the traffic between two Geneve
 endpoints may have been unencrypted when IPsec was configured to encrypt
 traffic for the specific UDP port used by the GENEVE tunnel allowing
 anyone between the two endpoints to read the traffic unencrypted
 (bsc#1177513).

CVE-2020-0429: Fixed a potential memory corruption due to a use after
 free which could have led local escalation of privilege with System
 execution privileges needed (bsc#1176931).

CVE-2020-1749: Fixed an issue in some networking protocols in IPsec,
 such as VXLAN and GENEVE tunnels over IPv6 where the kernel was not
 correctly routing tunneled data over the encrypted link rather sending
 the data unencrypted (bsc#1165631).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 39 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_149-default", rpm:"kgraft-patch-4_4_121-92_149-default~2~2.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_138-default", rpm:"kgraft-patch-4_4_180-94_138-default~2~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_138-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_138-default-debuginfo~2~2.2", rls:"SLES12.0SP3"))) {
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
