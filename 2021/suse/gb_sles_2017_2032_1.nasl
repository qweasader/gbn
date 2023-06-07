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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2032.1");
  script_cve_id("CVE-2017-11406", "CVE-2017-11407", "CVE-2017-11408", "CVE-2017-11410", "CVE-2017-11411");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2032-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172032-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2017:2032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This wireshark update to version 2.2.8 fixes the following issues:
Security issues fixed:
- CVE-2017-11411: The openSAFETY dissectorcould crash or exhaust system
 memory because of missing length validation. (bsc#1049621)
- CVE-2017-11410: The WBXML dissector could go into an infinite loop.
 (bsc#1049255)
- CVE-2017-11408: The AMQP dissector could crash. (bsc#1049255)
- CVE-2017-11407: The MQ dissector could crash. (bsc#1049255)
- CVE-2017-11406: The DOCSIS dissector could go into an infinite loop.
 (bsc#1049255)");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.14~40.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.0.14~40.7.1", rls:"SLES11.0SP4"))) {
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
