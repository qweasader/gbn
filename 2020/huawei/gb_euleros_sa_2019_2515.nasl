# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2515");
  script_cve_id("CVE-2014-6272", "CVE-2015-6525");
  script_tag(name:"creation_date", value:"2020-01-23 13:03:05 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-04-07T14:39:39+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:39:39 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Huawei EulerOS: Security Advisory for libevent (EulerOS-SA-2019-2515)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2515");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2515");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libevent' package(s) announced via the EulerOS-SA-2019-2515 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer overflows in the evbuffer API in Libevent 1.4.x before 1.4.15, 2.0.x before 2.0.22, and 2.1.x before 2.1.5-beta allow context-dependent attackers to cause a denial of service or possibly have other unspecified impact via 'insanely large inputs' to the (1) evbuffer_add, (2) evbuffer_expand, or (3) bufferevent_write function, which triggers a heap-based buffer overflow or an infinite loop. NOTE: this identifier has been SPLIT per ADT3 due to different affected versions. See CVE-2015-6525 for the functions that are only affected in 2.0 and later.(CVE-2014-6272)

Multiple integer overflows in the evbuffer API in Libevent 2.0.x before 2.0.22 and 2.1.x before 2.1.5-beta allow context-dependent attackers to cause a denial of service or possibly have other unspecified impact via 'insanely large inputs' to the (1) evbuffer_add, (2) evbuffer_prepend, (3) evbuffer_expand, (4) exbuffer_reserve_space, or (5) evbuffer_read function, which triggers a heap-based buffer overflow or an infinite loop. NOTE: this identifier was SPLIT from CVE-2014-6272 per ADT3 due to different affected versions.(CVE-2015-6525)");

  script_tag(name:"affected", value:"'libevent' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libevent", rpm:"libevent~2.0.21~4.h4", rls:"EULEROS-2.0SP2"))) {
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
