# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1546");
  script_cve_id("CVE-2022-23471");
  script_tag(name:"creation_date", value:"2023-03-20 08:10:36 +0000 (Mon, 20 Mar 2023)");
  script_version("2023-04-25T10:19:16+0000");
  script_tag(name:"last_modification", value:"2023-04-25 10:19:16 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 14:53:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2023-1546)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1546");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1546");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2023-1546 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"containerd is an open source container runtime. A bug was found in containerd's CRI implementation where a user can exhaust memory on the host. In the CRI stream server, a goroutine is launched to handle terminal resize events if a TTY is requested. If the user's process fails to launch due to, for example, a faulty command, the goroutine will be stuck waiting to send without a receiver, resulting in a memory leak. Kubernetes and crictl can both be configured to use containerd's CRI implementation and the stream server is used for handling container IO. This bug has been fixed in containerd 1.6.12 and 1.5.16. Users should update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted images and commands are used and that only trusted users have permissions to execute commands in running containers.(CVE-2022-23471)");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~1:18.09.0~200.h62.33.19.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
