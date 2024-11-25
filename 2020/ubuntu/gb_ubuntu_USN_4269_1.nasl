# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844328");
  script_cve_id("CVE-2018-16888", "CVE-2019-20386", "CVE-2019-3843", "CVE-2019-3844", "CVE-2020-1712");
  script_tag(name:"creation_date", value:"2020-02-06 04:00:14 +0000 (Thu, 06 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-10 15:42:07 +0000 (Fri, 10 Apr 2020)");

  script_name("Ubuntu: Security Advisory (USN-4269-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4269-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4269-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the USN-4269-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that systemd incorrectly handled certain PIDFile files.
A local attacker could possibly use this issue to trick systemd into
killing privileged processes. This issue only affected Ubuntu 16.04 LTS.
(CVE-2018-16888)

It was discovered that systemd incorrectly handled certain udevadm trigger
commands. A local attacker could possibly use this issue to cause systemd
to consume resources, leading to a denial of service. (CVE-2019-20386)

Jann Horn discovered that systemd incorrectly handled services that use the
DynamicUser property. A local attacker could possibly use this issue to
access resources owned by a different service in the future. This issue
only affected Ubuntu 18.04 LTS. (CVE-2019-3843, CVE-2019-3844)

Tavis Ormandy discovered that systemd incorrectly handled certain Polkit
queries. A local attacker could use this issue to cause systemd to crash,
resulting in a denial of service, or possibly execute arbitrary code and
escalate privileges. (CVE-2020-1712)");

  script_tag(name:"affected", value:"'systemd' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"229-4ubuntu21.27", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"237-3ubuntu10.38", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"242-7ubuntu3.6", rls:"UBUNTU19.10"))) {
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
