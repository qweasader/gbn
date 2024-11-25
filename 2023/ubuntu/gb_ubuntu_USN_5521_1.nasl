# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5521.1");
  script_cve_id("CVE-2021-32760", "CVE-2021-41103", "CVE-2022-23648", "CVE-2022-31030");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-14 19:38:38 +0000 (Thu, 14 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5521-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5521-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5521-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd' package(s) announced via the USN-5521-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that containerd insufficiently restricted permissions on
container root and plugin directories. If a user or automated system were
tricked into launching a specially crafted container image, a remote
attacker could traverse directory contents and modify files and execute
programs on the host file system, possibly leading to privilege escalation.
(CVE-2021-41103)

It was discovered that containerd incorrectly handled file permission
changes. If a user or automated system were tricked into launching a
specially crafted container image, a remote attacker could change
permissions on files on the host file system and possibly escalate
privileges. (CVE-2021-32760)

It was discovered that containerd allows attackers to gain access to read-
only copies of arbitrary files and directories on the host via a specially-
crafted image configuration. An attacker could possibly use this issue to
obtain sensitive information. (CVE-2022-23648)

It was discovered that containerd incorrectly handled certain memory
operations. A remote attacker could use this to cause a denial of service.
(CVE-2022-31030)");

  script_tag(name:"affected", value:"'containerd' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"containerd", ver:"1.2.6-0ubuntu1~16.04.6+esm2", rls:"UBUNTU16.04 LTS"))) {
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
