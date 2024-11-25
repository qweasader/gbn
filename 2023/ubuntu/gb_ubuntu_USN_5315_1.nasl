# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5315.1");
  script_cve_id("CVE-2020-10744", "CVE-2020-1733", "CVE-2021-3583", "CVE-2021-3620");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-05 16:12:52 +0000 (Tue, 05 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5315-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5315-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5315-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the USN-5315-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ansible did not properly manage directory
permissions when running playbooks with an unprivileged become user. A
local attacker could possibly use this issue to cause a race condition,
escalate privileges and execute arbitrary code. This issue only affected
Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-1733)

It was discovered that the fix to address CVE-2020-1733 in Ansible was
incomplete on systems using ACLs and FUSE filesystems. A local attacker
could possibly use this issue to cause a race condition, escalate
privileges and execute arbitrary code. This issue only affected
Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-10744)

It was discovered that Ansible did not properly manage multi-line YAML
strings and special template characters. A local attacker could possibly
use this issue to cause a template injection, resulting in the
disclosure of sensitive information or other unspecified impact.
(CVE-2021-3583)

It was discovered that the ansible-connection module in Ansible did
not properly manage certain error messages. A local attacker could
possibly use this issue to expose sensitive information. This issue
only affected Ubuntu 20.04 ESM and Ubuntu 22.04 ESM. (CVE-2021-3620)");

  script_tag(name:"affected", value:"'ansible' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.0.0.2-2ubuntu1.3+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.5.1+dfsg-1ubuntu0.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.9.6+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.10.7+merged+base+2.10.8+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
