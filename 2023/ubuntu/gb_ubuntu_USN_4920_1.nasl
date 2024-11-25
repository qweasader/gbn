# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.4920.1");
  script_cve_id("CVE-2019-13132", "CVE-2020-15166", "CVE-2021-20234", "CVE-2021-20235", "CVE-2021-20237");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-18 13:24:41 +0000 (Thu, 18 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-4920-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4920-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4920-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zeromq3' package(s) announced via the USN-4920-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ZeroMQ incorrectly handled certain application
metadata. A remote attacker could use this issue to cause ZeroMQ to crash,
or possibly execute arbitrary code. (CVE-2019-13132)

It was discovered that ZeroMQ mishandled certain network traffic. An
unauthenticated attacker could use this vulnerability to cause a denial-of-
service and prevent legitimate clients from communicating with ZeroMQ.
(CVE-2020-15166)

It was discovered that ZeroMQ did not properly manage memory under certain
circumstances. If a user or automated system were tricked into connecting
to one or multiple compromised servers, a remote attacker could use this
issue to cause a denial of service. (CVE-2021-20234)

It was discovered that ZeroMQ incorrectly handled memory when processing
messages with arbitrarily large sizes under certain circumstances. A remote
unauthenticated attacker could use this issue to cause a ZeroMQ server to crash,
resulting in a denial of service, or possibly execute arbitrary code. This issue
only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-20235)

It was discovered that ZeroMQ did not properly manage memory under certain
circumstances. A remote unauthenticated attacker could use this issue to
cause a ZeroMQ server to crash, resulting in a denial of service. This issue
only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-20237)");

  script_tag(name:"affected", value:"'zeromq3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libzmq3", ver:"4.0.4+dfsg-2ubuntu0.1+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libzmq5", ver:"4.1.4-7ubuntu0.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libzmq5", ver:"4.2.5-1ubuntu0.2+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libzmq5", ver:"4.3.2-2ubuntu1.20.04.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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
