# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6682.1");
  script_cve_id("CVE-2020-11076", "CVE-2020-11077", "CVE-2022-23634", "CVE-2022-24790", "CVE-2023-40175", "CVE-2024-21647");
  script_tag(name:"creation_date", value:"2024-03-08 04:08:45 +0000 (Fri, 08 Mar 2024)");
  script_version("2024-03-08T15:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-24 18:48:29 +0000 (Thu, 24 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6682-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6682-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puma' package(s) announced via the USN-6682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ZeddYu Lu discovered that Puma incorrectly handled parsing certain headers.
A remote attacker could possibly use this issue to perform an HTTP Request
Smuggling attack. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-11076)

It was discovered that Puma incorrectly handled parsing certain headers.
A remote attacker could possibly use this issue to perform an HTTP Request
Smuggling attack. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-11077)

Jean Boussier discovered that Puma might not always release resources
properly after handling HTTP requests. A remote attacker could possibly
use this issue to read sensitive information. (CVE-2022-23634)

It was discovered that Puma incorrectly handled certain malformed headers.
A remote attacker could use this issue to perform an HTTP Request Smuggling
attack. (CVE-2022-24790)

Ben Kallus discovered that Puma incorrectly handled parsing certain headers.
A remote attacker could use this issue to perform an HTTP Request Smuggling
attack. (CVE-2023-40175)

Bartek Nowotarski discovered that Puma incorrectly handled parsing certain
encoded content. A remote attacker could possibly use this to cause a
denial of service. (CVE-2024-21647)");

  script_tag(name:"affected", value:"'puma' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"puma", ver:"3.12.4-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"puma", ver:"5.5.2-2ubuntu2+esm1", rls:"UBUNTU22.04 LTS"))) {
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
