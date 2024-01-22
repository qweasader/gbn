# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6450.1");
  script_cve_id("CVE-2023-2975", "CVE-2023-3446", "CVE-2023-3817", "CVE-2023-5363");
  script_tag(name:"creation_date", value:"2023-10-25 04:08:37 +0000 (Wed, 25 Oct 2023)");
  script_version("2023-11-14T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-11-14 05:06:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 13:55:00 +0000 (Thu, 09 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6450-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6450-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6450-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-6450-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tony Battersby discovered that OpenSSL incorrectly handled key and
initialization vector (IV) lengths. This could lead to truncation issues
and result in loss of confidentiality for some symmetric cipher modes.
(CVE-2023-5363)

Juerg Wullschleger discovered that OpenSSL incorrectly handled the AES-SIV
cipher. This could lead to empty data entries being ignored, resulting in
certain applications being misled. This issue only affected Ubuntu 22.04
LTS and Ubuntu 23.04. (CVE-2023-2975)

It was discovered that OpenSSL incorrectly handled checking excessively
long DH keys or parameters. A remote attacker could possibly use this issue
to cause OpenSSL to consume resources, leading to a denial of service. This
issue only affected Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-3446,
CVE-2023-3817)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.8-1ubuntu1.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.10-1ubuntu2.1", rls:"UBUNTU23.10"))) {
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
