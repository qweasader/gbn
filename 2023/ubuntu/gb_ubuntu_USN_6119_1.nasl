# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6119.1");
  script_cve_id("CVE-2023-1255", "CVE-2023-2650");
  script_tag(name:"creation_date", value:"2023-05-31 04:09:47 +0000 (Wed, 31 May 2023)");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-29 18:04:00 +0000 (Tue, 29 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6119-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6119-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-6119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Caswell discovered that OpenSSL incorrectly handled certain ASN.1
object identifiers. A remote attacker could possibly use this issue to
cause OpenSSL to consume resources, resulting in a denial of service.
(CVE-2023-2650)

Anton Romanov discovered that OpenSSL incorrectly handled AES-XTS cipher
decryption on 64-bit ARM platforms. An attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service. This
issue only affected Ubuntu 22.04 LTS, Ubuntu 22.10, and Ubuntu 23.04.
(CVE-2023-1255)");

  script_tag(name:"affected", value:"'openssl, openssl1.0' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10, Ubuntu 23.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1-1ubuntu2.1~18.04.23", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.19", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.5-2ubuntu2.3", rls:"UBUNTU22.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.8-1ubuntu1.2", rls:"UBUNTU23.04"))) {
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
