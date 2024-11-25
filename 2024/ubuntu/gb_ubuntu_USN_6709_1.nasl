# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6709.1");
  script_cve_id("CVE-2023-3446", "CVE-2023-3817", "CVE-2023-5678", "CVE-2024-0727");
  script_tag(name:"creation_date", value:"2024-03-22 04:08:37 +0000 (Fri, 22 Mar 2024)");
  script_version("2024-03-22T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-03-22 05:05:34 +0000 (Fri, 22 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:53:24 +0000 (Fri, 02 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6709-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6709-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6709-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl1.0' package(s) announced via the USN-6709-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that checking excessively long DH keys or parameters
may be very slow. A remote attacker could possibly use this issue to
cause OpenSSL to consume resources, resulting in a denial of service.
(CVE-2023-3446)

After the fix for CVE-2023-3446 Bernd Edlinger discovered that a large
q parameter value can also trigger an overly long computation during
some of these checks. A remote attacker could possibly use this issue
to cause OpenSSL to consume resources, resulting in a denial of
service. (CVE-2023-3817)

David Benjamin discovered that generating excessively long X9.42 DH
keys or checking excessively long X9.42 DH keys or parameters may be
very slow. A remote attacker could possibly use this issue to cause
OpenSSL to consume resources, resulting in a denial of service.
(CVE-2023-5678)

Bahaa Naamneh discovered that processing a maliciously formatted
PKCS12 file may lead OpenSSL to crash leading to a potential Denial of
Service attack. (CVE-2024-0727)");

  script_tag(name:"affected", value:"'openssl1.0' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.13+esm1", rls:"UBUNTU18.04 LTS"))) {
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
