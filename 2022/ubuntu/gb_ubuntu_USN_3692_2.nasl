# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3692.2");
  script_cve_id("CVE-2018-0495", "CVE-2018-0732", "CVE-2018-0737");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:00:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-3692-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3692-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3692-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-3692-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3692-1 fixed a vulnerability in OpenSSL. This update provides
the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 Keegan Ryan discovered that OpenSSL incorrectly handled ECDSA key
 generation. An attacker could possibly use this issue to perform a
 cache-timing attack and recover private ECDSA keys. (CVE-2018-0495)

 Guido Vranken discovered that OpenSSL incorrectly handled very large prime
 values during a key agreement. A remote attacker could possibly use this
 issue to consume resources, leading to a denial of service. (CVE-2018-0732)

 Alejandro Cabrera Aldaya, Billy Brumley, Cesar Pereida Garcia and Luis
 Manuel Alvarez Tapia discovered that OpenSSL incorrectly handled RSA key
 generation. An attacker could possibly use this issue to perform a
 cache-timing attack and recover private RSA keys. (CVE-2018-0737)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.43", rls:"UBUNTU12.04 LTS"))) {
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
