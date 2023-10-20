# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842671");
  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799");
  script_tag(name:"creation_date", value:"2016-03-02 05:17:56 +0000 (Wed, 02 Mar 2016)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2914-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2914-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuval Yarom, Daniel Genkin, and Nadia Heninger discovered that OpenSSL was
vulnerable to a side-channel attack on modular exponentiation. On certain
CPUs, a local attacker could possibly use this issue to recover RSA keys.
This flaw is known as CacheBleed. (CVE-2016-0702)

Adam Langley discovered that OpenSSL incorrectly handled memory when
parsing DSA private keys. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-0705)

Guido Vranken discovered that OpenSSL incorrectly handled hex digit
calculation in the BN_hex2bn function. A remote attacker could use this
issue to cause OpenSSL to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-0797)

Emilia Kasper discovered that OpenSSL incorrectly handled memory when
performing SRP user database lookups. A remote attacker could possibly use
this issue to cause OpenSSL to consume memory, resulting in a denial of
service. (CVE-2016-0798)

Guido Vranken discovered that OpenSSL incorrectly handled memory when
printing very long strings. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-0799)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.35", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.18", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2d-0ubuntu1.4", rls:"UBUNTU15.10"))) {
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
