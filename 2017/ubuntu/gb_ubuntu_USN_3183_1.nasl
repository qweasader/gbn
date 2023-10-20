# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843032");
  script_cve_id("CVE-2016-7444", "CVE-2016-8610", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");
  script_tag(name:"creation_date", value:"2017-02-03 06:41:18 +0000 (Fri, 03 Feb 2017)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3183-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3183-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls26, gnutls28' package(s) announced via the USN-3183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Buehler discovered that GnuTLS incorrectly verified the serial
length of OCSP responses. A remote attacker could possibly use this issue
to bypass certain certificate validation measures. This issue only applied
to Ubuntu 16.04 LTS. (CVE-2016-7444)

Shi Lei discovered that GnuTLS incorrectly handled certain warning alerts.
A remote attacker could possibly use this issue to cause GnuTLS to hang,
resulting in a denial of service. This issue has only been addressed in
Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-8610)

It was discovered that GnuTLS incorrectly decoded X.509 certificates with a
Proxy Certificate Information extension. A remote attacker could use this
issue to cause GnuTLS to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS
and Ubuntu 16.10. (CVE-2017-5334)

It was discovered that GnuTLS incorrectly handled certain OpenPGP
certificates. A remote attacker could possibly use this issue to cause
GnuTLS to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2017-5335, CVE-2017-5336, CVE-2017-5337)");

  script_tag(name:"affected", value:"'gnutls26, gnutls28' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.14-5ubuntu3.13", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.23-12ubuntu2.6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.4.10-4ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.5.3-5ubuntu1.1", rls:"UBUNTU16.10"))) {
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
