# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844360");
  script_cve_id("CVE-2019-13734", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19924", "CVE-2019-19925", "CVE-2019-19926", "CVE-2019-19959", "CVE-2019-20218", "CVE-2020-9327");
  script_tag(name:"creation_date", value:"2020-03-11 04:00:17 +0000 (Wed, 11 Mar 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 19:15:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4298-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4298-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3' package(s) announced via the USN-4298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SQLite incorrectly handled certain shadow tables. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-13734,
CVE-2019-13750, CVE-2019-13753)

It was discovered that SQLite incorrectly handled certain corrupt records.
An attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-13751)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 19.10. (CVE-2019-19880)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-19923)

It was discovered that SQLite incorrectly handled parser tree rewriting. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 19.10. (CVE-2019-19924)

It was discovered that SQLite incorrectly handled certain ZIP archives. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-19925,
CVE-2019-19959)

It was discovered that SQLite incorrectly handled errors during parsing. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-19926)

It was discovered that SQLite incorrectly handled parsing errors. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-20218)

It was discovered that SQLite incorrectly handled generated column
optimizations. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2020-9327)");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.11.0-1ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.11.0-1ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.22.0-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.22.0-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.29.0-2ubuntu0.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.29.0-2ubuntu0.2", rls:"UBUNTU19.10"))) {
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
