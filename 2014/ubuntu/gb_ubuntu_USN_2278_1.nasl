# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841901");
  script_cve_id("CVE-2013-7345", "CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538");
  script_tag(name:"creation_date", value:"2014-07-21 11:52:02 +0000 (Mon, 21 Jul 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2278-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2278-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file' package(s) announced via the USN-2278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mike Frysinger discovered that the file awk script detector used multiple
wildcard with unlimited repetitions. An attacker could use this issue to
cause file to consume resources, resulting in a denial of service.
(CVE-2013-7345)

Francisco Alonso discovered that file incorrectly handled certain CDF
documents. A attacker could use this issue to cause file to hang or crash,
resulting in a denial of service. (CVE-2014-0207, CVE-2014-3478,
CVE-2014-3479, CVE-2014-3480, CVE-2014-3487)

Jan Kaluza discovered that file did not properly restrict the amount of
data read during regex searches. An attacker could use this issue to
cause file to consume resources, resulting in a denial of service.
(CVE-2014-3538)");

  script_tag(name:"affected", value:"'file' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.03-5ubuntu1.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.03-5ubuntu1.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.09-2ubuntu0.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.09-2ubuntu0.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.11-2ubuntu4.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.11-2ubuntu4.3", rls:"UBUNTU13.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"1:5.14-2ubuntu3.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"1:5.14-2ubuntu3.1", rls:"UBUNTU14.04 LTS"))) {
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
