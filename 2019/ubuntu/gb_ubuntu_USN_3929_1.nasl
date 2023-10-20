# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843961");
  script_cve_id("CVE-2014-9323", "CVE-2017-6369");
  script_tag(name:"creation_date", value:"2019-04-03 06:40:59 +0000 (Wed, 03 Apr 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3929-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3929-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firebird2.5' package(s) announced via the USN-3929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Firebird incorrectly handled certain malformed
packets. A remote attacker could possibly use this issue with a specially
crafted network packet to cause Firebird to crash, resulting in a denial of
service.
(CVE-2014-9323)

It was discovered that Firebird incorrectly handled certain UDF libraries.
A remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2017-6369)");

  script_tag(name:"affected", value:"'firebird2.5' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic-common", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-server-common", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-super", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-superclassic", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbembed2.5", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libib-util", ver:"2.5.2.26540.ds4-9ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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
