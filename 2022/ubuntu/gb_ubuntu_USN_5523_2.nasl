# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5523.2");
  script_cve_id("CVE-2022-0907", "CVE-2022-0908", "CVE-2022-0909", "CVE-2022-0924", "CVE-2022-22844");
  script_tag(name:"creation_date", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-19 15:50:32 +0000 (Wed, 19 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-5523-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5523-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5523-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-5523-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5523-1 fixed several vulnerabilities in LibTIFF. This update
provides the fixes for CVE-2022-0907, CVE-2022-0908, CVE-2022-0909,
CVE-2022-0924 and CVE-2022-22844 for Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that LibTIFF was not properly perf orming checks to
 guarantee that allocated memory space existed, which could lead to a
 NULL pointer dereference via a specially crafted file. An attacker
 could possibly use this issue to cause a denial of service.
 (CVE-2022-0907, CVE-2022-0908)

 It was discovered that LibTIFF was not properly performing checks to
 avoid division calculations where the denominator value was zero,
 which could lead to an undefined behavior situation via a specially
 crafted file. An attacker could possibly use this issue to cause a
 denial of service. (CVE-2022-0909)

 It was discovered that LibTIFF was not properly performing bounds
 checks, which could lead to an out-of-bounds read via a specially
 crafted file. An attacker could possibly use this issue to cause a
 denial of service or to expose sensitive information. (CVE-2022-0924)

 It was discovered that LibTIFF was not properly performing the
 calculation of data that would eventually be used as a reference for
 bounds checking operations, which could lead to an out-of-bounds
 read via a specially crafted file. An attacker could possibly use
 this issue to cause a denial of service or to expose sensitive
 information. (CVE-2020-19131)

 It was discovered that LibTIFF was not properly terminating a
 function execution when processing incorrect data, which could lead
 to an out-of-bounds read via a specially crafted file. An attacker
 could possibly use this issue to cause a denial of service or to
 expose sensitive information. (CVE-2020-19144)

 It was discovered that LibTIFF was not properly performing checks
 when setting the value for data later used as reference during memory
 access, which could lead to an out-of-bounds read via a specially
 crafted file. An attacker could possibly use this issue to cause a
 denial of service or to expose sensitive information.
 (CVE-2022-22844)");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.9-5ubuntu0.6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.9-5ubuntu0.6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.9-5ubuntu0.6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.9-5ubuntu0.6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.1.0+git191117-2ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.1.0+git191117-2ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.1.0+git191117-2ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.1.0+git191117-2ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
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
