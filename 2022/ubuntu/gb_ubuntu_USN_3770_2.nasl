# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3770.2");
  script_cve_id("CVE-2013-4276", "CVE-2016-10165", "CVE-2018-16435");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 15:05:10 +0000 (Thu, 09 Feb 2017)");

  script_name("Ubuntu: Security Advisory (USN-3770-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3770-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3770-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lcms, lcms2' package(s) announced via the USN-3770-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3770-1 fixed a vulnerability in Little CMS. This update provides
the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 Pedro Ribeiro discoreved that Little CMS incorrectly handled certain files.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2013-4276)

 Ibrahim El-Sayed discovered that Little CMS incorrectly handled certain files.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2016-10165)

 Quang Nguyen discovered that Little CMS incorrectly handled certain files.
 An attacker could possibly use this issue to execute arbitrary code.
 (CVE-2018-16435)");

  script_tag(name:"affected", value:"'lcms, lcms2' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblcms-utils", ver:"1.19.dfsg-1ubuntu3.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms1", ver:"1.19.dfsg-1ubuntu3.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-2", ver:"2.2+git20110628-2ubuntu3.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-utils", ver:"2.2+git20110628-2ubuntu3.3", rls:"UBUNTU12.04 LTS"))) {
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
