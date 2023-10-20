# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704952");
  script_cve_id("CVE-2021-30640", "CVE-2021-33037");
  script_tag(name:"creation_date", value:"2021-08-12 03:00:10 +0000 (Thu, 12 Aug 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-26 17:00:00 +0000 (Mon, 26 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4952)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4952");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4952");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4952");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tomcat9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat9' package(s) announced via the DSA-4952 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the Tomcat servlet and JSP engine, which could result in HTTP request smuggling, bypass of logout restrictions or authentications using variations of a valid user name.

For the stable distribution (buster), these problems have been fixed in version 9.0.31-1~deb10u5.

We recommend that you upgrade your tomcat9 packages.

For the detailed security status of tomcat9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-admin", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-docs", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-examples", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-user", ver:"9.0.31-1~deb10u5", rls:"DEB10"))) {
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
