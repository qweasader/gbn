# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703614");
  script_cve_id("CVE-2016-3092");
  script_tag(name:"creation_date", value:"2016-07-01 22:00:00 +0000 (Fri, 01 Jul 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-3614)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3614");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3614");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3614");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat7' package(s) announced via the DSA-3614 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The TERASOLUNA Framework Development Team discovered a denial of service vulnerability in Apache Commons FileUpload, a package to make it easy to add robust, high-performance, file upload capability to servlets and web applications. A remote attacker can take advantage of this flaw by sending file upload requests that cause the HTTP server using the Apache Commons Fileupload library to become unresponsive, preventing the server from servicing other requests.

Apache Tomcat uses a package renamed copy of Apache Commons FileUpload to implement the file upload requirements of the Servlet specification and is therefore also vulnerable to the denial of service vulnerability.

For the stable distribution (jessie), this problem has been fixed in version 7.0.56-3+deb8u3.

For the testing distribution (stretch), this problem has been fixed in version 7.0.70-1.

For the unstable distribution (sid), this problem has been fixed in version 7.0.70-1.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java-doc", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-admin", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-common", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-docs", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-examples", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-user", ver:"7.0.56-3+deb8u3", rls:"DEB8"))) {
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
