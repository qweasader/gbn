# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5522");
  script_cve_id("CVE-2023-24998", "CVE-2023-41080", "CVE-2023-42795", "CVE-2023-44487", "CVE-2023-45648");
  script_tag(name:"creation_date", value:"2023-10-12 04:35:23 +0000 (Thu, 12 Oct 2023)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5522-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5522-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5522-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5522");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tomcat9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat9' package(s) announced via the DSA-5522-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat servlet and JSP engine.

CVE-2023-24998

Denial of service. Tomcat uses a packaged renamed copy of Apache Commons FileUpload to provide the file upload functionality defined in the Jakarta Servlet specification. Apache Tomcat was, therefore, also vulnerable to the Commons FileUpload vulnerability CVE-2023-24998 as there was no limit to the number of request parts processed. This resulted in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads.

CVE-2023-41080

Open redirect. If the ROOT (default) web application is configured to use FORM authentication then it is possible that a specially crafted URL could be used to trigger a redirect to an URL of the attackers choice.

CVE-2023-42795

Information Disclosure. When recycling various internal objects, including the request and the response, prior to re-use by the next request/response, an error could cause Tomcat to skip some parts of the recycling process leading to information leaking from the current request/response to the next.

CVE-2023-44487

DoS caused by HTTP/2 frame overhead (Rapid Reset Attack)

CVE-2023-45648

Request smuggling. Tomcat did not correctly parse HTTP trailer headers. A specially crafted, invalid trailer header could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

For the oldstable distribution (bullseye), these problems have been fixed in version 9.0.43-2~deb11u7.

We recommend that you upgrade your tomcat9 packages.

For the detailed security status of tomcat9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-admin", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-docs", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-examples", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-user", ver:"9.0.43-2~deb11u7", rls:"DEB11"))) {
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
