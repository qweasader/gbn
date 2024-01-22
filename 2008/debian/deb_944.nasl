# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56188");
  script_cve_id("CVE-2005-4238", "CVE-2005-4518", "CVE-2005-4519", "CVE-2005-4520", "CVE-2005-4521", "CVE-2005-4522", "CVE-2005-4523", "CVE-2005-4524", "CVE-2006-0840");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-944-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-944-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-944");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mantis, a web-based bug tracking system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4238

Missing input sanitising allows remote attackers to inject arbitrary web script or HTML.

CVE-2005-4518

Tobias Klein discovered that Mantis allows remote attackers to bypass the file upload size restriction.

CVE-2005-4519

Tobias Klein discovered several SQL injection vulnerabilities that allow remote attackers to execute arbitrary SQL commands.

CVE-2005-4520

Tobias Klein discovered unspecified 'port injection' vulnerabilities in filters.

CVE-2005-4521

Tobias Klein discovered a CRLF injection vulnerability that allows remote attackers to modify HTTP headers and conduct HTTP response splitting attacks.

CVE-2005-4522

Tobias Klein discovered several cross-site scripting (XSS) vulnerabilities that allow remote attackers to inject arbitrary web script or HTML.

CVE-2005-4523

Tobias Klein discovered that Mantis discloses private bugs via public RSS feeds, which allows remote attackers to obtain sensitive information.

CVE-2005-4524

Tobias Klein discovered that Mantis does not properly handle 'Make note private' when a bug is being resolved, which has unknown impact and attack vectors, probably related to an information leak.

The old stable distribution (woody) does not seem to be affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 0.19.2-5sarge1.

For the unstable distribution (sid) these problems have been fixed in version 0.19.4-1.

We recommend that you upgrade your mantis package.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"mantis", ver:"0.19.2-5sarge1", rls:"DEB3.1"))) {
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
