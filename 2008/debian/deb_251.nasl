# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53326");
  script_cve_id("CVE-2002-1335", "CVE-2002-1348");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-251");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-251");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-251");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'w3m' package(s) announced via the DSA-251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hironori Sakamoto, one of the w3m developers, found two security vulnerabilities in w3m and associated programs. The w3m browser does not properly escape HTML tags in frame contents and img alt attributes. A malicious HTML frame or img alt attribute may deceive a user to send their local cookies which are used for configuration. The information is not leaked automatically, though.

For the stable distribution (woody) these problems have been fixed in version 0.3-2.4.

The old stable distribution (potato) is not affected by these problems.

For the unstable distribution (sid) these problems have been fixed in version 0.3.2.2-1 and later.

We recommend that you upgrade your w3m and w3m-ssl packages.");

  script_tag(name:"affected", value:"'w3m' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"w3m", ver:"0.3-2.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"w3m-img", ver:"0.3-2.4", rls:"DEB3.0"))) {
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
