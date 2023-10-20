# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56462");
  script_cve_id("CVE-2005-1120");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1010");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1010");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1010");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ilohamail' package(s) announced via the DSA-1010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar from the Debian Security Audit Project discovered that ilohamail, a lightweight multilingual web-based IMAP/POP3 client, does not always sanitise input provided by users which allows remote attackers to inject arbitrary web script or HTML.

The old stable distribution (woody) does not contain an ilohamail package.

For the stable distribution (sarge) these problems have been fixed in version 0.8.14-0rc3sarge1.

For the unstable distribution (sid) these problems have been fixed in version 0.8.14-0rc3sarge1.

We recommend that you upgrade your ilohamail package.");

  script_tag(name:"affected", value:"'ilohamail' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ilohamail", ver:"0.8.14-0rc3sarge1", rls:"DEB3.1"))) {
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
