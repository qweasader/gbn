# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704892");
  script_cve_id("CVE-2021-23980");
  script_tag(name:"creation_date", value:"2021-04-19 03:00:04 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 15:19:00 +0000 (Mon, 27 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-4892)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4892");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4892");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4892");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python-bleach");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-bleach' package(s) announced via the DSA-4892 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that python-bleach, a whitelist-based HTML-sanitizing library, is prone to a mutation XSS vulnerability in bleach.clean when svg or math are in the allowed tags, 'p' or br are in allowed tags, style, title, noscript, script, textarea, noframes, iframe, or xmp are in allowed tags and 'strip_comments=False' is set.

For the stable distribution (buster), this problem has been fixed in version 3.1.2-0+deb10u2.

We recommend that you upgrade your python-bleach packages.

For the detailed security status of python-bleach please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'python-bleach' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach-doc", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-bleach", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
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
