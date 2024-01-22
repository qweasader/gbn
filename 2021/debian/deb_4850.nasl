# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704850");
  script_cve_id("CVE-2021-24031");
  script_tag(name:"creation_date", value:"2021-02-11 04:00:04 +0000 (Thu, 11 Feb 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 15:28:00 +0000 (Wed, 14 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4850-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4850-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4850-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4850");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libzstd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libzstd' package(s) announced via the DSA-4850-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that zstd, a compression utility, temporarily exposed a world-readable version of its input even if the original file had restrictive permissions.

For the stable distribution (buster), this problem has been fixed in version 1.3.8+dfsg-3+deb10u1.

We recommend that you upgrade your libzstd packages.

For the detailed security status of libzstd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libzstd' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libzstd-dev", ver:"1.3.8+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzstd1", ver:"1.3.8+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzstd1-udeb", ver:"1.3.8+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zstd", ver:"1.3.8+dfsg-3+deb10u1", rls:"DEB10"))) {
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
