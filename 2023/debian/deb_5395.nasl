# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5395");
  script_cve_id("CVE-2023-23920");
  script_tag(name:"creation_date", value:"2023-05-03 04:24:42 +0000 (Wed, 03 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:06:26 +0000 (Fri, 03 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-5395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5395-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5395-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5395");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nodejs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nodejs' package(s) announced via the DSA-5395-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An untrusted search path vulnerability was discovered in Node.js, which could result in unexpected searching or loading ICU data when running with elevated privileges.

For the stable distribution (bullseye), this problem has been fixed in version 12.22.12~dfsg-1~deb11u4.

We recommend that you upgrade your nodejs packages.

For the detailed security status of nodejs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'nodejs' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"12.22.12~dfsg-1~deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.12~dfsg-1~deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.12~dfsg-1~deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"12.22.12~dfsg-1~deb11u4", rls:"DEB11"))) {
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
