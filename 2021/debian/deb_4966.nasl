# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704966");
  script_cve_id("CVE-2021-21834", "CVE-2021-21836", "CVE-2021-21837", "CVE-2021-21838", "CVE-2021-21839", "CVE-2021-21840", "CVE-2021-21841", "CVE-2021-21842", "CVE-2021-21843", "CVE-2021-21844", "CVE-2021-21845", "CVE-2021-21846", "CVE-2021-21847", "CVE-2021-21848", "CVE-2021-21849", "CVE-2021-21850", "CVE-2021-21853", "CVE-2021-21854", "CVE-2021-21855", "CVE-2021-21857", "CVE-2021-21858", "CVE-2021-21859", "CVE-2021-21860", "CVE-2021-21861");
  script_tag(name:"creation_date", value:"2021-09-02 01:00:28 +0000 (Thu, 02 Sep 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 17:30:00 +0000 (Tue, 24 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-4966)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-4966");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4966");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4966");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gpac");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gpac' package(s) announced via the DSA-4966 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the GPAC multimedia framework which could result in denial of service or the execution of arbitrary code.

The oldstable distribution (buster) is not affected.

For the stable distribution (bullseye), these problems have been fixed in version 1.0.1+dfsg1-4+deb11u1.

We recommend that you upgrade your gpac packages.

For the detailed security status of gpac please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gpac' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gpac", ver:"1.0.1+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpac-modules-base", ver:"1.0.1+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgpac-dev", ver:"1.0.1+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgpac10", ver:"1.0.1+dfsg1-4+deb11u1", rls:"DEB11"))) {
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
