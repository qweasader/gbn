# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705148");
  script_cve_id("CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856", "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860", "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864", "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868", "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872", "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876", "CVE-2022-4918");
  script_tag(name:"creation_date", value:"2022-05-28 01:00:21 +0000 (Sat, 28 May 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 12:36:00 +0000 (Wed, 03 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5148-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5148-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5148");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-5148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result in the execution of arbitrary code, denial of service or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 102.0.5005.61-1~deb11u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"102.0.5005.61-1~deb11u1", rls:"DEB11"))) {
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
