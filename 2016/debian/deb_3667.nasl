# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703667");
  script_cve_id("CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173", "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-5176", "CVE-2016-7395", "CVE-2016-7549");
  script_tag(name:"creation_date", value:"2016-09-14 22:00:00 +0000 (Wed, 14 Sep 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3667)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3667");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3667");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3667");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3667 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-5170

A use-after-free issue was discovered in Blink/Webkit.

CVE-2016-5171

Another use-after-free issue was discovered in Blink/Webkit.

CVE-2016-5172

Choongwoo Han discovered an information leak in the v8 javascript library.

CVE-2016-5173

A resource bypass issue was discovered in extensions.

CVE-2016-5174

Andrey Kovalev discovered a way to bypass the popup blocker.

CVE-2016-5175

The chrome development team found and fixed various issues during internal auditing.

CVE-2016-7395

An uninitialized memory read issue was discovered in the skia library.

For the stable distribution (jessie), these problems have been fixed in version 53.0.2785.113-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 53.0.2785.113-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"53.0.2785.113-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"53.0.2785.113-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"53.0.2785.113-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"53.0.2785.113-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"53.0.2785.113-1~deb8u1", rls:"DEB8"))) {
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
