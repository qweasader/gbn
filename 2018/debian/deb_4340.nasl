# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704340");
  script_cve_id("CVE-2018-17478");
  script_tag(name:"creation_date", value:"2018-11-17 23:00:00 +0000 (Sat, 17 Nov 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-28 16:25:00 +0000 (Fri, 28 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4340");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4340");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4340");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-4340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds bounds memory access issue was discovered in chromium's v8 javascript library by cloudfuzzer.

This update also fixes two problems introduced by the previous security upload. Support for arm64 has been restored and gconf-service is no longer a package dependency.

For the stable distribution (stretch), this problem has been fixed in version 70.0.3538.102-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"70.0.3538.102-1~deb9u1", rls:"DEB9"))) {
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
