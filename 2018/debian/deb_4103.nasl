# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704103");
  script_cve_id("CVE-2017-15420", "CVE-2017-15429", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054", "CVE-2018-6055", "CVE-2018-6119");
  script_tag(name:"creation_date", value:"2018-01-30 23:00:00 +0000 (Tue, 30 Jan 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 16:33:00 +0000 (Tue, 20 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4103-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4103-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4103");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-4103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-15420

Drew Springall discovered a URL spoofing issue.

CVE-2017-15429

A cross-site scripting issue was discovered in the v8 javascript library.

CVE-2018-6031

A use-after-free issue was discovered in the pdfium library.

CVE-2018-6032

Jun Kokatsu discovered a way to bypass the same origin policy.

CVE-2018-6033

Juho Nurminen discovered a race condition when opening downloaded files.

CVE-2018-6034

Tobias Klein discovered an integer overflow issue.

CVE-2018-6035

Rob Wu discovered a way for extensions to access devtools.

CVE-2018-6036

UK's National Cyber Security Centre discovered an integer overflow issue.

CVE-2018-6037

Paul Stone discovered an issue in the autofill feature.

CVE-2018-6038

cloudfuzzer discovered a buffer overflow issue.

CVE-2018-6039

Juho Nurminen discovered a cross-site scripting issue in the developer tools.

CVE-2018-6040

WenXu Wu discovered a way to bypass the content security policy.

CVE-2018-6041

Luan Herrera discovered a URL spoofing issue.

CVE-2018-6042

Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6043

A character escaping issue was discovered.

CVE-2018-6045

Rob Wu discovered a way for extensions to access devtools.

CVE-2018-6046

Rob Wu discovered a way for extensions to access devtools.

CVE-2018-6047

Masato Kinugawa discovered an information leak issue.

CVE-2018-6048

Jun Kokatsu discovered a way to bypass the referrer policy.

CVE-2018-6049

WenXu Wu discovered a user interface spoofing issue.

CVE-2018-6050

Jonathan Kew discovered a URL spoofing issue.

CVE-2018-6051

Antonio Sanso discovered an information leak issue.

CVE-2018-6052

Tanner Emek discovered that the referrer policy implementation was incomplete.

CVE-2018-6053

Asset Kabdenov discovered an information leak issue.

CVE-2018-6054

Rob Wu discovered a use-after-free issue.

For the oldstable distribution (jessie), security support for chromium has been discontinued.

For the stable distribution (stretch), these problems have been fixed in version 64.0.3282.119-1~deb9u1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"64.0.3282.119-1~deb9u1", rls:"DEB9"))) {
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
