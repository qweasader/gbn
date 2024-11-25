# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5386");
  script_cve_id("CVE-2023-1810", "CVE-2023-1811", "CVE-2023-1812", "CVE-2023-1813", "CVE-2023-1814", "CVE-2023-1815", "CVE-2023-1816", "CVE-2023-1817", "CVE-2023-1818", "CVE-2023-1819", "CVE-2023-1820", "CVE-2023-1821", "CVE-2023-1822", "CVE-2023-1823", "CVE-2023-2311", "CVE-2023-2313");
  script_tag(name:"creation_date", value:"2023-04-13 04:27:00 +0000 (Thu, 13 Apr 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 16:49:52 +0000 (Thu, 03 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5386-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5386-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5386");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-5386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result in the execution of arbitrary code, denial of service or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 112.0.5615.49-2~deb11u2.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"112.0.5615.49-2~deb11u2", rls:"DEB11"))) {
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
