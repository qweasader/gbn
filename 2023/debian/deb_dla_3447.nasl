# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3447");
  script_cve_id("CVE-2023-28755", "CVE-2023-28756");
  script_tag(name:"creation_date", value:"2023-06-07 04:20:59 +0000 (Wed, 07 Jun 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 17:17:00 +0000 (Tue, 30 May 2023)");

  script_name("Debian: Security Advisory (DLA-3447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3447-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3447-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.5' package(s) announced via the DLA-3447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two regular expression Denial of Service (ReDoS) issues were discovered in Ruby: the first in the URI component, and the second in the Time module. Each of these issues could have resulted in a dramatic increase in execution time given malicious input.

CVE-2023-28755

A ReDoS issue was discovered in the URI component through 0.12.0 in Ruby through 3.2.1. The URI parser mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing strings to URI objects. The fixed versions are 0.12.1, 0.11.1, 0.10.2 and 0.10.0.1.

CVE-2023-28756

A ReDoS issue was discovered in the Time component through 0.2.1 in Ruby through 3.2.1. The Time parser mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing strings to Time objects. The fixed versions are 0.1.1 and 0.2.2.

For Debian 10 Buster, these problems have been fixed in version 2.5.5-3+deb10u5.

We recommend that you upgrade your ruby2.5 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.5-3+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.5-3+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-dev", ver:"2.5.5-3+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-doc", ver:"2.5.5-3+deb10u5", rls:"DEB10"))) {
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
