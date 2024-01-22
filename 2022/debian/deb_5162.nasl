# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705162");
  script_cve_id("CVE-2022-24769", "CVE-2022-31030");
  script_tag(name:"creation_date", value:"2022-06-14 01:00:11 +0000 (Tue, 14 Jun 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 18:35:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5162-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5162-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5162");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/containerd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'containerd' package(s) announced via the DSA-5162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the containerd container runtime, which could result in denial of service or incomplete restriction of capabilities.

For the stable distribution (bullseye), these problems have been fixed in version 1.4.13~ds1-1~deb11u2.

We recommend that you upgrade your containerd packages.

For the detailed security status of containerd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'containerd' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"containerd", ver:"1.4.13~ds1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-containerd-containerd-dev", ver:"1.4.13~ds1-1~deb11u2", rls:"DEB11"))) {
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
