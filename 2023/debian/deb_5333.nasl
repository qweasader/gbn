# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705333");
  script_cve_id("CVE-2022-1354", "CVE-2022-1355", "CVE-2022-1622", "CVE-2022-1623", "CVE-2022-2056", "CVE-2022-2057", "CVE-2022-2058", "CVE-2022-2519", "CVE-2022-2520", "CVE-2022-2521", "CVE-2022-2867", "CVE-2022-2868", "CVE-2022-2869", "CVE-2022-2953", "CVE-2022-34526", "CVE-2022-3570", "CVE-2022-3597", "CVE-2022-3598", "CVE-2022-3599", "CVE-2022-3626", "CVE-2022-3627", "CVE-2022-3636", "CVE-2022-3970", "CVE-2022-4645", "CVE-2022-48281");
  script_tag(name:"creation_date", value:"2023-01-30 02:00:27 +0000 (Mon, 30 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-06 17:53:10 +0000 (Fri, 06 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5333-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5333-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5333");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tiff");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-5333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several buffer overflow, divide by zero or out of bounds read/write vulnerabilities were discovered in tiff, the Tag Image File Format (TIFF) library and tools, which may cause denial of service when processing a crafted TIFF image.

For the stable distribution (bullseye), these problems have been fixed in version 4.2.0-1+deb11u3.

We recommend that you upgrade your tiff packages.

For the detailed security status of tiff please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-dev", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.2.0-1+deb11u3", rls:"DEB11"))) {
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
