# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704210");
  script_cve_id("CVE-2018-3639");
  script_tag(name:"creation_date", value:"2018-05-24 22:00:00 +0000 (Thu, 24 May 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:51:06 +0000 (Wed, 14 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4210-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4210-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4210");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-263.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides mitigations for the Spectre v4 variant in x86-based micro processors. On Intel CPUs this requires updated microcode which is currently not released publicly (but your hardware vendor may have issued an update). For servers with AMD CPUs no microcode update is needed, please refer to [link moved to references] for further information.

For the stable distribution (stretch), this problem has been fixed in version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls:"DEB9"))) {
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
