# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703361");
  script_cve_id("CVE-2015-5278", "CVE-2015-5279", "CVE-2015-6815", "CVE-2015-6855");
  script_tag(name:"creation_date", value:"2015-09-17 22:00:00 +0000 (Thu, 17 Sep 2015)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-15 17:05:00 +0000 (Wed, 15 Dec 2021)");

  script_name("Debian: Security Advisory (DSA-3361-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3361-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3361-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3361");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-3361-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in qemu, a fast processor emulator.

CVE-2015-5278

Qinghao Tang of QIHU 360 Inc. discovered an infinite loop issue in the NE2000 NIC emulation. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash).

CVE-2015-5279

Qinghao Tang of QIHU 360 Inc. discovered a heap buffer overflow flaw in the NE2000 NIC emulation. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash), or potentially to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-6815

Qinghao Tang of QIHU 360 Inc. discovered an infinite loop issue in the e1000 NIC emulation. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash).

CVE-2015-6855

Qinghao Tang of QIHU 360 Inc. discovered a flaw in the IDE subsystem in QEMU occurring while executing IDE's WIN_READ_NATIVE_MAX command to determine the maximum size of a drive. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash).

For the oldstable distribution (wheezy), these problems have been fixed in version 1.1.2+dfsg-6a+deb7u11.

For the stable distribution (jessie), these problems have been fixed in version 1:2.1+dfsg-12+deb8u4.

For the testing distribution (stretch), these problems have been fixed in version 1:2.4+dfsg-3 or earlier.

For the unstable distribution (sid), these problems have been fixed in version 1:2.4+dfsg-3 or earlier.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u4", rls:"DEB8"))) {
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
