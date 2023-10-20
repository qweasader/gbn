# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844448");
  script_cve_id("CVE-2019-19377", "CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12657");
  script_tag(name:"creation_date", value:"2020-05-29 03:00:28 +0000 (Fri, 29 May 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 00:15:00 +0000 (Fri, 11 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4369-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4369-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4369-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1879690");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-raspi2, linux-raspi2-5.3' package(s) announced via the USN-4369-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4369-1 fixed vulnerabilities in the 5.3 Linux kernel. Unfortunately,
that update introduced a regression in overlayfs. This update corrects
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the btrfs implementation in the Linux kernel did not
 properly detect that a block was marked dirty in some situations. An
 attacker could use this to specially craft a file system image that, when
 unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

 Tristan Madani discovered that the file locking implementation in the Linux
 kernel contained a race condition. A local attacker could possibly use this
 to cause a denial of service or expose sensitive information.
 (CVE-2019-19769)

 It was discovered that the Serial CAN interface driver in the Linux kernel
 did not properly initialize data. A local attacker could use this to expose
 sensitive information (kernel memory). (CVE-2020-11494)

 It was discovered that the linux kernel did not properly validate certain
 mount options to the tmpfs virtual memory file system. A local attacker
 with the ability to specify mount options could use this to cause a denial
 of service (system crash). (CVE-2020-11565)

 It was discovered that the OV51x USB Camera device driver in the Linux
 kernel did not properly validate device metadata. A physically proximate
 attacker could use this to cause a denial of service (system crash).
 (CVE-2020-11608)

 It was discovered that the STV06XX USB Camera device driver in the Linux
 kernel did not properly validate device metadata. A physically proximate
 attacker could use this to cause a denial of service (system crash).
 (CVE-2020-11609)

 It was discovered that the Xirlink C-It USB Camera device driver in the
 Linux kernel did not properly validate device metadata. A physically
 proximate attacker could use this to cause a denial of service (system
 crash). (CVE-2020-11668)

 It was discovered that the block layer in the Linux kernel contained a race
 condition leading to a use-after-free vulnerability. A local attacker could
 possibly use this to cause a denial of service (system crash) or execute
 arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-raspi2, linux-raspi2-5.3' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1026-raspi2", ver:"5.3.0-1026.28~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2-hwe-18.04", ver:"5.3.0.1026.15", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1026-raspi2", ver:"5.3.0-1026.28", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-55-generic", ver:"5.3.0-55.49", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-55-generic-lpae", ver:"5.3.0-55.49", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-55-lowlatency", ver:"5.3.0-55.49", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-55-snapdragon", ver:"5.3.0-55.49", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.3.0.55.47", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.3.0.55.47", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.3.0.55.47", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.3.0.1026.23", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"5.3.0.55.47", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.3.0.55.47", rls:"UBUNTU19.10"))) {
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
