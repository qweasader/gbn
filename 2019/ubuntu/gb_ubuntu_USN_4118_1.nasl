# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844159");
  script_cve_id("CVE-2018-13053", "CVE-2018-13093", "CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13098", "CVE-2018-13099", "CVE-2018-13100", "CVE-2018-14609", "CVE-2018-14610", "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2018-14614", "CVE-2018-14615", "CVE-2018-14616", "CVE-2018-14617", "CVE-2018-16862", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-20511", "CVE-2018-20784", "CVE-2018-20856", "CVE-2018-5383", "CVE-2019-0136", "CVE-2019-10126", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11085", "CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11810", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-13631", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-14763", "CVE-2019-15090", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15218", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-2024", "CVE-2019-2101", "CVE-2019-3701", "CVE-2019-3819", "CVE-2019-3846", "CVE-2019-3900", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2019-09-03 02:02:11 +0000 (Tue, 03 Sep 2019)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 14:08:00 +0000 (Wed, 19 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-4118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4118-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4118-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-aws-hwe' package(s) announced via the USN-4118-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the alarmtimer implementation in the Linux kernel
contained an integer overflow vulnerability. A local attacker could use
this to cause a denial of service. (CVE-2018-13053)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly track inode validations. An attacker could use this
to construct a malicious XFS image that, when mounted, could cause a denial
of service (system crash). (CVE-2018-13093)

Wen Xu discovered that the f2fs file system implementation in the Linux
kernel did not properly validate metadata. An attacker could use this to
construct a malicious f2fs image that, when mounted, could cause a denial
of service (system crash). (CVE-2018-13096, CVE-2018-13097, CVE-2018-13098,
CVE-2018-13099, CVE-2018-13100, CVE-2018-14614, CVE-2018-14615,
CVE-2018-14616)

Wen Xu and Po-Ning Tseng discovered that btrfs file system implementation
in the Linux kernel did not properly validate metadata. An attacker could
use this to construct a malicious btrfs image that, when mounted, could
cause a denial of service (system crash). (CVE-2018-14609, CVE-2018-14610,
CVE-2018-14611, CVE-2018-14612, CVE-2018-14613)

Wen Xu discovered that the HFS+ filesystem implementation in the Linux
kernel did not properly handle malformed catalog data in some situations.
An attacker could use this to construct a malicious HFS+ image that, when
mounted, could cause a denial of service (system crash). (CVE-2018-14617)

Vasily Averin and Pavel Tikhomirov discovered that the cleancache subsystem
of the Linux kernel did not properly initialize new files in some
situations. A local attacker could use this to expose sensitive
information. (CVE-2018-16862)

Hui Peng and Mathias Payer discovered that the Option USB High Speed driver
in the Linux kernel did not properly validate metadata received from the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2018-19985)

Hui Peng and Mathias Payer discovered that the USB subsystem in the Linux
kernel did not properly handle size checks when handling an extra USB
descriptor. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2018-20169)

Zhipeng Xie discovered that an infinite loop could be triggered in the CFS
Linux kernel process scheduler. A local attacker could possibly use this to
cause a denial of service. (CVE-2018-20784)

It was discovered that a use-after-free error existed in the block layer
subsystem of the Linux kernel when certain failure conditions occurred. A
local attacker could possibly use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-20856)

Eli Biham and Lior Neumann discovered that the Bluetooth implementation in
the Linux kernel did not properly validate elliptic curve parameters during
Diffie-Hellman key exchange in some ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws, linux-aws-hwe' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1047-aws", ver:"4.15.0-1047.49~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1047.47", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1047-aws", ver:"4.15.0-1047.49", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.15.0.1047.46", rls:"UBUNTU18.04 LTS"))) {
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
