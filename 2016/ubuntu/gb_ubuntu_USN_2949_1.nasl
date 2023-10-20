# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842707");
  script_cve_id("CVE-2015-8812", "CVE-2016-2085", "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-04-07 03:00:55 +0000 (Thu, 07 Apr 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-2949-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2949-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2949-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-vivid' package(s) announced via the USN-2949-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
kernel's CXGB3 driver. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

Xiaofei Rex Guo discovered a timing side channel vulnerability in the Linux
Extended Verification Module (EVM). An attacker could use this to affect
system integrity. (CVE-2016-2085)

David Herrmann discovered that the Linux kernel incorrectly accounted file
descriptors to the original opener for in-flight file descriptors sent over
a unix domain socket. A local attacker could use this to cause a denial of
service (resource exhaustion). (CVE-2016-2550)

It was discovered that the Linux kernel did not enforce limits on the
amount of data allocated to buffer pipes. A local attacker could use this
to cause a denial of service (resource exhaustion). (CVE-2016-2847)");

  script_tag(name:"affected", value:"'linux-lts-vivid' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-generic", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-generic-lpae", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-lowlatency", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-powerpc-e500mc", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-powerpc-smp", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-powerpc64-emb", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-58-powerpc64-smp", ver:"3.19.0-58.64~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
