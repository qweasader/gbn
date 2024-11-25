# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842575");
  script_cve_id("CVE-2015-7799", "CVE-2015-7885", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2015-12-18 04:44:59 +0000 (Fri, 18 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:45:46 +0000 (Mon, 28 Dec 2015)");

  script_name("Ubuntu: Security Advisory (USN-2844-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2844-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2844-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2844-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Beulich discovered that the KVM svm hypervisor implementation in the
Linux kernel did not properly catch Debug exceptions on AMD processors. An
attacker in a guest virtual machine could use this to cause a denial of
service (system crash) in the host OS. (CVE-2015-8104)

Guo Yong Gang discovered that the ppp implementation in the Linux kernel did
not ensure that certain slot numbers are valid. A local attacker with the
privilege to call ioctl() on /dev/ppp could cause a denial of service
(system crash). (CVE-2015-7799)

It was discovered that the driver for Digi Neo and ClassicBoard devices did
not properly initialize data structures. A local attacker could use this to
obtain sensitive information from the kernel. (CVE-2015-7885)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-generic", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-generic-lpae", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-lowlatency", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-powerpc-e500mc", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-powerpc-smp", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-powerpc64-emb", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-56-powerpc64-smp", ver:"3.16.0-56.75~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
