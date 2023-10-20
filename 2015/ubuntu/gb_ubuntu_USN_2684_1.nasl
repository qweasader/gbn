# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842451");
  script_cve_id("CVE-2015-4692", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2015-09-18 08:43:41 +0000 (Fri, 18 Sep 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2684-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.04");

  script_xref(name:"Advisory-ID", value:"USN-2684-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2684-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2684-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the kvm (kernel virtual machine) subsystem's
kvm_apic_has_events function. A unprivileged local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2015-4692)

Daniel Borkmann reported a kernel crash in the Linux kernel's BPF filter
JIT optimization. A local attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2015-4700)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker could exploit this flaw to cause a denial of
service using a flood of UDP packets with invalid checksums.
(CVE-2015-5364)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker can cause a denial of service against
applications that use epoll by injecting a single packet with an invalid
checksum. (CVE-2015-5366)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.04.");

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

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-generic", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-generic-lpae", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-lowlatency", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-powerpc-e500mc", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-powerpc-smp", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-powerpc64-emb", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-23-powerpc64-smp", ver:"3.19.0-23.24", rls:"UBUNTU15.04"))) {
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
