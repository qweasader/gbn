# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840280");
  script_cve_id("CVE-2007-4571", "CVE-2007-5904", "CVE-2007-6694", "CVE-2008-0007", "CVE-2008-1294", "CVE-2008-1375", "CVE-2008-1669");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-618-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-618-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-backports-modules-2.6.15, linux-backports-modules-2.6.20, linux-backports-modules-2.6.22, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.20, linux-restricted-modules-2.6.22, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22, linux-ubuntu-modules-2.6.22' package(s) announced via the USN-618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ALSA /proc interface did not write the
correct number of bytes when reporting memory allocations. A local
attacker might be able to access sensitive kernel memory, leading to
a loss of privacy. (CVE-2007-4571)

Multiple buffer overflows were discovered in the handling of CIFS
filesystems. A malicious CIFS server could cause a client system crash
or possibly execute arbitrary code with kernel privileges. (CVE-2007-5904)

It was discovered that PowerPC kernels did not correctly handle reporting
certain system details. By requesting a specific set of information,
a local attacker could cause a system crash resulting in a denial
of service. (CVE-2007-6694)

It was discovered that some device driver fault handlers did not
correctly verify memory ranges. A local attacker could exploit this
to access sensitive kernel memory, possibly leading to a loss of privacy.
(CVE-2008-0007)

It was discovered that CPU resource limits could be bypassed.
A malicious local user could exploit this to avoid administratively
imposed resource limits. (CVE-2008-1294)

A race condition was discovered between dnotify fcntl() and close() in
the kernel. If a local attacker performed malicious dnotify requests,
they could cause memory consumption leading to a denial of service,
or possibly send arbitrary signals to any process. (CVE-2008-1375)

On SMP systems, a race condition existed in fcntl(). Local attackers
could perform malicious locks, causing system crashes and leading to
a denial of service. (CVE-2008-1669)");

  script_tag(name:"affected", value:"'linux-backports-modules-2.6.15, linux-backports-modules-2.6.20, linux-backports-modules-2.6.22, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.20, linux-restricted-modules-2.6.22, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22, linux-ubuntu-modules-2.6.22' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-386", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-686", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-amd64-generic", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-amd64-k8", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-amd64-server", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-amd64-xeon", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-hppa32", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-hppa32-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-hppa64", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-hppa64-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-itanium", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-itanium-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-k7", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-mckinley", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-mckinley-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-powerpc", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-powerpc-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-powerpc64-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-server", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-server-bigiron", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-sparc64", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-52-sparc64-smp", ver:"2.6.15-52.67", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-386", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-generic", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-hppa32", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-hppa64", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-itanium", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-lowlatency", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-mckinley", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-powerpc", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-powerpc-smp", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-powerpc64-smp", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-server", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-server-bigiron", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-sparc64", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-17-sparc64-smp", ver:"2.6.20-17.36", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-386", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-cell", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-generic", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-hppa32", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-hppa64", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-itanium", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-lpia", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-lpiacompat", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-mckinley", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-powerpc", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-powerpc-smp", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-powerpc64-smp", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-rt", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-server", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-sparc64", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-sparc64-smp", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-ume", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-virtual", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-15-xen", ver:"2.6.22-15.54", rls:"UBUNTU7.10"))) {
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
