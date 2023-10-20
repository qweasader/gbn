# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2009.1962");
  script_cve_id("CVE-2009-3638", "CVE-2009-3722", "CVE-2009-4031");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1962)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1962");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1962");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1962");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kvm' package(s) announced via the DSA-1962 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in kvm, a full virtualization system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3638

It was discovered an Integer overflow in the kvm_dev_ioctl_get_supported_cpuid function. This allows local users to have an unspecified impact via a KVM_GET_SUPPORTED_CPUID request to the kvm_arch_dev_ioctl function.

CVE-2009-3722

It was discovered that the handle_dr function in the KVM subsystem does not properly verify the Current Privilege Level (CPL) before accessing a debug register, which allows guest OS users to cause a denial of service (trap) on the host OS via a crafted application.

CVE-2009-4031

It was discovered that the do_insn_fetch function in the x86 emulator in the KVM subsystem tries to interpret instructions that contain too many bytes to be valid, which allows guest OS users to cause a denial of service (increased scheduling latency) on the host OS via unspecified manipulations related to SMP support.

For the stable distribution (lenny), these problems have been fixed in version 72+dfsg-5~lenny4.

For the testing distribution (squeeze), and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your kvm package.");

  script_tag(name:"affected", value:"'kvm' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-5~lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-5~lenny4", rls:"DEB5"))) {
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
