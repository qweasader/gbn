# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843840");
  script_cve_id("CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18445", "CVE-2018-18653", "CVE-2018-18955", "CVE-2018-6559");
  script_tag(name:"creation_date", value:"2018-12-04 07:10:51 +0000 (Tue, 04 Dec 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.10");

  script_xref(name:"Advisory-ID", value:"USN-3832-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3832-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-3832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the procfs file system implementation in the
Linux kernel did not properly restrict the ability to inspect the kernel
stack of an arbitrary task. A local attacker could use this to expose
sensitive information. (CVE-2018-17972)

Jann Horn discovered that the mremap() system call in the Linux kernel did
not properly flush the TLB when completing, potentially leaving access to a
physical page after it has been released to the page allocator. A local
attacker could use this to cause a denial of service (system crash), expose
sensitive information, or possibly execute arbitrary code. (CVE-2018-18281)

It was discovered that the BPF verifier in the Linux kernel did not
correctly compute numeric bounds in some situations. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-18445)

Daniel Dadap discovered that the module loading implementation in the Linux
kernel did not properly enforce signed module loading when booted with UEFI
Secure Boot in some situations. A local privileged attacker could use this
to execute untrusted code in the kernel. (CVE-2018-18653)

Jann Horn discovered that the Linux kernel mishandles mapping UID or GID
ranges inside nested user namespaces in some situations. A local attacker
could use this to bypass access controls on resources outside the
namespace. (CVE-2018-18955)

Philipp Wendler discovered that the overlayfs implementation in the Linux
kernel did not properly verify the directory contents permissions from
within a unprivileged user namespace. A local attacker could use this to
expose sensitive information (protected file names). (CVE-2018-6559)");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 18.10.");

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

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1006-aws", ver:"4.18.0-1006.7", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.18.0.1006.6", rls:"UBUNTU18.10"))) {
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
