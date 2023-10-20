# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841312");
  script_cve_id("CVE-2012-2669", "CVE-2012-4508", "CVE-2012-5532", "CVE-2013-0190");
  script_tag(name:"creation_date", value:"2013-02-15 05:55:03 +0000 (Fri, 15 Feb 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1720-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1720-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1720-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1720-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that hypervkvpd, which is distributed in the Linux
kernel, was not correctly validating the origin on Netlink messages. An
untrusted local user can cause a denial of service of Linux guests in
Hyper-V virtualization environments. (CVE-2012-2669)

Dmitry Monakhov reported a race condition flaw the Linux ext4 filesystem
that can expose stale data. An unprivileged user could exploit this flaw to
cause an information leak. (CVE-2012-4508)

Florian Weimer discovered that hypervkvpd, which is distributed in the
Linux kernel, was not correctly validating source addresses of netlink
packets. An untrusted local user can cause a denial of service by causing
hypervkvpd to exit. (CVE-2012-5532)

Andrew Cooper of Citrix reported a Xen stack corruption in the Linux
kernel. An unprivileged user in a 32bit PVOPS guest can cause the guest
kernel to crash, or operate erroneously. (CVE-2013-0190)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-generic", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-generic-pae", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-omap", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc-smp", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc64-smp", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-server", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-31-virtual", ver:"3.0.0-31.48", rls:"UBUNTU11.10"))) {
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
