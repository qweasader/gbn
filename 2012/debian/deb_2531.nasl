# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71820");
  script_cve_id("CVE-2012-3432", "CVE-2012-3433");
  script_tag(name:"creation_date", value:"2012-08-30 15:32:13 +0000 (Thu, 30 Aug 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2531");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2531");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2531");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several denial-of-service vulnerabilities have been discovered in Xen, the popular virtualization software. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2012-3432

Guest mode unprivileged code, which has been granted the privilege to access MMIO regions, may leverage that access to crash the whole guest. Since this can be used to crash a client from within, this vulnerability is considered to have low impact.

CVE-2012-3433

A guest kernel can cause the host to become unresponsive for a period of time, potentially leading to a DoS. Since an attacker with full control in the guest can impact the host, this vulnerability is considered to have high impact.

For the stable distribution (squeeze), this problem has been fixed in version 4.0.1-5.3.

For the unstable distribution (sid), this problem has been fixed in version 4.1.3-1.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.3", rls:"DEB6"))) {
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
