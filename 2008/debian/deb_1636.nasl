# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61594");
  script_cve_id("CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3276", "CVE-2008-3526", "CVE-2008-3534", "CVE-2008-3535", "CVE-2008-3792", "CVE-2008-3915");
  script_tag(name:"creation_date", value:"2008-09-17 02:23:15 +0000 (Wed, 17 Sep 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:36:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1636)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1636");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1636");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1636");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6.24' package(s) announced via the DSA-1636 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or leak sensitive data. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3272

Tobias Klein reported a locally exploitable data leak in the snd_seq_oss_synth_make_info() function. This may allow local users to gain access to sensitive information.

CVE-2008-3275

Zoltan Sogor discovered a coding error in the VFS that allows local users to exploit a kernel memory leak resulting in a denial of service.

CVE-2008-3276

Eugene Teo reported an integer overflow in the DCCP subsystem that may allow remote attackers to cause a denial of service in the form of a kernel panic.

CVE-2008-3526

Eugene Teo reported a missing bounds check in the SCTP subsystem. By exploiting an integer overflow in the SCTP_AUTH_KEY handling code, remote attackers may be able to cause a denial of service in the form of a kernel panic.

CVE-2008-3534

Kel Modderman reported an issue in the tmpfs filesystem that allows local users to crash a system by triggering a kernel BUG() assertion.

CVE-2008-3535

Alexey Dobriyan discovered an off-by-one-error in the iov_iter_advance function which can be exploited by local users to crash a system, resulting in a denial of service.

CVE-2008-3792

Vlad Yasevich reported several NULL pointer reference conditions in the SCTP subsystem that can be triggered by entering sctp-auth codepaths when the AUTH feature is inactive. This may allow attackers to cause a denial of service condition via a system panic.

CVE-2008-3915

Johann Dahm and David Richter reported an issue in the nfsd subsystem that may allow remote attackers to cause a denial of service via a buffer overflow.

For the stable distribution (etch), these problems have been fixed in version 2.6.24-6~etchnhalf.5.

We recommend that you upgrade your linux-2.6.24 packages.");

  script_tag(name:"affected", value:"'linux-2.6.24' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.24", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-alpha", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-amd64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-arm", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-hppa", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-i386", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-ia64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mips", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-s390", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-sparc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-common", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390-tape", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.24", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.24", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.24", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.24-etchnhalf.1", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.24", ver:"2.6.24-6~etchnhalf.5", rls:"DEB4"))) {
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
