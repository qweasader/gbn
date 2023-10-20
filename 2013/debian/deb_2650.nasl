# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702650");
  script_cve_id("CVE-2013-1766");
  script_tag(name:"creation_date", value:"2013-03-16 23:00:00 +0000 (Sat, 16 Mar 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2650)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2650");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2650");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2650");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-2650 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bastian Blank discovered that libvirtd, a daemon for management of virtual machines, network and storage, would change ownership of devices files so they would be owned by user libvirt-qemu and group kvm, which is a general purpose group not specific to libvirt, allowing unintended write access to those devices and files for the kvm group members.

For the stable distribution (squeeze), this problem has been fixed in version 0.8.3-5+squeeze5.

For the testing distribution (wheezy), this problem has been fixed in version 0.9.12-11.

For the unstable distribution (sid), this problem has been fixed in version 0.9.12-11.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-bin", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libvirt", ver:"0.8.3-5+squeeze4", rls:"DEB6"))) {
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
