# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703613");
  script_cve_id("CVE-2016-5008");
  script_tag(name:"creation_date", value:"2016-07-01 22:00:00 +0000 (Fri, 01 Jul 2016)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-3613-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3613-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3613-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3613");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-3613-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vivian Zhang and Christoph Anton Mitterer discovered that setting an empty VNC password does not work as documented in Libvirt, a virtualisation abstraction library. When the password on a VNC server is set to the empty string, authentication on the VNC server will be disabled, allowing any user to connect, despite the documentation declaring that setting an empty password for the VNC server prevents all client connections. With this update the behaviour is enforced by setting the password expiration to now.

For the stable distribution (jessie), this problem has been fixed in version 1.2.9-9+deb8u3.

For the unstable distribution (sid), this problem has been fixed in version 2.0.0-1.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-bin", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-clients", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"1.2.9-9+deb8u3", rls:"DEB8"))) {
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
