# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704513");
  script_cve_id("CVE-2019-10197");
  script_tag(name:"creation_date", value:"2019-09-05 02:00:07 +0000 (Thu, 05 Sep 2019)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4513-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4513-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4513");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2019-10197.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/samba");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-4513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Metzmacher discovered a flaw in Samba, a SMB/CIFS file, print, and login server for Unix. Specific combinations of parameters and permissions can allow user to escape from the share path definition and see the complete '/' filesystem. Unix permission checks in the kernel are still enforced.

Details can be found in the upstream advisory at [link moved to references]

For the stable distribution (buster), this problem has been fixed in version 2:4.9.5+dfsg-5+deb10u1.

We recommend that you upgrade your samba packages.

For the detailed security status of samba please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.9.5+dfsg-5+deb10u1+really0.02", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-samba", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
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
