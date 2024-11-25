# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704541");
  script_cve_id("CVE-2019-12412");
  script_tag(name:"creation_date", value:"2019-10-05 02:00:09 +0000 (Sat, 05 Oct 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 14:39:48 +0000 (Mon, 30 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-4541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4541-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4541-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4541");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libapreq2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapreq2' package(s) announced via the DSA-4541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Kellermann reported a NULL pointer dereference flaw in libapreq2, a generic Apache request library, allowing a remote attacker to cause a denial of service against an application using the library (application crash) if an invalid nested multipart body is processed.

For the oldstable distribution (stretch), this problem has been fixed in version 2.13-7~deb9u1.

For the stable distribution (buster), this problem has been fixed in version 2.13-7~deb10u1.

We recommend that you upgrade your libapreq2 packages.

For the detailed security status of libapreq2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libapreq2' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-apreq2", ver:"2.13-7~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-request-perl", ver:"2.13-7~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-3", ver:"2.13-7~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-dev", ver:"2.13-7~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-doc", ver:"2.13-7~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-apreq2", ver:"2.13-7~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-request-perl", ver:"2.13-7~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-3", ver:"2.13-7~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-dev", ver:"2.13-7~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapreq2-doc", ver:"2.13-7~deb9u1", rls:"DEB9"))) {
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
