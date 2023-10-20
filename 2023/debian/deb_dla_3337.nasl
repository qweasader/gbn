# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893337");
  script_tag(name:"creation_date", value:"2023-02-24 02:00:07 +0000 (Fri, 24 Feb 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3337");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3337");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-3-37-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-3-38-release-notes/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mariadb-10.3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mariadb-10.3' package(s) announced via the DLA-3337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A new MariaDB minor maintenance release 10.3.38 has been released. It includes fix for a major performance/memory consumption issue (MDEV-29988).

For further details, see the MariaDB 10.3 release notes:

[link moved to references] [link moved to references]

For Debian 10 buster, this problem has been fixed in version 1:10.3.38-0+deb10u1.

We recommend that you upgrade your mariadb-10.3 packages.

For the detailed security status of mariadb-10.3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.3' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb-dev", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb-dev-compat", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb3", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbclient-dev", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbd-dev", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbd19", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-backup", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-10.3", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-core-10.3", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-common", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-connect", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-cracklib-password-check", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-gssapi-client", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-gssapi-server", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-mroonga", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-oqgraph", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-rocksdb", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-spider", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-tokudb", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-10.3", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-core-10.3", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test-data", ver:"1:10.3.38-0+deb10u1", rls:"DEB10"))) {
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
