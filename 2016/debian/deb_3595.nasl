# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703595");
  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668");
  script_tag(name:"creation_date", value:"2016-06-04 22:00:00 +0000 (Sat, 04 Jun 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3595)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3595");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3595");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3595");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10024-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10025-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mariadb-10.0' package(s) announced via the DSA-3595 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MariaDB database server. The vulnerabilities are addressed by upgrading MariaDB to the new upstream version 10.0.25. Please see the MariaDB 10.0 Release Notes for further details:

[link moved to references]

[link moved to references]

For the stable distribution (jessie), these problems have been fixed in version 10.0.25-0+deb8u1.

We recommend that you upgrade your mariadb-10.0 packages.");

  script_tag(name:"affected", value:"'mariadb-10.0' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbd-dev", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-core-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-common", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-connect-engine-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-oqgraph-engine-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-core-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test-10.0", ver:"10.0.25-0+deb8u1", rls:"DEB8"))) {
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
