# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704470");
  script_cve_id("CVE-2019-10162", "CVE-2019-10163");
  script_tag(name:"creation_date", value:"2019-06-25 02:00:05 +0000 (Tue, 25 Jun 2019)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:27:00 +0000 (Fri, 02 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4470)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4470");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4470");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4470");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pdns");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns' package(s) announced via the DSA-4470 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in pdns, an authoritative DNS server which may result in denial of service via malformed zone records and excessive NOTIFY packets in a master/slave setup.

For the stable distribution (stretch), these problems have been fixed in version 4.0.3-1+deb9u5.

We recommend that you upgrade your pdns packages.

For the detailed security status of pdns please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-bind", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-geoip", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-lua", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-mydns", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-odbc", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-opendbx", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-remote", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-sqlite3", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-tinydns", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-tools", ver:"4.0.3-1+deb9u5", rls:"DEB9"))) {
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
