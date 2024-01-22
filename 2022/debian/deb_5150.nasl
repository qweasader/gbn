# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705150");
  script_cve_id("CVE-2022-24903");
  script_tag(name:"creation_date", value:"2022-05-31 08:35:33 +0000 (Tue, 31 May 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 14:00:00 +0000 (Tue, 17 May 2022)");

  script_name("Debian: Security Advisory (DSA-5150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5150-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5150-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5150");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rsyslog");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rsyslog' package(s) announced via the DSA-5150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Agten discovered that several modules for TCP syslog reception in rsyslog, a system and kernel logging daemon, have buffer overflow flaws when octet-counted framing is used, which could result in denial of service or potentially the execution of arbitrary code.

For the oldstable distribution (buster), this problem has been fixed in version 8.1901.0-1+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in version 8.2102.0-2+deb11u1.

We recommend that you upgrade your rsyslog packages.

For the detailed security status of rsyslog please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-czmq", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-elasticsearch", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-hiredis", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-kafka", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mongodb", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-relp", ver:"8.1901.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-czmq", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-elasticsearch", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-hiredis", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-kafka", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mongodb", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-openssl", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-relp", ver:"8.2102.0-2+deb11u1", rls:"DEB11"))) {
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
