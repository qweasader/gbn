# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892768");
  script_cve_id("CVE-2021-36160");
  script_tag(name:"creation_date", value:"2021-10-01 01:00:06 +0000 (Fri, 01 Oct 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-27 17:34:00 +0000 (Mon, 27 Sep 2021)");

  script_name("Debian: Security Advisory (DLA-2768-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2768-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2768-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/uwsgi");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uwsgi' package(s) announced via the DLA-2768-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the uwsgi proxy module for Apache2 (mod_proxy_uwsgi) can read above the allocated memory when processing a request with a carefully crafted uri-path. An attacker may cause the server to crash (DoS).

For Debian 9 stretch, this problem has been fixed in version 2.0.14+20161117-3+deb9u4.

We recommend that you upgrade your uwsgi packages.

For the detailed security status of uwsgi please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'uwsgi' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-mongodb-plugins", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python3", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gccgo", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gevent-python", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-glusterfs", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-8", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-8", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-mono", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.3", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ring-openjdk-8", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-servlet-openjdk-8", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-tornado-python", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-src", ver:"2.0.14+20161117-3+deb9u4", rls:"DEB9"))) {
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
