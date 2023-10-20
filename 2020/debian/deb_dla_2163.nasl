# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892163");
  script_cve_id("CVE-2017-11747");
  script_tag(name:"creation_date", value:"2020-04-01 03:00:08 +0000 (Wed, 01 Apr 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-31 15:15:00 +0000 (Tue, 31 Mar 2020)");

  script_name("Debian: Security Advisory (DLA-2163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2163");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2163");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tinyproxy' package(s) announced via the DLA-2163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A minor security issue and a severe packaging bug have been fixed in tinyproxy, a lightweight http proxy daemon.

CVE-2017-11747

main.c in Tinyproxy created a /var/run/tinyproxy/tinyproxy.pid file after dropping privileges to a non-root account, which might have allowed local users to kill arbitrary processes by leveraging access to this non-root account for tinyproxy.pid modification before a root script executed a 'kill `cat /run/tinyproxy/tinyproxy.pid`' command.

OTHER

Furthermore, a severe flaw had been discovered by Tim Duesterhus in Debian's init script for tinyproxy. With the tiny.conf configuration file having the PidFile option removed, the next run of logrotate (if installed) would have changed the owner of the system's base directory ('/') to tinyproxy:tinyproxy.

For Debian 8 Jessie, this problem has been fixed in version 1.8.3-3+deb8u1.

We recommend that you upgrade your tinyproxy packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tinyproxy' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tinyproxy", ver:"1.8.3-3+deb8u1", rls:"DEB8"))) {
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
