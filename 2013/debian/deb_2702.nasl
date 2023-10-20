# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702702");
  script_cve_id("CVE-2013-1431");
  script_tag(name:"creation_date", value:"2013-06-02 22:00:00 +0000 (Sun, 02 Jun 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2702)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2702");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2702");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2702");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'telepathy-gabble' package(s) announced via the DSA-2702 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maksim Otstavnov discovered that the Wocky submodule used by telepathy-gabble, the Jabber/XMPP connection manager for the Telepathy framework, does not respect the tls-required flag on legacy Jabber servers. A network intermediary could use this vulnerability to bypass TLS verification and perform a man-in-the-middle attack.

For the oldstable distribution (squeeze), this problem has been fixed in version 0.9.15-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 0.16.5-1+deb7u1.

For the testing distribution (jessie) and the unstable distribution (sid), this problem has been fixed in version 0.16.6-1.

We recommend that you upgrade your telepathy-gabble packages.");

  script_tag(name:"affected", value:"'telepathy-gabble' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"telepathy-gabble", ver:"0.9.15-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"telepathy-gabble-dbg", ver:"0.9.15-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"telepathy-gabble", ver:"0.16.5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"telepathy-gabble-dbg", ver:"0.16.5-1+deb7u1", rls:"DEB7"))) {
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
