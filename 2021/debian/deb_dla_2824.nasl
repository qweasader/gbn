# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892824");
  script_cve_id("CVE-2017-11509");
  script_tag(name:"creation_date", value:"2021-11-21 02:00:10 +0000 (Sun, 21 Nov 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 22:14:00 +0000 (Tue, 23 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2824)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2824");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2824");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firebird3.0");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firebird3.0' package(s) announced via the DLA-2824 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated remote attacker can execute arbitrary code in Firebird, a relational database based on InterBase 6.0, by executing a malformed SQL statement. The only known solution is to disable external UDF libraries from being loaded. In order to achieve this, the default configuration has changed to UdfAccess=None. This will prevent the fbudf module from being loaded, but may also break other functionality relying on modules.

For Debian 9 stretch, this problem has been fixed in version 3.0.1.32609.ds4-14+deb9u1.

We recommend that you upgrade your firebird3.0 packages.

For the detailed security status of firebird3.0 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firebird3.0' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firebird-dev", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-common", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-common-doc", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-doc", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-examples", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-server", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-server-core", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird3.0-utils", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libib-util", ver:"3.0.1.32609.ds4-14+deb9u1", rls:"DEB9"))) {
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
