# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.88");
  script_cve_id("CVE-2011-0188", "CVE-2011-2686", "CVE-2011-2705", "CVE-2011-4815", "CVE-2014-8080", "CVE-2014-8090");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DLA-88)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-88");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-88");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.8' package(s) announced via the DLA-88 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes multiple local and remote denial of service and remote code execute problems:

CVE-2011-0188

Properly allocate memory, to prevent arbitrary code execution or application crash. Reported by Drew Yao.

CVE-2011-2686

Reinitialize the random seed when forking to prevent CVE-2003-0900 like situations.

CVE-2011-2705

Modify PRNG state to prevent random number sequence repeatation at forked child process which has same pid. Reported by Eric Wong.

CVE-2011-4815

Fix a problem with predictable hash collisions resulting in denial of service (CPU consumption) attacks. Reported by Alexander Klink and Julian Waelde.

CVE-2014-8080

Fix REXML parser to prevent memory consumption denial of service via crafted XML documents. Reported by Willis Vandevanter.

CVE-2014-8090

Add REXML::Document#document to complement the fix for CVE-2014-8080. Reported by Tomas Hoger.

For Debian 6 Squeeze, these issues have been fixed in ruby1.8 version 1.8.7.302-2squeeze3");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.302-2squeeze3", rls:"DEB6"))) {
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
