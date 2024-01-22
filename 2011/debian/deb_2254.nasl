# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69986");
  script_cve_id("CVE-2011-1760");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2254-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2254-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2254-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2254");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'oprofile' package(s) announced via the DSA-2254-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OProfile is a performance profiling tool which is configurable by opcontrol, its control utility. Stephane Chauveau reported several ways to inject arbitrary commands in the arguments of this utility. If a local unprivileged user is authorized by sudoers file to run opcontrol as root, this user could use the flaw to escalate his privileges.

For the oldstable distribution (lenny), this problem has been fixed in version 0.9.3-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 0.9.6-1.1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 0.9.6-1.2.

For the unstable distribution (sid), this problem has been fixed in version 0.9.6-1.2.

We recommend that you upgrade your oprofile packages.");

  script_tag(name:"affected", value:"'oprofile' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"oprofile", ver:"0.9.3-2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oprofile-gui", ver:"0.9.3-2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"oprofile", ver:"0.9.6-1.1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oprofile-gui", ver:"0.9.6-1.1+squeeze2", rls:"DEB6"))) {
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
