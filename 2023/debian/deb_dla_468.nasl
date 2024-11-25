# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.468");
  script_cve_id("CVE-2015-3245", "CVE-2015-3246");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-468-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-468-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libuser' package(s) announced via the DLA-468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities were discovered in libuser, a library that implements a standardized interface for manipulating and administering user and group accounts, that could lead to a denial of service or privilege escalation by local users.

CVE-2015-3245

Incomplete blacklist vulnerability in the chfn function in libuser before 0.56.13-8 and 0.60 before 0.60-7, as used in the userhelper program in the usermode package, allows local users to cause a denial of service (/etc/passwd corruption) via a newline character in the GECOS field.

CVE-2015-3246

libuser before 0.56.13-8 and 0.60 before 0.60-7, as used in the userhelper program in the usermode package, directly modifies /etc/passwd, which allows local users to cause a denial of service (inconsistent file state) by causing an error during the modification. NOTE: this issue can be combined with CVE-2015-3245 to gain privileges.

In addition the usermode package, which depends on libuser, was rebuilt against the updated version.

For Debian 7 Wheezy, these problems have been fixed in

libuser 1:0.56.9.dfsg.1-1.2+deb7u1 usermode 1.109-1+deb7u2

We recommend that you upgrade your libuser and usermode packages.");

  script_tag(name:"affected", value:"'libuser' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libuser", ver:"1:0.56.9.dfsg.1-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuser1", ver:"1:0.56.9.dfsg.1-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuser1-dev", ver:"1:0.56.9.dfsg.1-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libuser", ver:"1:0.56.9.dfsg.1-1.2+deb7u1", rls:"DEB7"))) {
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
