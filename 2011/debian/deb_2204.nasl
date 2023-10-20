# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69340");
  script_cve_id("CVE-2010-3695");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2204");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2204");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2204");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imp4' package(s) announced via the DSA-2204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moritz Naumann discovered that IMP 4, a webmail component for the Horde framework, is prone to cross-site scripting attacks by a lack of input sanitising of certain Fetchmail information.

For the oldstable distribution (lenny), this problem has been fixed in version 4.2-4lenny3.

For the stable distribution (squeeze), this problem has been fixed in version 4.3.7+debian0-2.1, which was already included in the squeeze release.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 4.3.7+debian0-2.1.

We recommend that you upgrade your imp4 packages.");

  script_tag(name:"affected", value:"'imp4' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"imp4", ver:"4.2-4lenny3", rls:"DEB5"))) {
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
