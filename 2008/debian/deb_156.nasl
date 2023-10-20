# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53414");
  script_cve_id("CVE-2002-0984");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-156)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-156");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-156");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-156");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'epic4-script-light' package(s) announced via the DSA-156 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"All versions of the EPIC script Light prior to 2.7.30p5 (on the 2.7 branch) and prior to 2.8pre10 (on the 2.8 branch) running on any platform are vulnerable to a remotely-exploitable bug, which can lead to nearly arbitrary code execution.

This problem has been fixed in version 2.7.30p5-1.1 for the current stable distribution (woody) and in version 2.7.30p5-2 for the unstable distribution (sid). The old stable distribution (potato) is not affected, since it doesn't contain the Light package.

We recommend that you upgrade your epic4-script-light package and restart your IRC client.");

  script_tag(name:"affected", value:"'epic4-script-light' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"epic4-script-light", ver:"1:2.7.30p5-1.1", rls:"DEB3.0"))) {
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
