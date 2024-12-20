# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2102");
  script_cve_id("CVE-2010-2725");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2102-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2102-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2102");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'barnowl' package(s) announced via the DSA-2102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that in barnowl, a curses-based instant-messaging client, the return codes of calls to the ZPending and ZReceiveNotice functions in libzephyr were not checked, allowing attackers to cause a denial of service (crash of the application), and possibly execute arbitrary code.

For the stable distribution (lenny), this problem has been fixed in version 1.0.1-4+lenny2.

For the testing distribution (squeeze), this problem has been fixed in version 1.6.2-1.

For the unstable distribution (sid), this problem has been fixed in version 1.6.2-1.

We recommend that you upgrade your barnowl packages.");

  script_tag(name:"affected", value:"'barnowl' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"barnowl", ver:"1.0.1-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"barnowl-irc", ver:"1.0.1-4+lenny2", rls:"DEB5"))) {
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
