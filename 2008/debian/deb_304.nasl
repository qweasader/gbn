# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53596");
  script_cve_id("CVE-2003-0188");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-304");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-304");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-304");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lv' package(s) announced via the DSA-304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Leonard Stiles discovered that lv, a multilingual file viewer, would read options from a configuration file in the current directory. Because such a file could be placed there by a malicious user, and lv configuration options can be used to execute commands, this represented a security vulnerability. An attacker could gain the privileges of the user invoking lv, including root.

For the stable distribution (woody) this problem has been fixed in version 4.49.4-7woody2.

For the old stable distribution (potato) this problem has been fixed in version 4.49.3-4potato2.

For the unstable distribution (sid) this problem is fixed in version 4.49.5-2.

We recommend that you update your lv package.");

  script_tag(name:"affected", value:"'lv' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lv", ver:"4.49.4-7woody2", rls:"DEB3.0"))) {
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
