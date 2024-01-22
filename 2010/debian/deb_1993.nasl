# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66836");
  script_cve_id("CVE-2010-0438");
  script_tag(name:"creation_date", value:"2010-02-18 20:15:01 +0000 (Thu, 18 Feb 2010)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1993-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1993-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-1993-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1993");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DSA-1993-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that otrs2, the Open Ticket Request System, does not properly sanitise input data that is used on SQL queries, which might be used to inject arbitrary SQL to, for example, escalate privileges on a system that uses otrs2.

The oldstable distribution (etch) is not affected.

For the stable distribution (lenny), the problem has been fixed in version 2.2.7-2lenny3.

For the testing distribution (squeeze), the problem will be fixed soon.

For the unstable distribution (sid), the problem has been fixed in version 2.4.7-1.

We recommend that you upgrade your otrs2 packages.");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"2.2.7-2lenny3", rls:"DEB5"))) {
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
