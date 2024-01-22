# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53260");
  script_cve_id("CVE-2004-0911");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-556-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-556-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-556-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-556");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'netkit-telnet' package(s) announced via the DSA-556-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Zalewski discovered a bug in the netkit-telnet server (telnetd) whereby a remote attacker could cause the telnetd process to free an invalid pointer. This causes the telnet server process to crash, leading to a straightforward denial of service (inetd will disable the service if telnetd is crashed repeatedly), or possibly the execution of arbitrary code with the privileges of the telnetd process (by default, the 'telnetd' user).

For the stable distribution (woody) this problem has been fixed in version 0.17-18woody2.

For the unstable distribution (sid) this problem has been fixed in version 0.17-26.

We recommend that you upgrade your netkit-telnet package.");

  script_tag(name:"affected", value:"'netkit-telnet' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"telnet", ver:"0.17-18woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"telnetd", ver:"0.17-18woody2", rls:"DEB3.0"))) {
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
