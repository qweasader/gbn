# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53673");
  script_cve_id("CVE-2003-0785");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-389");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-389");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-389");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ipmasq' package(s) announced via the DSA-389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ipmasq is a package which simplifies configuration of Linux IP masquerading, a form of network address translation which allows a number of hosts to share a single public IP address. Due to use of certain improper filtering rules, traffic arriving on the external interface addressed for an internal host would be forwarded, regardless of whether it was associated with an established connection. This vulnerability could be exploited by an attacker capable of forwarding IP traffic with an arbitrary destination address to the external interface of a system with ipmasq installed.

For the current stable distribution (woody) this problem has been fixed in version 3.5.10c.

For the unstable distribution (sid) this problem has been fixed in version 3.5.12.

We recommend that you update your ipmasq package.");

  script_tag(name:"affected", value:"'ipmasq' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ipmasq", ver:"3.5.10c", rls:"DEB3.0"))) {
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
