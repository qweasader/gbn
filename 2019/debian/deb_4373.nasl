# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704373");
  script_cve_id("CVE-2018-4056", "CVE-2018-4058", "CVE-2018-4059");
  script_tag(name:"creation_date", value:"2019-01-27 23:00:00 +0000 (Sun, 27 Jan 2019)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:18:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-4373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4373");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4373");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4373");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/coturn");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'coturn' package(s) announced via the DSA-4373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in coTURN, a TURN and STUN server for VoIP.

CVE-2018-4056

An SQL injection vulnerability was discovered in the coTURN administrator web portal. As the administration web interface is shared with the production, it is unfortunately not possible to easily filter outside access and this security update completely disable the web interface. Users should use the local, command line interface instead.

CVE-2018-4058

Default configuration enables unsafe loopback forwarding. A remote attacker with access to the TURN interface can use this vulnerability to gain access to services that should be local only.

CVE-2018-4059

Default configuration uses an empty password for the local command line administration interface. An attacker with access to the local console (either a local attacker or a remote attacker taking advantage of CVE-2018-4058) could escalade privileges to administrator of the coTURN server.

For the stable distribution (stretch), these problems have been fixed in version 4.5.0.5-1+deb9u1.

We recommend that you upgrade your coturn packages.

For the detailed security status of coturn please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'coturn' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.0.5-1+deb9u1", rls:"DEB9"))) {
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
